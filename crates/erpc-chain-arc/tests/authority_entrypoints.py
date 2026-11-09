#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute generated Arc entries against real inert files, with root metadata modeled.

Adapted from the author's BSC/Avalanche entrypoint regression. Namespace and UID
mapping are the only filesystem virtualization; modes, links, hashes and bytes
remain real. No sudo, node, credential or host operation is executed.
"""
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import arc_helpers as helpers
import arc_units as units
ROOT=pathlib.Path(__file__).resolve().parents[1]
ACTUAL=json.load(sys.stdin)
SETUP=r'''import os
from pathlib import Path
from types import SimpleNamespace
original_lstat=os.lstat
fixture_root=Path(ROOT)
fixture_target=Path(TARGET)
fixture_uid=os.getuid()
def metadata(path,*args,**kwargs):
    value=original_lstat(path,*args,**kwargs);fields=list(value);candidate=Path(path)
    if candidate==fixture_root or fixture_root in candidate.parents:
        if fields[4]==fixture_uid:fields[4]=0
        if SCENARIO=='owner' and candidate==fixture_target:fields[4]=2
    elif candidate in fixture_root.parents:
        fields[4]=0;fields[0]&=~0o022
    return os.stat_result(fields)
os.lstat=metadata
original_scandir=os.scandir
def entries(directory):
    with original_scandir(directory) as stream:
        return [SimpleNamespace(name=entry.name,path=entry.path,
            stat=lambda *,follow_symlinks=True,p=entry.path:metadata(p)) for entry in stream]
os.scandir=entries
'''


class Entrypoints(unittest.TestCase):
    def test_canonical_source_and_every_generated_entry_refuse_before_interpretation(self):
        canonical=(ROOT.parent/'erpc-ssh/src/python-trust.py').read_bytes()
        self.assertEqual((ROOT/'templates/authority/arc_trust.py').read_bytes(),canonical)
        self.assertEqual((ROOT/'templates/authority/arc_helper_release.py').read_bytes(),(ROOT.parent/'erpc-ssh/src/python-release.py').read_bytes())
        controller=(ROOT/'templates/authority/control.py').read_text()
        self.assertEqual(controller.split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0].encode(),canonical)
        f=lifecycle.Lifecycle('runTest');f.setUp()
        try:
            f.install();state=f.c.state(f.contract)
            # Generate actual units from the production renderer and a complete
            # profile whose controller only writes a public inert marker.
            folder=f.root/'inert-profile';shutil.copytree(f.c.source,folder)
            control=folder/'control.py';control.write_text('from pathlib import Path\nPath(MARKER).write_text("interpreted")\n')
            names=helpers.profile(folder)
            identity=hashlib.sha256(b''.join((folder/name).read_bytes() for name in names)).hexdigest()
            texts,_=units.make(f.c,state,f.target,f.policy,folder,identity)
            commands=[]
            for text in texts.values():
                for line in text.splitlines():
                    if line.startswith(('ExecCondition=','ExecStartPre=','ExecStartPost=')):
                        commands.append(line.partition('=')[2].lstrip('+'))
                self.assertIn('User='+str(state['service_uid'])+'\n',text)
                self.assertIn('Group='+str(state['service_gid'])+'\n',text)
                self.assertIn('LimitCORE=0\n',text)
                self.assertIn('SendSIGKILL=no\n',text)
            commands.append(helpers.systemd_command(folder,identity,'firewall-load','firewall'))
            commands.append(ACTUAL['ssh'].removeprefix('sudo -n '))
            self.assertEqual(len(commands),9)
            total=0
            for command in commands:
                argv=shlex.split(command);self.assertEqual(argv[:3],['/usr/bin/python3','-I','-c'])
                self.assertEqual(len(argv),4)
                raw=argv[3]
                if raw.startswith("exec(bytes.fromhex('"):
                    raw=bytes.fromhex(raw.split("'",2)[1]).decode()
                for scenario in ('safe','file-write','directory-write','ancestor-write','symlink','hardlink','owner','hash'):
                    with self.subTest(scenario=scenario,entry=total//8),tempfile.TemporaryDirectory() as temporary:
                        root=pathlib.Path(temporary).resolve();namespace=root/'namespace';directory=namespace/'releases'/identity
                        directory.parent.mkdir(parents=True);shutil.copytree(folder,directory)
                        (namespace/'current').symlink_to('releases/'+identity)
                        target=directory/'control.py';marker=root/'interpreted'
                        # Marker is supplied through the inert controller's globals,
                        # keeping its sealed bytes/digest identical to generation.
                        if scenario=='file-write':target.chmod(0o666)
                        if scenario=='directory-write':directory.chmod(0o777)
                        if scenario=='ancestor-write':namespace.chmod(0o777)
                        if scenario=='symlink':
                            target.rename(root/'inert');target.symlink_to(root/'inert')
                        if scenario=='hardlink':os.link(target,root/'alias')
                        if scenario=='hash':target.write_text(target.read_text()+'# modified\n')
                        setup=SETUP.replace('ROOT',repr(str(root))).replace('TARGET',repr(str(target))).replace('SCENARIO',repr(scenario))
                        setup+='\nimport runpy\noriginal_run=runpy.run_path\ndef run(path,**kwargs):\n return original_run(path,init_globals={"MARKER":'+repr(str(marker))+'},**kwargs)\nrunpy.run_path=run\n'
                        program=raw.replace('/usr/local/lib/erpc/arc',str(namespace))
                        result=subprocess.run([sys.executable,'-I','-c',setup+program],capture_output=True,timeout=10)
                        self.assertEqual(marker.exists(),scenario=='safe',(scenario,result.stderr.decode()))
                        self.assertEqual(result.returncode==0,scenario=='safe',(scenario,result.stderr.decode()))
                        if scenario!='safe' and command!=commands[-1]:self.assertEqual(result.returncode,255)
                        total+=1
            print(str(total)+' actual Arc entrypoint scenarios passed')
        finally:f.tearDown()


if __name__=='__main__':unittest.main()
