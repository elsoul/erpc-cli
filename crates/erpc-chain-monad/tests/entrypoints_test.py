# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute actual emitted loaders on inert files; no root, node or credential action."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/node'))
import erpc_monad_units as units
import erpc_monad_entry as entry

SCENARIOS=('safe','file-write','directory-write','ancestor-write','file-link','hardlink','foreign-owner','fifo','ambient-hook')


def exercise(command):
    argv=shlex.split(command.removeprefix('+'));argv=argv[argv.index('/usr/bin/python3'):]
    assert argv[:3]==['/usr/bin/python3','-I','-c']
    source=argv[3]
    if source.startswith("exec(bytes.fromhex('"):
        source=bytes.fromhex(source.split("fromhex('",1)[1].split("')",1)[0]).decode()
    name='cleanup.py' if "cleanup.py" in source else 'control.py'
    for scenario in SCENARIOS:
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();helper=root/'helpers';helper.mkdir();marker=root/'interpreted'
            file=helper/name;file.write_text('import sys,json\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text(json.dumps(sys.argv[1:]))\n')
            evil=root/'ambient';evil.mkdir();poison=root/'poisoned'
            (evil/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(poison))+').touch()\n')
            if scenario=='file-write':file.chmod(0o666)
            if scenario=='directory-write':helper.chmod(0o777)
            if scenario=='ancestor-write':root.chmod(0o777)
            if scenario=='file-link':file.rename(root/'outside');file.symlink_to(root/'outside')
            if scenario=='hardlink':os.link(file,root/'alias')
            if scenario=='fifo':file.unlink();os.mkfifo(file)
            model='''import os
from pathlib import Path
from types import SimpleNamespace
real_lstat=os.lstat
root=Path(ROOT)
target=Path(TARGET)
def metadata(path,*args,**kwargs):
    info=list(real_lstat(path,*args,**kwargs));candidate=Path(path)
    if candidate==root or root in candidate.parents:
        if info[4]==os.getuid():info[4]=0
        if SCENARIO=='foreign-owner' and candidate==target:info[4]=2
    elif candidate in root.parents:info[4]=0;info[0]&=~0o022
    return os.stat_result(info)
os.lstat=metadata
real_scan=os.scandir
def scan(directory):
    with real_scan(directory) as rows:
        return [SimpleNamespace(name=row.name,path=row.path,stat=lambda *,follow_symlinks=True,p=row.path:metadata(p)) for row in rows]
os.scandir=scan
'''.replace('ROOT',repr(str(root))).replace('TARGET',repr(str(file))).replace('SCENARIO',repr(scenario))
            program=source.replace('/usr/local/lib/erpc/monad',str(helper))
            result=subprocess.run([argv[0],'-I','-c',model+program,*argv[4:]],capture_output=True,
                env=dict(os.environ,PYTHONPATH=str(evil)),timeout=10)
            expected=scenario in ('safe','ambient-hook')
            assert (result.returncode==0)==expected,(scenario,result.stderr.decode())
            if argv[4:] and argv[4]=='condition' and not expected:assert result.returncode==255,(scenario,result.returncode)
            assert marker.exists()==expected,scenario
            if expected:assert json.loads(marker.read_text())==argv[4:]
            assert not poison.exists()


class Entrypoints(unittest.TestCase):
    def test_actual_units_authenticate_before_interpreting_installed_controller_or_cleanup(self):
        root=Path(__file__).parents[1]/'templates/node'
        catalog=json.loads((root/'catalog.json').read_text())
        contract={'network':'testnet','role':'validator','owner':'a'*32,'partuuid':'abcdefab-abcd-abcd-abcd-abcdefabcdef'}
        identities={'erpc-monad':{'uid':995,'gid':995},'erpc-monad-proxy':{'uid':996,'gid':996}}
        rendered=units.render(catalog,contract,list(range(16)),[],[],identities)
        for unit,key in [('erpc-monad-bft.service','ExecCondition='),('erpc-monad-bft.service','ExecStartPre='),
            ('erpc-monad-memory.service','ExecStart='),('erpc-monad-firewall.service','ExecStart='),
            ('erpc-monad-gateway.service','ExecStartPre='),('erpc-monad-cleanup.service','ExecStart=')]:
            with self.subTest(unit=unit,key=key):
                exercise(next(line[len(key):] for line in rendered[unit].splitlines() if line.startswith(key)))
        self.assertIn('User=995\nGroup=995\n',rendered['erpc-monad-bft.service'])
        self.assertEqual(rendered['erpc-monad-bft.service'].count('ExecCondition='),1)

    def test_canonical_import_authority_is_not_a_divergent_local_copy(self):
        root=Path(__file__).parents[1]
        source=(root/'templates/node/erpc_monad_entry.py').read_text()
        embedded=source.split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0]
        self.assertEqual(embedded,(root.parent/'erpc-ssh/src/python-trust.py').read_text())


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--ssh':exercise(sys.argv[2])
    else:unittest.main()
