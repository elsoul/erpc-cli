# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute actual emitted external loaders on inert immutable profiles, never a node."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parents[1]/'templates/node'))
import erpc_hl_units as units
from erpc_hl_common import RUNTIME_FILES, RPC_RUNTIME_FILES

SCENARIOS = ('safe','file-write','directory-write','ancestor-write','file-link','hardlink',
             'foreign-owner','pointer-escape','digest-drift','extra-file','missing-file','fifo')


def exercise(command,profile=RUNTIME_FILES,inner_exit=None,namespace_name='/usr/local/lib/erpc/hyperliquid'):
    argv = shlex.split(command.removeprefix('+'))
    argv = argv[argv.index('/usr/bin/python3'):]
    assert argv[:3] == ['/usr/bin/python3','-I','-c']
    original = argv[3]
    for scenario in (SCENARIOS if inner_exit is None else ('safe',)):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            namespace = root/'helpers'; releases=namespace/'releases'; releases.mkdir(parents=True)
            stage = releases/'stage'; stage.mkdir()
            marker=root/'interpreted'; poison=root/'poisoned'; evil=root/'ambient'; evil.mkdir()
            for name in profile: (stage/name).write_bytes(b'# inert fixture\n')
            (stage/'control.py').write_text('import json,sys\nfrom pathlib import Path\n'
                'Path('+repr(str(marker))+').write_text(json.dumps(sys.argv[1:]))\n'
                +('' if inner_exit is None else ('raise ValueError("inert-inner-sensitive")\n' if inner_exit=='error' else 'raise SystemExit('+str(inner_exit)+')\n')))
            digest=hashlib.sha256(b''.join((stage/name).read_bytes() for name in profile)).hexdigest()
            selected=releases/digest;stage.rename(selected)
            (namespace/'current').symlink_to(selected)
            script=selected/'control.py'
            (evil/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(poison))+').touch()\n')
            if scenario=='file-write': script.chmod(0o666)
            if scenario=='directory-write': selected.chmod(0o777)
            if scenario=='ancestor-write': root.chmod(0o777)
            if scenario=='file-link': script.rename(root/'outside');script.symlink_to(root/'outside')
            if scenario=='hardlink': os.link(script,root/'alias')
            if scenario=='pointer-escape': (namespace/'current').unlink();(namespace/'current').symlink_to(root)
            if scenario=='digest-drift': script.write_text(script.read_text()+'# changed\n')
            if scenario=='extra-file': (selected/'unexpected.py').write_text('# extra\n')
            if scenario=='missing-file': (selected/'catalog.json').unlink()
            if scenario=='fifo': script.unlink();os.mkfifo(script)
            if original.startswith("exec(bytes.fromhex('"):
                program=bytes.fromhex(original.split("fromhex('",1)[1].split("')",1)[0]).decode()
            else: program=original
            program=program.replace(namespace_name,str(namespace))
            # Only UID/root ancestors are modeled. Modes, links, complete profile,
            # digest, interpretation order, isolated startup and argv are real.
            model='''import os
from pathlib import Path
from types import SimpleNamespace
real_lstat=os.lstat
fixture=Path(FIXTURE)
target=Path(TARGET)
def metadata(path,*args,**kwargs):
    fields=list(real_lstat(path,*args,**kwargs));candidate=Path(path)
    if candidate==fixture or fixture in candidate.parents:
        if fields[4]==os.getuid():fields[4]=0
        if SCENARIO=='foreign-owner' and candidate==target:fields[4]=2
    elif candidate in fixture.parents:
        fields[4]=0;fields[0]&=~0o022
    return os.stat_result(fields)
os.lstat=metadata
real_scandir=os.scandir
def scan(directory):
    with real_scandir(directory) as values:
        return [SimpleNamespace(name=item.name,path=item.path,stat=lambda *,follow_symlinks=True,p=item.path:metadata(p)) for item in values]
os.scandir=scan
'''.replace('FIXTURE',repr(str(root))).replace('TARGET',repr(str(script))).replace('SCENARIO',repr(scenario))
            result=subprocess.run([argv[0],'-I','-c',model+program,*argv[4:]],capture_output=True,
                env=dict(os.environ,PYTHONPATH=str(evil)),timeout=10)
            expected=0 if scenario=='safe' and inner_exit in (None,0) else (255 if argv[4:] and argv[4]=='condition' else 1)
            if inner_exit is None and (not argv[4:] or argv[4]!='condition'):
                assert (result.returncode==0)==(scenario=='safe'),(scenario,result.stderr.decode())
            else:assert result.returncode==expected,(scenario,inner_exit,result.returncode,result.stderr.decode())
            assert b'inert-inner-sensitive' not in result.stderr
            if argv[4:] and argv[4]=='condition' and scenario!='safe':assert result.returncode==255,(scenario,result.returncode)
            assert marker.exists()==(scenario=='safe'), scenario
            if marker.exists(): assert json.loads(marker.read_text())==argv[4:]
            assert not poison.exists()


class Entrypoints(unittest.TestCase):
    def test_actual_systemd_native_gateway_retention_and_firewall_programs(self):
        identities={'erpc-hyperliquid':{'uid':995,'gid':995},'erpc-hyperliquid-rpc':{'uid':996,'gid':996}}
        rendered=units.render({'network':'testnet','owner':'a'*32,'role':'rpc'},{'id':'visor-'+'b'*16},identities)
        for unit,key in [('erpc-hyperliquid-node.service','ExecStartPre='),
                         ('erpc-hyperliquid-node.service','ExecCondition='),
                         ('erpc-hyperliquid-rpc.service','ExecStartPre='),
                         ('erpc-hyperliquid-retention.service','ExecStartPre='),
                         ('erpc-hyperliquid-firewall.service','ExecStart=')]:
            with self.subTest(unit=unit):
                exercise(next(line[len(key):] for line in rendered[unit].splitlines() if line.startswith(key)))

    def test_actual_validator_credential_condition_guard_and_legacy_complete_profile(self):
        identities={'erpc-hyperliquid':{'uid':995,'gid':995},'erpc-hyperliquid-rpc':{'uid':996,'gid':996}}
        # Public structure only; cryptographic binding has separate custody tests.
        contract={'network':'testnet','owner':'a'*32,'role':'validator','validator':{
            'validator':'0x'+'ab'*20,'signer':'0x'+'cd'*20,'signer_public_key':'04'+'ef'*64,'max_hot_usdc':'0.01'}}
        unit=units.render(contract,{'id':'visor-'+'b'*16},identities,'validator')['erpc-hyperliquid-node.service']
        for key in ('ExecCondition=','ExecStartPre='):
            command=next(line[len(key):] for line in unit.splitlines() if line.startswith(key))
            exercise(command)
        rpc=units.render(dict(network='testnet',owner='a'*32,role='rpc'),{'id':'visor-'+'b'*16},identities)
        command=next(line[len('ExecCondition='):] for line in rpc['erpc-hyperliquid-node.service'].splitlines() if line.startswith('ExecCondition='))
        exercise(command,RPC_RUNTIME_FILES)
        for code in (0,1,7,255,'error'):exercise(command,inner_exit=code)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--ssh': exercise(sys.argv[2])
    else: unittest.main()
