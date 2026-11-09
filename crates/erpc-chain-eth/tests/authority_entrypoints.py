# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual emitted Ethereum loaders on inert immutable profiles, never native clients.

The root UID projection fixture is adapted from this author's Hyperliquid tests.
"""
import hashlib,json,os,shlex,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures
import eth_namespace as namespace
import eth_units as units

SCENARIOS = ('safe','file-write','directory-write','ancestor-write','file-link','hardlink',
             'foreign-owner','pointer-escape','digest-drift','extra-file','missing-file','fifo')


def exercise(command,profile,namespace_name,expected_args=None,fixed=False,script_name="control.py"):
    inner_exit=None
    argv = shlex.split(command.removeprefix('+'))
    argv = argv[argv.index('/usr/bin/python3'):]
    assert argv[:3] == ['/usr/bin/python3','-I','-c']
    original = argv[3]
    for scenario in (tuple(item for item in SCENARIOS if item!='pointer-escape') if fixed else SCENARIOS):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            namespace = root/'helpers'; releases=namespace/'releases'; releases.mkdir(parents=True)
            stage = releases/'stage'; stage.mkdir()
            marker=root/'interpreted'; poison=root/'poisoned'; evil=root/'ambient'; evil.mkdir()
            for name in profile: (stage/name).write_bytes(b'# inert fixture\n')
            (stage/script_name).write_text('import json,sys\nfrom pathlib import Path\n'
                'Path('+repr(str(marker))+').write_text(json.dumps(sys.argv[1:]))\n'
                +('' if inner_exit is None else ('raise ValueError("inert-inner-sensitive")\n' if inner_exit=='error' else 'raise SystemExit('+str(inner_exit)+')\n')))
            digest=hashlib.sha256(b''.join((stage/name).read_bytes() for name in profile)).hexdigest()
            selected=releases/digest;stage.rename(selected)
            (namespace/'current').symlink_to(selected)
            script=selected/script_name
            (evil/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(poison))+').touch()\n')
            if scenario=='file-write': script.chmod(0o666)
            if scenario=='directory-write': selected.chmod(0o777)
            if scenario=='ancestor-write': root.chmod(0o777)
            if scenario=='file-link': script.rename(root/'outside');script.symlink_to(root/'outside')
            if scenario=='hardlink': os.link(script,root/'alias')
            if scenario=='pointer-escape': (namespace/'current').unlink();(namespace/'current').symlink_to(root)
            if scenario=='digest-drift': script.write_text(script.read_text()+'# changed\n')
            if scenario=='extra-file': (selected/'unexpected.py').write_text('# extra\n')
            if scenario=='missing-file': (selected/profile[-1]).unlink()
            if scenario=='fifo': script.unlink();os.mkfifo(script)
            if original.startswith("exec(bytes.fromhex('"):
                program=bytes.fromhex(original.split("fromhex('",1)[1].split("')",1)[0]).decode()
            else: program=original
            program=program.replace(namespace_name,str(namespace))
            if fixed:program=program.replace("c"*64,digest)
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
            result=subprocess.run([sys.executable,'-I','-c',model+program,*argv[4:]],capture_output=True,
                env=dict(os.environ,PYTHONPATH=str(evil)),timeout=10)
            expected=0 if scenario=='safe' and inner_exit in (None,0) else (255 if argv[4:] and argv[4]=='condition' else 1)
            if inner_exit is None and (not argv[4:] or argv[4]!='condition'):
                assert (result.returncode==0)==(scenario=='safe'),(scenario,result.stderr.decode())
            else:assert result.returncode==expected,(scenario,inner_exit,result.returncode,result.stderr.decode())
            assert b'inert-inner-sensitive' not in result.stderr
            if argv[4:] and argv[4]=='condition' and scenario!='safe':assert result.returncode==255,(scenario,result.returncode)
            assert marker.exists()==(scenario=='safe'), scenario
            if marker.exists(): assert json.loads(marker.read_text())==(argv[4:] if expected_args is None else expected_args)
            assert not poison.exists()


class Entrypoints(unittest.TestCase):
    def test_actual_validator_guards_and_private_transport_entrypoints(self):
        import eth_validator_units as validator
        fixture=fixtures.Runtime();fixture.setUp();self.addCleanup(fixture.doCleanups)
        selected=[('guard',unit) for unit in validator.UNITS[:4]]+[('engine-serve',None),('peer-observe',None)]
        for action,unit in selected:
            with self.subTest(action=action,unit=unit):
                command=validator.external('c'*64,action,unit)
                exercise(command,namespace.VALIDATOR_FILES,str(namespace.PROFILES['validator']['helpers']),
                    [action]+([] if unit is None else [unit]),fixed=True,script_name='eth_validator_control.py')

    def test_actual_numeric_service_guard_snapshot_completion_and_firewall_boot_programs(self):
        fixture=fixtures.Runtime();fixture.setUp();self.addCleanup(fixture.doCleanups)
        profile=namespace.RPC_FILES;prefix=str(namespace.PROFILES['rpc']['helpers'])
        for action,argument in [('guard','reth.service'),('guard','lighthouse.service'),('snapshot-guard','a'*32),('snapshot-complete','a'*32),('firewall-load',None)]:
            with self.subTest(action=action,argument=argument):
                command=units.external('c'*64,action,argument)
                exercise(command,profile,prefix,[action]+([] if argument is None else [argument]),fixed=True)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--ssh':exercise(sys.argv[2],namespace.RPC_FILES,'/usr/local/lib/erpc/ethereum-rpc')
    elif len(sys.argv)==3 and sys.argv[1]=='--validator-ssh':exercise(sys.argv[2],namespace.VALIDATOR_FILES,'/usr/local/lib/erpc/ethereum-validator',script_name='eth_validator_control.py')
    else:unittest.main()
