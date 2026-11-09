# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled CLI inventory/play -> actual setup entry, with inert native effects."""
import base64
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]/'erpc-chain-near'
sys.path.insert(0,str(ROOT/'tests'))
from lifecycle import ForwardUpgrade,c,s


def exercise(raw):
    with tempfile.TemporaryDirectory() as temporary:
        bundle=Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive:
                path=Path(member.name)
                assert member.isfile() and not path.is_absolute() and '..' not in path.parts
                output=bundle/path;output.parent.mkdir(parents=True,exist_ok=True)
                output.write_bytes(archive.extractfile(member).read())
        for module in (c,s):
            assert (bundle/'node'/Path(module.__file__).name).read_bytes()==Path(module.__file__).read_bytes()
        inventory=json.loads((bundle/'inventory.yml').read_text())
        variables=inventory['all']['hosts']['fixture']
        request=variables['near_prepare'];assert request['allow_pending_upgrade'] is True
        expected=json.loads(base64.b64decode(variables['near_contract']))
        play=bundle/'node/prepare.yml';templated=False
        try:
            import ansible,yaml
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:
            argv=[str(bundle/'node/setup.py'),variables['near_contract']]
            stdin=json.dumps(request)
        else:
            assert ansible.__version__=='2.18.19'
            tasks=yaml.safe_load(play.read_text())[0]['tasks']
            task=next(task['ansible.builtin.command'] for task in tasks
                      if 'ansible.builtin.command' in task and 'setup.py' in str(task['ansible.builtin.command']))
            rendered=Templar(loader=DataLoader(),variables=dict(variables,playbook_dir=str(play.parent))).template(task)
            assert rendered['argv'][:2]==['/usr/bin/python3','-I']
            argv=rendered['argv'][2:];stdin=rendered['stdin'];assert json.loads(stdin)==request
            templated=True
        fixture=ForwardUpgrade('runTest');fixture.setUp()
        try:
            assert fixture.expected==expected
            fixture.target['policy_sha256']=request['policy_sha256']
            fixture.old['policy_sha256']=request['policy_sha256']
            fixture.bootstrap['request']['policy']=request['policy_sha256'];fixture.seed()
            directory=fixture.control.path('/etc/near')
            original=json.dumps({'rpc':{},'network':{},'store':{}}).encode()
            (directory/'source-config.json').write_bytes(original)
            profile=dict(c.PINS['mainnet'],config_sha256=fixture.control.digest(original),genesis_sha256=fixture.old['genesis_sha256'])
            fixture.control.write('genesis-source.json',{'network':'mainnet','source_sha256':profile['genesis_sha256']})
            cpu=fixture.control.path('/proc/cpuinfo');cpu.parent.mkdir();cpu.write_text('flags: cx16 popcnt sse4_1 sse4_2 avx sha_ni\n')
            def docker(*args):
                assert args[0]=='pull' or args[-1]=='--version','no native node or key generation in fixture'
                value=('neard (release '+profile['version']+') (build fixture) (commit '+profile['commit']+')').encode()
                return subprocess.CompletedProcess(args,0,value,b'')
            output=io.StringIO()
            with patch.dict(c.PINS,{'mainnet':profile}),patch.object(s,'Control',return_value=fixture.control), \
                 patch.object(fixture.control,'docker',side_effect=docker), \
                 patch.object(s,'fetch',side_effect=AssertionError('must retain verified original source')), \
                 patch.object(s,'observe_bootstrap',side_effect=AssertionError('must retain original peers')), \
                 patch.object(sys,'argv',argv),patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(stdin.encode()))), \
                 contextlib.redirect_stdout(output):
                s.main()
            result=json.loads(output.getvalue());assert result['version']=='2.14.0'
            assert fixture.control.read('operation.json')=={'intent':request['intent']}
            fixture.old_activation_refused();fixture.unchanged()
            return {'version':result['version'],'templated':templated,'original_data_preserved':True}
        finally:fixture.doCleanups()


if __name__=='__main__':print(json.dumps(exercise(sys.stdin.buffer.read())))
