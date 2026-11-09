# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual compiled network bundle, strict units and carried fresh init routing."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from unittest.mock import patch
sys.dont_write_bytecode=True
raw=sys.stdin.buffer.read()
with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary).resolve();bundle=root/'bundle';bundle.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        files={member.name:archive.extractfile(member).read() for member in archive.getmembers()}
    for name,value in files.items():
        path=Path(name);assert not path.is_absolute() and '..' not in path.parts
        target=bundle/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(value)
    variables=next(iter(json.loads(files['inventory.yml'])['all']['hosts'].values()))
    request=variables['validator_request'];expected=request['contract'];network=expected['network']
    assert expected['family']=='robinhood' and expected['role']=='defensive-validator'
    assert variables['validator_family']=='robinhood' and variables['validator_ssh_port']==22
    node=bundle/'validator/node';sys.path.insert(0,str(node))
    import scope,control,host,publication,protocol,configuration,custody,credentials,parent_tls,storage,state,locking
    assert scope.NETWORK==network and scope.STRATEGY=='Defensive'
    assert scope.NAMESPACE=='robinhood-'+network+'-validator'
    with patch.object(storage,'ROOT_UID',os.getuid()),patch.object(storage,'TRUST_ANCHOR',root):
        assert publication.profile(node)[0]==request['target']['helpers_sha256']
    assert configuration.public(expected['wallet'],'active')['node']['staker']['strategy']=='Defensive'
    assert not configuration.public(expected['wallet'],'active')['node']['bold']['auto-deposit']
    assert not configuration.public(expected['wallet'],'active')['node']['bold']['auto-increase-allowance']
    protocol.request(request)
    for wrong in ('mainnet','testnet','sepolia'):
        if wrong==network:continue
        try:protocol.request(dict(request,contract=dict(expected,network=wrong)))
        except ValueError:pass
        else:raise AssertionError('foreign network reached the sealed native profile')
    try:
        from jinja2 import Environment,StrictUndefined
        import ansible,yaml
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar
    except ImportError:
        assert not os.environ.get('ERPC_REQUIRE_PINNED_ANSIBLE'),'pinned render cannot skip'
    else:
        assert ansible.__version__=='2.18.19'
        env=Environment(undefined=StrictUndefined,keep_trailing_newline=True)
        env.filters['to_json']=json.dumps
        for phase in ('observing','active'):
            variables['validator_request']['target']['phase']=phase
            units={name:env.from_string(files['validator/ansible/'+name+'.service.j2'].decode()).render(**variables) for name in ('nitro','upstreams','firewall')}
            import re
            for key in ('validator_runtime_command','validator_condition_command'):
                encoded=re.search(r"bytes\.fromhex\('([a-f0-9]+)'\)",variables[key])[1]
                program=bytes.fromhex(encoded).decode()
                compile(program,'<actual scoped systemd bootstrap>','exec')
                for _ in range(3):
                    if str(host.HELPERS/'control.py') in program:break
                    nested=re.search(r"bytes\.fromhex\('([a-f0-9]+)'\)",program)
                    assert nested,'missing scoped original executable in the generated bootstrap'
                    program=bytes.fromhex(nested[1]).decode()
                assert str(host.HELPERS/'control.py') in program
            for name,unit in units.items():
                assert 'User=0\nGroup=0' in unit and '/usr/bin/python3 -I -c ' in unit
                assert 'arbitrum' not in unit and ('testnet' if network=='mainnet' else 'mainnet') not in unit
                if name!='firewall':
                    assert 'ExecCondition='+variables['validator_condition_command'] in unit
                    assert 'ExecStart='+variables['validator_runtime_command'] in unit
                    assert 'ReadWritePaths='+str(host.ROOT)+' '+str(host.RUNTIME) in unit
                    assert 'Restart=no' in unit and 'LimitCORE=0' in unit
            assert ('LoadCredentialEncrypted='+custody.NAME+':'+str(host.CUSTODY/'wallet.cred') in units['nitro'])==(phase=='active')
            assert 'LoadCredentialEncrypted='+credentials.NAME+':'+str(host.UPSTREAM_CUSTODY/'upstreams.cred') in units['upstreams']
            assert 'LoadCredentialEncrypted='+parent_tls.NAME+':'+str(host.TLS_CUSTODY/'parent-tls.cred') in units['upstreams']
            assert 'BindsTo='+scope.SERVICES['transport'] in units['nitro']
            firewall=env.from_string(files['validator/ansible/firewall.nft.j2'].decode()).render(**variables)
            assert 'table inet erpc_robinhood' in firewall and 'tcp dport 22' in firewall and 'dport 18545' not in firewall
        task=yaml.safe_load(files['validator/ansible/prepare.yml'])[0]['tasks'][0]['ansible.builtin.command']
        actual=Templar(loader=DataLoader(),variables=dict(variables,playbook_dir=str(bundle/'validator/ansible'))).template(task)
        assert actual['argv']==['/usr/bin/python3','-I',str(bundle/'validator/ansible/../node/entry.py'),'play-init']
        assert json.loads(actual['stdin'])=={'action':'init','contract':expected}
    tests=Path(__file__).resolve().parents[2]/'erpc-chain-nitro/tests'
    sys.path.insert(0,str(tests));sys.path.insert(0,str(Path(__file__).parent))
    import validator_host,validator_state
    from arbitrum_volume_play import invoke
    original=validator_state.StateFailures.setUp
    def selected(fixture):original(fixture);fixture.contract=expected
    fixture=validator_host.Host('runTest')
    with patch.object(validator_state.StateFailures,'setUp',selected):fixture.setUp()
    try:
        # Model only OS/NSS/command boundaries. Real init owns all receipt and
        # data-layout mutation, including original-volume restart qualification.
        real_init=host.initialize
        def initialize(contract,quiet):return real_init(contract,quiet,fixture.command,fixture.fixture.account_command)
        with patch.object(host,'initialize',side_effect=initialize),patch.object(control.processes,'quiescent',side_effect=lambda records:fixture.quiet.append(records)),patch.object(locking,'CONTROL',fixture.root/'operation.lock'):
            for _ in range(2):
                code,stdout,stderr=invoke(node/'entry.py',['play-init'],{'action':'init','contract':expected},fixture.root)
                assert code==0 and not stderr,(code,stderr)
                assert json.loads(stdout)['initialized'] is True
        assert state.State(host.ROOT).get('owner.json')['phase']=='robinhood-defensive-v1'
        assert state.State(host.ROOT).get('volume-authority.json')['contract']==expected
        assert len(fixture.fixture.calls)==4,'retry recreated original numeric accounts'
    finally:fixture.doCleanups()
print('compiled network profile, eight strict renders and two actual carried original init calls passed')
