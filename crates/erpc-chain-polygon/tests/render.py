# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Strict Jinja matrix and real service sealing; no native clients are executed."""
import json
from pathlib import Path
import shlex
import sys
import jinja2
ROOT=Path(__file__).resolve().parents[1]
ENV=jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT/'templates/jinja'),undefined=jinja2.StrictUndefined,trim_blocks=True)
ENV.filters['to_json']=json.dumps
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'templates/scripts'))
import state,install

def values(profile,architecture,contract,helpers,acl):
    return dict(polygon_runtime_accounts={name:{'uid':uid,'gid':uid} for name,uid in [('bor',1001),('heimdall',1002),('parent',1003)]},polygon_credential_condition=install.service_condition(ROOT/'templates/scripts/control.py','/usr/local/lib/erpc/polygon/releases/'+helpers+'/control.py'),polygon_service_guard=install.service_guard(ROOT/'templates/scripts/control.py','/usr/local/lib/erpc/polygon/releases/'+helpers+'/control.py'),polygon_network=profile['network'],polygon_profile=profile,polygon_contract=contract,polygon_helpers=helpers,
        polygon_management_v4=['192.0.2.1'],polygon_management_v6=['2001:db8::1'],polygon_rpc_v4=acl[0],polygon_rpc_v6=acl[1],
        polygon_metrics_v4=acl[0],polygon_metrics_v6=acl[1],polygon_ssh_port=2222,polygon_architecture=architecture)

def render(v):
    result={name:ENV.get_template(name+'.j2').render(v) for name in ('parent.service','firewall.service','firewall.nft')}
    for component in ('bor','heimdall'):
        result[component+'.service']=ENV.get_template('native.service.j2').render(dict(v,polygon_component=component))
    return result

def matrix():
    count=0
    for network in ('mainnet','amoy'):
        profile=json.loads((ROOT/'networks'/(network+'.json')).read_text())
        for arch in ('x86_64','aarch64'):
            contract=state.contract(network,'i'*26,arch,profile['bor_genesis_hash'],profile['heimdall_genesis']['sha256'])
            for acl in (([],[]),(['198.51.100.0/24'],[]),([],['2001:db8:1::/48'])):
                v=values(profile,arch,contract,'a'*64,acl);rendered=render(v)
                for component in ('bor','heimdall','parent'):
                    unit=rendered[component+'.service'];lines=unit.splitlines()
                    argv=shlex.split(next(line.removeprefix('ExecStartPre=') for line in lines if line.startswith('ExecStartPre=')))
                    assert argv[:2]==['+/usr/bin/python3','-I'];assert json.loads(argv[-1])==contract
                    assert argv[-3:-1]==['runtime',component] and argv[2]=='-c'
                    program=bytes.fromhex(argv[3].split("'")[1]).decode();assert '/releases/'+'a'*64+'/' in program
                    assert program.index('trusted_imports(')<program.index('runpy.run_path(')
                    assert 'ConditionPathExists' not in unit and 'Requires=erpc-polygon-firewall.service' in unit
                    assert 'ProtectSystem=strict' in lines and 'NoNewPrivileges=true' in lines
                    assert 'LoadCredentialEncrypted=' in unit
                    conditions=[line for line in lines if line.startswith('ExecCondition=')]
                    assert len(conditions)==1 and ' credential-condition '+component+' ' in conditions[0]
                    assert 'User='+str(v['polygon_runtime_accounts'][component]['uid']) in lines
                    assert 'Group='+str(v['polygon_runtime_accounts'][component]['gid']) in lines
                    assert 'LimitCORE=0' in lines and 'SupplementaryGroups=' in lines and 'DynamicUser=no' in lines

                    assert 'Requires=erpc-polygon-firewall.service' in lines
                    assert 'Restart=on-failure' in lines and 'StartLimitIntervalSec=0' in lines
                assert 'Wants=network-online.target polygon-heimdall.service' in rendered['bor.service']
                assert 'Wants=network-online.target polygon-l1-proxy.service' in rendered['heimdall.service']
                assert 'ConditionPathExists' not in rendered['firewall.service']
                assert 'ExecStart='+v['polygon_service_guard']+' firewall ' in rendered['firewall.service']
                policy=rendered['firewall.nft'];assert 'tcp dport 2222 accept' in policy and 'counter drop' in policy
                assert ('ip saddr 198.51.100.0/24 tcp dport { 8545, 8546 } accept' in policy)==bool(acl[0])
                assert ('ip6 saddr 2001:db8:1::/48 tcp dport { 8545, 8546 } accept' in policy)==bool(acl[1])
                assert all('{{' not in text and '{%' not in text for text in rendered.values());count+=1
    # Feed the actual rendered service definitions through the real sealing gate.
    import importlib.util
    spec=importlib.util.spec_from_file_location('polygon_control_tests',ROOT/'tests/control.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    test=fixture.Lifecycle();test.setUp()
    try:
        rendered=render(values(test.profile,'x86_64',test.contract,test.control.helpers,([],[])))
        for component,unit in [('bor','polygon-bor'),('heimdall','polygon-heimdall'),('parent','polygon-l1-proxy')]:
            test.file('/etc/systemd/system/'+unit+'.service',rendered[component+'.service'].encode())
        test.control.dispatch(dict(test.request,action='seal'))
        installed=install.installed(test.state,test.contract)
        assert set(installed['units'])=={'polygon-bor','polygon-heimdall','polygon-l1-proxy'}
    finally:test.doCleanups()
    print(str(count)+' strict network/architecture/ACL profiles (60 template renders), rendered units sealed by native controller')
if __name__=='__main__':matrix()
