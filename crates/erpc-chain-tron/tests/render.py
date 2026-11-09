# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Strict role/network/JVM templates; no provisioning or native client execution."""
import json
from pathlib import Path
import shlex
import jinja2
ROOT=Path(__file__).resolve().parents[1]/'templates/jinja'
env=jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT),undefined=jinja2.StrictUndefined,trim_blocks=True)
env.filters['to_json']=json.dumps
count=0
for network in ('mainnet','nile'):
    for role in ('fullnode','validator'):
        for architecture in ('x86_64','aarch64'):
            for allowed in ([],['192.0.2.0/24']):
                values={'tron_network':network,'tron_role':role,'tron_architecture':architecture,
                    'tron_service_guard':'''/usr/bin/python3 -I -c "exec(bytes.fromhex('696e657274'))"''',
                    'tron_firewall_guard':'''/usr/bin/python3 -I -c "exec(bytes.fromhex('696e657274'))"''',
                    'tron_release':'/opt/tron/releases/GreatVoyage-fixture-'+architecture,'tron_database':'LEVELDB' if architecture=='x86_64' else 'ROCKSDB',
                    'tron_owner':'public-owner-fixture','tron_management_allow':['192.0.2.1','2001:db8::1'],'tron_ssh_port':22,
                    'tron_rpc_allow':allowed,'tron_monitoring_allow':allowed,
                    'tron_contract_args':[network,role,'a'*64,architecture,'public-owner-fixture','public-signer-fixture','i'*26]}
                rendered={path.name:env.get_template(path.name).render(values) for path in ROOT.glob('*.j2')}
                service=rendered['tron-node.service.j2'];lines=service.splitlines()
                assert 'RequiresMountsFor=/var/lib/tron /opt/tron' in lines
                assert 'Requires=erpc-tron-firewall.service' in lines
                guard=shlex.split(next(line.split('=',1)[1] for line in lines if line.startswith('ExecStartPre=')))
                assert guard[:4]==['+/usr/bin/python3','-I','-c',"exec(bytes.fromhex('696e657274'))"]
                assert guard[4]=='runtime' and guard[5:]==values['tron_contract_args']
                assert 'ExecStart=/usr/bin/python3 -I /usr/local/lib/erpc/tron/launch.py' in lines
                assert ('LoadCredentialEncrypted=witness-password:' in service)==(role=='validator')
                firewall=rendered['firewall.nft.j2'];assert 'tcp dport 22 accept' in firewall
                assert ('192.0.2.0/24 tcp dport { 8090' in firewall)==(role=='fullnode' and bool(allowed))
                assert 'ConditionPathExists' not in rendered['erpc-tron-firewall.service.j2']
                assert 'ExecStart='+values['tron_firewall_guard']+' tron load' in rendered['erpc-tron-firewall.service.j2']
                assert all('{{' not in text and '{%' not in text for text in rendered.values())
                count+=1
print(str(count)+' strict network/role/architecture/access profiles; '+str(count*4)+' templates rendered')
