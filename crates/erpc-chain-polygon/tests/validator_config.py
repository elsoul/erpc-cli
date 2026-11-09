# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public validator transforms; Rust independently parses every emitted TOML."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('polygon_validator_config',root/'templates/scripts/configure.py')
config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)
rows=[]
for network in ('mainnet','amoy'):
    profile=json.loads((root/'networks'/(network+'.json')).read_text())
    for phase in ('observing','active'):
        bor={'chain':network,'p2p':{'discovery':{'dns':['inert-old-discovery']}},'protocol-marker':{'height':12345}}
        consensus={'p2p':{'seeds':'inert-old-peer'},'consensus':{'timeout_propose':'1s'}}
        app={'custom':{'chain':network,'amqp_url':'inert-old-broker'},'pruning':'default'}
        peers=[{'address':address,'bor_node_id':'ab'*64,'heimdall_node_id':'cd'*20}
            for address in ('192.0.2.2','2001:db8::3')]
        value={'signer':'0x'+'ab'*20,'sentries':peers,'phase':phase}
        allowed=lambda address:str(address) in ('192.0.2.1','192.0.2.2','2001:db8::3')
        rendered=config.profiles(profile,bor,consensus,app,'192.0.2.1',allowed,value)
        rows.append({'network':network,'phase':phase,'bor':rendered[0],'consensus':rendered[1],'app':rendered[2]})
        for invalid in ({'phase':'unknown'},{'signer':'0x'+'00'*20},{'sentries':[]},
                {'sentries':[peers[0],peers[0]]},{'sentries':[dict(peers[0],address='127.0.0.1')]},
                {'sentries':[dict(peers[0],bor_node_id='inert;exec')]},
                {'sentries':[dict(peers[0],heimdall_node_id='inert;exec')]}):
            try:config.validator_policy(copy.deepcopy(bor),copy.deepcopy(consensus),copy.deepcopy(app),dict(value,**invalid),allowed)
            except ValueError:pass
            else:raise AssertionError('unsafe validator configuration accepted')
print(json.dumps(rows))
