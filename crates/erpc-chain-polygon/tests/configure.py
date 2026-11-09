# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic configuration transforms, parsed independently by Rust's TOML parser."""
import importlib.util
import json
import hashlib
from pathlib import Path
import sys
from unittest.mock import patch
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('polygon_config_fixture',root/'templates/scripts/configure.py')
config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)
class Public:
    version=4;is_global=True;is_multicast=False
    def __str__(self):return '192.0.2.1'
rows=[]
for network in ('mainnet','amoy'):
    profile=json.loads((root/'networks'/(network+'.json')).read_text())
    bor={'chain':network,'p2p':{'discovery':{'static-nodes':['fixture-native-peer']}},'miner':{'mine':True},'protocol-marker':{'height':12345}}
    consensus={'p2p':{'seeds':'fixture-network-seed','external_address':'old-advertisement'},'consensus':{'timeout_propose':'1s'},'rpc':{'unsafe':True}}
    app={'custom':{'chain':network,'eth_rpc_url':'fixture-unsafe-upstream'},'pruning':'default'}
    with patch.object(config.ipaddress,'ip_address',return_value=Public()):
        result=config.profiles(profile,bor,consensus,app,'192.0.2.1',lambda address:str(address)=='192.0.2.1')
    rows.append({'network':network,'profile_digest':hashlib.sha256(json.dumps(profile,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'bor':result[0],'consensus':result[1],'app':result[2],'client':config.client(profile)})
    for invalid in ('127.0.0.1','10.0.0.1','224.0.0.1','::1','fe80::1'):
        try:config.profiles(profile,bor,consensus,app,invalid,lambda address:str(address)=='192.0.2.1')
        except ValueError:pass
        else:raise AssertionError('non-public advertisement accepted')
    try:config.profiles(dict(profile,network='unreviewed'),bor,consensus,app,'192.0.2.1',lambda address:str(address)=='192.0.2.1')
    except ValueError:pass
    else:raise AssertionError('cross-network source accepted')
print(json.dumps(rows))
