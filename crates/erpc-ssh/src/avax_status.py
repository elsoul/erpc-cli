# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
import json
import subprocess
import urllib.request


def rpc(path, method, params):
    try:
        request = urllib.request.Request('http://127.0.0.1:9650' + path, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.load(response)
    except Exception:
        return {'unavailable': True}


result = {'network': rpc('/ext/info', 'info.getNetworkID', {}),
          'identity': rpc('/ext/info', 'info.getNodeID', {}),
          'health': rpc('/ext/health', 'health.health', {}),
          'chain_id': rpc('/ext/bc/C/rpc', 'eth_chainId', []),
          'head': rpc('/ext/bc/C/rpc', 'eth_blockNumber', []),
          'uptime': rpc('/ext/info', 'info.uptime', {}),
          'version': rpc('/ext/info', 'info.getNodeVersion', {}),
          'bootstrap': {c: rpc('/ext/info', 'info.isBootstrapped', {'chain': c}) for c in ('P', 'X', 'C')}}
node = result['identity'].get('result', {}).get('nodeID')
if node:
    result['current'] = rpc('/ext/bc/P', 'platform.getCurrentValidators', {'nodeIDs': [node]})
for unit in ('avalanchego', 'avalanche-rpc'):
    result[unit] = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True).stdout.strip()
print(json.dumps(result))
