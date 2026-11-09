# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded public bootstrap observations and fixed loopback readiness checks."""
import datetime
import ipaddress
import json
import re
import time
import urllib.request

from erpc_hl_common import require, unique_json

EXCLUDED_V4 = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('public bootstrap redirects are refused')


def public_ipv4(value):
    require(isinstance(value, str) and len(value) <= 15, 'public IPv4 address required')
    parsed = ipaddress.IPv4Address(value)
    require(str(parsed) == value and not any(parsed in subnet for subnet in EXCLUDED_V4),
            'peer address is outside public IPv4 unicast')
    return value


def post(url, body):
    require(url in ('https://api.hyperliquid.xyz/info', 'https://api.hyperliquid-testnet.xyz/info',
                    'http://127.0.0.1:3001/info', 'http://127.0.0.1:3001/evm'),
            'unqualified public observation endpoint')
    request = urllib.request.Request(url, data=json.dumps(body, separators=(',', ':')).encode(),
                                    headers={'Content-Type': 'application/json', 'User-Agent': 'erpc-node-controller'})
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=10) as response:
        require(response.status == 200 and response.geturl() == url, 'public observation origin changed')
        raw = response.read(1048577)
    require(len(raw) <= 1048576, 'public observation exceeded bounds')
    return unique_json(raw)


def root_peers(profile):
    # Official instructions require an explicit mainnet root. Testnet supports
    # the native client's default discovery and currently returns an empty list.
    if profile['chain'] == 'Testnet':
        return None
    require(profile['chain'] == 'Mainnet', 'unsupported native chain selector')
    response = post(profile['info_url'], {'type': 'gossipRootIps'})
    require(isinstance(response, list) and 0 < len(response) <= 256, 'official root peer observation is empty or oversized')
    peers = sorted(set(public_ipv4(value) for value in response))
    require(0 < len(peers) <= 64, 'unexpected official root peer count')
    return {'root_node_ips': [{'Ip': value} for value in peers], 'chain': profile['chain']}


def evm(method, params):
    require(method in ('eth_chainId', 'eth_getBlockByNumber'), 'unsupported readiness method')
    result = post('http://127.0.0.1:3001/evm', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    require(isinstance(result, dict) and result.get('jsonrpc') == '2.0'
            and type(result.get('id')) is int and result['id'] == 1 and 'error' not in result and 'result' in result,
            'native EVM readiness response is invalid')
    return result['result']


def observe(profile, now=None):
    """Readiness requires native EVM and HyperCore freshness, never a guessed peer count."""
    current = time.time() if now is None else now
    result = {'ready': False, 'chain_id': profile['chain_id']}
    try:
        chain = evm('eth_chainId', [])
        require(chain == hex(profile['chain_id']), 'native EVM network differs')
        head = evm('eth_getBlockByNumber', ['latest', False])
        require(isinstance(head, dict) and all(isinstance(head.get(key), str)
            and re.fullmatch('0x[0-9a-fA-F]{1,16}', head[key]) for key in ('number', 'timestamp'))
            and isinstance(head.get('hash'), str) and re.fullmatch('0x[0-9a-fA-F]{64}', head['hash']),
            'native EVM head is malformed')
        core = post('http://127.0.0.1:3001/info', {'type': 'exchangeStatus'})
        require(isinstance(core, dict) and type(core.get('time')) is int and 0 < core['time'] < 2**63,
                'native HyperCore time is unavailable')
        core_age = current - core['time'] / 1000
        evm_age = current - int(head['timestamp'], 16)
        result.update(block=int(head['number'], 16), block_hash=head['hash'],
                      evm_age_seconds=evm_age, core_age_seconds=core_age,
                      observed_at=datetime.datetime.fromtimestamp(current, datetime.timezone.utc).isoformat())
        result['ready'] = -30 <= core_age <= 120 and -30 <= evm_age <= 120 and result['block'] > 0
    except Exception:
        result['inspection_error'] = 'native network or fresh EVM/HyperCore observation unavailable'
    return result
