# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Loopback, read-only observations. Registration and activation are separate facts."""
import json
import re
import time
import urllib.request
from erpc_monad_common import execute, require
from erpc_monad_package import NoRedirect

STAKING = '0x' + '0' * 36 + '1000'


def rpc(method, params):
    require(method in ('eth_chainId', 'eth_syncing', 'eth_getBlockByNumber', 'eth_call'), 'read-only RPC method required')
    request = urllib.request.Request('http://127.0.0.1:8080',
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=15) as response:
        data = response.read(1048577)
        require(response.status == 200 and len(data) <= 1048576, 'invalid local RPC response')
    value = json.loads(data)
    require(isinstance(value, dict) and value.get('id') == 1 and 'result' in value and 'error' not in value,
            'local RPC result unavailable')
    return value['result']


def quantity(value):
    require(isinstance(value, str) and re.fullmatch('0x(?:0|[1-9a-f][0-9a-f]*)', value), 'invalid RPC quantity')
    return int(value, 16)


def health(c):
    result = {'ready': False, 'network': c['network'], 'public_identity': {k: c[k] for k in ('secp', 'bls')},
              'services': {}}
    for name in ('execution', 'bft', 'rpc', 'gateway'):
        active = execute(['/usr/bin/systemctl', 'is-active', 'erpc-monad-' + name + '.service'], check=False)
        result['services'][name] = active.returncode == 0 and active.stdout.strip() == b'active'
    try:
        chain = quantity(rpc('eth_chainId', []))
        block = rpc('eth_getBlockByNumber', ['finalized', False])
        height, timestamp = quantity(block['number']), quantity(block['timestamp'])
        syncing = rpc('eth_syncing', [])
        require(type(syncing) in (bool, dict), 'unknown synchronization response')
        result.update(chain_id=chain, height=height, block_timestamp=timestamp, syncing=syncing is not False)
        result['ready'] = (chain == (143 if c['network'] == 'mainnet' else 10143) and height > 0
                           and -30 <= time.time() - timestamp <= 120 and syncing is False
                           and all(result['services'].values()))
    except Exception:
        result['observation'] = 'RPC is not ready or cannot establish network/freshness'
    return result


def words(value):
    require(isinstance(value, str) and re.fullmatch('0x(?:[0-9a-f]{64})+', value)
            and len(value) <= 32770, 'invalid precompile ABI response')
    data = bytes.fromhex(value[2:])
    return data, [int.from_bytes(data[i:i+32], 'big') for i in range(0, len(data), 32)]


def dynamic(data, offset, length):
    require(offset % 32 == 0 and offset + 32 <= len(data), 'invalid dynamic ABI offset')
    require(int.from_bytes(data[offset:offset+32], 'big') == length
            and offset + 32 + ((length + 31) // 32) * 32 <= len(data), 'invalid public-key ABI length')
    return data[offset+32:offset+32+length].hex()


def registration(c, validator_id, call=rpc):
    require(c['role'] == 'validator' and type(validator_id) is int and 0 < validator_id < 2**64,
            'registration status requires a positive validator ID from the external receipt')
    block = call('eth_getBlockByNumber', ['finalized', False])
    number = block['number']
    quantity(number)
    block_hash = block.get('hash')
    require(isinstance(block_hash, str) and re.fullmatch('0x[0-9a-f]{64}', block_hash), 'invalid finalized block identity')
    tag = {'blockHash': block_hash}
    require(quantity(call('eth_chainId', [])) == (143 if c['network'] == 'mainnet' else 10143),
            'registration RPC network differs')
    require(-30 <= time.time() - quantity(block['timestamp']) <= 120, 'registration observation is stale')
    def query(selector, suffix=''):
        return words(call('eth_call', [{'to': STAKING, 'data': '0x' + selector + suffix}, tag]))
    data, fields = query('2b6d639a', f'{validator_id:064x}')
    require(len(fields) >= 12, 'validator response is incomplete')
    matches = (dynamic(data, fields[10], 33) == c['secp'] and dynamic(data, fields[11], 48) == c['bls']
               and '0x' + f'{fields[0]:040x}' == c['auth_address'])
    if not matches:
        return {'validator_id': validator_id, 'identity_matches': False, 'state': 'ID does not identify this node', 'block': number, 'block_hash': block_hash}
    _, epoch = query('757991a8')
    require(len(epoch) == 2 and epoch[1] in (0, 1), 'invalid epoch response')
    # Native this_epoch_valset() selects snapshot while in the boundary delay.
    selector = 'de66a368' if epoch[1] else 'fb29b729'
    cursor, members = 0, []
    for _ in range(3):
        array, page = query(selector, f'{cursor:064x}')
        require(len(page) >= 4 and page[0] in (0, 1) and page[2] == 96 and page[3] <= 100
                and len(page) == 4 + page[3], 'invalid validator-set page')
        members.extend(page[4:])
        if page[0]:
            break
        require(page[1] > cursor, 'validator-set cursor did not advance')
        cursor = page[1]
    else:
        raise ValueError('validator-set pagination exceeded the native bound')
    require(len(members) <= 200 and all(0 < value < 2**64 for value in members), 'invalid active set')
    _, delegator = query('573c1ce0', f'{validator_id:064x}' + c['auth_address'][2:].rjust(64, '0'))
    require(len(delegator) == 7, 'invalid auth-delegator response')
    return {'validator_id': validator_id, 'identity_matches': True, 'epoch': epoch[0], 'epoch_delay': bool(epoch[1]),
            'state': 'active in current epoch' if validator_id in members else 'registered but not active in current epoch',
            'block': number, 'block_hash': block_hash, 'flags': fields[1], 'total_stake_wei': str(fields[2]), 'auth_stake_wei': str(delegator[0]),
            'auth_pending_delta_wei': str(delegator[3]), 'auth_next_delta_wei': str(delegator[4]),
            'commission': str(fields[4]), 'transaction_submitted': False}
