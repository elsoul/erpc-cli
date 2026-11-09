# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public Robinhood admission observations and unsigned administrator calldata.

The network identities come from the official pinned chain-info documents.
The ABI is nitro-contracts 4341b132cfbdcc980ead03765ca5224ff6cb5d97.
This module has no signer, wallet import, transaction submission or activation API.
The caller must authenticate the parent provider before supplying the RPC reader.
"""
import re
import time

import json
from pathlib import Path
CATALOG = json.loads(Path(__file__).with_name('catalog.json').read_text())
PROFILES = CATALOG['profiles']
SELECTORS = {'rollup': 'cb23bcb5', 'chainId': '9a8a0592', 'bridge': 'e78cea92',
    'stakeToken': '51ed6a30', 'validatorWhitelistDisabled': '12ab3d3b',
    'isValidator': 'facd743b', 'paused': '5c975abb', 'baseStake': '76e7e23b'}
SOURCE = CATALOG['contracts_source_commit']


def require(value, message):
    if not value: raise ValueError(message)


def address(value):
    require(isinstance(value, str) and re.fullmatch('0x[a-f0-9]{40}', value)
            and int(value[2:], 16) != 0, 'a canonical nonzero public address is required')
    return value


def quantity(value):
    require(isinstance(value, str) and re.fullmatch('0x(?:0|[1-9a-f][0-9a-f]{0,63})', value),
            'invalid bounded parent quantity')
    return int(value[2:], 16)


def word(value):
    require(isinstance(value, str) and re.fullmatch('0x[a-fA-F0-9]{64}', value),
            'invalid canonical ABI word')
    return int(value[2:], 16)


def observed_address(value):
    number = word(value)
    require(0 < number < 2**160, 'invalid canonical ABI address')
    return '0x' + format(number, '040x')


def boolean(value):
    number = word(value)
    require(number in (0, 1), 'invalid canonical ABI boolean')
    return number == 1


def header(value, now):
    require(isinstance(value, dict), 'finalized parent header is unavailable')
    number = quantity(value.get('number')); timestamp = quantity(value.get('timestamp'))
    block_hash = value.get('hash')
    require(number > 0 and isinstance(block_hash, str) and re.fullmatch('0x[a-f0-9]{64}', block_hash)
            and int(block_hash[2:], 16) != 0 and now-1800 <= timestamp <= now+30,
            'parent finalized observation is stale or malformed')
    return number, timestamp, block_hash


def calldata(validator):
    address(validator)
    # Two dynamic arrays, each exactly one element: offsets64/128, then length/value.
    fields = [64, 128, 1, int(validator[2:], 16), 1, 1]
    return '0xa3ffb772' + ''.join(format(value, '064x') for value in fields)


def observe(rpc, network, validator, now=None):
    require(network in PROFILES, 'Robinhood admission requires mainnet or testnet')
    address(validator); profile = PROFILES[network]
    now = int(time.time()) if now is None else now
    require(type(now) is int and now > 0, 'invalid observation time')
    require(quantity(rpc('eth_chainId', [])) == profile['parent'], 'wrong parent network')
    genesis = rpc('eth_getBlockByNumber', ['0x0', False])
    require(isinstance(genesis, dict) and genesis.get('hash') == profile['genesis'], 'wrong parent genesis')
    number, timestamp, block_hash = header(rpc('eth_getBlockByNumber', ['finalized', False]), now)
    block = hex(number)
    for target in (profile['bridge'], profile['rollup'], profile['stake_asset_address']):
        code = rpc('eth_getCode', [target, block])
        require(isinstance(code, str) and re.fullmatch('0x(?:[a-fA-F0-9]{2}){1,65536}', code)
                and any(value != '0' for value in code[2:]), 'qualified protocol contract is unavailable')
    # Dedicated EOA preparation does not silently prepare a smart-wallet sender.
    require(rpc('eth_getCode', [validator, block]) == '0x', 'dedicated sender must be a plain EOA')
    def read(target, method, argument=None):
        payload = '0x' + SELECTORS[method]
        if argument is not None: payload += address(argument)[2:].rjust(64, '0')
        return rpc('eth_call', [{'to': target, 'data': payload}, block])
    require(observed_address(read(profile['bridge'], 'rollup')) == profile['rollup'],
            'bridge selected another rollup; qualify its new public catalog before preparing admission')
    require(word(read(profile['rollup'], 'chainId')) == profile['child']
            and observed_address(read(profile['rollup'], 'bridge')) == profile['bridge']
            and observed_address(read(profile['rollup'], 'stakeToken')) == profile['stake_asset_address'],
            'Robinhood rollup identity or staking token differs')
    permissionless = boolean(read(profile['rollup'], 'validatorWhitelistDisabled'))
    listed = boolean(read(profile['rollup'], 'isValidator', validator))
    paused = boolean(read(profile['rollup'], 'paused'))
    base = word(read(profile['rollup'], 'baseStake'))
    require(header(rpc('eth_getBlockByNumber', [block, False]), now) == (number, timestamp, block_hash),
            'parent finalized snapshot changed during observation')
    return {'schema': 'erpc-robinhood-admission-observation-v1', 'network': network,
        'parent_chain_id': profile['parent'], 'child_chain_id': profile['child'],
        'parent_genesis': profile['genesis'], 'bridge': profile['bridge'], 'rollup': profile['rollup'],
        'stake_token': profile['stake_asset_address'], 'validator_address': validator,
        'block': block, 'block_hash': block_hash, 'block_timestamp': timestamp, 'observed_at': now,
        'allowlisted': listed, 'permissionless': permissionless, 'rollup_paused': paused,
        'admitted': listed or permissionless, 'base_stake_wei': str(base),
        'total_bond_budget_verified': False, 'funding_verified': False, 'administrator_authority_verified': False, 'deployed_implementation_verified': False,
        'activation_authorized': False, 'validator_runtime_verified': False,
        'financial_action_performed': False, 'contracts_source_commit': SOURCE}


def prepare(observed):
    network = observed['network']; profile = PROFILES[network]
    validator = address(observed['validator_address'])
    require(observed['rollup'] == profile['rollup'] and observed['parent_chain_id'] == profile['parent']
            and observed['contracts_source_commit'] == SOURCE, 'unqualified admission observation')
    return {'schema': 'erpc-robinhood-admission-intent-v1', 'network': network,
        'parent_chain_id': profile['parent'], 'child_chain_id': profile['child'],
        'parent_genesis': profile['genesis'], 'bridge': profile['bridge'], 'rollup': profile['rollup'],
        'validator_address': validator, 'value': '0x0', 'calldata': calldata(validator),
        'contracts_source_commit': SOURCE,
        'administrator_selected_externally': True, 'financial_action_performed': False,
        'snapshot': {name: observed[name] for name in ('block', 'block_hash', 'block_timestamp', 'observed_at')},
        'notice': CATALOG['external_review_notice']}


def validate(value, observed, rpc):
    expected = prepare(observed)
    require(isinstance(value, dict) and set(value) == set(expected), 'closed public admission intent required')
    require(all(type(value[name]) is type(item) and value[name] == item for name, item in expected.items() if name != 'snapshot'),
            'admission intent differs from the original network, sender or qualified administrative call')
    saved = value['snapshot']
    require(isinstance(saved, dict) and set(saved) == {'block', 'block_hash', 'block_timestamp', 'observed_at'}
            and type(saved['block_timestamp']) is int and saved['block_timestamp'] > 0
            and type(saved['observed_at']) is int and saved['observed_at'] <= observed['observed_at']
            and observed['observed_at']-saved['observed_at'] <= 1800,
            'admission intent needs fresh external preparation')
    saved_header = header({'number': saved['block'], 'hash': saved['block_hash'],
                           'timestamp': hex(saved['block_timestamp'])}, observed['observed_at'])
    require(saved_header[0] <= quantity(observed['block']),
            'admission intent snapshot is ahead of the verified parent')
    require(header(rpc('eth_getBlockByNumber', [saved['block'], False]), observed['observed_at']) == saved_header,
            'admission intent snapshot is not on the authenticated parent')
    require(header(rpc('eth_getBlockByNumber', [observed['block'], False]), observed['observed_at'])
            == (quantity(observed['block']), observed['block_timestamp'], observed['block_hash']),
            'parent finalized snapshot changed during intent validation')
    return {'intent_matches_current_observation': True, 'observation': observed,
        'administrator_authority_verified': False, 'deployed_implementation_verified': False,
        'activation_authorized': False, 'financial_action_performed': False}
