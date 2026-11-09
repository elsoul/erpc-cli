# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Owned native execution and block-validation health, distinct from activation.

arb_latestValidated is BlockValidatorAPI.LatestValidated in Nitro arbnode/api.go;
its default Go JSON fields are GlobalState/WasmRoots and BlockHash/SendRoot/
Batch/PosInBatch (staker/block_validator_schema.go, validator/execution_state.go).
Qualified source: 5f02f3f03076343061f167e81b8e82ec5518064b.
"""
import re
import scope
import time
from admission import quantity
from storage import require

COMMIT = scope.COMMIT


def digest(value):
    require(isinstance(value, str) and re.fullmatch('0x[0-9a-f]{64}', value), 'invalid native block identity')
    return value


def block(value):
    require(isinstance(value, dict), 'native block is unavailable')
    number = quantity(value.get('number')); timestamp = quantity(value.get('timestamp'))
    identity = digest(value.get('hash'))
    require(int(identity[2:], 16) != 0 and number > 0, 'native block identity is empty')
    return number, timestamp, identity


def inspect(rpc, prove, phase, protocol, now=None):
    require(phase in ('observing', 'active'), 'invalid original validator phase')
    now = int(time.time()) if now is None else now
    require(type(now) is int and type(protocol.get('observed_at')) is int
            and 0 <= now - protocol['observed_at'] <= 60, 'protocol observation is not current')
    original = prove()
    require(isinstance(original, dict) and type(original.get('pid')) is int and original['pid'] > 1
            and type(original.get('start_time')) is int and original['start_time'] > 0
            and isinstance(original.get('container_id'), str)
            and re.fullmatch('[0-9a-f]{64}', original['container_id']),
            'native runtime ownership is not established')
    require(rpc('eth_chainId', []) == hex(scope.CHILD_ID), 'native child chain differs from sealed profile')
    client = rpc('web3_clientVersion', [])
    # The native Go build-info fallback truncates the displayed commit to7.
    # Full content/source authority comes from the proved immutable OCI image.
    revision = r'(?:^|/)v?' + re.escape(scope.VERSION) + r'\+(?:' + COMMIT + '|' + COMMIT[:7] + r')-[0-9]{8}T[0-9]{6}Z(?:/|$)'
    require(isinstance(client, str) and len(client) <= 256 and re.search(revision, client)
            and '-modified' not in client, 'native version differs from the reviewed image')
    syncing = rpc('eth_syncing', [])
    require(syncing is False, 'native execution is still synchronizing')
    number, timestamp, identity = block(rpc('eth_getBlockByNumber', ['latest', False]))
    require(-30 <= now - timestamp <= 120, 'native execution head is stale')
    validated = rpc('arb_latestValidated', [])
    require(isinstance(validated, dict) and set(validated) == {'GlobalState', 'WasmRoots'},
            'native block validation has not produced a qualified result')
    global_state, roots = validated['GlobalState'], validated['WasmRoots']
    require(isinstance(global_state, dict) and set(global_state) == {'BlockHash', 'SendRoot', 'Batch', 'PosInBatch'}
            and all(type(global_state[name]) is int and 0 <= global_state[name] < 2**64
                    for name in ('Batch', 'PosInBatch')), 'invalid native validated global state')
    digest(global_state['SendRoot']); validated_hash = digest(global_state['BlockHash'])
    require(isinstance(roots, list) and 1 <= len(roots) <= 16 and len(set(roots)) == len(roots)
            and all(digest(value) for value in roots) and protocol['wasm_module_root'] in roots,
            'native validation does not include the current on-chain WASM root')
    validated_number, validated_time, actual_hash = block(rpc('eth_getBlockByHash', [validated_hash, False]))
    require(actual_hash == validated_hash and validated_number <= number
            and -30 <= now - validated_time <= 3600, 'native validated execution is missing, stale or ahead of its head')
    # Detect local reorgs/replacements instead of accepting a matching response
    # once. The proof callback binds service/container/PID/start time/listeners.
    require(block(rpc('eth_getBlockByNumber', [hex(validated_number), False])) ==
            (validated_number, validated_time, validated_hash), 'native validated block is not canonical')
    require(prove() == original, 'native process or listener changed during observation')
    active = (phase == 'active' and protocol.get(scope.ADMISSION_KEY) is True
              and protocol.get('funding_checks_passed') is True
              and (not scope.REQUIRES_EXISTING_STAKE or (protocol.get('is_staked') is True
                   and protocol.get('latest_staked_assertion') is not None
                   and int(protocol['existing_stake_wei']) >= int(protocol['assertion_bond_wei'])))
              and int(protocol['eth_balance_wei']) > 0)
    return {'phase': phase, 'strategy': scope.STRATEGY if phase == 'active' else 'Watchtower',
            'local_validation_ready': True, 'validator_ready': active,
            'block': hex(number), 'block_hash': identity, 'block_age_seconds': now - timestamp,
            'validated_block': hex(validated_number), 'validated_block_hash': validated_hash,
            'validated_age_seconds': now - validated_time, 'wasm_module_root': protocol['wasm_module_root'],
            'original_wallet_staked': protocol.get('is_staked') is True,
            'latest_staked_assertion': protocol.get('latest_staked_assertion'),
            'funding_reserve_sufficient': protocol.get('funding_checks_passed') is True,
            'gas_adequacy_verified': False, 'activation_authorized': False}
