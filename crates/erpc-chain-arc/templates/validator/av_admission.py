#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only original-controller admission at one source-qualified execution head."""
import base64
import re
import time

from arc_files import require

MANAGER = '0x3600000000000000000000000000000000000003'
REGISTRY = '0x3600000000000000000000000000000000000002'
# First four Keccak-256 bytes of the exact pinned Solidity signatures. Rust
# regression derives these independently with the existing sha3 dependency.
MANAGER_VALIDATOR = '1904bb2e'  # getValidator(address)
REGISTRATION = 'd773a741'       # getRegistrationId(address)
REGISTRY_VALIDATOR = 'b5d89627' # getValidator(uint256)


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,63})', value),
            'invalid native execution quantity')
    return int(value, 16)


def encoded(value, limit):
    require(isinstance(value, str) and value.startswith('0x') and len(value) % 2 == 0 and
            len(value) <= 2 + limit * 2 and re.fullmatch('[0-9a-f]*', value[2:]),
            'invalid or oversized native ABI result')
    return bytes.fromhex(value[2:])


def validator(value):
    raw = encoded(value, 192)
    require(len(raw) in (160, 192), 'unexpected native validator ABI tuple length')
    words = [int.from_bytes(raw[index:index + 32], 'big') for index in range(0, 160, 32)]
    offset, status, key_offset, power, length = words
    require(offset == 32 and status in (0, 1, 2) and key_offset == 96 and power < 2**64 and
            length in (0, 32) and len(raw) == 160 + length,
            'native validator ABI offsets, enum, key or power are invalid')
    require(length == 32 or (status == 0 and power == 0), 'registered validator has no native public key')
    return {'status': status, 'public_key': base64.b64encode(raw[160:]).decode(), 'voting_power': power}


def execution_head(context, state, now=None):
    original = state['contract']
    # Each call must use the controller's bound original EL IPC transport; this
    # module never accepts a caller URL or queries arbitrary public RPCs.
    call = lambda method, params: context.execution_call(state, method, params)
    require(quantity(call('eth_chainId', [])) == original['chain_id'],
            'native validator execution network differs')
    genesis = call('eth_getBlockByNumber', ['0x0', False])
    require(isinstance(genesis, dict) and genesis.get('hash') == original['genesis_hash'],
            'native validator execution genesis differs')
    require(call('eth_syncing', []) is False, 'native validator execution is still synchronizing')
    head = call('eth_getBlockByNumber', ['latest', False])
    require(isinstance(head, dict) and isinstance(head.get('hash'), str) and
            re.fullmatch('0x[0-9a-f]{64}', head['hash']), 'native admission head is unavailable')
    number, timestamp = quantity(head.get('number')), quantity(head.get('timestamp'))
    clock = time.time() if now is None else now
    require(number > 0 and clock - 300 <= timestamp <= clock + 120,
            'native admission head is stale or ahead of the host clock')
    return head


def observe(context, state, now=None, head=None):
    original = state['contract']
    head = execution_head(context, state, now) if head is None else head
    number = quantity(head['number'])
    call = lambda method, params: context.execution_call(state, method, params)
    controller = original['controller']
    require(isinstance(controller, str) and re.fullmatch('0x[0-9a-f]{40}', controller) and
            int(controller[2:], 16) != 0, 'original external controller is invalid')
    address = '0' * 24 + controller[2:]
    block = head['number']
    def abi(to, data):
        return call('eth_call', [{'to': to, 'data': '0x' + data}, block])
    registration_raw = encoded(abi(MANAGER, REGISTRATION + address), 32)
    require(len(registration_raw) == 32 and int.from_bytes(registration_raw, 'big') > 0,
            'external controller has no registered native validator')
    managed = validator(abi(MANAGER, MANAGER_VALIDATOR + address))
    registered = validator(abi(REGISTRY, REGISTRY_VALIDATOR + registration_raw.hex()))
    require(managed == registered and managed['public_key'] == original['public_key'],
            'external controller is assigned to another consensus identity')
    after = call('eth_getBlockByNumber', [block, False])
    require(isinstance(after, dict) and after.get('hash') == head['hash'] and after.get('number') == block,
            'native admission head changed during observation')
    return {'registration_id': str(int.from_bytes(registration_raw, 'big')),
            'controller': controller, 'public_key': managed['public_key'],
            'status': ('unknown', 'registered', 'active')[managed['status']],
            'voting_power': managed['voting_power'], 'block_number': number,
            'block_hash': head['hash'], 'admitted': managed['status'] == 2 and managed['voting_power'] > 0}


# Exact native management selectors, independently checked against Rust Keccak-256.
GOVERNANCE = {'602a9eee': 'validator-registerer',
              'd2c20cb3': 'permissioned-validator-manager-owner',
              '263a3402': 'configured-controller',
              '4cb4850a': 'configured-controller-with-sufficient-power-limit',
              '7f77403d': 'configured-controller'}


def public_intent(state, intent):
    original = state['contract']
    require(isinstance(intent, dict) and set(intent) == {'chain_id', 'genesis_hash', 'to', 'from', 'value',
            'data', 'required_role', 'consensus_public_key', 'admission_verified'}, 'invalid public governance intent')
    require(type(intent['chain_id']) is int and intent['chain_id'] == original['chain_id'] and
            intent['genesis_hash'] == original['genesis_hash'] and intent['to'] == MANAGER and
            intent['value'] == '0x0' and intent['consensus_public_key'] == original['public_key'] and
            intent['admission_verified'] is False and isinstance(intent['from'], str) and
            re.fullmatch('0x[0-9a-f]{40}', intent['from']) and int(intent['from'][2:], 16) > 0,
            'public governance intent differs from original network, manager or signer')
    raw = encoded(intent['data'], 100)
    selector = raw[:4].hex()
    require(selector in GOVERNANCE and intent['required_role'] == GOVERNANCE[selector],
            'unknown governance selector or role')
    if selector == '602a9eee':
        expected = (32).to_bytes(32, 'big') * 2 + base64.b64decode(original['public_key'], validate=True)
        require(raw[4:] == expected, 'registration cannot replace the original external public key')
    elif selector == 'd2c20cb3':
        require(len(raw) == 100 and raw[4:36] == bytes(12) + bytes.fromhex(original['controller'][2:]) and
                0 < int.from_bytes(raw[36:68], 'big') < 2**64 and
                0 < int.from_bytes(raw[68:], 'big') < 2**64,
                'controller assignment or registration/power identifier differs')
    else:
        require(intent['from'] == original['controller'], 'only the original external controller can request this action')
        require((selector in ('263a3402', '7f77403d') and len(raw) == 4) or
                (selector == '4cb4850a' and len(raw) == 36 and 0 < int.from_bytes(raw[4:], 'big') < 2**64),
                'unexpected governance arguments')
    return selector, raw


def simulate(context, state, intent, now=None):
    selector, raw = public_intent(state, intent)
    head = execution_head(context, state, now)
    block = head['number']
    call = lambda method, params: context.execution_call(state, method, params)
    if selector == 'd2c20cb3':
        registered = validator(call('eth_call', [{'to': REGISTRY,
            'data': '0x' + REGISTRY_VALIDATOR + raw[36:68].hex()}, block]))
        require(registered['public_key'] == state['contract']['public_key'] and registered['status'] in (1, 2),
                'requested registration identifier belongs to another external consensus key')
    elif selector != '602a9eee':
        # Observe the original controller/key binding at the exact simulation block.
        observe(context, state, now, head=head)
    result = call('eth_call', [{key: intent[key] for key in ('to', 'from', 'data', 'value')}, block])
    encoded(result, 256)
    after = call('eth_getBlockByNumber', [block, False])
    require(isinstance(after, dict) and after.get('hash') == head['hash'] and after.get('number') == block,
            'governance simulation head changed')
    return {'intent_validated': True, 'evm_simulation_succeeded': True,
            'block_number': quantity(block), 'block_hash': head['hash'],
            'private_signing_authority_verified': False, 'funding_verified': False,
            'deployed_governance_implementation_verified': False,
            'submitted': False, 'production_activation_authorized': False}
