#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Official dynamic Validator ABI and controller binding over inert read-only IPC."""
import base64
import copy
import pathlib
import sys
import types
import unittest

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_admission as admission
from arc_files import Refused

PUBLIC = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='


def response(status=2, power=10, public=PUBLIC):
    key = base64.b64decode(public)
    words = (32, status, 96, power, len(key))
    return '0x' + (b''.join(value.to_bytes(32, 'big') for value in words) + key).hex()


class Admission(unittest.TestCase):
    def setUp(self):
        self.state = {'contract': {'chain_id': 5042002, 'genesis_hash': '0x' + 'a' * 64,
                                  'public_key': PUBLIC, 'controller': '0x' + 'b' * 40},
                      'policy': {'phase': 'validator', 'approved': True,
                                 'execution_peers': ['inert peer'], 'sentry_peers': ['inert sentry']}}
        self.head = {'hash': '0x' + 'c' * 64, 'number': '0x64', 'timestamp': '0x3e8'}
        self.status, self.power, self.calls = 2, 10, []
        self.context = types.SimpleNamespace(execution_call=self.call)
        self.genesis = self.state['contract']['genesis_hash']
        self.chain = 5042002
        self.synching = False
        self.registry_key = PUBLIC
        self.forked = False
        self.governance_error = False
        self.controller_unconfigured = False

    def call(self, _state, method, params):
        self.calls.append((method, params))
        if method == 'eth_chainId':
            return hex(self.chain)
        if method == 'eth_syncing':
            return self.synching
        if method == 'eth_getBlockByNumber':
            if params == ['0x0', False]:
                return {'hash': self.genesis}
            result = copy.deepcopy(self.head)
            if self.forked and params[0] != 'latest':
                result['hash'] = '0x' + 'd' * 64
            return result
        if method == 'eth_call':
            self.assertEqual(params[1], '0x64')
            contract, data = params[0]['to'], params[0]['data']
            if data[2:10] in admission.GOVERNANCE:
                self.assertEqual(contract, admission.MANAGER)
                self.assertEqual(params[0]['value'], '0x0')
                self.assertEqual(params[0]['from'], self.state['contract']['controller'])
                if self.governance_error: raise Refused('inert native EVM revert')
                return '0x'
            if data[2:10] == admission.REGISTRATION:
                if self.controller_unconfigured: raise Refused('inert ControllerNotConfigured')
                self.assertEqual(contract, admission.MANAGER)
                return '0x' + (3).to_bytes(32, 'big').hex()
            if data[2:10] == admission.MANAGER_VALIDATOR:
                self.assertEqual(contract, admission.MANAGER)
                return response(self.status, self.power)
            self.assertEqual(data[2:10], admission.REGISTRY_VALIDATOR)
            self.assertEqual(contract, admission.REGISTRY)
            self.assertEqual(int(data[10:], 16), 3)
            return response(self.status, self.power, self.registry_key)
        self.fail('unexpected native method')

    def test_active_positive_power_same_controller_key_and_stable_head_admits(self):
        result = admission.observe(self.context, self.state, now=1000)
        self.assertTrue(result['admitted'])
        self.assertEqual(result['registration_id'], '3')
        self.assertEqual(result['voting_power'], 10)
        self.assertEqual({name for name, _ in self.calls},
                         {'eth_call', 'eth_chainId', 'eth_getBlockByNumber', 'eth_syncing'})

    def test_registered_or_zero_power_never_enables_consensus(self):
        for self.status, self.power in ((1, 0), (2, 0), (1, 10)):
            self.assertFalse(admission.observe(self.context, self.state, now=1000)['admitted'])
            self.assertNotIn('activation_authorized', admission.observe(self.context, self.state, now=1000))

    def test_membership_observation_is_not_native_signing_authorization(self):
        changed = copy.deepcopy(self.state)
        changed['policy'] = {'phase': 'observer', 'approved': False, 'sentry_peers': [], 'execution_peers': []}
        result = admission.observe(self.context, changed, now=1000)
        self.assertTrue(result['admitted'])
        self.assertNotIn('activation_authorized', result)
        self.assertNotIn('ready', result)

    def test_foreign_genesis_key_chain_or_changed_head_cannot_admit(self):
        for field, value in [('genesis', '0x' + 'e' * 64), ('chain', 1), ('synching', {}),
                             ('registry_key', base64.b64encode(bytes(32)).decode()), ('forked', True)]:
            previous = getattr(self, field)
            setattr(self, field, value)
            with self.assertRaises(Refused):
                admission.observe(self.context, self.state, now=1000)
            setattr(self, field, previous)
        for timestamp in (100, 1121):
            self.head['timestamp'] = hex(timestamp)
            with self.assertRaises(Refused):
                admission.observe(self.context, self.state, now=1000)

    def intent(self, selector):
        original = self.state['contract']
        word = lambda value: value.to_bytes(32, 'big')
        arguments = {
            '602a9eee': word(32) + word(32) + base64.b64decode(PUBLIC),
            'd2c20cb3': bytes(12) + bytes.fromhex(original['controller'][2:]) + word(3) + word(10),
            '263a3402': b'', '4cb4850a': word(10), '7f77403d': b'',
        }[selector]
        return {'chain_id': original['chain_id'], 'genesis_hash': original['genesis_hash'],
                'to': admission.MANAGER, 'from': original['controller'], 'value': '0x0',
                'data': '0x' + selector + arguments.hex(), 'required_role': admission.GOVERNANCE[selector],
                'consensus_public_key': PUBLIC, 'admission_verified': False}

    def test_all_five_official_actions_are_only_simulated_at_the_qualified_original_head(self):
        for selector in admission.GOVERNANCE:
            self.calls.clear()
            result = admission.simulate(self.context, self.state, self.intent(selector), now=1000)
            self.assertTrue(result['evm_simulation_succeeded'])
            self.assertFalse(result['submitted'])
            self.assertFalse(result['production_activation_authorized'])
            self.assertFalse(result['private_signing_authority_verified'])
            self.assertEqual(result['block_hash'], self.head['hash'])
            self.assertEqual(sum('from' in params[0] for method, params in self.calls if method == 'eth_call'), 1)
            self.assertTrue(all(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_syncing', 'eth_call')
                                for method, _ in self.calls))

    def test_registration_validation_does_not_require_a_controller_assignment_that_is_not_created_yet(self):
        self.controller_unconfigured = True
        result = admission.simulate(self.context, self.state, self.intent('602a9eee'), now=1000)
        self.assertTrue(result['intent_validated'])
        self.assertFalse(result['submitted'])
        self.assertNotIn('registration_id', result)

    def test_foreign_registration_assignment_and_failed_evm_call_never_validate(self):
        self.registry_key = base64.b64encode(bytes(32)).decode()
        with self.assertRaises(Refused):
            admission.simulate(self.context, self.state, self.intent('d2c20cb3'), now=1000)
        self.assertFalse(any('from' in params[0] for method, params in self.calls if method == 'eth_call'))
        self.registry_key = PUBLIC
        self.governance_error = True
        with self.assertRaises(Refused):
            admission.simulate(self.context, self.state, self.intent('602a9eee'), now=1000)
        self.governance_error = False
        self.forked = True
        with self.assertRaises(Refused):
            admission.simulate(self.context, self.state, self.intent('602a9eee'), now=1000)

    def test_unknown_or_changed_governance_payload_refuses_before_any_transport(self):
        for field, value in [('chain_id', True), ('to', self.state['contract']['controller']),
                             ('value', '0x1'), ('data', '0xdeadbeef'), ('admission_verified', True),
                             ('required_role', 'unrelated-role'), ('consensus_public_key', 'changed')]:
            intent = self.intent('602a9eee'); intent[field] = value
            with self.assertRaises(Refused): admission.simulate(self.context, self.state, intent, now=1000)
        self.assertEqual(self.calls, [])

    def test_strict_dynamic_abi_refuses_offsets_lengths_status_power_and_garbage(self):
        good = response()
        raw = bytearray.fromhex(good[2:])
        for index, value in ((0, 64), (1, 3), (2, 32), (3, 2**64), (4, 31)):
            changed = bytearray(raw)
            changed[index * 32:(index + 1) * 32] = value.to_bytes(32, 'big')
            with self.assertRaises(Refused):
                admission.validator('0x' + changed.hex())
        for value in (good[:-2], good + '00', '0xzz', True, '0x' + '0' * 1000):
            with self.assertRaises(Refused):
                admission.validator(value)


if __name__ == '__main__':
    unittest.main()
