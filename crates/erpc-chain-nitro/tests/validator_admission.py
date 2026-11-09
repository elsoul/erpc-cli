#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert RPC transcript: no node, wallet, contract call or transaction execution."""
import importlib.util
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
path = Path(__file__).resolve().parents[1] / 'templates/validator/node/admission.py'
spec = importlib.util.spec_from_file_location('bold_admission', path)
admission = importlib.util.module_from_spec(spec); spec.loader.exec_module(admission)


class Admission(unittest.TestCase):
    def setUp(self):
        self.wallet = '0x' + '1' * 40
        self.now = 1793100000
        self.header = {'number': '0x100', 'timestamp': hex(self.now - 800), 'hash': '0x' + 'a' * 64}
        self.calls = []; self.balance = 1000; self.gas = 10**18
        self.public = True; self.staked = False; self.allocated = 0
        self.rollup_allowance = 1000; self.challenge_allowance = 1000
        self.changed = {}; self.final_header = None

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method == 'eth_chainId': return '0x1'
        if method == 'eth_getBlockByNumber':
            return self.final_header if params[0] == '0x100' and self.final_header is not None else self.header
        if method == 'eth_getCode': return '0x6001600055'
        if method == 'eth_getBalance': return hex(self.gas)
        self.assertEqual(method, 'eth_call')
        target = params[0]['to']; data = params[0]['data']
        name = next(name for name, selector in admission.SELECTORS.items() if data[2:10] == selector)
        args = data[10:]
        response = self.changed.get((target, name))
        if response is not None: return response
        values = {
            'rollup': admission.ROLLUP, 'chainId': 42161, 'bridge': admission.BRIDGE,
            'challengeManager': admission.CHALLENGE, 'assertionChain': admission.ROLLUP,
            'stakeToken': admission.WETH, 'challengeGracePeriodBlocks': 20,
            'wasmModuleRoot': 999, 'paused': 0, 'validatorWhitelistDisabled': int(self.public),
            'baseStake': 200, 'NUM_BIGSTEP_LEVEL': 1, 'isStaked': int(self.staked),
            'latestStakedAssertion': 12345,
            'amountStaked': self.allocated, 'withdrawalAddress': self.wallet, 'balanceOf': self.balance,
        }
        if name == 'stakeAmounts': value = [100, 20, 5][int(args, 16)]
        elif name == 'allowance':
            self.assertEqual('0x' + args[24:64], self.wallet)
            value = self.rollup_allowance if '0x' + args[88:] == admission.ROLLUP else self.challenge_allowance
        else: value = values[name]
        if isinstance(value, str): value = int(value[2:], 16)
        return '0x' + format(value, '064x')

    def test_single_finalized_snapshot_records_actual_budget_without_authorizing_activation(self):
        result = admission.observe(self.rpc, self.wallet, self.now)
        self.assertTrue(result['funding_checks_passed'])
        self.assertFalse(result['activation_authorized']); self.assertFalse(result['gas_adequacy_verified'])
        self.assertEqual(result['external_weth_budget_wei'], '325')
        self.assertEqual(result['challenge_path_bonds_wei'], ['100', '20', '5'])
        self.assertEqual(result['strategy'], 'MakeNodes')
        self.assertTrue(all(params[-1] == '0x100' for method, params in self.calls
                            if method in ('eth_getBalance', 'eth_call', 'eth_getCode')))
        self.assertTrue(all(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getBalance')
                            for method, _params in self.calls))

    def test_existing_original_stake_is_not_counted_twice_and_foreign_withdrawer_refuses(self):
        self.staked = True; self.allocated = 200; self.balance = 125; self.rollup_allowance = 0
        result = admission.observe(self.rpc, self.wallet, self.now)
        self.assertTrue(result['funding_checks_passed']); self.assertEqual(result['external_weth_budget_wei'], '125')
        self.changed[(admission.ROLLUP, 'withdrawalAddress')] = '0x' + ('2' * 40).rjust(64, '0')
        with self.assertRaisesRegex(ValueError, 'withdrawal'): admission.observe(self.rpc, self.wallet, self.now)

    def test_funding_approvals_and_permissioned_state_are_explicit_nonactivation_failures(self):
        self.public = False; self.balance = 1; self.gas = 0
        self.rollup_allowance = 0; self.challenge_allowance = 0
        result = admission.observe(self.rpc, self.wallet, self.now)
        self.assertFalse(result['funding_checks_passed']); self.assertEqual(len(result['problems']), 5)
        self.assertFalse(result['activation_authorized'])
        self.staked = True; self.allocated = 199
        result = admission.observe(self.rpc, self.wallet, self.now)
        self.assertIn('existing assertion deposit needs an external top-up', result['problems'])

    def test_paused_rollup_never_reports_ready_for_activation(self):
        self.changed[(admission.ROLLUP,'paused')] = '0x'+format(1,'064x')
        value = admission.observe(self.rpc,self.wallet,self.now)
        self.assertTrue(value['rollup_paused']); self.assertFalse(value['funding_checks_passed'])
        self.assertIn('qualified rollup is paused', value['problems'])

    def test_protocol_reassignment_wrong_chain_or_staking_token_never_qualifies(self):
        for target, method in ((admission.BRIDGE, 'rollup'), (admission.ROLLUP, 'bridge'),
                               (admission.ROLLUP, 'challengeManager'), (admission.CHALLENGE, 'assertionChain'),
                               (admission.ROLLUP, 'stakeToken'), (admission.CHALLENGE, 'stakeToken')):
            self.changed = {(target, method): '0x' + ('9' * 40).rjust(64, '0')}
            with self.subTest(method=method), self.assertRaises(ValueError): admission.observe(self.rpc, self.wallet, self.now)
        self.changed = {(admission.ROLLUP, 'chainId'): '0x' + format(1, '064x')}
        with self.assertRaises(ValueError): admission.observe(self.rpc, self.wallet, self.now)

    def test_stale_reorg_or_noncanonical_observation_never_returns_success(self):
        self.final_header = dict(self.header, hash='0x' + 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'changed'): admission.observe(self.rpc, self.wallet, self.now)
        self.final_header = None
        with self.assertRaisesRegex(ValueError, 'stale'): admission.observe(self.rpc, self.wallet, self.now + 2000)
        self.changed = {(admission.ROLLUP, 'validatorWhitelistDisabled'): '0x' + format(2, '064x')}
        with self.assertRaisesRegex(ValueError, 'boolean'): admission.observe(self.rpc, self.wallet, self.now)
        self.changed = {(admission.CHALLENGE, 'NUM_BIGSTEP_LEVEL'): '0x' + format(255, '064x')}
        with self.assertRaisesRegex(ValueError, 'level count'): admission.observe(self.rpc, self.wallet, self.now)
        for value in ('0x00', '0x', '-1', '0x' + 'f' * 65, True):
            with self.subTest(value=value), self.assertRaises(ValueError): admission.quantity(value)


if __name__ == '__main__': unittest.main()
