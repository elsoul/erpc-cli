#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Source-shaped read-only native replies; process ownership callbacks are inert."""
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import observer


class Observer(unittest.TestCase):
    def setUp(self):
        self.now = 1793100000; self.syncing = False
        self.hash = '0x' + 'a'*64; self.root = '0x' + 'b'*64
        self.head = {'number': '0x100', 'timestamp': hex(self.now - 2), 'hash': '0x' + 'c'*64}
        self.validated_block = {'number': '0xf0', 'timestamp': hex(self.now - 900), 'hash': self.hash}
        self.validated = {'GlobalState': {'BlockHash': self.hash, 'SendRoot': '0x' + '0'*64, 'Batch': 23, 'PosInBatch': 1},
                          'WasmRoots': [self.root]}
        self.protocol = {'funding_checks_passed': True, 'observed_at': self.now, 'wasm_module_root': self.root, 'permissionless': True,
                         'is_staked': True, 'latest_staked_assertion': '0x' + 'd'*64,
                         'existing_stake_wei': '200', 'assertion_bond_wei': '200', 'eth_balance_wei': '1'}
        self.version = 'nitro/v3.12.2+5f02f3f-20261002T123456Z/linux-amd64/go1.25'
        self.proof = {'pid': 234, 'start_time': 567, 'container_id': 'e'*64}
        self.changed = False

    def rpc(self, method, params):
        if method == 'eth_chainId': return '0xa4b1'
        if method == 'web3_clientVersion': return self.version
        if method == 'eth_syncing': return self.syncing
        if method == 'arb_latestValidated': return self.validated
        if method == 'eth_getBlockByHash': return self.validated_block
        self.assertEqual(method, 'eth_getBlockByNumber')
        if params[0] == 'latest': return self.head
        return dict(self.validated_block, hash='0x' + 'f'*64) if self.changed else self.validated_block

    def observe(self, phase='active', prove=None):
        return observer.inspect(self.rpc, prove or (lambda: self.proof), phase, self.protocol, self.now)

    def test_ready_native_validation_is_distinct_from_active_staked_participation(self):
        result = self.observe('observing')
        self.assertTrue(result['local_validation_ready']); self.assertFalse(result['validator_ready'])
        self.assertFalse(result['activation_authorized'])
        self.assertTrue(self.observe()['validator_ready'])
        self.protocol['funding_checks_passed'] = False
        self.assertFalse(self.observe()['validator_ready'])
        self.protocol['funding_checks_passed'] = True
        self.protocol['is_staked'] = False
        self.assertFalse(self.observe()['validator_ready'])
        self.protocol['is_staked'] = True; self.protocol['eth_balance_wei'] = '0'
        self.assertFalse(self.observe()['validator_ready'])

    def test_missing_validation_sync_or_old_execution_never_claims_readiness(self):
        self.validated = None
        with self.assertRaises(ValueError): self.observe()
        self.setUp(); self.syncing = {'currentBlock': '0x1'}
        with self.assertRaises(ValueError): self.observe()
        self.setUp(); self.head['timestamp'] = hex(self.now - 121)
        with self.assertRaises(ValueError): self.observe()
        self.setUp(); self.validated_block['timestamp'] = hex(self.now - 3601)
        with self.assertRaises(ValueError): self.observe()

    def test_native_result_uses_go_case_integer_shape_and_current_wasm_root(self):
        self.validated['GlobalState']['Batch'] = '0x1'
        with self.assertRaises(ValueError): self.observe()
        self.setUp(); self.validated['WasmRoots'] = ['0x' + '9'*64]
        with self.assertRaises(ValueError): self.observe()
        self.setUp(); self.protocol['observed_at'] -= 61
        with self.assertRaises(ValueError): self.observe()

    def test_canonical_chain_and_exact_process_rechecks_reject_spoofs_and_pid_reuse(self):
        self.changed = True
        with self.assertRaises(ValueError): self.observe()
        self.changed = False
        values = iter([self.proof, dict(self.proof, start_time=999)])
        with self.assertRaises(ValueError): self.observe(prove=lambda: next(values))
        with self.assertRaises(ValueError): self.observe(prove=lambda: False)

    def test_short_display_commit_is_qualified_but_modified_or_wrong_source_is_not(self):
        self.assertTrue(self.observe()['local_validation_ready'])
        self.version = self.version.replace('5f02f3f', observer.COMMIT)
        self.assertTrue(self.observe()['local_validation_ready'])
        for version in ('nitro/v3.12.2+bad-20261002T123456Z/linux',
                        'nitro/v3.12.2+5f02f3f-20261002T123456Z-modified/linux',
                        'nitro/v3.12.3+5f02f3f-20261002T123456Z/linux'):
            self.version = version
            with self.assertRaises(ValueError): self.observe()


if __name__ == '__main__': unittest.main()
