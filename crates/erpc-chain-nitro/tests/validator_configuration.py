#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline native configuration boundaries, no binary or key execution."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
path = Path(__file__).resolve().parents[1] / 'templates/validator/node/configuration.py'
sys.path.insert(0,str(path.parent))
spec = importlib.util.spec_from_file_location('bold_configuration', path)
configuration = importlib.util.module_from_spec(spec); spec.loader.exec_module(configuration)


class Configuration(unittest.TestCase):
    def test_observer_never_loads_wallet_or_acquires_transaction_authority(self):
        value = configuration.public('0x' + '1' * 40, 'observing')
        self.assertEqual(value['node']['staker']['strategy'], 'Watchtower')
        self.assertNotIn('parent-chain-wallet', value['node']['staker'])
        self.assertTrue(value['node']['block-validator']['enable'])
        self.assertNotIn('private-key', json.dumps(value))

    def test_active_changes_strategy_only_after_explicit_phase_selection(self):
        value = configuration.public('0x' + '1' * 40, 'active')
        self.assertEqual(value['node']['staker']['strategy'], 'MakeNodes')
        self.assertEqual(value['node']['staker']['parent-chain-wallet'], {
            'pathname': '', 'account': '0x' + '1' * 40, 'only-create-key': False})
        self.assertFalse(value['node']['bold']['auto-deposit'])
        self.assertFalse(value['node']['bold']['auto-increase-allowance'])
        self.assertFalse(value['node']['staker']['use-smart-contract-wallet'])
        self.assertFalse(value['node']['bold']['delegated-staking']['enable'])
        self.assertFalse(value['node']['staker']['disable-challenge'])
        self.assertNotIn('private-key', json.dumps(value))

    def test_both_modes_preserve_history_and_local_authenticated_block_validation(self):
        for phase in configuration.MODES:
            value = json.loads(json.dumps(configuration.public('0x' + '1' * 40, phase)))
            self.assertEqual(value['parent-chain']['connection']['url'],'https://127.0.0.1:18545')
            self.assertEqual(value['parent-chain']['blob-client']['beacon-url'],'https://127.0.0.1:15052')
            self.assertEqual(value['persistent']['chain'], '/data/chain')
            queue = value['node']['staker']['data-poster']
            self.assertTrue(queue['use-db-storage']); self.assertFalse(queue['use-noop-storage'])
            self.assertFalse(queue['dangerous']['clear-dbstorage'])
            self.assertTrue(queue['wait-for-l1-finality']); self.assertEqual(queue['max-mempool-transactions'], 1)
            self.assertEqual(value['node']['block-validator']['validation-server']['url'], 'self-auth')
            self.assertFalse(value['validation']['api-public'])
            self.assertTrue(value['validation']['wasm']['enable-wasmroots-check'])
            self.assertEqual(value['execution']['recording-database']['mode'], 'chain-tip')
            # Qualified native NodeConfig.Validate refuses PathDB with validation.
            self.assertEqual(value['execution']['caching']['state-scheme'],'hash')
            self.assertFalse(value['node']['batch-poster']['enable'])
            self.assertFalse(value['node']['sequencer'])
            self.assertFalse(value['execution']['sequencer']['enable'])
            self.assertFalse(value['init']['force'])
            self.assertTrue(value['init']['validate-checksum'])

    def test_no_arbitrary_mode_or_wallet_can_select_native_configuration(self):
        for phase in ('MakeNodes', 'validator', 'watchtower', '', None):
            with self.assertRaises(ValueError): configuration.public('0x' + '1' * 40, phase)
        for wallet in ('0x' + '0' * 40, '0x' + 'A' * 40, 'address', None):
            with self.assertRaises(ValueError): configuration.public(wallet, 'active')


if __name__ == '__main__': unittest.main()
