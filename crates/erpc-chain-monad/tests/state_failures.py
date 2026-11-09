#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import erpc_monad_common as common
import erpc_monad_state as state


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.patch = patch.object(state, 'read', lambda p: common.read(p, owner=os.getuid()))
        self.patch.start()
        self.state = state.State(self.directory)
        self.contract = {'network': 'testnet', 'owner': 'inert-fixture'}
        self.target = {'version': '0.16.5', 'config': 'inert'}
        self.first, self.second = 'a' * 32, 'b' * 32
        self.state.put('owner.json', {'contract': self.contract})
        self.state.authorize(self.contract, self.first, self.target)
        self.state.begin(self.contract, self.first, self.target, lambda: None)
        self.state.finish(self.contract, self.first, {'files': {}})

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def fails(self):
        raise OSError('inert failure')

    def test_failed_new_intent_publication_revokes_previous_activation(self):
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.guard(self.contract, self.first)

    def test_failed_supersession_cannot_finish_an_old_install_and_clear_its_fence(self):
        self.state.authorize(self.contract, self.first, self.target)
        self.state.begin(self.contract, self.first, self.target, lambda: None)
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        before = sorted((p.name, p.read_bytes()) for p in self.directory.iterdir())
        for attempt in (
                lambda: self.state.current(self.contract, self.first),
                lambda: self.state.begin(self.contract, self.first, self.target, lambda: self.fail('stale shutdown')),
                lambda: self.state.finish(self.contract, self.first, {}),
                lambda: self.state.guard(self.contract, self.first)):
            with self.assertRaises(ValueError):
                attempt()
            self.assertEqual(before, sorted((p.name, p.read_bytes()) for p in self.directory.iterdir()))
        self.state.authorize(self.contract, self.second, self.target)
        self.state.begin(self.contract, self.second, self.target, lambda: None)
        self.state.finish(self.contract, self.second, {})
        self.state.guard(self.contract, self.second)

    def test_manual_start_cannot_erase_a_failed_authorization_over_an_ordinary_stop(self):
        self.state.cancel(self.contract, False, lambda: None)
        self.state.guard(self.contract, manual=True)
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.manual_ready(self.contract)
        self.assertTrue((self.directory / 'stopped').exists())
        self.assertEqual(self.state.get('activation-revoked'), {'intent': self.second})
        self.state.cancel(self.contract, False, lambda: None)
        self.state.manual_ready(self.contract)
        self.state.guard(self.contract)

    def test_failed_stop_and_retire_cannot_allow_old_queued_activation(self):
        for retired in (False, True):
            with self.assertRaises(OSError):
                self.state.cancel(self.contract, retired, self.fails)
            with self.assertRaises(ValueError):
                self.state.guard(self.contract, self.first)

    def test_failed_cancel_intent_write_still_leaves_durable_stop(self):
        stopped = []
        with patch.object(self.state, 'put', side_effect=OSError('intent write failure')):
            with self.assertRaisesRegex(ValueError, 'cancellation was not persisted'):
                self.state.cancel(self.contract, False, lambda: stopped.append(True))
        self.assertEqual(stopped, [True])
        with self.assertRaises(ValueError):
            self.state.guard(self.contract, self.first)

    def test_first_marker_failure_attempts_shutdown_without_claiming_a_durable_stop(self):
        for retired in (False, True):
            stopped = []
            with patch.object(self.state, 'marker', side_effect=OSError('inert private storage detail')):
                with self.assertRaisesRegex(ValueError, 'cancellation was not persisted') as error:
                    self.state.cancel(self.contract, retired, lambda: stopped.append(True))
            self.assertEqual(stopped, [True])
            self.assertNotIn('private storage', str(error.exception))
            self.assertFalse((self.directory / 'stopped').exists())
            self.assertFalse((self.directory / 'retired').exists())
            # Disk still contains the old generation. Reporting a durable stop
            # would be false even though the owned shutdown callback ran.
            self.state.guard(self.contract, self.first)

    def test_second_marker_failure_retains_the_stop_fence_and_attempts_shutdown(self):
        original = self.state.marker
        calls = []
        def marker(name):
            if name == 'activation-revoked':
                raise OSError('inert second marker failure')
            original(name)
        with patch.object(self.state, 'marker', marker):
            with self.assertRaisesRegex(ValueError, 'cancellation was not persisted'):
                self.state.cancel(self.contract, False, lambda: calls.append(True))
        self.assertEqual(calls, [True])
        self.assertTrue((self.directory / 'stopped').exists())
        with self.assertRaises(ValueError):
            self.state.guard(self.contract, self.first)

    def test_combined_persistence_and_shutdown_failure_is_explicit_but_foreign_scope_never_stops(self):
        calls = []
        def failed_shutdown():
            calls.append(True)
            raise OSError('inert private shutdown detail')
        for stage in ('marker', 'put'):
            with patch.object(self.state, stage, side_effect=OSError('inert private storage detail')):
                with self.assertRaisesRegex(ValueError, 'durable cancellation and owned shutdown both failed') as error:
                    self.state.cancel(self.contract, False, failed_shutdown)
                self.assertNotIn('private', str(error.exception))
        before = list(calls)
        with self.assertRaises(ValueError):
            self.state.cancel(dict(self.contract, network='mainnet'), True, failed_shutdown)
        self.assertEqual(calls, before)

    def test_stale_begin_and_finish_cannot_mutate_the_replacement(self):
        self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.begin(self.contract, self.first, self.target, lambda: self.fail('stale shutdown'))
        self.state.begin(self.contract, self.second, self.target, lambda: None)
        with self.assertRaises(ValueError):
            self.state.finish(self.contract, self.first, {})
        self.state.finish(self.contract, self.second, {})
        self.state.guard(self.contract, self.second)

    def test_incomplete_install_can_be_stopped_and_retried_only_at_same_target(self):
        self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(OSError):
            self.state.begin(self.contract, self.second, self.target, self.fails)
        self.state.cancel(self.contract, True, lambda: None)
        third = 'c' * 32
        self.state.authorize(self.contract, third, dict(self.target, version='0.17.0'))
        with self.assertRaises(ValueError):
            self.state.begin(self.contract, third, dict(self.target, version='0.17.0'), lambda: None)
        self.state.authorize(self.contract, third, self.target)
        self.state.begin(self.contract, third, self.target, lambda: None)
        self.state.finish(self.contract, third, {})
        self.state.guard(self.contract, third)

    def test_foreign_scope_cannot_cancel_or_destroy_and_manual_start_cannot_unretire(self):
        wrong = dict(self.contract, network='mainnet')
        before = sorted((p.name, p.read_bytes()) for p in self.directory.iterdir())
        with self.assertRaises(ValueError):
            self.state.cancel(wrong, True, lambda: self.fail('foreign shutdown'))
        self.assertEqual(before, sorted((p.name, p.read_bytes()) for p in self.directory.iterdir()))
        self.state.cancel(self.contract, True, lambda: None)
        with self.assertRaises(ValueError):
            self.state.manual_ready(self.contract)


if __name__ == '__main__':
    unittest.main()
