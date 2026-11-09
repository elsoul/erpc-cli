#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual state publication/cancellation with inert process and target capabilities."""
import copy
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_state as state_module
from av_files import Files, ROOT
from arc_files import Refused


class State(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.context = Files(pathlib.Path(self.temporary.name), owner=os.getuid())
        self.context.mkdir(ROOT)
        network = state_module.NETWORKS['testnet']
        self.contract = {'owner': 'a' * 26, 'network': 'testnet', 'chain_id': network['chain_id'],
                         'genesis_hash': network['genesis_hash'], 'public_key':
                         '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
                         'peer_public_key': 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=',
                         'controller': '0x' + 'b' * 40, 'host_binding': 'c' * 64}
        self.state = {'schema': 'erpc-arc-validator-v1', 'contract': self.contract, 'phase': 'reserved'}
        self.context.save(self.state)
        self.stopped, self.disabled = 0, 0
        self.context.stop_original = self.stop
        self.context.disable_original = self.disable
        self.context.assert_all_quiescent = lambda _state: None
        self.context.validate_target = lambda target: self.context.require(target == {'inert': 'source'}, 'bad source')
        self.context.validate_policy = lambda _state, policy: self.context.require(policy == {'inert': 'policy'}, 'bad policy')

    def stop(self, _state):
        self.stopped += 1

    def disable(self, _state):
        self.disabled += 1

    def authorize(self, identity):
        return state_module.authorize(self.context, self.state, identity, {'inert': 'source'}, {'inert': 'policy'})

    def installed(self, identity):
        self.authorize(identity)
        state_module.begin(self.context, self.state, identity)
        self.state['phase'] = 'installed'
        self.context.save(self.state)

    def test_stop_in_installation_revokes_delayed_activation_and_preserves_history(self):
        identity = '1' * 32
        self.authorize(identity)
        state_module.begin(self.context, self.state, identity)
        self.state['signing_history'] = {'inert': 'original'}
        state_module.cancel_and_stop(self.context, self.state)
        self.state['phase'] = 'installed'
        with self.assertRaises(Refused):
            state_module.ready_to_activate(self.context, self.state, identity)
        self.assertEqual(self.state['signing_history'], {'inert': 'original'})

    def test_superseding_operation_write_failure_cannot_reenable_previous_intent(self):
        self.installed('1' * 32)
        original_write = self.context.write
        def fail(name, value, *args):
            if name == state_module.OPERATION:
                raise OSError('inert replacement operation failure')
            return original_write(name, value, *args)
        with mock.patch.object(self.context, 'write', fail):
            with self.assertRaises(Refused):
                self.authorize('2' * 32)
        with self.assertRaises(Refused):
            state_module.ready_to_activate(self.context, self.state, '1' * 32)
        self.assertEqual(self.stopped, 2)
        self.assertEqual(self.disabled, 1)

    def test_first_or_later_storage_failure_still_attempts_owned_shutdown(self):
        for failed_path in (state_module.HALT, state_module.OPERATION, state_module.RETIRED):
            self.installed(('3' if failed_path == state_module.HALT else
                            '4' if failed_path == state_module.OPERATION else '5') * 32)
            original_write = self.context.write
            old_stopped, old_disabled = self.stopped, self.disabled
            def fail(name, value, *args):
                if name == failed_path:
                    raise OSError('inert persistent cancellation failure')
                return original_write(name, value, *args)
            with mock.patch.object(self.context, 'write', fail):
                with self.assertRaisesRegex(Refused, 'durable cancellation'):
                    state_module.cancel_and_stop(self.context, self.state, retire=True)
            self.assertEqual(self.stopped, old_stopped + 1)
            self.assertEqual(self.disabled, old_disabled + 1)

    def test_permanent_actual_directory_sync_failure_never_reports_cancel_success(self):
        self.installed('6' * 32)
        actual = os.fsync
        def fail(descriptor):
            if os.fstat(descriptor).st_ino == self.context.ROOT.stat().st_ino:
                raise OSError('inert persistent directory failure')
            return actual(descriptor)
        with mock.patch.object(os, 'fsync', fail):
            with self.assertRaisesRegex(Refused, 'cancellation incomplete'):
                state_module.cancel_and_stop(self.context, self.state, retire=True)
        self.assertEqual(self.stopped, 2)
        self.assertEqual(self.disabled, 1)

    def test_foreign_scope_is_rejected_before_cancellation_dispatch(self):
        changed = copy.deepcopy(self.contract)
        changed['controller'] = '0x' + 'd' * 40
        with self.assertRaises(Refused):
            state = state_module.original(self.context, changed)
            state_module.cancel_and_stop(self.context, state, retire=True)
        self.assertEqual((self.stopped, self.disabled), (0, 0))

    def test_explicit_new_deploy_can_resume_retirement_but_cannot_reuse_any_old_intent(self):
        self.installed('7' * 32)
        state_module.cancel_and_stop(self.context, self.state, retire=True)
        self.installed('8' * 32)
        state_module.ready_to_activate(self.context, self.state, '8' * 32)
        self.assertFalse(self.context.protected(state_module.RETIRED, missing=True).exists())
        for previous in ('7' * 32, '8' * 32):
            with self.assertRaises(Refused):
                self.authorize(previous)

    def test_complete_pending_reservation_reuses_original_identity_without_nss_or_storage_adoption(self):
        self.context.remove(state_module.OWNER)
        pending = {'schema': 'erpc-arc-validator-v1', 'contract': self.contract,
                   'accounts': {'execution': 999, 'consensus': 998, 'engine': 997, 'established': False},
                   'storage': {'filesystem': 'inert original volume'},
                   'phase': 'reserved', 'signer_used': False, 'generation': None, 'retired': False}
        self.context.write(state_module.OWNER + '.pending', pending)
        checks = []
        self.context.preflight_fresh_namespace = lambda **kwargs: checks.append(kwargs)
        with mock.patch.object(state_module.av_accounts, 'verify', return_value=({}, {}, None)), \
             mock.patch.object(state_module.av_accounts, 'reserve', side_effect=AssertionError('must retain original')), \
             mock.patch.object(state_module.av_storage, 'fresh', return_value=pending['storage']):
            result = state_module.reserve(self.context, self.contract)
        self.assertEqual(result, pending)
        self.assertEqual(checks, [{'pending_owner': True}])
        self.assertEqual(self.context.json(state_module.OWNER), pending)

    def test_pending_reservation_foreign_owner_is_retained_without_commands(self):
        self.context.remove(state_module.OWNER)
        original = b'{"schema":"unrecognized pending authority"}'
        self.context.write_bytes(state_module.OWNER + '.pending', original)
        with self.assertRaises(Refused):
            state_module.reserve(self.context, self.contract)
        self.assertEqual(self.context.read(state_module.OWNER + '.pending'), original)
        self.assertEqual((self.stopped, self.disabled), (0, 0))


if __name__ == '__main__':
    unittest.main()
