#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual public controller dispatch with inert NSS, storage and PID1 effects."""
import copy
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
spec = importlib.util.spec_from_file_location('validator_control', TEMPLATES / 'validator/control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
from arc_files import Refused, digest
from av_files import ROOT
import av_state
import av_remote


class Controller(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.context = control.Controller(pathlib.Path(self.temporary.name), owner=os.getuid())
        self.context.mkdir(ROOT)
        network = av_state.NETWORKS['testnet']
        self.contract = {'owner': 'a' * 26, 'network': 'testnet', 'chain_id': network['chain_id'],
                         'genesis_hash': network['genesis_hash'],
                         'public_key': '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
                         'peer_public_key': 'PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=',
                         'controller': '0x' + 'b' * 40, 'host_binding': 'c' * 64}
        # An inert public-CA-shaped input exercises original-byte publication only;
        # no TLS verification or real certificate is claimed by these tests.
        self.ca = '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n'
        self.profile = {'endpoint': 'https://127.0.0.1:50051', 'server_ca_sha256': digest(self.ca.encode()),
                        'image_sha256': 'd' * 64, **{key: 'e' * 96 for key in ('pcr0', 'pcr1', 'pcr2', 'pcr4')}}
        self.accounts = {'execution': 991, 'consensus': 992, 'engine': 993, 'established': False}
        self.storage = {'filesystem': {'uuid': 'inert-original-volume', 'fstype': 'ext4'}}
        self.stopped = mock.Mock()
        self.disabled = mock.Mock()
        self.context.stop_original = self.stopped
        self.context.disable_original = self.disabled

    def request(self, action, **fields):
        return {'action': action, 'contract': copy.deepcopy(self.contract), **fields}

    def reserve(self):
        with mock.patch.object(control.av_accounts, 'reserve', return_value=copy.deepcopy(self.accounts)), \
             mock.patch.object(control.av_storage, 'fresh', return_value=copy.deepcopy(self.storage)):
            return control.dispatch(self.context, self.request('reserve', remote_signer=self.profile, ca=self.ca))

    def state(self):
        return self.context.json(av_state.OWNER, private=True)

    def test_preflight_checks_fresh_scope_without_persisting_nss_or_a_key(self):
        with mock.patch.object(control.av_storage, 'fresh', return_value=self.storage) as storage, \
             mock.patch.object(control.av_accounts, 'reserve', return_value=self.accounts) as accounts:
            result = control.dispatch(self.context, {'action': 'preflight'})
        self.assertEqual(result, {'fresh': True, 'activation_authorized': False})
        storage.assert_called_once()
        accounts.assert_called_once()
        self.assertFalse(self.context.path(av_state.OWNER).exists())
        self.assertEqual(list(self.context.path(ROOT).iterdir()), [])

    def test_existing_preflight_needs_the_original_contract_and_account_observation(self):
        self.reserve()
        with mock.patch.object(control.av_accounts, 'verify', return_value=None) as verified:
            self.assertEqual(control.dispatch(self.context, self.request('preflight')), {'original': True})
            verified.assert_called_once_with(self.accounts, missing=True)
        with mock.patch.object(control.av_accounts, 'reserve') as reserve:
            with self.assertRaises(Refused):
                control.dispatch(self.context, {'action': 'preflight'})
            reserve.assert_not_called()
        with mock.patch.object(control.av_accounts, 'verify', side_effect=Refused('inert foreign NSS')):
            with self.assertRaises(Refused):
                control.dispatch(self.context, self.request('preflight'))

    def test_actual_private_lock_survives_first_reservation_without_shared_run_lock_assumption(self):
        with control.operation_lock(self.context):
            self.reserve()
        path = self.context.path(ROOT + '/lock')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(self.context.path('/run/lock').exists())
        with control.operation_lock(self.context):
            self.reserve()

    def test_remote_public_inputs_are_bound_without_any_consensus_secret_or_activation(self):
        result = self.reserve()
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['consensus_public_key'], self.contract['public_key'])
        self.assertEqual(result['peer_public_key'], self.contract['peer_public_key'])
        self.assertEqual(self.state()['remote_signer'], self.profile)
        self.assertEqual(av_remote.ca(self.context, self.state()), self.ca.encode())
        self.stopped.assert_not_called()
        self.disabled.assert_not_called()

    def test_invalid_certificate_refuses_before_reserving_nss_or_owner(self):
        self.ca = 'not-a-public-certificate'
        self.profile['server_ca_sha256'] = digest(self.ca.encode())
        with self.assertRaises(Refused):
            self.reserve()
        self.assertFalse(self.context.path(av_state.OWNER).exists())

    def test_interrupted_ca_file_publication_retries_only_original_profile_and_bytes(self):
        original_sync = os.fsync
        def fail_ca(descriptor):
            pending = self.context.path(av_remote.CA + '.pending')
            info = os.fstat(descriptor)
            if pending.exists() and (info.st_dev, info.st_ino) == (pending.stat().st_dev, pending.stat().st_ino):
                raise OSError('inert CA publication interruption')
            return original_sync(descriptor)
        with mock.patch.object(os, 'fsync', side_effect=fail_ca):
            with self.assertRaises(OSError):
                self.reserve()
        retained = self.state()
        self.assertEqual(retained['remote_signer'], self.profile)
        self.assertTrue(self.context.path(av_remote.CA + '.pending').exists())
        old = self.profile['endpoint']
        self.profile['endpoint'] = 'https://127.0.0.1:50052'
        with self.assertRaises(Refused):
            self.reserve()
        self.assertEqual(self.state(), retained)
        self.profile['endpoint'] = old
        self.reserve()
        self.assertEqual(self.state(), retained)
        self.assertEqual(self.context.read(av_remote.CA, private=True), self.ca.encode())

    def test_visible_owner_does_not_turn_persistent_ancestor_sync_failure_into_success(self):
        root_inode = self.context.path(ROOT).stat().st_ino
        original_sync = os.fsync
        def fail_owner_parent(descriptor):
            info = os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode) and info.st_ino == root_inode and self.context.path(av_state.OWNER).exists():
                raise OSError('inert persistent original namespace sync failure')
            return original_sync(descriptor)
        with mock.patch.object(os, 'fsync', side_effect=fail_owner_parent):
            for _ in range(2):
                with self.assertRaises(OSError):
                    self.reserve()
        self.assertFalse(self.context.path(av_remote.CA).exists())
        original = self.state()['accounts']
        self.reserve()
        self.assertEqual(self.state()['accounts'], original)
        self.assertEqual(av_remote.ca(self.context, self.state()), self.ca.encode())

    def test_signer_probe_refuses_drifted_public_qualification_before_transport(self):
        self.reserve()
        changed = copy.deepcopy(self.profile)
        changed['endpoint'] = 'https://127.0.0.1:50052'
        with mock.patch.object(control.av_remote, 'public_key') as probe:
            with self.assertRaisesRegex(Refused, 'qualification differs'):
                control.dispatch(self.context, self.request('remote-public-key', remote_signer=changed))
            probe.assert_not_called()
            probe.return_value = {'transport': 'inert-model'}
            self.assertEqual(control.dispatch(self.context, self.request('remote-public-key', remote_signer=self.profile)),
                             {'transport': 'inert-model'})

    def test_foreign_contract_never_stops_or_retires_original_writer(self):
        self.reserve()
        before = self.context.read(av_state.OWNER)
        for operation in ('stop', 'destroy', 'start', 'status'):
            request = self.request(operation)
            request['contract']['owner'] = 'z' * 26
            with self.assertRaises(Refused):
                control.dispatch(self.context, request)
        self.stopped.assert_not_called()
        self.disabled.assert_not_called()
        self.assertEqual(self.context.read(av_state.OWNER), before)

    def test_cancellation_write_failure_still_attempts_original_stop_and_retains_bytes(self):
        self.reserve()
        self.context.write_bytes(ROOT + '/consensus-key.cred', b'inert-original-encrypted-peer-identity')
        original = self.context.write
        def fail(name, value, *args):
            if name == av_state.HALT:
                raise OSError('inert persistent cancellation failure')
            return original(name, value, *args)
        with mock.patch.object(self.context, 'write', side_effect=fail):
            with self.assertRaisesRegex(Refused, 'durable cancellation'):
                control.dispatch(self.context, self.request('destroy'))
        self.stopped.assert_called_once()
        self.disabled.assert_called_once()
        self.assertEqual(self.context.read(ROOT + '/consensus-key.cred'), b'inert-original-encrypted-peer-identity')
        self.assertTrue(self.context.path(av_state.RETIRED).exists())

    def test_unknown_or_incomplete_request_does_not_reach_authority_mutation(self):
        for value in (self.request('unknown'), self.request('authorize', intent='a' * 32),
                      self.request('stop', key='unexpected'), self.request('reserve', ca=self.ca)):
            with self.assertRaises(Refused):
                control.dispatch(self.context, value)
        self.assertFalse(self.context.path(av_state.OWNER).exists())
        self.stopped.assert_not_called()

    def test_successful_stop_fence_blocks_delayed_stages_even_if_operation_write_failed(self):
        self.reserve()
        state = self.state()
        self.context.validate_target = mock.Mock()
        self.context.validate_policy = mock.Mock()
        av_state.authorize(self.context, state, '1' * 32, {'inert': 'target'}, {'phase': 'observer'})
        original = self.context.write
        def failed_operation(name, value, *args):
            if name == av_state.OPERATION:
                raise OSError('inert operation cancellation write failure')
            return original(name, value, *args)
        with mock.patch.object(self.context, 'write', side_effect=failed_operation):
            with self.assertRaises(Refused):
                control.dispatch(self.context, self.request('stop'))
        self.context.firewall = mock.Mock()
        for action in ('apply-firewall', 'confirm-firewall', 'require-firewall'):
            with self.assertRaisesRegex(Refused, 'startup fence|lifecycle history'):
                control.dispatch(self.context, self.request(action, intent='1' * 32,
                                 firewall_run='r-inert-original', firewall_bundle='a' * 64))
        self.context.firewall.assert_not_called()

    def test_retired_host_can_confirm_only_a_fresh_explicit_deployment(self):
        self.reserve()
        control.dispatch(self.context, self.request('destroy'))
        state = self.state()
        self.context.validate_target = mock.Mock()
        self.context.validate_policy = mock.Mock()
        av_state.authorize(self.context, state, '2' * 32, {'inert': 'target'}, {'phase': 'observer'})
        self.context.firewall = mock.Mock()
        result = control.dispatch(self.context, self.request('require-firewall', intent='2' * 32,
                                  firewall_run='r-inert-fresh', firewall_bundle='b' * 64))
        self.assertEqual(result, {'ingress': 'confirmed'})
        self.assertTrue(self.context.path(av_state.RETIRED).exists())
        self.assertEqual(self.state()['firewall'], {'run': 'r-inert-fresh', 'bundle': 'b' * 64})

    def bootstrap_state(self):
        self.reserve()
        state = self.state()
        self.context.validate_target = mock.Mock()
        self.context.validate_policy = mock.Mock()
        av_state.authorize(self.context, state, '3' * 32, {'inert': 'target'}, {'phase': 'observer'})
        state.update({'generation': '3' * 32, 'phase': 'installing', 'policy': {'phase': 'observer'}})
        self.context.save(state)
        self.context.confirmed_ingress = mock.Mock()
        self.context.unit_proof = mock.Mock()
        self.context.assert_all_quiescent = mock.Mock()
        self.context.command = mock.Mock()
        return state

    def test_failed_runtime_still_reports_public_original_bootstrap_intent_for_explicit_recovery(self):
        self.reserve()
        state = self.state()
        state.update({'phase': 'bootstrap', 'bootstrap_intent': '4' * 32, 'generation': '4' * 32})
        self.context.save(state)
        self.context.verify_original = mock.Mock(side_effect=Refused('inert absent runtime'))
        result = control.dispatch(self.context, self.request('status'))
        self.assertFalse(result['ready'])
        self.assertFalse(result['running'])
        self.assertEqual(result['bootstrap_intent'], '4' * 32)
        self.assertFalse(result['production_activation_available'])
        self.assertNotIn('credential', result)
        self.assertNotIn('accounts', result)

    def test_polling_status_distinguishes_legitimate_bootstrap_fence_from_explicit_cancellation(self):
        state = self.bootstrap_state()
        state['phase'] = 'bootstrap'
        self.context.save(state)
        self.context.verify_original = mock.Mock(side_effect=Refused('inert bootstrap in progress'))
        self.context.unit_proof = mock.Mock()
        with mock.patch.object(control.av_process, 'properties', return_value={'Result': 'success', 'ExecMainStatus': '0'}):
            result = control.dispatch(self.context, self.request('status'))
            self.assertFalse(result['operation_cancelled'])
            self.assertFalse(result['bootstrap_failed'])
            control.dispatch(self.context, self.request('stop'))
            self.assertTrue(control.dispatch(self.context, self.request('status'))['operation_cancelled'])
        with mock.patch.object(control.av_process, 'properties', return_value={'Result': 'exit-code', 'ExecMainStatus': '1'}):
            self.assertTrue(control.dispatch(self.context, self.request('status'))['bootstrap_failed'])

    def test_incomplete_bootstrap_requires_explicit_quarantine_before_new_download(self):
        state = self.bootstrap_state()
        state['bootstrap_intent'] = '2' * 32
        state['directories'] = {'bootstrap': {'inode': 123}}
        self.context.save(state)
        with mock.patch.object(control.av_bootstrap, 'prepare') as prepare:
            with self.assertRaisesRegex(Refused, 'explicit stop and reset-bootstrap'):
                control.dispatch(self.context, self.request('bootstrap', intent='3' * 32))
            prepare.assert_not_called()
        self.context.command.assert_not_called()
        self.assertEqual(self.state(), state)

    def test_completed_or_partially_promoted_original_pair_is_not_downloaded_again(self):
        for promoting in (False, True):
            state = self.bootstrap_state() if not promoting else self.state()
            state['bootstrap_pair'] = {'execution': {'inode': 111}, 'consensus': {'inode': 222}}
            state['bootstrap_intent'] = '2' * 32
            state['promotion_started'] = promoting
            self.context.save(state)
            with mock.patch.object(control.av_bootstrap, 'prepare') as prepare:
                result = control.dispatch(self.context, self.request('bootstrap', intent='3' * 32))
                prepare.assert_not_called()
            self.context.command.assert_not_called()
            self.assertEqual(result['bootstrap'], 'original-pair-retained')
            self.assertEqual(self.state()['bootstrap_pair'], state['bootstrap_pair'])
            self.assertEqual(self.state()['phase'], 'promoting' if promoting else 'bootstrap-complete')
            self.assertEqual(self.state()['bootstrap_generation'], '3' * 32)

    def test_only_original_explicit_quarantine_receipt_permits_new_bootstrap(self):
        state = self.bootstrap_state()
        state['bootstrap_intent'] = '2' * 32
        state['retained_bootstrap'] = {'name': 'inert-retained', 'root': {'inode': 123}, 'intent': '2' * 32}
        self.context.save(state)
        with mock.patch.object(control.av_bootstrap, 'prepare') as prepare:
            result = control.dispatch(self.context, self.request('bootstrap', intent='3' * 32))
            prepare.assert_called_once()
        self.assertEqual(result['bootstrap'], 'requested')
        self.assertEqual(self.state()['bootstrap_intent'], '3' * 32)
        self.assertEqual(self.state()['retained_bootstrap'], state['retained_bootstrap'])
        self.context.command.assert_called_once_with('/usr/bin/systemctl', 'start', '--no-block',
                                                    'erpc-arc-validator-bootstrap.service')

    def prepare_start(self):
        self.reserve()
        state = self.state()
        state.update({'phase': 'installed', 'policy': {'phase': 'observer'}, 'bootstrap_complete': True})
        self.context.save(state)
        self.context.write(av_state.HALT, {'intent': None, 'reason': 'stopped'})
        self.context.verify_original = mock.Mock()
        self.context.assert_all_quiescent = mock.Mock()
        self.context.confirmed_ingress = mock.Mock()
        return state

    def test_async_start_reports_request_not_readiness_and_does_not_authorize_production(self):
        self.prepare_start()
        self.context.command = mock.Mock(return_value=types.SimpleNamespace(returncode=0))
        result = control.dispatch(self.context, self.request('start'))
        self.assertTrue(result['startup_requested'])
        self.assertFalse(result['ready'])
        self.assertFalse(result['validator_ready'])
        self.assertEqual(self.state()['phase'], 'starting')
        self.assertEqual(self.context.command.call_args.args[1:4], ('enable', '--now', '--no-block'))

    def test_rejected_async_start_revokes_and_stops_without_erasing_originals(self):
        self.prepare_start()
        self.context.command = mock.Mock(return_value=types.SimpleNamespace(returncode=1))
        with self.assertRaises(Refused):
            control.dispatch(self.context, self.request('start'))
        self.stopped.assert_called_once()
        self.disabled.assert_called_once()
        self.assertEqual(self.context.json(av_state.HALT)['intent'], None)
        self.assertEqual(self.state()['accounts'], self.accounts)

    def test_native_condition_checks_quiescence_and_original_ciphertext_before_credential_grant(self):
        state = self.prepare_start()
        state['phase'] = 'starting'
        state['helper_hash'] = 'a' * 64
        state['authorization_history'] = control.av_events.basis(self.context)
        self.context.save(state)
        self.context.remove(av_state.HALT)
        self.context.unit_proof = mock.Mock()
        self.context.firewall = mock.Mock()
        self.context.assert_native_start = mock.Mock(side_effect=Refused('inert original UID orphan'))
        with mock.patch.object(control.av_helpers, 'source', return_value=([], [], 'a' * 64)), \
             mock.patch.object(control.av_accounts, 'verify'), \
             mock.patch.object(control.av_custody, 'verified', side_effect=Refused('inert missing original ciphertext')) as credential:
            with self.assertRaisesRegex(Refused, 'UID orphan'):
                control.boot(self.context, 'condition', 'consensus')
            credential.assert_not_called()
            self.context.assert_native_start.side_effect = None
            with self.assertRaisesRegex(Refused, 'original ciphertext'):
                control.boot(self.context, 'condition', 'consensus')
            credential.side_effect = None
            self.assertEqual(control.boot(self.context, 'condition', 'consensus'),
                             {'original_account': 'verified', 'original_credential': True})

    def test_used_consensus_history_cannot_fall_back_to_observer(self):
        state = self.prepare_start()
        state['signer_used'] = True
        self.context.save(state)
        self.context.command = mock.Mock()
        with self.assertRaisesRegex(Refused, 'used history'):
            control.dispatch(self.context, self.request('start'))
        self.context.command.assert_not_called()
        self.context.verify_original.assert_not_called()


if __name__ == '__main__':
    unittest.main()
