#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual atomic writer and controller failures: immutable revocation and recovery.

Filesystem writes/renames/syncs are real inert files. NSS, native source and PID1
are modeled using the author's existing fixture; no reviewer probe is copied.
"""
import copy
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
import validator_control as fixture
control = fixture.control
from arc_files import Refused
import av_state
import av_events
from av_files import ROOT


class Revocation(unittest.TestCase):
    def fixture(self):
        case = fixture.Controller('runTest'); case.setUp(); self.addCleanup(case.doCleanups)
        case.reserve()
        context = case.context
        context.validate_target = mock.Mock()
        context.validate_policy = mock.Mock()
        context.assert_all_quiescent = mock.Mock()
        context.verify_original = mock.Mock()
        context.confirmed_ingress = mock.Mock()
        context.command = mock.Mock(return_value=type('Result', (), {'returncode': 0})())
        context.write_bytes(ROOT + '/consensus-key.cred', b'inert-original-ciphertext')
        self.authorize(case, '1' * 32)
        self.installed(case, '1' * 32)
        return case

    def authorize(self, case, token):
        return control.dispatch(case.context, case.request('authorize', intent=token,
                                target={'version':'v0.8.1','commit':control.arc_release.QUALIFIED_COMMIT,
                                        'platform':'x86_64-unknown-linux-gnu',
                                        'archive_sha256':control.arc_release.QUALIFIED_ARCHIVES['x86_64-unknown-linux-gnu']},
                                policy={'phase': 'observer'}))

    def installed(self, case, token):
        state = case.state()
        av_state.begin(case.context, state, token)
        state.update({'phase': 'installed', 'bootstrap_complete': True, 'source_floor': state['target']})
        case.context.save(state)

    def refuse_old(self, case):
        before = case.context.command.call_count
        for action in ('activate', 'install', 'bootstrap', 'promote'):
            fields = {'intent': '1' * 32}
            if action == 'install': fields['helper_hash'] = 'a' * 64
            with self.assertRaises((Refused, OSError)):
                control.dispatch(case.context, case.request(action, **fields))
        self.assertEqual(case.context.command.call_count, before)
        self.assertEqual(case.context.read(ROOT + '/consensus-key.cred'), b'inert-original-ciphertext')

    def recover(self, case, token='3' * 32):
        self.authorize(case, token)
        self.installed(case, token)
        result = control.dispatch(case.context, case.request('activate', intent=token))
        self.assertTrue(result['startup_requested'])
        self.assertFalse(case.context.is_retired())
        self.assertEqual(case.context.read(ROOT + '/consensus-key.cred'), b'inert-original-ciphertext')
        self.refuse_old(case)

    def file_name(self, context, descriptor):
        info = os.fstat(descriptor)
        for path in context.path(ROOT).rglob('*'):
            if path.is_file() and (path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino):
                return path.name
        return None

    def test_complete_restrictive_pending_and_failed_new_authorize_never_restore_old_grant(self):
        for retire in (False, True):
            case = self.fixture(); context = case.context
            original_sync = os.fsync
            def fail_pending(descriptor):
                if self.file_name(context, descriptor) in {Path(path).name for path in av_events.PENDING}:
                    raise OSError('inert pending file fsync failure')
                return original_sync(descriptor)
            before = case.stopped.call_count
            with mock.patch.object(os, 'fsync', side_effect=fail_pending):
                with self.assertRaises(Refused):
                    control.dispatch(context, case.request('destroy' if retire else 'stop'))
            self.assertEqual(case.stopped.call_count, before + 1)
            self.assertTrue(av_events.pending(context))
            self.refuse_old(case)
            # A new operation that fails after publishing its immutable event is
            # not a reason to discard earlier restrictive pending evidence.
            with mock.patch.object(os, 'fsync', side_effect=OSError('inert persistent storage failure')):
                with self.assertRaises(Refused): self.authorize(case, '2' * 32)
            self.refuse_old(case)
            if retire: self.assertTrue(context.is_retired())
            self.recover(case)
            before = case.stopped.call_count
            with self.assertRaises(Refused): self.authorize(case, '2' * 32)
            self.assertEqual(case.stopped.call_count, before)

    def test_pending_evidence_alone_fences_even_when_event_creation_cannot_begin(self):
        for retire in (False, True):
            case = self.fixture(); context = case.context
            old_basis = av_events.basis(context)
            original_open, original_sync = os.open, os.fsync
            def fail_event(path, *args, **kwargs):
                if str(path).endswith('.event') and args[0] & os.O_CREAT:
                    raise OSError('inert event allocation failure')
                return original_open(path, *args, **kwargs)
            def fail_pending(descriptor):
                if self.file_name(context, descriptor) in {Path(path).name for path in av_events.PENDING}:
                    raise OSError('inert pending fsync failure')
                return original_sync(descriptor)
            with mock.patch.object(os, 'open', side_effect=fail_event), mock.patch.object(os, 'fsync', side_effect=fail_pending):
                with self.assertRaises(Refused): control.dispatch(context, case.request('destroy' if retire else 'stop'))
            self.assertEqual(av_events.basis(context), old_basis)
            self.refuse_old(case)
            # Archive and recover raw pending bytes, rather than assuming that a
            # complete committed stop file was present.
            self.recover(case)

    def test_empty_and_partial_files_remain_restrictive_through_repeated_failure(self):
        for cut in (0, 1, 7):
            for retire in (False, True):
                case = self.fixture(); context = case.context
                original_write = os.write
                seen = set()
                def fail_write(descriptor, raw):
                    name = self.file_name(context, descriptor)
                    if name and (name.endswith('.event') or name.endswith('.pending')):
                        if cut and descriptor not in seen:
                            seen.add(descriptor)
                            return original_write(descriptor, bytes(raw[:cut]))
                        raise OSError('inert interrupted write')
                    return original_write(descriptor, raw)
                with mock.patch.object(os, 'write', side_effect=fail_write):
                    with self.assertRaises(Refused): control.dispatch(context, case.request('destroy' if retire else 'stop'))
                    with self.assertRaises(Refused): self.authorize(case, '2' * 32)
                self.refuse_old(case)
                if retire: self.assertTrue(context.is_retired())
                self.recover(case)

    def test_failed_activation_publication_attempts_shutdown_and_never_enables_or_resumes_old_work(self):
        for boundary in ('owner-file', 'halt-removal'):
            case = self.fixture(); context = case.context
            original_sync = os.fsync
            before = case.stopped.call_count
            fired = False
            def fail(descriptor):
                nonlocal fired
                info = os.fstat(descriptor)
                name = self.file_name(context, descriptor)
                trigger = ((boundary == 'owner-file' and name == 'owner.json.pending') or
                           (boundary == 'halt-removal' and stat.S_ISDIR(info.st_mode) and
                            info.st_ino == context.path(ROOT).stat().st_ino and not context.path(av_state.HALT).exists()))
                if trigger and not fired:
                    fired = True
                    raise OSError('inert activation publication failure')
                return original_sync(descriptor)
            with mock.patch.object(os, 'fsync', side_effect=fail):
                with self.assertRaises((Refused, OSError)):
                    control.dispatch(context, case.request('activate', intent='1' * 32))
            self.assertTrue(fired)
            self.assertEqual(case.stopped.call_count, before + 1)
            self.assertFalse(any(call.args[:2] == ('/usr/bin/systemctl', 'enable') for call in context.command.call_args_list))
            self.refuse_old(case)
            self.recover(case)

    def test_retired_halt_alone_cannot_be_weakened_by_plain_stop_retry(self):
        for pending in (False, True):
            case = self.fixture(); context = case.context
            real_open, real_sync = os.open, os.fsync
            def fail_other_records(path, *args, **kwargs):
                if args[0] & os.O_CREAT and (str(path).endswith('.event') or
                        Path(path).name in ('retired.json.pending', 'operation.json.pending')):
                    raise OSError('inert only HALT can be allocated')
                return real_open(path, *args, **kwargs)
            def halt_barrier(descriptor):
                if pending and self.file_name(context, descriptor) == 'startup-revoked.json.pending':
                    raise OSError('inert HALT pending file sync failure')
                return real_sync(descriptor)
            before = case.stopped.call_count
            with mock.patch.object(os, 'open', side_effect=fail_other_records), \
                 mock.patch.object(os, 'fsync', side_effect=halt_barrier):
                with self.assertRaises(Refused): control.dispatch(context, case.request('destroy'))
            self.assertEqual(case.stopped.call_count, before + 1)
            self.assertFalse(context.path(av_state.RETIRED).exists())
            self.assertIsNone(av_events.retirement(context))
            location = av_state.HALT + ('.pending' if pending else '')
            self.assertEqual(context.json(location)['reason'], 'retired')
            self.assertTrue(context.is_retired())
            with self.assertRaises(Refused): control.dispatch(context, case.request('start'))
            result = control.dispatch(context, case.request('stop'))
            self.assertTrue(result['retired'])
            self.assertTrue(context.is_retired())
            self.assertEqual(context.json(av_state.HALT)['reason'], 'retired')
            with self.assertRaises(Refused): control.dispatch(context, case.request('start'))
            self.refuse_old(case)
            self.recover(case)

    def test_committed_recovery_only_halt_is_not_downgraded_by_stop(self):
        for raw in (b'{"intent":null,"reason":"failed-deployment"}', b'{"intent":'):
            case = self.fixture(); context = case.context
            context.write_bytes(av_state.HALT, raw)
            control.dispatch(context, case.request('stop'))
            self.assertTrue(av_events.needs_recovery(context, case.state()))
            with self.assertRaises(Refused): control.dispatch(context, case.request('start'))
            self.refuse_old(case)
            self.recover(case)

    def test_failed_stop_archive_preserves_pending_bytes_and_still_attempts_owned_shutdown(self):
        case = self.fixture(); context = case.context
        original = b'{"intent":null,"reason":"retired"}'
        context.write_bytes(av_state.HALT + '.pending', original)
        real_open = os.open
        def no_events(path, *args, **kwargs):
            if str(path).endswith('.event') and args[0] & os.O_CREAT:
                raise OSError('inert archive allocation failure')
            return real_open(path, *args, **kwargs)
        before = case.stopped.call_count
        with mock.patch.object(os, 'open', side_effect=no_events):
            with self.assertRaises(Refused): control.dispatch(context, case.request('stop'))
        self.assertEqual(case.stopped.call_count, before + 1)
        self.assertEqual(context.read(av_state.HALT + '.pending'), original)
        self.assertTrue(context.is_retired())
        self.refuse_old(case)
        self.recover(case)

    def test_archived_partial_pending_evidence_cannot_be_bypassed_by_manual_start_after_failed_recovery(self):
        case = self.fixture(); context = case.context
        control.dispatch(context, case.request('stop'))
        context.write_bytes(av_state.HALT + '.pending', b'{"intent":null,"reason":"retired')
        original_write = context.write
        def fail_mutable(name, value, *args):
            if name == av_state.HALT:
                raise OSError('inert new grant write failure before open')
            return original_write(name, value, *args)
        with mock.patch.object(context, 'write', side_effect=fail_mutable):
            with self.assertRaises(Refused): self.authorize(case, '2' * 32)
        self.assertFalse(av_events.pending(context))
        self.assertTrue(av_events.needs_recovery(context, case.state()))
        with self.assertRaises(Refused): control.dispatch(context, case.request('start'))
        self.refuse_old(case)
        self.recover(case)

    def test_visible_directory_barrier_failure_and_manual_recovery_are_not_implicit_activation(self):
        for location in (ROOT, av_events.DIRECTORY):
            case = self.fixture(); context = case.context
            original_sync = os.fsync
            def fail_directory(descriptor):
                info = os.fstat(descriptor)
                path = context.path(location)
                if stat.S_ISDIR(info.st_mode) and path.exists() and info.st_ino == path.stat().st_ino:
                    raise OSError('inert directory barrier failure')
                return original_sync(descriptor)
            with mock.patch.object(os, 'fsync', side_effect=fail_directory):
                with self.assertRaises(Refused): control.dispatch(context, case.request('stop'))
                with self.assertRaises(Refused): self.authorize(case, '2' * 32)
            self.refuse_old(case)
            self.recover(case)
        case = self.fixture()
        control.dispatch(case.context, case.request('stop'))
        before = av_events.basis(case.context)
        result = control.dispatch(case.context, case.request('start'))
        self.assertTrue(result['startup_requested'])
        self.assertNotEqual(av_events.basis(case.context), before)
        self.refuse_old(case)


if __name__ == '__main__': unittest.main()
