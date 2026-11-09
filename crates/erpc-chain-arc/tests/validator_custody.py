#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original ciphertext publication and interrupted rewrap without operational keys."""
import contextlib
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_custody as custody
from av_files import Files, ROOT
from arc_files import Refused

PUBLIC = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='  # RFC 8032 public vector only.
RAW = b'inert plaintext fixture; deliberately not a valid private key'


class Custody(unittest.TestCase):
    def setUp(self):
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.context = Files(pathlib.Path(self.temporary.name), owner=os.getuid(), run=self.command)
        self.context.mkdir(ROOT)
        self.state = {'contract': {'peer_public_key': PUBLIC}, 'accounts': {'inert': True},
                      'signer_used': False, 'cancelled': True}
        self.calls, self.encrypted = [], 0
        self.context.assert_all_quiescent = lambda _state: None
        self.context.assert_cancelled = lambda state: self.context.require(state['cancelled'], 'not cancelled')
        self.patches.enter_context(mock.patch.object(custody.av_accounts, 'verify', return_value=None))
        self.patches.enter_context(mock.patch.object(custody, 'public', side_effect=self.public))

    def public(self, _context, raw):
        return PUBLIC if raw == RAW else 'different original public identity'

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[0], '/usr/bin/systemd-creds')
        self.assertEqual(argv[2:], ['--name=arc-validator-key', '-', '-'])
        if argv[1] == 'encrypt':
            self.assertEqual(kwargs['input'], RAW)
            self.encrypted += 1
            output = ('inert-cipher-' + str(self.encrypted)).encode()
        else:
            self.assertTrue(kwargs['input'].startswith(b'inert-cipher-'))
            output = RAW
        return types.SimpleNamespace(returncode=0, stdout=output, stderr=b'')

    def prepare(self):
        custody.import_original(self.context, self.state, RAW)
        return custody.receipt(self.state)

    def test_original_import_retry_never_regenerates_ciphertext(self):
        original = self.prepare()
        custody.import_original(self.context, self.state, RAW)
        self.assertEqual(self.encrypted, 1)
        self.assertEqual(custody.verified(self.context, self.state), original)
        with self.assertRaises(Refused):
            custody.import_original(self.context, self.state, b'another inert identity')
        self.assertEqual(custody.receipt(self.state), original)

    def test_nss_or_original_receipt_sync_failure_precedes_secret_tools(self):
        with mock.patch.object(custody.av_accounts, 'verify', side_effect=Refused('NSS drift')):
            with self.assertRaises(Refused):
                self.prepare()
        actual = os.fsync
        def fail(descriptor):
            if os.fstat(descriptor).st_ino == self.context.ROOT.stat().st_ino:
                raise OSError('inert directory storage failure')
            return actual(descriptor)
        with mock.patch.object(os, 'fsync', fail):
            for _ in range(3):
                with self.assertRaises(OSError):
                    self.prepare()
        self.assertEqual(self.calls, [])

    def test_restore_retains_each_ciphertext_and_history_without_implicit_activation(self):
        original = self.prepare()
        self.state['signer_used'] = True
        self.state['signing_history'] = {'inert': 'unchanged original history'}
        result = custody.restore_original(self.context, self.state, RAW)
        self.assertFalse(result['started'])
        self.assertTrue(self.state['cancelled'])
        self.assertEqual(self.state['signing_history'], {'inert': 'unchanged original history'})
        self.assertNotEqual(custody.receipt(self.state), original)
        retained = ROOT + '/cipher-history/' + custody.digest(original) + '.cred'
        self.assertEqual(self.context.read(retained, private=True), original)

    def test_restore_pending_target_survives_removed_stage_before_receipt_clear(self):
        original = self.prepare()
        remove = self.context.remove
        def interruption(name):
            remove(name)
            if name == custody.RESTORE:
                raise OSError('inert interruption after durable staged removal')
        with mock.patch.object(self.context, 'remove', interruption):
            with self.assertRaises(OSError):
                custody.restore_original(self.context, self.state, RAW)
        pending = self.context.json(ROOT + '/owner.json')
        target = custody.receipt(pending)
        self.assertNotEqual(target, original)
        custody.restore_original(self.context, pending, RAW)
        self.assertEqual(custody.receipt(pending), target)
        self.assertEqual(self.encrypted, 2)

    def test_unknown_ciphertext_and_unfenced_restore_are_not_overwritten(self):
        self.prepare()
        self.state['cancelled'] = False
        with self.assertRaises(Refused):
            custody.restore_original(self.context, self.state, RAW)
        self.state['cancelled'] = True
        self.context.write_bytes(custody.CREDENTIAL, b'unrecognized inert ciphertext')
        with self.assertRaises(Refused):
            custody.restore_original(self.context, self.state, RAW)
        self.assertEqual(self.context.read(custody.CREDENTIAL, private=True), b'unrecognized inert ciphertext')


if __name__ == '__main__':
    unittest.main()
