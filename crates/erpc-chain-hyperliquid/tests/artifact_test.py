#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert public artifact fixtures; no downloaded program is executed."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
path = Path(__file__).parents[1] / 'templates/node/erpc_hl_artifact.py'
spec = importlib.util.spec_from_file_location('hyperliquid_artifact_fixture', path)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class Artifact(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = bytes([62, 0])
        self.data = bytes(header) + b'inert artifact, never executable code'
        self.signature, self.key = b'inert detached public signature', b'inert public key'
        h = lambda data: hashlib.sha256(data).hexdigest()
        prefix = a.ORIGINS[0]
        self.pin = {'id': 'visor-' + h(self.data)[:16], 'sha256': h(self.data), 'size': len(self.data),
                    'signature_sha256': h(self.signature), 'signed_at': 123, 'url': prefix + 'hl-visor',
                    'signature_url': prefix + 'hl-visor.asc'}
        self.public = {'sha256': h(self.key), 'primary_fingerprint': 'A' * 40,
                       'url': a.ORIGINS[2] + 'pub_key.asc'}
        self.assets = {self.pin['url']: self.data, self.pin['signature_url']: self.signature,
                       self.public['url']: self.key}
        self.addCleanup(patch.stopall)
        patch.object(a, 'ROOT_UID', os.getuid()).start()

    def opener(self, changed=False, oversized=False):
        class Response:
            status = 200
            def __init__(inner, request): inner.url = request.full_url
            def __enter__(inner): return inner
            def __exit__(inner, *args): return False
            def geturl(inner): return 'http://127.0.0.1/redirected' if changed else inner.url
            def read(inner, limit): return b'x' * limit if oversized else self.assets[inner.url]
        return SimpleNamespace(open=lambda request, **kwargs: Response(request))

    def test_verified_supervisor_is_publicly_executable_under_private_umask(self):
        previous = os.umask(0o077)
        try:
            with patch.object(a.urllib.request, 'build_opener', return_value=self.opener()), \
                 patch.object(a, 'verify') as verify:
                destination = a.install(self.root, {'supervisor': self.pin}, self.public)
                verify.assert_called_once()
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((destination / 'hl-visor').stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((destination / 'publisher.asc').stat().st_mode), 0o444)
                self.assertEqual(a.install(self.root, {'supervisor': self.pin}, self.public), destination)
                self.assertEqual(verify.call_count, 1)
                (destination / 'publisher.asc').chmod(0o600)
                (destination / 'publisher.asc').write_bytes(b'substituted publisher')
                with self.assertRaises(ValueError):
                    a.install(self.root, {'supervisor': self.pin}, self.public)
        finally:
            os.umask(previous)

    def test_changed_signature_or_redirect_never_publishes_a_release(self):
        for changed, oversized in [(True, False), (False, True)]:
            with patch.object(a.urllib.request, 'build_opener', return_value=self.opener(changed, oversized)), \
                 patch.object(a, 'verify') as verify:
                with self.assertRaises(ValueError):
                    a.install(self.root, {'supervisor': self.pin}, self.public)
                verify.assert_not_called()
                self.assertFalse((self.root / self.pin['id']).exists())
        self.assets[self.pin['signature_url']] = b'substituted signature'
        with patch.object(a.urllib.request, 'build_opener', return_value=self.opener()), patch.object(a, 'verify') as verify:
            with self.assertRaises(ValueError):
                a.install(self.root, {'supervisor': self.pin}, self.public)
            verify.assert_not_called()

    def test_gpg_status_must_name_exactly_the_pinned_publisher(self):
        for value in [b'', b'[GNUPG:] VALIDSIG ' + b'B' * 40 + b' 1970-01-01 123 metadata\n',
                      2 * (b'[GNUPG:] VALIDSIG ' + b'A' * 40 + b' 1970-01-01 123 metadata\n')]:
            with tempfile.TemporaryDirectory() as temporary, patch.object(a, 'run', side_effect=[b'', value]):
                with self.assertRaises(ValueError):
                    a.verify(Path(temporary), 'A' * 40, 123)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(a, 'run', side_effect=[b'', b'[GNUPG:] VALIDSIG ' + b'A' * 40 + b' 1970-01-01 123 metadata\n']):
            a.verify(Path(temporary), 'A' * 40, 123)

    def test_native_supervisor_is_never_invoked_by_qualification(self):
        with patch.object(a.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'private', stderr=b'private')) as run:
            with self.assertRaisesRegex(ValueError, '^supervisor publisher verification failed$'):
                a.run(['/usr/bin/gpgv', 'inert-public-proof'])
            self.assertEqual(run.call_args.kwargs['env'], a.ENV)
            self.assertEqual(run.call_args.args[0][0], '/usr/bin/gpgv')


if __name__ == '__main__':
    unittest.main()
