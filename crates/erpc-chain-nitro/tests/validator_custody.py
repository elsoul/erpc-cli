#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original-key custody with inert encryption and real protected temporary files."""
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace as Result
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validator_state import StateFailures
import custody
import host
import storage


class Custody(unittest.TestCase):
    def setUp(self):
        StateFailures.setUp(self)
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        patch.object(host, 'CUSTODY', self.root/'custody').start()
        patch.object(host, 'RUNTIME', self.root/'runtime').start()
        patch.object(host, 'namespaces', return_value=None).start()
        patch.object(custody, 'wallet', return_value=self.contract['wallet']).start()
        # Public scalar-one encoding is an inert fixture, never a generated or
        # operational key; curve derivation and signing are not invoked here.
        self.raw = b'0'*63 + b'1'; self.encrypted = {}; self.transforms = []

    def transform(self, action, value):
        self.transforms.append(action)
        if action == 'encrypt':
            cipher = ('inert-encrypted-generation-' + str(len(self.encrypted))).encode()
            self.encrypted[cipher] = value; return cipher
        return self.encrypted[value]

    def import_key(self, restore=False):
        return custody.import_original(self.store, self.contract, self.intent, self.raw, self.stop, restore, self.transform)

    def test_first_import_has_exact_readback_and_retry_never_rotates_the_original(self):
        result = self.import_key(); self.assertTrue(result['original_verified'])
        original = (self.path/'key-origin.json').read_bytes(); cipher = (host.CUSTODY/'wallet.cred').read_bytes()
        self.assertFalse(self.import_key()['changed'])
        self.assertEqual(self.transforms.count('encrypt'), 1)
        self.assertEqual((self.path/'key-origin.json').read_bytes(), original)
        self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(), cipher)
        self.assertNotIn(self.raw, cipher)
        self.assertEqual((host.CUSTODY/'wallet.cred').stat().st_mode & 0o777, 0o600)
        self.assertEqual(custody.sealed(self.store, self.contract)[0]['wallet'], self.contract['wallet'])

    def test_lost_state_publication_reuses_the_same_staged_ciphertext(self):
        original = self.store.put
        def fail(name, value):
            if name == 'key-current.json': raise OSError('inert lost publication')
            original(name, value)
        with patch.object(self.store, 'put', fail), self.assertRaises(OSError): self.import_key()
        cipher = (host.CUSTODY/'wallet.cred').read_bytes()
        self.assertTrue(self.import_key()['changed'])
        self.assertEqual(self.transforms.count('encrypt'), 1)
        self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(), cipher)

    def test_explicit_restore_retains_original_cipher_and_ambiguous_retry_is_idempotent(self):
        self.import_key(); original = self.store.get('key-origin.json')
        first = (host.CUSTODY/('import-'+self.intent)/'wallet.cred').read_bytes()
        self.intent = 'e'*32; self.store.prepare(self.contract, self.intent, self.target, self.stop)
        (host.CUSTODY/'wallet.cred').unlink()
        with self.assertRaises(FileNotFoundError): self.import_key()
        self.assertTrue(self.import_key(restore=True)['original_verified'])
        self.assertTrue(self.import_key(restore=True)['original_verified'])
        self.assertEqual(self.transforms.count('encrypt'), 2)
        self.assertEqual(self.store.get('key-origin.json'), original)
        self.assertEqual((host.CUSTODY/('import-'+'d'*32)/'wallet.cred').read_bytes(), first)

    def test_foreign_key_or_cancelled_request_never_writes_custody(self):
        with patch.object(custody, 'wallet', return_value='0x'+'2'*40), self.assertRaises(ValueError): self.import_key()
        self.assertFalse(host.CUSTODY.exists()); self.assertEqual(self.transforms, [])
        self.store.stop(self.contract, self.stop)
        with self.assertRaises(ValueError): self.import_key()
        self.assertEqual(self.transforms, [])

    def test_ciphertext_drift_or_orphan_material_does_not_get_silently_repaired(self):
        host.CUSTODY.mkdir(mode=0o700); (host.CUSTODY/'orphan').write_text('retain me')
        with self.assertRaises(ValueError): self.import_key()
        self.assertFalse((self.path/'key-origin.json').exists()); (host.CUSTODY/'orphan').unlink()
        self.import_key(); (host.CUSTODY/'wallet.cred').write_bytes(b'inert corruption')
        with self.assertRaises(ValueError): self.import_key()
        self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(), b'inert corruption')

    def test_native_credential_tool_receives_secret_only_through_stdin_and_has_no_ambient_environment(self):
        with patch.dict(os.environ, {'PYTHONPATH': 'inert', 'LD_PRELOAD': 'inert'}),\
             patch.object(custody.subprocess, 'run', return_value=Result(returncode=0, stdout=b'inert cipher')) as run:
            custody.command('encrypt', self.raw)
        args, options = run.call_args
        self.assertEqual(args[0], ['/usr/bin/systemd-creds', 'encrypt', '--name=arbitrum-wallet', '--with-key=host', '-', '-'])
        self.assertEqual(options['input'], self.raw); self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertNotIn(self.raw.decode(), repr(args[0]))

    def test_runtime_publication_is_atomic_root_owned_and_only_original_numeric_group_can_read(self):
        self.import_key(); records = {'node': {'uid': 20000, 'gid': 20000}}
        original = custody.origin(self.store, self.contract)
        self.store.put('signer-activated.json', {'contract': self.contract, 'origin': original,
                                               'history': {'inert original database identity': True}})
        self.store.prepare(self.contract, 'f'*32, dict(self.target, phase='active'), self.stop)
        self.store.activate(self.contract, 'f'*32, lambda _: None)
        real_lstat, real_fstat = Path.lstat, os.fstat
        groups = {}; publications = []
        def metadata(info):
            values = list(info); values[4] = 0; values[5] = groups.get(info.st_ino, 0)
            return os.stat_result(values)
        def own_path(path, uid, gid):
            self.assertEqual(uid, 0); groups[real_lstat(path).st_ino] = gid
        def own_fd(fd, uid, gid):
            self.assertEqual(uid, 0); groups[real_fstat(fd).st_ino] = gid; publications.append(gid)
        def quiet(record): self.assertEqual(record, records['node'])
        with patch.object(storage, 'ROOT_UID', 0), patch.object(Path, 'lstat', lambda path, *a, **k: metadata(real_lstat(path, *a, **k))),\
             patch.object(os, 'fstat', lambda fd: metadata(real_fstat(fd))), patch.object(os, 'chown', side_effect=own_path),\
             patch.object(os, 'fchown', side_effect=own_fd), patch.object(custody.accounts, 'verify', return_value=records):
            path = custody.stage_runtime(self.store, self.contract, records, self.raw, quiet)
            self.assertEqual(path.lstat().st_uid, 0); self.assertEqual(path.lstat().st_gid, 20000)
            self.assertEqual(path.lstat().st_mode & 0o777, 0o440)
            self.assertEqual(path.parent.lstat().st_mode & 0o777, 0o750)
            self.assertEqual(publications, [20000])
            self.assertEqual(set(item.name for item in path.parent.iterdir()), {'wallet.json'})
            self.assertIn(self.raw, path.read_bytes())

    def test_runtime_key_delivery_refuses_observer_or_nss_drift_before_any_plaintext_publication(self):
        self.import_key(); records = {'node': {'uid': 20000, 'gid': 20000}}
        with self.assertRaises(ValueError): custody.stage_runtime(self.store, self.contract, records, self.raw, lambda _: None)
        self.assertFalse(host.RUNTIME.exists())
        active = dict(self.target, phase='active')
        self.store.prepare(self.contract, 'f'*32, active, self.stop)
        self.store.activate(self.contract, 'f'*32, lambda _: None)
        with patch.object(custody.accounts, 'verify', side_effect=ValueError('inert original account drift')):
            with self.assertRaises(ValueError): custody.stage_runtime(self.store, self.contract, records, self.raw, lambda _: None)
        self.assertFalse(host.RUNTIME.exists())


if __name__ == '__main__':
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(Custody))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
