#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public RFC8032 vector, inert ciphertext and actual interrupted file publication."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_custody as custody
import native_files as files
import native_state as lifecycle
import native_deployment as deployment
import native_runtime_control as control
from mounts import owner

# RFC8032 section7.1 TEST1, public test material, never an operational credential.
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
RAW = files.encoded(list(SEED + PUBLIC))
EXPECTED = custody.base58(PUBLIC)


class Custody(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temporary.name); directory = self.root / 'state'; directory.mkdir()
        patch.object(custody, 'CUSTODY', self.root / 'ciphertexts').start()
        patch.object(custody, 'root_directory', lambda p, create=False, mode=0o755: p.mkdir(mode=mode, exist_ok=True) if create else None).start()
        patch.object(custody, 'read', lambda p, n: files.read(p, n, os.getuid())).start()
        patch.object(custody, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        patch.object(lifecycle, 'read', lambda p, n: files.read(p, n, os.getuid())).start()
        patch.object(lifecycle, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        patch.object(deployment, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        patch.object(custody, 'public', return_value=PUBLIC).start()
        self.contract = owner(); self.intent = 'a'*32; self.target = {'mode': 'sync', 'identity': EXPECTED}
        self.state = lifecycle.State(directory); self.state.reserve(self.contract)
        self.state.authorize(self.contract, self.intent, self.target, 'deploy')
        self.state.begin(self.contract, self.intent, lambda: None)
        self.encrypted = []; self.quiet = 0
        def crypt(action, raw):
            if action == 'encrypt':
                self.encrypted.append(raw)
                return b'inert-' + str(len(self.encrypted)).encode() + b':' + raw
            return raw.split(b':', 1)[1]
        patch.object(custody, 'crypt', crypt).start()

    def quiescent(self): self.quiet += 1

    def import_key(self, restore=False, **kwargs):
        return custody.import_identity(self.state, self.contract, self.intent, kwargs.get('role', 'sync'),
            kwargs.get('raw', RAW), kwargs.get('expected', EXPECTED), self.quiescent, restore)

    def test_original_cipher_survives_retry_without_reencryption_or_key_replacement(self):
        receipt = self.import_key(); original = (custody.CUSTODY / 'sync.cred').read_bytes()
        self.assertEqual(self.import_key(), receipt); self.assertEqual(len(self.encrypted), 1)
        self.assertEqual((custody.CUSTODY / 'sync.cred').read_bytes(), original)
        self.assertFalse((self.state.directory / 'identity-import-sync.json').exists())
        with self.assertRaises(ValueError): self.import_key(expected=self.contract['identity_account'])
        with self.assertRaises(ValueError): self.import_key(role='withdrawal')

    def test_registered_identity_cannot_enter_an_unrelated_sync_cutover(self):
        with self.assertRaisesRegex(ValueError,'authorized runtime target'):
            self.import_key(role='validator',expected=self.contract['identity_account'])
        self.assertEqual(self.encrypted,[]);self.assertEqual(self.quiet,0)
        self.assertFalse(custody.CUSTODY.exists())

    def recover_original_cutover(self):
        self.state.stop(self.contract,self.quiescent)
        with patch.object(control,'shutdown_all',side_effect=lambda *_:self.quiescent()):
            result=deployment.recover_cutover(self.state,self.contract,self.intent)
        self.assertFalse(result['runtime_started'])
        with self.assertRaises(ValueError):self.import_key()
        self.intent='f'*32
        self.state.authorize(self.contract,self.intent,self.target,'deploy')
        self.state.begin(self.contract,self.intent,self.quiescent)

    def test_cutover_recovery_before_identity_receipt_retains_cipher_and_reimports_same_original(self):
        original=self.state.put
        def fail(name,value):
            if name=='identity-sync.json':raise OSError('inert interruption before original receipt')
            original(name,value)
        with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):self.import_key()
        retained={p:p.read_bytes() for p in custody.CUSTODY.iterdir()}
        self.recover_original_cutover();receipt=self.import_key()
        self.assertEqual(receipt['public'],EXPECTED)
        self.assertTrue(all(path.read_bytes()==raw for path,raw in retained.items()))
        self.assertTrue(all(raw==RAW for raw in self.encrypted))

    def test_cutover_recovery_after_identity_receipt_finishes_original_pending_cipher(self):
        original=os.replace
        def fail(source,destination):
            if Path(destination)==custody.CUSTODY/'sync.cred':raise OSError('inert interruption before credential rename')
            original(source,destination)
        with patch.object(os,'replace',side_effect=fail),self.assertRaises(OSError):self.import_key()
        receipt=self.state.get('identity-sync.json')
        encrypted=(custody.CUSTODY/receipt['pending']).read_bytes()
        self.recover_original_cutover()
        self.assertEqual(self.import_key(),receipt)
        self.assertEqual((custody.CUSTODY/'sync.cred').read_bytes(),encrypted)
        self.assertEqual(len(self.encrypted),1)

    def test_cutover_recovery_during_restore_preserves_previously_original_cipher(self):
        first=self.import_key();original_cipher=(custody.CUSTODY/'sync.cred').read_bytes()
        self.intent='b'*32;self.state.authorize(self.contract,self.intent,self.target,'deploy')
        self.state.begin(self.contract,self.intent,self.quiescent)
        original=self.state.put
        def fail(name,value):
            if name=='identity-sync.json':raise OSError('inert restored ciphertext awaits receipt')
            original(name,value)
        with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):self.import_key(restore=True)
        retained={p:p.read_bytes() for p in custody.CUSTODY.iterdir()}
        self.recover_original_cutover()
        self.assertEqual(self.import_key(),first)
        self.assertEqual((custody.CUSTODY/'sync.cred').read_bytes(),original_cipher)
        self.assertTrue(all(path.read_bytes()==raw for path,raw in retained.items()))

    def test_wrong_native_public_half_boolean_and_unexpected_json_refuse(self):
        for value in ([True] + list((SEED + PUBLIC)[1:]), list(SEED + b'\x00'*32), {'key': list(SEED + PUBLIC)}, [1]*63):
            with self.assertRaises(ValueError): self.import_key(raw=files.encoded(value))
        self.assertEqual(self.encrypted, [])

    def test_cipher_without_original_receipt_is_not_adopted(self):
        custody.CUSTODY.mkdir(); (custody.CUSTODY / 'sync.cred').write_bytes(b'inert orphan')
        with self.assertRaises(ValueError): self.import_key()
        self.assertEqual(self.encrypted, [])

    def test_stop_revokes_a_previously_authorized_key_import(self):
        self.state.stop(self.contract, lambda: None)
        with self.assertRaises(ValueError): self.import_key()
        self.assertEqual(self.encrypted, []); self.assertEqual(self.quiet, 0)

    def test_rpc_stores_only_its_original_nonvoting_identity(self):
        self.contract = dict(self.contract, profile='agave-native-rpc', identity_account=EXPECTED,
                             vote_account=None, authority_account=None)
        folder = self.root / 'rpc-state'; folder.mkdir(); self.state = lifecycle.State(folder)
        self.state.reserve(self.contract)
        self.state.authorize(self.contract, self.intent, {'mode': 'rpc', 'identity': EXPECTED}, 'deploy')
        self.state.begin(self.contract, self.intent, lambda: None)
        self.assertEqual(self.import_key(role='rpc')['public'], EXPECTED)
        self.assertTrue((custody.CUSTODY / 'rpc.cred').exists())
        for role in ('sync', 'validator'):
            with self.assertRaises(ValueError): self.import_key(role=role)

    def test_explicit_restore_retains_an_independent_original_cipher_inode(self):
        first = self.import_key(); target = custody.CUSTODY / 'sync.cred'; old = target.read_bytes()
        self.intent = 'b'*32; self.state.authorize(self.contract, self.intent, self.target, 'deploy')
        self.state.begin(self.contract, self.intent, lambda: None)
        restored = self.import_key(restore=True)
        previous = custody.CUSTODY / ('sync.previous.' + first['cipher_sha256'] + '.cred')
        self.assertEqual(previous.read_bytes(), old)
        self.assertNotEqual(previous.stat().st_ino, target.stat().st_ino)
        self.assertEqual(previous.stat().st_nlink, 1)
        self.assertNotEqual(first['cipher_sha256'], restored['cipher_sha256'])
        self.assertEqual(first['plaintext_sha256'], restored['plaintext_sha256'])
        self.assertEqual(self.import_key(restore=True), restored); self.assertEqual(len(self.encrypted), 2)

    def test_pending_cipher_and_receipt_retry_before_failed_final_directory_sync(self):
        original = custody.os.replace
        def failed(source, destination):
            if Path(destination) == custody.CUSTODY / 'sync.cred': raise OSError('inert rename failure')
            return original(source, destination)
        with patch.object(custody.os, 'replace', failed):
            with self.assertRaises(OSError): self.import_key()
        self.assertTrue((self.state.directory / 'identity-sync.json').exists())
        recovered = self.import_key()
        self.assertEqual(len(self.encrypted), 1)
        self.assertEqual(hashlib.sha256((custody.CUSTODY / 'sync.cred').read_bytes()).hexdigest(), recovered['cipher_sha256'])

    def test_corrupt_cipher_requires_explicit_original_key_restore_and_is_retained(self):
        self.import_key(); target = custody.CUSTODY / 'sync.cred'
        bad = b'inert corrupted ciphertext'; target.write_bytes(bad)
        with self.assertRaises(ValueError): self.import_key()
        self.intent = 'c'*32; self.state.authorize(self.contract, self.intent, self.target, 'deploy')
        self.state.begin(self.contract, self.intent, lambda: None)
        restored = self.import_key(restore=True)
        quarantine = custody.CUSTODY / ('sync.unrecognized.' + hashlib.sha256(bad).hexdigest() + '.cred')
        self.assertEqual(quarantine.read_bytes(), bad)
        self.assertEqual(restored['public'], EXPECTED)
        self.assertNotEqual(target.read_bytes(), bad)

    def test_visible_receipt_is_synchronized_before_cipher_publication_on_retry(self):
        original = custody.os.replace
        def failed(source, destination):
            if Path(destination) == custody.CUSTODY / 'sync.cred': raise OSError('inert pending rename')
            return original(source, destination)
        with patch.object(custody.os, 'replace', failed):
            with self.assertRaises(OSError): self.import_key()
        self.assertFalse((custody.CUSTODY / 'sync.cred').exists())
        with patch.object(custody, 'sync_file', side_effect=OSError('persistent receipt fsync failure')):
            with self.assertRaises(OSError): self.import_key()
        self.assertFalse((custody.CUSTODY / 'sync.cred').exists())
        self.assertEqual(len(self.encrypted), 1)
        self.import_key()

    def test_real_control_dispatch_keeps_import_result_public_and_rechecks_owner(self):
        import native_runtime_control as control
        request = {'action': 'import-identity', 'contract': self.contract, 'intent': self.intent,
                   'role': 'sync', 'key_file': RAW.decode(), 'expected': EXPECTED, 'restore': False}
        with patch.object(control, 'shutdown', side_effect=lambda *_args: self.quiescent()):
            result = control.dispatch(self.state, self.contract, request)
        self.assertEqual(result, {'identity': EXPECTED, 'role': 'sync', 'custody_verified': True})
        before = list(self.encrypted)
        with self.assertRaises(ValueError):
            control.dispatch(self.state, self.contract, dict(request, contract=dict(self.contract, name='foreign')))
        self.assertEqual(self.encrypted, before)

    def test_each_real_first_import_fsync_failure_preserves_retry_with_original_key(self):
        # Each case gets its own real state namespace. Mock only host/root/crypto
        # authority, while file contents, fsync position and replacement are real.
        for fail_at in range(1, 25):
            child = Custody(); child.setUp()
            try:
                original = custody.os.fsync; count = [0]; injected = [False]
                def failed(fd):
                    count[0] += 1
                    if count[0] == fail_at:
                        injected[0] = True; raise OSError('inert fsync failure')
                    return original(fd)
                with patch.object(custody.os, 'fsync', failed):
                    try: child.import_key()
                    except OSError: self.assertTrue(injected[0])
                    else: self.assertFalse(injected[0])
                receipt = child.import_key()
                self.assertEqual(receipt['public'], EXPECTED)
                self.assertEqual(receipt['plaintext_sha256'], hashlib.sha256(RAW).hexdigest())
                self.assertTrue(all(raw == RAW for raw in child.encrypted))
                self.assertFalse((child.state.directory / 'identity-import-sync.json').exists())
            finally: child.doCleanups()


class Derivation(unittest.TestCase):
    def test_rfc8032_public_derivation_uses_stdin_not_an_argument_or_environment(self):
        executable = next((p for p in ('/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/bin/openssl') if Path(p).is_file()), None)
        if executable is None: self.skipTest('OpenSSL not installed')
        original = custody.native_command; commands = []
        def run(argv, raw, maximum):
            commands.append((argv, raw, maximum))
            return original([executable, *argv[1:]], raw, maximum)
        with patch.object(custody, 'native_command', run):
            self.assertEqual(custody.public(SEED), PUBLIC)
        self.assertEqual(commands[0][0], ['/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'])
        self.assertEqual(commands[0][1], custody.PKCS8 + SEED)


if __name__ == '__main__': unittest.main()
