#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert filesystem/process metadata only: no key generator or device operations."""
import base64
import copy
import importlib.util
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
import erpc_monad_device as device
import erpc_monad_identity as identity

UUID = 'abcdefab-abcd-abcd-abcd-abcdefabcdef'
PUBLIC = {'secp': '02' + 'ab' * 32, 'bls': 'ab' * 48}


def records():
    partition = {'path': '/dev/nvme1n1p1', 'type': 'part', 'partuuid': UUID, 'size': 3_000_000_000_000,
                 'start': 2048, 'log-sec': 512, 'phy-sec': 4096, 'ro': False, 'mountpoints': [None],
                 'fstype': None, 'uuid': None, 'pkname': '/dev/nvme1n1', 'serial': None, 'maj:min': '259:3'}
    return [{'path': '/dev/nvme1n1', 'type': 'disk', 'ro': False, 'serial': 'fixture-device',
             'size': 3_100_000_000_000, 'mountpoints': [None], 'fstype': None, 'children': [partition]}]


def qualify(data):
    return device.qualify_inventory(data, UUID, '/dev/nvme1n1p1', '259:3', set())


def native(suffix):
    # Artificial format fixture. It is neither decrypted nor used for signing.
    return common.json_bytes({'version': 2, 'ciphertext': suffix * 64, 'checksum': 'b' * 64,
                              'hash': 'SHA256', 'cipher': {'cipher_function': 'AES_128_CTR',
                              'params': {'iv': 'c' * 32}}, 'kdf': {'kdf_name': 'scrypt', 'params': {
                              'salt': 'd' * 64, 'key_len': 32, 'N': 262144, 'r': 8, 'p': 1}}})


def bundle():
    return common.json_bytes({'schema': 1, **{k: {'public_key': PUBLIC[k],
                             'keystore_base64': base64.b64encode(native(v)).decode()}
                             for k, v in [('secp', 'a'), ('bls', 'b')]}})


class DeviceTests(unittest.TestCase):
    def test_partuuid_and_physical_geometry_are_immutable_across_device_renumbering(self):
        before = qualify(records())
        after = dict(before, path='/dev/nvme2n1p1', major_minor='259:7', parent='/dev/nvme2n1')
        device.same_device(before, after)
        for key in ('partuuid', 'size', 'start', 'disk_serial', 'logical_sector', 'physical_sector', 'disk_size'):
            changed = dict(after, **{key: 'different'})
            with self.assertRaises(ValueError, msg=key):
                device.same_device(before, changed)

    def test_selected_and_parent_mounts_swap_signatures_and_mappers_refuse(self):
        for field, value in [('ro', True), ('log-sec', 4096), ('size', 100000),
                             ('fstype', 'ext4'), ('uuid', 'filesystem'), ('mountpoints', ['/data']),
                             ('type', 'crypt'), ('maj:min', '259:5'), ('start', 0)]:
            data = records()
            data[0]['children'][0][field] = value
            with self.assertRaises(ValueError, msg=field):
                qualify(data)
        data = records()
        data[0]['children'].append({'path': '/dev/nvme1n1p2', 'type': 'part', 'mountpoints': ['/']})
        with self.assertRaises(ValueError):
            qualify(data)
        with self.assertRaises(ValueError):
            device.qualify_inventory(records(), UUID, '/dev/nvme1n1p1', '259:3', {'/dev/nvme1n1p1'})

    def test_duplicate_partition_uuid_is_refused(self):
        with self.assertRaises(ValueError):
            qualify(records() + records())


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.reader = patch.object(identity, 'read', lambda p, limit=1048576: common.read(p, limit, os.getuid()))
        self.reader.start()
        self.calls = []

    def tearDown(self):
        self.reader.stop()
        self.tmp.cleanup()

    def verify(self, data, kind):
        self.calls.append(kind)
        return PUBLIC[kind]

    @staticmethod
    def seal(value, kind):
        return b'INERT-SEALED:' + value

    @staticmethod
    def unseal(value, kind):
        return value.removeprefix(b'INERT-SEALED:')

    def install(self):
        return identity.import_once(self.root, bundle(), PUBLIC, self.verify, self.seal)

    def test_original_bytes_and_both_public_keys_are_pinned_and_checked(self):
        original = self.install()
        self.assertEqual(self.calls, ['secp', 'bls'])
        identity.check(self.root, PUBLIC, self.verify, self.unseal)
        self.assertEqual(original, json.loads((self.root / 'identity.json').read_bytes()))
        item = json.loads(bundle())
        data = json.loads(base64.b64decode(item['secp']['keystore_base64']))
        # Semantically equal reserialization is still a different original file.
        item['secp']['keystore_base64'] = base64.b64encode(json.dumps(data, indent=2).encode()).decode()
        with self.assertRaises(ValueError):
            identity.import_once(self.root, common.json_bytes(item), PUBLIC, self.verify, self.seal)

    def test_interrupted_initial_publication_resumes_its_receipt_without_new_encryption(self):
        actual = identity.atomic
        def interrupted(path, data):
            if path.name == 'monad-bls.cred':
                raise OSError('inert interruption')
            actual(path, data)
        with patch.object(identity, 'atomic', interrupted):
            with self.assertRaises(OSError):
                self.install()
        receipt = (self.root / 'identity.json').read_bytes()
        identity.import_once(self.root, bundle(), PUBLIC, self.verify,
                             lambda *_: self.fail('a durable receipt must not generate new ciphertext'))
        self.assertEqual(receipt, (self.root / 'identity.json').read_bytes())

    def test_established_missing_corrupt_and_substituted_identity_never_auto_regenerates(self):
        self.install()
        path = self.root / 'monad-secp.cred'
        original = path.read_bytes()
        for replacement in (None, b'corrupt', original + b'substituted'):
            path.unlink(missing_ok=True)
            if replacement is not None:
                path.write_bytes(replacement)
            with self.assertRaises((ValueError, FileNotFoundError)):
                identity.check(self.root, PUBLIC, self.verify, self.unseal)
            with self.assertRaises(ValueError):
                self.install()
            identity.restore(self.root, bundle(), PUBLIC, self.verify, self.seal)
            self.assertEqual(path.read_bytes(), original)

    def test_orphan_ciphertext_and_public_identity_mismatch_cannot_be_adopted(self):
        (self.root / 'monad-secp.cred').write_bytes(b'orphan')
        with self.assertRaises(ValueError):
            self.install()
        (self.root / 'monad-secp.cred').unlink()
        with self.assertRaises(ValueError):
            identity.import_once(self.root, bundle(), PUBLIC, lambda *_: '03' + 'cd' * 32, self.seal)
        self.assertFalse((self.root / 'identity.json').exists())

    def test_explicit_restore_can_reseal_original_bytes_after_host_key_rotation(self):
        old = self.install()
        identity.restore(self.root, bundle(), PUBLIC, self.verify, lambda value, kind: b'NEW-HOST:' + value)
        new = json.loads((self.root / 'identity.json').read_bytes())
        self.assertEqual(old['secp']['plain_sha256'], new['secp']['plain_sha256'])
        self.assertNotEqual(old['secp']['cipher_sha256'], new['secp']['cipher_sha256'])
        self.assertTrue(list(self.root.glob('identity-previous-*.json')))

    def test_interrupted_restore_resumes_only_its_published_ciphertexts(self):
        self.install()
        actual = identity.atomic
        def fail(path, data):
            if path.name == 'monad-bls.cred':
                raise OSError('interrupted replacement')
            actual(path, data)
        with patch.object(identity, 'atomic', fail):
            with self.assertRaises(OSError):
                identity.restore(self.root, bundle(), PUBLIC, self.verify, lambda value, kind: b'NEXT:' + value)
        with self.assertRaises(ValueError):
            identity.check(self.root, PUBLIC, self.verify, self.unseal)
        identity.restore(self.root, bundle(), PUBLIC, self.verify, lambda *_: self.fail('must reuse pending ciphertext'))
        self.assertFalse((self.root / 'identity-restore-pending.json').exists())

    def test_kdf_and_duplicate_fields_are_bounded_before_native_execution(self):
        for name, value in [('N', 2**40), ('r', 1024), ('p', 4096), ('key_len', 999), ('N', True)]:
            data = json.loads(native('a'))
            data['kdf']['params'][name] = value
            with self.assertRaises(ValueError):
                identity.keystore(common.json_bytes(data))
        with self.assertRaises(ValueError):
            identity.keystore(native('a').replace(b'"version":2', b'"version":2,"version":2'))


if __name__ == '__main__':
    unittest.main()
