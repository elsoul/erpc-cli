# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Credential and protocol failure cases; native tools and all network I/O mocked."""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1] / 'templates' / 'jinja'


def load():
    loader = importlib.machinery.SourceFileLoader('validator', str(ROOT / 'erpc-sui-validator.py.j2'))
    spec = importlib.util.spec_from_loader('validator', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Validator(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.m.CREDENTIALS = self.root / 'sui-validator'
        self.m.MARKER = self.root / 'receipt'
        self.m.METADATA = self.root / 'validator.json'
        # Synthetic bytes only: native key derivation is mocked, no keys generated.
        self.metadata = {'info': {'account-address': '0x' + '0' * 64}}
        for name, length in [('protocol', 96), ('network', 32), ('worker', 32)]:
            self.metadata['info'][name + '-key'] = base64.b64encode(bytes([length]) * length).decode()
        self.m.METADATA.write_text(json.dumps(self.metadata))
        self.payload = {name: base64.b64encode(bytes(32 if name == 'protocol' else 33)).decode()
                        for name in self.m.KEYS}
        self.calls = []
        original_temp = tempfile.TemporaryDirectory
        self.temp = patch.object(self.m.tempfile, 'TemporaryDirectory',
                                 side_effect=lambda **kw: original_temp(prefix=kw.get('prefix', ''), dir=self.root))
        self.temp.start()
        self.addCleanup(self.temp.stop)

    def native(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == 'systemd-creds':
            pathlib.Path(argv[-1]).write_bytes(pathlib.Path(argv[-2]).read_bytes())
            return subprocess.CompletedProcess(argv, 0)
        self.assertEqual(argv[:4], ['/opt/sui/current/sui', 'keytool', '--json', 'show'])
        name = pathlib.Path(argv[4]).stem
        raw = base64.b64decode(self.metadata['info'][name + '-key'])
        public = raw if name == 'protocol' else bytes([0]) + raw
        result = {'publicBase64Key': base64.b64encode(public).decode(),
                  'keyScheme': 'bls12381' if name == 'protocol' else 'ed25519'}
        return subprocess.CompletedProcess(argv, 0, json.dumps(result).encode())

    def imported(self):
        with patch.object(self.m, 'observe', return_value={'keys_in_active_set': False}), \
                patch.object(self.m.subprocess, 'run', side_effect=self.native):
            self.m.import_keys(self.metadata, 'testnet', self.payload)

    def test_initial_import_binds_three_keys_and_redeploy_preserves_ciphertext(self):
        self.imported()
        before = self.m.MARKER.read_bytes()
        with patch.object(self.m, 'observe', side_effect=AssertionError('no network required')), \
                patch.object(self.m.subprocess, 'run', side_effect=self.native):
            self.m.import_keys(self.metadata, 'testnet', self.payload)
        self.assertEqual(before, self.m.MARKER.read_bytes())
        self.assertEqual(sum(c[:2] == ['systemd-creds', 'encrypt'] for c in self.calls), 3)
        self.assertFalse(any('make-validator-info' in c for c in self.calls))

    def test_owner_key_and_active_duplicate_refused_before_encryption(self):
        with patch.object(self.m.subprocess, 'run', side_effect=self.native), \
                patch.object(self.m, 'observe', return_value={'keys_in_active_set': True}):
            with self.assertRaises(ValueError):
                self.m.import_keys(self.metadata, 'testnet', dict(self.payload, owner='refused'))
            with self.assertRaises(ValueError):
                self.m.import_keys(self.metadata, 'testnet', self.payload)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.m.CREDENTIALS.exists())

    def test_wrong_key_does_not_publish_partial_bundle(self):
        expected = self.metadata['info']['worker-key']
        self.metadata['info']['worker-key'] = base64.b64encode(bytes([17]) * 32).decode()
        def wrong(path, directory):
            name = pathlib.Path(path).stem
            return expected if name == 'worker' else self.metadata['info'][name + '-key']
        with patch.object(self.m, 'public_key', side_effect=wrong), \
                patch.object(self.m, 'observe', return_value={'keys_in_active_set': False}), \
                patch.object(self.m.subprocess, 'run', side_effect=self.native):
            with self.assertRaises(ValueError):
                self.m.import_keys(self.metadata, 'testnet', self.payload)
        self.assertFalse(self.m.CREDENTIALS.exists())
        self.assertFalse(self.m.MARKER.exists())

    def test_partial_loss_requires_explicit_same_host_restore(self):
        self.imported()
        (self.m.CREDENTIALS / 'worker.key').unlink()
        with patch.object(self.m.subprocess, 'run', side_effect=self.native), \
                patch.object(self.m, 'observe', side_effect=AssertionError('restore is same-host')):
            with self.assertRaises(OSError):
                self.m.import_keys(self.metadata, 'testnet', self.payload)
            self.m.import_keys(self.metadata, 'testnet', self.payload, restore=True)
            self.m.check_keys(self.metadata)
        self.assertEqual(len(list(self.root.glob('sui-validator.quarantine.*'))), 1)

    def test_restore_refuses_missing_receipt_or_changed_metadata(self):
        with self.assertRaises(ValueError):
            self.m.import_keys(self.metadata, 'testnet', self.payload, restore=True)
        self.imported()
        self.m.METADATA.write_text('{}')
        before = self.m.MARKER.read_bytes()
        with self.assertRaises(ValueError):
            self.m.import_keys(self.metadata, 'testnet', self.payload, restore=True)
        self.assertEqual(before, self.m.MARKER.read_bytes())

    def test_keytool_flag_normalization_and_wrong_scheme(self):
        with patch.object(self.m.subprocess, 'run', side_effect=self.native):
            for name in self.m.KEYS:
                self.assertEqual(self.m.public_key(self.root / (name + '.key'), self.root),
                                 self.metadata['info'][name + '-key'])
        result = {'publicBase64Key': base64.b64encode(bytes(33)).decode(), 'keyScheme': 'secp256k1'}
        with patch.object(self.m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(result).encode())):
            with self.assertRaises(ValueError):
                self.m.public_key(self.root / 'network.key', self.root)

    def test_protobuf_rejects_truncation_oversize_and_duplicate_singular(self):
        for value in [b'\x00', b'\x0b', b'\x0a\x05a', b'\x08' + b'\xff' * 10, b'\x0d\x00']:
            with self.assertRaises(ValueError):
                self.m.fields(value)
        with self.assertRaises(ValueError):
            self.m.one({1: [1, 2]}, 1)

    def observation(self, *, age=0, chain=None, epoch=23, second_epoch=None, protocol=139):
        b = self.m.blob_field
        service = {1: [(chain or self.m.ENDPOINTS['testnet'][2]).encode()], 2: [b'testnet'],
                   3: [epoch], 5: [bytes([8]) + self.m.encoded_varint(int(time.time()) - age)]}
        active = b(2, self.metadata['info']['account-address'].encode())
        for field, name in [(7, 'protocol'), (10, 'network'), (12, 'worker')]:
            active += b(field, base64.b64decode(self.metadata['info'][name + '-key']))
        validators = b(2, active) + b(9, b(1, b'0x123'))
        system = bytes([24]) + self.m.encoded_varint(protocol) + b(4, validators)
        epoch_response = {1: [bytes([8]) + self.m.encoded_varint(epoch) + b(3, system)]}
        def response(network, method, *args, **kwargs):
            if method == 'GetServiceInfo':
                value = dict(service)
                if second_epoch is not None and response.count:
                    value[3] = [second_epoch]
                response.count += 1
                return value
            return epoch_response if method == 'GetEpoch' else {}
        response.count = 0
        return response

    def test_network_epoch_freshness_and_public_key_binding(self):
        for kwargs in [dict(age=121), dict(age=-31), dict(chain='another'), dict(second_epoch=24)]:
            with patch.object(self.m, 'rpc', side_effect=self.observation(**kwargs)):
                with self.assertRaises(ValueError):
                    self.m.observe('testnet', self.metadata)
        with patch.object(self.m, 'rpc', side_effect=self.observation()):
            value = self.m.observe('testnet', self.metadata)
        self.assertEqual(value['membership'], 'active')
        self.assertTrue(value['keys_match'])
        self.assertTrue(value['keys_in_active_set'])

    def test_admission_phases_pagination_and_unknown_protocol(self):
        b = self.m.blob_field
        table = {9: [b(1, b'0x123')]}
        name = b(1, b'0x3::validator_set::VotingPowerAdmissionStartEpochKey')
        entry = b(5, name) + b(6, b(2, (100).to_bytes(8, 'little'))) + b(7, b'u64')
        with patch.object(self.m, 'rpc', return_value={1: [entry]}):
            for epoch, expected in [(99, 12), (113, 12), (114, 6), (127, 6), (128, 3)]:
                for protocol in (139, 140):
                    self.assertEqual(self.m.admission('testnet', table, epoch, protocol)['minimum_joining_voting_power'], expected)
        with patch.object(self.m, 'rpc', return_value={2: [b'next']}):
            self.assertEqual(self.m.admission('testnet', table, 128, 139)['status'], 'unknown')
        with patch.object(self.m, 'rpc', side_effect=AssertionError('unknown policy must not infer')):
            self.assertEqual(self.m.admission('testnet', table, 128, 141)['status'], 'unknown')
            self.assertEqual(self.m.admission('mainnet', table, 128, 140)['status'], 'unknown')

    def test_grpc_failed_trailer_or_compressed_response_refused(self):
        def native(trailer, frame):
            def run(argv, **kwargs):
                pathlib.Path(argv[argv.index('-D') + 1]).write_text('HTTP/2 200\n' + trailer)
                pathlib.Path(argv[argv.index('-o') + 1]).write_bytes(frame)
                return subprocess.CompletedProcess(argv, 0)
            return run
        for trailers, frame in [('grpc-status: 14\n', bytes(5)), ('', bytes(5)),
                                ('grpc-status: 0\n', bytes([1, 0, 0, 0, 0])),
                                ('grpc-status: 0\n', bytes(6))]:
            with patch.object(self.m.subprocess, 'run', side_effect=native(trailers, frame)):
                with self.assertRaises(ValueError):
                    self.m.rpc('testnet', 'GetServiceInfo')
        with self.assertRaises(ValueError):
            self.m.rpc('testnet', 'ExecuteTransaction')


if __name__ == '__main__':
    unittest.main()
