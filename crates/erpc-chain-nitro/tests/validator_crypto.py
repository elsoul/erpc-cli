#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public vector decoding/recovery only; never generate a key or sign a message.

Optional --library selects a LOCAL TEST libsecp256k1 built from the qualified
source. Production has no environment or CLI override of its fixed OS library.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/validator/node'))
import crypto
import rlp
import storage
LIBRARY = None
if len(sys.argv) == 3 and sys.argv[1] == '--library':
    LIBRARY = Path(sys.argv[2]).resolve(); sys.argv = [sys.argv[0]]
VECTOR = json.loads((ROOT / 'tests/fixtures/bold-public-transaction.json').read_text())


class Encoding(unittest.TestCase):
    def test_public_type2_vector_roundtrips_canonically_without_any_signing(self):
        raw = bytes.fromhex(VECTOR['txbytes'][2:]); decoded = rlp.dynamic_fee(raw)
        self.assertEqual(decoded['chain'], 1); self.assertEqual(decoded['nonce'], 0)
        self.assertEqual(decoded['value'], 0); self.assertEqual(decoded['access_list'], [])
        self.assertEqual(decoded['gas'], 21000)
        self.assertEqual(rlp.encode(rlp.parse(raw[1:])), raw[1:])
        self.assertEqual(decoded['signing_payload'][:1], b'\x02')
        self.assertEqual(len(rlp.parse(decoded['signing_payload'][1:])), 9)

    def test_noncanonical_lengths_integers_nesting_and_trailing_bytes_refuse(self):
        for value in (b'', b'\x81\x01', b'\xb8\x01x', b'\xb9\x00\x38' + b'x'*56,
                      b'\xc1\x81', b'\x80\x80', b'\xc5\xc4\xc3\xc2\xc1\x80'):
            with self.subTest(value=value), self.assertRaises(ValueError): rlp.parse(value)
        with self.assertRaises(ValueError): rlp.integer(b'\x00')
        with self.assertRaises(ValueError): rlp.integer(b'\x01' * 33)
        raw = bytes.fromhex(VECTOR['txbytes'][2:])
        for value in (b'\x01' + raw[1:], raw + b'\x00', raw[:-1]):
            with self.assertRaises(ValueError): rlp.dynamic_fee(value)
        decoded = rlp.parse(raw[1:]); decoded[9] = b'\x02'
        with self.assertRaises(ValueError): rlp.dynamic_fee(b'\x02' + rlp.encode(decoded))

    def test_signature_bounds_refuse_before_loading_any_library(self):
        with patch.object(crypto, 'load', side_effect=AssertionError('must not load')):
            for parity, r, s in [(2, 1, 1), (0, 0, 1), (0, 1, 0), (0, crypto.ORDER, 1),
                                 (0, 1, crypto.ORDER // 2 + 1), (True, 1, 1)]:
                with self.assertRaises(ValueError): crypto.sender(b'\x01' * 32, parity, r, s)

    @unittest.skipUnless(LIBRARY is not None, 'explicit local crypto fixture library not selected')
    def test_actual_os_abi_recovers_published_sender_and_rejects_changed_signature(self):
        from Cryptodome.Hash import keccak
        self.assertTrue(callable(keccak.new))
        raw = bytes.fromhex(VECTOR['txbytes'][2:]); decoded = rlp.dynamic_fee(raw)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve(); library = directory / 'libsecp256k1.fixture'
            shutil.copy(LIBRARY, library)
            with patch.object(storage, 'ROOT_UID', os.getuid()), patch.object(storage, 'TRUST_ANCHOR', directory),\
                 patch.object(crypto, 'LIBRARY', library):
                self.assertTrue(crypto.self_test())
                digest = crypto.keccak(decoded['signing_payload'])
                self.assertEqual(crypto.sender(digest, decoded['parity'], decoded['r'], decoded['s']), VECTOR['sender'])
                self.assertEqual('0x' + crypto.keccak(raw).hex(), VECTOR['hash'])
                self.assertNotEqual(crypto.sender(digest, decoded['parity'] ^ 1, decoded['r'], decoded['s']), VECTOR['sender'])
                self.assertNotEqual(crypto.sender(crypto.keccak(b'inert changed public payload'), decoded['parity'],
                                                  decoded['r'], decoded['s']), VECTOR['sender'])
                library.chmod(0o666)
                with self.assertRaises(ValueError): crypto.sender(digest, decoded['parity'], decoded['r'], decoded['s'])


if __name__ == '__main__': unittest.main()
