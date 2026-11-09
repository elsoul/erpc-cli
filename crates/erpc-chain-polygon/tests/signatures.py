#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public Ethereum recovery only; optional qualified C fixture never signs."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
import signatures
LIBRARY=None
if len(sys.argv)==3 and sys.argv[1]=='--library':
    LIBRARY=Path(sys.argv[2]).resolve();sys.argv=[sys.argv[0]]


class PublicRecovery(unittest.TestCase):
    def test_invalid_scalar_bounds_refuse_before_loading_cryptographic_code(self):
        with patch.object(signatures,'load',side_effect=AssertionError('must not load')):
            for parity,r,s in [(2,1,1),(True,1,1),(0,0,1),(0,1,0),(0,signatures.ORDER,1),(0,1,signatures.ORDER//2+1)]:
                with self.assertRaises(ValueError):signatures.sender(bytes(32),parity,r,s)

    def test_only_reviewed_native_architectures_select_fixed_os_library_paths(self):
        for machine,directory in [('x86_64','x86_64-linux-gnu'),('aarch64','aarch64-linux-gnu')]:
            with patch.object(signatures.platform,'machine',return_value=machine):
                self.assertEqual(signatures.library_path(),Path('/usr/lib')/directory/'libsecp256k1.so.1')
        with patch.object(signatures.platform,'machine',return_value='unqualified'),self.assertRaises(ValueError):
            signatures.library_path()

    @unittest.skipUnless(LIBRARY is not None,'explicit qualified public-vector library not selected')
    def test_actual_public_vector_abi_and_library_trust(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();library=root/'secp-public-fixture';shutil.copy(LIBRARY,library)
            with patch.object(signatures,'ROOT_UID',os.getuid()),patch.object(signatures,'TRUST_ANCHOR',root),\
                 patch.object(signatures,'library_path',return_value=library):
                self.assertTrue(signatures.self_test())
                library.chmod(0o666)
                with self.assertRaises(ValueError):signatures.self_test()
                library.chmod(0o644);link=root/'unknown-selector';link.symlink_to(library.name)
                with patch.object(signatures,'library_path',return_value=link),self.assertRaises(ValueError):
                    signatures.self_test()


if __name__=='__main__':unittest.main()
