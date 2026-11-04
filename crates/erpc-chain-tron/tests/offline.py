# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert native API stubs and filesystem/process fixtures. No chain client runs."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PUBLIC = 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb'


def load():
    spec = importlib.util.spec_from_file_location('tron_identity', ROOT / 'templates/jinja/identity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture():
    return {'version': 3, 'address': PUBLIC, 'crypto': {
        'cipher': 'aes-128-ctr', 'cipherparams': {'iv': '00' * 16},
        'ciphertext': '00' * 32, 'mac': '00' * 32, 'kdf': 'scrypt',
        'kdfparams': {'n': 262144, 'r': 8, 'p': 1, 'dklen': 32, 'salt': '00' * 32}}}


class Custody(unittest.TestCase):
    def test_public_address_checksum_and_supported_keystore_bounds(self):
        module = load()
        self.assertEqual(module.address(PUBLIC), bytes([65]) + bytes(20))
        for invalid in [PUBLIC[:-1] + 'a', '0x' + '00' * 20, 'T' * 35, 'T0' + PUBLIC[2:]]:
            with self.assertRaises((ValueError, OverflowError)):
                module.address(invalid)
        value = fixture()
        with self.assertRaises(ValueError):
            module.keystore(json.dumps(value).replace('"version": 3', '"version": 3, "version": 3'), PUBLIC)
        self.assertEqual(module.keystore(json.dumps(value), PUBLIC), value)
        for field, invalid in [('n', 1 << 30), ('n', 17), ('r', 100), ('p', 100), ('dklen', 64), ('n', True)]:
            changed = copy.deepcopy(value)
            changed['crypto']['kdfparams'][field] = invalid
            with self.assertRaises(ValueError):
                module.keystore(json.dumps(changed), PUBLIC)
        for field in ['owner-key', 'privateKey']:
            changed = copy.deepcopy(value)
            changed[field] = 'fixture must be refused'
            with self.assertRaises(ValueError):
                module.keystore(json.dumps(changed), PUBLIC)

    def test_inspection_uses_stdin_and_only_accepts_native_derived_address(self):
        module = load()
        calls = []
        def native(argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(json.loads(Path(argv[-1]).read_text()), fixture())
            self.assertNotIn('fixture password', ' '.join(argv))
            self.assertEqual(set(kwargs['env']), {'PATH', 'LANG'})
            self.assertNotIn('fixture password', str(kwargs['env']))
            self.assertEqual(kwargs['input'], b'fixture password\n')
            return subprocess.CompletedProcess(argv, 0, (PUBLIC + '\n').encode())
        def temporary(**kwargs):
            self.assertEqual(kwargs['dir'], '/run')
            return tempfile.TemporaryDirectory(prefix=kwargs['prefix'])
        self.assertEqual(module.inspect(json.dumps(fixture()), 'fixture password', PUBLIC, 'x86_64', native, temporary), PUBLIC)
        self.assertFalse(Path(calls[0][0][-1]).exists())
        for code, output in [(1, b'private failure text'), (0, b'wrong public key')]:
            def rejected(argv, **kwargs):
                return subprocess.CompletedProcess(argv, code, output)
            with self.assertRaisesRegex(ValueError, 'native keystore authentication'):
                module.inspect(json.dumps(fixture()), 'fixture password', PUBLIC, 'aarch64', rejected, temporary)
        for password in ['short', 'multi\nline', '\ufeffsecret', 'secret\0value']:
            with self.assertRaises(ValueError):
                module.inspect(json.dumps(fixture()), password, PUBLIC, 'x86_64', native, temporary)
        self.assertEqual(len(calls), 1)


class NativeAdapter(unittest.TestCase):
    def test_adapter_compiles_against_api_shape_and_redacts_native_errors(self):
        # These are inert API-shape stubs, not java-tron or a cryptographic wallet.
        # Actual pinned-JAR execution remains part of deferred Linux acceptance.
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac, 'JDK needed for adapter compilation')
        self.assertIsNotNone(java, 'JDK needed for adapter execution')
        with tempfile.TemporaryDirectory(prefix='tron-java-fixture-') as directory:
            root = Path(directory)
            wallet = root / 'org/tron/keystore/WalletUtils.java'
            util = root / 'org/tron/common/utils/StringUtil.java'
            wallet.parent.mkdir(parents=True)
            util.parent.mkdir(parents=True)
            wallet.write_text('''package org.tron.keystore;
public class WalletUtils {
  public static Credentials loadCredentials(String password, java.io.File file, boolean ecKey) throws Exception {
    if (!ecKey || password.equals("fail-secret")) throw new Exception("native error " + password);
    return new Credentials();
  }
  public static class Credentials { public Sign getSignInterface() { return new Sign(); } }
  public static class Sign { public byte[] getAddress() { return new byte[21]; } }
}''')
            util.write_text('package org.tron.common.utils; public class StringUtil { public static String encode58Check(byte[] value) { return "' + PUBLIC + '"; }}')
            adapter = root / 'ErpcTronKey.java'
            shutil.copyfile(ROOT / 'templates/ErpcTronKey.java', adapter)
            subprocess.run([javac, '-d', str(root), str(wallet), str(util), str(adapter)], check=True, capture_output=True)
            command = [java, '-cp', str(root), 'ErpcTronKey', str(root / 'encrypted.json')]
            for password, success in [(b'fixture password\n', True), (b'fail-secret\n', False), (b'short\n', False), (b'x' * 2048, False)]:
                result = subprocess.run(command, input=password, capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, success)
                if success:
                    self.assertEqual(result.stdout.decode().strip(), PUBLIC)
                else:
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr.strip(), b'TRON keystore validation failed')
                    self.assertNotIn(password.strip(), result.stderr)


if __name__ == '__main__':
    unittest.main()
