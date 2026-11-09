#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Observed official OCI bytes bind the validator-only catalog, without layers."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/validator/node'))
import protocol
import configuration


class Artifact(unittest.TestCase):
    def fixture(self, name, digest):
        raw = (ROOT / ('tests/fixtures/validator-3122-' + name + '.json')).read_bytes()
        self.assertEqual('sha256:' + hashlib.sha256(raw).hexdigest(), digest)
        return json.loads(raw), len(raw)

    def test_observed_index_platform_manifest_and_config_bind_the_actual_validator_catalog(self):
        index, _ = self.fixture('index', 'sha256:87548501c3ee41cff84e6764cc86f65eb7f0a14e2e50a0d3219d462e5793680d')
        manifest, length = self.fixture('amd64-manifest', protocol.IMAGE.split('@')[1])
        descriptors = [row for row in index['manifests'] if row['platform'] == {'architecture': 'amd64', 'os': 'linux'}]
        self.assertEqual(len(descriptors), 1)
        self.assertEqual(descriptors[0]['digest'], protocol.IMAGE.split('@')[1])
        self.assertEqual(descriptors[0]['size'], length)
        config, length = self.fixture('amd64-config', protocol.IMAGE_ID)
        self.assertEqual(manifest['config']['digest'], protocol.IMAGE_ID)
        self.assertEqual(manifest['config']['size'], length)
        self.assertEqual((config['architecture'], config['os']), ('amd64', 'linux'))
        self.assertEqual((protocol.VERSION, protocol.COMMIT),
                         ('3.12.2', '5f02f3f03076343061f167e81b8e82ec5518064b'))
        # ERPC explicitly selects native same-process authenticated validation;
        # the separately recommended split -validator image is not this pin.
        self.assertEqual(config['config']['Entrypoint'], [
            '/usr/local/bin/nitro', '--validation.wasm.allowed-wasm-module-roots',
            '/home/user/nitro-legacy/machines,/home/user/target/machines'])
        for phase in configuration.MODES:
            value = configuration.public('0x' + '1' * 40, phase)
            self.assertEqual(','.join(value['validation']['wasm']['allowed-wasm-module-roots']),
                             config['config']['Entrypoint'][2])
            self.assertEqual(value['node']['block-validator']['validation-server']['url'], 'self-auth')
            self.assertTrue(value['validation']['api-auth'])
            self.assertFalse(value['validation']['api-public'])


if __name__ == '__main__': unittest.main()
