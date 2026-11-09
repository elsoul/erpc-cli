#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Old frontend and cross-operation inputs cannot change native authority."""
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import protocol


class Protocol(unittest.TestCase):
    def setUp(self):
        self.target = {'phase': 'observing', 'version': protocol.VERSION, 'commit': protocol.COMMIT,
                       'image': protocol.IMAGE, 'image_id': protocol.IMAGE_ID,
                       'helpers_sha256': 'a'*64, 'config_id': 'b'*64}

    def test_old_catalog_and_content_mismatch_refuse_before_transition(self):
        for field, value in [('version', '4.0.0'), ('commit', 'c'*40), ('image_id', 'sha256:'+'c'*64)]:
            previous = dict(self.target, **{field: value})
            with self.assertRaises(ValueError): protocol.transition(previous, self.target)
        with self.assertRaises(ValueError): protocol.target(self.target, 'b'*64)
        self.assertEqual(protocol.target(self.target, 'a'*64), self.target)

    def test_original_active_history_cannot_be_reset_to_observer(self):
        active = dict(self.target, phase='active')
        self.assertEqual(protocol.transition(self.target, active), active)
        with self.assertRaisesRegex(ValueError, 'history'): protocol.transition(active, self.target, activated=True)
        self.assertEqual(protocol.transition(active, active, activated=True), active)

    def test_preflight_cannot_smuggle_private_or_mutation_parameters(self):
        self.assertEqual(protocol.request({'action': 'preflight'}), {'action': 'preflight'})
        for fields in ({'secret': 'inert'}, {'target': self.target}, {'role': 'rpc'}):
            with self.assertRaises(ValueError): protocol.request(dict(action='preflight', **fields))


if __name__ == '__main__': unittest.main()
