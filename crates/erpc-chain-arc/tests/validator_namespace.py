#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert namespace paths; hostile artifacts are retained without adoption."""
import os
import pathlib
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_namespace as namespace
from av_files import Files, ROOT, NAMESPACE
from arc_files import Refused


class Namespace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = Files(pathlib.Path(self.temp.name), owner=os.getuid())
        self.context.mkdir(ROOT)

    def test_only_empty_private_lock_is_a_legitimate_fresh_control_artifact(self):
        self.context.write_bytes(ROOT + '/lock', b'')
        namespace.check(self.context, fresh=True)
        self.context.write_bytes(ROOT + '/consensus-key.staged', b'inert-ciphertext')
        with self.assertRaisesRegex(Refused, 'unowned'):
            namespace.check(self.context, fresh=True)
        self.assertEqual(self.context.read(ROOT + '/consensus-key.staged'), b'inert-ciphertext')

    def test_known_pending_ingress_files_do_not_block_original_stop_or_recovery(self):
        family = '/etc/erpc/arc-validator'
        for name in ('pending.json', 'pending.nft', 'pending.new', 'startup-revoked', 'startup-revoked.new',
                     'firewall.nft', 'firewall.new', 'confirmed.json', 'confirmed.new', 'previous.nft', 'previous.new'):
            self.context.write_bytes(family + '/' + name, b'inert-original-policy')
        namespace.check(self.context)
        with self.assertRaises(Refused):
            namespace.check(self.context, fresh=True)
        self.context.write_bytes(family + '/foreign-policy', b'inert-foreign')
        with self.assertRaisesRegex(Refused, 'unknown validator ingress'):
            namespace.check(self.context)

    def test_closed_dropins_reject_later_overrides_without_repairing_them(self):
        directory = '/etc/systemd/system/' + namespace.FIREWALL + '.d'
        self.context.mkdir(directory, 0o755)
        for name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new'):
            self.context.write_bytes(directory + '/' + name, b'[Service]\n', 0o644)
        namespace.check(self.context)
        with self.assertRaises(Refused):
            namespace.check(self.context, fresh=True)
        extra = self.context.path(directory + '/99-foreign.conf')
        extra.write_bytes(b'[Service]\nExecStart=\n')
        for mode in (0o644, 0o666):
            extra.chmod(mode)
            with self.assertRaises(Refused):
                namespace.check(self.context)
            self.assertEqual(stat.S_IMODE(extra.stat().st_mode), mode)
            self.assertEqual(extra.read_bytes(), b'[Service]\nExecStart=\n')

    def test_only_closed_original_helper_pointer_is_accepted(self):
        name = NAMESPACE + '/releases/' + 'a' * 64
        self.context.mkdir(name, 0o755)
        self.context.write_bytes(name + '/control.py', b'# inert helper', 0o644)
        pointer = self.context.path(NAMESPACE + '/current')
        pointer.symlink_to('releases/' + 'a' * 64)
        namespace.check(self.context)
        pointer.unlink()
        pointer.symlink_to('/inert-foreign')
        with self.assertRaises(Refused):
            namespace.check(self.context)
        self.assertTrue(pointer.is_symlink())

    def test_absent_original_helper_target_can_be_reached_only_by_a_sealed_carried_recovery(self):
        self.context.mkdir(NAMESPACE, 0o755)
        pointer = self.context.path(NAMESPACE + '/current')
        pointer.symlink_to('releases/' + 'b' * 64)
        namespace.check(self.context)
        self.assertFalse(pointer.exists())
        self.assertTrue(pointer.is_symlink())
        # The ordinary external release loader still refuses missing bytes; this
        # namespace check merely lets a newly sealed controller authenticate owner.
        with self.assertRaises(Refused):
            self.context.protected(NAMESPACE + '/releases/' + 'b' * 64, directory=True)

    def test_original_parent_and_private_receipt_modes_are_not_repaired(self):
        parent = self.context.path('/etc/erpc')
        parent.chmod(0o777)
        with self.assertRaises(Refused):
            namespace.check(self.context)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)
        parent.chmod(0o755)
        self.context.write_bytes(ROOT + '/owner.json', b'{}', 0o644)
        with self.assertRaises(Refused):
            namespace.check(self.context)
        self.assertEqual(stat.S_IMODE(self.context.path(ROOT + '/owner.json').stat().st_mode), 0o644)

    def test_fresh_preparation_does_not_cohost_another_managed_firewall_namespace(self):
        self.context.mkdir('/etc/erpc/eth')
        with self.assertRaisesRegex(Refused, 'another ERPC namespace'):
            namespace.check(self.context, fresh=True)
        self.assertTrue(self.context.path('/etc/erpc/eth').is_dir())
        # Original shutdown remains available if an operator later adds another
        # namespace; this check never removes or adopts that unrelated state.
        namespace.check(self.context)

    def test_shared_native_cache_and_root_settings_are_not_freshly_adopted(self):
        self.context.mkdir('/opt/arc')
        self.context.write_bytes('/opt/arc/foreign.bin', b'inert-native')
        with self.assertRaisesRegex(Refused, 'unowned native'):
            namespace.check(self.context, fresh=True)
        self.assertEqual(self.context.read('/opt/arc/foreign.bin'), b'inert-native')
        self.context.remove('/opt/arc/foreign.bin')
        self.context.mkdir('/etc/sysctl.d')
        self.context.write_bytes('/etc/sysctl.d/90-erpc-arc-validator.conf', b'inert-original-settings')
        with self.assertRaisesRegex(Refused, 'unowned validator host settings'):
            namespace.check(self.context, fresh=True)

    def test_resuming_original_public_directory_restores_its_target_mode_not_global_ancestors(self):
        self.context.mkdir('/opt', 0o700)
        self.context.path('/opt/arc').mkdir(mode=0o700)
        self.context.mkdir('/opt/arc', 0o755)
        self.assertEqual(stat.S_IMODE(self.context.path('/opt').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.context.path('/opt/arc').stat().st_mode), 0o755)
        self.context.mkdir(ROOT, 0o700)
        self.assertEqual(stat.S_IMODE(self.context.path(ROOT).stat().st_mode), 0o700)


if __name__ == '__main__':
    unittest.main()
