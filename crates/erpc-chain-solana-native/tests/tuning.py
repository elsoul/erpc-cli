#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real durable files; inert kernel/sysctl/NTP boundary, no host configuration."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_tuning as tuning
import native_state as lifecycle
import native_files as files
from mounts import owner


class Tuning(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temporary.name); directory = self.root / 'state'; directory.mkdir()
        patch.object(tuning, 'CONFIG', self.root / 'policy.conf').start()
        patch.object(tuning, 'root_directory', lambda *_args, **_kw: None).start()
        patch.object(tuning, 'read', lambda path, size: files.read(path, size, os.getuid())).start()
        patch.object(tuning, 'sync_file', lambda path: files.sync_file(path, os.getuid())).start()
        patch.object(lifecycle, 'read', lambda path, size: files.read(path, size, os.getuid())).start()
        self.contract = owner(); self.state = lifecycle.State(directory); self.state.reserve(self.contract)
        self.values = dict.fromkeys(tuning.MINIMUM, 1024); self.calls = []; self.clock = 'yes'

    def command(self, args):
        self.calls.append(args)
        if args[:2] == ['/usr/sbin/sysctl', '-n']: return str(self.values[args[2]]) + '\n'
        if args[:2] == ['/usr/sbin/sysctl', '-p']:
            for line in tuning.CONFIG.read_text().splitlines():
                if line.startswith('#'): continue
                name, value = line.split(' = '); self.values[name] = int(value)
            return ''
        self.assertEqual(args, ['/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value'])
        return self.clock + '\n'

    def test_initial_floors_preserve_higher_original_values_and_verify_live_clock(self):
        self.values['fs.nr_open'] = 2048000
        tuning.configure(self.state, self.contract, self.command)
        self.assertEqual(self.values['fs.nr_open'], 2048000)
        self.assertEqual(tuning.verify(self.state, self.contract, self.command), self.values)
        tuning.configure(self.state, self.contract, self.command)
        self.clock = 'no'
        with self.assertRaisesRegex(ValueError, 'clock'): tuning.verify(self.state, self.contract, self.command)
        self.clock = 'yes'; self.values['net.core.rmem_max'] = 212992
        with self.assertRaisesRegex(ValueError, 'floor'): tuning.verify(self.state, self.contract, self.command)

    def test_unowned_file_changed_managed_content_or_foreign_owner_never_applies(self):
        tuning.CONFIG.write_text('unowned policy')
        with self.assertRaises(ValueError): tuning.configure(self.state, self.contract, self.command)
        self.assertEqual(self.calls, []); tuning.CONFIG.unlink()
        tuning.configure(self.state, self.contract, self.command); self.calls.clear()
        tuning.CONFIG.write_text('changed policy')
        with self.assertRaises(ValueError): tuning.configure(self.state, self.contract, self.command)
        with self.assertRaises(ValueError): tuning.configure(self.state, dict(self.contract, name='foreign'), self.command)
        self.assertEqual(self.calls, [])

    def test_visible_receipt_must_be_resynced_before_retry_applies(self):
        real = self.state.put
        def interrupted(name, value):
            real(name, value)
            if name == 'tuning.json': raise OSError('inert failed directory durability')
        with patch.object(self.state, 'put', interrupted), self.assertRaises(OSError):
            tuning.configure(self.state, self.contract, self.command)
        self.assertFalse(tuning.CONFIG.exists()); self.calls.clear()
        with patch.object(tuning, 'sync_file', side_effect=OSError('persistent fsync failure')), self.assertRaises(OSError):
            tuning.configure(self.state, self.contract, self.command)
        self.assertEqual(self.calls, []); self.assertFalse(tuning.CONFIG.exists())
        tuning.configure(self.state, self.contract, self.command)
        tuning.verify(self.state, self.contract, self.command)

    def test_kernel_write_failure_is_retryable_and_readback_drift_is_not_success(self):
        def fail(args):
            if '-p' in args: raise ValueError('inert kernel apply failure')
            return self.command(args)
        with self.assertRaises(ValueError): tuning.configure(self.state, self.contract, fail)
        self.assertTrue(tuning.CONFIG.exists())
        def ignored(args): return '' if '-p' in args else self.command(args)
        with self.assertRaisesRegex(ValueError, 'accept'): tuning.configure(self.state, self.contract, ignored)
        tuning.configure(self.state, self.contract, self.command)

    def test_linked_or_world_writable_configuration_and_invalid_numeric_observation_refuse(self):
        with self.assertRaises(ValueError): tuning.configure(self.state, self.contract, lambda _: '1\n2\n')
        tuning.configure(self.state, self.contract, self.command)
        original = tuning.CONFIG.read_bytes(); tuning.CONFIG.chmod(0o666)
        with self.assertRaises(ValueError): tuning.verify(self.state, self.contract, self.command)
        tuning.CONFIG.unlink(); other = self.root / 'outside'; other.write_bytes(original); tuning.CONFIG.symlink_to(other)
        with self.assertRaises(OSError): tuning.configure(self.state, self.contract, self.command)


if __name__ == '__main__': unittest.main()
