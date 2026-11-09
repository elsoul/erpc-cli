#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Executable regular-file flock and atomic revocation; no network or signing."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import authority
import host
import state
import storage


class Authority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.group = os.getgid()
        self.addCleanup(patch.stopall)
        patch.object(storage, 'ROOT_UID', os.getuid()).start()
        patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        patch.object(host, 'RUNTIME', self.root / 'run').start()
        self.expected = {'owner': 'a'*26, 'family': 'arbitrum', 'network': 'mainnet', 'platform': 'amd64',
                         'role': 'assertion-validator', 'wallet': '0x'+'1'*40, 'creation': 'b'*32,
                         'host_binding': 'c'*64, 'data_uuid': '00000000-0000-0000-0000-000000000001'}
        self.state = state.State(self.root/'state'); storage.directory(self.state.root, create=True)
        self.state.reserve(self.expected)
        self.target = {'phase': 'active', 'native': 'inert public target'}
        self.state.prepare(self.expected, 'd'*32, self.target, lambda: None)
        self.state.activate(self.expected, 'd'*32, lambda _: None)
        self.records = {'transport': {'gid': self.group}}
        self.granted = authority.grant(self.state, self.expected, self.records)
        self.acquire = authority.acquire(self.group, self.expected, self.granted['generation'], self.target)

    def test_inflight_request_finishes_but_late_request_refuses_before_drain(self):
        with self.acquire():
            with self.assertRaisesRegex(ValueError, 'did not release'): authority.revoke(self.group, timeout=0)
            with self.assertRaisesRegex(ValueError, 'revoked'):
                with self.acquire(): self.fail('late financial operation admitted')
        self.assertTrue(authority.revoke(self.group, timeout=0))
        with self.assertRaises(ValueError):
            with self.acquire(): self.fail('cancelled financial operation admitted')

    def test_new_generation_does_not_reauthorize_old_transport_instance(self):
        authority.revoke(self.group, timeout=0)
        self.state.stop(self.expected, lambda: None)
        self.state.start(self.expected, lambda _: None)
        fresh = authority.grant(self.state, self.expected, self.records)
        with self.assertRaises(ValueError):
            with self.acquire(): self.fail('superseded transport instance admitted')
        with authority.acquire(self.group, self.expected, fresh['generation'], self.target)(): pass

    def test_failed_durable_stop_can_still_cancel_same_boot_requests(self):
        with patch.object(self.state, 'put', side_effect=OSError('inert durable-storage failure')):
            with self.assertRaises(OSError):
                self.state.stop(self.expected, lambda: authority.revoke(self.group, timeout=0))
        with self.assertRaises(ValueError):
            with self.acquire(): self.fail('operation admitted after failed stop persistence')
        # We make no next-boot guarantee when durable storage could not be written.
        self.assertEqual(self.state.guard(self.expected), self.target)
        with self.assertRaisesRegex(ValueError, 'this boot cancelled'):
            authority.grant(self.state, self.expected, self.records)

    def test_linked_or_writeable_lock_is_not_adopted_or_repaired(self):
        lock = authority.paths()[0]; original = lock.stat().st_ino
        lock.chmod(0o660)
        with self.assertRaises(ValueError): authority.initialize(self.group)
        self.assertEqual(lock.stat().st_mode & 0o777, 0o660)
        lock.chmod(0o440); os.link(lock, self.root/'aliased-lock')
        with self.assertRaises(ValueError): authority.initialize(self.group)
        self.assertEqual(lock.stat().st_ino, original)


if __name__ == '__main__': unittest.main()
