#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real temporary durable files with inert host ownership and shutdown callbacks."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import storage
import state


class StateFailures(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(tmp.name).resolve()
        patch.object(storage, 'ROOT_UID', os.getuid()).start()
        patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        self.path = self.root / 'state'; storage.directory(self.path, create=True)
        self.store = state.State(self.path)
        self.contract = {'owner': 'a' * 26, 'family': 'arbitrum', 'network': 'mainnet',
                         'platform': 'amd64', 'role': 'assertion-validator', 'wallet': '0x' + '1' * 40,
                         'creation': 'b' * 32, 'host_binding': 'c' * 64,
                         'data_uuid': '00000000-0000-0000-0000-000000000001'}
        self.shutdowns = []
        self.stop = lambda: self.shutdowns.append('owned shutdown')
        self.intent = 'd' * 32; self.target = {'native': 'reviewed immutable image', 'phase': 'observing'}

    def test_interrupted_original_owner_recovers_without_changing_identity(self):
        real = self.store.put
        def fail(name, value):
            real(name, value)
            if name == 'owner.json': raise OSError('inert publication interruption')
        with patch.object(self.store, 'put', fail), self.assertRaises(OSError): self.store.reserve(self.contract)
        original = (self.path / 'owner.json').read_bytes()
        self.store.reserve(self.contract)
        self.assertEqual((self.path / 'owner.json').read_bytes(), original)
        self.assertTrue(self.store.fence()['stopped'])
        with self.assertRaises(ValueError): self.store.reserve(dict(self.contract, wallet='0x' + '2' * 40))

    def test_unknown_or_legacy_state_is_not_migrated_by_reservation(self):
        (self.path / 'unknown').write_text('retain')
        with self.assertRaises(ValueError): self.store.reserve(self.contract)
        self.assertFalse((self.path / 'owner.json').exists()); (self.path / 'unknown').unlink()
        storage.write(self.path / 'owner.json', storage.encode({'phase': 'v2:installed'}))
        with self.assertRaises(ValueError): self.store.reserve(self.contract)
        self.assertEqual(storage.decode((self.path / 'owner.json').read_bytes()), {'phase': 'v2:installed'})

    def test_failed_pending_publication_invalidates_the_old_intent_before_shutdown(self):
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        real = self.store.put
        def fail(name, value):
            if name == 'pending.json': raise OSError('inert disk failure')
            real(name, value)
        with patch.object(self.store, 'put', fail), self.assertRaises(OSError):
            self.store.prepare(self.contract, 'e' * 32, self.target, self.stop)
        self.assertEqual(len(self.shutdowns), 2)
        with self.assertRaises(ValueError): self.store.activate(self.contract, self.intent, lambda _: None)
        self.assertFalse((self.path / 'active.json').exists())
        self.store.prepare(self.contract, 'f' * 32, self.target, self.stop)
        self.store.activate(self.contract, 'f' * 32, lambda _: None)
        self.assertEqual(self.store.guard(self.contract), self.target)

    def test_lost_apply_reply_can_only_resume_its_exact_still_active_generation(self):
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        self.store.activate(self.contract, self.intent, lambda _: None)
        self.assertEqual(self.store.completed(self.contract, self.intent), self.target)
        with self.assertRaises(ValueError): self.store.completed(self.contract, 'e'*32)
        self.store.stop(self.contract, self.stop)
        with self.assertRaises(ValueError): self.store.completed(self.contract, self.intent)
        self.store.start(self.contract, lambda _: None)
        with self.assertRaises(ValueError): self.store.completed(self.contract, self.intent)

    def test_stop_revokes_running_and_delayed_deployment_authority(self):
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        self.store.activate(self.contract, self.intent, lambda _: None)
        self.store.stop(self.contract, self.stop)
        with self.assertRaises(ValueError): self.store.guard(self.contract)
        with self.assertRaises(ValueError): self.store.activate(self.contract, self.intent, lambda _: None)
        self.assertEqual(self.store.get('active.json')['target'], self.target)

    def test_manual_start_cannot_revive_a_pending_or_cancelled_activation(self):
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        self.store.activate(self.contract, self.intent, lambda _: None)
        self.store.prepare(self.contract, 'e' * 32, dict(self.target, phase='active'), self.stop)
        with self.assertRaises(ValueError): self.store.start(self.contract, lambda _: None)
        self.store.stop(self.contract, self.stop)
        self.assertEqual(self.store.start(self.contract, lambda _: None), self.target)
        with self.assertRaises(ValueError): self.store.activate(self.contract, 'e' * 32, lambda _: None)
        self.assertEqual(self.store.guard(self.contract)['phase'], 'observing')
        self.store.stop(self.contract, self.stop, retired=True)
        with self.assertRaises(ValueError): self.store.start(self.contract, lambda _: None)

    def test_stopping_a_retired_original_does_not_restore_start_authority(self):
        self.store.reserve(self.contract);self.store.prepare(self.contract,self.intent,self.target,self.stop)
        self.store.activate(self.contract,self.intent,lambda _:None)
        self.store.stop(self.contract,self.stop,retired=True)
        self.store.stop(self.contract,self.stop)
        self.assertTrue(self.store.fence()['retired'])
        with self.assertRaises(ValueError):self.store.start(self.contract,lambda _:None)
        self.store.prepare(self.contract,'e'*32,self.target,self.stop)
        self.store.activate(self.contract,'e'*32,lambda _:None)
        self.assertFalse(self.store.fence()['retired'])

    def test_first_fence_write_failure_still_attempts_only_owned_shutdown_and_never_succeeds(self):
        self.store.reserve(self.contract)
        with patch.object(self.store, 'put', side_effect=OSError('inert persistent storage failure')):
            with self.assertRaises(OSError): self.store.stop(self.contract, self.stop)
            self.assertEqual(len(self.shutdowns), 1)
            with self.assertRaisesRegex(ValueError, 'both failed'):
                self.store.stop(self.contract, lambda: (_ for _ in ()).throw(OSError('inert stop failure')))
        with self.assertRaises(ValueError): self.store.stop(dict(self.contract, owner='z' * 26), self.stop)
        self.assertEqual(len(self.shutdowns), 1)

    def test_same_boot_guard_rejects_old_activation_after_first_durable_write_failure(self):
        self.store.cancellation = self.root/'runtime/cancelled-state.json'
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        original = self.store.get('pending.json')
        with patch.object(self.store, 'put', side_effect=OSError('inert first durable fence failure')):
            with self.assertRaises(OSError): self.store.stop(self.contract, self.stop)
        self.assertEqual(self.store.get('pending.json'), original)
        with self.assertRaisesRegex(ValueError, 'cancelled'): self.store.pending(self.contract, self.intent)
        with self.assertRaisesRegex(ValueError, 'cancelled'): self.store.activate(self.contract, self.intent, lambda _: None)
        self.store.prepare(self.contract, 'f'*32, self.target, self.stop)
        self.store.activate(self.contract, 'f'*32, lambda _: None)
        self.assertEqual(self.store.guard(self.contract), self.target)

    def test_qualification_failure_does_not_publish_runtime_authority(self):
        self.store.reserve(self.contract); self.store.prepare(self.contract, self.intent, self.target, self.stop)
        with self.assertRaises(ValueError):
            self.store.activate(self.contract, self.intent, lambda _: (_ for _ in ()).throw(ValueError('inert funding failure')))
        self.assertTrue(self.store.fence()['stopped']); self.assertFalse((self.path / 'active.json').exists())
        with self.assertRaises(ValueError): self.store.guard(self.contract)

    def test_linked_writable_or_nonregular_state_never_gets_overwritten(self):
        self.store.reserve(self.contract)
        path = self.path / 'fence.json'; old = path.read_bytes(); path.chmod(0o666)
        with self.assertRaises(ValueError): self.store.stop(self.contract, self.stop)
        self.assertEqual(path.read_bytes(), old); path.unlink()
        external = self.root / 'external'; external.write_bytes(old); path.symlink_to(external)
        with self.assertRaises(OSError): self.store.stop(self.contract, self.stop)
        self.assertEqual(external.read_bytes(), old)


if __name__ == '__main__': unittest.main()
