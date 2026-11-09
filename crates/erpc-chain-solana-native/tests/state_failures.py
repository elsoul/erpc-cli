#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real private metadata, injected failures, and inert shutdown callbacks."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_files as files
import native_state as lifecycle


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.reader = patch.object(lifecycle, 'read', lambda p, bound: files.read(p, bound, os.geteuid()))
        self.reader.start()
        self.state = lifecycle.State(self.root)
        self.contract = {'owner': 'a' * 32, 'network': 'testnet'}
        self.old, self.new = 'b' * 32, 'c' * 32
        self.target = {'version': '4.4.0-beta.1', 'mode': 'sync'}
        self.state.reserve(self.contract)

    def tearDown(self):
        self.reader.stop()
        self.temporary.cleanup()

    def deploy(self):
        self.state.authorize(self.contract, self.old, self.target, 'deploy')
        self.state.begin(self.contract, self.old, lambda: None)
        self.state.publish(self.contract, self.old, {'qualified': True})
        self.state.consume(self.contract, self.old)

    def fail(self, *_):
        raise OSError('inert publication failure')

    def test_long_build_does_not_revoke_last_approved_runtime_but_cutover_does(self):
        self.deploy()
        active = self.state.guard(self.contract)
        self.state.authorize(self.contract, self.new, self.target, 'update')
        self.assertEqual(self.state.guard(self.contract), active)
        self.state.begin(self.contract, self.new, lambda: None)
        with self.assertRaises(ValueError): self.state.guard(self.contract)
        self.state.publish(self.contract, self.new, {'qualified': True})
        self.assertEqual(self.state.guard(self.contract)['intent'], self.new)

    def test_stop_during_build_revokes_every_old_continuation_before_secondary_write_failure(self):
        self.deploy()
        self.state.authorize(self.contract, self.new, self.target, 'update')
        original = self.state.put
        def fail_fence(name, value):
            if name == 'intent-fence.json': self.fail()
            original(name, value)
        calls = []
        with patch.object(self.state, 'put', fail_fence):
            with self.assertRaises(OSError): self.state.stop(self.contract, lambda: calls.append('stopped'))
        self.assertEqual(calls, ['stopped'])
        for run in [lambda: self.state.current(self.contract, self.new),
                    lambda: self.state.begin(self.contract, self.new, lambda: self.fail('stale shutdown')),
                    lambda: self.state.guard(self.contract)]:
            with self.assertRaises(ValueError): run()

    def test_first_halt_write_failure_still_attempts_shutdown_without_claiming_durability(self):
        self.deploy()
        original = self.state.put
        def fail_halt(name, value):
            if name == 'halt.json': self.fail()
            original(name, value)
        calls = []
        with patch.object(self.state, 'put', fail_halt):
            with self.assertRaises(OSError): self.state.stop(self.contract, lambda: calls.append('shutdown attempted'))
        self.assertEqual(calls, ['shutdown attempted'])
        # No durable cancellation was possible. Do not turn best-effort stopping
        # into a false claim that the old disk generation has been revoked.
        self.state.guard(self.contract)
        def failed_shutdown():
            calls.append('failed shutdown attempted')
            raise OSError('inert private callback detail')
        with patch.object(self.state, 'put', fail_halt):
            with self.assertRaisesRegex(ValueError, 'cancellation could not be persisted and owned shutdown also failed') as error:
                self.state.stop(self.contract, failed_shutdown)
        self.assertNotIn('private callback', str(error.exception))
        self.assertEqual(calls[-1], 'failed shutdown attempted')
        before = list(calls)
        with self.assertRaises(ValueError):
            self.state.stop(dict(self.contract, network='mainnet'), failed_shutdown)
        self.assertEqual(calls, before)

    def test_failed_new_intent_publication_cannot_finish_an_old_cutover(self):
        self.state.authorize(self.contract, self.old, self.target, 'deploy')
        self.state.begin(self.contract, self.old, lambda: None)
        original = self.state.put
        def fail_pending(name, value):
            if name == 'pending.json': self.fail()
            original(name, value)
        with patch.object(self.state, 'put', fail_pending):
            with self.assertRaises(OSError): self.state.authorize(self.contract, self.new, self.target, 'deploy')
        with self.assertRaises(ValueError): self.state.publish(self.contract, self.old, {})
        self.assertTrue((self.root / 'cutover.json').exists())

    def test_cutover_stop_or_activation_publication_failure_preserves_runtime_fence(self):
        self.deploy()
        self.state.authorize(self.contract, self.new, self.target, 'update')
        with self.assertRaises(OSError): self.state.begin(self.contract, self.new, self.fail)
        with self.assertRaises(ValueError): self.state.guard(self.contract)

        original = self.state.put
        def fail_active(name, value):
            if name == 'active.json': self.fail()
            original(name, value)
        with patch.object(self.state, 'put', fail_active):
            with self.assertRaises(OSError): self.state.publish(self.contract, self.new, {})
        with self.assertRaises(ValueError): self.state.guard(self.contract)

    def test_unretirement_persistence_failure_keeps_the_explicit_deploy_fenced_until_retry(self):
        self.deploy();self.state.stop(self.contract,lambda:None,retired=True)
        self.state.authorize(self.contract,self.new,self.target,'deploy')
        self.state.begin(self.contract,self.new,lambda:None)
        original=self.state.put
        def failed(name,value):
            if name=='halt.json':raise OSError('inert unretirement persistence failure')
            original(name,value)
        with patch.object(self.state,'put',side_effect=failed),self.assertRaises(OSError):
            self.state.publish(self.contract,self.new,{'qualified':True})
        self.assertTrue(self.state.halt()['retired'])
        with self.assertRaises(ValueError):self.state.guard(self.contract)
        self.state.publish(self.contract,self.new,{'qualified':True})
        self.assertFalse(self.state.halt()['retired'])
        self.assertEqual(self.state.guard(self.contract)['intent'],self.new)

    def test_manual_start_never_erases_a_failed_new_authorization_or_retirement(self):
        self.deploy()
        self.state.stop(self.contract, lambda: None)
        original = self.state.put
        def fail_pending(name, value):
            if name == 'pending.json': self.fail()
            original(name, value)
        with patch.object(self.state, 'put', fail_pending):
            with self.assertRaises(OSError): self.state.authorize(self.contract, self.new, self.target, 'update')
        with self.assertRaises(ValueError): self.state.manual_start(self.contract, lambda _: None)
        self.state.stop(self.contract, lambda: None)
        self.state.manual_start(self.contract, lambda _: None)
        self.state.guard(self.contract)
        self.state.stop(self.contract, lambda: None, retired=True)
        with self.assertRaises(ValueError): self.state.manual_start(self.contract, lambda _: None)
        with self.assertRaises(ValueError): self.state.authorize(self.contract, self.new, self.target, 'update')
        self.state.authorize(self.contract, self.new, self.target, 'deploy')

    def test_original_ownership_and_missing_halt_can_never_be_implicitly_recreated(self):
        self.deploy()
        foreign = dict(self.contract, network='mainnet')
        with self.assertRaises(ValueError): self.state.stop(foreign, lambda: self.fail('foreign shutdown'))
        (self.root / 'halt.json').unlink()
        with self.assertRaises(FileNotFoundError): self.state.reserve(self.contract)
        with self.assertRaises(FileNotFoundError): self.state.guard(self.contract)

    def test_interrupted_initial_reservation_resumes_only_its_original_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = lifecycle.State(Path(temporary)); original = state.put
            def fail_fence(name, value):
                if name == 'intent-fence.json': self.fail()
                original(name, value)
            with patch.object(state, 'put', fail_fence):
                with self.assertRaises(OSError): state.reserve(self.contract)
            generation = state.get('owner.json')['initial_halt']
            state.reserve(self.contract)
            self.assertEqual(state.halt()['generation'], generation)
            self.assertTrue(state.get('owner.json')['initialized'])


if __name__ == '__main__':
    unittest.main()
