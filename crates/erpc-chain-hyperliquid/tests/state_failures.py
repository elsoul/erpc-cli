#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import erpc_hl_common as common
import erpc_hl_state as state


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.patch = patch.object(state, 'read', lambda p: common.read(p, owner=os.getuid()))
        self.patch.start()
        self.state = state.State(self.directory)
        self.contract = {'network': 'testnet', 'owner': 'inert-fixture'}
        self.target = {'id': 'visor-inert', 'signed_at': 100, 'sha256': 'inert'}
        self.first, self.second = 'a' * 32, 'b' * 32
        self.state.put('owner.json', {'contract': self.contract})
        self.state.authorize(self.contract, self.first, self.target)
        self.state.begin(self.contract, self.first, self.target, lambda: None)
        self.state.finish(self.contract, self.first, {'files': {}})

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def fails(self):
        raise OSError('inert failure')

    def test_failed_new_intent_publication_revokes_previous_activation(self):
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.guard(self.contract, self.first)

    def test_failed_supersession_cannot_finish_an_old_install_and_clear_its_fence(self):
        self.state.authorize(self.contract, self.first, self.target)
        self.state.begin(self.contract, self.first, self.target, lambda: None)
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        before = sorted((p.name, p.read_bytes()) for p in self.directory.iterdir())
        for attempt in (
                lambda: self.state.current(self.contract, self.first),
                lambda: self.state.begin(self.contract, self.first, self.target, lambda: self.fail('stale shutdown')),
                lambda: self.state.finish(self.contract, self.first, {}),
                lambda: self.state.guard(self.contract, self.first)):
            with self.assertRaises(ValueError):
                attempt()
            self.assertEqual(before, sorted((p.name, p.read_bytes()) for p in self.directory.iterdir()))
        self.state.authorize(self.contract, self.second, self.target)
        self.state.begin(self.contract, self.second, self.target, lambda: None)
        self.state.finish(self.contract, self.second, {})
        self.state.guard(self.contract, self.second)

    def test_manual_start_cannot_erase_a_failed_authorization_over_an_ordinary_stop(self):
        self.state.cancel(self.contract, False, lambda: None)
        self.state.guard(self.contract, manual=True)
        original = self.state.put
        def fail_operation(name, value):
            if name == 'operation.json':
                self.fails()
            original(name, value)
        with patch.object(self.state, 'put', fail_operation):
            with self.assertRaises(OSError):
                self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.manual_ready(self.contract)
        self.assertTrue((self.directory / 'stopped').exists())
        self.assertEqual(self.state.get('activation-revoked'), {'intent': self.second})
        self.state.cancel(self.contract, False, lambda: None)
        self.state.manual_ready(self.contract)
        self.state.guard(self.contract)

    def test_failed_stop_and_retire_cannot_allow_old_queued_activation(self):
        for retired in (False, True):
            with self.assertRaises(OSError):
                self.state.cancel(self.contract, retired, self.fails)
            with self.assertRaises(ValueError):
                self.state.guard(self.contract, self.first)

    def test_failed_cancel_intent_write_still_leaves_durable_stop(self):
        stopped = []
        with patch.object(self.state, 'put', side_effect=OSError('intent write failure')):
            with self.assertRaisesRegex(common.Refused, 'cancellation was not persisted'):
                self.state.cancel(self.contract, False, lambda: stopped.append(True))
        self.assertEqual(stopped, [True])
        with self.assertRaises(ValueError):
            self.state.guard(self.contract, self.first)

    def test_first_cancel_write_failure_still_attempts_shutdown_without_claiming_durability(self):
        stopped = []
        with patch.object(self.state, 'marker', side_effect=OSError('first marker failed')):
            with self.assertRaisesRegex(common.Refused, 'cancellation was not persisted'):
                self.state.cancel(self.contract, False, lambda: stopped.append(True))
        self.assertEqual(stopped, [True])
        self.assertFalse((self.directory / 'stopped').exists())
        self.assertFalse((self.directory / 'retired').exists())

    def test_both_storage_and_shutdown_failures_are_reported_without_private_details(self):
        stopped = []
        def fail_stop():
            stopped.append(True)
            raise OSError('private shutdown diagnostic')
        with patch.object(self.state, 'marker', side_effect=OSError('private storage diagnostic')):
            with self.assertRaisesRegex(common.Refused, 'persistence and owned shutdown both failed') as result:
                self.state.cancel(self.contract, True, fail_stop)
        self.assertNotIn('private', str(result.exception))
        self.assertEqual(stopped, [True])
        # Independent intent cancellation still succeeds after failed markers.
        self.assertIsNone(self.state.get('operation.json')['intent'])

    def test_stale_begin_and_finish_cannot_mutate_the_replacement(self):
        self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(ValueError):
            self.state.begin(self.contract, self.first, self.target, lambda: self.fail('stale shutdown'))
        self.state.begin(self.contract, self.second, self.target, lambda: None)
        with self.assertRaises(ValueError):
            self.state.finish(self.contract, self.first, {})
        self.state.finish(self.contract, self.second, {})
        self.state.guard(self.contract, self.second)

    def test_incomplete_install_can_be_stopped_and_retried_only_at_same_target(self):
        self.state.authorize(self.contract, self.second, self.target)
        with self.assertRaises(OSError):
            self.state.begin(self.contract, self.second, self.target, self.fails)
        self.state.cancel(self.contract, True, lambda: None)
        third = 'c' * 32
        self.state.authorize(self.contract, third, dict(self.target, id='visor-new', signed_at=200))
        with self.assertRaises(ValueError):
            self.state.begin(self.contract, third, dict(self.target, id='visor-new', signed_at=200), lambda: None)
        self.state.authorize(self.contract, third, self.target)
        self.state.begin(self.contract, third, self.target, lambda: None)
        self.state.finish(self.contract, third, {})
        self.state.guard(self.contract, third)

    def test_authorized_policy_update_can_keep_same_supervisor_but_cannot_substitute_its_bytes(self):
        changed=dict(self.target,config_id='a'*64,helper_sha='b'*64)
        self.state.authorize(self.contract,self.second,changed)
        self.state.begin(self.contract,self.second,changed,lambda:None)
        self.state.finish(self.contract,self.second,{})
        self.assertEqual(self.state.guard(self.contract,self.second)['operation']['target'],changed)
        replaced=dict(changed,sha256='substitution')
        self.state.authorize(self.contract,'c'*32,replaced)
        with self.assertRaisesRegex(ValueError,'substitution'):
            self.state.begin(self.contract,'c'*32,replaced,lambda:self.fail('unqualified shutdown'))

    def test_recovery_preserves_native_data_and_old_receipt_and_requires_fresh_authorization(self):
        data=self.directory/'home/hl/data';data.mkdir(parents=True);(data/'inert-history').write_bytes(b'original')
        self.state.authorize(self.contract,self.second,self.target)
        self.state.begin(self.contract,self.second,self.target,lambda:None)
        stopped=[]
        self.assertTrue(self.state.recover_preparation(self.contract,lambda:stopped.append(True))['recovered'])
        self.assertEqual(stopped,[True]);self.assertEqual((data/'inert-history').read_bytes(),b'original')
        self.assertEqual(self.state.get('abandoned-'+self.second+'.json'),{'intent':self.second,'target':self.target})
        self.assertFalse((self.directory/'installing.json').exists())
        for stale in (lambda:self.state.current(self.contract,self.second),lambda:self.state.finish(self.contract,self.second,{})):
            with self.assertRaises(ValueError):stale()
        self.assertFalse(self.state.recover_preparation(self.contract,lambda:self.fail('already recovered'))['recovered'])
        next_target=dict(self.target,id='visor-next',sha256='next',signed_at=200)
        self.state.authorize(self.contract,'c'*32,next_target)
        self.state.begin(self.contract,'c'*32,next_target,lambda:None)
        self.state.finish(self.contract,'c'*32,{})
        self.state.guard(self.contract,'c'*32)

    def test_failed_recovery_does_not_remove_incomplete_state_or_change_foreign_scope(self):
        self.state.authorize(self.contract,self.second,self.target)
        self.state.begin(self.contract,self.second,self.target,lambda:None)
        with self.assertRaises(OSError):self.state.recover_preparation(self.contract,self.fails)
        self.assertTrue((self.directory/'installing.json').exists())
        with self.assertRaises(ValueError):self.state.recover_preparation(dict(self.contract,network='mainnet'),lambda:self.fail('foreign stop'))
        original=self.state.put
        def fail_archive(name,value):
            if name.startswith('abandoned-'):raise OSError('inert archive fault')
            original(name,value)
        with patch.object(self.state,'put',side_effect=fail_archive):
            with self.assertRaises(OSError):self.state.recover_preparation(self.contract,lambda:None)
        self.assertTrue((self.directory/'installing.json').exists())
        self.state.recover_preparation(self.contract,lambda:None)
        self.assertFalse((self.directory/'installing.json').exists())

    def test_foreign_scope_cannot_cancel_or_destroy_and_manual_start_cannot_unretire(self):
        wrong = dict(self.contract, network='mainnet')
        before = sorted((p.name, p.read_bytes()) for p in self.directory.iterdir())
        with self.assertRaises(ValueError):
            self.state.cancel(wrong, True, lambda: self.fail('foreign shutdown'))
        self.assertEqual(before, sorted((p.name, p.read_bytes()) for p in self.directory.iterdir()))
        self.state.cancel(self.contract, True, lambda: None)
        with self.assertRaises(ValueError):
            self.state.manual_ready(self.contract)


if __name__ == '__main__':
    unittest.main()
