# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual authority IO with inert process effects and persistent storage failures."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Accounts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.contract=self.fixture.c;self.intent='a'*32
        self.target={'release':'inert-qualified-pair','configuration':'b'*64}
        self.history=self.state.directory/'retained-native-history';self.history.write_bytes(b'original history')
        self.stops=[]

    def authorize(self):return self.state.authorize(self.contract,self.intent,self.target,'deploy')
    def shutdown(self):self.stops.append('owned shutdown')
    def complete(self):
        self.authorize();self.state.begin(self.contract,self.intent,self.shutdown)
        self.state.publish(self.contract,self.intent,{'inert':'original unit/artifact receipt'})
        self.state.consume(self.contract,self.intent)

    def test_qualified_cutover_consumes_once_and_stop_fences_delayed_continuation(self):
        self.authorize();self.state.begin(self.contract,self.intent,self.shutdown)
        with self.assertRaises(ValueError):self.state.guard(self.contract)
        self.state.publish(self.contract,self.intent,{'inert':'receipt'});self.state.consume(self.contract,self.intent)
        self.state.guard(self.contract);self.state.stop(self.contract,self.shutdown)
        with self.assertRaises(ValueError):self.state.guard(self.contract)
        with self.assertRaises((ValueError,FileNotFoundError)):self.state.current(self.contract,self.intent)
        qualified=[];self.state.start(self.contract,lambda value:qualified.append(value))
        self.assertEqual(len(qualified),1);self.state.guard(self.contract)
        self.assertEqual(self.history.read_bytes(),b'original history')

    def test_foreign_scope_cannot_stop_and_unknown_recovery_cannot_discard_original(self):
        self.authorize();self.state.begin(self.contract,self.intent,self.shutdown);self.stops.clear()
        with self.assertRaises(ValueError):self.state.stop(dict(self.contract,owner='foreign'),self.shutdown)
        with self.assertRaises(ValueError):self.state.recover(self.contract,'f'*32,self.shutdown)
        self.assertEqual(self.stops,[]);self.assertTrue(self.state.exists('pending.json'))

    def test_first_and_secondary_persistence_failure_still_attempt_shutdown_and_report_failure(self):
        self.complete();self.stops.clear();original=self.state.put
        for selected in ['halt.json','operation.json']:
            def failure(name,value):
                if name==selected:raise OSError('inert persistent storage failure')
                original(name,value)
            with patch.object(self.state,'put',side_effect=failure):
                with self.assertRaisesRegex(ValueError,'durable cancellation unavailable'):
                    self.state.stop(self.contract,self.shutdown)
            self.assertEqual(len(self.stops),1);self.stops.clear()
            self.assertEqual(self.history.read_bytes(),b'original history')

    def test_storage_and_shutdown_failure_are_both_reported_and_no_data_is_removed(self):
        self.authorize()
        def failure():self.stops.append('attempt');raise OSError('inert native failure')
        with patch.object(self.state,'put',side_effect=OSError('inert storage')):
            with self.assertRaisesRegex(ValueError,'owned shutdown.*durable cancellation unavailable'):
                self.state.stop(self.contract,failure,retire=True)
        self.assertEqual(self.stops,['attempt']);self.assertTrue(self.state.exists('pending.json'))
        self.assertEqual(self.history.read_bytes(),b'original history')

    def test_retired_original_requires_deploy_and_success_unretires_observed_state(self):
        self.complete();self.state.stop(self.contract,self.shutdown,retire=True)
        with self.assertRaises(ValueError):self.state.start(self.contract,lambda _:None)
        self.intent='c'*32
        with self.assertRaises(ValueError):self.state.authorize(self.contract,self.intent,self.target,'update')
        self.complete();self.assertFalse(self.state.halted()['retired']);self.state.guard(self.contract)

    def test_interrupted_cutover_recovery_keeps_receipts_and_cancels_original_intent(self):
        self.authorize();self.state.begin(self.contract,self.intent,self.shutdown)
        self.state.put('original-cipher-receipt.json',{'inert':'original retained ciphertext digest'})
        self.state.stop(self.contract,self.shutdown);self.stops.clear()
        with self.assertRaises(ValueError):self.state.start(self.contract,lambda _:None)
        result=self.state.recover(self.contract,self.intent,self.shutdown)
        self.assertFalse(result['started']);self.assertEqual(len(self.stops),1)
        self.assertTrue(self.state.exists('original-cipher-receipt.json'))
        with self.assertRaises(ValueError):self.authorize()
        self.intent='d'*32;self.authorize()
        count=len(self.stops);self.state.recover(self.contract,'a'*32,self.shutdown)
        self.assertEqual(len(self.stops),count);self.assertEqual(self.state.current(self.contract,self.intent)['intent'],self.intent)

    def test_persistent_directory_fsync_keeps_visible_recovery_from_granting_new_authority(self):
        self.authorize();self.state.begin(self.contract,self.intent,self.shutdown)
        real=os.fsync
        def fault(fd):
            if self.state.exists('recovery.json'):raise OSError('inert persistent recovery storage')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fault):
            for _ in range(2):
                with self.assertRaises(ValueError if self.state.exists('recovery.json') else OSError):
                    self.state.recover(self.contract,self.intent,self.shutdown)
                with self.assertRaises(ValueError):self.state.authorize(self.contract,'d'*32,self.target,'deploy')
        self.state.recover(self.contract,self.intent,self.shutdown)
        self.state.authorize(self.contract,'d'*32,self.target,'deploy')
        self.assertEqual(self.history.read_bytes(),b'original history')

    def test_failed_qualification_and_pending_operation_cannot_be_cleared_by_start(self):
        self.complete();self.state.stop(self.contract,self.shutdown)
        previous=self.state.get('active.json')
        def refusal(_):raise ValueError('inert original artifact/account mismatch')
        with self.assertRaises(ValueError):self.state.start(self.contract,refusal)
        self.assertEqual(self.state.get('active.json'),previous)
        self.intent='e'*32;self.authorize()
        with self.assertRaises(ValueError):self.state.start(self.contract,lambda _:None)


if __name__=='__main__':unittest.main()
