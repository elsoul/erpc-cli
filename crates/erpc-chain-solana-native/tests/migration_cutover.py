# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual copied-data/cipher/provider-ack handoff with interrupted persistence."""
import copy
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_files as files
import native_migration_cutover as cutover
import native_migration_retire as retirement
import native_state
from migration_custody import MigrationCustody
from custody import RAW


class Cutover(unittest.TestCase):
    def setUp(self):
        self.custody=MigrationCustody('runTest');self.custody.setUp();self.addCleanup(self.custody.doCleanups)
        self.fixture=self.custody.fixture;f=self.fixture
        self.custody.worker.capture()
        f.patch(cutover.guard,'verify',lambda operation:{'revision':'e'*64})
        f.patch(cutover,'sync_file',lambda path:files.sync_file(path,os.getuid()))
        self.worker=cutover.Cutover(f.operation)
        self.receipt={'schema':1,'intent':self.worker.scope['intent'],'inventory_id':f.contract['inventory_id'],
            'reserved_version':2,'source_sha256':self.worker.scope['source_sha256'],
            'contract_sha256':hashlib.sha256(files.encoded(f.contract)).hexdigest(),'config_sha256':'b'*64,
            'custody_sha256':hashlib.sha256(RAW).hexdigest()}
    def test_actual_copy_original_cipher_ack_and_data_opening_order(self):
        result=self.worker.prepare(self.receipt);self.assertFalse(result['migration_complete'])
        with self.assertRaises(ValueError):native_state.State(self.fixture.home/'state').owner(self.fixture.contract)
        completed=self.worker.finalize(self.receipt,3)
        self.assertTrue(completed['migration_complete']);self.assertFalse(completed['runtime_started'])
        self.assertEqual(self.worker.state.get('helper-revision.json'),{'revision':'e'*64})
        native_state.State(self.fixture.home/'state').owner(self.fixture.contract)
        cutover.committed(native_state.State(self.fixture.home/'state'),self.fixture.contract)
        self.fixture.retained();self.assertEqual(len(self.custody.encrypted),1)
        with self.assertRaises(ValueError):self.custody.worker.export()
    def test_lost_marker_retry_never_reopens_original_data_or_recaptures_key(self):
        self.worker.prepare(self.receipt);self.worker.finalize(self.receipt,3)
        path=self.worker.state.directory/'migration.json';path.unlink()
        newer=self.worker.state.directory/'later-native-history.json';newer.write_bytes(b'original newer history retained')
        with patch.object(self.worker,'gate',side_effect=AssertionError('must not replay original handoff')):
            result=self.worker.finalize(self.receipt,5)
        self.assertEqual(result['provider_version'],3);self.assertEqual(newer.read_bytes(),b'original newer history retained')
        self.fixture.retained()
    def test_changed_provider_binding_or_cipher_never_completes(self):
        for field,value in [('inventory_id','foreign'),('contract_sha256','e'*64),('custody_sha256','f'*64),('source_sha256','e'*64)]:
            wrong=copy.deepcopy(self.receipt);wrong[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.worker.prepare(wrong)
        for version in (None,True,1,2):
            with self.subTest(version=version),self.assertRaises(ValueError):self.worker.finalize(self.receipt,version)
        self.assertFalse((self.worker.state.directory/cutover.COMPLETE).exists());self.fixture.retained()
    def test_stale_carried_actions_refuse_after_ack_before_any_stage(self):
        self.worker.prepare(self.receipt);self.worker.finalize(self.receipt,3)
        request=dict(self.fixture.operation.binding)
        with patch.object(retirement,'scope',return_value=request),patch.object(retirement,'management',return_value=1002), \
             patch.object(retirement,'Retirement',return_value=self.fixture.operation), \
             patch.object(retirement.host,'STATE',self.worker.state.directory):
            for action in ('migration-reserve','migration-retire','migration-copy','migration-promote-data','migration-custody','migration-confirm-manager'):
                with self.subTest(action=action),self.assertRaisesRegex(ValueError,'stale'):
                    retirement.control(dict(request,action=action),True)
        self.fixture.retained()
    def test_each_reached_ack_sync_failure_preserves_original_and_resumes(self):
        # Exercise every persistence boundary reached by actual preparation and
        # finalization, including failure after the complete marker became visible.
        real=os.fsync
        reached=[]
        with patch.object(os,'fsync',side_effect=lambda fd:(reached.append(fd),real(fd))[1]):
            self.worker.prepare(self.receipt);self.worker.finalize(self.receipt,3)
        self.assertGreater(len(reached),10)
        for index in range(1,len(reached)+1):
            fixture=Cutover('runTest');fixture.setUp()
            try:
                count=[0]
                def fail(fd):
                    count[0]+=1
                    if count[0]==index:raise OSError('inert persistence interruption')
                    return real(fd)
                with patch.object(os,'fsync',side_effect=fail):
                    with self.assertRaises(OSError):
                        fixture.worker.prepare(fixture.receipt);fixture.worker.finalize(fixture.receipt,3)
                fixture.fixture.retained()
                # Existing complete acknowledgment permits only marker repair.
                fixture.worker.finalize(fixture.receipt,3)
                fixture.fixture.retained()
            finally:fixture.doCleanups()


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Cutover))
    raise SystemExit(not result.wasSuccessful())
