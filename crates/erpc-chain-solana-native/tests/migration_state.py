# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Pending-copy state cannot become an empty native deployment, even via old init."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_files as files
import native_state as state

# Verbatim State prefix through halt() at original reviewed migration base
# fc0de2dc58aa1875a5342a29d29ce731a95fa9a5; no reviewer reproduction used.
FIXTURE=Path(__file__).parent/'fixtures/native_state_before_migration.py'
spec=importlib.util.spec_from_file_location('old_state',FIXTURE);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)


class PendingMigration(unittest.TestCase):
    def test_old_helper_fixture_is_the_unchanged_reviewed_prefix(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
                         '0f350f2050bf93b882cb2d2f2fe5a2e19f50dc477f2919e374108905c9a3a67b')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.contract={'network':'testnet','owner':'inert'}
        self.scope={'intent':'a'*32,'source_sha256':'b'*64}
        for module in (state,old):
            item=patch.object(module,'read',lambda p,bound:files.read(p,bound,os.getuid()));item.start();self.addCleanup(item.stop)
        item=patch.object(state,'sync_file',lambda p:files.sync_file(p,os.getuid()));item.start();self.addCleanup(item.stop)
        self.scoped=state.State(self.root,self.scope);self.ordinary=state.State(self.root)
        self.marker={'contract':self.contract,'scope':self.scope,'phase':'preparing'}
        self.scoped.put('migration.json',self.marker)
    def test_pending_marker_and_owner_refuse_both_current_unscoped_and_actual_old_init(self):
        for phase in ('before-owner','owner-initialized'):
            if phase=='owner-initialized':self.scoped.reserve(self.contract)
            before={path.name:path.read_bytes() for path in self.root.iterdir()}
            for candidate in (self.ordinary,old.State(self.root)):
                with self.subTest(phase=phase,kind=type(candidate)):
                    with self.assertRaises(ValueError):candidate.reserve(self.contract)
                    self.assertEqual({path.name:path.read_bytes() for path in self.root.iterdir()},before)
            if phase=='owner-initialized':
                with self.assertRaises(ValueError):self.ordinary.owner(self.contract)
                with self.assertRaises(ValueError):self.ordinary.authorize(self.contract,'c'*32,{'mode':'sync'},'deploy')
                self.assertEqual(self.scoped.owner(self.contract)['migration'],self.scope)
    def test_wrong_scope_contract_or_missing_marker_is_not_reinterpreted(self):
        self.scoped.reserve(self.contract)
        for candidate in (state.State(self.root,dict(self.scope,intent='d'*32)),state.State(self.root,dict(self.scope,source_sha256='e'*64))):
            with self.assertRaises(ValueError):candidate.reserve(self.contract)
        (self.root/'migration.json').unlink()
        with self.assertRaises(FileNotFoundError):self.scoped.owner(self.contract)
        with self.assertRaises(FileNotFoundError):self.ordinary.owner(self.contract)
    def test_complete_promotion_opens_normal_current_lifecycle_without_rewriting_old_scope(self):
        self.scoped.reserve(self.contract);original=self.scoped.get('owner.json')
        self.scoped.put('migration.json',dict(self.marker,phase='complete'))
        self.ordinary.reserve(self.contract)
        self.assertEqual(self.ordinary.owner(self.contract),original)
        self.ordinary.authorize(self.contract,'c'*32,{'mode':'sync'},'deploy')
        self.assertEqual(self.ordinary.current(self.contract,'c'*32)['target'],{'mode':'sync'})
        with self.assertRaises(ValueError):old.State(self.root).reserve(self.contract)
    def test_completed_host_stop_does_not_need_successful_resync_of_unmodified_marker(self):
        self.scoped.reserve(self.contract);self.scoped.put('migration.json',dict(self.marker,phase='complete'))
        calls=[]
        with patch.object(state,'sync_file',side_effect=OSError('inert read-only sync failure')):
            self.ordinary.stop(self.contract,lambda:calls.append('owned stop'))
        self.assertEqual(calls,['owned stop'])
    def test_initial_owner_publication_faults_resume_only_with_explicit_original_scope(self):
        real=os.fsync;points=[]
        def record(fd):points.append(True);return real(fd)
        with patch.object(os,'fsync',record):self.scoped.reserve(self.contract)
        for index in range(len(points)):
            fixture=PendingMigration('runTest');fixture.setUp()
            try:
                seen=[]
                def fail(fd):
                    position=len(seen);seen.append(True)
                    if position==index:raise OSError('inert native migration owner interruption')
                    return real(fd)
                with patch.object(os,'fsync',fail),self.assertRaises(OSError):fixture.scoped.reserve(fixture.contract)
                with self.assertRaises(ValueError):fixture.ordinary.reserve(fixture.contract)
                fixture.scoped.reserve(fixture.contract)
                self.assertEqual(fixture.scoped.owner(fixture.contract)['migration'],fixture.scope)
            finally:fixture.doCleanups()
        print(str(len(points))+' native migration owner barriers retried')

if __name__=='__main__':unittest.main()
