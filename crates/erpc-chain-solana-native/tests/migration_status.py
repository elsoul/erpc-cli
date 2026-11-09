# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only original progress before helpers and after final-ack interruption."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_status as status
from mounts import owner


class Progress(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.store=self.root/'migration';self.state=self.root/'native/state'
        self.binding={'intent':'a'*32,'contract':owner(),'legacy':{'source_sha256':'b'*64},'ssh_port':2222}
        self.scope={'intent':'a'*32,'source_sha256':'b'*64};self.owner=self.binding['contract']
        uid=os.getuid();real=Path.lstat
        def metadata(path):
            observed=real(path)
            if path==self.root or self.root in path.parents:return observed
            values={key:getattr(observed,key) for key in dir(observed) if key.startswith('st_')}
            values['st_uid']=uid;values['st_mode']&=~0o022
            return SimpleNamespace(**values)
        for item in (patch.object(status,'ROOT_UID',uid),patch.object(Path,'lstat',metadata)):
            item.start();self.addCleanup(item.stop)
    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(status.encoded(value));path.chmod(0o600)
    def observe(self):
        with patch.object(os,'fsync',side_effect=AssertionError('status must not write')):
            return status.progress(self.binding,1002,self.store,self.state)
    def reserve(self):
        self.write(self.store/'original.json',{'schema':1,'binding':self.binding,'observation':{},'manager_uid':1002})
    def complete(self):
        self.reserve();kinds=('accounts','ledger','snapshots')
        self.write(self.store/'transfer/complete.json',{'binding':hashlib.sha256(status.encoded(self.binding)).hexdigest(),
            'volumes':dict.fromkeys(kinds,{}),'results':dict.fromkeys(kinds,{})})
        self.write(self.state/'data.json',{'contract':self.owner,'uid':1003,'gid':1004})
        self.write(self.state/'owner.json',{'contract':self.owner,'migration':self.scope,'initial_halt':'c'*32,'initialized':True})
        receipt={'schema':1,'intent':'a'*32,'inventory_id':self.owner['inventory_id'],'reserved_version':2,
            'source_sha256':'b'*64,'contract_sha256':hashlib.sha256(status.encoded(self.owner)).hexdigest(),
            'config_sha256':'d'*64,'custody_sha256':'e'*64}
        self.write(self.state/'migration-complete.json',{'contract':self.owner,'scope':self.scope,'receipt':receipt,'provider_version':3})
    def test_unreserved_and_partial_helper_publication_are_readonly(self):
        result=self.observe();self.assertEqual(result['recorded_phase'],'unreserved');self.assertFalse(self.store.exists())
        self.reserve();result=self.observe();self.assertEqual(result['recorded_phase'],'reserved');self.assertIsNone(result['helper_revision'])
        self.write(self.store/'helper-revision.json',{'binding_sha256':hashlib.sha256(status.encoded(self.binding)).hexdigest(),'revision':'f'*64})
        self.assertEqual(self.observe()['helper_revision'],'f'*64)
    def test_complete_ack_missing_marker_reports_finalizing_without_claiming_health(self):
        self.complete();result=self.observe();self.assertEqual(result['recorded_phase'],'finalizing')
        self.assertFalse(result['migration_complete']);self.assertIsNone(result['ready']);self.assertFalse(result['runtime_inspected'])
        self.write(self.state/'migration.json',{'contract':self.owner,'scope':self.scope,'phase':'complete'})
        result=self.observe();self.assertTrue(result['migration_complete']);self.assertIsNone(result['ready'])
        (self.state/'migration-complete.json').unlink()
        with self.assertRaises(ValueError):self.observe()
    def test_missing_owner_and_symlink_or_writable_namespace_never_look_unreserved(self):
        self.store.mkdir();self.store.chmod(0o777)
        with self.assertRaises(ValueError):self.observe()
        self.store.chmod(0o700);self.store.rmdir();self.store.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.observe()
        self.store.unlink();self.state.mkdir(parents=True);(self.state/'owner.json').symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.observe()
    def test_foreign_binding_and_unsafe_record_refuse_without_content_diagnostics(self):
        self.reserve();original=copy.deepcopy(self.binding);self.binding['intent']='f'*32
        with self.assertRaises(ValueError):self.observe()
        self.binding=original;(self.store/'original.json').chmod(0o666)
        with self.assertRaises(ValueError):self.observe()


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Progress))
    raise SystemExit(not result.wasSuccessful())
