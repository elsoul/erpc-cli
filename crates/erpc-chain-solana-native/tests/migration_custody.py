# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual original ciphertext state machine after real inert copy/promotion."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_custody as capture
import native_files as files
import native_state as state
from migration_transfer import MigrationTransfer
from migration_promote import Promotion
from custody import RAW,PUBLIC,EXPECTED
from mounts import owner


class MigrationCustody(unittest.TestCase):
    def setUp(self):
        original_setup=MigrationTransfer.setUp
        def original(fixture):
            original_setup(fixture)
            fixture.scope['legacy']['network']=owner()['network'];fixture.scope['legacy']['commission']=5
            fixture.scope['legacy']['host_identity']={'role':'sync','path':'/home/solv/unstaked-identity.json',
                'uid':fixture.uid,'gid':fixture.gid,'inode':123,'bytes':len(RAW),'mtime_ns':1,'public':EXPECTED,'bls_public':'3'*66}
        with patch.object(MigrationTransfer,'setUp',original):
            self.fixture=Promotion('runTest');self.fixture.setUp()
        f=self.fixture;self.addCleanup(f.doCleanups);self.materials=[];self.encrypted=[]
        f.promotion.prepare_data()
        f.patch(capture.process,'assert_quiescent',lambda uid:capture.require(not f.writer and not f.native_running
            and uid in {f.uid,*[v['uid'] for v in f.plan.values()]},'original or native writer remains'))
        f.patch(capture.keys,'source',lambda request:(None,{k:v for k,v in request['host_identity'].items() if k not in ('public','bls_public')}))
        def material(request):
            key=bytearray(json.loads(RAW));self.materials.append(key)
            return copy.deepcopy(request['host_identity']),key
        f.patch(capture.keys,'qualified_material',material)
        f.patch(capture.keys,'classify',lambda *_,**kwargs:{'scope':'inert fresh snapshot','bls_authority_checked':True,'commission':5})
        f.patch(capture.custody,'CUSTODY',f.home/'custody')
        f.patch(capture.custody,'root_directory',lambda path,create=False,mode=0o755:path.mkdir(mode=mode,exist_ok=True) if create else None)
        f.patch(capture.custody,'read',lambda path,maximum:files.read(path,maximum,os.getuid()))
        f.patch(capture.custody,'sync_file',lambda path:files.sync_file(path,os.getuid()))
        f.patch(capture.custody,'public',lambda seed:PUBLIC)
        def crypt(action,raw):
            if action=='encrypt':self.encrypted.append(raw);return b'inert:'+raw
            return raw.removeprefix(b'inert:')
        f.patch(capture.custody,'crypt',crypt)
        self.worker=capture.Capture(f.operation)
    def test_cipher_readback_retains_original_and_never_opens_runtime_gate(self):
        result=self.worker.capture();self.assertTrue(result['custody_verified']);self.assertFalse(result['private_exported'])
        self.assertFalse(result['runtime_started']);self.assertEqual(self.worker.capture(),result)
        self.assertEqual(len(self.encrypted),1);self.assertEqual(self.worker.export(),RAW)
        self.assertTrue(all(not any(value) for value in self.materials))
        with self.assertRaises(ValueError):state.State(self.fixture.home/'state').owner(self.fixture.contract)
        self.fixture.retained()
    def test_disabled_snapshot_or_original_writer_refuses_before_encryption(self):
        with patch.object(capture.keys,'classify',side_effect=ValueError('snapshot unavailable')):
            with self.assertRaises(ValueError):self.worker.capture()
        self.assertEqual(self.encrypted,[]);self.assertTrue(all(not any(value) for value in self.materials))
        self.fixture.writer=True
        with patch.object(capture.keys,'qualified_material') as material:
            with self.assertRaises(ValueError):self.worker.capture()
            material.assert_not_called()
    def test_ed25519_only_snapshot_cannot_authorize_capture_or_export(self):
        with patch.object(capture.keys,'classify',return_value={'scope':'inert Ed25519-only snapshot'}):
            with self.assertRaisesRegex(ValueError,'BLS'):self.worker.capture()
            with self.assertRaisesRegex(ValueError,'BLS'):self.worker.export()
        self.assertEqual(self.encrypted,[])

    def test_changed_original_commission_refuses_before_custody_transfer(self):
        with patch.object(capture.keys,'classify',return_value={'bls_authority_checked':True,'commission':6}):
            with self.assertRaisesRegex(ValueError,'commission'):self.worker.capture()
        self.assertEqual(self.encrypted,[])

    def test_partial_cipher_publication_resumes_same_original_without_generation(self):
        original=self.worker.state.put
        def fail(name,value):
            if name=='identity-sync.json':raise OSError('inert receipt interruption')
            original(name,value)
        with patch.object(self.worker.state,'put',side_effect=fail):
            with self.assertRaises(OSError):self.worker.capture()
        pending=list(capture.custody.CUSTODY.glob('*.pending.cred'));self.assertEqual(len(pending),1)
        retained=pending[0].read_bytes();self.worker.capture()
        self.assertEqual((capture.custody.CUSTODY/'sync.cred').read_bytes(),retained)
        self.assertEqual(len(self.encrypted),1);self.fixture.retained()
    def test_wrong_seed_public_or_replaced_cipher_never_exports(self):
        with patch.object(capture.custody,'public',return_value=bytes(32)):
            with self.assertRaises(ValueError):self.worker.capture()
        self.assertEqual(self.encrypted,[])
        self.worker.capture();path=capture.custody.CUSTODY/'sync.cred';path.write_bytes(b'changed inert ciphertext')
        with self.assertRaises(ValueError):self.worker.export()
        self.fixture.retained()


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(MigrationCustody))
    raise SystemExit(not result.wasSuccessful())
