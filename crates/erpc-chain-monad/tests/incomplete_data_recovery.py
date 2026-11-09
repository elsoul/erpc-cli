# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Build real reviewed40 interruptions, then exercise actual current recovery.

fixtures/legacy_data_setup.py is the verbatim data-setup prefix of
this repository at commit d5a690f9cb2f4cacd21050d5fdb1ce6f5ece3100.
The failure drivers here are author-written, not copied from a review harness.
"""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import data_layout
fixture=data_layout.fixture
setup=data_layout.setup
SOURCE=Path(__file__).parent/'fixtures/legacy_data_setup.py'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()=='372d0a799b7c75670998d17721289d1f6670c6a681d657c59c71ca3e05015b1b', 'reviewed legacy source fixture changed'
spec=importlib.util.spec_from_file_location('reviewed40_data_setup_fixture',SOURCE)
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)


class Recovery(data_layout.DataLayout):
    # Keep the original17 cases as separate suite; this class owns its scenarios.
    def setUp(self):
        super().setUp()
        original=Path.lstat
        def metadata(path,*args,**kwargs):
            value=original(path,*args,**kwargs);fields=list(value)
            if stat.S_ISDIR(value.st_mode):fields[4],fields[5]=self.owners.get((value.st_dev,value.st_ino),(0,0))
            return os.stat_result(fields)
        for obj,name,value in ((legacy,'ROOT',self.root),(legacy,'owned_directory',lambda path:None),
                (legacy,'read',lambda path:fixture.common.read(path,owner=os.getuid())),(Path,'lstat',metadata)):
            entry=patch.object(obj,name,value);entry.start();self.addCleanup(entry.stop)
    def old_initial(self,point='handoff'):
        if point=='handoff':
            with patch.object(os,'fchown',side_effect=OSError('inert first original ownership failure')),self.assertRaises(OSError):
                legacy.prepare_data(self.state,self.c,self.uid,self.gid,final=False)
        else:
            original=self.state.put
            def fail(name,value):
                original(name,value)
                if name=='data-preparing.json':raise OSError('inert first pending acknowledgement loss')
            with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):
                legacy.prepare_data(self.state,self.c,self.uid,self.gid,final=False)
        self.assertFalse((self.root/'data-ready.json').exists())
        self.state.cancel(self.c,False,lambda:None)
        return {name:(self.root/name).read_bytes() for name in ('data-preparing.json',)}
    def old_selection(self,point='publish'):
        legacy.prepare_data(self.state,self.c,self.uid,self.gid,final=False)
        (self.root/'data').rename(self.root/'original-unused-provisional')
        (self.root/'data').mkdir(mode=0o755);(self.root/'data/lost+found').mkdir(mode=0o700)
        self.fs_uuid='00000000-0000-0000-0000-000000000002'
        if point=='publish':
            original=self.state.put
            def fail(name,value):
                if name=='data-ready.json':raise OSError('inert selected layout final publication loss')
                original(name,value)
            with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):
                legacy.prepare_data(self.state,self.c,self.uid,self.gid,final=True)
        else:
            with patch.object(os,'fchown',side_effect=OSError('inert selected original handoff failure')),self.assertRaises(OSError):
                legacy.prepare_data(self.state,self.c,self.uid,self.gid,final=True)
        self.state.cancel(self.c,False,lambda:None)
        return {name:(self.root/name).read_bytes() for name in
            ('data-preparing.json','data-ready.json','data-mount-preparing.json')}
    def preserved(self,original):
        journal=self.state.get('data-incomplete-upgrade.json')
        for name,raw in original.items():
            saved=journal['original_files'][name]
            self.assertEqual(base64.b64decode(saved['bytes']),raw)
            self.assertEqual(saved['sha256'],hashlib.sha256(raw).hexdigest())
            if name!='data-ready.json':self.assertEqual((self.root/name).read_bytes(),raw)
        self.assertTrue((self.root/'stopped').exists())
        self.assertFalse((self.root/'device-initialized.json').exists())
        self.assertFalse((self.root/'installed.json').exists())
    def test_reviewed_initial_before_any_directory_is_resumed_only_as_unused_provisional(self):
        original=self.old_initial('pending')
        result=self.recover();self.assertTrue(result['empty_layout_completed']);self.preserved(original)
        self.assertFalse(self.state.get('data-ready.json')['final'])
        with self.assertRaises(ValueError):setup.verify_data(self.state,self.c,self.uid,self.gid)
        self.prepare();setup.verify_data(self.state,self.c,self.uid,self.gid)
    def test_reviewed_initial_after_first_mkdir_retains_original_inode_and_scope(self):
        original=self.old_initial();inode=(self.root/'data').stat().st_ino
        self.recover();self.recover();self.preserved(original)
        self.assertEqual((self.root/'data').stat().st_ino,inode)
        self.assertFalse(self.state.get('data-ready.json')['final'])
        self.prepare();setup.verify_data(self.state,self.c,self.uid,self.gid)
    def test_reviewed_selected_mount_final_publication_failure_uses_recorded_selection_not_hidden_provisional(self):
        original=self.old_selection();selected=self.state.get('data-mount-preparing.json')['binding']['inode']
        lost=(self.root/'data/lost+found').stat().st_ino
        self.assertNotEqual(self.state.get('data-ready.json')['binding']['inode'],selected)
        self.recover();self.preserved(original);self.assertTrue(self.state.get('data-ready.json')['final'])
        self.assertEqual(self.state.get('data-ready.json')['binding']['inode'],selected)
        self.assertEqual((self.root/'data/lost+found').stat().st_ino,lost)
        self.prepare();self.recover();setup.verify_data(self.state,self.c,self.uid,self.gid)
    def test_selected_mount_before_handoff_preserves_recovery_directory_and_completes_only_empty_layout(self):
        original=self.old_selection('handoff')
        self.recover();self.preserved(original)
        self.assertEqual(list((self.root/'data/lost+found').iterdir()),[])
        setup.verify_data(self.state,self.c,self.uid,self.gid)
    def test_initial_and_selected_unknown_payload_or_used_history_are_never_adopted(self):
        original=self.old_initial();payload=self.root/'data/private-history';payload.write_bytes(b'preserve unknown payload')
        with self.assertRaisesRegex(ValueError,'payload'):self.recover()
        self.assertEqual(payload.read_bytes(),b'preserve unknown payload')
        self.assertFalse((self.root/'data-incomplete-upgrade.json').exists());payload.unlink()
        self.state.put('device-initializing.json',{'original':'native write attempted'})
        with self.assertRaisesRegex(ValueError,'used native'):self.recover()
        self.assertFalse((self.root/'data-incomplete-upgrade.json').exists())
        self.assertEqual((self.root/'data-preparing.json').read_bytes(),original['data-preparing.json'])
    def test_selected_wrong_uuid_replaced_inode_or_unknown_recovered_content_refuses(self):
        original=self.old_selection()
        with self.assertRaisesRegex(ValueError,'UUID'):self.recover('00000000-0000-0000-0000-000000000003')
        extra=self.root/'data/lost+found/recovered';extra.write_bytes(b'preserve recovered history')
        with self.assertRaisesRegex(ValueError,'payload'):self.recover()
        self.assertEqual(extra.read_bytes(),b'preserve recovered history');extra.unlink()
        (self.root/'data').rename(self.root/'original-selected');(self.root/'data').mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError,'inode'):self.recover()
        self.assertEqual((self.root/'data-ready.json').read_bytes(),original['data-ready.json'])
        self.assertFalse((self.root/'data-incomplete-upgrade.json').exists())
    def sweep(self,kind):
        def original_state(test):return test.old_initial() if kind=='initial' else test.old_selection('handoff')
        real=os.fsync;probe=Recovery();probe.setUp();count=[0]
        try:
            original_state(probe)
            def observed(fd):count[0]+=1;return real(fd)
            with patch.object(os,'fsync',side_effect=observed):probe.recover()
        finally:probe.doCleanups()
        self.assertGreater(count[0],20)
        for point in range(1,count[0]+1):
            with self.subTest(kind=kind,fsync=point):
                test=Recovery();test.setUp();seen=[0]
                try:
                    original=original_state(test)
                    def interrupted(fd):
                        seen[0]+=1
                        if seen[0]==point:raise OSError('inert single recovery sync failure')
                        return real(fd)
                    with patch.object(os,'fsync',side_effect=interrupted),self.assertRaises((OSError,ValueError)):
                        test.recover()
                    self.assertGreaterEqual(seen[0],point)
                    test.recover();test.preserved(original)
                    self.assertEqual(test.state.get('data-ready.json')['final'],kind=='selected')
                finally:test.doCleanups()
        print(kind+': '+str(count[0])+' actual fsync failure points recovered from original evidence')
    def test_every_initial_recovery_sync_failure_retains_original_evidence_and_can_resume(self):
        self.sweep('initial')
    def test_every_selected_recovery_sync_failure_retains_original_evidence_and_can_resume(self):
        self.sweep('selected')
    def test_persistent_sync_failure_never_claims_completed_empty_layout(self):
        original=self.old_selection('handoff')
        for _ in range(3):
            with patch.object(os,'fsync',side_effect=OSError('inert persistent storage failure')),self.assertRaises((OSError,ValueError)):
                self.recover()
            self.assertEqual((self.root/'data-ready.json').read_bytes(),original['data-ready.json'])
            self.assertFalse((self.root/'installed.json').exists())
        self.recover();self.preserved(original)

    def test_lost_recovery_journal_or_final_acknowledgement_retries_same_original_selection(self):
        original=self.old_selection('handoff');write=self.state.put
        def fail(name,value):
            write(name,value)
            if name=='data-incomplete-upgrade.json':raise OSError('inert migration directory acknowledgement failure')
        with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):self.recover()
        with self.assertRaises(ValueError):self.recover('00000000-0000-0000-0000-000000000003')
        self.recover();self.preserved(original)
        self.assertTrue(self.state.get('data-ready.json')['final'])


# Inherit the fixture helpers, not its tests: the existing suite runs independently.
for name in dir(data_layout.DataLayout):
    if name.startswith('test_') and name not in Recovery.__dict__:setattr(Recovery,name,None)

if __name__=='__main__':unittest.main()
