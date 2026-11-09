# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual copy-to-data rename/source floor; isolated UID changes are modeled."""
import copy
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_promote as promote
import native_migration_transfer as transfer
import native_state as state
import native_files as files
from migration_transfer import MigrationTransfer
from mounts import owner
REAL_FCHOWN=os.fchown


class Promotion(MigrationTransfer):
    def setUp(self):
        super().setUp()
        self.observation['startup']={'mode':'validator','options':{},'overrides':None}
        self.patch(promote.settings,'sync_file',lambda p:files.sync_file(p,os.getuid()))
        self.contract=owner();self.contract['volumes']=self.volumes;self.scope['contract']=self.contract
        profile=json.loads((Path(__file__).resolve().parents[1]/'templates/node/migration-sources.json').read_bytes())['sources'][self.contract['network']][0]
        self.scope['legacy']['source_sha256']='c'*64
        self.scope['legacy']['source_history']['highest']={key:profile[key] for key in ('version','commit')}
        self.history={key:profile[key] for key in promote.floor.FULL}
        self.scope['legacy']['artifact_evidence']={'source':self.history}
        self.worker=transfer.Transfer(self.operation)
        files.atomic(self.store/'manager-confirmed.json',files.encoded({'binding_sha256':self.worker.binding,'manager_uid':2002}))
        with patch.object(os,'fchown',REAL_FCHOWN):self.worker.copy()
        self.ownership={};self.native_running=False;self.changes=[]
        self.home=self.root/'native';self.home.mkdir(mode=0o755)
        self.patch(promote.host,'HOME',self.home);self.patch(promote.host,'STATE',self.home/'state')
        self.patch(promote,'ROOT_UID',os.getuid());self.patch(promote,'ROOT_GID',os.getgid())
        self.patch(promote,'sync_file',lambda p,owner=0:files.sync_file(p,os.getuid()))
        self.patch(promote.floor,'sync_file',lambda p:files.sync_file(p,os.getuid()))
        self.patch(state,'sync_file',lambda p:files.sync_file(p,os.getuid()))
        self.patch(state,'read',lambda p,maximum:files.read(p,maximum,os.getuid()))
        def trusted(path,create=False,mode=0o755):
            self.assertTrue(path==self.root or self.root in path.parents)
            if create:path.mkdir(parents=True,exist_ok=True,mode=mode)
            info=path.lstat();promote.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022,'unsafe promotion root')
        self.patch(promote,'root_directory',trusted)
        self.plan={role:{'name':name,'home':home,'shell':promote.accounts.SHELL,'uid':20000+i,'gid':20000+i}
                   for i,(role,(name,home)) in enumerate(promote.accounts.SPECS.items())}
        self.patch(promote.accounts,'SPECS',{role:(item['name'],str(self.root/role)) for role,item in self.plan.items()})
        for role,item in self.plan.items():item['home']=promote.accounts.SPECS[role][1]
        def account_prepare(lifecycle,contract):
            lifecycle.owner(contract);lifecycle.put('accounts.json',{'contract':contract,'accounts':self.plan,'opening_protocol':1});return self.plan
        def account_verify(lifecycle,contract):
            lifecycle.owner(contract);self.assertEqual(lifecycle.get('accounts.json')['accounts'],self.plan);return self.plan
        self.patch(promote.accounts,'ensure',account_prepare);self.patch(promote.accounts,'verify',account_verify)
        self.patch(promote.process,'assert_quiescent',lambda uid:promote.require(not self.writer and not self.native_running
            and uid in (self.uid,20000),'original or new native writer remains'))
        self.patch(promote.floor.units,'MOUNTS',self.targets)
        real_fstat=os.fstat;real_lstat=Path.lstat
        def metadata(info):
            if info.st_ino not in self.ownership:return info
            values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            values['st_uid'],values['st_gid']=self.ownership[info.st_ino];return SimpleNamespace(**values)
        self.patch(os,'fstat',lambda fd:metadata(real_fstat(fd)))
        self.patch(Path,'lstat',lambda path,*args,**kwargs:metadata(real_lstat(path,*args,**kwargs)))
        def handoff(fd,uid,gid):
            self.assertEqual((uid,gid),(20000,20000));self.assertFalse(self.native_running)
            inode=real_fstat(fd).st_ino
            self.assertNotIn(inode,[path.stat().st_ino for path in self.sources.values()])
            self.ownership[inode]=(uid,gid);self.changes.append(inode)
        self.patch(os,'fchown',handoff)
        self.promotion=promote.Promotion(self.operation)
        self.payloads={kind:(path/('.erpc-migration-'+self.scope['intent'])/'payload').stat().st_ino for kind,path in self.targets.items()}
    def test_unpublished_first_marker_bytes_are_retained_but_never_used_as_authority(self):
        directory=self.home/'state';directory.mkdir(mode=0o700)
        pending=directory/('.erpc-'+'c'*32);pending.write_bytes(b'incomplete untrusted public JSON');pending.chmod(0o600)
        self.assertTrue(self.promotion.prepare_data()['native_data_promoted'])
        self.assertEqual(pending.read_bytes(),b'incomplete untrusted public JSON');self.retained()

    def test_verified_copied_inodes_become_native_data_without_empty_floor_or_startup(self):
        result=self.promotion.prepare_data();self.assertTrue(result['native_data_promoted'])
        self.assertFalse(result['runtime_started']);self.assertFalse(result['migration_complete']);self.retained()
        for kind,mount in self.targets.items():
            data=mount/'data';self.assertEqual(data.stat().st_ino,self.payloads[kind])
            self.assertEqual((data/'payload.bin').read_bytes(),self.original[kind]);self.assertEqual(data.lstat().st_uid,20000)
            self.assertEqual(mount.stat().st_mode&0o7777,0o755)
        actual=promote.floor.records(self.promotion.state,self.contract)
        self.assertEqual(promote.floor.highest(actual),self.history)
        for kind,item in actual[promote.floor.COMPLETE]['binding']['data'].items():
            self.assertEqual(item,{'uuid':self.volumes[kind],'inode':self.payloads[kind]})
        with self.assertRaises(ValueError):state.State(self.home/'state').owner(self.contract)
        self.assertEqual(self.promotion.prepare_data(),result)
    def test_completed_owner_cannot_omit_original_settings_at_runtime(self):
        self.promotion.prepare_data();lifecycle=self.promotion.state
        recorded=promote.settings.load(lifecycle,self.contract)
        self.assertEqual(recorded,promote.settings.settings(self.observation['startup']))
        marker=lifecycle.get('migration.json');marker['phase']='complete';lifecycle.put('migration.json',marker)
        import native_runtime_control as runtime
        with patch.object(runtime,'selected',side_effect=AssertionError('must refuse before native unit/proc checks')):
            with self.assertRaisesRegex(ValueError,'omitted or changed'):
                runtime.qualify(lifecycle,self.contract,{'receipt':{}})
        self.retained()

    def test_foreign_content_or_untracked_new_writer_cannot_receive_ownership(self):
        self.native_running=True
        with self.assertRaises(ValueError):self.promotion.prepare_data()
        self.assertEqual(self.changes,[]);self.native_running=False
        payload=self.targets['ledger']/('.erpc-migration-'+self.scope['intent'])/'payload/payload.bin'
        payload.write_bytes(b'foreign bytes retained')
        with self.assertRaises(ValueError):self.promotion.prepare_data()
        self.assertEqual(payload.read_bytes(),b'foreign bytes retained');self.retained()
        self.assertFalse((self.home/'state'/promote.floor.COMPLETE).exists())
    def test_original_inode_survives_lost_rename_reply_and_native_source_floor_is_not_reset(self):
        real=os.rename;calls=[]
        def lost(source,target):
            real(source,target);calls.append(True)
            if len(calls)==1:raise OSError('inert copied-inode publication reply lost')
        with patch.object(os,'rename',lost),self.assertRaises(OSError):self.promotion.prepare_data()
        self.assertTrue((self.targets['accounts']/'data').exists());self.retained()
        self.assertTrue(self.promotion.prepare_data()['native_data_promoted']);self.retained()
        higher=dict(self.history,version='4.9.0',commit='e'*40)
        promote.floor.claim(self.promotion.state,self.contract,higher)
        with self.assertRaises(ValueError):self.promotion.prepare_data()
        self.assertEqual(promote.floor.highest(promote.floor.records(self.promotion.state,self.contract)),higher)
    def test_interrupted_original_recipient_handoff_resumes_same_payloads(self):
        real=os.fchown;once=[]
        def lost(fd,uid,gid):
            real(fd,uid,gid);once.append(True)
            if len(once)==1:raise OSError('inert original UID handoff reply lost')
        with patch.object(os,'fchown',lost),self.assertRaises(OSError):self.promotion.prepare_data()
        self.retained();self.assertTrue(self.promotion.prepare_data()['native_data_promoted'])
        for kind,mount in self.targets.items():self.assertEqual((mount/'data').stat().st_ino,self.payloads[kind])
    def test_every_promotion_barrier_retries_original_inodes_and_preserves_source_floor(self):
        real=os.fsync;points=[]
        def record(fd):points.append(True);return real(fd)
        with patch.object(os,'fsync',record):self.promotion.prepare_data()
        for position in range(len(points)):
            fixture=Promotion('runTest');fixture.setUp()
            try:
                seen=[]
                def fail(fd):
                    index=len(seen);seen.append(True)
                    if index==position:raise OSError('inert promotion persistence interruption')
                    return real(fd)
                with patch.object(os,'fsync',fail),self.assertRaises(OSError):fixture.promotion.prepare_data()
                fixture.retained();fixture.promotion.prepare_data();fixture.retained()
                for kind,mount in fixture.targets.items():self.assertEqual((mount/'data').stat().st_ino,fixture.payloads[kind])
                records=promote.floor.records(fixture.promotion.state,fixture.contract)
                self.assertEqual(promote.floor.highest(records),fixture.history)
                with self.assertRaises(ValueError):state.State(fixture.home/'state').owner(fixture.contract)
            finally:fixture.doCleanups()
        print(str(len(points))+' copied-inode promotion barriers retried')

    def test_completed_migration_marker_cannot_reenter_old_data_promotion(self):
        self.promotion.prepare_data();lifecycle=self.promotion.state
        lifecycle.put('migration.json',dict(lifecycle.get('migration.json'),phase='complete'))
        count=len(self.changes)
        with self.assertRaises(ValueError):self.promotion.prepare_data()
        self.assertEqual(len(self.changes),count);self.retained()

if __name__=='__main__':
    names=[name for name in Promotion.__dict__ if name.startswith('test_')]
    result=unittest.TextTestRunner().run(unittest.TestSuite(Promotion(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
