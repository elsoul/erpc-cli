#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual lifecycle receipts across modeled mount-number changes, without mounts.

Only metadata device observations and findmnt responses are modeled. UUID,
original inode/ownership, actual files, promotion, journal and controller paths
remain the existing lifecycle fixtures. No reviewer reproduction is imported.
"""
import copy
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import authority_migration as migration_fixture
import arc_files as files
import arc_custody as custody
import arc_migration as migration
import arc_storage as storage


class DeviceView:
    def __init__(self,original,device):self.original,self.st_dev=original,device
    def __getattr__(self,name):return getattr(self.original,name)


class VolumeModel:
    def __init__(self,f):
        self.f=f;self.home=f.c.path(storage.DATA_HOME);self.stack=ExitStack()
        self.device=f.real_stat(self.home).st_dev;self.offset=0
        self.uuid='fixture-volume';self.extra_mounts=[];self.foreign=None;self.race=False
        path_stat,path_lstat=pathlib.Path.stat,pathlib.Path.lstat
        system_stat,descriptor=os.stat,os.fstat
        def named(path,info):
            path=pathlib.Path(path)
            if path==self.home or self.home in path.parents:
                extra=100 if self.foreign is not None and (path==self.foreign or self.foreign in path.parents) else 0
                return DeviceView(info,self.device+self.offset+extra)
            return info
        self.stack.enter_context(patch.object(pathlib.Path,'stat',lambda path,*a,**kw:named(path,path_stat(path,*a,**kw))))
        self.stack.enter_context(patch.object(pathlib.Path,'lstat',lambda path,*a,**kw:named(path,path_lstat(path,*a,**kw))))
        def associated(info):
            # Derive current named data inodes through DirEntry's unpatched OS
            # metadata, including files created or renamed during this operation.
            pending=[self.home]
            while pending:
                path=pending.pop()
                try:current=f.real_stat(path,follow_symlinks=False)
                except FileNotFoundError:continue
                if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):return named(path,info)
                if stat.S_ISDIR(current.st_mode):
                    with os.scandir(path) as entries:pending.extend(pathlib.Path(entry.path) for entry in entries)
            return info
        self.stack.enter_context(patch.object(os,'fstat',lambda fd:associated(descriptor(fd))))
        self.stack.enter_context(patch.object(os,'stat',lambda path,*a,**kw:associated(system_stat(path,*a,**kw)) if isinstance(path,int) or kw.get('dir_fd') is not None else named(path,system_stat(path,*a,**kw))))
        command=f.c.command
        def observed(*args,**kwargs):
            if args[0]!='/usr/bin/findmnt':return command(*args,**kwargs)
            if '--list' in args:
                value={'filesystems':[{'target':str(self.home)},*[{'target':str(path)} for path in self.extra_mounts]]}
            else:
                value={'filesystems':[{'target':str(self.home),'uuid':self.uuid,'fstype':'ext4','options':'rw'}]}
                if self.race:self.offset+=10;self.race=False
            return subprocess.CompletedProcess(args,0,json.dumps(value).encode(),b'')
        self.stack.enter_context(patch.object(f.c,'command',observed))
    def close(self):self.stack.close()
    def old_records(self,value):
        """The exact pre-fix persistent shapes, with the originally observed dev."""
        result=copy.deepcopy(value)
        def walk(item):
            if isinstance(item,dict):
                if set(item)=={'inode'} or set(item)=={'uuid','fstype'}:item['device']=self.device
                for child in item.values():walk(child)
            elif isinstance(item,list):
                for child in item:walk(child)
        walk(result);return result
    def legacy_owner(self):
        state=self.old_records(self.f.c.state(self.f.contract));self.f.c.save(state);return state


class Volumes(unittest.TestCase):
    def fixture(self,cls=lifecycle.Lifecycle):
        f=cls('runTest');f.setUp();self.addCleanup(f.tearDown)
        view=VolumeModel(f);self.addCleanup(view.close)
        return f,view
    def active(self,f):f.install();f.native_snapshot();f.call('activate',intent=f.intent)

    def test_active_guard_and_prepare_keep_legacy_originals_across_device_renumbering(self):
        f,view=self.fixture();self.active(f)
        original=view.legacy_owner();cipher=f.c.read(custody.CREDENTIAL)
        view.offset=73
        f.c.guard(f.c.state(f.contract),'execution')
        f.c.guard(f.c.state(f.contract),'execution',opening=True)
        f.call('prepare',helpers=f.helper)
        saved=f.c.state(f.contract)
        self.assertEqual(saved['storage'],original['storage'])
        self.assertEqual(saved['directories'],original['directories'])
        self.assertEqual(f.c.read(custody.CREDENTIAL),cipher)
        self.assertEqual(storage.verify(f.c,saved),view.home)

    def test_initial_prepared_volume_replay_keeps_empty_recovery_directory(self):
        f,view=self.fixture()
        recovery=view.home/'lost+found';recovery.mkdir(mode=0o700)
        original=view.legacy_owner();original['storage'].pop('prepared');f.c.save(original)
        inode=recovery.stat().st_ino;view.offset=31
        f.call('prepare',helpers=f.helper)
        self.assertEqual(recovery.stat().st_ino,inode)
        self.assertEqual(f.c.state(f.contract)['storage']['home'],original['storage']['home'])

    def test_bootstrap_completion_and_promotion_reuse_original_volume_after_renumbering(self):
        f,view=self.fixture();f.install();view.legacy_owner();view.offset=11
        f.native_snapshot();old=view.legacy_owner();view.offset=22
        f.call('activate',intent=f.intent)
        state=f.c.state(f.contract)
        self.assertTrue(state['bootstrap_complete'])
        for layer in storage.LAYERS:
            self.assertEqual(state['directories'][layer],old['bootstrap_pair'][layer])
        f.c.guard(state,'execution')

    def test_half_promoted_original_pair_resumes_after_a_new_device_number(self):
        f,view=self.fixture();f.install();f.native_snapshot();original=view.legacy_owner()
        rename=os.rename;hit=[]
        def interrupted(source,target,*args,**kwargs):
            result=rename(source,target,*args,**kwargs)
            if pathlib.Path(target)==view.home/'execution' and not hit:
                hit.append(True);raise OSError('inert interruption after first original promotion')
            return result
        with patch.object(os,'rename',interrupted),self.assertRaises(OSError):f.call('activate',intent=f.intent)
        view.offset=51
        f.call('activate',intent=f.intent)
        for name,record in original['bootstrap_pair'].items():
            self.assertEqual((view.home/name).stat().st_ino,record['inode'])
        self.assertEqual((view.home/'execution/db/mdbx.dat').read_bytes(),b'original inert block history')

    def test_quarantine_retry_keeps_legacy_receipt_name_and_original_partial_bytes(self):
        f,view=self.fixture();f.install();view.legacy_owner()
        (view.home/'bootstrap/partial').write_text('original interrupted snapshot')
        first=f.call('reset-bootstrap',intent=f.intent);view.offset=43
        self.assertEqual(f.call('reset-bootstrap',intent=f.intent),first)
        self.assertEqual((view.home/first['retained']/'partial').read_text(),'original interrupted snapshot')

    def test_legacy_migration_journal_resumes_with_original_ids_and_inodes(self):
        f,view=self.fixture(migration_fixture.Migration)
        result=f.c.dispatch(f.migration_request);f.c.write_bytes(result['archive'],f.archive)
        write=f.c.write;hit=[]
        def interrupted(name,value,*args,**kwargs):
            if name==migration.JOURNAL and not hit:
                hit.append(True);write(name,view.old_records(value),*args,**kwargs)
                raise OSError('inert migration journal interruption')
            return write(name,value,*args,**kwargs)
        with patch.object(f.c,'write',interrupted),self.assertRaises(OSError):f.c.dispatch(dict(f.migration_request,action='migrate'))
        journal=f.c.json(migration.JOURNAL);view.offset=91
        self.assertTrue(f.migrate()['stopped'])
        state=f.c.state(f.contract)
        self.assertEqual(state['storage']['home'],journal['layout']['directories']['root'])
        self.assertEqual(state['service_uid'],f.evidence['uid'])
        storage.verify(f.c,state)
        self.assertEqual((view.home/'consensus/store.db').read_bytes(),b'original legacy block history')

    def test_changed_uuid_never_rebinds_the_original_receipt_but_stop_stays_available(self):
        f,view=self.fixture();self.active(f);original=view.legacy_owner()
        view.offset=10;view.uuid='foreign-volume'
        for operation in (lambda:f.c.guard(f.c.state(f.contract),'execution'),lambda:f.call('prepare',helpers=f.helper)):
            with self.assertRaises(files.Refused):operation()
        self.assertEqual(f.c.state(f.contract)['storage'],original['storage'])
        self.assertEqual(f.call('stop',layer='both')['applied'],'stopped')

    def test_same_uuid_with_replacement_inode_cannot_be_adopted(self):
        f,view=self.fixture();self.active(f);original=view.legacy_owner()
        retained=view.home.with_name('retained-original');view.home.rename(retained)
        shutil.copytree(retained,view.home);view.offset=9
        with self.assertRaises(files.Refused):storage.verify(f.c,f.c.state(f.contract))
        with self.assertRaises(files.Refused):f.c.guard(f.c.state(f.contract),'execution')
        with self.assertRaises(files.Refused):f.call('prepare',helpers=f.helper)
        self.assertEqual(f.c.state(f.contract)['storage'],original['storage'])

    def test_qualified_bootstrap_pair_cannot_be_replaced_even_on_the_same_uuid(self):
        f,view=self.fixture();f.install();f.native_snapshot();original=view.legacy_owner();view.offset=19
        root=view.home/'bootstrap/execution';root.rename(view.home/'bootstrap/retained-execution')
        root.mkdir(mode=0o700)
        with self.assertRaises(files.Refused):f.call('activate',intent=f.intent)
        self.assertEqual(f.c.state(f.contract)['bootstrap_pair'],original['bootstrap_pair'])
        self.assertFalse((view.home/'execution').exists())

    def test_migration_resume_refuses_a_different_uuid_without_replacing_history(self):
        f,view=self.fixture(migration_fixture.Migration)
        result=f.c.dispatch(f.migration_request);f.c.write_bytes(result['archive'],f.archive)
        write=f.c.write
        def interrupted(name,value,*args,**kwargs):
            write(name,view.old_records(value),*args,**kwargs)
            if name==migration.JOURNAL:raise OSError('inert before migration publication')
        with patch.object(f.c,'write',interrupted),self.assertRaises(OSError):f.c.dispatch(dict(f.migration_request,action='migrate'))
        original=f.c.read(migration.JOURNAL);view.offset=5;view.uuid='substituted-volume'
        with self.assertRaises(files.Refused):f.migrate()
        self.assertEqual(f.c.read(migration.JOURNAL),original)
        self.assertEqual((view.home/'execution/db/mdbx.dat').read_bytes(),b'original legacy block history')

    def test_nested_same_device_and_stacked_mounts_still_refuse_before_start(self):
        f,view=self.fixture();self.active(f);view.legacy_owner();view.offset=80
        for mount in (view.home/'execution/db',view.home):
            view.extra_mounts=[mount]
            with self.subTest(mount=mount),self.assertRaises(files.Refused):f.c.guard(f.c.state(f.contract),'execution')
        view.extra_mounts=[];f.c.guard(f.c.state(f.contract),'execution')

    def test_current_observation_cannot_cross_devices_or_accept_a_mid_probe_rebind(self):
        f,view=self.fixture();self.active(f);view.legacy_owner();view.offset=61
        view.foreign=view.home/'execution'
        with self.assertRaises(files.Refused):f.c.guard(f.c.state(f.contract),'execution')
        view.foreign=None;view.race=True
        with self.assertRaises(files.Refused):storage.verify(f.c,f.c.state(f.contract))
        f.c.guard(f.c.state(f.contract),'execution')


if __name__=='__main__':unittest.main()
