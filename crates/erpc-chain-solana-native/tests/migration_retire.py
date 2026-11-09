# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compose actual ownership journal, service mask and privilege retirement."""
import copy
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_files
import native_runtime_control as runtime
import native_migration_retire as migration
import native_migration_guard
import native_migration_fence as fence
import native_migration_privileges as privileges
from migration_privileges import Retirement as PrivilegeFixture
from mounts import owner


class Coordinator(PrivilegeFixture):
    def setUp(self):
        super().setUp()
        self.original_store=self.store;self.store=self.root/'migration';self.store.mkdir(mode=0o700)
        self.unit=self.root/'etc/systemd/system/solv.service';self.unit.parent.mkdir(parents=True)
        self.unit.write_bytes(b'[Service]\nUser=solv\nExecStart=/home/solv/start-validator.sh\n');self.unit.chmod(0o644)
        self.unit_raw=self.unit.read_bytes();self.running=True;self.loaded_mask=False
        self.parent_trusted=migration.root_directory
        def trusted(path,create=False,mode=0o755):
            self.assertTrue(path==self.root or self.root in path.parents)
            if create:path.mkdir(parents=True,exist_ok=True,mode=mode)
            info=path.lstat();migration.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022,'untrusted fixture root')
        self.trusted=trusted
        for module in (migration,fence):
            self.patch(module,'root_directory',trusted);self.patch(module,'ROOT_UID',os.getuid())
            self.patch(module,'sync_file',lambda p,owner=0:native_files.sync_file(p,os.getuid()))
        self.patch(migration.host,'STATE',self.root/'native-state')
        self.patch(native_migration_guard,'install',lambda operation:None)
        self.patch(native_migration_guard,'other_runs_idle',lambda run:None)
        self.patch(migration,'STORE',self.store);self.patch(fence,'STORE',self.store/'retirement');self.patch(fence,'UNIT',self.unit)
        self.patch(privileges,'STORE',self.store/'privileges')
        self.patch(privileges,'root_directory',trusted)
        self.contract=owner();origins=json.loads((migration.SOURCE/'migration-sources.json').read_bytes())
        profile=origins['sources'][self.contract['network']][0]
        self.machine=b'1'*32;self.write('/etc/machine-id',self.machine+b'\n')
        self.request={'action':'migration-reserve','intent':'c'*32,'contract':self.contract,'ssh_port':2222,
            'legacy':{'network':self.contract['network'],'role':'validator','identity_account':self.contract['identity_account'],
            'vote_account':self.contract['vote_account'],'management_user':'operator','source_sha256':'b'*64,
            'historical':{'uid':1001,'gid':1101,'machine_id_sha256':hashlib.sha256(self.machine).hexdigest(),
                'source':dict.fromkeys(('passwd','group','machine_id'),'d'*64)},
            'source_history':{'document_sha256':'e'*64,'highest':{key:profile[key] for key in ('version','commit')}},
            'artifact_evidence':{'document_sha256':'f'*64,'network':self.contract['network'],
                'source':{key:profile[key] for key in ('version','commit','cargo_lock_sha256','rust','rust_manifest_sha256')},
                'executable_sha256':'a'*64,'executable_bytes':8192},'target_volumes':self.contract['volumes']}}
        self.request['legacy']['commission']=5
        self.request['legacy']['keygen_evidence']=copy.deepcopy(self.request['legacy']['artifact_evidence'])
        self.request['legacy']['host_identity']={'role':'sync','path':'/home/solv/unstaked-identity.json','uid':1001,'gid':1101,'inode':123,'bytes':240,'mtime_ns':1,'public':'7'*44,'bls_public':'2'*66}
        self.patch(migration.keys,'source',lambda request:(None,{k:v for k,v in request['host_identity'].items() if k not in ('public','bls_public')}))
        self.keygen_available=True
        def keygen(request):
            migration.require(self.keygen_available,'original keygen unavailable')
            return contextlib.nullcontext()
        self.patch(migration.bls,'artifact',keygen)
        self.native={'pid':1234,'start_ticks':5678,'device':12,'inode':345,'image_sha256':'a'*64,'image_bytes':8192,
                     'artifact_evidence_matches':True,'effective_environment_sha256':'b'*64,'source_layout':'managed-agave-build','native_source_verified':False}
        self.storage={kind:{'uuid':'10000000-0000-0000-0000-00000000000'+str(index),'device':[8,index],'inode':index+100,
                   'mount_id':str(index),'fs':'ext4','uid':1001,'gid':1101} for index,kind in enumerate(('accounts','ledger','snapshots'),1)}
        self.observed={'unit_sha256':hashlib.sha256(self.unit_raw).hexdigest(),'startup':{'script_sha256':'a'*64,'mode':'validator','options':{},'overrides':None},
            'service':{'process':self.native,'commands_sha256':'c'*64,'execution_policy_sha256':'e'*64,'dependencies_sha256':'d'*64},
            'dropins':None,'storage':copy.deepcopy(self.storage),'copy_preflight':{'copy_authorized':False}}
        self.patch(migration.host,'platform_facts',lambda *_:{});self.patch(migration.legacy,'ROOT',self.root)
        self.patch(migration.legacy,'inspect',lambda request,run,uid:copy.deepcopy(self.observed))
        self.request['legacy']['settings_sha256']=migration.legacy.settings_digest(migration.settings.settings(self.observed['startup']))
        self.patch(migration.legacy,'read_public',lambda name,uid=0,maximum=65536:self.machine if name=='etc/machine-id' else b'inert original startup')
        self.patch(migration.legacy,'startup',lambda *_:self.observed['startup'])
        self.patch(migration.legacy,'storage_observation',lambda *_:copy.deepcopy(self.storage))
        self.patch(migration.legacy,'service_properties',lambda run,allow_reload=False:{'MainPID':str(self.native['pid']) if self.running else '0','ActiveState':'active' if self.running else 'inactive'})
        for name,field in (('loaded_commands','commands_sha256'),('loaded_policy','execution_policy_sha256'),('loaded_dependencies','dependencies_sha256')):
            self.patch(migration.legacy,name,lambda *_,field=field:self.observed['service'][field])
        self.patch(migration.legacy,'process_observation',lambda *_:copy.deepcopy(self.native) if self.running else None)
        self.patch(migration,'original_processes',lambda uid,pid:migration.require(not self.writer and (pid==self.native['pid'] or pid==0 and not self.running),'unknown writer'))
        self.patch(migration.process,'assert_quiescent',self.quiet)
        self.operation=migration.Retirement(self.request,1002,self.service,self.command)
    def quiet(self,uid):
        self.assertEqual(uid,1001);migration.require(not self.writer and not self.running,'original writer remains')
    def service(self,argv):
        self.commands.append(argv);self.assertEqual(argv[0],'/usr/bin/systemctl')
        if argv[1]=='list-units':return 'solv.service loaded active running original\n'
        if argv[1]=='show':
            if argv[2]!='solv.service':return ''
            values={'LoadState':'masked' if self.loaded_mask else 'loaded','ActiveState':'active' if self.running else 'inactive',
                'SubState':'running' if self.running else 'dead','MainPID':str(self.native['pid']) if self.running else '0','ControlPID':'0',
                'NeedDaemonReload':'no','FragmentPath':'/dev/null' if self.loaded_mask else '/etc/systemd/system/solv.service','DropInPaths':''}
            return ''.join(key+'='+value+'\n' for key,value in values.items())
        if argv[1]=='stop':self.assertTrue(self.unit.exists() or self.unit.is_symlink());self.running=False
        elif argv[1]=='daemon-reload':self.loaded_mask=self.unit.is_symlink()
        elif argv[1]!='disable':self.fail('unexpected native/systemd action')
        return ''
    def test_actual_status_dispatch_is_readonly_and_available_during_a_locked_copy(self):
        self.operation.reserve();before={p.name:p.read_bytes() for p in self.store.iterdir()}
        operations=self.root/'operations';operations.mkdir();fd=os.open(operations,os.O_RDONLY)
        real=migration.Retirement
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(runtime,'OPERATION_ROOT',operations),patch.object(os,'fsync',side_effect=OSError('no writes in status')), \
                    patch.object(migration,'management',return_value=1002), \
                    patch.object(migration,'Retirement',side_effect=lambda request,uid:real(request,uid,self.service,self.command)):
                result=runtime.control(dict(self.request,action='migration-status'))
            self.assertEqual(result['recorded_phase'],'reserved');self.assertIsNone(result['ready'])
            self.assertFalse(result['runtime_inspected']);self.assertEqual({p.name:p.read_bytes() for p in self.store.iterdir()},before)
        finally:os.close(fd)
        self.store.rename(self.store.with_name('preserved'))
        missing=migration.status(self.operation)
        self.assertEqual(missing["recorded_phase"],"unreserved");self.assertFalse(missing["migration_reserved"])
        self.assertFalse(self.store.exists(),'read-only status created a namespace')

    def test_actual_dispatch_publishes_only_reserved_scope_and_requires_direct_confirmation(self):
        real=migration.Retirement
        with patch.object(migration,'management',return_value=1002), patch.object(migration.helpers,'publish',return_value='f'*64), \
                patch.object(migration,'Retirement',side_effect=lambda request,uid:real(request,uid,self.service,self.command)):
            result=migration.control(self.request,True)
            self.assertEqual(result['helper_revision'],'f'*64);self.assertTrue(self.running)
            request=dict(self.request,action='migration-confirm-manager')
            with self.assertRaises(ValueError):migration.control(request,True)
            with self.assertRaises(FileNotFoundError):migration.control(request,False)
            self.assertTrue(self.running)
            request['action']='migration-retire'
            self.assertFalse(migration.control(request,True)['copy_authorized'])
            request['action']='migration-confirm-manager'
            self.assertTrue(migration.control(request,False)['manager_reauthenticated'])

    def test_every_composed_durable_barrier_recovers_only_the_same_retired_source(self):
        real=os.fsync;points=[]
        def record(fd):points.append(True);return real(fd)
        with patch.object(os,'fsync',record):
            self.operation.reserve();self.operation.retire();self.operation.confirm()
        for position in range(len(points)):
            fixture=Coordinator('runTest');fixture.setUp()
            try:
                seen=[]
                def fail(fd):
                    index=len(seen);seen.append(True)
                    if index==position:raise OSError('inert composed durability interruption')
                    return real(fd)
                with patch.object(os,'fsync',fail),self.assertRaises(OSError):
                    fixture.operation.reserve();fixture.operation.retire();fixture.operation.confirm()
                fixture.operation.reserve();fixture.operation.retire()
                self.assertTrue(fixture.operation.confirm()['manager_reauthenticated'])
                self.assertEqual((fixture.store/'retirement/original.service').read_bytes(),fixture.unit_raw)
                self.assertEqual(fixture.storage,fixture.observed['storage']);self.assertFalse(fixture.running)
            finally:fixture.doCleanups()
        print(str(len(points))+' composed original retirement fsync interruptions retried')

    def test_persistent_first_fence_sync_failure_still_attempts_only_owned_shutdown(self):
        self.operation.reserve();original=(self.store/'original.json').read_bytes()
        with patch.object(os,'fsync',side_effect=OSError('persistent inert storage failure')):
            with self.assertRaises(OSError):self.operation.retire()
        self.assertFalse(self.running)
        self.assertEqual((self.store/'original.json').read_bytes(),original)
        self.assertEqual(self.storage,self.observed['storage'])
        self.operation.retire();self.assertTrue(self.operation.confirm()['manager_reauthenticated'])

    def test_failed_shutdown_is_not_reported_successful_and_unknown_source_is_not_stopped(self):
        self.operation.reserve();original=self.operation.run
        def failure(args):
            if args[:2]==['/usr/bin/systemctl','stop']:raise OSError('inert owned stop failed')
            return original(args)
        self.operation.run=failure
        with patch.object(os,'fsync',side_effect=OSError('persistent inert storage failure')):
            with self.assertRaisesRegex(ValueError,'shutdown failed'):self.operation.retire()
        self.assertTrue(self.running);self.operation.run=original
        self.native['image_sha256']='f'*64
        before=len([x for x in self.commands if x[:2]==['/usr/bin/systemctl','stop']])
        with patch.object(os,'fsync',side_effect=OSError('persistent inert storage failure')):
            with self.assertRaisesRegex(ValueError,'image or source layout changed'):self.operation.retire()
        self.assertTrue(self.running)
        self.assertEqual(before,len([x for x in self.commands if x[:2]==['/usr/bin/systemctl','stop']]))

    def test_scheduled_or_independent_original_uid_launch_is_refused_before_stop(self):
        directory=self.root/'var/lib/systemd/linger';directory.mkdir(parents=True)
        (directory/'solv').write_bytes(b'')
        with self.assertRaises(ValueError):self.operation.reserve()
        self.assertTrue(self.running);self.assertFalse((self.store/'original.json').exists())
        (directory/'solv').unlink();original_run=self.operation.run
        def other_service(argv):
            if argv[1]=='list-units':return 'solv.service loaded active running original\nother.service loaded inactive dead original\n'
            if argv[1:3]==['show','other.service']:return '1001\n'
            return original_run(argv)
        self.operation.run=other_service
        with self.assertRaises(ValueError):self.operation.reserve()
        self.assertTrue(self.running);self.assertFalse((self.store/'original.json').exists())

    # Parent methods exercise its own primitive in a different store; run them
    # only in migration_privileges.py, not through this coordinator subclass.
    def test_reserved_original_retire_and_reconnect_keep_data_and_identity(self):
        saved=self.operation.reserve();self.assertTrue(self.running)
        self.assertEqual(saved['observation'],self.observed)
        result=self.operation.retire();self.assertFalse(result['copy_authorized'])
        self.assertTrue(result['manager_reauthentication_required']);self.assertFalse(self.running)
        self.assertEqual(os.readlink(self.unit),'/dev/null');self.assertEqual((self.store/'retirement/original.service').read_bytes(),self.unit_raw)
        self.assertTrue(self.operation.confirm()['manager_reauthenticated'])
        self.assertEqual(self.users()[0].pw_uid,1001);self.assertEqual(self.users()[0].pw_dir,'/home/solv')
        self.assertEqual(self.storage,self.observed['storage'])
    def test_resume_uses_original_snapshot_and_stable_uuid_after_device_renumber(self):
        self.operation.reserve();self.operation.retire()
        for value in self.storage.values():value['device'][0]=42;value['mount_id']='999'
        self.assertTrue(self.operation.confirm()['manager_reauthenticated'])
        self.storage['ledger']['uuid']='20000000-0000-0000-0000-000000000002'
        with self.assertRaises(ValueError):self.operation.confirm()
        self.assertFalse(self.running)
    def test_missing_original_keygen_is_refused_before_retirement_or_source_receipt(self):
        self.keygen_available=False
        with self.assertRaisesRegex(ValueError,'keygen'):self.operation.reserve()
        self.assertTrue(self.running);self.assertFalse((self.store/'original.json').exists())

    def test_approved_settings_cannot_change_before_reservation_or_retirement(self):
        self.observed['startup']['options']['--limit-ledger-size']=['50000000']
        with self.assertRaisesRegex(ValueError,'approved migration plan'): self.operation.reserve()
        self.assertFalse((self.store/'original.json').exists());self.assertTrue(self.running)
        self.observed['startup']['options']={}
        self.operation.reserve();before=(self.store/'original.json').read_bytes()
        self.observed['startup']['options']['--limit-blockstore-size']=['400000000']
        with self.assertRaises(ValueError):self.operation.retire()
        self.assertTrue(self.running);self.assertEqual((self.store/'original.json').read_bytes(),before)

    def test_same_qualified_source_restart_keeps_original_snapshot_and_can_retire(self):
        original=self.operation.reserve()['observation']['service']['process']
        self.native.update(pid=4321,start_ticks=9999,device=42,effective_environment_sha256='f'*64)
        self.assertFalse(self.operation.retire()['copy_authorized'])
        self.assertEqual(self.operation.saved()['observation']['service']['process'],original)
        self.assertTrue(self.operation.confirm()['manager_reauthenticated'])

    def test_restart_with_different_image_or_unknown_source_layout_is_not_stopped(self):
        self.operation.reserve();original=copy.deepcopy(self.native)
        for field,value in (('image_sha256','f'*64),('image_bytes',8193),('inode',346),('source_layout','unowned')):
            self.native.update(original);self.native.update(pid=4321,start_ticks=9999);self.native[field]=value
            count=len([row for row in self.commands if row[:2]==['/usr/bin/systemctl','stop']])
            with self.assertRaises(ValueError):self.operation.retire()
            self.assertEqual(len([row for row in self.commands if row[:2]==['/usr/bin/systemctl','stop']]),count)
            self.assertTrue(self.running);self.assertEqual(self.unit.read_bytes(),self.unit_raw)

    def test_no_native_or_copy_when_old_process_unknown_or_public_scope_changed(self):
        self.writer=True
        with self.assertRaises(ValueError):self.operation.reserve()
        self.assertTrue(self.running);self.assertEqual(self.unit.read_bytes(),self.unit_raw)
        self.writer=False;self.operation.reserve();request=copy.deepcopy(self.request);request['intent']='d'*32
        other=migration.Retirement(request,1002,self.service,self.command)
        with self.assertRaises(ValueError):other.retire()
        self.assertTrue(self.running)
    def test_failure_at_first_mask_receipt_attempts_owned_shutdown_but_never_reports_success(self):
        self.operation.reserve();real=fence.atomic
        def fail(path,*args):
            if path.name=='retirement.json':raise OSError('inert persistent journal failure')
            return real(path,*args)
        with patch.object(fence,'atomic',fail),self.assertRaises(OSError):self.operation.retire()
        self.assertFalse(self.running);self.assertEqual(self.unit.read_bytes(),self.unit_raw)
        self.assertFalse((self.store/'manager-confirmed.json').exists())
        self.assertFalse(self.operation.retire()['copy_authorized'])
    def test_command_failure_leaves_mask_and_retries_original_only(self):
        self.operation.reserve();self.fail_action='/usr/sbin/usermod'
        with self.assertRaises(OSError):self.operation.retire()
        self.assertFalse(self.running);self.assertEqual(os.readlink(self.unit),'/dev/null')
        self.assertFalse((self.store/'manager-confirmed.json').exists())
        self.fail_action=None;self.assertFalse(self.operation.retire()['copy_authorized'])
        self.assertTrue(self.operation.confirm()['manager_reauthenticated'])
    def test_carried_uploader_receipt_and_direct_ssh_confirmation_are_distinct(self):
        source=self.root/'runs/r-fixture/bundle/node';source.mkdir(parents=True)
        self.patch(migration,'SOURCE',source);self.patch(migration,'RUNS',source.parents[2])
        seal=source.parents[1]/'sealed.json';seal.write_text(json.dumps({'bundle':'a'*64,'login':1002,'group':1102}));seal.chmod(0o600)
        self.assertEqual(migration.management(self.request['legacy'],True),1002)
        with patch.dict(os.environ,{'SUDO_USER':'solv','SUDO_UID':'1001'}):
            with self.assertRaises(ValueError):migration.management(self.request['legacy'],False)
        with patch.dict(os.environ,{'SUDO_USER':'operator','SUDO_UID':'1002'}):
            self.assertEqual(migration.management(self.request['legacy'],False),1002)
        seal.write_text(json.dumps({'bundle':'a'*64,'login':1001,'group':1101}))
        with self.assertRaises(ValueError):migration.management(self.request['legacy'],True)

# unittest would also discover inherited methods; explicitly restrict this suite.
if __name__=='__main__':
    names=[name for name in Coordinator.__dict__ if name.startswith('test_')]
    result=unittest.TextTestRunner().run(unittest.TestSuite(Coordinator(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
