# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual descriptor-relative directory operations; inert UID/process authority."""
import os
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import host_failures as fixture
common=fixture.common
state=fixture.state
control=fixture.control
setup=control.setup


class DataLayout(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.state=state.State(self.root)
        self.c={'owner':'inert-owner','network':'testnet'}
        self.state.put('owner.json',{'contract':self.c})
        self.uid,self.gid=995,995
        self.owners={};self.changes=[]
        self.real_fstat=os.fstat
        def metadata(fd):
            real=self.real_fstat(fd)
            if stat.S_ISDIR(real.st_mode):
                value=list(real);value[4],value[5]=self.owners.get((real.st_dev,real.st_ino),(0,0))
                return os.stat_result(value)
            return real
        def ownership(fd,uid,gid):
            value=self.real_fstat(fd);key=(value.st_dev,value.st_ino)
            self.owners[key]=(uid,gid);self.changes.append(key)
        self.patches=[]
        def install(obj,name,value):
            item=patch.object(obj,name,value);item.start();self.patches.append(item)
        self.addCleanup(lambda:[item.stop() for item in reversed(self.patches)])
        install(setup,'ROOT',self.root);install(setup,'owned_directory',lambda path:None)
        install(setup,'read',lambda path:common.read(path,owner=os.getuid()))
        install(state,'read',lambda path:common.read(path,owner=os.getuid()))
        install(os,'fstat',metadata);install(os,'fchown',ownership)
        self.fs_uuid='00000000-0000-0000-0000-000000000001'
        self.fs_type='ext4';self.fs_root='/';self.fs_options='rw,relatime';self.mounts=[]
        self.observations=[];self.mount_device=None
        def mounted(args,**kwargs):
            self.observations.append(args)
            self.assertEqual(args[:4],['/usr/bin/findmnt','--task','1','--json'])
            if '--list' in args:rows=[{'target':'/'},*({'target':str(path)} for path in self.mounts)]
            else:
                path=Path(args[args.index('--target')+1]);info=path.lstat()
                dev=info.st_dev if self.mount_device is None else self.mount_device
                rows=[{'uuid':self.fs_uuid,'fstype':self.fs_type,'fsroot':self.fs_root,
                    'options':self.fs_options,'maj:min':str(os.major(dev))+':'+str(os.minor(dev))}]
            return fixture.types.SimpleNamespace(stdout=json.dumps({'filesystems':rows}).encode())
        install(setup,'execute',mounted)

    def prepare(self):setup.prepare_data(self.state,self.c,self.uid,self.gid)

    def test_fresh_layout_retry_retains_existing_data_without_rechown_or_chmod(self):
        old=os.umask(0o077)
        try:self.prepare()
        finally:os.umask(old)
        self.assertEqual(len(self.changes),len(setup.DATA_LAYOUT))
        payload=self.root/'data/wal/original';payload.write_bytes(b'inert retained native data')
        before=payload.stat();count=len(self.changes)
        self.prepare()
        setup.verify_data(self.state,self.c,self.uid,self.gid)
        self.assertEqual(len(self.changes),count)
        self.assertEqual(payload.read_bytes(),b'inert retained native data')
        self.assertEqual(payload.stat().st_ino,before.st_ino)
        for relative in setup.DATA_LAYOUT:
            self.assertEqual(stat.S_IMODE((self.root/relative).stat().st_mode),0o700)

    def test_linked_native_child_never_changes_an_unrelated_directory(self):
        self.prepare()
        for relative in ('data/ledger/headers','data/wal'):
            path=self.root/relative;path.rmdir()
            outside=self.root/('outside-'+path.name);outside.mkdir(mode=0o755)
            original=outside.stat();path.symlink_to(outside)
            before=len(self.changes)
            with self.assertRaises(OSError):self.prepare()
            self.assertEqual(outside.stat().st_mode,original.st_mode)
            self.assertEqual(list(outside.iterdir()),[]);self.assertEqual(len(self.changes),before)
            path.unlink();path.mkdir(mode=0o700)
            info=path.stat();self.owners[(info.st_dev,info.st_ino)]=(self.uid,self.gid)
        # A ledger-level redirect is rejected before creating headers or bodies.
        ledger=self.root/'data/ledger'
        for path in ledger.iterdir():path.rmdir()
        ledger.rmdir();outside=self.root/'outside-ledger';outside.mkdir(mode=0o755)
        ledger.symlink_to(outside)
        with self.assertRaises(OSError):self.prepare()
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode),0o755)
        self.assertEqual(list(outside.iterdir()),[])

    def test_foreign_scope_unreceipted_data_and_missing_established_history_refuse(self):
        with self.assertRaises(ValueError):setup.prepare_data(self.state,dict(self.c,network='mainnet'),self.uid,self.gid)
        data=self.root/'data';data.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'unreceipted'):self.prepare()
        self.assertFalse((self.root/'data-preparing.json').exists());data.rmdir()
        self.prepare();(data/'wal').rmdir()
        with self.assertRaisesRegex(ValueError,'recreation'):self.prepare()
        self.assertFalse((data/'wal').exists())

    def test_interrupted_empty_mkdir_recovers_only_original_durable_intent(self):
        with patch.object(os,'fchown',side_effect=OSError('inert interrupted first directory')):
            with self.assertRaises(OSError):self.prepare()
        self.assertTrue((self.root/'data-preparing.json').exists())
        self.assertFalse((self.root/'data-ready.json').exists())
        extra=self.root/'data/foreign';extra.write_bytes(b'retain unknown bytes')
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(extra.read_bytes(),b'retain unknown bytes');extra.unlink()
        self.prepare()
        self.assertTrue((self.root/'data-ready.json').exists())

    def test_visible_intent_requires_durability_before_any_mkdir(self):
        real=self.state.put
        def ambiguous(name,value):
            real(name,value)
            if name=='data-preparing.json':raise OSError('inert post-publication failure')
        with patch.object(self.state,'put',ambiguous),self.assertRaises(OSError):self.prepare()
        with patch.object(os,'fsync',side_effect=OSError('inert persistent storage failure')):
            with self.assertRaises(OSError):self.prepare()
        self.assertFalse((self.root/'data').exists());self.assertEqual(self.changes,[])
        self.prepare()

    def test_only_unused_initial_layout_can_bind_a_clean_replacement_filesystem(self):
        setup.prepare_data(self.state,self.c,self.uid,self.gid,final=False)
        old=self.state.get('data-ready.json')
        data=self.root/'data';data.rename(self.root/'initial-layout');data.mkdir(mode=0o755)
        lost=data/'lost+found';lost.mkdir(mode=0o700)
        original_lstat=Path.lstat
        def metadata(path,*args,**kwargs):
            raw=original_lstat(path,*args,**kwargs);values=list(raw)
            if stat.S_ISDIR(raw.st_mode):values[4],values[5]=self.owners.get((raw.st_dev,raw.st_ino),(0,0))
            return os.stat_result(values)
        with patch.object(Path,'lstat',metadata):
            foreign=data/'unowned';foreign.write_bytes(b'retain')
            with self.assertRaisesRegex(ValueError,'unowned'):self.prepare()
            self.assertEqual(foreign.read_bytes(),b'retain');foreign.unlink()
            with patch.object(os,'fchown',side_effect=OSError('inert failed mount owner transition')):
                with self.assertRaises(OSError):self.prepare()
            self.assertEqual(stat.S_IMODE(data.stat().st_mode),0o700)
            self.assertEqual(self.state.get('data-ready.json'),old)
            self.prepare()
            new=self.state.get('data-ready.json')
            self.assertTrue(new['final']);self.assertNotEqual(old['binding'],new['binding'])
            setup.verify_data(self.state,self.c,self.uid,self.gid)
            self.assertEqual(list(lost.iterdir()),[])
            data.rename(self.root/'selected-layout');data.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError,'filesystem changed'):self.prepare()
            with self.assertRaises(ValueError):setup.verify_data(self.state,self.c,self.uid,self.gid)
            self.assertEqual(list(data.iterdir()),[])
            self.assertEqual(stat.S_IMODE(data.stat().st_mode),0o755)

    def test_started_initialization_forbids_provisional_filesystem_substitution(self):
        setup.prepare_data(self.state,self.c,self.uid,self.gid,final=False)
        (self.root/'data').rename(self.root/'initial-layout');(self.root/'data').mkdir(mode=0o755)
        self.state.put('device-initializing.json',{'inert':'first native write was attempted'})
        with self.assertRaisesRegex(ValueError,'filesystem changed'):self.prepare()
        self.assertFalse((self.root/'data-mount-preparing.json').exists())

    def test_nested_storage_device_refuses_before_mutation_and_on_startup(self):
        self.prepare();inode=(self.root/'data/ledger').stat().st_ino
        original=os.fstat
        def changed(fd):
            raw=original(fd)
            if raw.st_ino==inode:
                values=list(raw);values[2]=raw.st_dev+1;return os.stat_result(values)
            return raw
        count=len(self.changes)
        with patch.object(os,'fstat',changed):
            with self.assertRaisesRegex(ValueError,'filesystem differs'):self.prepare()
            with self.assertRaisesRegex(ValueError,'filesystem differs'):setup.verify_data(self.state,self.c,self.uid,self.gid)
        self.assertEqual(len(self.changes),count)

    def test_reboot_device_renumbering_preserves_data_and_actual_startup_qualification(self):
        self.c['role']='rpc';self.state.put('owner.json',{'contract':self.c});self.prepare()
        payload=self.root/'data/wal/history';payload.write_bytes(b'inert original consensus history')
        saved=(self.root/'data-ready.json').read_bytes();changes=len(self.changes)
        before_stat=Path.lstat;before_fd=os.fstat
        def renumber(value):
            if stat.S_ISDIR(value.st_mode):
                fields=list(value);fields[2]=os.makedev(79,23);return os.stat_result(fields)
            return value
        with patch.object(Path,'lstat',lambda path,*args,**kw:renumber(before_stat(path,*args,**kw))), \
             patch.object(os,'fstat',lambda fd:renumber(before_fd(fd))):
            self.prepare();setup.verify_data(self.state,self.c,self.uid,self.gid)
            self.state.put('device-initialized.json',{'inert':'raw execution authority is independent'})
            installed={'receipt':{'configuration':{}}}
            with patch.object(control,'ROOT',self.root),patch.object(control,'STATE',self.state), \
                 patch.object(control,'paths'),patch.object(self.state,'guard',return_value=installed), \
                 patch.object(control,'account',return_value=fixture.types.SimpleNamespace(pw_uid=self.uid,pw_gid=self.gid)), \
                 patch.object(control,'inspect_device'),patch.object(control,'device_access'), \
                 patch.object(control,'capacity'),patch.object(control,'qualify_native'), \
                 patch.object(control,'read_identity'),patch.object(setup,'admitted_keys',return_value=False), \
                 patch.object(control,'firewall'):
                self.assertEqual(control.check_ready(self.c),installed)
                self.fs_uuid='00000000-0000-0000-0000-000000000002'
                with self.assertRaises(ValueError):control.check_ready(self.c)
        self.assertEqual((self.root/'data-ready.json').read_bytes(),saved)
        self.assertEqual(len(self.changes),changes);self.assertEqual(payload.read_bytes(),b'inert original consensus history')
        self.assertEqual(set(self.state.get('data-ready.json')['binding']),{'uuid','filesystem','filesystem_root','inode'})

    def test_current_mount_metadata_and_same_device_bind_subtrees_fail_before_mutation(self):
        self.prepare();saved=(self.root/'data-ready.json').read_bytes();changes=len(self.changes)
        cases=[('fs_uuid',None),('fs_type','tmpfs'),('fs_root','/other-data'),('fs_options','ro'),
               ('mount_device',self.root.stat().st_dev+1),('mounts',[self.root/'data/wal']),
               ('mounts',[self.root/'data',self.root/'data'])]
        for name,value in cases:
            previous=getattr(self,name);setattr(self,name,value)
            with self.subTest(name=name),self.assertRaises(ValueError):self.prepare()
            with self.subTest(name=name),self.assertRaises(ValueError):setup.verify_data(self.state,self.c,self.uid,self.gid)
            setattr(self,name,previous)
        self.assertEqual(len(self.changes),changes);self.assertEqual((self.root/'data-ready.json').read_bytes(),saved)

    def test_initial_intent_retains_filesystem_before_first_ownership_change(self):
        with patch.object(os,'fchown',side_effect=OSError('inert lost ownership mutation')):
            with self.assertRaises(OSError):self.prepare()
        pending=(self.root/'data-preparing.json').read_bytes();self.fs_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaisesRegex(ValueError,'original filesystem'):self.prepare()
        self.assertFalse((self.root/'data-ready.json').exists());self.assertEqual(self.changes,[])
        self.assertEqual((self.root/'data-preparing.json').read_bytes(),pending)

    def test_legacy_device_only_receipt_never_silently_adopts_uuid_but_owned_stop_is_available(self):
        self.prepare();legacy=self.state.get('data-ready.json');legacy.pop('format')
        legacy['binding']={'device':(self.root/'data').stat().st_dev,'inode':(self.root/'data').stat().st_ino}
        self.state.put('data-ready.json',legacy);before=(self.root/'data-ready.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'legacy'):self.prepare()
        with self.assertRaisesRegex(ValueError,'legacy'):setup.verify_data(self.state,self.c,self.uid,self.gid)
        with patch.object(control,'ROOT',self.root),patch.object(control,'STATE',self.state), \
             patch.object(control,'contract',lambda value:value),patch.object(control.namespace,'paths'), \
             patch.object(control,'stop_native') as shutdown,patch.object(setup,'execute',side_effect=AssertionError('stop must not probe storage')):
            self.assertTrue(control.dispatch({'contract':self.c,'operation':'stop'})['stopped'])
            shutdown.assert_called_once_with(retire=False)
            with self.assertRaises(ValueError):control.dispatch({'contract':dict(self.c,network='foreign'),'operation':'stop'})
            self.assertEqual(shutdown.call_count,1)
        self.assertEqual((self.root/'data-ready.json').read_bytes(),before)

    def legacy(self,final=True):
        setup.prepare_data(self.state,self.c,self.uid,self.gid,final=final)
        original=self.state.get('data-ready.json');original.pop('format')
        original['binding']={'device':123,'inode':(self.root/'data').stat().st_ino}
        self.state.put('data-ready.json',original)
        self.state.cancel(self.c,False,lambda:None)
        return (self.root/'data-ready.json').read_bytes()

    def recover(self,identifier=None):
        with patch.object(control,'ROOT',self.root),patch.object(control,'STATE',self.state), \
             patch.object(control,'contract',lambda value:value),patch.object(control.namespace,'paths'), \
             patch.object(control,'quiescent') as quiet, \
             patch.object(control,'account',return_value=fixture.types.SimpleNamespace(pw_uid=self.uid,pw_gid=self.gid)):
            result=control.dispatch({'contract':self.c,'operation':'recover-data-filesystem',
                'original_uuid':identifier or self.fs_uuid})
            quiet.assert_called_once();return result

    def test_explicit_uuid_upgrade_retains_exact_original_receipt_histories_and_release_floors(self):
        import base64
        original=self.legacy();self.state.put('installed.json',{'original_version':'future-reviewed-native'})
        self.state.put('device-initialized.json',{'original_partuuid':'independent-raw-partition'})
        payload=self.root/'data/wal/history';payload.write_bytes(b'original mutable history')
        unchanged={name:(self.root/name).read_bytes() for name in
            ('owner.json','installed.json','device-initialized.json','operation.json','data/wal/history')}
        count=len(self.changes)
        result=self.recover();self.assertTrue(result['stopped']);self.assertTrue(result['history_preserved'])
        record=self.state.get('data-identity-upgrade.json')
        self.assertEqual(base64.b64decode(record['original_receipt']),original)
        self.assertEqual(record['original_sha256'],common.digest(original))
        self.assertEqual(record['upgraded'],self.state.get('data-ready.json'))
        self.assertTrue((self.root/'stopped').exists());self.assertEqual(len(self.changes),count)
        self.recover();setup.verify_data(self.state,self.c,self.uid,self.gid)
        self.assertEqual({name:(self.root/name).read_bytes() for name in unchanged},unchanged)

    def test_uuid_upgrade_rejects_wrong_original_input_and_missing_or_changed_directory(self):
        self.legacy();before=(self.root/'data-ready.json').read_bytes()
        for identifier in ('invented','00000000-0000-0000-0000-000000000002'):
            with self.assertRaises(ValueError):self.recover(identifier)
        self.assertFalse((self.root/'data-identity-upgrade.json').exists())
        old=self.state.get('data-ready.json');old['binding']['inode']+=1;self.state.put('data-ready.json',old)
        with self.assertRaisesRegex(ValueError,'inode'):self.recover()
        (self.root/'data-ready.json').write_bytes(before)
        (self.root/'data/wal').rmdir()
        with self.assertRaises(FileNotFoundError):self.recover()
        self.assertFalse((self.root/'data/wal').exists())
        self.assertEqual((self.root/'data-ready.json').read_bytes(),before)

    def test_upgrade_requires_durable_stop_and_quiescence_before_publishing(self):
        self.legacy();(self.root/'stopped').unlink()
        with self.assertRaisesRegex(ValueError,'stop'):self.recover()
        self.assertFalse((self.root/'data-identity-upgrade.json').exists())
        self.state.marker('stopped')
        with patch.object(control,'ROOT',self.root),patch.object(control,'STATE',self.state), \
             patch.object(control,'contract',lambda value:value),patch.object(control.namespace,'paths'), \
             patch.object(control,'quiescent',side_effect=ValueError('inert original writer')):
            with self.assertRaisesRegex(ValueError,'writer'):
                control.dispatch({'contract':self.c,'operation':'recover-data-filesystem','original_uuid':self.fs_uuid})
        self.assertFalse((self.root/'data-identity-upgrade.json').exists())

    def test_interrupted_upgrade_retries_only_original_uuid_without_resetting_provisional_selection(self):
        original=self.legacy(final=False);write=self.state.put
        def ambiguous(name,value):
            write(name,value)
            if name=='data-identity-upgrade.json':raise OSError('inert lost durable upgrade acknowledgement')
        with patch.object(self.state,'put',side_effect=ambiguous),self.assertRaises(OSError):self.recover()
        self.assertEqual((self.root/'data-ready.json').read_bytes(),original)
        self.fs_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaisesRegex(ValueError,'another original'):self.recover()
        self.fs_uuid='00000000-0000-0000-0000-000000000001'
        self.recover();self.recover()
        self.assertFalse(self.state.get('data-ready.json')['final'])
        with self.assertRaises(ValueError):setup.verify_data(self.state,self.c,self.uid,self.gid)
        self.prepare();setup.verify_data(self.state,self.c,self.uid,self.gid)

    def test_real_dispatch_checks_scope_intent_and_quiescence_before_data_preparation(self):
        target={key:control.CATALOG[key] for key in ('version','consensus_commit','execution_commit')}
        request={'operation':'prepare-data','contract':self.c,'target':target,'initial':True}
        with patch.object(control,'ROOT',self.root),patch.object(control,'STATE',self.state),\
             patch.object(control,'contract',lambda value:value),patch.object(control,'paths'),\
             patch.object(control.namespace,'paths'),patch.object(control,'quiescent') as quiet,\
             patch.object(control,'account',return_value=fixture.types.SimpleNamespace(pw_uid=self.uid,pw_gid=self.gid)):
            with self.assertRaises(ValueError):control.dispatch(dict(request,contract=dict(self.c,network='mainnet')))
            quiet.assert_not_called()
            quiet.side_effect=ValueError('inert surviving original writer')
            with self.assertRaisesRegex(ValueError,'writer'):control.dispatch(request)
            self.assertFalse((self.root/'data-preparing.json').exists())
            quiet.side_effect=None
            with self.assertRaises(FileNotFoundError):control.dispatch(dict(request,initial=False,intent='a'*32))
            self.assertTrue(control.dispatch(request)['native_data_prepared'])
            self.assertTrue((self.root/'data-ready.json').exists())


if __name__=='__main__':unittest.main()
