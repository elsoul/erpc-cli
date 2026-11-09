#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original ROOT/DATA UUID authority and stopped legacy upgrades, without mounts.

Uses actual state/history/controller paths and real temporary records. Only NSS,
process drain and kernel/filesystem observations are inert. This fixture is
independently authored from the failure mechanism, not a reviewer reproduction.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'erpc-chain-rollup/templates/scripts'))
import validator_history as history_fixture
import control
import history
import host
import state
import storage
import volumes


class Metadata:
    def __init__(self,original,device):self.original,self.st_dev=original,device
    def __getattr__(self,name):return getattr(self.original,name)


class Volumes(unittest.TestCase):
    def setUp(self):
        self.f=history_fixture.History('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.expected=self.f.expected;self.account=self.f.account
        self.root_uuid=self.expected['data_uuid'];self.data_uuid=self.expected['data_uuid']
        self.offset=0;self.separate=False;self.extra_mounts=[];self.race=False
        self.root_device=host.ROOT.stat().st_dev
        raw_stat,raw_lstat,raw_fstat=os.stat,os.lstat,os.fstat
        path_stat,path_lstat=Path.stat,Path.lstat
        def named(path,info):
            path=Path(os.fsdecode(path))
            if path==host.ROOT or host.ROOT in path.parents:
                extra=1000 if self.separate and (path==host.DATA or host.DATA in path.parents) else 0
                return Metadata(info,self.root_device+self.offset+extra)
            return info
        def associated(info):
            pending=[host.ROOT]
            while pending:
                path=pending.pop()
                try:current=raw_lstat(path)
                except FileNotFoundError:continue
                if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):return named(path,info)
                if stat.S_ISDIR(current.st_mode):
                    with os.scandir(path) as entries:pending.extend(Path(entry.path) for entry in entries)
            return info
        patch.object(Path,'stat',lambda path,*a,**kw:named(path,path_stat(path,*a,**kw))).start()
        patch.object(Path,'lstat',lambda path,*a,**kw:named(path,path_lstat(path,*a,**kw))).start()
        patch.object(os,'stat',lambda path,*a,**kw:associated(raw_stat(path,*a,**kw)) if isinstance(path,int) or kw.get('dir_fd') is not None else named(path,raw_stat(path,*a,**kw))).start()
        patch.object(os,'fstat',lambda fd:associated(raw_fstat(fd))).start()
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/findmnt':
                if '--submounts' in argv:
                    return json.dumps({'filesystems':[{'target':str(host.ROOT),'children':[{'target':str(host.DATA)},*self.extra_mounts]}]}).encode()
                selected=Path(argv[argv.index('--target')+1]);uuid=self.data_uuid if selected==host.DATA else self.root_uuid
                if self.race:self.offset+=1;self.race=False
                return json.dumps({'filesystems':[{'uuid':uuid,'fstype':'ext4','options':'rw'}]}).encode()
            raise AssertionError(argv)
        patch.object(host,'command',side_effect=command).start();self.command=command
        self.records={'node':self.account,'transport':self.account}
        patch.object(control.accounts,'verify',return_value=self.records).start()
        patch.object(control.Control,'retained',return_value=self.records).start()
        patch.object(control.Control,'quiet').start()
        self.stops=[]
        patch.object(control.Control,'shutdown',side_effect=lambda retain_history=True:self.stops.append(retain_history)).start()
        self.control_class=control.Control
        def selected(expected):
            controller=self.control_class(expected,run=self.command)
            controller.state=self.state
            return controller
        self.controller=selected(self.expected)
        patch.object(control,'Control',side_effect=selected).start()

    def legacy(self,separate=False):
        # Exact original pre-fix record shapes; the saved numeric observations
        # describe their creation, before the remount simulated by offset.
        self.separate=separate
        if separate:self.root_uuid='00000000-0000-0000-0000-000000000002'
        layout={'contract':self.expected,'root':{'device':self.root_device,'inode':host.ROOT.stat().st_ino},
                'data':{'device':self.root_device+(1000 if separate else 0),'inode':host.DATA.stat().st_ino}}
        self.state.put('storage-layout.json',layout)
        saved=self.state.get('data.json');saved['directory']=layout['data'];self.state.put('data.json',saved)
        self.state.put('owner.json',{'phase':'assertion-validator-v1','contract':self.expected})
        (self.state.root/volumes.NAME).unlink()
        current=history.inspect(self.account)
        for anchor in current['anchors']:anchor['device']=layout['data']['device']
        for record in current['databases'].values():record['device']=layout['data']['device']
        self.state.put('signer-activated.json',{'contract':self.expected,'account':self.account,
            'origin':self.f.origin,'history':current,'observer':self.f.observed})
        self.state.put('active.json',{'target':{'phase':'active','source':'inert original qualified image'},'generation':self.state.fence()['generation']})
        return {name:(self.state.root/name).read_bytes() for name in volumes.ORIGINALS if (self.state.root/name).exists()}

    def proof(self):
        return {'uuid':self.root_uuid,'fstype':'ext4','inode':host.ROOT.stat().st_ino,'record_sha256':'d'*64}

    def upgrade(self,proof=None):
        return control.dispatch({'action':'upgrade-volume-authority','contract':self.expected,'original_root':proof})

    def test_new_original_volumes_and_history_survive_only_kernel_number_changes(self):
        self.f.activate();self.offset=37
        history.verify(self.state,self.expected,self.account,self.f.quiet)
        history.retain(self.state,self.expected,self.account,self.f.quiet)
        self.assertNotIn('device',str(self.state.get('signer-activated.json')['history']))
        self.assertEqual(volumes.verify(self.state,self.expected)['root']['uuid'],self.root_uuid)

    def test_unupgraded_original_cannot_prepare_import_or_start_but_can_stop(self):
        self.legacy()
        original=(self.state.root/'owner.json').read_bytes()
        with self.assertRaises(ValueError):self.state.prepare(self.expected,'e'*32,{'phase':'observing'},lambda:None)
        with self.assertRaises(ValueError):self.state.pending(self.expected,'e'*32)
        with self.assertRaises(ValueError):self.state.start(self.expected,lambda _:None)
        stopped=[];self.state.stop(self.expected,lambda:stopped.append(True))
        self.assertEqual(stopped,[True]);self.assertEqual((self.state.root/'owner.json').read_bytes(),original)

    def test_same_filesystem_legacy_upgrade_preserves_exact_receipts_and_native_identity(self):
        old=self.legacy();self.offset=73
        with self.assertRaises(ValueError):history.verify(self.state,self.expected,self.account,self.f.quiet)
        result=self.upgrade()
        self.assertTrue(result['stopped']);self.assertFalse(result['runtime_started'])
        self.assertEqual(self.stops,[False]);self.assertTrue(self.state.fence()['stopped'])
        for name,raw in old.items():
            if name!='owner.json':self.assertEqual((self.state.root/name).read_bytes(),raw)
        origin=self.state.get(volumes.ORIGIN)
        for name,raw in old.items():self.assertEqual(origin['receipts'][name]['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.state.owner(self.expected)['phase'],'assertion-validator-v2')
        # The previous source required this exact v1 owner shape before dispatch.
        self.assertNotEqual(self.state.get('owner.json'),{'phase':'assertion-validator-v1','contract':self.expected})
        history.verify(self.state,self.expected,self.account,self.f.quiet)
        self.offset+=21;history.verify(self.state,self.expected,self.account,self.f.quiet)
        host.reserve_layout(self.state,self.expected,self.command)

    def test_separate_legacy_root_requires_independent_record_and_never_guesses_current_uuid(self):
        self.legacy(separate=True);self.offset=51
        with self.assertRaisesRegex(ValueError,'historical ROOT'):self.upgrade()
        self.assertFalse((self.state.root/volumes.NAME).exists())
        with self.assertRaises(ValueError):self.upgrade(dict(self.proof(),uuid=self.expected['data_uuid']))
        result=self.upgrade(self.proof());self.assertTrue(result['stopped'])
        original=self.state.get(volumes.ORIGIN)
        self.assertEqual(original['proof'],self.proof())
        self.offset+=91;history.verify(self.state,self.expected,self.account,self.f.quiet)

    def test_wrong_uuid_inode_and_nested_or_stacked_mounts_refuse_without_rebinding(self):
        self.f.activate();original=(self.state.root/volumes.NAME).read_bytes()
        for target in ('root','data'):
            old=getattr(self,target+'_uuid');setattr(self,target+'_uuid','00000000-0000-0000-0000-000000000003')
            with self.subTest(target=target),self.assertRaises(ValueError):history.verify(self.state,self.expected,self.account,self.f.quiet)
            setattr(self,target+'_uuid',old)
        for path in (host.ROOT,host.DATA,host.DATA/'chain',host.ROOT/'receipt-mount'):
            self.extra_mounts=[{'target':str(path)}]
            with self.subTest(path=path),self.assertRaises(ValueError):history.verify(self.state,self.expected,self.account,self.f.quiet)
        self.extra_mounts=[];self.race=True
        with self.assertRaises(ValueError):history.verify(self.state,self.expected,self.account,self.f.quiet)
        self.assertEqual((self.state.root/volumes.NAME).read_bytes(),original)
        directory=host.DATA/'chain/nitro/arbitrumdata';directory.rename(directory.with_name('retained-original'))
        directory.mkdir();(directory/'marker.manifest.000007.MANIFEST-000010').touch();(directory/'MANIFEST-000010').write_text('inert replacement')
        with self.assertRaises(ValueError):history.verify(self.state,self.expected,self.account,self.f.quiet)

    def test_original_manifest_floor_and_identity_hash_remain_required_after_upgrade(self):
        self.legacy();self.offset=11;self.upgrade()
        path=host.DATA/'chain/nitro/arbitrumdata'
        (path/'marker.manifest.000007.MANIFEST-000010').unlink()
        (path/'marker.manifest.000006.MANIFEST-000010').touch()
        with self.assertRaisesRegex(ValueError,'regressed'):history.verify(self.state,self.expected,self.account,self.f.quiet)
        (path/'marker.manifest.000006.MANIFEST-000010').unlink();(path/'marker.manifest.000007.MANIFEST-000010').touch()
        (host.DATA/'jwtsecret').write_text('inert replaced identity')
        with self.assertRaisesRegex(ValueError,'identities'):history.verify(self.state,self.expected,self.account,self.f.quiet)

    def test_original_hash_and_historical_scope_cannot_be_replaced_by_current_observations(self):
        self.legacy(separate=True);self.upgrade(self.proof())
        original=(self.state.root/volumes.NAME).read_bytes()
        value=self.state.get(volumes.NAME);value['root']['uuid']=self.data_uuid
        self.state.put(volumes.NAME,value)
        with self.assertRaises(ValueError):volumes.verify(self.state,self.expected)
        storage.write(self.state.root/volumes.NAME,original)
        origin=self.state.get(volumes.ORIGIN)
        origin['receipts']['data.json']['value']['directory']['inode']+=1
        self.state.put(volumes.ORIGIN,origin)
        with self.assertRaises(ValueError):volumes.verify(self.state,self.expected)

    def test_unknown_preexisting_volume_authority_is_never_overwritten(self):
        self.legacy();self.state.put(volumes.NAME,{'inert':'unrecognized authority'})
        original=(self.state.root/volumes.NAME).read_bytes()
        with self.assertRaises(ValueError):self.upgrade()
        self.assertEqual((self.state.root/volumes.NAME).read_bytes(),original)
        self.assertFalse((self.state.root/volumes.ORIGIN).exists())
        self.assertEqual(self.state.owner(self.expected)['phase'],'assertion-validator-v1')

    def test_persistent_directory_sync_failure_never_promotes_legacy_owner(self):
        self.legacy(separate=True);proof=self.proof();real=os.fsync
        inode=host.ROOT.stat().st_ino
        def failed(fd):
            if os.fstat(fd).st_ino==inode and (self.state.root/volumes.NAME).exists():raise OSError('inert post-volume directory sync failure')
            return real(fd)
        with patch.object(os,'fsync',failed):
            for _ in range(3):
                with self.assertRaises(OSError):self.upgrade(proof)
                self.assertEqual(self.state.owner(self.expected)['phase'],'assertion-validator-v1')
        self.assertEqual(self.upgrade(proof)['volume_authority'],'original')
        self.assertTrue(self.state.fence()['stopped']);self.assertGreaterEqual(len(self.stops),4)

    def test_interrupted_owner_promotion_reuses_the_exact_original_upgrade(self):
        self.legacy(separate=True);proof=self.proof();write=self.state.put;hit=[]
        def interrupted(name,value):
            write(name,value)
            if name=='owner.json' and not hit:hit.append(True);raise OSError('inert post-owner publication failure')
        with patch.object(self.state,'put',interrupted),self.assertRaises(OSError):self.upgrade(proof)
        origin=(self.state.root/volumes.ORIGIN).read_bytes();self.offset+=83
        self.assertTrue(self.upgrade(proof)['stopped'])
        self.assertEqual((self.state.root/volumes.ORIGIN).read_bytes(),origin)
        history.verify(self.state,self.expected,self.account,self.f.quiet)

    def test_source_scope_retirement_and_failed_drain_cannot_be_lifted_by_upgrade(self):
        self.legacy();self.state.stop(self.expected,lambda:None,retired=True)
        self.upgrade();self.assertTrue(self.state.fence()['retired'])
        with self.assertRaises(ValueError):self.state.start(self.expected,lambda _:None)
        with patch.object(self.control_class,'shutdown',side_effect=ValueError('inert drain failure')):
            with self.assertRaises(ValueError):self.upgrade()
        self.assertTrue(self.state.fence()['stopped'])
        before=len(self.stops)
        with self.assertRaises(ValueError):control.dispatch({'action':'upgrade-volume-authority','contract':dict(self.expected,owner='z'*26),'original_root':None})
        self.assertEqual(len(self.stops),before)


class FreshVolumes(unittest.TestCase):
    def test_actual_initialization_binds_separate_root_and_data_uuids_before_nss(self):
        import validator_host
        fixture=validator_host.Host('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.owned.mkdir(mode=0o755);fixture.data.mkdir(mode=0o700)
        fixture.mounts=[{'target':str(fixture.data)}]
        root_uuid='00000000-0000-0000-0000-000000000002'
        base=fixture.command
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/findmnt' and '--submounts' not in argv and argv[argv.index('--target')+1]==str(fixture.owned):
                return json.dumps({'filesystems':[{'uuid':root_uuid,'fstype':'ext4','options':'rw'}]}).encode()
            return base(argv,**kwargs)
        patch.object(fixture,'command',side_effect=command).start()
        offset=[0];device=fixture.owned.stat().st_dev
        raw_stat,raw_lstat,raw_fstat=os.stat,os.lstat,os.fstat
        path_stat,path_lstat=Path.stat,Path.lstat
        def named(path,info):
            path=Path(path)
            if path==fixture.owned or fixture.owned in path.parents:
                return Metadata(info,device+offset[0]+(1000 if path==fixture.data or fixture.data in path.parents else 0))
            return info
        def descriptor(fd):
            info=raw_fstat(fd);pending=[fixture.owned]
            while pending:
                path=pending.pop();current=raw_lstat(path)
                if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):return named(path,info)
                if stat.S_ISDIR(current.st_mode):
                    with os.scandir(path) as entries:pending.extend(Path(entry.path) for entry in entries)
            return info
        patch.object(Path,'stat',lambda path,*a,**kw:named(path,path_stat(path,*a,**kw))).start()
        patch.object(Path,'lstat',lambda path,*a,**kw:named(path,path_lstat(path,*a,**kw))).start()
        patch.object(os,'stat',lambda path,*a,**kw:raw_stat(path,*a,**kw) if isinstance(path,int) or kw.get('dir_fd') is not None else named(path,raw_stat(path,*a,**kw))).start()
        patch.object(os,'fstat',descriptor).start()
        self.assertTrue(fixture.initialize()['initialized'])
        current=state.State(fixture.owned);original=(fixture.owned/volumes.NAME).read_bytes()
        self.assertEqual(current.get(volumes.NAME)['root']['uuid'],root_uuid)
        self.assertEqual(current.get(volumes.NAME)['data']['uuid'],fixture.expected['data_uuid'] if hasattr(fixture,'expected') else fixture.contract['data_uuid'])
        self.assertEqual(len(fixture.fixture.calls),4)
        offset[0]=87
        self.assertTrue(fixture.initialize()['initialized'])
        self.assertEqual((fixture.owned/volumes.NAME).read_bytes(),original)
        self.assertEqual(len(fixture.fixture.calls),4)


if __name__=='__main__':unittest.main()
