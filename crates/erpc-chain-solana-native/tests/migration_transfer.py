# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real three-volume payload copies; authority/mount/NSS observations are inert."""
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
import native_files
import native_migration_transfer as transfer


class MigrationTransfer(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.parent=self.root/'mnt';self.parent.mkdir(mode=0o700)
        self.store=self.root/'original';self.store.mkdir(mode=0o700)
        self.uid,self.gid=os.getuid() or 1,os.getgid() or 1
        self.targets={};self.sources={};self.volumes={};self.storage={};self.target_records={}
        self.allowed=True;self.writer=False
        for index,kind in enumerate(('accounts','ledger','snapshots'),1):
            source=self.parent/('snapshot' if kind=='snapshots' else kind);source.mkdir(mode=0o700)
            (source/'payload.bin').write_bytes(('inert original '+kind+' bytes\n').encode());(source/'payload.bin').chmod(0o600)
            if os.getuid()==0:
                os.chown(source,self.uid,self.gid);os.chown(source/'payload.bin',self.uid,self.gid)
            target=self.parent/('erpc-solana-'+kind);target.mkdir(mode=0o700)
            self.sources[kind]=source;self.targets[kind]=target
            self.volumes[kind]='20000000-0000-0000-0000-00000000000'+str(index)
            self.storage[kind]={'uuid':'10000000-0000-0000-0000-00000000000'+str(index),'inode':source.stat().st_ino}
            self.target_records[kind]={'uuid':self.volumes[kind],'inode':target.stat().st_ino,'fs':'ext4'}
        self.scope={'intent':'a'*32,'contract':{'volumes':self.volumes},
            'legacy':{'historical':{'uid':self.uid,'gid':self.gid},'source_history':{'document_sha256':'b'*64}}}
        self.observation={'storage':self.storage,'copy_preflight':{'targets':self.target_records}}
        self.operation=SimpleNamespace(binding=self.scope,manager_uid=2002,saved=self.saved,
            fence=lambda _:SimpleNamespace(saved=lambda:{'phase':'retired'},unit=self.mask),
            revoker=lambda _:SimpleNamespace(verify=self.revoked),run=self.command)
        self.worker=transfer.Transfer(self.operation)
        self.original= {kind:(path/'payload.bin').read_bytes() for kind,path in self.sources.items()}
        def trusted(path,create=False,mode=0o755):
            self.assertTrue(path==self.root or self.root in path.parents)
            if create:path.mkdir(exist_ok=True,mode=mode)
            info=path.lstat();transfer.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022,'unsafe fixture root')
        for name,value in [('ROOT_UID',os.getuid()),('ROOT_GID',os.getgid()),('PARENT',self.parent),('root_directory',trusted),
                           ('sync_file',lambda p,owner=0:native_files.sync_file(p,os.getuid()))]:self.patch(transfer,name,value)
        self.patch(transfer.retirement,'STORE',self.store);self.patch(transfer.legacy,'ROOT',self.root)
        self.patch(transfer.mounts,'MOUNTS',self.targets)
        self.patch(transfer.mounts,'inspect_volumes',lambda volumes:self.mounts(volumes))
        self.patch(transfer.shutil,'disk_usage',lambda _:SimpleNamespace(total=2_000_000_000_000,free=1_000_000_000_000))
        self.patch(transfer.retirement,'original_quiescent',lambda uid:transfer.require(not self.writer and uid==self.uid,'original account writer remains'))
        self.patch(transfer.copying,'ROOT_UID',os.getuid())
        ancestors={(p.stat().st_dev,p.stat().st_ino) for p in self.root.parents};real=os.fstat
        def metadata(fd):
            info=real(fd)
            if stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino) in ancestors:
                values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')};values['st_mode']&=~0o022
                return SimpleNamespace(**values)
            return info
        self.patch(os,'fstat',metadata)
        # Constructor captured the original store before the fixture path patch.
        self.worker=transfer.Transfer(self.operation)
        native_files.atomic(self.store/'manager-confirmed.json',native_files.encoded({'binding_sha256':self.worker.binding,'manager_uid':2002}))
    def patch(self,target,name,value):
        item=patch.object(target,name,value);item.start();self.addCleanup(item.stop)
    def saved(self):
        transfer.require(self.allowed,'original scope changed');return {'observation':self.observation}
    def mask(self):transfer.require(self.allowed,'original mask changed');return 'masked'
    def revoked(self):transfer.require(self.allowed,'original privileges changed');return {'phase':'revoked'}
    def mounts(self,volumes):
        self.assertEqual(volumes,self.volumes)
        return {kind:dict(record,free_bytes=1_000_000_000_000,total_bytes=2_000_000_000_000) for kind,record in self.target_records.items()}
    def command(self,args):
        self.assertEqual(args[0],'/usr/bin/du');return '4096\t'+args[-1]+'\n'
    def retained(self):
        for kind,path in self.sources.items():
            self.assertEqual((path/'payload.bin').read_bytes(),self.original[kind]);self.assertEqual(path.stat().st_uid,self.uid)
    def test_actual_three_copies_keep_original_bytes_private_and_are_idempotent(self):
        first=self.worker.copy();self.assertEqual(self.worker.copy(),first)
        self.assertFalse(first['runtime_started']);self.assertFalse(first['native_data_promoted']);self.retained()
        for kind,path in self.targets.items():
            payload=path/('.erpc-migration-'+self.scope['intent'])/'payload/payload.bin'
            self.assertEqual(payload.read_bytes(),self.original[kind]);self.assertEqual(payload.stat().st_mode&0o7777,0o600)
            self.assertFalse((path/'data').exists())
    def test_foreign_target_uuid_inode_or_unrecorded_content_never_changes_source(self):
        self.target_records['ledger']['inode']+=1
        with self.assertRaises(ValueError):self.worker.copy()
        self.retained();self.target_records['ledger']['inode']-=1
        unknown=self.targets['ledger']/'unknown';unknown.write_bytes(b'retain foreign bytes')
        with self.assertRaises(ValueError):self.worker.copy()
        self.assertEqual(unknown.read_bytes(),b'retain foreign bytes');self.retained()
    def test_no_copy_without_confirmed_manager_or_when_original_writer_returns(self):
        marker=self.store/'manager-confirmed.json';raw=marker.read_bytes();marker.unlink()
        with self.assertRaises(FileNotFoundError):self.worker.copy()
        self.assertFalse(self.worker.directory.exists());self.retained()
        native_files.atomic(marker,raw);self.writer=True
        with self.assertRaises(ValueError):self.worker.copy()
        self.retained()
    def test_interrupted_stream_uses_original_staging_only(self):
        real=os.write
        def lost(fd,raw):real(fd,raw);raise OSError('inert stream reply lost')
        with patch.object(os,'write',lost),self.assertRaises(OSError):self.worker.copy()
        self.retained();self.assertTrue(self.worker.copy()['copied']);self.retained()
    def test_each_setup_and_completion_directory_barrier_can_resume_same_copy(self):
        real=os.fsync;points=[]
        def selected(fd):
            info=os.fstat(fd)
            # The copier has its own exhaustive file/link barrier suite. Here
            # exhaust new ancestor/staging/coordinator-directory barriers.
            return stat.S_ISDIR(info.st_mode) and info.st_ino in {p.stat().st_ino for p in
                [self.parent,self.store,self.worker.directory,*self.targets.values()] if p.exists()}
        def record(fd):
            if selected(fd):points.append(True)
            return real(fd)
        with patch.object(os,'fsync',record):self.worker.copy()
        for position in range(len(points)):
            fixture=MigrationTransfer('runTest');fixture.setUp()
            try:
                seen=[]
                def fail(fd):
                    info=os.fstat(fd);paths=[fixture.parent,fixture.store,fixture.worker.directory,*fixture.targets.values()]
                    if stat.S_ISDIR(info.st_mode) and info.st_ino in {p.stat().st_ino for p in paths if p.exists()}:
                        index=len(seen);seen.append(True)
                        if index==position:raise OSError('inert setup persistence failure')
                    return real(fd)
                with patch.object(os,'fsync',fail),self.assertRaises(OSError):fixture.worker.copy()
                fixture.retained();self.assertTrue(fixture.worker.copy()['copied']);fixture.retained()
            finally:fixture.doCleanups()
        print(str(len(points))+' composed copy ancestor/staging barriers retried')

if __name__=='__main__':unittest.main()
