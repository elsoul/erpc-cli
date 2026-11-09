# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fresh original volumes and remount-safe identity; no actual mount/chown/NSS."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).parent))
import accounts
c = accounts.c


class Metadata:
    def __init__(self, original, **changes): self.original=original; self.__dict__.update(changes)
    def __getattr__(self, name): return getattr(self.original,name)


class Volumes(unittest.TestCase):
    def setUp(self):
        self.fixture = accounts.Accounts('runTest'); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        patch.object(c,'ROOT',c.ROOT.parent/'volume').start(); c.ROOT.mkdir(mode=0o755)
        self.state = dict(c.contract(self.fixture.state),phase='prepared')
        self.root_uuid='00000000-0000-0000-0000-000000000001'
        self.data_uuid=self.root_uuid
        self.offset=0; self.separate=False; self.owner=None; self.extra=[]
        raw_lstat,raw_stat,raw_fstat=os.lstat,os.stat,os.fstat
        self.raw_lstat=raw_lstat
        def change(path, info):
            data = c.ROOT/'data'
            if path==c.ROOT or c.ROOT in path.parents:
                extra = 1000 if self.separate and (path==data or data in path.parents) else 0
                fields={'st_dev':info.st_dev+self.offset+extra}
                if path==data and self.owner is not None:
                    fields.update(st_uid=self.owner[0],st_gid=self.owner[1])
                return Metadata(info,**fields)
            return info
        def named(path, info):
            return change(Path(os.fsdecode(path)),info)
        def descriptor(info):
            for path in [c.ROOT,*c.ROOT.rglob('*')]:
                try: existing=raw_lstat(path)
                except FileNotFoundError: continue
                if (existing.st_dev,existing.st_ino)==(info.st_dev,info.st_ino): return change(path,info)
            return info
        patch.object(os,'lstat',side_effect=lambda path,*a,**kw:named(path,raw_lstat(path,*a,**kw))).start()
        patch.object(os,'stat',side_effect=lambda path,*a,**kw:descriptor(raw_stat(path,*a,**kw)) if isinstance(path,int) else named(path,raw_stat(path,*a,**kw))).start()
        patch.object(os,'fstat',side_effect=lambda fd:descriptor(raw_fstat(fd))).start()
        patch.object(Path,'lstat',lambda path:named(path,raw_lstat(path))).start()
        patch.object(Path,'stat',lambda path,*,follow_symlinks=True:named(path,raw_stat(path,follow_symlinks=follow_symlinks))).start()
        def ownership(fd,uid,gid):
            info=raw_fstat(fd); data=raw_lstat(c.ROOT/'data')
            assert (info.st_dev,info.st_ino)==(data.st_dev,data.st_ino)
            self.owner=(uid,gid)
        self.ownership=ownership
        patch.object(os,'fchown',side_effect=ownership).start()
        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/findmnt':
                if '--submounts' in argv:
                    return json.dumps({'filesystems':[{'target':str(c.ROOT),
                        'children':[{'target':str(c.ROOT/'data')},*self.extra]}]}).encode()
                path=Path(argv[argv.index('--target')+1])
                value=self.data_uuid if path==c.ROOT/'data' else self.root_uuid
                return json.dumps({'filesystems':[{'uuid':value,'fstype':'ext4','options':'rw'}]}).encode()
            return self.fixture.command(argv,**kwargs)
        patch.object(c,'run',side_effect=command).start()

    def reserve(self):
        self.state['layout']=c.initial_layout()
        c.save(self.state)
        return c.account_ensure(self.state)

    def test_fresh_premounted_root_data_and_empty_recovery_directories_are_retained(self):
        (c.ROOT/'lost+found').mkdir(mode=0o700)
        data=c.ROOT/'data'; data.mkdir(mode=0o755); (data/'lost+found').mkdir(mode=0o700)
        self.separate=True; self.data_uuid='00000000-0000-0000-0000-000000000002'
        identity={str(path):path.stat().st_ino for path in (c.ROOT,c.ROOT/'lost+found',data,data/'lost+found')}
        record=self.reserve(); c.prepare_data(self.state,record)
        c.verified_data(self.state,record)
        self.assertEqual(data.stat().st_mode&0o7777,0o700)
        for path,inode in identity.items(): self.assertEqual(Path(path).stat().st_ino,inode)
        self.assertEqual(self.state['layout']['data']['uuid'],self.data_uuid)

    def test_current_device_numbers_can_change_but_original_uuid_or_inode_cannot(self):
        record=self.reserve(); c.prepare_data(self.state,record)
        original=copy.deepcopy(self.state['layout'])
        self.offset=5000
        c.verified_data(self.state,record)
        self.assertEqual(self.state['layout'],original)
        self.data_uuid='00000000-0000-0000-0000-000000000003'
        with self.assertRaises(c.Refused): c.verified_data(self.state,record)
        self.data_uuid=self.root_uuid
        (c.ROOT/'data').rename(c.ROOT/'retained-data'); (c.ROOT/'data').mkdir(mode=0o700)
        with self.assertRaises(c.Refused): c.verified_data(self.state,record)
        self.assertTrue((c.ROOT/'retained-data').exists())

    def test_nested_and_stacked_mounts_are_refused_even_on_the_same_device(self):
        record=self.reserve(); c.prepare_data(self.state,record)
        for path in (c.ROOT,c.ROOT/'data',c.ROOT/'data/blocks',c.ROOT/'unknown-mount'):
            self.extra=[{'target':str(path)}]
            with self.assertRaises(c.Refused): c.verified_data(self.state,record)

    def test_interrupted_descriptor_ownership_reuses_the_original_inode(self):
        record=self.reserve()
        def interrupted(fd,uid,gid):
            self.ownership(fd,uid,gid)
            raise OSError('inert ownership interruption')
        with patch.object(os,'fchown',side_effect=interrupted), self.assertRaises(OSError):
            c.prepare_data(self.state,record)
        saved=c.read_state(); inode=saved['layout']['data_inode']
        self.assertFalse(saved.get('data_ready',False))
        self.offset=9000
        c.prepare_data(saved,record)
        self.assertEqual(saved['layout']['data_inode'],inode)
        c.verified_data(saved,record)

    def test_unknown_recovery_data_and_links_are_not_adopted_or_removed(self):
        directory=c.ROOT/'lost+found'; directory.mkdir(mode=0o700)
        saved=directory/'recovered'; saved.write_bytes(b'inert recovered content')
        with self.assertRaises(c.Refused): c.initial_layout()
        self.assertEqual(saved.read_bytes(),b'inert recovered content')
        saved.unlink(); directory.rmdir(); directory.symlink_to(c.ROOT)
        with self.assertRaises(c.Refused): c.initial_layout()
        self.assertTrue(directory.is_symlink())
        self.assertEqual(self.fixture.calls,[])


if __name__=='__main__': unittest.main()
