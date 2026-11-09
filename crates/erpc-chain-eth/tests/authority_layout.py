# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-relative native layout fixtures; no actual chown, mounts or native process."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_accounts as accounts
import eth_layout as layout


class Layout(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Accounts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.state=f.state;self.contract=f.c;self.plan=accounts.provision(self.state,'validator')
        self.data=f.root/'native';f.install(layout,'ROOTS',{'validator':self.data})
        original=os.fstat;owners=self.owners={};self.changes=[]
        def metadata(fd):
            value=list(original(fd));key=(value[2],value[1])
            if key in owners:value[4],value[5]=owners[key]
            return os.stat_result(value)
        def change(fd,uid,gid):
            info=original(fd);fixtures.hold(self,fd);owners[(info.st_dev,info.st_ino)]=(uid,gid);self.changes.append((info.st_ino,uid,gid))
        f.install(os,'fstat',metadata);f.install(os,'fchown',change)

    def test_new_private_layout_is_bound_once_and_startup_never_recreates_loss(self):
        layout.prepare(self.state,self.contract,self.plan);record=self.state.get('layout.json')
        self.assertEqual(len(self.changes),3);layout.verify(self.state,self.contract,self.plan)
        layout.prepare(self.state,self.contract,self.plan);self.assertEqual(len(self.changes),3)
        self.assertEqual(self.state.get('layout.json'),record)
        (self.data/'vc').rmdir()
        with self.assertRaises(OSError):layout.prepare(self.state,self.contract,self.plan)
        self.assertFalse((self.data/'vc').exists());self.assertEqual(len(self.changes),3)

    def test_unowned_and_established_symlinks_never_change_an_outside_directory(self):
        outside=self.fixture.root/'outside';outside.mkdir(mode=0o755);(outside/'sentinel').write_text('retained')
        self.data.mkdir(mode=0o755);(self.data/'vc').symlink_to(outside)
        with self.assertRaises(ValueError):layout.prepare(self.state,self.contract,self.plan)
        self.assertEqual(self.changes,[]);self.assertEqual(outside.stat().st_mode&0o777,0o755)
        (self.data/'vc').unlink();layout.prepare(self.state,self.contract,self.plan);before=len(self.changes)
        (self.data/'vc').rmdir();(self.data/'vc').symlink_to(outside)
        with self.assertRaises(OSError):layout.verify(self.state,self.contract,self.plan)
        with self.assertRaises(OSError):layout.prepare(self.state,self.contract,self.plan)
        self.assertEqual(len(self.changes),before);self.assertEqual((outside/'sentinel').read_text(),'retained')

    def test_visible_intent_resync_failure_prevents_any_native_identity_publication(self):
        self.data.mkdir(mode=0o755)
        original=os.fsync
        def failed(fd):
            if self.state.exists('layout-intent.json'):raise OSError('inert pending sync failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):layout.prepare(self.state,self.contract,self.plan)
                self.assertEqual(self.changes,[]);self.assertEqual(list(self.data.iterdir()),[])
        layout.prepare(self.state,self.contract,self.plan);layout.verify(self.state,self.contract,self.plan)

    def test_visible_stable_volume_failure_requires_same_uuid_before_native_ownership(self):
        actual=os.fsync
        def failed(fd):
            if self.state.exists('volume.json'):raise OSError('inert persistent stable-volume sync failure')
            actual(fd)
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):layout.prepare(self.state,self.contract,self.plan)
                self.assertEqual(self.changes,[])
        captured=self.state.get('volume.json')
        with patch.object(layout,'probe',return_value=dict(captured['filesystem'],uuid='22345678-1234-1234-1234-123456789abc')):
            with self.assertRaises(ValueError):layout.prepare(self.state,self.contract,self.plan)
        self.assertEqual(self.changes,[]);self.assertEqual(self.state.get('volume.json'),captured)
        layout.prepare(self.state,self.contract,self.plan);layout.verify(self.state,self.contract,self.plan)
        self.assertEqual(self.state.get('volume.json'),captured)

    def key(self,path):info=path.stat();return (info.st_dev,info.st_ino)

    def interrupted(self):
        """Leave the original intent and its owned children, stopping before layout.json."""
        original=self.state.put
        def failed(name,value):
            if name=='layout.json':raise OSError('inert interruption before the completed layout')
            return original(name,value)
        with patch.object(self.state,'put',side_effect=failed):
            with self.assertRaises(OSError):layout.prepare(self.state,self.contract,self.plan)
        self.assertEqual(len(self.changes),3);self.assertFalse(self.state.exists('layout.json'))

    def test_unfinished_layout_never_completes_over_a_changed_root_or_child_owner(self):
        self.interrupted();root=self.key(self.data);vc=self.key(self.data/'vc');reth=self.key(self.data/'reth')
        owner=self.owners[vc];beacon=self.owners[self.key(self.data/'beacon')];retained=self.fixture.root/'retained-native'
        volume=self.state.get('volume.json')
        def owned(key,value):return lambda:self.owners.__setitem__(key,value)
        def replace():
            # Only a volume receipt naming the replacement passes the volume check first.
            self.data.rename(retained);self.data.mkdir(mode=0o711)
            self.state.put('volume.json',dict(volume,inode=self.data.stat().st_ino))
        def restore():self.data.rmdir();retained.rename(self.data);self.state.put('volume.json',volume)
        cases=[('foreign root',owned(root,(77,0)),None,'native root ownership changed'),
               ('group-writable root',lambda:self.data.chmod(0o731),lambda:self.data.chmod(0o711),'native root ownership changed'),
               ('other-writable root',lambda:self.data.chmod(0o713),lambda:self.data.chmod(0o711),'native root ownership changed'),
               ('replaced root',replace,restore,'selected original native directory changed'),
               ('foreign child',owned(vc,(77,owner[1])),None,'native directory owner differs'),
               ('foreign child group',owned(vc,(owner[0],77)),None,'native directory owner differs'),
               ('child of another service',owned(reth,beacon),None,'native directory owner differs')]
        for name,change,undo,message in cases:
            with self.subTest(name):
                saved=dict(self.owners);change()
                try:
                    with self.assertRaisesRegex(ValueError,message):layout.prepare(self.state,self.contract,self.plan)
                finally:
                    if undo:undo()
                    self.owners.clear();self.owners.update(saved)
                self.assertEqual(len(self.changes),3);self.assertFalse(self.state.exists('layout.json'))
        layout.prepare(self.state,self.contract,self.plan);layout.verify(self.state,self.contract,self.plan)
        self.assertEqual(len(self.changes),3)

    def test_verify_refuses_a_private_directory_with_another_owner_or_inode(self):
        layout.prepare(self.state,self.contract,self.plan);child=self.data/'vc';key=self.key(child);owner=self.owners[key]
        beacon=self.owners[self.key(self.data/'beacon')];outside=self.fixture.root/'outside'
        refused='original native directory identity or permissions changed'
        for value in [(77,owner[1]),(owner[0],77),beacon]:
            with self.subTest(owner=value):
                self.owners[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,refused):layout.verify(self.state,self.contract,self.plan)
                finally:self.owners[key]=owner
        with self.subTest('replaced directory with the same owner'):
            child.rename(outside);child.mkdir(mode=0o700);self.owners[fixtures.held(self,child)]=owner
            try:
                with self.assertRaisesRegex(ValueError,refused):layout.verify(self.state,self.contract,self.plan)
            finally:child.rmdir();outside.rename(child)
        layout.verify(self.state,self.contract,self.plan);self.assertEqual(len(self.changes),3)

    def test_empty_root_volume_recovery_directory_is_preserved(self):
        self.data.mkdir(mode=0o755);lost=self.data/'lost+found';lost.mkdir(mode=0o700)
        layout.prepare(self.state,self.contract,self.plan)
        self.assertTrue(lost.is_dir());self.assertEqual(lost.stat().st_mode&0o777,0o700)
        layout.verify(self.state,self.contract,self.plan)


if __name__=='__main__':unittest.main()
