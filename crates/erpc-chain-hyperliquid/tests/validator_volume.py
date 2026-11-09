# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual private-state publication/recovery under inert kernel and original UID metadata."""
import base64
import contextlib
import io
import os
from pathlib import Path
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import validator_custody as fixture
import phases_test
custody=fixture.custody


class Volume(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Custody();self.f.setUp();self.addCleanup(self.f.tearDown);self.f.import_key()
        self.root=self.f.state_dir;self.state=self.f.state;self.contract=self.f.contract
        self.home=self.root/'home';self.data=self.home/'hl/data';self.data.mkdir(parents=True,mode=0o700)
        self.native={'uid':995,'gid':995};self.state.put('accounts.json',{custody.setup.NATIVE:self.native})
        self.owners={};self.changes=[];self.dev=None
        for path in (self.home,self.home/'hl',self.data):
            path.chmod(0o700);self.owners[path.stat().st_ino]=(995,995)
        self.original_fd=os.fstat;self.original_stat=Path.lstat
        def metadata(value):
            values=list(value)
            if stat.S_ISDIR(value.st_mode):
                values[4],values[5]=self.owners.get(value.st_ino,(os.getuid(),os.getgid()))
                if self.dev is not None:values[2]=self.dev
            return os.stat_result(values)
        def chown(fd,uid,gid):
            inode=self.original_fd(fd).st_ino;self.owners[inode]=(uid,gid);self.changes.append(inode)
        for obj,name,value in ((custody.setup,'HOME',self.home),(custody.setup,'ROOT_UID',os.getuid()),
                (custody.processes,'quiescent',lambda *_:None),(os,'fstat',lambda fd:metadata(self.original_fd(fd))),
                (Path,'lstat',lambda path,*args,**kwargs:metadata(self.original_stat(path,*args,**kwargs))),
                (os,'fchown',chown)):
            entry=patch.object(obj,name,value);entry.start();self.addCleanup(entry.stop)
    def publish(self):return Path(custody.native_path(self.contract,create=True))
    def invoke(self,identifier):
        request={'action':'recover-validator-filesystem','contract':self.contract,'original_uuid':identifier}
        control=phases_test.control;common=phases_test.common
        source=SimpleNamespace(buffer=io.BytesIO(common.json_bytes(request)));output=io.StringIO()
        with patch.object(control,'ROOT',self.root,create=True),patch.object(common,'ROOT',self.root), \
             patch.object(control,'trusted_imports',lambda *_:None),patch.object(phases_test.host,'ROOT',self.root), \
             patch.object(phases_test.host,'protected_paths'),patch.object(phases_test.host,'contract',lambda value:value), \
             patch.object(control.os,'geteuid',return_value=0),patch.object(phases_test.resource,'setrlimit'), \
             patch.object(sys,'argv',['control.py','play']),patch.object(sys,'stdin',source),contextlib.redirect_stdout(output):
            control.main()
        return common.unique_json(output.getvalue().encode())
    def legacy(self):
        path=self.publish();saved=self.state.get('validator-native-path.json')
        self.state.put('validator-native-path.json',{'contract':self.contract,'device':123,'inode':saved['inode']})
        original=(self.root/'validator-native-path.json').read_bytes()
        self.state.cancel(self.contract,False,lambda:None)
        return path,original
    def test_reboot_renumbering_preserves_original_private_state_and_placeholder(self):
        path=self.publish();history=path.parent/'consensus-history';history.write_bytes(b'inert original history')
        original=(self.root/'validator-native-path.json').read_bytes();changes=len(self.changes)
        self.dev=os.makedev(81,27)
        self.assertEqual(custody.native_path(self.contract),str(path));self.publish()
        self.assertEqual((self.root/'validator-native-path.json').read_bytes(),original)
        self.assertEqual(len(self.changes),changes);self.assertEqual(history.read_bytes(),b'inert original history')
        self.assertNotIn('device',self.state.get('validator-native-path.json'))
        self.f.filesystem_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(history.read_bytes(),b'inert original history')
    def test_interrupted_original_publication_keeps_uuid_inode_before_handoff(self):
        original=self.state.put
        def fail(state,name,value):
            original(name,value)
            if name=='validator-native-path.pending.json':raise OSError('inert lost durable pending acknowledgement')
        with patch.object(custody.State,'put',fail),self.assertRaises(OSError):self.publish()
        self.assertFalse((self.root/'validator-native-path.json').exists());self.assertFalse(self.changes)
        self.f.filesystem_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaisesRegex(ValueError,'interrupted'):self.publish()
        self.assertFalse(self.changes)
        self.f.filesystem_uuid='00000000-0000-0000-0000-000000000001'
        path=self.publish();self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)
        self.assertEqual(len(self.changes),1)
    def test_missing_uuid_nested_mount_readonly_volume_never_changes_original_publication(self):
        path=self.publish();before=(self.root/'validator-native-path.json').read_bytes()
        for name,value in [('filesystem_uuid',None),('filesystem_type','tmpfs'),('filesystem_root','/other'),('filesystem_options','ro')]:
            old=getattr(self.f,name);setattr(self.f,name,value)
            with self.assertRaises(ValueError):custody.native_path(self.contract)
            setattr(self.f,name,old)
        self.f.mounts.write_text('1 0 1:1 / '+str(path.parent)+' rw - ext4 /dev/inert rw\n')
        with self.assertRaisesRegex(ValueError,'nested'):self.publish()
        self.assertEqual((self.root/'validator-native-path.json').read_bytes(),before)
        self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)
    def test_explicit_legacy_upgrade_actual_controller_preserves_ciphertext_and_history(self):
        path,original=self.legacy();history=path.parent/'state';history.write_bytes(b'inert native history')
        self.state.put('installed.json',{'operation':{'target':{'mode':'validator','id':'original-supervisor','signed_at':123}}})
        unchanged={name:(self.root/name).read_bytes() for name in ('owner.json','accounts.json','validator-identity.json','operation.json','installed.json')}
        cipher=custody.ACTIVE.read_bytes();count=len(self.changes);self.dev=os.makedev(82,28)
        with self.assertRaises(ValueError):custody.native_path(self.contract)
        value=self.invoke(self.f.filesystem_uuid);self.assertTrue(value['private_filesystem_upgraded']);self.assertTrue(value['stopped'])
        saved=self.state.get('validator-native-volume-upgrade.json')
        self.assertEqual(base64.b64decode(saved['original_receipt']),original)
        self.assertEqual(saved['original_sha256'],fixture.common.digest(original))
        self.invoke(self.f.filesystem_uuid);self.assertEqual(custody.native_path(self.contract),str(path))
        self.assertEqual(history.read_bytes(),b'inert native history');self.assertEqual(custody.ACTIVE.read_bytes(),cipher)
        self.assertEqual({name:(self.root/name).read_bytes() for name in unchanged},unchanged)
        self.assertEqual(len(self.changes),count)
    def test_wrong_uuid_stopped_fence_writer_and_replaced_inode_refuse_before_recovery(self):
        path,original=self.legacy()
        with self.assertRaises(ValueError):self.invoke('00000000-0000-0000-0000-000000000002')
        with patch.object(custody.processes,'quiescent',side_effect=ValueError('inert writer')),self.assertRaisesRegex(ValueError,'writer'):
            self.invoke(self.f.filesystem_uuid)
        (self.root/'stopped').unlink()
        with self.assertRaisesRegex(ValueError,'stop'):self.invoke(self.f.filesystem_uuid)
        self.state.marker('stopped');saved=self.state.get('validator-native-path.json');saved['inode']+=1
        self.state.put('validator-native-path.json',saved)
        with self.assertRaisesRegex(ValueError,'inode'):self.invoke(self.f.filesystem_uuid)
        self.assertFalse((self.root/'validator-native-volume-upgrade.json').exists());self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)
    def test_lost_upgrade_acknowledgement_retries_only_original_input(self):
        path,original=self.legacy();write=self.state.put
        def fail(state,name,value):
            write(name,value)
            if name=='validator-native-volume-upgrade.json':raise OSError('inert upgrade fsync acknowledgement loss')
        with patch.object(custody.State,'put',fail),self.assertRaises(OSError):self.invoke(self.f.filesystem_uuid)
        self.assertEqual((self.root/'validator-native-path.json').read_bytes(),original)
        self.f.filesystem_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaisesRegex(ValueError,'another original'):self.invoke(self.f.filesystem_uuid)
        self.f.filesystem_uuid='00000000-0000-0000-0000-000000000001'
        self.invoke(self.f.filesystem_uuid);self.invoke(self.f.filesystem_uuid)
        self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)


    def test_lost_final_receipt_acknowledgement_is_idempotent_without_any_history_write(self):
        path,original=self.legacy();write=self.state.put
        def fail(state,name,value):
            write(name,value)
            if name=='validator-native-path.json':raise OSError('inert final receipt directory sync loss')
        with patch.object(custody.State,'put',fail),self.assertRaises(OSError):self.invoke(self.f.filesystem_uuid)
        self.assertEqual(self.state.get('validator-native-path.json')['format'],2)
        self.invoke(self.f.filesystem_uuid)
        self.assertEqual(base64.b64decode(self.state.get('validator-native-volume-upgrade.json')['original_receipt']),original)
        self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)

    def test_original_final_publication_failure_retains_pending_binding_and_reuses_destination(self):
        write=self.state.put
        def fail(state,name,value):
            if name=='validator-native-path.json':raise OSError('inert initial final publication failure')
            write(name,value)
        with patch.object(custody.State,'put',fail),self.assertRaises(OSError):self.publish()
        pending=(self.root/'validator-native-path.pending.json').read_bytes()
        destination=self.home/'hl/hyperliquid_data/node_config.json';inode=destination.stat().st_ino
        self.assertEqual(self.publish(),destination)
        self.assertEqual(destination.stat().st_ino,inode)
        self.assertEqual((self.root/'validator-native-path.pending.json').read_bytes(),pending)


if __name__=='__main__':unittest.main()
