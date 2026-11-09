#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual reserve dispatcher/storage paths; mount/udev/NSS observations are inert."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


@unittest.skipUnless(os.name=='posix','original-volume fixtures require POSIX descriptors')
class Reserve(unittest.TestCase):
    def setUp(self):
        import control,install,state,volume_fixture,volume
        self.volume=volume
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.commands=[]
        def run(args,**_):
            self.commands.append(args)
            if args[:2]==['systemctl','show']:
                data=b'0' if '--property=MainPID' in args else b'not-found'
            elif args[:2]==['systemctl','is-active']:data=b'inactive'
            else:raise AssertionError('unexpected mutation in storage fixture')
            return subprocess.CompletedProcess(args,0,data,b'')
        authority=SimpleNamespace(initial=lambda:None,quiescent=lambda:None,unoccupied=lambda:None)
        self.state=state.State(self.root,run,owner=os.getuid(),proof=authority,
            account=SimpleNamespace(preflight=lambda *_:None))
        for path in ('etc','var/lib/polygon','opt/erpc','usr/local/lib/erpc/polygon/releases'):
            (self.root/path).mkdir(parents=True,exist_ok=True)
        volume_fixture.attach(self,self.state)
        source=self.root/'source';source.mkdir()
        for name in install.SCRIPTS:
            file=ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py' if name=='upstreams.py' else ROOT/'templates/scripts'/name
            shutil.copyfile(file,source/name)
        self.control=control.Control(self.state,source)
        profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.expected=state.contract('amoy','i'*26,'x86_64',profile['bor_genesis_hash'],profile['heimdall_genesis']['sha256'])
        self.data=self.state.path(volume.DATA)
    def reserve(self):return self.control.dispatch({'action':'reserve','contract':self.expected})
    def test_validator_initial_public_contract_is_reserved_without_creating_a_key_or_claiming_admission(self):
        self.expected=dict(self.expected,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        result=self.reserve();self.assertTrue(result['reserved']);self.assertEqual(result['role'],'validator')
        self.assertFalse(self.state.path('/etc/polygon/identity.json').exists())
        self.assertFalse(self.state.path('/etc/polygon/validator-admission.json').exists())
        foreign=dict(self.expected,stake_owner='0x'+'3'*40)
        with self.assertRaises(ValueError):self.control.dispatch({'action':'reserve','contract':foreign})

    def test_actual_dispatch_accepts_prepared_empty_volume_and_preserves_lost_found_on_retry(self):
        recovery=self.data/'lost+found';recovery.mkdir(mode=0o700)
        original=(self.data.stat().st_ino,recovery.stat().st_ino)
        self.assertTrue(self.reserve()['reserved'])
        saved=self.state.path(self.volume.RECEIPT).read_bytes()
        self.assertTrue(self.reserve()['reserved']);self.assertEqual(self.state.path(self.volume.RECEIPT).read_bytes(),saved)
        self.assertEqual((self.data.stat().st_ino,recovery.stat().st_ino),original)
        self.assertFalse(self.commands);self.assertTrue(self.state.volume_observations)
        self.assertEqual(self.state.read('/etc/polygon/contract.json')['runtime_protocol'],3)
    def test_absent_data_directory_is_created_only_after_readonly_filesystem_qualification(self):
        self.data.rmdir();self.reserve();self.assertTrue(self.data.is_dir())
        self.assertEqual(self.state.read(self.volume.RECEIPT)['inode'],self.data.stat().st_ino)
        self.assertFalse(self.commands)
    def test_unknown_recovery_history_writable_or_symlinked_storage_is_not_adopted(self):
        for bad in ('history','recovered','writable','symlink'):
            with self.subTest(bad=bad):
                if bad=='history':(self.data/'chain-history').write_text('retain')
                if bad=='recovered':
                    (self.data/'lost+found').mkdir();(self.data/'lost+found/recovered').write_text('retain')
                if bad=='writable':self.data.chmod(0o777)
                if bad=='symlink':(self.data/'lost+found').symlink_to(self.root)
                with self.assertRaises(ValueError):self.reserve()
                self.assertFalse(self.state.path('/etc/polygon/contract.json').exists());self.assertFalse(self.commands)
                if bad=='history':(self.data/'chain-history').unlink()
                if bad=='recovered':shutil.rmtree(self.data/'lost+found')
                if bad=='writable':self.data.chmod(0o755)
                if bad=='symlink':(self.data/'lost+found').unlink()
    def test_lost_publication_acknowledgement_reuses_original_storage_before_nss(self):
        original=self.state.write
        def fail(path,*args,**kwargs):
            original(path,*args,**kwargs)
            if path==self.volume.RECEIPT:raise OSError('inert storage directory fsync failure')
        with patch.object(self.state,'write',side_effect=fail),self.assertRaises(OSError):self.reserve()
        saved=self.state.path(self.volume.RECEIPT).read_bytes()
        self.reserve();self.assertEqual(self.state.path(self.volume.RECEIPT).read_bytes(),saved);self.assertFalse(self.commands)
    def test_uuid_or_directory_replacement_and_nested_same_device_bind_refuse_without_rebinding(self):
        self.reserve();saved=self.state.path(self.volume.RECEIPT).read_bytes()
        self.state.volume_uuid='00000000-0000-0000-0000-000000000002'
        with self.assertRaises(ValueError):self.reserve()
        self.state.volume_uuid='00000000-0000-0000-0000-000000000001'
        self.state.volume_mounts=[self.data/'heimdall/data']
        with self.assertRaisesRegex(ValueError,'nested'):self.reserve()
        with self.assertRaisesRegex(ValueError,'nested'):self.state.capacity(self.expected)
        self.state.volume_mounts=[self.data,self.data]
        with self.assertRaisesRegex(ValueError,'stacked'):self.reserve()
        self.state.volume_mounts=[];self.data.rename(self.data.with_name('retained-original'));self.data.mkdir()
        with self.assertRaises(ValueError):self.reserve()
        self.assertEqual(self.state.path(self.volume.RECEIPT).read_bytes(),saved);self.assertFalse(self.commands)
        # Protective shutdown does not depend on the damaged/replaced data mount.
        self.control.dispatch({'action':'stop-v2','contract':self.expected})
        self.assertTrue(self.state.path('/etc/polygon/stopped').exists())
    def test_reboot_device_renumbering_keeps_original_uuid_inode_and_live_checks(self):
        self.reserve();saved=self.state.path(self.volume.RECEIPT).read_bytes()
        before_stat=Path.stat;before_lstat=Path.lstat
        def changed(original,path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==self.data:
                fields=list(value);fields[2]=os.makedev(77,19)
                return os.stat_result(fields)
            return value
        with patch.object(Path,'stat',lambda path,*args,**kwargs:changed(before_stat,path,*args,**kwargs)), \
             patch.object(Path,'lstat',lambda path,*args,**kwargs:changed(before_lstat,path,*args,**kwargs)):
            self.assertTrue(self.reserve()['reserved'])
            self.assertEqual(self.state.path(self.volume.RECEIPT).read_bytes(),saved)
            with patch.object(self.volume,'uuid_device',return_value=os.makedev(77,20)),self.assertRaises(ValueError):
                self.reserve()
        self.assertNotIn('device',self.state.read(self.volume.RECEIPT))

    def test_retained_accounts_without_storage_receipt_never_silently_rebind(self):
        self.reserve();self.state.path(self.volume.RECEIPT).unlink()
        self.state.write('/etc/polygon/runtime-accounts.json',{'inert':'retained original authority'})
        with self.assertRaisesRegex(ValueError,'original storage'):self.reserve()
        self.assertFalse(self.commands)


@unittest.skipUnless(os.name=='posix','udev metadata model requires POSIX paths')
class Udev(unittest.TestCase):
    def test_uuid_selector_uses_only_metadata_and_rejects_links_outside_the_device_namespace(self):
        import volume,state
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);directory=root/'dev/disk/by-uuid';directory.mkdir(parents=True)
            identifier='00000000-0000-0000-0000-000000000001'
            device=root/'dev/inert-device';device.write_bytes(b'')
            selector=directory/identifier;selector.symlink_to('../../inert-device')
            scope=state.State(root,owner=os.getuid());original=Path.lstat
            def metadata(path,*args,**kwargs):
                value=original(path,*args,**kwargs)
                if path==device:return SimpleNamespace(st_mode=stat.S_IFBLK|0o600,st_uid=os.getuid(),st_rdev=1234)
                return value
            with patch.object(Path,'lstat',metadata),patch('builtins.open',side_effect=AssertionError('no block open')),                 patch.object(os,'open',side_effect=AssertionError('no block open')):
                self.assertEqual(volume.uuid_device(scope,identifier),1234)
            with self.assertRaises(ValueError):volume.uuid_device(scope,identifier)
            selector.unlink();selector.symlink_to('../../../../outside-device-namespace')
            with self.assertRaises(ValueError):volume.uuid_device(scope,identifier)


if __name__=='__main__':unittest.main()
