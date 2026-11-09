#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Composed host/state/account logic; NSS/mount/process observations are inert."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as Record
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validator_accounts import Accounts
import host
import storage
import state


class Host(unittest.TestCase):
    def setUp(self):
        self.fixture = Accounts(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.contract = self.fixture.contract
        # Accounts fixture already reserved an independent state; move host
        # preparation to an actually absent root in the same trusted namespace.
        self.owned = self.root / 'nitro'; self.data = self.owned / 'data'
        for name, value in [('ROOT', self.owned), ('DATA', self.data), ('HELPERS', self.root/'helpers'),
                            ('CONFIG', self.root/'config'), ('CUSTODY', self.root/'custody'),
                            ('UPSTREAM_CUSTODY', self.root/'l1-custody'), ('TLS_CUSTODY', self.root/'tls-custody'),
                            ('UNITS', self.root/'units'), ('RUNTIME', self.root/'runtime'),
                            ('FIREWALL', self.root/'firewall'), ('FIREWALL_HELPER', self.root/'firewall.py'),
                            ('DOCKER', self.root/'missing-docker')]:
            patch.object(host, name, value).start()
        host.UNITS.mkdir()
        patch.object(host, 'platform_facts', return_value={'systemd': 255}).start()
        self.free = host.BUDGET; self.uuid = self.contract['data_uuid']; self.allocated = 0
        patch.object(host.shutil, 'disk_usage', side_effect=lambda _: Record(free=self.free)).start()
        patch.object(host.os, 'chown', return_value=None).start()
        self.original_ensure = host.accounts.ensure
        def ensure(owned, expected, runner):
            # Full real account reservation verification stays in the account
            # fixture; data owner is mapped to the current inert test UID/GID.
            self.fixture.path = owned.root
            result = self.original_ensure(owned, expected, runner)
            return dict(result, node=dict(result['node'], uid=os.getuid(), gid=os.getgid()))
        patch.object(host.accounts, 'ensure', side_effect=ensure).start()
        patch.object(host.accounts, 'verify', side_effect=lambda *_: {'node': {'uid': os.getuid(), 'gid': os.getgid()}}).start()
        self.quiet = []; self.mounts = []

    def command(self, argv, **_kwargs):
        if argv[0] == '/usr/bin/findmnt':
            if '--submounts' in argv:
                return json.dumps({'filesystems':[{'target':'/','children':self.mounts}]}).encode()
            return json.dumps({'filesystems': [{'uuid': self.uuid, 'fstype': 'ext4', 'options': 'rw,noatime'}]}).encode()
        if argv[0] == '/usr/bin/du': return (str(self.allocated)+'\t'+str(self.data)+'\n').encode()
        self.assertEqual(argv[0:2], ['/usr/bin/systemctl', 'show']); return b'not-found\n'

    def initialize(self):
        return host.initialize(self.contract, lambda records: self.quiet.append(records), self.command, self.fixture.account_command)

    def test_fresh_composed_initialization_records_original_uuid_before_data_and_preserves_retries(self):
        self.assertTrue(self.initialize()['initialized'])
        original = (self.owned / 'owner.json').read_bytes()
        self.assertEqual(len(self.fixture.calls), 4); self.assertEqual(len(self.quiet), 2)
        block = self.data/'retained-block'; block.write_text('inert native data')
        self.assertTrue(self.initialize()['initialized'])
        self.assertEqual((self.owned/'owner.json').read_bytes(), original)
        self.assertEqual(block.read_text(), 'inert native data'); self.assertEqual(len(self.fixture.calls), 4)

    def test_owner_only_or_empty_data_retry_never_bypasses_initial_budget(self):
        with patch.object(host.accounts, 'ensure', side_effect=OSError('inert failure before accounts')):
            with self.assertRaises(OSError): self.initialize()
        self.assertTrue((self.owned/'owner.json').exists()); self.assertFalse(self.data.exists())
        self.free = host.HEADROOM
        with self.assertRaisesRegex(ValueError, 'synchronization'): self.initialize()
        self.free = host.BUDGET; self.initialize(); self.free = host.HEADROOM
        with self.assertRaisesRegex(ValueError, 'synchronization'): self.initialize()
        (self.data/'allocated-block').write_text('inert allocated native payload')
        self.allocated = host.BUDGET
        self.assertTrue(self.initialize()['initialized'])

    def test_mount_uuid_replacement_and_unowned_legacy_data_refuse_before_nss(self):
        self.uuid = '00000000-0000-0000-0000-000000000002'
        with self.assertRaisesRegex(ValueError, 'filesystem'): self.initialize()
        self.assertEqual(self.fixture.calls, []); self.assertFalse(self.owned.exists())
        self.uuid = self.contract['data_uuid']; self.owned.mkdir(); self.data.mkdir()
        (self.data/'retained-native-block').write_text('inert old history')
        with self.assertRaisesRegex(ValueError, 'unowned Nitro data'): self.initialize()
        self.assertEqual(self.fixture.calls, [])

    def test_helper_ancestor_symlink_and_writable_dropin_are_never_repaired(self):
        outside = self.root/'outside'; outside.mkdir(); host.HELPERS.symlink_to(outside)
        with self.assertRaises(ValueError): self.initialize()
        self.assertTrue(host.HELPERS.is_symlink()); host.HELPERS.unlink()
        overrides = host.UNITS/(host.NAMES[0]+'.d'); overrides.mkdir()
        override = overrides/'override.conf'; override.write_text('inert unsafe override'); override.chmod(0o666)
        with self.assertRaises(ValueError): self.initialize()
        self.assertEqual(override.stat().st_mode & 0o777, 0o666); self.assertEqual(self.fixture.calls, [])

    def test_nested_filesystem_or_same_device_bind_refuses_repeat_init_and_capacity_without_mutation(self):
        self.initialize(); original=(self.owned/'owner.json').read_bytes();calls=len(self.fixture.calls)
        for nested in (self.data/'chain',self.data/'chain/nitro/l2chaindata'):
            self.mounts=[{'target':str(nested)}]
            with self.assertRaisesRegex(ValueError,'nested'): self.initialize()
            with self.assertRaisesRegex(ValueError,'nested'): host.capacity(state.State(self.owned),self.contract,self.command)
            self.assertEqual((self.owned/'owner.json').read_bytes(),original)
            self.assertEqual(len(self.fixture.calls),calls)
        self.mounts=[{'target':str(self.data)}]
        self.assertTrue(self.initialize()['initialized'])
        self.mounts=[{'target':str(self.data),'children':[{'target':str(self.data)}]}]
        with self.assertRaisesRegex(ValueError,'stacked'): self.initialize()

    def test_premounted_root_and_data_accept_only_empty_original_directories_and_preserve_recovery(self):
        self.owned.mkdir(mode=0o755); self.data.mkdir(mode=0o755)
        roots = (self.owned/'lost+found', self.data/'lost+found')
        for path in roots: path.mkdir(mode=0o700)
        original = [(path.stat().st_dev,path.stat().st_ino,path.stat().st_mode) for path in roots]
        data_inode=self.data.stat().st_ino
        self.assertTrue(self.initialize()['initialized'])
        self.assertEqual(self.data.stat().st_ino,data_inode)
        self.assertEqual(self.data.stat().st_mode & 0o777,0o700)
        self.assertEqual([(path.stat().st_dev,path.stat().st_ino,path.stat().st_mode) for path in roots],original)
        self.assertTrue(self.initialize()['initialized'])
        self.assertEqual(len(self.fixture.calls),4)
        self.assertEqual(state.State(self.owned).get('data.json')['directory']['inode'],data_inode)

    def test_recovery_content_symlink_or_writable_prepared_volume_refuses_before_nss(self):
        self.owned.mkdir();self.data.mkdir();recovery=self.data/'lost+found';recovery.mkdir()
        (recovery/'recovered-file').write_text('retain filesystem recovery')
        with self.assertRaises(ValueError):self.initialize()
        self.assertEqual(self.fixture.calls,[]);self.assertFalse((self.owned/'owner.json').exists())
        (recovery/'recovered-file').unlink();recovery.chmod(0o777)
        with self.assertRaises(ValueError):self.initialize()
        recovery.chmod(0o700);recovery.rmdir();recovery.symlink_to(self.root)
        with self.assertRaises((ValueError,OSError)):self.initialize()
        recovery.unlink();self.data.chmod(0o777)
        with self.assertRaises(ValueError):self.initialize()
        self.assertEqual(self.fixture.calls,[])

    def test_prepared_volume_retry_after_owner_publication_and_lost_data_receipt_keeps_original_inode(self):
        self.owned.mkdir();self.data.mkdir();(self.data/'lost+found').mkdir()
        original=state.State.put
        def fail_owner(owned,name,value):
            original(owned,name,value)
            if name=='owner.json':raise OSError('inert owner directory sync failure')
        with patch.object(state.State,'put',fail_owner),self.assertRaises(OSError):self.initialize()
        self.assertEqual(self.fixture.calls,[])
        def fail_data(owned,name,value):
            if name=='data.json':raise OSError('inert data receipt publication failure')
            original(owned,name,value)
        with patch.object(state.State,'put',fail_data),self.assertRaises(OSError):self.initialize()
        inode=self.data.stat().st_ino
        self.assertTrue(self.initialize()['initialized'])
        self.assertEqual(self.data.stat().st_ino,inode);self.assertEqual(len(self.fixture.calls),4)

    def test_storage_reservation_is_durable_before_nss_and_replacement_cannot_resume(self):
        self.owned.mkdir();self.data.mkdir();original=state.State.put
        def fail(owned,name,value):
            original(owned,name,value)
            if name=='storage-layout.json':raise OSError('inert visible storage reservation before sync acknowledgement')
        with patch.object(state.State,'put',fail),self.assertRaises(OSError):self.initialize()
        self.assertEqual(self.fixture.calls,[])
        saved=(self.owned/'storage-layout.json').read_bytes()
        with patch.object(host,'synchronize',side_effect=OSError('inert persistent sync failure')),self.assertRaises(OSError):self.initialize()
        self.assertEqual(self.fixture.calls,[])
        self.data.rename(self.owned/'retained-volume');self.data.mkdir()
        with self.assertRaises(ValueError):self.initialize()
        self.assertEqual(self.fixture.calls,[]);self.assertEqual((self.owned/'storage-layout.json').read_bytes(),saved)

    def test_unknown_data_after_owner_fence_and_foreign_descriptor_refuse_before_nss(self):
        self.owned.mkdir();self.data.mkdir()
        original_fstat=os.fstat;identity=(self.data.stat().st_dev,self.data.stat().st_ino)
        def foreign(descriptor):
            value=original_fstat(descriptor)
            if (value.st_dev,value.st_ino)==identity:
                return Record(st_dev=value.st_dev,st_ino=value.st_ino,st_mode=value.st_mode,st_uid=20001)
            return value
        with patch.object(host.os,'fstat',side_effect=foreign),self.assertRaises(ValueError):self.initialize()
        self.assertEqual(self.fixture.calls,[]);self.assertFalse((self.owned/'owner.json').exists())
        with patch.object(host.accounts,'ensure',side_effect=OSError('inert before NSS')),self.assertRaises(OSError):self.initialize()
        self.assertTrue((self.owned/'fence.json').exists())
        (self.data/'unknown-native-history').write_text('retain')
        with self.assertRaises(ValueError):self.initialize()
        self.assertEqual(self.fixture.calls,[]);self.assertEqual((self.data/'unknown-native-history').read_text(),'retain')

    def test_replaced_directory_after_durable_intent_is_not_chowned_or_adopted(self):
        self.owned.mkdir();self.data.mkdir();original=state.State.put
        def replace(owned,name,value):
            original(owned,name,value)
            if name=='data-intent.json':
                self.data.rename(self.owned/'original-data');self.data.mkdir(mode=0o755)
        with patch.object(state.State,'put',replace),self.assertRaises(ValueError):self.initialize()
        self.assertFalse((self.owned/'data.json').exists());self.assertEqual(self.data.stat().st_mode & 0o777,0o755)
        calls=len(self.fixture.calls)
        with self.assertRaises(ValueError):self.initialize()
        self.assertEqual(len(self.fixture.calls),calls)

    def test_data_intent_directory_fsync_failure_does_not_publish_data_authority(self):
        original = state.State.put
        def fail(owned, name, value):
            original(owned, name, value)
            if name == 'data-intent.json': raise OSError('inert visible intent without acknowledged durability')
        with patch.object(state.State, 'put', fail), self.assertRaises(OSError): self.initialize()
        self.assertFalse(self.data.exists()); self.assertFalse((self.owned/'data.json').exists())
        with patch.object(host, 'synchronize', side_effect=OSError('inert persistent sync failure')):
            with self.assertRaises(OSError): self.initialize()
        self.assertFalse(self.data.exists())
        self.assertTrue(self.initialize()['initialized'])


if __name__ == '__main__':
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(Host))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
