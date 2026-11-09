# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual preparation callers with original account/volume helpers, inert OS APIs."""
import copy
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).parent))
import volumes
import lifecycle
c = volumes.c


class Authority(unittest.TestCase):
    def setUp(self):
        self.fixture = volumes.Volumes('runTest'); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.native = self.fixture.fixture.fixture
        patch.object(c,'original_runtime',side_effect=lifecycle.ORIGINAL_RUNTIME).start()
        patch.object(c,'loaded',return_value=False).start()
        self.machine = c.ROOT.parent/'machine-id'
        self.machine.write_text('1'*32+'\n'); self.machine.chmod(0o644)
        patch.object(c,'MACHINE_FILE',self.machine).start()
        c.CONF.unlink(); c.UNIT_PATH.unlink(); shutil.rmtree(c.OPT); c.OPT.mkdir(mode=0o755)
        self.request = dict(c.contract(self.native.state),action='prepare',host_binding='d'*64,pin=self.native.pin)

    def test_actual_fresh_preparation_preserves_premounted_recovery_directories_and_numeric_identity(self):
        (c.ROOT/'lost+found').mkdir(mode=0o700)
        (c.ROOT/'data').mkdir(mode=0o755); (c.ROOT/'data/lost+found').mkdir(mode=0o700)
        inode=(c.ROOT/'data').stat().st_ino
        c.locked(self.request)
        saved=c.read_state(); account=c.original_runtime(saved)
        self.assertEqual(account['name'],'erpc-bitcoin')
        self.assertEqual(account['uid'],20000)
        self.assertTrue(saved['data_ready'])
        self.assertEqual(saved['layout']['data_inode'],inode)
        self.assertEqual(saved['machine_sha256'],c.machine_identity())
        self.assertTrue((c.ROOT/'data/lost+found').is_dir())
        self.fixture.offset=7000
        self.fixture.fixture.calls.clear()
        c.locked(self.request)
        self.assertEqual(self.fixture.fixture.calls,[])
        self.assertEqual(c.original_runtime(c.read_state()),account)

    def test_missing_root_is_traversable_even_under_the_actual_private_process_umask(self):
        c.ROOT.rmdir()
        previous=os.umask(0o077)
        try: c.locked(self.request)
        finally: os.umask(previous)
        self.assertEqual(c.ROOT.stat().st_mode&0o7777,0o755)
        self.assertEqual((c.ROOT/'data').stat().st_mode&0o7777,0o700)
        self.assertEqual(c.original_runtime(c.read_state())['uid'],20000)

    def test_same_name_or_historical_host_reassignment_never_recreates_an_established_account(self):
        c.locked(self.request)
        original=(c.ROOT/'account.json').read_bytes()
        self.fixture.fixture.users.clear()
        self.fixture.fixture.calls.clear()
        with self.assertRaises(c.Refused): c.locked(self.request)
        self.assertEqual(self.fixture.fixture.calls,[])
        self.assertEqual((c.ROOT/'account.json').read_bytes(),original)
        # Retained numeric identity remains available to the shutdown proof.
        self.assertEqual(c.retained_account(c.read_state())['uid'],20000)

    def test_machine_binding_and_established_private_mode_drift_are_not_repaired(self):
        c.locked(self.request)
        original=(c.ROOT/'owner.json').read_bytes()
        self.machine.write_text('2'*32)
        with self.assertRaises(c.Refused): c.locked(self.request)
        self.machine.write_text('1'*32)
        (c.ROOT/'data').chmod(0o755)
        with self.assertRaises(c.Refused): c.locked(self.request)
        self.assertEqual((c.ROOT/'data').stat().st_mode&0o7777,0o755)
        self.assertEqual((c.ROOT/'owner.json').read_bytes(),original)

    def test_low_capacity_does_not_reserve_account_and_retry_uses_the_original_prepared_volume(self):
        self.native.free=1
        with self.assertRaises(c.Refused): c.locked(self.request)
        self.assertFalse((c.ROOT/'owner.json').exists())
        self.assertEqual(self.fixture.fixture.calls,[])
        self.native.free=200_000_000_000
        c.locked(self.request)
        self.assertTrue(c.read_state()['data_ready'])

    def test_partial_nss_creation_resumes_the_same_reserved_id_without_data_replacement(self):
        original_command=c.run
        def interrupted(argv,**kwargs):
            value=original_command(argv,**kwargs)
            if argv[0]=='/usr/sbin/groupadd': raise c.Refused('inert interrupted group creation')
            return value
        with patch.object(c,'run',side_effect=interrupted), self.assertRaises(c.Refused):
            c.locked(self.request)
        intent=(c.ROOT/'account-intent.json').read_bytes()
        c.locked(self.request)
        self.assertEqual((c.ROOT/'account-intent.json').read_bytes(),intent)
        self.assertEqual(c.original_runtime(c.read_state())['uid'],20000)

    def test_complete_pending_first_owner_is_reused_after_file_sync_failure(self):
        real=os.fsync; failed=False
        def interrupted(fd):
            nonlocal failed
            pending=c.ROOT/'owner.json.new'
            if not failed and pending.exists() and os.fstat(fd).st_ino==pending.stat().st_ino:
                failed=True
                raise OSError('inert first owner durability failure')
            return real(fd)
        with patch.object(c.os,'fsync',side_effect=interrupted), self.assertRaises(OSError):
            c.locked(self.request)
        self.assertTrue(failed)
        self.assertFalse((c.ROOT/'owner.json').exists())
        self.assertEqual(self.fixture.fixture.calls,[])
        original=(c.ROOT/'owner.json.new').read_bytes()
        c.locked(self.request)
        self.assertFalse((c.ROOT/'owner.json.new').exists())
        self.assertEqual(c.read_state()['layout']['root_inode'],c.ROOT.stat().st_ino)
        self.assertIn(self.request['host_binding'].encode(),original)
        self.assertEqual(c.original_runtime(c.read_state())['uid'],20000)

    def test_legacy_owner_without_historical_authority_is_preserved_for_explicit_migration(self):
        old=copy.deepcopy(self.native.state)
        c.save(old)
        before=(c.ROOT/'owner.json').read_bytes()
        with self.assertRaises(c.Refused): c.locked(self.request)
        self.assertEqual((c.ROOT/'owner.json').read_bytes(),before)
        self.assertEqual(self.fixture.fixture.calls,[])


if __name__=='__main__': unittest.main()
