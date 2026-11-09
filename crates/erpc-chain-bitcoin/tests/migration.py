# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stopped original-history migration with real files and modeled NSS/mount facts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
import accounts
import lifecycle
c=accounts.c


class Migration(unittest.TestCase):
    def setUp(self):
        self.fixture=accounts.Accounts('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.native=self.fixture.fixture
        account={'name':'bitcoin','uid':os.getuid(),'gid':os.getgid(),'home':str(c.ROOT.parent/'old-home'),'shell':'/usr/sbin/nologin'}
        self.fixture.users['bitcoin']=dict(account)
        self.fixture.groups['bitcoin']={'name':'bitcoin','gid':os.getgid(),'members':[]}
        state={key:self.native.state[key] for key in ('owner','network','storage','prune_mib','phase','installed')}
        (c.ROOT/'owner.json').write_text(json.dumps(state));(c.ROOT/'owner.json').chmod(0o600)
        (c.ROOT/'data').chmod(0o700);c.ROOT.chmod(0o700)
        machine=c.ROOT.parent/'machine-id';machine.write_text('1'*32);machine.chmod(0o644)
        patch.object(c,'MACHINE_FILE',machine).start()
        self.uuid='10000000-0000-0000-0000-000000000001'
        self.mounts=[];self.calls=[]
        def command(argv,**kwargs):
            self.calls.append(argv)
            if argv[0]=='/usr/bin/findmnt':
                if '--submounts' in argv:return json.dumps({'filesystems':[{'target':'/','children':[{'target':str(path)} for path in self.mounts]}]}).encode()
                return json.dumps({'filesystems':[{'uuid':self.uuid,'fstype':'ext4','options':'rw,relatime'}]}).encode()
            return self.native.service_run(argv,**kwargs)
        patch.object(c,'run',side_effect=command).start()
        self.record={'schema':'erpc-bitcoin-original-v1','contract':dict(c.contract(state),host_binding='d'*64),
            'machine_sha256':c.machine_identity(),'layout':{'root':{'uuid':self.uuid,'fstype':'ext4'},
            'data':{'uuid':self.uuid,'fstype':'ext4'},'root_inode':c.ROOT.stat().st_ino,'data_inode':(c.ROOT/'data').stat().st_ino},
            'account':account,'highest_source':dict(state['installed'])}
        for name,field in [('bitcoind','daemon_sha256'),('bitcoin-cli','client_sha256')]:
            self.record[field]=hashlib.sha256((c.release_dir(state['installed'])/'bin'/name).read_bytes()).hexdigest()
        self.query=dict(self.native.request('migrate-original'),host_binding='d'*64,original=self.record)
        self.sentinel=(c.ROOT/'data/chainstate-fixture').read_bytes()

    def test_actual_dispatch_migration_stays_stopped_preserves_original_ids_and_retries(self):
        result=c.locked(self.query)
        self.assertTrue(result['migrated']);self.assertEqual(result['service'],'stopped')
        state=c.read_state()
        self.assertEqual(state['origin'],'verified-legacy');self.assertTrue(state['stopped'])
        self.assertEqual(c.retained_account(state),self.record['account'])
        self.assertEqual(c.source_floor(state),self.record['highest_source'])
        self.assertEqual((c.ROOT/'data/chainstate-fixture').read_bytes(),self.sentinel)
        original=(c.ROOT/'migration.json').read_bytes()
        c.locked(self.query)
        self.assertEqual((c.ROOT/'migration.json').read_bytes(),original)
        self.assertFalse(any(argv[0] in ('/usr/sbin/useradd','/usr/sbin/groupadd') or argv[1:2]==['start'] for argv in self.calls))

    def test_wrong_history_or_keyed_nss_or_nested_mount_refuses_before_any_shutdown(self):
        for field in ('machine_sha256','daemon_sha256','client_sha256'):
            query=copy.deepcopy(self.query);query['original'][field]='0'*64
            with self.assertRaises(c.Refused):c.locked(query)
        for field in ('root','data'):
            query=copy.deepcopy(self.query);query['original']['layout'][field]['uuid']='20000000-0000-0000-0000-000000000002'
            with self.assertRaises(c.Refused):c.locked(query)
        query=copy.deepcopy(self.query);query['original']['layout']['data_inode']+=1
        with self.assertRaises(c.Refused):c.locked(query)
        with patch.object(c.pwd,'getpwuid',side_effect=KeyError),self.assertRaises(c.Refused):c.locked(self.query)
        self.mounts=[c.ROOT/'data/blocks']
        with self.assertRaises(c.Refused):c.locked(self.query)
        self.assertFalse(any(argv[0]=='/usr/bin/systemctl' for argv in self.calls))
        self.assertFalse((c.ROOT/'migration.json').exists())

    def test_every_receipt_postrename_failure_resumes_same_originals_without_native_start(self):
        for name in ('migration.json','account-intent.json','account.json','native-releases.json',
                     'source-floor.pending.json','source-floor.json','owner.json'):
            with self.subTest(name=name):
                fixture=Migration('runTest');fixture.setUp()
                try:
                    real=c.original_write;seen=[]
                    def fail(record,value):
                        real(record,value)
                        if record==name and not seen:seen.append(record);raise OSError('inert postrename interruption')
                    if name=='owner.json':
                        save=c.save
                        def save_fail(value):
                            save(value)
                            if value.get('origin')=='verified-legacy' and not seen:seen.append(name);raise OSError('inert owner promotion interruption')
                        context=patch.object(c,'save',side_effect=save_fail)
                    else:context=patch.object(c,'original_write',side_effect=fail)
                    with context,self.assertRaises((OSError,c.Refused)):c.locked(fixture.query)
                    self.assertTrue(seen)
                    c.locked(fixture.query)
                    self.assertTrue(c.read_state()['stopped'])
                    self.assertEqual(c.retained_account(c.read_state()),fixture.record['account'])
                    self.assertEqual((c.ROOT/'data/chainstate-fixture').read_bytes(),fixture.sentinel)
                    self.assertFalse(any(argv[1:2]==['start'] for argv in fixture.calls))
                finally:fixture.doCleanups()

    def test_persistent_original_record_directory_sync_failure_never_bypasses_barrier(self):
        real=os.fsync
        def failure(fd):
            if os.fstat(fd).st_ino==c.ROOT.stat().st_ino:raise OSError('inert ROOT sync failure')
            return real(fd)
        with patch.object(c.os,'fsync',side_effect=failure):
            for _ in range(2):
                with self.assertRaises((OSError,c.Refused)):c.locked(self.query)
                self.assertFalse((c.ROOT/'account-intent.json').exists())
        c.locked(self.query)
        self.assertTrue(c.read_state()['stopped'])
        self.assertEqual((c.ROOT/'data/chainstate-fixture').read_bytes(),self.sentinel)


if __name__=='__main__':unittest.main()
