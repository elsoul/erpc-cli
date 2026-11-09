# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original account receipts and keyed NSS failures without creating host accounts."""
import copy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import corecell_lifecycle_test as fixtures
c=fixtures.c;a=c.coreaccount
class Accounts(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.CoreLifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.users={};self.groups={};self.calls=[]
        def lookup(records,field,value):
            for item in records.values():
                if getattr(item,field)==value:return item
            raise KeyError(value)
        for module,methods,records,prefix in ((a.pwd,('getpwnam','getpwuid','getpwall'),self.users,'pw'),(a.grp,('getgrnam','getgrgid','getgrall'),self.groups,'gr')):
            patch.object(module,methods[0],side_effect=lambda value,r=records,p=prefix:lookup(r,p+'_name',value)).start()
            patch.object(module,methods[1],side_effect=lambda value,r=records,p=prefix:lookup(r,p+('_uid' if p=='pw' else '_gid'),value)).start()
            patch.object(module,methods[2],side_effect=lambda r=records:list(r.values())).start()
        patch.object(a.os,'getgrouplist',side_effect=lambda name,gid:[gid]).start()
        patch.object(c,'run',side_effect=self.command).start()
        self.original=c.state_read()
    def command(self,argv,**kwargs):
        self.calls.append(argv)
        if argv[0]=='/usr/sbin/groupadd':
            self.groups[a.NAME]=SimpleNamespace(gr_name=a.NAME,gr_gid=int(argv[argv.index('--gid')+1]),gr_mem=[])
        elif argv[0]=='/usr/sbin/useradd':
            self.users[a.NAME]=SimpleNamespace(pw_name=a.NAME,pw_uid=int(argv[argv.index('--uid')+1]),pw_gid=int(argv[argv.index('--gid')+1]),pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        else:raise AssertionError('unexpected privileged account command')
        return b''
    def provision(self):return self.fixture.call('provision-account')
    def test_visible_receipt_cannot_authorize_nss_until_real_file_and_directory_sync_succeed(self):
        actual=os.fsync
        for failing in range(1,5):
            count=[0]
            def fault(fd):
                count[0]+=1
                if count[0]==failing:raise OSError('inert original-account persistence failure')
                return actual(fd)
            with patch.object(os,'fsync',side_effect=fault):
                with self.assertRaises(OSError):self.provision()
            self.assertEqual(self.calls,[])
            self.assertEqual(c.state_read()['service_uid'],self.original['service_uid'])
        self.provision();self.assertEqual(len(self.calls),2)
        self.provision();self.assertEqual(len(self.calls),2)
        self.assertEqual(c.state_read()['service_gid'],self.original['service_gid'])
    def test_interrupted_user_creation_reuses_both_original_numeric_ids(self):
        original=self.command
        def interrupted(argv,**kwargs):
            result=original(argv,**kwargs)
            if argv[0]=='/usr/sbin/useradd':raise OSError('inert creation response lost')
            return result
        with patch.object(c,'run',side_effect=interrupted):
            with self.assertRaises(OSError):self.provision()
        self.assertEqual(len(self.calls),2);self.provision();self.assertEqual(len(self.calls),2)
        a.verify(c,c.state_read())
    def test_keyed_lookup_profile_and_group_sharing_refuse_without_nss_repair(self):
        self.provision();count=len(self.calls)
        wrong=SimpleNamespace(**dict(vars(self.users[a.NAME]),pw_dir='/changed'))
        with patch.object(a.pwd,'getpwuid',return_value=wrong):
            with self.assertRaises(c.Refused):self.provision()
        self.groups[a.NAME].gr_mem=['foreign']
        with self.assertRaises(c.Refused):self.provision()
        self.groups[a.NAME].gr_mem=[]
        self.users['foreign']=SimpleNamespace(pw_name='foreign',pw_uid=4000,pw_gid=self.original['service_gid'],pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        with self.assertRaises(c.Refused):self.provision()
        self.assertEqual(len(self.calls),count)
    def test_actual_native_execute_refuses_nss_drift_before_any_nonroot_key_staging(self):
        self.provision()
        with patch.object(c,'run',side_effect=self.fixture.command):self.fixture.backed_up()
        state=c.state_read();state.update(phase='installed',installed=c.pin(state),startup_revoked=False)
        c.CONF.mkdir();c.corecell.publish_configuration(c,state)
        (c.ROOT/'data/klay/chaindata').mkdir(parents=True)
        with patch.object(c,'account',side_effect=lambda value:a.verify(c,value)),patch.object(c,'run',side_effect=self.fixture.command), \
             patch.object(c.custody,'materialize') as grant,patch.object(c.os,'execve') as execute:
            c.execute(state);grant.assert_called_once();execute.assert_called_once()
            grant.reset_mock();execute.reset_mock();self.users[a.NAME].pw_uid=2001
            with self.assertRaises(c.Refused):c.execute(state)
            grant.assert_not_called();execute.assert_not_called()

    def test_completed_original_account_is_not_silently_recreated_after_deletion(self):
        self.provision();self.assertTrue(c.state_read()['account_established'])
        count=len(self.calls);del self.users[a.NAME]
        with self.assertRaises(c.Refused):self.provision()
        self.assertEqual(len(self.calls),count)

    def test_primary_gids_and_non_enumerated_keyed_names_are_never_freshly_adopted(self):
        self.users['foreign']=SimpleNamespace(pw_name='foreign',pw_uid=4000,pw_gid=999,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        reserved=a.reserve(c);self.assertEqual(reserved,{'service_uid':998,'service_gid':998})
        with patch.object(a.pwd,'getpwnam',return_value=SimpleNamespace(pw_name=a.NAME)):
            with self.assertRaises(c.Refused):a.reserve(c)
        with patch.object(a.pwd,'getpwuid',side_effect=OSError('unavailable NSS')):
            with self.assertRaises(OSError):a.reserve(c)
        self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()
