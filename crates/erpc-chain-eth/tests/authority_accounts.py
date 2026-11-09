# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric-authority tests with inert NSS and real temporary fsync boundaries."""
import contextlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/authority'))
import eth_accounts as accounts
import eth_files as files
import eth_state as states
import eth_layout as layout


OPEN=os.open


def hold(case,target):
    """Keep the inode of a descriptor or path allocated until the test ends.

    These fixtures emulate ownership per inode. A filesystem may give the
    number of a removed file to the next file it creates, and that file would
    then show the removed file's emulated owner."""
    copy=os.dup(target) if isinstance(target,int) else OPEN(target,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
    case.addCleanup(os.close,copy)


def held(case,path):
    """hold the inode at path and return its (device, inode) key for a per-inode emulation."""
    info=os.stat(path);hold(case,str(path));return (info.st_dev,info.st_ino)


class Accounts(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.users={};self.groups={};self.calls=[];self.foreign=set()
        def install(obj,name,value,**kwargs):return self.stack.enter_context(patch.object(obj,name,value,**kwargs))
        self.install=install
        install(layout,'probe',lambda *_:{'uuid':'12345678-1234-1234-1234-123456789abc','type':'ext4','root':'/'})
        fstat=os.fstat;real_stat=os.stat;ancestors={(p.stat().st_dev,p.stat().st_ino) for p in self.root.parents}
        def metadata(fd):
            value=list(fstat(fd));value[4]=77 if (value[2],value[1]) in self.foreign else 0
            if (value[2],value[1]) in ancestors:value[0]&=~0o022
            return os.stat_result(value)
        install(os,'fstat',metadata)
        def path_metadata(path,*args,**kwargs):
            value=list(real_stat(path,*args,**kwargs));value[4]=77 if (value[2],value[1]) in self.foreign else 0
            return os.stat_result(value)
        install(os,'stat',path_metadata)
        def get(records,field,value):
            for row in records.values():
                if getattr(row,field)==value:return row
            raise KeyError(value)
        for module,prefix,records,methods in [(accounts.pwd,'pw',self.users,('getpwnam','getpwuid','getpwall')),
                                             (accounts.grp,'gr',self.groups,('getgrnam','getgrgid','getgrall'))]:
            install(module,methods[0],lambda value,r=records,p=prefix:get(r,p+'_name',value))
            install(module,methods[1],lambda value,r=records,p=prefix:get(r,p+('_uid' if p=='pw' else '_gid'),value))
            install(module,methods[2],lambda r=records:list(r.values()))
        install(os,'getgrouplist',lambda name,gid:[gid]+[row.gr_gid for row in self.groups.values() if name in row.gr_mem],create=True)
        install(accounts,'run',self.native)
        self.c={'schema':1,'owner':'originalfixture','role':'validator','network':'hoodi','kind':'validator','host_binding':'a'*64}
        self.state=states.State('validator',self.root/'state').reserve(self.c,'b'*64)

    def native(self,argv):
        self.calls.append(argv)
        name=argv[-1]
        if argv[0].endswith('groupadd'):
            self.groups[name]=SimpleNamespace(gr_name=name,gr_gid=int(argv[argv.index('--gid')+1]),gr_mem=[])
        elif argv[0].endswith('useradd'):
            self.users[name]=SimpleNamespace(pw_name=name,pw_uid=int(argv[argv.index('--uid')+1]),
                pw_gid=int(argv[argv.index('--gid')+1]),pw_dir=argv[argv.index('--home-dir')+1],pw_shell='/usr/sbin/nologin')
            if '--groups' in argv:
                for group in argv[argv.index('--groups')+1].split(','):self.groups[group].gr_mem.append(name)
        else:
            self.assertTrue(argv[0].endswith('usermod'))
            for group in self.groups.values():group.gr_mem=[member for member in group.gr_mem if member!=name]
            for group in filter(None,argv[argv.index('--groups')+1].split(',')):self.groups[group].gr_mem.append(name)
        return b''

    def test_original_validator_plan_precedes_nss_and_rechecks_completed_identity(self):
        actual=self.native
        def after_receipt(argv):
            self.assertTrue(self.state.exists('accounts-intent.json'));self.assertTrue(self.state.exists('owner.json'))
            return actual(argv)
        self.install(accounts,'run',after_receipt)
        value=accounts.provision(self.state,'validator')
        self.assertEqual(len(self.calls),9);self.assertEqual(accounts.verify(value),value)
        self.assertEqual(accounts.provision(self.state,'validator'),value);self.assertEqual(len(self.calls),9)
        self.assertEqual(set(os.getgrouplist('ev-validator',value['users']['ev-validator']['gid'])),{value['users']['ev-validator']['gid']})
        self.assertIn(value['groups']['ev-engine'],os.getgrouplist('ev-beacon',value['users']['ev-beacon']['gid']))
        del self.users['ev-validator']
        with self.assertRaises(ValueError):accounts.provision(self.state,'validator')
        self.assertEqual(len(self.calls),9)

    def test_persistent_directory_sync_failure_never_authorizes_nss_on_visible_retry(self):
        original=os.fsync
        def failure(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert persistent directory failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=failure):
            for _ in range(3):
                with self.assertRaises(OSError):accounts.provision(self.state,'validator')
                self.assertEqual(self.calls,[])
        expected=self.state.get('accounts-intent.json')
        self.assertEqual(accounts.provision(self.state,'validator'),expected)

    def test_completed_receipt_visible_after_failure_is_resynced_without_recreation(self):
        original=os.fsync
        def failure(fd):
            if self.state.exists('accounts.json') and stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert completion failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=failure):
            for _ in range(2):
                with self.assertRaises(OSError):accounts.provision(self.state,'validator')
        self.assertEqual(len(self.calls),9);accounts.provision(self.state,'validator');self.assertEqual(len(self.calls),9)

    def test_explicit_migrated_home_metadata_is_preserved_and_drift_is_not_repaired(self):
        plan=accounts.provision(self.state,'validator')
        plan['homes']={name:('/nonexistent' if name=='ev-transport' else '/home/'+name) for name in plan['users']}
        for name,home in plan['homes'].items():self.users[name].pw_dir=home
        accounts.validate(plan,'validator');accounts.verify(plan)
        self.users['ev-validator'].pw_dir='/another-home'
        with self.assertRaises(ValueError):accounts.verify(plan)
        self.assertEqual(self.users['ev-validator'].pw_dir,'/another-home')
        plan['homes']['ev-validator']='/another-home'
        with self.assertRaises(ValueError):accounts.validate(plan,'validator')

    def test_unknown_account_is_not_adopted_and_used_primary_gid_is_not_allocated(self):
        self.users['ev-validator']=SimpleNamespace(pw_name='ev-validator',pw_uid=777,pw_gid=777,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        with self.assertRaises(ValueError):accounts.provision(self.state,'validator')
        self.assertEqual(self.calls,[]);self.assertFalse(self.state.exists('accounts-intent.json'))
        self.users.clear();self.users['other']=SimpleNamespace(pw_name='other',pw_uid=2000,pw_gid=999,pw_dir='/inert',pw_shell='/bin/sh')
        plan=accounts.provision(self.state,'validator');self.assertNotIn(999,plan['groups'].values())

    def test_direct_numeric_alias_and_supplementary_membership_drift_refuse(self):
        plan=accounts.provision(self.state,'validator');before=len(self.calls)
        original=accounts.pwd.getpwuid
        wrong=SimpleNamespace(**dict(vars(self.users['ev-validator']),pw_dir='/foreign'))
        with patch.object(accounts.pwd,'getpwuid',side_effect=lambda uid:wrong if uid==plan['users']['ev-validator']['uid'] else original(uid)):
            with self.assertRaises(ValueError):accounts.verify(plan)
        self.groups['foreign']=SimpleNamespace(gr_name='foreign',gr_gid=77,gr_mem=['ev-validator'])
        with self.assertRaises(ValueError):accounts.provision(self.state,'validator')
        self.assertEqual(len(self.calls),before)

    def test_original_partial_membership_can_finish_but_completed_profile_is_never_repaired(self):
        original=self.native
        def interrupted(argv):
            original(argv)
            if argv[0].endswith('useradd'):
                for group in self.groups.values():group.gr_mem=[]
                raise OSError('inert interrupted supplementary group publication')
        with patch.object(accounts,'run',side_effect=interrupted):
            with self.assertRaises(OSError):accounts.provision(self.state,'validator')
        accounts.provision(self.state,'validator')
        self.assertTrue(any(argv[0].endswith('usermod') for argv in self.calls))
        count=len(self.calls);self.groups['ev-engine'].gr_mem=[]
        with self.assertRaises(ValueError):accounts.provision(self.state,'validator')
        self.assertEqual(len(self.calls),count)

    def test_rpc_shared_group_still_has_distinct_original_users(self):
        self.c.update(role='rpc',network='mainnet',kind='full')
        state=states.State('rpc',self.root/'rpc').reserve(self.c,'b'*64)
        plan=accounts.provision(state,'rpc')
        self.assertEqual(len(plan['groups']),1);self.assertNotEqual(plan['users']['reth']['uid'],plan['users']['lighthouse']['uid'])
        self.assertEqual(plan['users']['reth']['gid'],plan['users']['lighthouse']['gid'])
        self.assertEqual(self.users['reth'].pw_dir,'/var/lib/ethereum/reth')

    def test_state_and_private_read_reject_symlink_hardlink_and_unsafe_ancestor_without_repair(self):
        owner=self.state.path('owner.json');outside=self.root/'outside'
        os.link(owner,outside)
        with self.assertRaises(ValueError):self.state.check(self.c)
        outside.unlink();owner.rename(outside);owner.symlink_to(outside)
        with self.assertRaises(OSError):self.state.check(self.c)
        owner.unlink();outside.rename(owner);self.state.directory.chmod(0o777)
        with self.assertRaises(ValueError):self.state.check(self.c)
        self.assertEqual(self.state.directory.stat().st_mode&0o777,0o777)


if __name__=='__main__':unittest.main()
