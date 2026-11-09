#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert NSS/account-command fixtures with actual durable reservation files."""
import os
import stat
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_accounts as accounts
import native_files as files
import native_state as lifecycle


class AccountReservation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.state_path=self.root/'state';self.state_path.mkdir()
        self.users={};self.groups={};self.memberships={};self.calls=[]
        self.contract={'network':'testnet','owner':'inert'}
        self.state=lifecycle.State(self.state_path)
        self.patches=[]
        def install(obj,name,value):
            item=patch.object(obj,name,value);item.start();self.patches.append(item)
        install(lifecycle,'read',lambda path,maximum:files.read(path,maximum,os.getuid()))
        install(accounts,'TRUST_ANCHOR',self.root)
        install(accounts,'sync_file',lambda path:files.sync_file(path,os.getuid()))
        install(accounts,'read',lambda path,maximum:files.read(path,maximum,os.getuid()))
        self.state.reserve(self.contract)
        specs={role:(name,str(self.root/role)) for role,(name,_) in accounts.SPECS.items()}
        install(accounts,'SPECS',specs)
        def get(values,key,field):
            for value in values.values():
                if getattr(value,field)==key:return value
            raise KeyError(key)
        install(accounts.pwd,'getpwnam',lambda key:get(self.users,key,'pw_name'))
        install(accounts.pwd,'getpwuid',lambda key:get(self.users,key,'pw_uid'))
        install(accounts.pwd,'getpwall',lambda:list(self.users.values()))
        install(accounts.grp,'getgrnam',lambda key:get(self.groups,key,'gr_name'))
        install(accounts.grp,'getgrgid',lambda key:get(self.groups,key,'gr_gid'))
        install(accounts.grp,'getgrall',lambda:list(self.groups.values()))
        install(accounts.os,'getgrouplist',lambda name,gid:self.memberships.get(name,[gid]))
        # Root path authority itself is tested by native_files/toolchain tests;
        # this unprivileged fixture creates only its private temporary homes.
        def directory(path,create=False):
            if create:path.mkdir(mode=0o755,parents=True,exist_ok=True)
            if not path.is_dir() or path.is_symlink():raise ValueError('fixture directory unavailable')
        install(accounts,'root_directory',directory)

    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.tmp.cleanup()

    def account_command(self,args):
        self.assertTrue((self.state_path/'accounts-intent.json').exists(),'NSS mutation before durable reservation')
        self.calls.append(args)
        name=args[-1]
        if args[0].endswith('/groupadd'):
            self.groups[name]=types.SimpleNamespace(gr_name=name,gr_gid=int(args[args.index('--gid')+1]),gr_mem=[])
        elif args[0].endswith('/useradd'):
            self.users[name]=types.SimpleNamespace(pw_name=name,pw_uid=int(args[args.index('--uid')+1]),
                pw_gid=int(args[args.index('--gid')+1]),pw_dir=args[args.index('--home-dir')+1],pw_shell=args[args.index('--shell')+1])
        else:self.fail('unqualified account command')

    def test_original_migration_marker_allows_only_explicit_scoped_account_reservation(self):
        # Use the production node-home layout and a pending migration marker.
        # Ordinary init cannot interpret this as a fresh empty service home.
        for path in self.state_path.iterdir():path.unlink()
        scope={'intent':'a'*32,'source_sha256':'b'*64}
        self.state=lifecycle.State(self.state_path,scope)
        self.state.put('migration.json',{'contract':self.contract,'scope':scope,'phase':'preparing'})
        specs=dict(accounts.SPECS);specs['node']=(specs['node'][0],str(self.root))
        with patch.object(lifecycle,'sync_file',lambda p:files.sync_file(p,os.getuid())),patch.object(accounts,'SPECS',specs):
            self.state.reserve(self.contract)
            pending=self.state_path/('.erpc-'+'c'*32);pending.write_bytes(b'unpublished inert public bytes');pending.chmod(0o600)
            with self.assertRaises(ValueError):accounts.ensure(lifecycle.State(self.state_path),self.contract,self.account_command)
            self.assertEqual(self.calls,[])
            plan=accounts.ensure(self.state,self.contract,self.account_command)
            self.assertEqual(accounts.verify(self.state,self.contract),plan)
            self.assertEqual(self.state.get('owner.json')['migration'],scope)

    def test_creation_and_interrupted_group_creation_preserve_original_ids(self):
        def interrupted(args):
            self.account_command(args)
            raise OSError('interrupted after group creation')
        with self.assertRaises(OSError):accounts.ensure(self.state,self.contract,interrupted)
        planned=self.state.get('accounts-intent.json')['accounts']
        ready=accounts.ensure(self.state,self.contract,self.account_command)
        self.assertEqual(ready,planned)
        self.assertEqual(len(self.groups),3);self.assertEqual(len(self.users),3)
        count=len(self.calls)
        self.assertEqual(accounts.ensure(self.state,self.contract,self.account_command),ready)
        self.assertEqual(len(self.calls),count,'retry must not modify an existing account')

    def test_real_host_layout_reserves_accounts_with_only_its_initialized_state_inside_node_home(self):
        node = Path(accounts.SPECS['node'][1]); node.mkdir()
        nested = node / 'state'; self.state_path.rename(nested)
        self.state_path = nested; self.state = lifecycle.State(nested)
        unknown = nested / 'unowned'; unknown.write_text('retain')
        with self.assertRaises(ValueError): accounts.ensure(self.state, self.contract, self.account_command)
        self.assertEqual(self.calls, []); unknown.unlink()
        plan = accounts.ensure(self.state, self.contract, self.account_command)
        self.assertEqual(plan['node']['home'], str(node)); self.assertEqual(len(self.calls), 6)

    def test_unknown_existing_user_or_group_is_refused_before_any_intent_or_command(self):
        name,_=accounts.SPECS['node']
        self.groups[name]=types.SimpleNamespace(gr_name=name,gr_gid=20000,gr_mem=[])
        with self.assertRaises(ValueError):accounts.ensure(self.state,self.contract,self.account_command)
        self.assertFalse((self.state_path/'accounts-intent.json').exists());self.assertEqual(self.calls,[])
        self.groups.clear()
        self.users[name]=types.SimpleNamespace(pw_name=name,pw_uid=20000,pw_gid=20000,pw_dir='/inert',pw_shell='/bin/sh')
        with self.assertRaises(ValueError):accounts.ensure(self.state,self.contract,self.account_command)
        self.assertFalse((self.state_path/'accounts-intent.json').exists());self.assertEqual(self.calls,[])

    def test_unenumerated_numeric_id_is_skipped_before_durable_reservation(self):
        original = accounts.pwd.getpwuid
        hidden = types.SimpleNamespace(pw_name='directory-user', pw_uid=20000)
        with patch.object(accounts.pwd, 'getpwuid', side_effect=lambda uid: hidden if uid == 20000 else original(uid)):
            plan = accounts.ensure(self.state, self.contract, self.account_command)
        self.assertEqual(plan['node']['uid'], 20001)
        self.assertNotIn(20000, [record['uid'] for record in plan.values()])
        self.assertEqual(self.state.get('accounts-intent.json')['accounts'], plan)

    def test_numeric_lookup_cannot_disagree_with_named_original_profile(self):
        plan = accounts.ensure(self.state, self.contract, self.account_command)
        record = plan['node']; original = accounts.pwd.getpwuid
        changed = types.SimpleNamespace(**dict(vars(self.users[record['name']]), pw_dir='/inert/other'))
        with patch.object(accounts.pwd, 'getpwuid', side_effect=lambda uid: changed if uid == record['uid'] else original(uid)):
            with self.assertRaises(ValueError): accounts.verify(self.state, self.contract)

    def test_membership_uid_gid_home_shell_and_shared_identity_drift_are_refused(self):
        plan=accounts.ensure(self.state,self.contract,self.account_command);record=plan['node'];name=record['name'];user=self.users[name]
        count=len(self.calls)
        for field,value in [('pw_uid',0),('pw_gid',0),('pw_dir','/inert/other'),('pw_shell','/bin/sh')]:
            old=getattr(user,field);setattr(user,field,value)
            with self.subTest(field=field),self.assertRaises(ValueError):accounts.verify(self.state,self.contract)
            setattr(user,field,old)
        self.memberships[name]=[record['gid'],0]
        with self.assertRaises(ValueError):accounts.verify(self.state,self.contract)
        self.memberships.clear()
        self.users['alias']=types.SimpleNamespace(pw_name='alias',pw_uid=record['uid'],pw_gid=42,pw_dir='/inert',pw_shell='/bin/sh')
        with self.assertRaises(ValueError):accounts.verify(self.state,self.contract)
        del self.users['alias']
        self.groups[name].gr_mem=['foreign']
        with self.assertRaises(ValueError):accounts.verify(self.state,self.contract)
        self.assertEqual(len(self.calls),count,'identity drift must not be repaired by silently changing accounts')

    def test_visible_intent_after_failed_directory_sync_cannot_mutate_nss_on_retry(self):
        real = os.fsync
        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('inert persistent directory sync failure')
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fail):
            with self.assertRaises(OSError): accounts.ensure(self.state, self.contract, self.account_command)
            planned = self.state.get('accounts-intent.json')['accounts']
            self.assertEqual(self.calls, [])
            with self.assertRaises(OSError): accounts.ensure(self.state, self.contract, self.account_command)
            self.assertEqual(self.calls, [], 'visible intent must not bypass durable namespace checks')
        self.assertEqual(accounts.ensure(self.state, self.contract, self.account_command), planned)
        self.assertEqual(len(self.calls), 6)

    def test_visible_final_receipt_is_resynchronized_before_successful_retry(self):
        real = os.fsync
        def fail(fd):
            if (self.state_path / 'accounts.json').exists() and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('inert final receipt directory sync failure')
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fail):
            with self.assertRaises(OSError): accounts.ensure(self.state, self.contract, self.account_command)
            self.assertTrue((self.state_path / 'accounts.json').exists())
            self.assertEqual(len(self.calls), 6)
            with self.assertRaises(OSError): accounts.ensure(self.state, self.contract, self.account_command)
            self.assertEqual(len(self.calls), 6)
        wanted = self.state.get('accounts-intent.json')['accounts']
        self.assertEqual(accounts.ensure(self.state, self.contract, self.account_command), wanted)
        self.assertEqual(len(self.calls), 6)

    def test_unflushed_namespace_ancestor_blocks_all_account_commands(self):
        real = accounts.sync_directory
        def fail(path):
            if path == self.root: raise OSError('inert namespace ancestor sync failure')
            return real(path)
        with patch.object(accounts, 'sync_directory', side_effect=fail):
            with self.assertRaises(OSError): accounts.ensure(self.state, self.contract, self.account_command)
        self.assertEqual(self.calls, [])
        accounts.ensure(self.state, self.contract, self.account_command)
        self.assertEqual(len(self.calls), 6)

    def test_first_reservation_failure_and_foreign_contract_never_run_account_commands(self):
        original=self.state.put
        def failed(name,value):
            if name=='accounts-intent.json':raise OSError('inert storage failure')
            original(name,value)
        with patch.object(self.state,'put',failed),self.assertRaises(OSError):
            accounts.ensure(self.state,self.contract,self.account_command)
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):accounts.ensure(self.state,dict(self.contract,network='mainnet'),self.account_command)
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
