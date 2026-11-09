#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Composed controller lifecycle over actual receipts/files and inert OS boundaries."""
import base64
import hashlib
import io
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from authority_prepare import Host, SOURCE
import control
import arc_accounts as accounts
import arc_bootstrap as bootstrap
import arc_custody as custody
import arc_files as files
import arc_helpers as helpers
import arc_migration as migration
import arc_process as process
import arc_protocol as protocol
import arc_release as release
import arc_storage as storage
import arc_units as units


class Metadata:
    def __init__(self, original, owner):
        self.original, self.st_uid, self.st_gid = original, *owner
    def __getattr__(self, name):
        return getattr(self.original, name)


class Model(Host):
    def __init__(self, root):
        super().__init__(root)
        self.calls, self.jobs, self.active = [], [], set()
        self.policy_confirmed = False
        self.cipher = b'inert sealed original public-vector capsule'
        self.mkdir('/etc/systemd/system', mode=0o755)
        self.mkdir('/proc/net', mode=0o755)
        self.mkdir('/opt/erpc', mode=0o755)
        self.write_bytes('/opt/erpc/runs/inert/rpc-firewall.py', b'# inert model only\n', 0o700)

    def command(self, *argv, **kwargs):
        if argv[0] == '/usr/bin/systemctl' and argv[1] != '--version':
            self.calls.append(argv)
            if argv[1] == 'show':
                unit = argv[2]
                values = {'LoadState': 'loaded' if self.path('/etc/systemd/system/' + unit).exists() else 'not-found',
                          'ActiveState': 'active' if unit in self.active else 'inactive', 'MainPID': '0',
                          'ControlGroup': '/system.slice/' + unit, 'Result': 'success', 'ExecMainStatus': '0'}
                return subprocess.CompletedProcess(argv, 0, '\n'.join(k+'='+v for k,v in values.items()).encode(), b'')
            if argv[1] == 'start':
                self.jobs.append(argv[-1])
            if argv[1] == 'stop':
                self.active.discard(argv[-1])
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        if argv[0] == '/usr/bin/du':
            return subprocess.CompletedProcess(argv, 0, b'0\tfixture\n', b'')
        if argv[0] == '/usr/sbin/sysctl':
            return subprocess.CompletedProcess(argv, 0, b'9999999999\n', b'')
        if argv[0] == '/usr/bin/timedatectl':
            return subprocess.CompletedProcess(argv, 0, b'yes\n', b'')
        if argv[0].endswith(('/arc-node-execution','/arc-node-consensus','/arc-snapshots')) and argv[1:] == ('--version',):
            return subprocess.CompletedProcess(argv, 0, b'v0.8.1 aaaaaaaa\n', b'')
        if argv[0] == '/usr/bin/systemd-creds':
            return subprocess.CompletedProcess(argv, 0, self.cipher if argv[1] == 'encrypt' else b'inert public vector', b'')
        return super().command(*argv, **kwargs)

    def common(self):
        c = self
        class Policy:
            def token(self, operation, bundle):
                files.require(operation == 'r-inert' and bundle == 'f'*64, 'inert exact firewall token differs')
            def dispatch(self, action, operation=None, bundle=None):
                if action == 'confirm': c.policy_confirmed = True
            def prepare_guards(self): pass
            def require_guards(self): pass
            def require_confirmed(self, operation, bundle):
                self.token(operation,bundle)
                files.require(c.policy_confirmed, 'firewall not confirmed')
            def guard(self): files.require(c.policy_confirmed, 'firewall not confirmed')
        return Policy()


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.c = Model(self.root)
        self.stack = ExitStack()
        self.owners = {}
        self.real_stat, self.real_fstat = os.stat, os.fstat
        def wrap(value):
            key=(value.st_dev,value.st_ino)
            return Metadata(value,self.owners[key]) if key in self.owners else value
        self.stack.enter_context(patch.object(os,'stat',lambda *args,**kwargs:wrap(self.real_stat(*args,**kwargs))))
        self.stack.enter_context(patch.object(os,'fstat',lambda fd:wrap(self.real_fstat(fd))))
        real_path_stat, real_path_lstat = pathlib.Path.stat, pathlib.Path.lstat
        self.stack.enter_context(patch.object(pathlib.Path,'stat',lambda path,*a,**kw:wrap(real_path_stat(path,*a,**kw))))
        self.stack.enter_context(patch.object(pathlib.Path,'lstat',lambda path,*a,**kw:wrap(real_path_lstat(path,*a,**kw))))
        self.stack.enter_context(patch.object(os,'fchown',lambda fd,uid,gid:self.owners.__setitem__((self.real_fstat(fd).st_dev,self.real_fstat(fd).st_ino),(uid,gid))))
        def named(collection,name):
            if name not in collection: raise KeyError(name)
            return collection[name]
        def numbered(collection,field,number):
            for value in collection.values():
                if getattr(value,field)==number:return value
            raise KeyError(number)
        for fn,impl in [('getpwall',lambda:list(self.c.users.values())),('getpwnam',lambda x:named(self.c.users,x)),('getpwuid',lambda x:numbered(self.c.users,'pw_uid',x))]:
            self.stack.enter_context(patch.object(accounts.pwd,fn,impl))
        for fn,impl in [('getgrall',lambda:list(self.c.groups.values())),('getgrnam',lambda x:named(self.c.groups,x)),('getgrgid',lambda x:numbered(self.c.groups,'gr_gid',x))]:
            self.stack.enter_context(patch.object(accounts.grp,fn,impl))
        self.stack.enter_context(patch.object(os,'getgrouplist',lambda name,gid:[gid]))
        self.stack.enter_context(patch.object(os,'statvfs',lambda path:types.SimpleNamespace(f_bavail=3_000_000_000_000,f_frsize=1,f_blocks=4_000_000_000_000,f_bfree=3_000_000_000_000)))
        self.stack.enter_context(patch.object(control,'__file__',str(self.c.source/'control.py')))
        self.stack.enter_context(patch.object(migration,'__file__',str(self.c.source/'arc_migration.py')))
        self.public=base64.b64encode(bytes([1])*32).decode()
        self.stack.enter_context(patch.object(custody,'public',lambda c,raw:self.public))
        self.contract={'owner':'i'*26,'network':'testnet','chain_id':5042002,
                       'genesis_hash':protocol.NETWORKS['testnet']['genesis_hash'],'public_key':self.public,
                       'rpc_type':'full','host_key_sha256':'a'*64}
        self.helper=helpers.source(self.c,self.c.source)[2]
        self.call('prepare',helpers=self.helper)
        self.call('credential-import',key={'fixture':'public inert vector'})
        self.target={'version':'v0.8.1','commit':'a'*40,'archive_sha256':'b'*64,'platform':'x86_64-unknown-linux-gnu'}
        self.policy={'rpc_allow':[],'monitoring_allow':[],'management_allow':[],'ssh_port':22,
                     'debug_api':False,'trusted_peers':[],'sentry_peers':[]}
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as tar:
            for name in release.BINARIES:
                raw=b'inert native '+name.encode();item=tarfile.TarInfo(name);item.size=len(raw)
                tar.addfile(item,io.BytesIO(raw))
        self.archive=stream.getvalue()
        self.target['archive_sha256']=files.digest(self.archive)
        self.stack.enter_context(patch.object(release,'QUALIFIED_VERSION',self.target['version']))
        self.stack.enter_context(patch.object(release,'QUALIFIED_COMMIT',self.target['commit']))
        self.stack.enter_context(patch.dict(release.QUALIFIED_ARCHIVES,{self.target['platform']:self.target['archive_sha256']}))
        self.intent='b'*32

    def tearDown(self):
        self.stack.close();self.tmp.cleanup()

    def call(self,action,**extra):
        return self.c.dispatch({'schema':control.SCHEMA,'action':action,'contract':self.contract,**extra})

    def install(self):
        self.call('reserve',intent=self.intent,target=self.target,policy=self.policy)
        self.call('firewall-prepare',intent=self.intent,helpers=self.helper)
        self.call('firewall-confirm',intent=self.intent,operation='r-inert',bundle='f'*64)
        begin=self.call('begin-install',intent=self.intent,firewall_operation='r-inert',firewall_bundle='f'*64)
        self.c.write_bytes(begin['archive'],self.archive)
        return self.call('install',intent=self.intent)

    def native_snapshot(self):
        state=self.c.state(self.contract)
        with self.c.lock():self.c.guard(state,'snapshots',opening=True)
        stage=self.c.path('/var/lib/arc/bootstrap')
        for name,db in [('execution','db/mdbx.dat'),('consensus','store.db')]:
            folder=stage/name;folder.mkdir()
            database=folder/db;database.parent.mkdir(exist_ok=True)
            database.write_bytes(b'original inert block history')
            (folder/'.snapshot-url').write_text('public native snapshot fixture')
            for path in [folder,*folder.rglob('*')]:
                value=self.real_stat(path,follow_symlinks=False)
                self.owners[(value.st_dev,value.st_ino)]=(state['service_uid'],state['service_gid'])
        with self.c.lock():
            state=self.c.state(self.contract);bootstrap.completed(self.c,state)

    def test_prepare_install_bootstrap_promote_preserves_one_original_identity(self):
        old=self.c.read(custody.CREDENTIAL)
        self.assertEqual(self.install()['phase'],'bootstrap')
        self.assertEqual(self.c.jobs,['arc-snapshots.service'])
        self.native_snapshot()
        result=self.call('activate',intent=self.intent)
        self.assertTrue(result['startup_requested'])
        state=self.c.state(self.contract)
        self.assertTrue(state['bootstrap_complete'])
        self.assertEqual(self.c.read(custody.CREDENTIAL),old)
        self.assertEqual((self.c.path('/var/lib/arc/execution/db/mdbx.dat')).read_bytes(),b'original inert block history')
        self.assertEqual(self.c.jobs[-2:],['arc-execution.service','arc-consensus.service'])
        self.assertEqual(state['source_floor']['version'],'v0.8.1')
        for component in process.UNITS:
            text=self.c.read('/etc/systemd/system/'+process.UNITS[component]).decode()
            self.assertIn('User='+str(state['service_uid'])+'\n',text)
            self.assertIn('ExecCondition=+/usr/bin/python3 -I -c ',text)

    def test_stop_during_initial_bootstrap_revokes_stale_completion_and_activation(self):
        self.install()
        self.call('stop',layer='both')
        before=list(self.c.jobs)
        with self.assertRaises(files.Refused):self.call('activate',intent=self.intent)
        with self.c.lock(),self.assertRaises(files.Refused):
            bootstrap.completed(self.c,self.c.state(self.contract))
        self.assertEqual(self.c.jobs,before)

    def test_owned_bootstrap_quarantine_is_explicit_and_never_resets_active_history(self):
        self.install()
        stage=self.c.path('/var/lib/arc/bootstrap')
        (stage/'partial').write_text('retained unfinished payload')
        result=self.call('reset-bootstrap',intent=self.intent)
        self.assertEqual((self.c.path('/var/lib/arc')/result['retained']/'partial').read_text(),'retained unfinished payload')
        self.intent='c'*32
        self.install();self.native_snapshot();self.call('activate',intent=self.intent)
        state=self.c.state(self.contract);state['native_started']=True;self.c.save(state)
        with self.assertRaises(files.Refused):self.call('reset-bootstrap',intent=self.intent)
        self.assertTrue(self.c.path('/var/lib/arc/execution/db/mdbx.dat').exists())

    def test_lost_reset_acknowledgement_repeats_the_same_quarantine_without_losing_bytes(self):
        self.install()
        (self.c.path('/var/lib/arc/bootstrap')/'partial').write_text('original partial')
        first=self.call('reset-bootstrap',intent=self.intent)
        second=self.call('reset-bootstrap',intent=self.intent)
        self.assertEqual(first,second)
        self.assertEqual((self.c.path('/var/lib/arc')/first['retained']/'partial').read_text(),'original partial')
        self.assertFalse(self.c.path('/var/lib/arc/bootstrap').exists())

    def test_first_condition_refuses_changed_original_account_before_any_model_grant(self):
        self.install();self.native_snapshot();self.call('activate',intent=self.intent)
        self.c.users['arc'].pw_uid+=1
        with self.c.lock(),self.assertRaises(files.Refused):
            self.c.guard(self.c.state(self.contract),'consensus',opening=False)

    def test_long_run_cannot_use_another_confirmed_preparation(self):
        self.call('reserve',intent=self.intent,target=self.target,policy=self.policy)
        self.call('firewall-prepare',intent=self.intent,helpers=self.helper)
        self.call('firewall-confirm',intent=self.intent,operation='r-inert',bundle='f'*64)
        with self.assertRaises(files.Refused):
            self.call('begin-install',intent=self.intent,firewall_operation='r-another',firewall_bundle='f'*64)
        self.assertFalse(self.c.path('/opt/arc/downloads').exists())


if __name__=='__main__':unittest.main()
