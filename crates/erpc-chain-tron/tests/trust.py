# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Privileged destination and original account boundaries, without root or NSS writes."""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/jinja'))


def fixture():
    spec=importlib.util.spec_from_file_location('tron_trust_fixtures',ROOT/'tests/control_paths.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    value=module.ControlPaths();value.setUp();return value


@unittest.skipUnless(os.name=='posix','root/NSS host authority uses POSIX semantics')
class RuntimeAccount(unittest.TestCase):
    def setUp(self):
        import accounts
        self.module=accounts;self.f=fixture();self.addCleanup(self.f.doCleanups)
        self.c=self.f.control;self.users=[];self.groups=[];self.extra=[]
        self.account=accounts.Accounts(self.c,lambda:self.users,lambda:self.groups,lambda name,gid:[gid,*self.extra])
        self.c.accounts=self.account
        original=self.c.run
        def run(args,**kwargs):
            if args[0]=='/usr/sbin/groupadd':
                record=self.account.record(self.f.expected);self.assertEqual(record['state'],'reserved')
                self.groups.append(SimpleNamespace(gr_name='tron',gr_gid=int(args[args.index('--gid')+1]),gr_mem=[]))
            if args[0]=='/usr/sbin/useradd':
                record=self.account.record(self.f.expected);self.assertEqual(record['state'],'reserved')
                self.users.append(SimpleNamespace(pw_name='tron',pw_uid=int(args[args.index('--uid')+1]),
                    pw_gid=int(args[args.index('--gid')+1]),pw_dir='/var/lib/tron',pw_shell='/usr/sbin/nologin'))
            return original(args,**kwargs)
        self.c.run=run
    def test_unknown_account_or_group_is_refused_before_initial_host_mutation(self):
        for kind in ('user','group'):
            if kind=='user':self.users=[SimpleNamespace(pw_name='tron',pw_uid=1001,pw_gid=1001,pw_dir='/home/old',pw_shell='/bin/bash')]
            else:self.users=[];self.groups=[SimpleNamespace(gr_name='tron',gr_gid=1001,gr_mem=[])]
            before=len(self.f.calls)
            with self.assertRaises(ValueError):self.c.contract(self.f.expected,initial=True)
            with self.assertRaises(ValueError):self.account.provision(self.f.expected)
            self.assertEqual(len(self.f.calls),before)
            self.assertFalse(self.c.path(self.module.RECEIPT).exists())
    def test_reserved_uid_gid_precede_nss_mutation_and_exact_account_is_pinned(self):
        self.c.dispatch('provision-account',self.f.expected)
        record=self.account.verify(self.f.expected)
        self.assertEqual(record['state'],'established');self.assertEqual(record['uid'],999);self.assertEqual(record['gid'],999)
        before=len(self.f.calls);self.c.dispatch('provision-account',self.f.expected)
        self.assertEqual(len(self.f.calls),before)
    def test_failed_reservation_never_creates_an_account(self):
        with patch.object(self.c,'write',side_effect=OSError('inert reservation sync failure')):
            with self.assertRaises(OSError):self.account.provision(self.f.expected)
        self.assertFalse(self.users);self.assertFalse(self.groups)
    def test_interrupted_group_and_user_creation_resume_only_reserved_identity(self):
        original=self.c.command;failed=[]
        def after_group(*args,**kwargs):
            value=original(*args,**kwargs)
            if args[0]=='/usr/sbin/groupadd' and not failed:failed.append(True);raise OSError('inert interrupted group creation')
            return value
        with patch.object(self.c,'command',side_effect=after_group):
            with self.assertRaises(OSError):self.account.provision(self.f.expected)
        self.assertFalse(self.users);self.assertEqual(len(self.groups),1)
        def after_user(*args,**kwargs):
            value=original(*args,**kwargs)
            if args[0]=='/usr/sbin/useradd':raise OSError('inert interrupted user creation')
            return value
        with patch.object(self.c,'command',side_effect=after_user):
            with self.assertRaises(OSError):self.account.provision(self.f.expected)
        self.assertEqual(len(self.users),1);self.assertEqual(self.account.record(self.f.expected)['state'],'reserved')
        self.account.provision(self.f.expected)
        self.assertEqual(self.account.verify(self.f.expected)['state'],'established')
    def test_account_group_and_membership_drift_refuse_start_but_allow_stop(self):
        self.account.provision(self.f.expected);self.f.prepare();self.f.activate(self.f.policy())
        original=copy.deepcopy(self.users[0]);group=copy.deepcopy(self.groups[0])
        for kind in ('uid','gid','home','shell','extra','group-name','group-member','alias'):
            self.users=[copy.deepcopy(original)];self.groups=[copy.deepcopy(group)];self.extra=[]
            if kind=='uid':self.users[0].pw_uid+=1
            elif kind=='gid':self.users[0].pw_gid+=1
            elif kind=='home':self.users[0].pw_dir='/home/another'
            elif kind=='shell':self.users[0].pw_shell='/bin/bash'
            elif kind=='extra':self.extra=[998]
            elif kind=='group-name':self.groups[0].gr_name='other'
            elif kind=='group-member':self.groups[0].gr_mem=['another-user']
            else:self.users.append(SimpleNamespace(**dict(vars(original),pw_name='alias')))
            with self.assertRaises(ValueError):self.c.runtime(self.f.expected)
            with self.assertRaises(ValueError):self.c.dispatch('start',self.f.expected)
            self.c.dispatch('stop',self.f.expected)
            self.assertFalse(self.f.active)
        self.c.dispatch('guard-stop',self.f.expected)
        self.c.dispatch('destroy',self.f.expected)
    def test_carried_stop_keeps_legacy_recovery_without_reacquiring_the_run_lock(self):
        import threading
        self.c.accounts=type('LegacyBootstrap',(),{'verify':lambda *_:None,'retained_uid':lambda *_:None})()
        self.f.prepare();self.f.activate(self.f.policy());self.c.accounts=self.account
        errors=[]
        def stop():
            try:self.c.dispatch('stop-play',self.f.expected)
            except Exception as error:errors.append(error)
        with self.f.lock():
            thread=threading.Thread(target=stop,daemon=True);thread.start();thread.join(2)
            self.assertFalse(thread.is_alive(),'carried stop must not wait on its parent operation lock')
        self.assertFalse(errors);self.assertFalse(self.f.active)

    def test_actual_launcher_refuses_extra_groups_before_opening_credentials(self):
        import launch
        contract=self.f.expected;record={'format':1,'state':'established','contract':contract,'uid':999,'gid':999}
        with patch.object(launch.os,'getuid',return_value=999),patch.object(launch.os,'geteuid',return_value=999), \
                patch.object(launch.os,'getgid',return_value=999),patch.object(launch.os,'getegid',return_value=999):
            with patch.object(launch.os,'getgroups',return_value=[999]):launch.runtime_account(contract,record)
            with patch.object(launch.os,'getgroups',return_value=[999,998]):
                with self.assertRaises(ValueError):launch.runtime_account(contract,record)

    def test_legacy_without_receipt_never_claims_implicit_account_migration(self):
        self.c.accounts=self.f.control.accounts=type('LegacyBootstrap',(),{'verify':lambda *_:None,'retained_uid':lambda *_:None})()
        self.f.prepare();self.f.activate(self.f.policy())
        self.c.accounts=self.account
        with self.assertRaises(ValueError):self.c.runtime(self.f.expected)
        with self.assertRaises(ValueError):self.f.prepare('b'*32)
        self.c.dispatch('stop',self.f.expected);self.assertFalse(self.f.active)
        self.c.dispatch('guard-stop',self.f.expected);self.c.dispatch('destroy',self.f.expected)


@unittest.skipUnless(os.name=='posix','managed paths use POSIX metadata')
class Namespaces(unittest.TestCase):
    def setUp(self):
        self.f=fixture();self.addCleanup(self.f.doCleanups);self.c=self.f.control
    def test_every_privileged_namespace_rejects_symlink_or_writable_parent_before_mutation(self):
        for logical in ('/usr/local/lib/erpc','/etc/credstore.encrypted','/etc/erpc','/opt/tron/releases','/etc/systemd/system'):
            path=self.c.path(logical);path.mkdir(parents=True,exist_ok=True)
            saved=path.with_name(path.name+'-original');path.rename(saved)
            outside=self.c.path('/redirect-'+path.name);outside.mkdir();outside.chmod(0o777)
            path.symlink_to(outside,target_is_directory=True)
            before=len(self.f.calls)
            with self.assertRaises(ValueError):self.c.contract(self.f.expected,initial=True)
            with self.assertRaises(ValueError):self.f.prepare()
            self.assertEqual(len(self.f.calls),before);self.assertTrue(path.is_symlink());self.assertFalse(any(outside.iterdir()))
            path.unlink();saved.rename(path);outside.rmdir()
            mode=path.stat().st_mode&0o777;path.chmod(0o777)
            with self.assertRaises(ValueError):self.c.contract(self.f.expected,initial=True)
            self.assertEqual(path.stat().st_mode&0o777,0o777);path.chmod(mode)
    def test_common_firewall_and_controller_content_cannot_be_unsafe_existing_files(self):
        for logical in ('/usr/local/lib/erpc/rpc-firewall.py','/usr/local/lib/erpc/tron/control.py',
                '/etc/tron/logback.xml','/etc/systemd/system/tron-node.service'):
            path=self.c.path(logical);path.parent.mkdir(parents=True,exist_ok=True);path.write_text('inert');path.chmod(0o666)
            with self.assertRaises(ValueError):self.c.namespaces()
            path.chmod(0o600);path.unlink()
    def test_all_service_dropins_are_checked_before_initial_owner_and_startup(self):
        for unit in ('tron-node.service','erpc-tron-firewall.service'):
            directory=self.c.path('/etc/systemd/system/'+unit+'.d');directory.mkdir(parents=True)
            file=directory/'override.conf';file.write_text('[Service]\nUser=root\n');file.chmod(0o666)
            before=len(self.f.calls)
            with self.assertRaises(ValueError):self.c.contract(self.f.expected,initial=True)
            with self.assertRaises(ValueError):self.f.prepare()
            self.assertEqual(len(self.f.calls),before)
            file.unlink();file.symlink_to(self.c.path('/etc/tron/contract.json'))
            with self.assertRaises(ValueError):self.c.namespaces()
            file.unlink();nested=directory/'nested';nested.mkdir();(nested/'override.conf').write_text('inert');(nested/'override.conf').chmod(0o666)
            with self.assertRaises(ValueError):self.c.namespaces()
            shutil.rmtree(directory)

    def test_safe_existing_namespace_and_narrow_root_owned_pointers_are_accepted(self):
        self.c.namespaces();self.f.prepare();self.f.activate(self.f.policy());self.c.namespaces()

try:
    import ansible
    import yaml
    ANSIBLE=True
except ImportError:
    ANSIBLE=False


@unittest.skipUnless(ANSIBLE and os.name=='posix','actual publication probe requires pinned Ansible runtime')
class Publication(unittest.TestCase):
    def test_actual_guard_then_ansible_copy_refuses_unsafe_namespace_without_repair(self):
        import getpass
        for kind in ('protected','symlink','writable','target-link'):
            with self.subTest(kind=kind):
                f=fixture()
                try:
                    c=f.control;namespace=c.path('/usr/local/lib/erpc/tron');namespace.parent.mkdir(parents=True,exist_ok=True)
                    outside=c.path('/outside');outside.mkdir()
                    if kind=='symlink':namespace.symlink_to(outside,target_is_directory=True)
                    elif kind=='writable':namespace.parent.chmod(0o777)
                    elif kind=='target-link':
                        namespace.mkdir();(outside/'inert').write_text('unchanged');(namespace/'control.py').symlink_to(outside/'inert')
                    wrapper=c.path('/guard-fixture.py')
                    wrapper.write_text('import os,sys; sys.dont_write_bytecode=True; from pathlib import Path; sys.path.insert(0,'+repr(str(ROOT/'templates/jinja'))+'); import control; control.Control(root=Path('+repr(str(c.root))+'),owner=os.getuid()).namespaces()')
                    carried=c.path('/inert-source.py');carried.write_text('inert reviewed helper bytes')
                    tasks=[{'name':'Carried destination guard','ansible.builtin.command':{'argv':[sys.executable,'-I',str(wrapper)]}},
                        {'ansible.builtin.file':{'path':str(namespace),'state':'directory','owner':getpass.getuser(),'group':str(os.getgid()),'mode':'0755'}},
                        {'ansible.builtin.copy':{'src':str(carried),'dest':str(namespace/'control.py'),'owner':getpass.getuser(),'group':str(os.getgid()),'mode':'0755'}}]
                    play=c.path('/publication.yml');play.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,'tasks':tasks}]))
                    result=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(play)],capture_output=True,text=True)
                    if kind=='protected':
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        self.assertEqual((namespace/'control.py').read_text(),carried.read_text())
                    else:
                        self.assertNotEqual(result.returncode,0)
                        if kind=='symlink':self.assertTrue(namespace.is_symlink());self.assertFalse(any(outside.iterdir()))
                        if kind=='writable':self.assertEqual(namespace.parent.stat().st_mode&0o777,0o777);self.assertFalse(namespace.exists())
                        if kind=='target-link':self.assertTrue((namespace/'control.py').is_symlink());self.assertEqual((outside/'inert').read_text(),'unchanged')
                finally:f.doCleanups()

if __name__=='__main__':unittest.main()
