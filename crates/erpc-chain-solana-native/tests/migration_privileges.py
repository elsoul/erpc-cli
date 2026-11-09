# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real durable policy files with inert NSS, sshd, sudo and account mutations."""
import grp
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_files
import native_migration_privileges as migration


class Retirement(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.store=self.root/'receipt';self.store.mkdir(mode=0o700)
        for name in ('etc/ssh/sshd_config.d','etc/sudoers.d'):(self.root/name).mkdir(parents=True,mode=0o755)
        self.policy=b'root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n'+migration.SUDO_GRANT+b'@includedir /etc/sudoers.d\n'
        self.write('/etc/sudoers',self.policy,0o440)
        self.write('/etc/ssh/sshd_config',b'Include /etc/ssh/sshd_config.d/*.conf\nPubkeyAuthentication yes\n')
        self.write('/etc/nsswitch.conf',b'passwd: files\ngroup: files\nsudoers: files\n')
        self.write('/etc/sudo.conf',b'# default sudoers plugin\n')
        for name in ('passwd','group','shadow','gshadow'):self.write('/etc/'+name,b'inert original metadata\n',0o600)
        self.scope={'intent':'a'*32,'source_sha256':'b'*64,'uid':1001,'gid':1101,'manager':'operator','manager_uid':1002,'ssh_port':2222}
        self.shell='/bin/bash';self.groups=[1101,27];self.password='P';self.expires='never'
        self.commands=[];self.foreign=False;self.writer=False;self.manager_ok=True;self.manager_uid=1002;self.sudo_denial=True
        self.fail_action=None
        def trusted(path,create=False,mode=0o755):
            self.assertTrue(path==self.root or self.root in path.parents)
            if create:path.mkdir(exist_ok=True,mode=mode)
            info=path.lstat()
            migration.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022,'untrusted fixture namespace')
        def sync(path,owner=0):return native_files.sync_file(path,os.getuid())
        patches={'ROOT':self.root,'STORE':self.store,'ROOT_UID':os.getuid(),'root_directory':trusted,'sync_file':sync}
        for name,value in patches.items():self.patch(migration,name,value)
        self.patch(pwd,'getpwall',self.users);self.patch(grp,'getgrall',self.group_records)
        self.patch(pwd,'getpwnam',lambda name:next(v for v in self.users() if v.pw_name==name))
        self.patch(pwd,'getpwuid',lambda uid:next(v for v in self.users() if v.pw_uid==uid))
        self.patch(grp,'getgrnam',lambda name:next(v for v in self.group_records() if v.gr_name==name))
        self.patch(grp,'getgrgid',lambda gid:next(v for v in self.group_records() if v.gr_gid==gid))
        self.patch(os,'getgrouplist',lambda name,gid:list(self.groups))
        self.revocation=migration.Revocation(self.scope,self.authorize,self.quiet,self.command)
    def patch(self,target,name,value):
        item=patch.object(target,name,value);item.start();self.addCleanup(item.stop)
    def write(self,name,data,mode=0o644):
        path=self.root/name.lstrip('/')
        if path.exists():path.chmod(0o600)
        path.write_bytes(data);path.chmod(mode);return path
    def users(self):
        return [pwd.struct_passwd(('solv','x',1001,1101,'','/home/solv',self.shell)),
                pwd.struct_passwd(('operator','x',self.manager_uid,1102,'','/home/operator','/bin/bash'))]
    def group_records(self):
        return [grp.struct_group(('solv','x',1101,[])),grp.struct_group(('sudo','x',27,['solv','operator'] if 27 in self.groups else ['operator'])),
                grp.struct_group(('operator','x',1102,[]))]
    def authorize(self,scope):
        self.assertEqual(scope,self.scope);migration.require(not self.foreign,'original source changed')
    def quiet(self,uid):
        self.assertEqual(uid,1001);migration.require(not self.writer,'original writer remains')
    def command(self,args):
        self.commands.append(args)
        if self.fail_action==args[0]:raise OSError('inert command interruption')
        stdout=b'';status=0
        if args[0]=='/usr/bin/sudo':
            if args[1:3]==['-n','-u']:status=0 if self.manager_ok else 1
            else:
                status=1 if self.sudo_denial else 0
                stdout=b'User solv is not allowed to run sudo on fixture.\n' if self.sudo_denial else b'allowed\n'
        elif args[0]=='/usr/sbin/sshd' and args[1]=='-T':
            stdout=b'port 2222\npubkeyauthentication yes\n'
            if (self.root/migration.SSH_FILE.lstrip('/')).exists():stdout+=b'denyusers solv\n'
        elif args[0]=='/usr/bin/passwd':stdout=('solv '+self.password+' 2026-10-29 0 99999 7 -1\n').encode()
        elif args[0]=='/usr/bin/chage':stdout=('Account expires : '+self.expires+'\n').encode()
        elif args[0]=='/usr/sbin/usermod':
            self.assertFalse(self.writer)
            self.assertTrue((self.root/migration.SSH_FILE.lstrip('/')).exists())
            self.assertNotIn(migration.SUDO_GRANT,(self.root/'etc/sudoers').read_bytes())
            if args[1]=='--shell':self.shell=args[2]
            elif args[1]=='--groups':self.assertEqual(args[2],'');self.groups=[1101]
            elif args[1]=='--lock':self.password='L'
            elif args[1]=='--expiredate':self.assertEqual(args[2],'1');self.expires='1970-01-02'
            else:self.fail('unqualified account mutation')
        else:self.assertIn(args[0],('/usr/sbin/sshd','/usr/sbin/visudo','/usr/bin/systemctl'))
        return subprocess.CompletedProcess(args,status,stdout,b'')

    def test_original_identity_and_policy_backup_retained_without_copy_permission(self):
        result=self.revocation.revoke()
        self.assertFalse(result['copy_authorized']);self.assertTrue(result['manager_reauthentication_required'])
        self.assertEqual((self.store/'sudoers.original').read_bytes(),self.policy)
        self.assertEqual(self.revocation.saved()['phase'],'revoked')
        self.assertEqual(self.revocation.verify()['binding'],self.scope)
        self.assertEqual(self.users()[0].pw_uid,1001);self.assertEqual(self.users()[0].pw_dir,'/home/solv')
        previous=sum(row[0]=='/usr/sbin/usermod' for row in self.commands)
        self.assertEqual(self.revocation.revoke(),result)
        self.assertEqual(sum(row[0]=='/usr/sbin/usermod' for row in self.commands),previous)
    def test_unqualified_ownership_manager_or_policy_refuses_before_any_mutation(self):
        for kind in ('source','manager','ssh','sudo','namespace'):
            with self.subTest(kind=kind):
                f=Retirement('runTest');f.setUp()
                try:
                    if kind=='source':f.foreign=True
                    elif kind=='manager':f.manager_ok=False
                    elif kind=='ssh':f.write('/etc/ssh/sshd_config.d/custom.conf',b'Match User solv\n  PermitTTY yes\n')
                    elif kind=='sudo':f.write('/etc/sudoers',f.policy.replace(migration.SUDO_GRANT,b'solv ALL=ALL\n'),0o440)
                    else:(f.store/'unknown').write_bytes(b'unowned')
                    with self.assertRaises(ValueError):f.revocation.revoke()
                    self.assertFalse(any(row[0] in ('/usr/sbin/usermod','/usr/bin/systemctl') for row in f.commands))
                    self.assertFalse((f.root/migration.SSH_FILE.lstrip('/')).exists())
                finally:f.doCleanups()
    def test_existing_writers_prevent_sudo_account_changes_and_copy_success(self):
        self.writer=True
        with self.assertRaises(ValueError):self.revocation.revoke()
        self.assertEqual((self.root/'etc/sudoers').read_bytes(),self.policy)
        self.assertFalse(any(row[0]=='/usr/sbin/usermod' for row in self.commands))
        self.assertEqual(self.revocation.saved()['phase'],'ssh-denied')
        self.writer=False;self.assertFalse(self.revocation.revoke()['copy_authorized'])
    def test_interrupted_individual_account_change_retains_original_numeric_identity(self):
        real=self.command;count=[]
        def fail(args):
            if args[0]=='/usr/sbin/usermod':
                count.append(True)
                if len(count)==2:raise OSError('inert NSS reply lost')
            return real(args)
        self.revocation.run=fail
        with self.assertRaises(OSError):self.revocation.revoke()
        self.assertEqual(self.shell,'/usr/sbin/nologin');self.assertEqual(self.groups,[1101,27])
        self.revocation.run=real;self.assertFalse(self.revocation.revoke()['copy_authorized'])
    def test_manager_uid_drift_or_remaining_sudo_cannot_report_retirement(self):
        self.revocation.revoke();self.manager_uid=2002
        with self.assertRaises(ValueError):self.revocation.verify()
        self.manager_uid=1002;self.sudo_denial=False
        with self.assertRaises(ValueError):self.revocation.verify()
    def test_changed_backup_policy_or_link_is_never_repaired(self):
        self.revocation.revoke()
        for path in (self.store/'sudoers.original',self.root/'etc/sudoers'):
            raw=path.read_bytes();mode=path.stat().st_mode&0o7777;path.chmod(0o600);path.write_bytes(b'foreign policy retained');path.chmod(mode)
            with self.assertRaises(ValueError):self.revocation.revoke()
            self.assertEqual(path.read_bytes(),b'foreign policy retained');path.chmod(0o600);path.write_bytes(raw);path.chmod(mode)
        denial=self.root/migration.SSH_FILE.lstrip('/');denial.unlink();denial.symlink_to(self.root/'etc/sudoers')
        with self.assertRaises((ValueError,OSError)):self.revocation.revoke()
        self.assertTrue(denial.is_symlink())
    def test_each_durable_barrier_failure_keeps_original_backup_and_resumes(self):
        real=os.fsync;points=[]
        def record(fd):points.append(True);return real(fd)
        with patch.object(os,'fsync',record):self.revocation.revoke()
        for position in range(len(points)):
            f=Retirement('runTest');f.setUp()
            try:
                seen=[]
                def fail(fd):
                    current=len(seen);seen.append(True)
                    if current==position:raise OSError('inert durability interruption')
                    return real(fd)
                with patch.object(os,'fsync',fail),self.assertRaises(OSError):f.revocation.revoke()
                result=f.revocation.revoke()
                self.assertFalse(result['copy_authorized']);self.assertEqual((f.store/'sudoers.original').read_bytes(),f.policy)
            finally:f.doCleanups()
        print(str(len(points))+' actual privilege retirement fsync failures retried')

if __name__=='__main__':unittest.main()
