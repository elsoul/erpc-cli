# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original proc/NSS fixtures exercise root publication and unprivileged reads."""
import importlib.util
import os
from pathlib import Path
import subprocess
import socket
import shutil
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
if os.name=='posix':import native_authority as authority


@unittest.skipUnless(os.name=='posix','host account/proc authority is POSIX-only')
class Authority(unittest.TestCase):
    def enter(self,context):
        value=context.start();self.addCleanup(context.stop);return value

    def setUp(self):
        spec=importlib.util.spec_from_file_location('polygon_host_authority_fixture',ROOT/'tests/host.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        self.fixture=fixture.Authority();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.accounts=self.fixture.original_accounts()
        self.state.path('/run').mkdir(exist_ok=True)
        self.expected=dict(self.fixture.fixture.contract,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        storage=self.state.read('/etc/polygon/storage.json');storage['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',storage)
        record=self.state.read('/etc/polygon/runtime-accounts.json');record['contract']=self.expected
        record['accounts']['broker']={'uid':996,'gid':996}
        import accounts
        self.accounts.users().append(SimpleNamespace(pw_name='polygon-rabbitmq',pw_uid=996,pw_gid=996,
            pw_dir='/var/lib/polygon/broker',pw_shell=accounts.SHELL))
        self.accounts.groups().append(SimpleNamespace(gr_name='polygon-rabbitmq',gr_gid=996,gr_mem=[]))
        self.state.write('/etc/polygon/runtime-accounts.json',record,mode=0o644)
        self.installed=dict(self.fixture.installed,contract=self.expected,
            profile=dict(self.fixture.installed['profile'],validator={'phase':'observing'}))
        self.fixture.native('bor',200)
        directory=self.state.path('/proc/200/net');directory.mkdir()
        (directory/'unix').write_text('Num RefCount Protocol Flags Type St Inode Path\n0: 00000002 00000000 00010000 0001 01 2000 /run/polygon-bor/native.rpc\n')
        original=self.state.run
        def run(args,**kwargs):
            if args[:3]==['systemctl','show','--property=InvocationID']:
                return subprocess.CompletedProcess(args,0,b'1'*32,b'')
            return original(args,**kwargs)
        self.state.run=run
        self.identity=[1,2,3,4]
        self.grant=self.enter(patch.object(authority,'grant_socket',return_value=self.identity))
        self.enter(patch.object(authority.native_peer,'identity',return_value=tuple(self.identity)))
        self.authorize=lambda:self.installed

    def publish(self):return authority.publish(self.state,self.expected,'bor',self.authorize)
    def read(self):return authority.read(self.state,self.expected,'bor',self.installed['helpers'],self.installed['profile_sha256'])

    def test_actual_root_process_proof_and_public_reader_agree_without_ptrace(self):
        value=self.publish();self.assertEqual(value['peer']['uid'],999)
        self.grant.assert_called_once_with(self.state,'bor',999,999,997)
        with patch.object(self.state.proof,'process',side_effect=AssertionError('public reader cannot inspect executable/fds')):
            self.assertEqual(self.read(),value['peer'])
        destination=self.state.path(authority.DIRECTORY+'/bor.json')
        self.assertEqual(destination.stat().st_mode&0o777,0o644)
        before=destination.stat().st_mtime_ns
        self.publish();self.assertEqual(destination.stat().st_mtime_ns,before)

    def test_socket_owned_by_another_process_is_not_granted(self):
        file=self.state.path('/proc/200/net/unix')
        for wrong in ('2000','00010000','0001','01'):
            before=file.read_text()
            file.write_text(before.replace(wrong,'9999',1))
            with self.assertRaises(ValueError):self.publish()
            self.grant.assert_not_called();file.write_text(before)
        self.assertFalse(self.state.path(authority.DIRECTORY+'/bor.json').exists())

    def test_pid_or_activation_change_during_grant_never_publishes(self):
        original=self.grant.side_effect
        def replace(*args):
            file=self.state.path('/proc/200/stat');file.write_text(file.read_text().replace('101','202'))
            return self.identity
        self.grant.side_effect=replace
        with self.assertRaises(ValueError):self.publish()
        self.assertFalse(self.state.path(authority.DIRECTORY+'/bor.json').exists())
        self.grant.side_effect=original

    def test_public_reader_rejects_original_account_pid_cgroup_and_socket_drift(self):
        self.publish()
        changes=[('proc/200/stat','101','202'),('proc/200/status','999','998'),
                 ('proc/200/cgroup','polygon-bor.service','foreign.service')]
        for name,before,after in changes:
            file=self.state.root/name;original=file.read_text();file.write_text(original.replace(before,after))
            with self.assertRaises(ValueError):self.read()
            file.write_text(original)
        with patch.object(authority.native_peer,'identity',return_value=(1,2,3,5)):
            with self.assertRaises(ValueError):self.read()
        with patch.object(self.accounts,'lookup',return_value=None):
            with self.assertRaises(ValueError):self.read()

    def test_fences_and_superseded_release_reject_cached_public_receipts(self):
        self.publish()
        for name in ('stopped','preparing','retired'):
            file=self.state.path('/etc/polygon/'+name);file.touch()
            with self.assertRaises(ValueError):self.read()
            with self.assertRaises(ValueError):self.publish()
            file.unlink()
        with self.assertRaises(ValueError):authority.read(self.state,self.expected,'bor','f'*64,self.installed['profile_sha256'])
        with patch.object(self.state.proof,'show',return_value='f'*32):
            with self.assertRaises(ValueError):self.read()

    def test_unknown_public_directory_is_never_repaired(self):
        directory=self.state.path(authority.DIRECTORY);directory.mkdir(parents=True,mode=0o777);directory.chmod(0o777)
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(directory.stat().st_mode&0o777,0o777)

    def test_global_drain_keeps_original_broker_uid_without_blocking_bor_only_startup(self):
        self.fixture.pids.clear();self.fixture.fixture.running.clear()
        shutil.rmtree(self.state.path('/proc/200'))
        self.state.path('/sys/fs/cgroup/system.slice/polygon-bor.service/cgroup.procs').write_text('')
        self.fixture.process(400,996,'/usr/bin/inert',[b'inert'],'/untracked.scope')
        with self.assertRaises(ValueError):self.state.proof.quiescent()
        self.state.proof.quiescent(('bor',))

    def test_actual_controller_entrypoint_uses_its_separate_publication_lock(self):
        import control
        import json
        controller=self.fixture.fixture.control
        with patch.object(control,'Control',return_value=controller), patch.object(controller,'runtime',return_value=self.installed), \
                patch.object(self.state,'locked',side_effect=AssertionError('must not reacquire the node-run lock')), \
                patch.object(sys,'argv',['control.py','peer-publish','bor',json.dumps(self.expected)]):
            control.main()
        self.assertEqual(self.read()['pid'],200)


@unittest.skipUnless(os.name=='posix','socket inode grants use Linux O_PATH, modeled without root')
class DescriptorGrant(unittest.TestCase):
    def run_grant(self,rebind=False):
        import state
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);runtime=root/'run/polygon-bor';runtime.mkdir(parents=True);runtime.chmod(0o700)
            path=runtime/'native.rpc';stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);stream.bind(str(path));path.chmod(0o700)
            self.addCleanup(stream.close)
            uid,gid=os.getuid(),os.getgid();instance=state.State(root=root,owner=uid)
            placeholder=root/'descriptor';placeholder.write_text('inert O_PATH stand-in')
            open_original=os.open;stat_original=os.fstat;chmod_original=os.chmod
            opened={};current=[path];replacement=[]
            def opening(name,flags,*args,**kwargs):
                if flags & os.O_PATH:
                    self.assertEqual(name,'native.rpc');self.assertIn('dir_fd',kwargs)
                    descriptor=open_original(placeholder,os.O_RDONLY)
                    opened[descriptor]=path.stat()
                    return descriptor
                return open_original(name,flags,*args,**kwargs)
            def fstat(descriptor):return opened.get(descriptor) or stat_original(descriptor)
            def chown(name,wanted_uid,wanted_gid):
                self.assertEqual((wanted_uid,wanted_gid),(uid,gid))
                self.assertTrue(str(name).startswith('/proc/self/fd/'))
                if rebind:
                    old=path.with_suffix('.original');path.rename(old);current[0]=old
                    other=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);other.bind(str(path));chmod_original(path,0o700)
                    replacement.append(other);self.addCleanup(other.close)
            def chmod(name,mode):
                self.assertTrue(str(name).startswith('/proc/self/fd/'));chmod_original(current[0],mode)
            with patch.object(os,'O_PATH',getattr(os,'O_PATH',0x20000000),create=True), \
                    patch.object(os,'open',side_effect=opening),patch.object(os,'fstat',side_effect=fstat), \
                    patch.object(os,'chown',side_effect=chown),patch.object(os,'chmod',side_effect=chmod), \
                    patch.object(os,'fchown') as directory_owner:
                if rebind:
                    with self.assertRaisesRegex(ValueError,'rebound'):authority.grant_socket(instance,'bor',uid,gid,gid)
                else:
                    identity=authority.grant_socket(instance,'bor',uid,gid,gid)
                    self.assertEqual(identity,[runtime.stat().st_dev,runtime.stat().st_ino,path.stat().st_dev,path.stat().st_ino])
                directory_owner.assert_called_once()
            self.assertEqual(current[0].stat().st_mode&0o777,0o660)
            if rebind:self.assertEqual(path.stat().st_mode&0o777,0o700)
            self.assertEqual(runtime.stat().st_mode&0o777,0o710)

    def test_descriptor_grant_preserves_original_inode_and_closes_descriptors(self):self.run_grant()
    def test_rebound_path_is_never_chmodded_and_cannot_publish_authority(self):self.run_grant(rebind=True)


if __name__=='__main__':unittest.main()
