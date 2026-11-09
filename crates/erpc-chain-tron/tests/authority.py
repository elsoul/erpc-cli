# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Linux authority models, actual inert orphan writer and durable failure paths."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/jinja'))


def fixtures():
    spec=importlib.util.spec_from_file_location('tron_authority_fixtures',ROOT/'tests/control_paths.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


@unittest.skipUnless(os.name=='posix','Linux service authority requires POSIX paths')
class Authority(unittest.TestCase):
    def setUp(self):
        import host,launch,observe
        self.host,self.launch,self.observe=host,launch,observe
        self.fixture=fixtures().ControlPaths();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare();self.fixture.activate(self.fixture.policy());self.fixture.active=False
        self.control=self.fixture.control;self.root=self.fixture.root;self.pid=0;self.loaded='loaded'
        self.proof=host.Proof(self.control,lookup=lambda _:SimpleNamespace(pw_uid=1001));self.control.proof=self.proof
        self.release=self.control.verify_install(self.fixture.expected)
        (self.root/'proc/net').mkdir(parents=True)
        for family in ('tcp','tcp6','udp','udp6'):(self.root/'proc/net'/family).write_text('header\n')
        self.group=self.root/'sys/fs/cgroup/system.slice/tron-node.service';self.group.mkdir(parents=True);(self.group/'cgroup.procs').write_text('')
        self.process(1,0,'/sbin/init',[b'/sbin/init'],'/init.scope')
        original=self.control.run
        def run(args,**kwargs):
            if args[:2]==['systemctl','show']:
                if '--property=LoadState' in args:out=self.loaded
                elif '--property=MainPID' in args:out=str(self.pid)
                elif '--property=ControlGroup' in args:out='/system.slice/tron-node.service' if self.pid else ''
                else:return original(args,**kwargs)
                return subprocess.CompletedProcess(args,0,out.encode(),b'')
            return original(args,**kwargs)
        self.control.run=run
    def process(self,pid,uid,exe,args,group,descriptors=()):
        directory=self.root/'proc'/str(pid);directory.mkdir(exist_ok=True);(directory/'fd').mkdir(exist_ok=True)
        (directory/'stat').write_text(str(pid)+' (fixture) S '+'0 '*18+'100 0\n')
        (directory/'status').write_text('State:\tS (sleeping)\nUid:\t'+' '.join([str(uid)]*4)+'\nGid:\t'+' '.join([str(uid)]*4)+'\nGroups:\t'+str(uid)+'\n')
        (directory/'cmdline').write_bytes(b'\0'.join(args)+b'\0');(directory/'cgroup').write_text('0::'+group+'\n')
        (directory/'exe').symlink_to(exe)
        for number,target in enumerate(descriptors):(directory/'fd'/str(number)).symlink_to(target)
        return directory
    def native(self):
        args=self.launch.arguments(self.fixture.expected,self.release)
        java=self.control.path(args[0]);java.parent.mkdir(parents=True,exist_ok=True);java.write_text('inert JVM image');java.chmod(0o755)
        sockets=['socket:['+str(3000+index)+']' for index,_ in enumerate(self.host.api_ports(self.fixture.expected))]
        self.process(300,1001,str(java),[arg.encode() for arg in args],'/system.slice/tron-node.service',sockets)
        rows=['0: 00000000:'+format(port,'04X')+' 00000000:0000 0A 0:0 00:0 0 1001 0 '+str(3000+index) for index,port in enumerate(self.host.api_ports(self.fixture.expected))]
        (self.root/'proc/net/tcp').write_text('header\n'+'\n'.join(rows)+'\n')
        (self.group/'cgroup.procs').write_text('300\n');self.pid=300;self.fixture.active=True
    def healthy_status(self):
        counter=[100];original=self.observe.local_state
        def query(network,method,payload=None,local=False):
            if method.endswith('getnowblock'):
                counter[0]+=1
                return {'blockID':'d'*64,'block_header':{'raw_data':{'number':counter[0],'timestamp':int(time.time()*1000)}}}
            if method.endswith('getblockbynum'):return {'blockID':self.fixture.expected['genesis']}
            if method.endswith('getnodeinfo'):return {'configNodeInfo':{'codeVersion':self.release['client_version']},'activeConnectCount':8}
            return self.fixture.query(network,method,payload,local)
        self.control.query=query
        with patch.object(self.observe,'local_state',side_effect=lambda expected,query:original(expected,query,sleep=lambda _:None)),patch.object(self.observe,'grpc',return_value=True),patch.object(self.observe,'json_rpc',return_value=True):
            return self.control.status(self.fixture.expected)
    def test_missing_unit_does_not_hide_a_real_orphan_data_writer(self):
        data=self.root/'var/lib/tron';data.mkdir(parents=True,exist_ok=True)
        writer=subprocess.Popen([sys.executable,'-I','-c','import sys,time; from pathlib import Path; p=Path(sys.argv[2])/"inert-writer"; [(p.write_text(str(i)),time.sleep(.02)) for i in range(3000)]','-d',str(data)])
        self.addCleanup(lambda:writer.poll() is None and (writer.terminate(),writer.wait(timeout=3)))
        def next_write(after):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                self.assertIsNone(writer.poll())
                try:
                    counter = (data / 'inert-writer').read_text()
                except FileNotFoundError:
                    counter = ''
                if counter.isdecimal() and int(counter) > after:
                    return int(counter)
                time.sleep(.01)
            self.fail(f'orphan writer did not advance past {after}')
        next_write(-1)
        self.process(writer.pid,1001,sys.executable,[sys.executable.encode(),b'-d',str(data).encode()],'/untracked.scope')
        original=self.control.path('/etc/tron/release.json').read_bytes()
        for loaded in ('not-found','loaded'):
            self.loaded=loaded
            for action in ('start','restart','prepare','destroy'):
                with self.assertRaises(ValueError):self.control.dispatch(action,self.fixture.expected,self.fixture.intent,target=self.fixture.target)
                self.assertIsNone(writer.poll());self.assertEqual(self.control.path('/etc/tron/release.json').read_bytes(),original)
                self.assertIsNotNone(self.fixture.live)
        before = next_write(-1)
        next_write(before)
    def test_unreadable_metadata_pid_reuse_foreign_data_fd_and_udp_block_drain(self):
        data=self.root/'var/lib/tron';data.mkdir(parents=True,exist_ok=True);(data/'inert').touch()
        path=self.process(400,999,'/usr/bin/other',[b'other'],'/other.scope',[str(data/'inert')])
        with self.assertRaises(ValueError):self.control.stopped()
        (path/'fd/0').unlink()
        with patch.object(self.proof,'process',side_effect=PermissionError('inert metadata failure')):
            with self.assertRaises(PermissionError):self.control.stopped()
        original=self.proof.generation;count={}
        def reused(pid):
            count[pid]=count.get(pid,0)+1
            return '200' if pid==400 and count[pid]>1 else original(pid)
        with patch.object(self.proof,'generation',side_effect=reused):
            with self.assertRaises(ValueError):self.control.stopped()
        (self.root/'proc/net/udp').write_text('header\n0: 00000000:'+format(18888,'04X')+' 00000000:0000 07 0:0 00:0 0 999 0 4567\n')
        with self.assertRaises(ValueError):self.control.stopped()
    def test_forged_responses_need_a_real_owned_listener_and_immutable_jar_profile(self):
        self.assertFalse(self.healthy_status()['ready'])
        self.native();self.assertTrue(self.healthy_status()['ready'])
        path=self.root/'proc/300/cmdline';original=path.read_bytes()
        path.write_bytes(original.replace(self.release['directory'].encode(),b'/opt/tron/current'))
        self.assertFalse(self.healthy_status()['ready'])
        path.write_bytes(original)
        sockets=self.root/'proc/net/tcp';sockets.write_text(sockets.read_text().replace('1001 0 3000','999 0 3000'))
        self.assertFalse(self.healthy_status()['ready'])
    def test_both_jvm_architectures_and_roles_bind_their_exact_launch_and_api_ports(self):
        original=json.loads(json.dumps(self.release))
        for architecture in ('x86_64','aarch64'):
            for role in ('fullnode','validator'):
                if (self.root/'proc/300').exists():shutil.rmtree(self.root/'proc/300')
                self.release=json.loads(json.dumps(original))
                self.release['architecture']=architecture
                self.release['directory']=original['directory'].removesuffix('x86_64')+architecture
                self.fixture.expected={**self.fixture.expected,'architecture':architecture,'role':role}
                self.native()
                observed=self.proof.listener(self.fixture.expected,self.release)
                self.assertEqual({row[0] for row in observed[2]},set(self.host.api_ports(self.fixture.expected)))
                self.assertEqual(len(observed[2]),6 if role=='fullnode' else 4)

    def test_retained_uid_remains_part_of_drain_after_nss_identity_changes(self):
        self.process(400,1001,'/usr/bin/sleep',[b'sleep',b'60'],'/untracked.scope')
        self.proof.lookup=lambda _:SimpleNamespace(pw_uid=2002)
        with patch.object(self.control.accounts,'retained_uid',return_value=1001):
            with self.assertRaises(ValueError):self.control.stopped()

    def test_actual_native_group_privilege_drift_cannot_report_ready(self):
        self.native();self.assertTrue(self.healthy_status()['ready'])
        status=self.root/'proc/300/status'
        status.write_text(status.read_text().replace('Groups:\t1001','Groups:\t1001 998'))
        self.assertFalse(self.healthy_status()['ready'])

    def test_native_process_or_socket_replacement_during_sampling_is_not_ready(self):
        self.native();original=self.proof.listener;count=[0]
        def replace(*args):
            count[0]+=1
            if count[0]==2:(self.root/'proc/300/stat').write_text('300 (replaced) S '+'0 '*18+'200 0\n')
            return original(*args)
        with patch.object(self.proof,'listener',side_effect=replace):self.assertFalse(self.healthy_status()['ready'])
    def test_first_owner_cannot_adopt_an_untracked_native_jar(self):
        self.process(400,999,'/other/java',[b'java',b'-jar',b'/other/FullNode.jar'],'/other.scope')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'etc').mkdir()
            shutil.copytree(self.root/'proc',root/'proc',symlinks=True);shutil.copytree(self.root/'sys',root/'sys',symlinks=True)
            fresh=self.fixture.module.Control(root,self.control.run,owner=os.getuid())
            fresh.proof=self.host.Proof(fresh,lookup=self.proof.lookup)
            with self.assertRaises(ValueError):fresh.contract(self.fixture.expected,initial=True)
            self.assertFalse((root/'etc/tron').exists())


@unittest.skipUnless(os.name=='posix','directory sync requires POSIX host semantics')
class Durability(unittest.TestCase):
    def setUp(self):
        import host
        self.host=host;self.fixture=fixtures().ControlPaths();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare();self.fixture.activate(self.fixture.policy());self.control=self.fixture.control
    def test_stop_fence_and_directory_are_durable_before_service_stop(self):
        events=[];original_sync=self.host.sync_directory;original_run=self.control.run
        def sync(path):events.append(('sync',str(path)));return original_sync(path)
        def run(args,**kwargs):events.append(('command',args));return original_run(args,**kwargs)
        self.control.run=run
        with patch.object(self.host,'sync_directory',side_effect=sync):self.control.dispatch('stop',self.fixture.expected)
        stop=next(index for index,value in enumerate(events) if value[0]=='command' and value[1][:2]==['systemctl','stop'])
        self.assertTrue(any(kind=='sync' and path==str(self.fixture.root/'etc/tron') for kind,path in events[:stop]))
        with self.assertRaises(ValueError):self.control.runtime(self.fixture.expected)
    def test_stop_and_cancellation_sync_failure_never_start_or_remove_fence(self):
        before=len(self.fixture.calls)
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert storage failure')):
            with self.assertRaises(OSError):self.control.dispatch('stop',self.fixture.expected)
        self.assertFalse(self.fixture.active)
        self.assertTrue(any(args[:3]==['systemctl','disable','--now'] for args in self.fixture.calls[before:]))
        self.control.dispatch('stop',self.fixture.expected)
        before=len(self.fixture.calls)
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert cancellation failure')):
            with self.assertRaises(OSError):self.control.dispatch('start',self.fixture.expected)
        self.assertFalse(self.fixture.active);self.assertTrue(self.control.path('/etc/tron/stopped').exists())
        self.assertFalse(any(args[:2]==['systemctl','start'] for args in self.fixture.calls[before:]))
    def failed_cancellation(self):
        original=self.control.write
        def write(path,value,**kwargs):
            if path=='/etc/tron/intent.json':raise OSError('inert cancellation publication failure')
            return original(path,value,**kwargs)
        with patch.object(self.control,'write',side_effect=write):
            with self.assertRaises(OSError):self.control.dispatch('stop',self.fixture.expected)
        self.assertEqual(self.control.read('/etc/tron/intent.json')['intent'],self.fixture.intent)
        self.assertFalse(self.fixture.active)
        self.assertTrue(self.control.path('/etc/tron/stopped').exists())

    def assert_cancelled(self,intent,receipt):
        before=len(self.fixture.calls)
        for action in ('guard-phase','confirm','activate','import','restore'):
            with self.assertRaises(ValueError):self.control.dispatch(action,self.fixture.expected,intent,receipt,target=self.fixture.target)
        self.assertEqual(len(self.fixture.calls),before)

    def test_failed_stop_intent_write_refuses_old_phases_and_new_prepare_resumes(self):
        receipt=self.fixture.policy('bbbbbb')
        original=self.control.path('/etc/tron/contract.json').read_bytes()
        self.failed_cancellation();old=self.fixture.intent
        self.assert_cancelled(old,receipt)
        with self.assertRaises(ValueError):self.fixture.prepare()
        unlink=self.host.unlink;cleared=[]
        def checked(path,stop):
            if path.name=='stopped':
                self.assertEqual(self.control.read('/etc/tron/intent.json')['intent'],'b'*32)
                self.assertTrue(self.control.path('/etc/tron/preparing').exists())
                self.assertFalse(self.fixture.active);cleared.append(True)
            return unlink(path,stop)
        with patch.object(self.host,'unlink',side_effect=checked):self.fixture.prepare('b'*32)
        self.assertEqual(cleared,[True]);self.assert_cancelled(old,receipt)
        self.fixture.activate(self.fixture.policy('cccccc'))
        self.assertTrue(self.fixture.active)
        self.assertEqual(self.control.path('/etc/tron/contract.json').read_bytes(),original)

    def test_explicit_start_invalidates_surviving_old_intent_before_clearing_stop(self):
        active=self.control.read('/etc/tron/activation.json');receipt=(active['run'],active['bundle'])
        self.failed_cancellation();old=self.fixture.intent
        self.control.dispatch('start',self.fixture.expected)
        self.assertTrue(self.fixture.active)
        self.assertFalse(self.control.path('/etc/tron/stopped').exists())
        self.assert_cancelled(old,receipt)

    def test_initial_fence_write_failure_still_invalidates_and_disables(self):
        with patch.object(self.host,'fence',side_effect=OSError('inert first fence creation failure')):
            with self.assertRaises(OSError):self.control.dispatch('destroy',self.fixture.expected)
        self.assertFalse(self.fixture.active);self.assertIsNotNone(self.fixture.live)
        self.assertNotEqual(self.control.read('/etc/tron/intent.json')['intent'],self.fixture.intent)
        self.assertTrue(any(args[:3]==['systemctl','disable','--now'] for args in self.fixture.calls))

    def test_missing_original_receipt_never_adopts_unknown_store_or_retained_history(self):
        fixture=fixtures().ControlPaths();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.validator();fixture.prepare();control=fixture.control
        payload={'keystore':'inert encrypted key fixture','password':'inert fixture'}
        store=control.path('/etc/credstore.encrypted/tron');store.mkdir()
        with self.assertRaises(ValueError):control.dispatch('import',fixture.expected,fixture.intent,payload=payload)
        self.assertFalse(control.path('/etc/tron/identity.json').exists())
        control.write('/etc/tron/credential-preparation.json',{'format':1,'contract':fixture.expected})
        data=control.path('/var/lib/tron');data.mkdir(parents=True);history=data/'retained-history';history.write_text('prior signer history')
        with self.assertRaises(ValueError):control.dispatch('import',fixture.expected,fixture.intent,payload=payload)
        self.assertEqual(history.read_text(),'prior signer history');self.assertFalse(control.path('/etc/tron/identity.json').exists())
        store.rmdir()
        with self.assertRaises(ValueError):control.dispatch('import',fixture.expected,fixture.intent,payload=payload)

    def test_credential_publication_and_restore_failure_keep_history_and_fence(self):
        self.fixture=fixtures().ControlPaths();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.control=self.fixture.control;self.fixture.validator();self.fixture.prepare()
        payload={'keystore':'inert encrypted key fixture','password':'inert fixture'}
        data=self.control.path('/var/lib/tron');data.mkdir(parents=True,exist_ok=True);history=data/'retained-history'
        original=self.host.sync_directory
        def fail(path):
            if Path(path).name=='generations':raise OSError('inert generation durability failure')
            return original(path)
        with patch.object(self.host,'sync_directory',side_effect=fail):
            with self.assertRaises(OSError):self.control.dispatch('import',self.fixture.expected,self.fixture.intent,payload=payload)
        self.assertFalse(self.control.path('/etc/tron/identity.json').exists());self.assertTrue(self.control.path('/etc/tron/preparing').exists())
        generations=self.control.path('/etc/credstore.encrypted/tron/generations');previous=set(generations.iterdir())
        self.control.dispatch('import',self.fixture.expected,self.fixture.intent,payload=payload)
        self.assertTrue(previous.issubset(set(generations.iterdir())))
        history.write_text('inert signed history')
        with patch.object(self.host,'sync_directory',side_effect=fail):
            with self.assertRaises(OSError):self.control.dispatch('restore',self.fixture.expected,self.fixture.intent,payload=payload)
        self.assertFalse(self.fixture.active);self.assertEqual(history.read_text(),'inert signed history')
        self.control.dispatch('restore',self.fixture.expected,self.fixture.intent,payload=payload)
        self.assertEqual(history.read_text(),'inert signed history')

if __name__=='__main__':unittest.main()
