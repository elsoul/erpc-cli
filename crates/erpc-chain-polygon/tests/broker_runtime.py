# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual tempfile publication with inert encryption, NSS and no broker process."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
if os.name=='posix':
    import broker_runtime as runtime
    import gateway
    import host
    import local_tls
    import state as state_module


@unittest.skipUnless(os.name=='posix','root publication uses inert POSIX tempfile ownership')
class Publication(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name in ('etc/polygon','etc/credstore.encrypted/polygon','run'):(self.root/name).mkdir(parents=True,exist_ok=True)
        self.expected={'role':'validator','owner':'public-fixture','architecture':'x86_64'}
        self.value={'format':1,'contract':self.expected,'password':'a'*64,'cookie':'b'*64}
        self.account={'uid':os.getuid(),'gid':os.getgid()}
        self.accounts=SimpleNamespace(verify=Mock(return_value={'broker':self.account}))
        self.calls=[]
        def run(args,**kwargs):
            self.calls.append((args,kwargs))
            if args[0]=='findmnt':return subprocess.CompletedProcess(args,0,b'/run tmpfs\n',b'')
            self.assertEqual(args[0],'/usr/bin/systemd-creds')
            raw=kwargs['input']
            output=b'encrypted:'+raw if args[1]=='encrypt' else raw.removeprefix(b'encrypted:')
            return subprocess.CompletedProcess(args,0,output,b'')
        self.state=state_module.State(self.root,run=run,owner=os.getuid(),account=self.accounts)
        for name in ('ownership','phase','stopped'):
            context=patch.object(self.state,name);context.start();self.addCleanup(context.stop)
        self.state.path('/etc/polygon/preparing').touch()
        self.create=Mock(return_value=self.value)
        self.tls={'ca':'inert public CA','leaves':{'broker':{'certificate':'inert public leaf','key':'inert private test marker'}}}

    def prepare(self):return runtime.prepare(self.state,self.expected,'a'*32,{},'b'*64,create=self.create)
    def stage(self):
        with patch.object(local_tls,'load',return_value=(self.tls,{})):
            return runtime.stage(self.state,self.expected,'a'*32,{},'b'*64)

    def test_actual_credential_transform_names_and_original_readback_survive_retry(self):
        self.assertEqual(self.prepare(),self.value);cipher=self.state.path(runtime.CIPHER).read_bytes()
        self.assertEqual(self.prepare(),self.value);self.create.assert_called_once()
        self.assertEqual(self.state.path(runtime.CIPHER).read_bytes(),cipher)
        for args,_kwargs in self.calls:
            self.assertNotIn(self.value['password'],' '.join(args));self.assertNotIn(self.value['cookie'],' '.join(args))
        self.state.path(runtime.CIPHER).unlink()
        with self.assertRaises(ValueError):self.prepare()
        self.create.assert_called_once()

    def test_actual_gateway_default_converter_accepts_only_closed_credential_names(self):
        auth={'format':1,'contract':self.expected,'password':'c'*64}
        self.assertEqual(gateway.prepare_auth(self.state,self.expected,'a'*32,{},'b'*64,create=lambda _:auth),auth)
        with self.assertRaises(ValueError):local_tls.transform(self.state,'encrypt','arbitrary',b'inert')

    def test_interrupted_original_publication_never_regenerates_durable_candidate(self):
        publish=host.publish
        def failed(source,destination,*args,**kwargs):
            if destination==self.state.path(runtime.CIPHER):raise OSError('inert durable publication fault')
            return publish(source,destination,*args,**kwargs)
        with patch.object(host,'publish',side_effect=failed):
            with self.assertRaises(OSError):self.prepare()
        self.assertTrue(self.state.path(runtime.CIPHER+'.pending').exists())
        self.assertEqual(self.prepare(),self.value);self.create.assert_called_once()

    def test_private_runtime_selects_only_broker_leaf_original_ids_and_no_plugins(self):
        self.prepare();observed=self.stage()
        root=self.state.path(runtime.broker.RUNTIME)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o750)
        self.assertEqual((root/'config/enabled_plugins').read_bytes(),b'[].\n')
        self.assertEqual((root/'config/private-key.pem').read_text(),self.tls['leaves']['broker']['key'])
        self.assertEqual((root/'cookie').read_text(),self.value['cookie'])
        for path in (root/'config').iterdir():
            self.assertEqual((path.stat().st_uid,path.stat().st_gid,stat.S_IMODE(path.stat().st_mode)),
                (os.getuid(),os.getgid(),0o440))
        self.assertEqual(stat.S_IMODE((root/'cookie').stat().st_mode),0o400)
        self.assertEqual(observed['ca_sha256'],hashlib.sha256(self.tls['ca'].encode()).hexdigest())
        self.stage();self.create.assert_called_once()

    def test_symlink_hardlink_unknown_content_and_writable_runtime_are_refused_without_target_writes(self):
        self.prepare();self.stage();root=self.state.path(runtime.broker.RUNTIME)
        target=self.root/'outside';target.write_bytes(b'original public sentinel')
        path=root/'config/private-key.pem';saved=path.read_bytes();path.unlink();path.symlink_to(target)
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(target.read_bytes(),b'original public sentinel');path.unlink()
        os.link(target,path)
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(target.read_bytes(),b'original public sentinel');path.unlink()
        path.write_bytes(saved);path.chmod(0o440)
        unknown=root/'config/unknown';unknown.write_bytes(b'inert')
        with self.assertRaises(ValueError):self.stage()
        unknown.unlink();path.chmod(0o666)
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o666)

    def test_account_drift_and_non_tmpfs_refuse_before_secret_publication(self):
        self.prepare();self.accounts.verify.side_effect=ValueError('inert NSS drift')
        with self.assertRaises(ValueError):self.stage()
        self.assertFalse(self.state.path(runtime.broker.RUNTIME).exists())
        self.accounts.verify.side_effect=None
        with patch.object(self.state,'command',return_value=SimpleNamespace(stdout=b'ext4\n')):
            with self.assertRaises(ValueError):self.stage()
        self.assertFalse(self.state.path(runtime.broker.RUNTIME).exists())

    def test_interrupted_empty_directory_and_private_pending_file_recover_from_original_cipher(self):
        self.prepare();root=self.state.path(runtime.broker.RUNTIME)
        root.mkdir(mode=0o700)
        chmod=os.fchmod
        def fail(fd,mode):
            if mode==0o440:raise OSError('inert failure before file permission publication')
            return chmod(fd,mode)
        with patch.object(os,'fchmod',side_effect=fail):
            with self.assertRaises(OSError):self.stage()
        pending=root/'config/rabbitmq.conf.pending'
        self.assertTrue(pending.exists());self.assertEqual(pending.stat().st_mode&0o777,0o600)
        self.stage();self.assertFalse(pending.exists())
        self.assertEqual((root/'config/rabbitmq.conf').stat().st_mode&0o777,0o440)

    def test_sync_failure_preserves_pending_without_following_it_or_reporting_success(self):
        self.prepare();self.stage()
        original=host.publish
        def fail(source,destination,*args,**kwargs):
            if destination.name=='cookie':raise OSError('inert directory persistence failure')
            return original(source,destination,*args,**kwargs)
        with patch.object(host,'publish',side_effect=fail):
            with self.assertRaises(OSError):self.stage()
        root=self.state.path(runtime.broker.RUNTIME)
        self.assertTrue((root/'cookie.pending').exists())
        self.stage();self.assertFalse((root/'cookie.pending').exists())





@unittest.skipUnless(os.name=='posix','container lifecycle uses inert Docker/proc and real durable receipts')
class Containers(unittest.TestCase):
    def setUp(self):
        import copy
        import importlib.util
        fixture=Publication();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.state=fixture.state;self.expected=fixture.expected;self.root=fixture.root
        spec=importlib.util.spec_from_file_location('polygon_broker_inspection_fixture',ROOT/'tests/broker.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        model=module.Broker();model.setUp()
        self.template,self.account,self.helpers,self.image=model.container()
        self.template['Config']['Labels']['erpc.polygon.owner']=self.expected['owner']
        self.template['State']={'Running':False,'Paused':False,'Restarting':False,'Dead':False,'Pid':0,'Status':'created'}
        self.state.accounts.verify.return_value={'broker':self.account}
        self.state.write('/etc/polygon/broker-image.json',{'contract':self.expected,'image':runtime.broker.identity(self.expected)})
        self.proc=self.state.path('/proc');self.proc.mkdir();(self.proc/'1').mkdir()
        self.process={'dead':False,'uids':(0,)*4,'arguments':[b'/sbin/init'],'descriptors':[],'cgroup':'0::/init.scope'}
        self.state.proof=SimpleNamespace(proc=self.proc,process=Mock(side_effect=lambda pid:self.process),listening=Mock(return_value=[]))
        import broker_storage
        context=patch.object(broker_storage,'original');context.start();self.addCleanup(context.stop)
        self.calls=[];self.current=None;self.created=0;self.timeout=False;self.staging=Mock()
        def inspect(kind,identity):
            if kind=='image':return copy.deepcopy(self.image)
            self.assertIsNotNone(self.current);self.assertEqual(identity,self.current['Id'])
            return copy.deepcopy(self.current)
        def call(*args,**kwargs):
            self.calls.append(args);out=b''
            if args[:2]==('container','ls'):
                selector=args[args.index('--filter')+1]
                if self.current and selector in ('name=^/'+runtime.broker.NAME+'$','id='+self.current['Id']):out=(self.current['Id']+'\n').encode()
            elif args[0]=='create':
                receipt=self.state.read(runtime.CONTAINER)
                self.assertEqual(receipt['state'],'reserved');self.assertIsNone(receipt['container_id'])
                self.current=copy.deepcopy(self.template);self.created+=1
                self.current['Id']=('d' if self.created==1 else 'f')*64
                for index,value in enumerate(args[:-1]):
                    if value=='--label':
                        key,val=args[index+1].split('=',1);self.current['Config']['Labels'][key]=val
                if self.timeout:raise subprocess.TimeoutExpired(['inert docker'],120)
                out=(self.current['Id']+'\n').encode()
            elif args[:2]==('container','stop'):
                self.assertEqual(args[-1],self.current['Id']);self.current['State']=dict(self.template['State'],Status='exited')
            elif args[:2]==('container','rm'):
                self.assertEqual(args[-1],self.current['Id']);self.current=None
            else:self.fail('unexpected Docker operation')
            return subprocess.CompletedProcess(args,0,out,b'')
        self.client=SimpleNamespace(call=call,inspect=inspect,prefix=['/usr/bin/docker','--host','unix:///run/docker.sock'])
        self.manager=runtime.Container(self.state,self.expected,self.client)
    def prepare(self,helpers=None,creation='e'*32):
        return self.manager.prepare('a'*32,{},helpers or self.helpers,creation=creation,stage_files=self.staging)

    def test_durable_create_intent_then_exact_cid_retry_never_uses_a_name_for_start(self):
        token=self.prepare();self.assertEqual(token['container_id'],'d'*64)
        self.assertEqual(self.prepare(),token);self.assertEqual(self.created,1)
        command=self.manager.start_command(token)
        self.assertEqual(command[-4:],['container','start','--attach','d'*64])
        self.assertNotIn(runtime.broker.NAME,command)

    def test_ambiguous_create_reuses_original_creation_and_never_creates_twice(self):
        self.timeout=True
        with self.assertRaises(subprocess.TimeoutExpired):self.prepare()
        self.assertEqual(self.state.read(runtime.CONTAINER)['state'],'reserved')
        self.timeout=False;token=self.prepare(creation='9'*32)
        self.assertEqual(token['creation'],'e'*32);self.assertEqual(self.created,1)

    def test_foreign_creation_label_after_timeout_is_never_adopted(self):
        self.timeout=True
        with self.assertRaises(subprocess.TimeoutExpired):self.prepare()
        self.current['Config']['Labels']['erpc.polygon.creation']='9'*32
        self.staging.reset_mock()
        with self.assertRaises(ValueError):self.prepare()
        self.staging.assert_not_called()
        self.assertEqual(self.state.read(runtime.CONTAINER)['state'],'reserved')
        self.assertFalse(any(args[:2] in (('container','stop'),('container','rm')) for args in self.calls))

    def test_delayed_old_stop_cannot_stop_replacement_after_helper_upgrade(self):
        old=self.prepare();new=self.prepare(helpers='8'*64,creation='9'*32)
        self.assertNotEqual(old,new);self.assertEqual(self.created,2)
        self.calls.clear()
        with self.assertRaises(ValueError):self.manager.stop(old)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.manager.stop(new)['container_id'],new['container_id'])

    def test_original_stop_ignores_nss_and_budget_drift_but_start_refuses_it(self):
        token=self.prepare();self.state.accounts.verify.side_effect=ValueError('inert NSS drift')
        self.current['HostConfig']['Memory']=1024
        with self.assertRaises(ValueError):self.manager.start_command(token)
        self.assertTrue(self.manager.stop(token)['broker_stopped'])

    def test_missing_original_cid_cannot_be_silently_recreated(self):
        self.prepare();self.current=None
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.created,1)

    def test_failed_retirement_resumes_only_original_cid_and_does_not_reset_data(self):
        self.prepare();original=self.client.call
        def failed(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[:2]==('container','rm'):raise subprocess.TimeoutExpired(['inert docker'],60)
            return result
        self.client.call=failed
        with self.assertRaises(subprocess.TimeoutExpired):self.prepare(helpers='8'*64,creation='9'*32)
        self.assertEqual(self.state.read(runtime.CONTAINER)['state'],'retiring')
        self.client.call=original
        self.assertEqual(self.prepare(helpers='8'*64,creation='9'*32)['container_id'],'f'*64)
        self.assertFalse(any(args[0] in ('volume','system','image') for args in self.calls))

    def test_running_broker_requires_original_beam_pid_socket_and_tls_identity(self):
        from unittest.mock import MagicMock
        token=self.prepare();cid=token['container_id'];pid=601
        self.current['State']=dict(self.template['State'],Running=True,Status='running',Pid=pid)
        native='/opt/erlang/lib/erlang/erts-16.3/bin/beam.smp'
        path=self.proc/str(pid);image=path/'root'/native.lstrip('/');image.parent.mkdir(parents=True)
        image.write_bytes(b'inert original image executable');(path/'exe').symlink_to(image)
        group='/system.slice/docker-'+cid+'.scope';directory=self.state.path('/sys/fs/cgroup'+group)
        directory.mkdir(parents=True);(directory/'cgroup.procs').write_text(str(pid))
        self.process={'dead':False,'pid':pid,'generation':'701','uids':(991,)*4,'gids':(992,)*4,
            'groups':(992,),'executable':native,'deleted':False,'arguments':[native.encode()],
            'cgroup':'0::'+group,'descriptors':['socket:[56710]']}
        self.state.proof.generation=Mock(return_value='701')
        self.state.proof.listening.return_value=[(5671,'127.0.0.14',991,'56710')]
        self.state.path('/etc/polygon/local-ca.pem').write_bytes(b'inert public CA')
        self.state.write(local_tls.RECORD,{'contract':self.expected,'ca_sha256':hashlib.sha256(b'inert public CA').hexdigest()})
        context=MagicMock();stream=Mock();connect=Mock(return_value=stream)
        with patch.object(local_tls,'client_context',return_value=context):
            self.assertTrue(self.manager.health(token,connect)['ready'])
            context.wrap_socket.assert_called_once_with(stream,server_hostname='127.0.0.14')
            connect.assert_called_once_with(('127.0.0.14',5671),timeout=8)
            self.state.proof.listening.return_value=[(5671,'127.0.0.14',2001,'foreign')]
            with self.assertRaises(ValueError):self.manager.health(token,connect)
            self.state.proof.listening.return_value=[(5671,'127.0.0.14',991,'56710')]
            self.state.proof.generation.return_value='702'
            with self.assertRaises(ValueError):self.manager.health(token,connect)
        stream.close.assert_called()

    def test_creation_receipt_sync_failure_precedes_any_docker_mutation(self):
        write=self.state.write
        def failed(path,value,*args,**kwargs):
            write(path,value,*args,**kwargs)
            if path==runtime.CONTAINER:raise OSError('inert post-rename directory sync failure')
        with patch.object(self.state,'write',side_effect=failed):
            with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.created,0);self.staging.assert_not_called()
        self.assertEqual(self.prepare()['creation'],'e'*32);self.assertEqual(self.created,1)

    def test_inactive_container_is_not_proof_of_no_retained_uid_or_foreign_data_writer(self):
        token=self.prepare()
        for changed in (dict(self.process,uids=(991,)*4),dict(self.process,descriptors=[runtime.broker.DATA+'/mnesia/db']),
                        dict(self.process,cgroup='0::/system.slice/docker-'+token['container_id']+'.scope')):
            self.process=changed
            with self.assertRaises(ValueError):self.manager.stop(token)
        self.state.proof.process.side_effect=PermissionError('inert proc denial')
        with self.assertRaises(PermissionError):self.manager.stop(token)


if __name__=='__main__':unittest.main()
