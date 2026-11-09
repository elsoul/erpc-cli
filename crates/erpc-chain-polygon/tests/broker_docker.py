# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual local-daemon boundary with inert peer metadata and no Docker process."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


@unittest.skipUnless(os.name=='posix','root daemon socket is Linux-specific, modeled without root')
class Boundary(unittest.TestCase):
    def setUp(self):
        import broker_docker
        self.module=broker_docker
        spec=importlib.util.spec_from_file_location('polygon_broker_daemon_fixture',ROOT/'tests/control.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        self.fixture=fixture.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.expected=dict(self.fixture.contract,role='validator')
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        # Actual init.yml creates this protected management namespace before
        # validator preparation can construct its dedicated Docker client.
        self.state.path('/etc/erpc/polygon').mkdir(parents=True,exist_ok=True,mode=0o700)
        binary=self.state.path('/usr/bin/docker');binary.parent.mkdir(parents=True);binary.write_text('inert CLI marker');binary.chmod(0o755)
        self.state.path('/run').mkdir(exist_ok=True)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(self.state.path(broker_docker.SOCKET)))
        self.addCleanup(listener.close);self.state.path(broker_docker.SOCKET).chmod(0o660)
        self.peer=(123,0,0);self.closed=False;self.commands=[]
        self.info={'OSType':'linux','CgroupVersion':'2','CgroupDriver':'systemd','MemoryLimit':True,'SwapLimit':True,
            'PidsLimit':True,'CpuCfsQuota':True,'SecurityOptions':['name=seccomp,profile=builtin','name=cgroupns']}
        outer=self
        class Stream:
            def settimeout(self,value):outer.assertEqual(value,10)
            def connect(self,path):outer.assertEqual(path,str(outer.state.path(broker_docker.SOCKET)))
            def getsockopt(self,*args):return struct.pack('3i',*outer.peer)
            def close(self):outer.closed=True
        self.stream=Stream()
        original=self.state.run
        def run(args,**kwargs):
            if args[0]!='/usr/bin/docker':return original(args,**kwargs)
            self.commands.append((args,kwargs))
            result=self.info if 'info' in args else [{'Id':'inert public metadata'}]
            return subprocess.CompletedProcess(args,0,json.dumps(result).encode(),b'')
        self.state.run=run
        entry=patch.object(socket,'SO_PEERCRED',getattr(socket,'SO_PEERCRED',17),create=True);entry.start();self.addCleanup(entry.stop)

    def open(self,create=True):return self.module.Docker(self.state,self.expected,create,lambda *args:self.stream)

    def test_fixed_local_root_daemon_and_anonymous_namespace_ignore_ambient_contexts(self):
        with patch.dict(os.environ,{'DOCKER_HOST':'inert-foreign','DOCKER_CONTEXT':'inert-context'}):
            client=self.open();self.assertTrue(self.closed)
            self.assertEqual(client.inspect('container','inert-id'),{'Id':'inert public metadata'})
        self.assertEqual(self.state.read(self.module.CONFIG+'/config.json'),{'auths':{'docker.io':{}}})
        for args,kwargs in self.commands:
            self.assertEqual(args[:5],['/usr/bin/docker','--host','unix:///run/docker.sock','--config',self.module.CONFIG])
            self.assertNotIn('DOCKER_HOST',kwargs['env']);self.assertNotIn('DOCKER_CONTEXT',kwargs['env'])
        # A nonempty explicit anonymous auth record prevents Docker CLI's
        # documented automatic credential-helper discovery (ContainsAuth).
        self.assertTrue(self.module.LOCAL_CONFIG['auths'])
        self.assertEqual(self.module.LOCAL_CONFIG['auths']['docker.io'],{})

    def test_nonroot_peer_is_refused_before_namespace_publication_or_cli_execution(self):
        self.peer=(123,1001,1001)
        with self.assertRaises(ValueError):self.open()
        self.assertTrue(self.closed);self.assertEqual(self.commands,[])
        self.assertFalse(self.state.path(self.module.CONFIG).exists())

    def test_rootless_remapped_uid_or_wrong_kernel_daemon_is_refused(self):
        baseline=self.info
        for change in ({'OSType':'windows'},{'CgroupVersion':'1'},{'CgroupDriver':'cgroupfs'},
                       {'SecurityOptions':['name=rootless']},{'SecurityOptions':['name=userns']},
                       *({name:False} for name in ('MemoryLimit','SwapLimit','PidsLimit','CpuCfsQuota'))):
            self.info=dict(baseline,**change)
            with self.assertRaises(ValueError):self.open()
        self.assertTrue(all('info' in args for args,_kwargs in self.commands))

    def test_existing_credential_helper_or_unprotected_namespace_is_never_repaired(self):
        self.open();directory=self.state.path(self.module.CONFIG)
        self.state.write(self.module.CONFIG+'/config.json',{'credsStore':'inert-untrusted-helper'})
        before=len(self.commands)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(len(self.commands),before)
        self.assertEqual(self.state.read(self.module.CONFIG+'/config.json'),{'credsStore':'inert-untrusted-helper'})
        directory.chmod(0o777)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(directory.stat().st_mode&0o777,0o777)

    def test_redirected_or_publicly_accessible_daemon_socket_is_refused(self):
        path=self.state.path(self.module.SOCKET);path.chmod(0o666)
        with self.assertRaises(ValueError):self.open()
        path.chmod(0o660);path.rename(path.with_suffix('.original'));path.symlink_to(path.with_suffix('.original'))
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.commands,[])

    def test_stopped_foreign_daemon_data_is_not_implicitly_started(self):
        self.assertEqual(self.module.start_allowed(self.state,self.expected),{'fresh_daemon':True})
        data=self.state.path('/var/lib/docker');data.mkdir();(data/'inert-foreign-container-state').touch()
        with self.assertRaises(ValueError):self.module.start_allowed(self.state,self.expected)
        self.assertTrue((data/'inert-foreign-container-state').exists())
        self.assertEqual(self.commands,[])
        self.assertFalse(any(args[:2]==['systemctl','start'] for args in self.fixture.calls))

    def test_interrupted_anonymous_config_publication_resumes_only_exact_public_bytes(self):
        import host
        original=host.publish
        def publish(source,destination,*args,**kwargs):
            if destination==self.state.path(self.module.CONFIG+'/config.json'):raise OSError('inert interrupted publication')
            return original(source,destination,*args,**kwargs)
        with patch.object(host,'publish',side_effect=publish):
            with self.assertRaises(OSError):self.open()
        self.assertEqual(self.commands,[])
        self.assertEqual(self.state.read(self.module.CONFIG+'/config.pending'),self.module.LOCAL_CONFIG)
        self.open();self.assertFalse(self.state.path(self.module.CONFIG+'/config.pending').exists())
        self.state.path(self.module.CONFIG+'/config.json').rename(self.state.path(self.module.CONFIG+'/config.pending'))
        self.state.path(self.module.CONFIG+'/config.pending').write_text('{"credsStore":"inert-untrusted"}')
        before=len(self.commands)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(len(self.commands),before)


if __name__=='__main__':unittest.main()
