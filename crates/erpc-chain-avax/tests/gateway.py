# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Managed gateway process/socket/HTTP proofs, with inert files and transport."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('avax_gateway_native_fixture',Path(__file__).with_name('observe.py'))
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
o=n.o

class Gateway(unittest.TestCase):
    def setUp(self):
        self.native=n.Process();self.native.setUp();self.addCleanup(self.native.doCleanups)
        self.c=self.native.c;self.expected=self.native.expected;self.root=self.native.root
        self.binary=self.root/'usr/sbin/nginx';self.binary.parent.mkdir(parents=True,exist_ok=True)
        self.binary.write_bytes(b'inert distribution nginx placeholder');self.binary.chmod(0o755)
        self.config=self.root/'etc/avalanchego/proxy.conf'
        self.config.write_text('http { server {\n    listen 0.0.0.0:9652;\n} server {\n    listen 127.0.0.1:9653;\n}}\n')
        self.c.gateway(self.expected,publish=True)
        self.proc=self.root/'proc/234';self.proc.mkdir();self.native.fixture.data_owners[self.proc]=(999,999)
        self.stat='234 (nginx) S '+'0 '*18+'200 '+'0 '*5
        (self.proc/'stat').write_text(self.stat)
        (self.proc/'status').write_text('Uid:\t999 999 999 999\nGid:\t999 999 999 999\nGroups:\t999\n')
        (self.proc/'cmdline').write_bytes(b'nginx: master process /usr/sbin/nginx -c /etc/avalanchego/proxy.conf -g daemon off;\0\0')
        (self.proc/'cgroup').write_text('0::/system.slice/avalanche-rpc.service\n')
        (self.proc/'exe').symlink_to(self.binary);(self.proc/'fd').mkdir()
        for fd,inode in ((8,666),(9,667)):(self.proc/'fd'/str(fd)).symlink_to('socket:['+str(inode)+']')
        self.tcp=self.native.tcp
        self.tcp.write_text(self.tcp.read_text()+'0: 00000000:25B4 00000000:0000 0A 0:0 0:0 0 999 0 666\n0: 0100007F:25B5 00000000:0000 0A 0:0 0:0 0 999 0 667\n')
        self.properties=dict(self.native.properties,MainPID=b'234',ControlGroup=b'/system.slice/avalanche-rpc.service')
        previous=self.c.run
        def command(argv,**kwargs):
            if argv[:2]==['systemctl','show'] and argv[-1]=='avalanche-rpc.service':
                key=next(x[len('--property='):] for x in argv if x.startswith('--property='))
                if key in self.properties:return subprocess.CompletedProcess(argv,0,self.properties[key],b'')
            return previous(argv,**kwargs)
        self.c.run=command

    @staticmethod
    def reply(path,method,params,port=9650):
        values={'info.getNetworkID':{'networkID':'5'},'info.getNodeID':{'nodeID':'NodeID-abc'},
                'eth_chainId':'0xa869','eth_blockNumber':'0x1','health.health':{'healthy':True},
                'info.isBootstrapped':{'isBootstrapped':True},'platform.getCurrentValidators':{'validators':[]}}
        return {'jsonrpc':'2.0','id':1,'result':values.get(method,{})}

    def observe(self):
        with patch.object(o,'rpc',side_effect=self.reply):return o.observe(self.c,self.expected)

    def test_actual_native_and_gateway_observation_preserve_separate_authority(self):
        result=self.observe()
        self.assertTrue(result['authority']['verified']);self.assertTrue(result['gateway']['authority']['verified'])
        self.assertEqual(result['gateway']['rpc_bind'],'0.0.0.0')
        self.assertEqual(result['gateway']['external_reachability'],'not tested')
        self.properties['ActiveState']=b'inactive'
        calls=[]
        def reply(*args,**kwargs):calls.append(kwargs.get('port',9650));return self.reply(*args,**kwargs)
        with patch.object(o,'rpc',side_effect=reply):result=o.observe(self.c,self.expected)
        self.assertTrue(result['authority']['verified']);self.assertFalse(result['gateway']['authority']['verified'])
        self.assertNotIn(9652,calls)

    def test_loopback_only_gateway_and_legacy_missing_receipt_are_distinguished(self):
        self.config.write_text(self.config.read_text().replace('0.0.0.0:9652','127.0.0.1:9652'))
        self.tcp.write_text(self.tcp.read_text().replace('00000000:25B4','0100007F:25B4'))
        self.c.gateway(self.expected,publish=True)
        result=self.observe()
        self.assertTrue(result['gateway']['authority']['verified'])
        self.assertEqual(result['gateway']['rpc_bind'],'127.0.0.1')
        self.assertEqual(result['gateway']['external_reachability'],'not tested')
        self.c.path('/etc/avalanchego/gateway.json').unlink()
        result=self.observe()
        self.assertTrue(result['authority']['verified'])
        self.assertFalse(result['gateway']['authority']['verified'])
        self.assertFalse(self.c.path('/etc/avalanchego/gateway.json').exists())

    def test_spoofed_listener_process_and_public_binding_do_not_report_gateway_ready(self):
        original=self.tcp.read_text()
        for bad in (original.replace('666','668'),original.replace('00000000:25B4','0100007F:25B4'),
                    original+'0: 0100007F:270F 00000000:0000 0A 0:0 0:0 0 999 0 666\n'):
            self.tcp.write_text(bad);self.assertFalse(self.observe()['gateway']['authority']['verified'])
        self.tcp.write_text(original)
        self.native.fixture.data_owners[self.proc]=(2001,2001)
        self.assertFalse(self.observe()['gateway']['authority']['verified'])
        self.native.fixture.data_owners[self.proc]=(999,999)
        (self.proc/'cmdline').write_bytes(b'nginx: worker process\0')
        self.assertFalse(self.observe()['gateway']['authority']['verified'])

    def test_config_package_change_and_replaced_executable_require_redeployment(self):
        config=self.config.read_bytes();self.config.write_bytes(config+b'# drift\n')
        self.assertFalse(self.observe()['gateway']['authority']['verified']);self.config.write_bytes(config)
        old=self.binary.with_name('old');self.binary.rename(old);self.binary.write_bytes(b'changed binary')
        (self.proc/'exe').unlink();(self.proc/'exe').symlink_to(old)
        self.assertFalse(self.observe()['gateway']['authority']['verified'])
        self.c.gateway(self.expected,publish=True)
        self.assertFalse(self.observe()['gateway']['authority']['verified'])
        (self.proc/'exe').unlink();(self.proc/'exe').symlink_to(self.binary)
        self.assertTrue(self.observe()['gateway']['authority']['verified'])

    def test_failed_http_mismatched_identity_and_pid_reuse_keep_native_observations(self):
        for failure in ('http','identity','generation'):
            def reply(path,method,params,port=9650):
                if port==9652:
                    if failure=='http':raise OSError('inert gateway refused')
                    if failure=='generation':(self.proc/'stat').write_text(self.stat.replace('200','201'))
                    if failure=='identity' and method=='info.getNodeID':return {'result':{'nodeID':'NodeID-other'}}
                return self.reply(path,method,params,port)
            with patch.object(o,'rpc',side_effect=reply):result=o.observe(self.c,self.expected)
            self.assertTrue(result['authority']['verified']);self.assertIn('bootstrap',result)
            self.assertFalse(result['gateway']['authority']['verified']);(self.proc/'stat').write_text(self.stat)

    def test_receipt_failure_does_not_complete_install_and_retry_resyncs(self):
        self.c.write('/etc/avalanchego/lifecycle.json',{'contract':self.expected,'phase':'preparing','intent':'a'*32,'target':self.native.target})
        root=self.c.ROOT;actual=os.fsync;calls=[];publishing=[False];write=self.c.write
        def tracked(name,*args,**kwargs):
            publishing[0]=name=='/etc/avalanchego/gateway.json'
            try:return write(name,*args,**kwargs)
            finally:publishing[0]=False
        def fault(fd):
            if publishing[0] and os.fstat(fd).st_ino==root.stat().st_ino:
                calls.append(fd);raise OSError('inert gateway receipt sync failure')
            return actual(fd)
        # Both mocked processes are inert files; isolate publication from process drain.
        with patch.object(self.c,'quiet_uid'),patch.object(self.c,'write',side_effect=tracked):
            for _ in range(2):
                with patch.object(os,'fsync',side_effect=fault):
                    with self.assertRaises(OSError):self.c.installed(self.expected,'a'*32)
                self.assertEqual(self.c.durable_json('/etc/avalanchego/lifecycle.json')['phase'],'preparing')
            self.c.installed(self.expected,'a'*32)
        self.assertTrue(calls);self.assertEqual(self.c.durable_json('/etc/avalanchego/lifecycle.json')['phase'],'installed')

    def test_gateway_transport_is_fixed_no_proxy_no_redirect_and_bounded(self):
        class Response:
            status=302
            def read(self,size):return b'x'*size
        class Connection:
            def request(self,*args):self.requested=args
            def getresponse(self):return Response()
            def close(self):pass
        connection=Connection()
        with patch.object(o.http.client,'HTTPConnection',return_value=connection) as create:
            with self.assertRaises(ValueError):o.rpc('/ext/info','info.getNodeID',{},port=9652)
            create.assert_called_once_with('127.0.0.1',9652,timeout=8)
            Response.status=200
            with self.assertRaises(ValueError):o.rpc('/ext/info','info.getNodeID',{},port=9652)
        with self.assertRaises(ValueError):o.rpc('/ext/info','info.getNodeID',{},port=80)

if __name__=='__main__':unittest.main()
