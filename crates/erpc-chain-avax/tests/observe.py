# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original process/socket authority using inert files; never execute native code."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('avax_authority_fixture',Path(__file__).with_name('authority.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
source=Path(__file__).resolve().parents[1]/'templates/jinja/observe.py'
spec=importlib.util.spec_from_file_location('avax_observer_fixture',source)
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)

class Process(unittest.TestCase):
    def setUp(self):
        self.fixture=a.Authority();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.original_identity();self.c=self.fixture.c;self.root=self.fixture.root;self.expected=self.fixture.expected
        self.native=self.root/'opt/avalanchego/v1.15.2/avalanchego'
        self.native.parent.mkdir(parents=True);self.native.write_bytes(b'inert native file never executed');self.native.chmod(0o755)
        (self.native.parent.parent/'current').symlink_to('/opt/avalanchego/v1.15.2')
        self.c.write('/etc/avalanchego/node.json',{'data-dir':'/var/lib/avalanchego'})
        self.target={'version':'v1.15.2','commit':'a'*40,'archive_sha256':'b'*64}
        (self.native.parent/'.verified-sha256').write_text(self.target['archive_sha256'])
        (self.native.parent/'.verified-binary-sha256').write_text(hashlib.sha256(self.native.read_bytes()).hexdigest())
        self.c.native(self.expected,publish=True,target=self.target)
        self.proc=self.root/'proc/123';self.proc.mkdir();self.fixture.data_owners[self.proc]=(999,999)
        self.stat='123 (avalanchego) S '+'0 '*18+'100 '+'0 '*5
        (self.proc/'stat').write_text(self.stat)
        (self.proc/'status').write_text('Uid:\t999 999 999 999\nGid:\t999 999 999 999\nGroups:\t999\n')
        (self.proc/'cmdline').write_bytes(b'/opt/avalanchego/current/avalanchego\0--config-file=/etc/avalanchego/node.json\0')
        (self.proc/'cgroup').write_text('0::/system.slice/avalanchego.service\n')
        (self.proc/'exe').symlink_to(self.native)
        (self.proc/'fd').mkdir();(self.proc/'fd/7').symlink_to('socket:[555]')
        (self.root/'proc/net').mkdir();self.tcp=self.root/'proc/net/tcp'
        self.tcp.write_text('header\n0: 0100007F:25B2 00000000:0000 0A 0:0 0:0 0 999 0 555\n')
        self.properties={'User':b'999','Group':b'999','SupplementaryGroups':b'','MainPID':b'123','ControlGroup':b'/system.slice/avalanchego.service','ActiveState':b'active'}
        previous=self.fixture.command
        def command(argv,**kwargs):
            if argv[:2]==['systemctl','show']:
                key=next(x[len('--property='):] for x in argv if x.startswith('--property='))
                if key in self.properties:return subprocess.CompletedProcess(argv,0,self.properties[key],b'')
            if argv[:2]==['systemctl','is-active']:return subprocess.CompletedProcess(argv,0,b'active',b'')
            return previous(argv,**kwargs)
        self.c.run=command

    def test_real_original_process_and_loopback_inode_are_required(self):
        self.assertEqual(o.process(self.c,self.expected)[0:2],('123','100'))
        for key,value in [('MainPID',b'0'),('ActiveState',b'inactive'),('ControlGroup',b'/unrelated')]:
            original=self.properties[key];self.properties[key]=value
            with self.assertRaises(ValueError):o.process(self.c,self.expected)
            self.properties[key]=original
        self.fixture.data_owners[self.proc]=(2001,2001)
        with self.assertRaises(ValueError):o.process(self.c,self.expected)

    def test_foreign_listener_replaced_binary_and_changed_argv_are_refused(self):
        original=self.tcp.read_text()
        for changed in (original.replace('555','556'),original.replace('0100007F','00000000'),original+original.splitlines()[1]+'\n'):
            self.tcp.write_text(changed)
            with self.assertRaises(ValueError):o.process(self.c,self.expected)
        self.tcp.write_text(original)
        (self.proc/'cmdline').write_bytes(b'unrelated\0')
        with self.assertRaises(ValueError):o.process(self.c,self.expected)
        (self.proc/'cmdline').write_bytes(b'/opt/avalanchego/current/avalanchego\0--config-file=/etc/avalanchego/node.json\0')
        old=self.native.with_name('old-native');self.native.rename(old);self.native.write_bytes(b'substituted inert bytes')
        (self.proc/'exe').unlink();(self.proc/'exe').symlink_to(old)
        with self.assertRaises(ValueError):o.process(self.c,self.expected)

    def test_matching_rpc_replies_cannot_replace_process_authority_or_survive_pid_reuse(self):
        self.properties['ActiveState']=b'inactive'
        with patch.object(o,'rpc',return_value={'result':{'nodeID':'NodeID-abc'}}) as rpc:
            result=o.observe(self.c,self.expected);rpc.assert_not_called()
        self.assertFalse(result['authority']['verified'])
        self.properties['ActiveState']=b'active'
        def reply(*args):
            (self.proc/'stat').write_text(self.stat.replace('100','101'))
            return {'result':{'nodeID':'NodeID-abc'}}
        with patch.object(o,'rpc',side_effect=reply):result=o.observe(self.c,self.expected)
        self.assertFalse(result['authority']['verified'])
        self.assertNotIn('identity',result)
        (self.proc/'stat').write_text(self.stat)
        with patch.object(o,'rpc',return_value={'result':{'nodeID':'NodeID-abc'}}):result=o.observe(self.c,self.expected)
        self.assertTrue(result['authority']['verified'])

    def test_remote_database_floor_rejects_stale_inventory_before_any_new_mutation(self):
        old=dict(self.target)
        newer=dict(self.target,version='v1.15.3',commit='c'*40,archive_sha256='d'*64)
        self.c.write('/etc/avalanchego/database-floor.json',{'contract':self.expected,'target':newer})
        before=self.c.path('/etc/avalanchego/contract.json').read_bytes();self.fixture.calls.clear()
        with self.assertRaises(ValueError):self.c.begin(self.expected,'a'*32,old)
        with self.assertRaises(ValueError):self.c.floor(self.expected,dict(newer,commit='e'*40))
        self.assertFalse(self.fixture.calls)
        self.assertEqual(self.c.path('/etc/avalanchego/contract.json').read_bytes(),before)
        self.assertFalse(self.c.path('/etc/avalanchego/stopped').exists())

    def test_floor_persistence_failure_never_starts_and_retry_preserves_same_target(self):
        import shutil
        shutil.rmtree(self.proc)
        self.c.write('/etc/avalanchego/lifecycle.json',{'contract':self.expected,'phase':'installed','intent':'a'*32,'target':self.target})
        class Firewall:
            def dispatch(self,*args):pass
        real_sync=os.fsync;root=self.c.ROOT;attempts=[]
        def fail_floor(fd):
            if self.c.path('/etc/avalanchego/database-floor.json').exists() and os.fstat(fd).st_ino==root.stat().st_ino:
                attempts.append(fd);raise OSError('inert database floor directory sync failure')
            return real_sync(fd)
        with patch.object(self.c,'capacity'),patch.object(self.c,'firewall',return_value=Firewall()),patch.object(self.c,'start_units') as started:
            for _ in range(2):
                with patch.object(os,'fsync',side_effect=fail_floor):
                    with self.assertRaises(OSError):self.c.activate(self.expected,'a'*32)
                started.assert_not_called()
            result=self.c.activate(self.expected,'a'*32)
            self.assertTrue(result['startup_requested']);started.assert_called_once()
        self.assertGreaterEqual(len(attempts),2)
        self.assertEqual(self.c.durable_json('/etc/avalanchego/database-floor.json')['target'],self.target)

    def test_fixed_transport_does_not_follow_redirects_or_report_success_errors(self):
        class Connection:
            def request(self,*args):self.requested=args
            def getresponse(self):return type('Response',(),{'status':302})()
            def close(self):pass
        connection=Connection()
        with patch.object(o.http.client,'HTTPConnection',return_value=connection) as create:
            with self.assertRaises(ValueError):o.rpc('/ext/info','info.getNodeID',{})
        create.assert_called_once_with('127.0.0.1',9650,timeout=8)
        self.assertEqual(connection.requested[0:2],('POST','/ext/info'))

if __name__=='__main__':unittest.main()
