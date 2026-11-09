# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual process/socket authority with inert proc files; no native daemon."""
import sys
sys.dont_write_bytecode=True
import hashlib
import json
import os
from pathlib import Path
import signal
import unittest
from unittest.mock import patch
import lifecycle
c=lifecycle.c
RUNNING=c.running_process


class Processes(unittest.TestCase):
    def setUp(self):
        self.fixture=lifecycle.HostTests('runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        patch.object(c,'running_process',side_effect=RUNNING).start()
        patch.object(c,'service_properties',side_effect=lifecycle.ORIGINAL_PROPERTIES).start()
        patch.object(c,'drain_original',side_effect=lifecycle.ORIGINAL_DRAIN).start()
        patch.object(c,'disable_original_boot',side_effect=lifecycle.ORIGINAL_DISABLE).start()
        self.state=c.read_state();self.pid=98761;self.proc=c.PROC/str(self.pid)
        self.proc.mkdir();(self.proc/'fd').mkdir()
        (c.PROC/'net').mkdir()
        self.stat('111');self.credentials()
        (self.proc/'cgroup').write_text('0::/system.slice/erpc-bitcoin.service\n')
        (self.proc/'cmdline').write_bytes(('\0'.join(c.daemon_arguments())+'\0').encode())
        (self.proc/'exe').symlink_to(c.release_dir(self.state['installed'])/'bin/bitcoind')
        (self.proc/'fd/3').symlink_to('socket:[6001]')
        self.network()
        template=Path(c.__file__).with_name('erpc-bitcoin.service').read_text()
        # The actual template keeps the exact same protected argument syntax.
        template=template.replace('@BITCOIN_UID@',str(os.getuid())).replace('@BITCOIN_GID@',str(os.getgid()))
        template=template.replace('@BITCOIN_GUARD@',"/usr/bin/python3 -I -c 'inert public loader' guard")
        template=template.replace('/opt/erpc-bitcoin',str(c.OPT)).replace('/var/lib/erpc-bitcoin',str(c.ROOT)).replace('/etc/erpc/bitcoin.conf',str(c.CONF))
        c.UNIT_PATH.write_text(template)
        digest=hashlib.sha256(template.encode()).hexdigest()
        self.state.update(unit_sha256=digest,unit_receipts=[digest]);c.save(self.state)
        self.properties={key:'' for key in c.SERVICE_FIELDS}
        self.properties.update(LoadState='loaded',ActiveState='active',SubState='running',MainPID=str(self.pid),
            ControlGroup='/system.slice/erpc-bitcoin.service',FragmentPath=str(c.UNIT_PATH),User=str(os.getuid()),Group=str(os.getgid()),NoNewPrivileges='yes')
        for name in ('ExecStart','ExecStartPre'):
            line=next(line.partition('=')[2] for line in template.splitlines() if line.startswith(name+'='))
            argv=c.shlex.split(line.lstrip('+'))
            self.properties[name]='{ path='+argv[0]+' ; argv[]='+' '.join(argv)+' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'
        self.calls=[];self.signals=[]
        def run(argv,**kwargs):
            self.calls.append(argv)
            if argv[1]=='show':return ''.join(key+'='+value+'\n' for key,value in self.properties.items()).encode()
            if argv[1]=='stop':self.remove_process()
            return b''
        patch.object(c,'run',side_effect=run).start()
        self.original_run=run
        patch.object(c.os,'pidfd_open',side_effect=lambda pid,flags:os.open(c.UNIT_PATH,os.O_RDONLY),create=True).start()
        def send(descriptor,number):
            self.signals.append(number);self.remove_process()
        patch.object(c.signal,'pidfd_send_signal',side_effect=send,create=True).start()

    def stat(self,start):
        fields=['S']+['0']*18+[start]+['0']*3
        (self.proc/'stat').write_text(str(self.pid)+' (inert public fixture) '+' '.join(fields))

    def credentials(self,uid=None):
        uid=os.getuid() if uid is None else uid
        (self.proc/'status').write_text('Uid:\t'+'\t'.join([str(uid)]*4)+'\nGid:\t'+'\t'.join([str(os.getgid())]*4)+'\nGroups:\t'+str(os.getgid())+'\n')

    def network(self,owner=None,accepted=False):
        port=format(c.NETWORKS['signet'][1],'04X');uid=os.getuid() if owner is None else owner
        rows=['header',f'0: 0100007F:{port} 00000000:0000 0A 0:0 0:0 0 {uid} 0 6001']
        if accepted:rows.append(f'1: 0100007F:{port} 0100007F:C350 01 0:0 0:0 0 {uid} 0 6002')
        (c.PROC/'net/tcp').write_text('\n'.join(rows)+'\n');(c.PROC/'net/tcp6').write_text('header\n')

    def remove_process(self):
        import shutil
        if self.proc.exists():shutil.rmtree(self.proc)
        self.properties.update(ActiveState='inactive',SubState='dead',MainPID='0')

    def test_real_unit_proc_and_socket_prove_the_original_daemon(self):
        value=RUNNING(self.state,sockets=True)
        self.assertEqual(value['pid'],self.pid)
        self.assertEqual(value['start'],'111')
        c.guard(self.state)
        self.remove_process()
        with patch.object(c.sys,'argv',['controller','guard']),patch.object(c.os,'geteuid',return_value=0):
            c.main()

    def test_loaded_policy_drift_refuses_explicit_start_activation_and_actual_boot_guard(self):
        for field,value in [('ExecStartPost','unexpected hook'),('DropInPaths','/run/systemd/system/foreign.conf'),
                            ('User','0'),('Group','0'),('ExecStart','unexpected start')]:
            with self.subTest(field=field):
                original=self.properties[field];self.properties[field]=value
                self.calls.clear()
                with self.assertRaises(c.Refused):c.locked(self.fixture.request('start',generation=c.generation(c.read_state())))
                with patch.object(c.sys,'argv',['controller','guard']),patch.object(c.os,'geteuid',return_value=0):
                    with self.assertRaises(c.Refused):c.main()
                self.assertFalse(any(argv[1] in ('enable','start') for argv in self.calls))
                self.properties[field]=original
        # Publication has completed but activation has not. The real loaded
        # policy check must still precede any start; status cannot repair it.
        query=self.fixture.request('authorize',generation=c.generation(c.read_state()))
        query['unit']=c.UNIT_PATH.read_text()
        c.locked(query)
        self.properties['ExecStartPost']='unexpected hook';self.calls.clear()
        with self.assertRaises(c.Refused):c.locked(dict(query,action='activate'))
        self.assertFalse(any(argv[1] in ('enable','start') for argv in self.calls))
        self.assertTrue(c.read_state()['stopped'])

    def test_status_rejects_matching_rpc_when_service_socket_is_foreign(self):
        (self.proc/'fd/3').unlink()
        with patch.object(c,'cli',return_value={'chain':'signet'}) as rpc:
            result=c.status(self.state)
        self.assertFalse(result['rpc_available']);rpc.assert_not_called()

    def test_missing_unit_owned_orphan_is_drained_with_sigterm(self):
        self.properties['LoadState']='not-found'
        lifecycle.ORIGINAL_DRAIN(self.state)
        self.assertEqual(self.signals,[signal.SIGTERM]);self.assertFalse(self.proc.exists())

    def test_failed_systemd_stop_still_drains_original_and_reports_failure(self):
        def failed(argv,**kwargs):
            if argv[1]=='stop':raise c.Refused('inert failed stop')
            return self.original_run(argv,**kwargs)
        with patch.object(c,'run',side_effect=failed):
            with self.assertRaises(c.Refused):lifecycle.ORIGINAL_DRAIN(self.state)
        self.assertEqual(self.signals,[signal.SIGTERM]);self.assertFalse(self.proc.exists())

    def test_real_cancellation_fsync_failure_still_drains_and_disables(self):
        original=c.os.fsync;attempts=[]
        def fault(descriptor):
            attempts.append(descriptor)
            if len(attempts)==1:raise OSError('inert persistent write failure')
            return original(descriptor)
        with patch.object(c.os,'fsync',side_effect=fault):
            with self.assertRaises(c.Refused):c.locked(self.fixture.request('stop'))
        self.assertFalse(self.proc.exists())
        self.assertTrue(any(argv[1]=='disable' for argv in self.calls))
        self.assertTrue(c.read_state()['stopped'])
        self.assertTrue((c.ROOT/'data/chainstate-fixture').exists())

    def test_foreign_uid_argv_image_and_cgroup_never_receive_a_signal(self):
        foreign=str(os.getuid()+1)
        cases=[('status','Uid:\t'+'\t'.join([foreign]*4)+'\nGid:\t0\t0\t0\t0\nGroups:\t0\n'),
               ('cmdline','foreign\0'),('cgroup','0::/foreign.service\n')]
        for name,value in cases:
            path=self.proc/name;old=path.read_bytes()
            with self.subTest(name=name):
                path.write_text(value)
                with self.assertRaises(c.Refused):c.signal_original(self.state)
                self.assertEqual(self.signals,[])
            path.write_bytes(old)
        image=self.proc/'exe';old=os.readlink(image);image.unlink();image.symlink_to(c.ROOT/'foreign')
        (c.ROOT/'foreign').write_text('inert')
        with self.assertRaises(c.Refused):c.signal_original(self.state)
        self.assertEqual(self.signals,[])
        image.unlink();image.symlink_to(old)

    def test_pid_reuse_refuses_signal_after_pidfd_acquisition(self):
        def changed(pid,flags):
            self.stat('222');return os.open(c.UNIT_PATH,os.O_RDONLY)
        with patch.object(c.os,'pidfd_open',side_effect=changed):
            with self.assertRaises(c.Refused):c.signal_original(self.state)
        self.assertEqual(self.signals,[])

    def test_unexpected_loaded_stop_hook_is_never_executed(self):
        self.properties['ExecStop']='inert foreign hook'
        with self.assertRaises(c.Refused):lifecycle.ORIGINAL_DRAIN(self.state)
        self.assertFalse(any(argv[1]=='stop' for argv in self.calls))
        self.assertEqual(self.signals,[signal.SIGTERM])

    def test_retained_shutdown_does_not_resolve_reassigned_nss(self):
        with patch.object(c.pwd,'getpwnam',side_effect=AssertionError('NSS must not be read')):
            c.signal_original(self.state)
        self.assertEqual(self.signals,[signal.SIGTERM])

    def test_connected_socket_proves_pid_before_any_cookie_use(self):
        observed=RUNNING(self.state,sockets=True)
        sock=type('Socket',(),{'getsockname':lambda _:('127.0.0.1',50000),
                              'getpeername':lambda _:('127.0.0.1',38332)})()
        connection=type('Connection',(),{'sock':sock})()
        self.network(accepted=True);(self.proc/'fd/4').symlink_to('socket:[6002]')
        c.connected_peer(self.state,observed,connection)
        self.network(owner=os.getuid()+1,accepted=True)
        with self.assertRaises(c.Refused):c.connected_peer(self.state,observed,connection)
        self.network(accepted=True);self.stat('222')
        with self.assertRaises(c.Refused):c.connected_peer(self.state,observed,connection)

    def test_cookie_is_private_original_file_and_unsafe_files_are_not_read(self):
        data=c.ROOT/'data';data.chmod(0o700);network=data/'signet';network.mkdir(mode=0o700)
        cookie=network/'.cookie';cookie.write_bytes(b'__cookie__:'+b'1'*64);cookie.chmod(0o600)
        account=c.retained_account(self.state)
        with patch.object(c,'verified_data',return_value={'device':data.stat().st_dev}):
            self.assertEqual(c.original_cookie(self.state,account),b'__cookie__:'+b'1'*64)
            for mode in (0o644,0o666):
                cookie.chmod(mode)
                with self.assertRaises(c.Refused):c.original_cookie(self.state,account)
            cookie.chmod(0o600);alias=network/'alias';alias.symlink_to(cookie);cookie.rename(network/'original');cookie.symlink_to(network/'original')
            with self.assertRaises(OSError):c.original_cookie(self.state,account)


class Rpc(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.events=[];self.cookie=bytearray(b'__cookie__:'+b'1'*64)
        patch.object(c,'original_runtime',return_value={'uid':1234}).start()
        patch.object(c,'running_process',return_value={'pid':1234}).start()
        patch.object(c,'connected_peer',side_effect=lambda *args:self.events.append('peer')).start()
        patch.object(c,'original_cookie',side_effect=lambda *args:(self.events.append('cookie') or self.cookie)).start()
        outer=self
        class Connection:
            def __init__(self,*args,**kwargs):self.status=200;outer.connection=self
            def connect(self):outer.events.append('connect')
            def request(self,*args,**kwargs):outer.events.append('request');self.requested=(args,kwargs)
            def getresponse(self):return self
            def read(self,maximum):return json.dumps(outer.result).encode()
            def close(self):outer.events.append('close')
        patch.object(c.http.client,'HTTPConnection',Connection).start()
        self.result={'jsonrpc':'2.0','id':1,'result':'public-result'}

    def test_actual_transport_orders_peer_then_cookie_then_request_and_clears_bytes(self):
        self.assertEqual(c.inspect_rpc({'network':'signet'},'getblockhash',('0',)),'public-result')
        self.assertEqual(self.events,['connect','peer','cookie','request','close'])
        self.assertEqual(json.loads(self.connection.requested[1]['body'])['params'],[0])
        self.assertFalse(any(self.cookie))

    def test_wrong_peer_never_reads_or_sends_cookie(self):
        with patch.object(c,'connected_peer',side_effect=c.Refused('inert foreign connection')):
            with self.assertRaises(c.Refused):c.inspect_rpc({'network':'signet'},'getblockchaininfo',())
        self.assertEqual(self.events,['connect','close'])

    def test_error_redirect_or_changed_process_refuses_readiness(self):
        self.result={'jsonrpc':'2.0','id':1,'error':{'code':-28,'message':'public warming up'}}
        with self.assertRaises(c.Refused):c.inspect_rpc({'network':'signet'},'getblockchaininfo',())
        self.assertFalse(any(self.cookie))
        self.result={'jsonrpc':'2.0','id':1,'result':{}}
        with patch.object(c,'running_process',side_effect=[{'pid':1234},{'pid':1235}]):
            with self.assertRaises(c.Refused):c.inspect_rpc({'network':'signet'},'getblockchaininfo',())

    def test_mutating_rpc_is_rejected_before_transport_creation(self):
        for method in ('sendrawtransaction','stop','setnetworkactive','getwalletinfo'):
            with self.assertRaises(c.Refused):c.inspect_rpc({'network':'signet'},method,())
        self.assertEqual(self.events,[])


if __name__=='__main__':unittest.main()
