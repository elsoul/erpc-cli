#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original process generations, real proc-shaped descriptors and fixed sockets."""
import copy
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import arc_files as files
import arc_process as process
import arc_observe as observe
import arc_protocol as protocol
import arc_units as units


class Processes(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.Lifecycle('runTest');self.f.setUp();self.f.install()
        self.c=self.f.c;self.state=self.c.state(self.f.contract)
        self.runtime=self.state['runtime'];self.pid=50001
        self.root=self.c.path('/proc')/str(self.pid);self.root.mkdir();(self.root/'fd').mkdir()
        self.image('execution')
        command=self.c.command
        def with_pid(*args,**kwargs):
            result=command(*args,**kwargs)
            if args[:2]==('/usr/bin/systemctl','show') and args[2]=='arc-execution.service':
                text=result.stdout.decode().replace('ActiveState=inactive','ActiveState=active').replace('MainPID=0','MainPID='+str(self.pid))
                return subprocess.CompletedProcess(args,0,text.encode(),b'')
            return result
        self.calls=patch.object(self.c,'command',with_pid);self.calls.start()

    def tearDown(self):self.calls.stop();self.f.tearDown()

    def image(self,component):
        data=self.runtime[component]
        link=self.root/'exe'
        if link.is_symlink():link.unlink()
        link.symlink_to(self.c.path(data['binary']))
        uid,gid=self.state['service_uid'],self.state['service_gid']
        (self.root/'status').write_text(f'Uid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\nGroups:\t{gid}\n')
        (self.root/'stat').write_text(str(self.pid)+' (original inert process) '+' '.join(['S']+['0']*18+['12345']+['0']*8))
        (self.root/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in data['argv'])+b'\0')
        (self.root/'cgroup').write_text('0::/system.slice/'+process.UNITS[component]+'\n')

    def listeners(self):
        uid=self.state['service_uid'];lines=['sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode']
        for index,port in enumerate((8545,8546,9001),100):
            (self.root/'fd'/str(index)).symlink_to('socket:['+str(index)+']')
            lines.append(f'0: 0100007F:{port:04X} 00000000:0000 0A 0:0 0:0 0 {uid} 0 {index}')
        self.c.path('/proc/net/tcp').write_text('\n'.join(lines)+'\n')
        self.c.path('/proc/net/tcp6').write_text('header\n')

    def test_all_native_network_history_and_provider_profiles_preserve_closed_roles(self):
        for network,values in protocol.NETWORKS.items():
            for kind in ('full','archive','provider'):
                with self.subTest(network=network,kind=kind):
                    state=copy.deepcopy(self.state)
                    state['contract'].update(network=network,chain_id=values['chain_id'],genesis_hash=values['genesis_hash'],rpc_type=kind)
                    policy=copy.deepcopy(self.f.policy)
                    if kind=='provider':
                        policy['trusted_peers']=['enode://'+'a'*128+'@192.0.2.10:30303']
                        policy['sentry_peers']=['/ip4/192.0.2.20/tcp/27000/p2p/12D3PublicFixture']
                    text,runtime=units.make(self.c,state,self.f.target,policy,self.c.source,self.f.helper)
                    for component in process.UNITS:
                        self.assertNotIn('--validator',runtime[component]['argv'])
                        self.assertIn('User='+str(state['service_uid'])+'\n',text[component])
                        self.assertIn('ExecCondition=+',text[component])
                        self.assertEqual('LoadCredentialEncrypted=' in text[component],component=='consensus')
                    self.assertEqual('--full' in runtime['execution']['argv'],kind!='archive')
                    self.assertEqual('--follow' in runtime['consensus']['argv'],kind!='provider')
                    self.assertEqual('--no-consensus' in runtime['consensus']['argv'],kind=='provider')
                    self.assertEqual(runtime['snapshots']['argv'][5],'archive' if kind=='archive' else 'full')

    def test_real_process_and_socket_identity_then_substitution_refusal(self):
        self.listeners()
        self.assertEqual(observe.listeners(self.c,self.state,'execution')['pid'],self.pid)
        path=self.c.path('/proc/net/tcp');original=path.read_text()
        for bad in (original.replace(' 0 100',' 0 999'),original.replace('0100007F','00000000'),original+original.splitlines()[1]+'\n'):
            path.write_text(bad)
            with self.assertRaises(files.Refused):observe.listeners(self.c,self.state,'execution')
        path.write_text(original)
        (self.root/'status').write_text('Uid:\t7 7 7 7\nGid:\t7 7 7 7\nGroups:\t7\n')
        with self.assertRaises(files.Refused):observe.listeners(self.c,self.state,'execution')

    def test_generation_changes_during_socket_observation_never_report_authority(self):
        self.listeners();original=observe.sockets
        def replaced(c,record):
            result=original(c,record)
            path=self.root/'stat';path.write_text(path.read_text().replace('12345','23456'))
            return result
        with patch.object(observe,'sockets',replaced),self.assertRaises(files.Refused):
            observe.listeners(self.c,self.state,'execution')

    def test_native_snapshot_child_is_scoped_to_original_image_data_and_service(self):
        data=self.runtime['execution'];parent=self.runtime['snapshots']['argv']
        args=[data['binary'],'download','--chain',parent[3],'--datadir',parent[7],'--full','--manifest-url','https://127.0.0.1/public-fixture']
        (self.root/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in args)+b'\0')
        (self.root/'cgroup').write_text('0::/system.slice/arc-snapshots.service\n')
        original=process.process(self.c,self.pid)
        self.assertEqual(process.classify(self.c,self.state,original,[self.runtime]),'snapshots')
        for change in ('argv','image','cgroup','uids'):
            bad=copy.deepcopy(original)
            if change=='argv':bad[change][5]='/var/lib/arc/execution'
            elif change=='uids':bad[change]=['7']*4
            else:bad[change]='wrong'
            with self.subTest(change=change),self.assertRaises(files.Refused):
                process.classify(self.c,self.state,bad,[self.runtime])
        with self.assertRaises(files.Refused):process.quiescent(self.c,self.state,{'snapshots'},[self.runtime])

    def test_retained_deleted_image_has_shutdown_authority_but_cannot_pass_runtime_readiness(self):
        original=process.process(self.c,self.pid);original['deleted']=True
        with self.assertRaises(files.Refused):process.matches(self.c,self.state,'execution',original,self.runtime)
        self.assertEqual(process.classify(self.c,self.state,original,[self.runtime]),'execution')
        # The installed path is not authority for a retained original /proc image.
        self.c.path(self.runtime['execution']['binary']).unlink()
        self.assertEqual(process.classify(self.c,self.state,original,[self.runtime]),'execution')
        original['image']='f'*64
        with self.assertRaises(files.Refused):process.classify(self.c,self.state,original,[self.runtime])

    def test_unknown_original_account_process_is_not_killed_or_ignored(self):
        (self.root/'cmdline').write_bytes(b'/unrecognized\0')
        with self.assertRaises(files.Refused):process.quiescent(self.c,self.state,{'execution'},[self.runtime])
        self.assertFalse(any(call[1]=='stop' for call in self.c.calls))


if __name__=='__main__':unittest.main()
