#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual account receipts and legitimate prerequisite PID/listener startup proofs."""
from pathlib import Path
import sys
from types import SimpleNamespace as Record
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/validator/node'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
sys.path.insert(0,str(Path(__file__).parent))
from validator_accounts import Accounts
from validator_processes import Processes
import accounts
import host
import installer
import runtime
import services


class Runtime(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.accounts=Accounts();self.accounts.setUp();self.addCleanup(self.accounts.doCleanups)
        self.records=accounts.ensure(self.accounts.store,self.accounts.contract,self.accounts.account_command)
        self.state,self.expected=self.accounts.store,self.accounts.contract
        self.target={'phase':'active','native':'inert reviewed target'}
        self.state.prepare(self.expected,'d'*32,self.target,lambda:None)
        self.state.activate(self.expected,'d'*32,lambda _:None)
        self.proc=Processes();self.proc.setUp();self.addCleanup(self.proc.doCleanups)
        parent=self.proc.process(pid=235,uid=self.records['transport']['uid'])
        argv=['/usr/bin/python3','-I','-c','inert checked loader','runtime-run','transport']
        (parent/'exe').unlink();(parent/'exe').symlink_to('/usr/bin/python3.12')
        (parent/'cmdline').write_bytes(b'\0'.join(value.encode() for value in argv)+b'\0')
        (parent/'cgroup').write_text('0::/system.slice/erpc-arbitrum-upstreams.service\n')
        self.proc.listen(parent,18545,uid=self.records['transport']['uid'],inode=123)
        self.proc.listen(parent,15052,uid=self.records['transport']['uid'],inode=124)
        self.state.put('transport-process.json',{'contract':self.expected,'generation':self.state.fence()['generation'],
            'account':self.records['transport'],'pid':235,'start_time':345,'executable':'/usr/bin/python3.12','argv':argv})
        patch.object(runtime,'original',return_value=(self.state,self.expected)).start()
        patch.object(runtime.publication,'verify').start();patch.object(host,'capacity').start()
        patch.object(installer,'verify_config').start();patch.object(runtime,'common').start()
        self.sealed=patch.object(runtime.custody,'sealed').start();patch.object(runtime.credentials,'sealed').start();patch.object(runtime.parent_tls,'sealed').start()
        self.crypto=patch.object(runtime.crypto,'self_test').start()
        patch.object(runtime.history,'verify',side_effect=lambda _s,_e,_a,quiet:quiet()).start()
        self.loaded={'ActiveState':'active','SubState':'running','MainPID':'235','User':'0','Group':'0'}
        patch.object(services,'loaded',side_effect=lambda _s,_e,role,_run=host.command:self.loaded if role=='transport' else {'User':'0','Group':'0'}).start()

    def test_node_start_accepts_real_original_parent_pid_and_both_owned_listeners(self):
        state,expected,target,records=runtime.condition('node')
        self.assertIs(state,self.state);self.assertEqual(records,self.records);self.assertEqual(target,self.target)
        self.crypto.assert_called_once();self.sealed.assert_called_once()
        # A native writer with the original node UID must still refuse startup.
        self.proc.process(pid=236,uid=self.records['node']['uid'])
        with self.assertRaisesRegex(ValueError,'process remains'):runtime.condition('node')

    def test_name_reassignment_refuses_before_credential_read_or_runtime_materialization(self):
        node=self.records['node']
        wrong=Record(pw_name=node['name'],pw_uid=40000,pw_gid=40000,pw_dir=node['home'],pw_shell=node['shell'])
        with patch.object(accounts.pwd,'getpwnam',return_value=wrong),patch.object(runtime,'credential') as material:
            with self.assertRaises(ValueError):runtime.condition('node')
            material.assert_not_called()
        self.sealed.assert_not_called();self.crypto.assert_not_called()
        self.assertEqual(accounts.retained(self.state,self.expected),self.records)

    def test_unowned_parent_socket_or_pid_replacement_cannot_satisfy_dependency(self):
        (self.proc.root/'235/fd/124').unlink()
        with self.assertRaisesRegex(ValueError,'listener'):runtime.condition('node')
        (self.proc.root/'235/fd/124').symlink_to('socket:[124]')
        path=self.proc.root/'235/stat';path.write_text(path.read_text().replace('345','346'))
        with self.assertRaisesRegex(ValueError,'reused'):runtime.condition('node')

    def test_start_post_barrier_accepts_only_the_real_activating_parent_pid(self):
        self.loaded.update(ActiveState='activating',SubState='start-post')
        with self.assertRaisesRegex(ValueError,'did not enter'):services.transport(self.state,self.expected,self.records)
        self.assertEqual(services.transport(self.state,self.expected,self.records,starting=True)['pid'],235)


if __name__=='__main__':
    raise SystemExit(not unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime)).wasSuccessful())
