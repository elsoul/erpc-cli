#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Kernel-format proc fixtures; no native process, socket or privileged action."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import processes


class Processes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(tmp.name); patch.object(processes, 'PROC', self.root).start()
        (self.root/'1/ns').mkdir(parents=True); (self.root/'1/ns/net').write_text('inert namespace')
        self.account = {'uid': 20000, 'gid': 20000}
        self.argv = ['/usr/local/bin/nitro', '--conf.file', '/config/node.json']
        self.group = '/system.slice/docker-' + 'a'*64 + '.scope'

    def process(self, pid=234, uid=20000, start=345):
        path = self.root/str(pid); path.mkdir(); (path/'ns').mkdir(); (path/'fd').mkdir(); (path/'net').mkdir()
        os.link(self.root/'1/ns/net', path/'ns/net')
        (path/'exe').symlink_to('/usr/local/bin/nitro')
        (path/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in self.argv)+b'\0')
        (path/'cgroup').write_text('0::'+self.group+'\n')
        (path/'status').write_text('Name:\tinert\nPid:\t'+str(pid)+'\nUid:\t'+(' '.join([str(uid)]*4))
            +'\nGid:\t'+(' '.join([str(uid)]*4))+'\nGroups:\t'+str(uid)+'\nNoNewPrivs:\t1\n'
            +'\n'.join(name+':\t'+'0'*16 for name in ('CapInh','CapPrm','CapEff','CapAmb'))+'\n')
        (path/'stat').write_text(str(pid)+' (inert ) tricky) S 1 '+'0 '*17+str(start)+'\n')
        (path/'net/tcp').write_text('inert kernel header\n'); (path/'net/tcp6').write_text('inert kernel header\n')
        return path

    def listen(self, path, port=8547, uid=20000, inode=123, local='0100007F', family='tcp', descriptor=True):
        with (path/'net'/family).open('a') as output:
            output.write('0: '+local+':'+format(port,'04X')+' 00000000:0000 0A 00000000:00000000 00:00000000 00000000 '+str(uid)+' 0 '+str(inode)+'\n')
        if descriptor: (path/'fd'/str(inode)).symlink_to('socket:['+str(inode)+']')

    def test_exact_original_uid_argv_cgroup_starttime_and_listener_inode_prove_one_process(self):
        path = self.process(); self.listen(path)
        value = processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})
        self.assertEqual(value['start_time'], 345); self.assertEqual(value['uid'], 20000)
        self.assertEqual(processes.listeners(234, 20000, (8547,)), {'8547': 123})
        with self.assertRaises(ValueError): processes.quiescent({'node': self.account})

    def test_component_start_only_drains_its_uid_but_global_stop_includes_original_transport(self):
        self.process(pid=235, uid=20001)
        processes.quiescent({'node': self.account})
        with self.assertRaises(ValueError):
            processes.quiescent({'node': self.account, 'transport': {'uid': 20001, 'gid': 20001}})
        self.process(pid=236, uid=20000)
        with self.assertRaises(ValueError): processes.quiescent({'node': self.account})

    def test_foreign_executable_shared_groups_or_unreadable_metadata_never_prove_quiescence(self):
        path = self.process()
        (path/'exe').unlink(); (path/'exe').symlink_to('/tmp/unqualified-writer')
        with self.assertRaises(ValueError): processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})
        (path/'exe').unlink(); (path/'exe').symlink_to(self.argv[0])
        (path/'status').write_text((path/'status').read_text().replace('Groups:\t20000', 'Groups:\t20000 998'))
        with self.assertRaises(ValueError): processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})
        with patch.object(processes, 'bounded', side_effect=PermissionError('inert proc observation denied')):
            with self.assertRaises(PermissionError): processes.quiescent({'node': self.account})

    def test_responding_foreign_socket_unowned_inode_and_public_or_ipv6_listener_refuse(self):
        path = self.process()
        self.listen(path, descriptor=False)
        with self.assertRaises(ValueError): processes.listeners(234, 20000, (8547,))
        (path/'fd/123').symlink_to('socket:[123]')
        self.listen(path, inode=124)
        with self.assertRaises(ValueError): processes.listeners(234, 20000, (8547,))
        (path/'net/tcp').write_text('header\n'); self.listen(path, inode=125, local='00000000')
        with self.assertRaises(ValueError): processes.listeners(234, 20000, (8547,))
        (path/'net/tcp').write_text('header\n'); self.listen(path, inode=126, family='tcp6', local='0'*32)
        with self.assertRaises(ValueError): processes.listeners(234, 20000, (8547,))

    def test_process_names_are_opaque_bytes_and_cannot_break_unrelated_uid_observation(self):
        path = self.process(uid=20001)
        (path/'status').write_bytes((path/'status').read_bytes().replace(b'Name:\tinert', b'Name:\t' + bytes([255, 254])))
        (path/'stat').write_bytes((path/'stat').read_bytes().replace(b'inert ) tricky', bytes([255, 254]) + b' ) tricky'))
        processes.quiescent({'node': self.account})
        self.assertEqual(processes.identity(234)['start_time'], 345)

    def test_native_jit_child_is_allowed_but_orphan_same_uid_writer_refuses(self):
        self.process(); child = self.process(pid=235)
        (child/'exe').unlink(); (child/'exe').symlink_to('/usr/local/bin/jit')
        self.assertEqual(processes.container_members(self.account, 234, self.group), {234, 235})
        (child/'cgroup').write_text('0::/unowned-writer\n')
        with self.assertRaisesRegex(ValueError, 'orphan'): processes.container_members(self.account, 234, self.group)
        (child/'cgroup').write_text('0::'+self.group+'\n')
        (child/'exe').unlink(); (child/'exe').symlink_to('/bin/sh')
        with self.assertRaisesRegex(ValueError, 'unqualified'): processes.container_members(self.account, 234, self.group)

    def test_pid_reuse_cgroup_change_and_native_privilege_drift_are_rejected(self):
        path = self.process(); self.listen(path); original = processes.identity(234)
        with patch.object(processes, 'identity', side_effect=[original, dict(original, start_time=999)]):
            with self.assertRaises(ValueError): processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})
        with patch.object(processes, 'identity', side_effect=[original, dict(original, start_time=999)]):
            with self.assertRaises(ValueError): processes.listeners(234, 20000, (8547,))
        (path/'cgroup').write_text('0::/unowned\n')
        with self.assertRaises(ValueError): processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})
        (path/'cgroup').write_text('0::'+self.group+'\n')
        (path/'status').write_text((path/'status').read_text().replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'))
        with self.assertRaises(ValueError): processes.snapshot(234, self.account, self.argv[0], self.argv, {self.group})


if __name__ == '__main__': unittest.main()
