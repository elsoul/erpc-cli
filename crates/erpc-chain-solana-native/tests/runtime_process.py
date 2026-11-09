#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert proc-shaped files and kernel-link fixtures; never run a node."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_runtime_process as runtime


class RuntimeProcess(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name); self.proc = self.root / 'proc'; self.proc.mkdir()
        self.binary = self.root / 'inert-executable'; self.binary.write_bytes(b'never executed'); self.binary.chmod(0o555)
        self.argv = [str(self.binary), '--identity', '/run/credentials/erpc-solana.service/identity', '--no-voting']
        self.pid, self.uid, self.gid = 123, 20001, 20001
        self.directory = self.process(self.pid, self.uid)
        for name in ('fd', 'net', 'ns'): (self.directory / name).mkdir()
        (self.directory / 'exe').symlink_to(self.binary)
        (self.directory / 'cmdline').write_bytes(b'\x00'.join(v.encode() for v in self.argv) + b'\x00')
        (self.directory / 'cgroup').write_text('0::/system.slice/erpc-solana.service\n')
        (self.proc / 'self/ns').mkdir(parents=True)
        namespace = self.proc / 'self/ns/net'; namespace.touch()
        (self.directory / 'ns/net').symlink_to(namespace)
        (self.directory / 'fd/3').symlink_to('socket:[1001]')
        (self.directory / 'fd/4').symlink_to('socket:[1002]')
        self.header = '  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
        self.write_sockets()
        patcher = patch.object(runtime.proc, 'PROC', self.proc); patcher.start(); self.addCleanup(patcher.stop)

    def process(self, pid, uid):
        directory = self.proc / str(pid); directory.mkdir()
        (directory / 'stat').write_text(str(pid) + ' (inert ) task) S ' + '0 ' * 18 + '90210 0\n')
        lines = {'Uid': ' '.join([str(uid)] * 4), 'Gid': ' '.join([str(self.gid)] * 4),
                 'Groups': str(self.gid), 'NoNewPrivs': '1',
                 **{name: '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}}
        (directory / 'status').write_text(''.join(k + ':\t' + v + '\n' for k, v in lines.items()))
        return directory

    def record(self, port, inode, uid=None, address='0100007F'):
        return f'0: {address}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {self.uid if uid is None else uid} 0 {inode} 1 0\n'

    def write_sockets(self, extra='', address='0100007F', uid=None):
        (self.directory / 'net/tcp').write_text(self.header + self.record(8899, 1001, uid, address) + self.record(8900, 1002) + extra)
        (self.directory / 'net/tcp6').write_text(self.header)

    def prove(self):
        return runtime.prove(self.pid, self.uid, self.gid, self.binary, self.argv)

    def test_exact_runtime_and_both_loopback_sockets_are_required(self):
        self.assertEqual(self.prove()[:2], (123, 90210))
        (self.directory / 'fd/4').unlink()
        with self.assertRaisesRegex(ValueError, 'listeners'): self.prove()

    def test_matching_process_name_or_path_cannot_replace_executable_inode(self):
        other = self.root / 'other'; other.write_bytes(self.binary.read_bytes()); other.chmod(0o555)
        (self.directory / 'exe').unlink(); (self.directory / 'exe').symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'inode'): self.prove()

    def test_every_uid_gid_and_supplementary_group_is_verified(self):
        path = self.directory / 'status'; original = path.read_text()
        for name in ('Uid', 'Gid'):
            for position in range(4):
                values = [str(self.uid)] * 4; values[position] = '0'
                text = original.replace(name + ':\t' + ' '.join([str(self.uid)] * 4), name + ':\t' + ' '.join(values))
                path.write_text(text)
                with self.assertRaises(ValueError): self.prove()
        path.write_text(original.replace('Groups:\t20001', 'Groups:\t20001 27'))
        with self.assertRaises(ValueError): self.prove()
        path.write_text(original.replace('Groups:\t20001', 'Groups:\t'))
        self.prove()  # An empty supplementary list preserves the primary GID.

    def test_capabilities_and_no_new_privileges_are_checked(self):
        path = self.directory / 'status'; original = path.read_text()
        for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
            path.write_text(original.replace(name + ':\t0000000000000000', name + ':\t0000000000000001'))
            with self.assertRaises(ValueError): self.prove()
        path.write_text(original.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'))
        with self.assertRaises(ValueError): self.prove()

    def test_foreign_cgroup_namespace_and_argv_refuse(self):
        for name, bad in [('cgroup', b'0::/system.slice/foreign.service\n'), ('cmdline', b'inert\x00')]:
            path = self.directory / name; original = path.read_bytes(); path.write_bytes(bad)
            with self.assertRaises(ValueError): self.prove()
            path.write_bytes(original)
        (self.directory / 'ns/net').unlink(); (self.directory / 'ns/net').touch()
        with self.assertRaisesRegex(ValueError, 'network namespace'): self.prove()

    def test_orphan_account_process_and_saved_uid_are_not_hidden(self):
        other = self.process(456, 20002)
        self.prove()
        path = other / 'status'; original = path.read_text()
        path.write_text(original.replace('Uid:\t20002 20002 20002 20002', 'Uid:\t20002 20002 20001 20002'))
        with self.assertRaisesRegex(ValueError, 'orphan'): self.prove()

    def test_foreign_duplicate_wildcard_and_ipv6_listener_refuse(self):
        for kwargs in ({'extra': self.record(8899, 9999)}, {'address': '00000000'}, {'uid': 20002}):
            self.write_sockets(**kwargs)
            with self.assertRaises(ValueError): self.prove()
        self.write_sockets()
        (self.directory / 'net/tcp6').write_text(self.header + self.record(8899, 9999, address='0' * 32))
        with self.assertRaises(ValueError): self.prove()

    def test_pid_generation_change_during_socket_scan_refuses(self):
        original = runtime.socket_inodes
        def changed(directory):
            value = original(directory)
            path = directory / 'stat'; path.write_text(path.read_text().replace('90210', '90211'))
            return value
        with patch.object(runtime, 'socket_inodes', changed):
            with self.assertRaisesRegex(ValueError, 'changed'): self.prove()

    def test_arbitrary_task_names_are_ignored_but_duplicate_uid_is_refused(self):
        path = self.directory / 'status'; original = path.read_bytes()
        path.write_bytes(b'Name:\t\xff\xfe\n' + original)
        self.prove()
        path.write_bytes(original + b'Uid:\t20001 20001 20001 20001\n')
        with self.assertRaisesRegex(ValueError, 'ambiguous'): self.prove()


if __name__ == '__main__': unittest.main()
