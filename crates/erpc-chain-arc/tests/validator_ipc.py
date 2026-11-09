#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual IPC caller order over an inert socket inode and a bounded test stream."""
import contextlib
import json
import os
import pathlib
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_ipc as ipc
from av_files import Files
from arc_files import Refused


class Stream:
    def __init__(self, peer):
        self.peer = peer
        self.events = []
        self.chunks = [b'{"jsonrpc":"2.0","id":1,"result":"0x1"}\n']

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def settimeout(self, value):
        self.events.append(('timeout', value))

    def connect(self, value):
        self.events.append(('connect', value))

    def getsockopt(self, *_args):
        self.events.append(('peer', self.peer))
        return struct.pack('3i', *self.peer)

    def sendall(self, value):
        self.events.append(('send', value))

    def recv(self, _bound):
        return self.chunks.pop(0) if self.chunks else b''


class Ipc(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.context = Files(pathlib.Path(temporary.name), owner=os.getuid())
        self.root = self.context.mkdir(ipc.ENGINE_RUN, 0o710)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        target = self.root / 'reth.ipc'
        server.bind(str(target))
        target.chmod(0o660)
        self.state = {'accounts': {'execution': os.getuid(), 'engine': os.getgid()}, 'runtime': {}}
        self.observed = {'pid': 12345, 'start': '99'}
        self.stream = Stream((12345, os.getuid(), os.getgid()))
        self.stack.enter_context(mock.patch.object(ipc.av_accounts, 'verify', return_value=None))
        self.running = self.stack.enter_context(mock.patch.object(ipc.av_process, 'running', return_value=self.observed))
        self.stack.enter_context(mock.patch.object(ipc.socket, 'SO_PEERCRED', 17, create=True))
        self.stack.enter_context(mock.patch.object(ipc.socket, 'socket', return_value=self.stream))

    def test_actual_caller_authenticates_connected_native_peer_before_sending_bytes(self):
        self.assertEqual(ipc.call(self.context, self.state, 'eth_chainId', []), '0x1')
        names = [name for name, _ in self.stream.events]
        self.assertLess(names.index('peer'), names.index('send'))
        request = json.loads(next(value for name, value in self.stream.events if name == 'send'))
        self.assertEqual(request['method'], 'eth_chainId')
        self.assertEqual(self.running.call_count, 3)

    def test_foreign_peer_pid_uid_gid_receive_no_request_bytes(self):
        for peer in [(1, os.getuid(), os.getgid()), (12345, 1, os.getgid()), (12345, os.getuid(), 1)]:
            self.stream.peer = peer
            self.stream.events.clear()
            with self.assertRaises(Refused):
                ipc.call(self.context, self.state, 'eth_chainId', [])
            self.assertNotIn('send', [name for name, _ in self.stream.events])

    def test_process_generation_change_after_connect_receives_no_request_bytes(self):
        self.running.side_effect = [self.observed, {'pid': 12345, 'start': '100'}]
        with self.assertRaises(Refused):
            ipc.call(self.context, self.state, 'eth_chainId', [])
        self.assertNotIn('send', [name for name, _ in self.stream.events])

    def test_group_writable_or_foreign_inode_namespace_is_refused(self):
        self.root.chmod(0o730)
        with self.assertRaises(Refused):
            ipc.call(self.context, self.state, 'eth_chainId', [])
        self.assertEqual(self.stream.events, [])

    def test_duplicate_error_multiple_results_and_incomplete_response_fail_without_native_body(self):
        for raw in [b'{"jsonrpc":"2.0","id":1,"error":{"message":"inert-private-diagnostic"}}',
                    b'{"jsonrpc":"2.0","id":1,"id":1,"result":null}',
                    b'{"jsonrpc":"2.0","id":1,"result":null}{}', b'{']:
            self.stream.chunks = [raw]
            with self.assertRaises(Refused) as result:
                ipc.call(self.context, self.state, 'eth_chainId', [])
            self.assertNotIn('inert-private-diagnostic', str(result.exception))


if __name__ == '__main__':
    unittest.main()
