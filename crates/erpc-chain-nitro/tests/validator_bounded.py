#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real HTTP parsing over an inert socket pair; bounded resolver/fake-clock faults."""
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'templates/validator/node'))
sys.path.insert(0, str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
import bounded
import upstreams


class Bounded(unittest.TestCase):
    def exchange(self, response):
        client, provider = socket.socketpair()
        self.addCleanup(client.close); self.addCleanup(provider.close)
        provider.sendall(response)
        calls = []
        class Raw:
            def settimeout(self, value): client.settimeout(value)
            def connect(self, destination): calls.append(destination)  # No real connection.
            def recv_into(self, value): return client.recv_into(value)
            def sendall(self, value): client.sendall(value)
            def close(self): client.close()
        endpoint = bounded.Endpoint.__new__(bounded.Endpoint)
        endpoint.deadline = lambda:time.monotonic()+1
        endpoint.host, endpoint.port = 'localhost', 18545
        endpoint.path, endpoint.query, endpoint.headers, endpoint.tls = '/', '', {}, False
        endpoint.addresses = lambda:[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,('127.0.0.1',18545))]
        return endpoint, Raw(), calls

    def test_actual_http_parser_uses_only_the_checked_numeric_destination(self):
        endpoint, raw, calls = self.exchange(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{"ok":true}')
        with patch.object(bounded.socket, 'socket', return_value=raw): value = endpoint.request('POST', body=b'{}')
        self.assertEqual(value, {'ok':True}); self.assertEqual(calls, [('127.0.0.1',18545)])

    def test_redirect_cannot_reconnect_or_forward_a_credential(self):
        endpoint, raw, calls = self.exchange(b'HTTP/1.1 302 Redirect\r\nLocation: INERT_PRIVATE_MARKER\r\nContent-Length: 0\r\n\r\n')
        with patch.object(bounded.socket, 'socket', return_value=raw), self.assertRaises(upstreams.Rejected) as result:
            endpoint.request('POST', body=b'{}')
        self.assertNotIn('INERT_PRIVATE_MARKER', str(result.exception)); self.assertEqual(len(calls), 1)

    def test_slow_drip_read_cannot_restart_a_relative_timeout_forever(self):
        clock = [0]
        class Raw:
            def settimeout(self, timeout): self.timeout = timeout
            def recv_into(self, value): clock[0] += 2; value[0] = 65; return 1
        raw = Raw(); stream = bounded.Reader(bounded.Socket(raw, 1))
        with patch.object(bounded, 'time', SimpleNamespace(monotonic=lambda:clock[0])):
            with self.assertRaises(upstreams.Rejected): stream.readinto(bytearray(1))
        self.assertEqual(raw.timeout, 1)

    def test_timed_out_dns_never_connects_and_does_not_create_unbounded_workers(self):
        release = threading.Event(); finished = threading.Event(); calls = []
        def resolver():
            calls.append('read-only DNS'); release.wait(2)
            if len(calls) == 2: finished.set()
            return [('inert resolved answer',)]
        with patch.object(bounded, 'RESOLVERS', threading.BoundedSemaphore(2)):
            try:
                for _ in range(2):
                    with self.assertRaises(upstreams.Rejected): bounded.resolve(resolver,time.monotonic()+0.01)
                with self.assertRaises(upstreams.Rejected): bounded.resolve(resolver,time.monotonic()+0.01)
                self.assertEqual(len(calls), 2)
            finally: release.set(); self.assertTrue(finished.wait(1))


if __name__ == '__main__': unittest.main()
