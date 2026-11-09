#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert loopback HTTP and response fixtures, without chain network access."""
import base64
import http.server
import json
from pathlib import Path
import struct
import sys
import threading
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_runtime_observer as observer


def clock(slot, timestamp):
    raw = struct.pack('<QqQQq', slot, 0, 0, 0, timestamp)
    return {'context': {'slot': slot}, 'value': {'data': [base64.b64encode(raw).decode(), 'base64']}}


class Observation(unittest.TestCase):
    def setUp(self):
        self.profile = {'genesis': 'inert genesis', 'version': '4.3.2'}
        self.replies = {'getGenesisHash': self.profile['genesis'], 'getIdentity': {'identity': 'inert identity'},
                        'getVersion': {'solana-core': '4.3.2'}, 'getHealth': 'ok',
                        'getAccountInfo': clock(12345, 1000)}
        self.calls = []; self.proofs = 0

    def prove(self):
        self.proofs += 1
        return (123, 90210, 1, 2)

    def call(self, method, params):
        self.calls.append((method, params))
        return self.replies[method]

    def inspect(self, **kwargs):
        return observer.inspect(self.profile, 'inert identity', kwargs.get('prove', self.prove),
                                kwargs.get('call', self.call), lambda: kwargs.get('time', 1020))

    def test_full_readiness_requires_fixed_identity_fresh_finality_and_two_proofs(self):
        result = self.inspect()
        self.assertTrue(result['rpc_ready']); self.assertEqual(self.proofs, 2)
        self.assertIn(('getAccountInfo', [observer.CLOCK, {'commitment': 'finalized', 'encoding': 'base64'}]), self.calls)
        # A node that only syncs keeps no transaction history for getBlockTime.
        self.assertNotIn('getBlockTime', [method for method, _ in self.calls])
        self.assertEqual(result['finalized_slot'], 12345)
        self.assertEqual(result['finalized_age_seconds'], 20)
        self.assertNotIn('validator_ready', result)

    def test_wrong_chain_identity_version_health_slot_and_timestamp_refuse(self):
        original = dict(self.replies)
        good = clock(12345, 1000)['value']['data'][0]
        for method, values in [('getGenesisHash', ['other']), ('getIdentity', [None, {'identity': 'other'}]),
                               ('getVersion', [{'solana-core': '4.3.1'}]), ('getHealth', ['unknown']),
                               ('getAccountInfo', [None, [], {}, {'value': None}, {'value': {'data': 'inert'}},
                                                   {'value': {'data': ['AAAA', 'base58']}}, {'value': {'data': [1, 'base64']}},
                                                   {'value': {'data': ['AAAA', 'base64', 'extra']}},
                                                   {'value': {'data': ['not base64!', 'base64']}},
                                                   {'value': {'data': ['AAAA', 'base64']}},
                                                   {'value': {'data': [good, 'base58']}},
                                                   {'value': {'data': [good, 'base64', 'extra']}},
                                                   {'value': {'data': [good[:4] + '!' + good[4:], 'base64']}},
                                                   clock(12345, -1), clock(12345, 0), clock(12345, 500), clock(12345, 2000)])]:
            for value in values:
                self.replies = dict(original); self.replies[method] = value
                self.assertFalse(self.inspect()['rpc_ready'], (method, value))

    def test_failed_initial_proof_makes_no_rpc_call_and_changed_generation_refuses(self):
        def fail(): raise ValueError('inert private-looking diagnostic')
        result = self.inspect(prove=fail)
        self.assertFalse(result['rpc_ready']); self.assertEqual(self.calls, [])
        self.assertNotIn('private-looking', json.dumps(result))
        with patch.object(self, 'prove', side_effect=[(1, 2), (1, 3)]):
            self.assertFalse(self.inspect()['rpc_ready'])

    def test_error_diagnostics_and_native_body_are_not_returned(self):
        def fail(*_): raise ValueError('inert private-looking native diagnostic')
        result = self.inspect(call=fail)
        self.assertFalse(result['rpc_ready']); self.assertNotIn('private-looking', json.dumps(result))

    def test_actual_http_redirect_duplicates_oversize_and_errors_are_rejected(self):
        seen = []; response = [200, b'{"jsonrpc":"2.0","id":1,"result":"ok"}']
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.path); self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(response[0]); self.send_header('Location', '/unwanted')
                self.end_headers()
                try: self.wfile.write(response[1])
                except (BrokenPipeError, ConnectionResetError): pass
            def do_GET(self):
                seen.append(self.path); self.send_response(200); self.end_headers()
            def log_message(self, *_args): pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with patch.object(observer, 'PORT', server.server_port):
                self.assertEqual(observer.rpc('getHealth', []), 'ok')
                for status, body in [(302, b''), (200, b'{"jsonrpc":"2.0","id":1,"id":1,"result":"ok"}'),
                                     (200, b'{"jsonrpc":"2.0","id":true,"result":"ok"}'),
                                     (200, b'{"jsonrpc":"2.0","id":1,"error":{"message":"inert"}}'),
                                     (200, b' ' * 1048577), (503, b'inert')]:
                    response[:] = [status, body]
                    with self.assertRaises(Exception): observer.rpc('getHealth', [])
                self.assertNotIn('/unwanted', seen)
        finally:
            server.shutdown(); thread.join(); server.server_close()


if __name__ == '__main__': unittest.main()
