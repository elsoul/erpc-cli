# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public gateway schema fixtures; no native API or network listener is started."""
import importlib.util
import io
from email.message import Message
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import ipaddress
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
path = Path(__file__).parents[1] / 'templates/node/erpc_hl_gateway.py'
spec = importlib.util.spec_from_file_location('hyperliquid_gateway_fixture', path)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class Gateway(unittest.TestCase):
    def test_dual_stack_listener_does_not_depend_on_ambient_ipv6only_default(self):
        server=object.__new__(g.Gateway);server.socket=MagicMock()
        with patch.object(g.ThreadingHTTPServer,'server_bind') as bind:
            g.Gateway.server_bind(server)
            server.socket.setsockopt.assert_called_once_with(g.socket.IPPROTO_IPV6,g.socket.IPV6_V6ONLY,0)
            bind.assert_called_once()

    def test_documented_info_reads_pass_but_native_file_output_never_does(self):
        for kind in ('exchangeStatus', 'meta', 'clearinghouseState', 'delegations'):
            body = json.dumps({'type': kind}).encode()
            self.assertEqual(json.loads(g.validated('/info', body)), {'type': kind})
        for value in ({'type': 'fileSnapshot', 'request': {'type': 'l4Snapshots'}, 'outPath': '/inert/path'},
                      {'type': 'meta', 'outPath': '/inert/path'}, {'type': 'exchangeStatus', 'request': {}},
                      {'type': 'sendSignedAction'}, [{'type': 'meta'}]):
            with self.assertRaises(ValueError):
                g.validated('/info', json.dumps(value).encode())
        with self.assertRaises(ValueError):
            g.validated('/info', b'{"type":"fileSnapshot","type":"meta"}')

    def test_rpc_cannot_enable_admin_signing_or_redirect_the_backend(self):
        good = {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_blockNumber', 'params': []}
        self.assertEqual(json.loads(g.validated('/evm', json.dumps([good]).encode())), [good])
        for method in ('admin_addPeer', 'personal_unlockAccount', 'eth_sign', 'miner_start', 'debug_traceTransaction'):
            with self.assertRaises(ValueError):
                g.validated('/evm', json.dumps(dict(good, method=method)).encode())
        for path in ('/evm?target=other', 'http://127.0.0.1/evm', '/info/../evm'):
            with self.assertRaises(ValueError):
                g.validated(path, json.dumps(good).encode())
        for body in (b'[]', json.dumps([good] * 33).encode(), json.dumps(dict(good, id=True)).encode(),
                     b'{"jsonrpc":"2.0","method":"eth_call","id":NaN}'):
            with self.assertRaises(ValueError):
                g.validated('/evm', body)

    def test_empty_policy_denies_all_and_mapped_ipv4_uses_ipv4_policy(self):
        self.assertFalse(g.permitted('192.0.2.5', []))
        policy = [ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('2001:db8::/32')]
        self.assertTrue(g.permitted('::ffff:192.0.2.5', policy))
        self.assertTrue(g.permitted('2001:db8::5', policy))
        self.assertFalse(g.permitted('198.51.100.5', policy))


    def handler(self, body, address='192.0.2.5'):
        handler = object.__new__(g.Handler)
        handler.client_address = (address, 12345)
        handler.server = SimpleNamespace(ranges=[ipaddress.ip_network('192.0.2.0/24')])
        handler.path = '/info'
        handler.headers = Message()
        handler.headers['Content-Length'] = str(len(body))
        handler.headers['Authorization'] = 'inert client header never forwarded'
        handler.rfile = io.BytesIO(body)
        handler.reply = MagicMock()
        return handler

    def test_actual_handler_refuses_file_output_and_unauthorized_clients_before_opening_backend(self):
        for body, address, status in ((b'{"type":"fileSnapshot","outPath":"/inert"}', '192.0.2.5', 400),
                                      (b'{"type":"exchangeStatus"}', '198.51.100.5', 403)):
            handler = self.handler(body, address)
            with patch.object(g.http.client, 'HTTPConnection') as connection:
                handler.do_POST()
                connection.assert_not_called()
                self.assertEqual(handler.reply.call_args.args[0], status)
        handler = self.handler(b'{"type":"meta"}')
        handler.headers['Content-Length'] = '1'
        with patch.object(g.http.client, 'HTTPConnection') as connection:
            handler.do_POST()
            connection.assert_not_called()
            self.assertEqual(handler.reply.call_args.args[0], 400)

    def test_actual_handler_uses_only_fixed_backend_and_never_forwards_authorization_or_diagnostics(self):
        handler = self.handler(b'{"type":"exchangeStatus"}')
        backend = MagicMock()
        backend.getresponse.return_value = SimpleNamespace(status=200, read=lambda limit: b'{"time":123}')
        with patch.object(g.http.client, 'HTTPConnection', return_value=backend) as connection:
            handler.do_POST()
            connection.assert_called_once_with('127.0.0.1', 3001, timeout=25)
            self.assertNotIn('Authorization', backend.request.call_args.kwargs['headers'])
            self.assertEqual(handler.reply.call_args.args, (200, b'{"time":123}'))
            backend.close.assert_called_once()
        handler = self.handler(b'{"type":"exchangeStatus"}')
        backend = MagicMock()
        backend.getresponse.return_value = SimpleNamespace(status=500, read=lambda limit: b'inert private diagnostic')
        with patch.object(g.http.client, 'HTTPConnection', return_value=backend):
            handler.do_POST()
            self.assertEqual(handler.reply.call_args.args, (502, b'{"error":"native API unavailable"}'))


if __name__ == '__main__':
    unittest.main()
