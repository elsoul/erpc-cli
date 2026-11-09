# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual inert HTTPS requests using only pinned public CPython test certificates.

Pass --public-fixtures DIRECTORY containing public-current-{allsans,pycacert}.pem
from CPython bcee1c322115c581da27600f2ae55e5439c027eb Lib/test/certdata.
No operational certificate/key is generated or imported, and no node is run.
Private fixture bytes are never copied into this repository.
"""
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
from authority_validator_transport import token
import eth_validator_transport as transport

FIXTURES=None
if len(sys.argv)==3 and sys.argv[1]=='--public-fixtures':
    FIXTURES=Path(sys.argv[2]);sys.argv=[sys.argv[0]]
    for name,sha in [('allsans','d2411a15a825a0f815a883c5d4c53af8e7bdb908ae42b980ac81777bccf41209'),
                     ('pycacert','702fdeac3a1450e2886b85c081b758487429d857f64ad331d4a5e948b3bc2231')]:
        if hashlib.sha256((FIXTURES/('public-current-'+name+'.pem')).read_bytes()).hexdigest()!=sha:
            raise SystemExit('only the pinned public CPython certificate fixture is accepted')


@unittest.skipUnless(FIXTURES,'explicit pinned public certificate fixture directory required')
class Https(unittest.TestCase):
    def setUp(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(FIXTURES/'public-current-allsans.pem'))
        self.client=ssl.create_default_context(cafile=str(FIXTURES/'public-current-pycacert.pem'))
        self.server=transport.server(context,bytes(32),Path('/inert/socket'),Path('/inert/proof'),'a'*64,'inert-boot',('127.0.0.1',0))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.port=self.server.server_address[1]
        def cleanup():self.server.shutdown();self.thread.join(5);self.server.server_close()
        self.addCleanup(cleanup)

    def test_real_tls_handler_enforces_jwt_before_opening_private_ipc_and_preserves_valid_rpc(self):
        class Peer:
            def close(self):pass
        with patch.object(transport,'connect',return_value=Peer()) as connected,\
             patch.object(transport,'exchange',return_value=b'{"jsonrpc":"2.0","id":1,"result":true}') as exchange:
            client=http.client.HTTPSConnection('127.0.0.1',self.port,context=self.client,timeout=5)
            client.request('POST','/',json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_syncing','params':[]}),
                           {'Authorization':token({'iat':int(transport.time.time())})})
            result=client.getresponse();self.assertEqual(result.status,200);self.assertTrue(json.loads(result.read())['result']);client.close()
            self.assertEqual(connected.call_count,1);self.assertEqual(exchange.call_count,1)
            client=http.client.HTTPSConnection('127.0.0.1',self.port,context=self.client,timeout=5)
            client.request('POST','/',b'{}',{'Authorization':'Bearer invalid'})
            result=client.getresponse();self.assertEqual(result.status,503);result.read();client.close()
            self.assertEqual(connected.call_count,1);self.assertEqual(exchange.call_count,1)

    def test_wrong_ca_and_other_tls_audience_refuse_before_request_bytes(self):
        with patch.object(transport,'connect') as connected:
            unknown=ssl.create_default_context()
            client=http.client.HTTPSConnection('127.0.0.1',self.port,context=unknown,timeout=5)
            with self.assertRaises(ssl.SSLCertVerificationError):client.request('POST','/',b'{}')
            client.close()
            with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):self.client.wrap_socket(raw,server_hostname=transport.ENGINE_IP)
            connected.assert_not_called()

    def test_plain_http_cannot_reach_the_private_ipc_transport(self):
        with patch.object(transport,'connect') as connected:
            with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
                raw.sendall(b'POST / HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}')
                try:self.assertEqual(raw.recv(1),b'')
                except ConnectionResetError:pass
            connected.assert_not_called()


if __name__=='__main__':unittest.main()
