#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only gRPC PublicKey; optional actual HTTP/2 with pinned public TLS fixtures.

Fixtures are CPython bcee1c322115c581da27600f2ae55e5439c027eb test certificates.
No operational key/certificate is created and the fixture never implements Sign.
"""
import base64
import hashlib
import os
import pathlib
import socket
import ssl
import struct
import sys
import tempfile
import threading
import unittest

sys.dont_write_bytecode = True
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / 'templates'
sys.path[:0] = [str(TEMPLATES / 'validator'), str(TEMPLATES / 'authority')]
import av_remote as remote
from av_files import Files, ROOT
from arc_files import Refused

PUBLIC = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
FRAME = b'\0' + struct.pack('>I', 34) + b'\x0a\x20' + base64.b64decode(PUBLIC)
FIXTURES = None
if len(sys.argv) == 3 and sys.argv[1] == '--public-fixtures':
    FIXTURES = pathlib.Path(sys.argv[2])
    sys.argv = [sys.argv[0]]
    for name, expected in [('allsans', 'd2411a15a825a0f815a883c5d4c53af8e7bdb908ae42b980ac81777bccf41209'),
                           ('pycacert', '702fdeac3a1450e2886b85c081b758487429d857f64ad331d4a5e948b3bc2231')]:
        if hashlib.sha256((FIXTURES / ('public-current-' + name + '.pem')).read_bytes()).hexdigest() != expected:
            raise SystemExit('only the pinned public CPython certificate fixtures are accepted')


class Protocol(unittest.TestCase):
    def test_exact_grpc_public_key_response_and_closed_failures(self):
        headers = b'HTTP/2 200\r\ncontent-type: application/grpc\r\n\r\n'
        end = b'grpc-status: 0\r\n\nERPC_RESULT=2=200\n'
        self.assertEqual(remote.public_response(headers + FRAME + end), PUBLIC)
        for value in [headers + FRAME + end.replace(b'grpc-status: 0', b'grpc-status: 7'),
                      headers + FRAME[:-1] + end, headers + b'\1' + FRAME[1:] + end,
                      headers + FRAME + FRAME + end,
                      headers + FRAME + end.replace(b'RESULT=2=200', b'RESULT=1.1=200'),
                      headers.replace(b'application/grpc', b'text/html') + FRAME + end]:
            with self.assertRaises(Refused):
                remote.public_response(value)


@unittest.skipUnless(FIXTURES, 'explicit pinned public TLS fixture directory required')
class ActualPublicKey(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.context = Files(pathlib.Path(self.temporary.name), owner=os.getuid())
        self.context.mkdir(ROOT)
        ca = (FIXTURES / 'public-current-pycacert.pem').read_bytes()
        # The public CPython fixture also contains an OpenSSL text dump. Supply
        # only its already hash-qualified public PEM certificate to the profile.
        ca = ca[ca.index(b'-----BEGIN CERTIFICATE-----'):]
        self.context.write_bytes(remote.CA, ca)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.addCleanup(self.listener.close)
        self.port = self.listener.getsockname()[1]
        self.payloads, self.errors = [], []
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(str(FIXTURES / 'public-current-allsans.pem'))
        self.tls.set_alpn_protocols(['h2'])
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        self.addCleanup(lambda: self.thread.join(6))
        self.state = {'contract': {'public_key': PUBLIC}, 'remote_signer': {
            'endpoint': 'https://127.0.0.1:' + str(self.port),
            'server_ca_sha256': hashlib.sha256(ca).hexdigest(), 'image_sha256': 'b' * 64,
            'pcr0': 'c' * 96, 'pcr1': 'd' * 96, 'pcr2': 'e' * 96, 'pcr4': 'f' * 96}}

    def serve(self):
        def exact(stream, length):
            value = bytearray()
            while len(value) < length:
                block = stream.recv(length - len(value))
                if not block:
                    raise EOFError()
                value.extend(block)
            return bytes(value)
        def frame(kind, flags, stream_id, value=b''):
            return len(value).to_bytes(3, 'big') + bytes([kind, flags]) + stream_id.to_bytes(4, 'big') + value
        try:
            raw, _ = self.listener.accept()
            with self.tls.wrap_socket(raw, server_side=True) as stream:
                stream.settimeout(5)
                assert stream.selected_alpn_protocol() == 'h2'
                assert exact(stream, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                stream.sendall(frame(4, 0, 0))  # SETTINGS
                request = bytearray()
                while True:
                    header = exact(stream, 9)
                    size, kind, flags = int.from_bytes(header[:3], 'big'), header[3], header[4]
                    stream_id = int.from_bytes(header[5:], 'big') & 0x7fffffff
                    value = exact(stream, size)
                    if kind == 4 and not flags & 1:
                        stream.sendall(frame(4, 1, 0))
                    elif kind == 0:
                        request.extend(value)
                        if flags & 1:
                            self.payloads.append(bytes(request))
                            # Minimal RFC 7541 HPACK literal headers; no dynamic table.
                            headers = b'\x88\x0f\x10\x10application/grpc'
                            trailers = b'\x00\x0bgrpc-status\x010'
                            stream.sendall(frame(1, 4, stream_id, headers) + frame(0, 0, stream_id, FRAME) +
                                           frame(1, 5, stream_id, trailers))
                            return
        except (ssl.SSLError, EOFError):
            pass
        except Exception as error:
            self.errors.append(type(error).__name__)

    def test_production_curl_reads_only_public_key_over_verified_actual_http2(self):
        result = remote.public_key(self.context, self.state)
        self.assertEqual(result['public_key'], PUBLIC)
        self.assertEqual(result['signing_history_protection'], 'not-qualified')
        self.thread.join(5)
        self.assertEqual(self.payloads, [b'\0' * 5])
        self.assertEqual(self.errors, [])

    def test_original_public_key_substitution_cannot_qualify(self):
        self.state['contract']['public_key'] = base64.b64encode(bytes(32)).decode()
        with self.assertRaisesRegex(Refused, 'original consensus public key'):
            remote.public_key(self.context, self.state)


if __name__ == '__main__':
    unittest.main()
