#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert Linux peer credentials; no native process or privileged socket starts."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('polygon_native_peer',ROOT/'templates/scripts/native_peer.py')
peer=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer)


class Stream:
    def __init__(self,*_):self.closed=False;self.sent=[];self.credentials=(1234,20000,20000);self.chunks=[b'{"jsonrpc":"2.0","id":1,"result":42}\n']
    def connect(self,path):self.path=path
    def settimeout(self,value):self.timeout=value
    def getsockopt(self,*_):return struct.pack('3i',*self.credentials)
    def sendall(self,value):self.sent.append(value)
    def recv(self,maximum):
        if self.closed:raise OSError('inert read from closed native stream')
        if not self.chunks:return b''
        value=self.chunks.pop(0)
        if len(value)>maximum:self.chunks.insert(0,value[maximum:])
        return value[:maximum]
    def recv_into(self,buffer):
        value=self.recv(len(buffer));buffer[:len(value)]=value;return len(value)
    def close(self):self.closed=True


class Connected(unittest.TestCase):
    def setUp(self):
        self.original={'pid':1234,'uid':20000,'gid':20000,'reader_gid':20001,'generation':'5678'}
        self.stream=Stream();self.addCleanup(patch.stopall)
        self.identity=patch.object(peer,'identity',return_value=(1,2,3,4)).start()
        patch.object(peer.socket,'SO_PEERCRED',17,create=True).start()
    def prove(self):return dict(self.original)
    def factory(self,*_):return self.stream
    def request(self):return peer.rpc('bor',self.prove,b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}',json.loads,self.factory)

    def test_actual_rpc_path_proves_peer_before_first_request_byte_and_closes_after_reply(self):
        self.assertEqual(self.request()['result'],42)
        self.assertEqual(self.stream.path,str(peer.PATHS['bor']))
        self.assertTrue(self.stream.closed);self.assertEqual(len(self.stream.sent),1)
        self.assertEqual(self.identity.call_count,2)

    def test_foreign_pid_uid_gid_or_replaced_path_never_receives_any_bytes(self):
        for credentials in ((1235,20000,20000),(1234,20001,20000),(1234,20000,20001)):
            self.stream=Stream();self.stream.credentials=credentials
            with self.assertRaises(ValueError):self.request()
            self.assertEqual(self.stream.sent,[]);self.assertTrue(self.stream.closed)
        self.stream=Stream();self.identity.side_effect=[(1,2,3,4),(1,2,3,5)]
        with self.assertRaises(ValueError):self.request()
        self.assertEqual(self.stream.sent,[])

    def test_original_pid_reuse_before_connect_completion_refuses_without_request(self):
        values=iter([self.original,dict(self.original,generation='9999')])
        with self.assertRaises(ValueError):peer.connect('heimdall',lambda:next(values),self.factory)
        self.assertEqual(self.stream.sent,[]);self.assertTrue(self.stream.closed)

    def test_response_bounds_suffix_disconnect_and_deadline_refuse(self):
        for chunks in ([b'{}\n{}\n'],[b''],[b'x'*65]):
            self.stream=Stream();self.stream.chunks=chunks
            with patch.object(peer,'MAXIMUM',64),self.assertRaises(ValueError):self.request()
            self.assertTrue(self.stream.closed)
        self.stream=Stream()
        with patch.object(peer.time,'monotonic',side_effect=[100,131]),self.assertRaises(ValueError):self.request()
        self.assertTrue(self.stream.closed)

    def test_actual_http_client_uses_checked_unix_peer_and_bounded_json_response(self):
        self.stream.chunks=[b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: application/json\r\n\r\n{"x":1}']
        result=peer.rest('/checkpoint/latest',self.prove,lambda proof:peer.HTTPConnection(proof,self.factory))
        self.assertEqual(result,(200,b'{"x":1}'))
        self.assertTrue(self.stream.sent[0].startswith(b'GET /checkpoint/latest HTTP/1.1'))
        self.assertEqual(self.stream.path,str(peer.PATHS['heimdall']));self.assertTrue(self.stream.closed)

    def test_connection_close_responses_keep_the_checked_descriptor_until_body_completion(self):
        for version,header in [(b'HTTP/1.0',b''),(b'HTTP/1.1',b'Connection: close\r\n')]:
            self.stream=Stream()
            self.stream.chunks=[version+b' 200 OK\r\n'+header+b'Content-Length: 7\r\n\r\n',b'{"x":1}']
            self.assertEqual(peer.rest('/checkpoint',self.prove,lambda proof:peer.HTTPConnection(proof,self.factory)),(200,b'{"x":1}'))
            self.assertTrue(self.stream.closed)

    def test_slow_headers_share_one_absolute_deadline_instead_of_resetting_per_read(self):
        reader=peer.DeadlineReader(self.stream,130)
        with patch.object(peer.time,'monotonic',side_effect=[100,129,131]):
            self.assertGreater(reader.readinto(bytearray(1)),0)
            with self.assertRaisesRegex(ValueError,'deadline'):reader.readinto(bytearray(1))

    def test_rest_rejects_ambiguous_paths_without_constructing_a_connection(self):
        for path in ('https://github.com/','//host/path','/x\r\nHeader: y','/x#fragment','/x\\y','/'+'x'*8192):
            with self.assertRaises(ValueError):peer.rest(path,self.prove,lambda *_:self.fail('must not connect'))


@unittest.skipUnless(os.name=='posix' and hasattr(socket,'AF_UNIX'),'local Unix metadata fixture requires POSIX')
class PathAuthority(unittest.TestCase):
    def test_real_socket_ancestry_mode_owner_and_symlink_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();home=root/'native';home.mkdir(mode=0o710)
            path=home/'native.sock';stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                stream.bind(str(path));path.chmod(0o660)
                with patch.object(peer,'ROOT_UID',os.getuid()),patch.object(peer,'TRUST_ANCHOR',root):
                    identity=peer.identity(path,os.getuid(),os.getgid())
                    self.assertEqual(identity[3],path.stat().st_ino)
                    with self.assertRaises(ValueError):peer.identity(path,os.getuid()+1,os.getgid())
                    path.chmod(0o777)
                    with self.assertRaises(ValueError):peer.identity(path,os.getuid(),os.getgid())
                    path.chmod(0o660);root.chmod(0o777)
                    with self.assertRaises(ValueError):peer.identity(path,os.getuid(),os.getgid())
                    root.chmod(0o700);alias=home/'alias';alias.symlink_to(path)
                    with self.assertRaises(ValueError):peer.identity(alias,os.getuid(),os.getgid())
            finally:stream.close()


if __name__=='__main__':unittest.main()
