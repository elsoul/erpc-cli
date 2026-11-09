# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""No native services: engine framing and connected-peer refusal with inert sockets."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import socket
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/authority'))
import eth_validator_transport as transport


def token(body,head=None):
    def enc(value):return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    parts=[enc(head or {'alg':'HS256','typ':'JWT'}),enc(body)]
    signature=hmac.digest(bytes(32),'.'.join(parts).encode(),'sha256')
    return 'Bearer '+'.'.join(parts+[base64.urlsafe_b64encode(signature).decode().rstrip('=')])


class Engine(unittest.TestCase):
    def test_authenticated_engine_methods_preserve_negotiation_but_deny_transaction_and_admin(self):
        for method in ('engine_newPayloadV6','engine_getBlobsV4','eth_getLogs','engine_exchangeCapabilities'):
            value={'jsonrpc':'2.0','id':1,'method':method,'params':[]}
            self.assertEqual(transport.request(json.dumps(value).encode()),value)
        for method in ('eth_sendRawTransaction','admin_addPeer','personal_unlockAccount'):
            with self.assertRaises(ValueError):transport.request(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':[]}).encode())
        with self.assertRaises(ValueError):transport.request(b'{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_syncing","params":[]}')

    def test_jwt_requires_valid_signature_and_recent_integer_issuance_without_echoing_input(self):
        transport.jwt(token({'iat':100}),bytes(32),now=100)
        for body in ({'iat':True},{'iat':0},{'iat':100,'exp':99},{'iat':'100'}):
            with self.assertRaises(ValueError):transport.jwt(token(body),bytes(32),now=100)
        with self.assertRaises(ValueError):transport.jwt(token({'iat':100},{'alg':'none'}),bytes(32),now=100)
        with self.assertRaises(ValueError):transport.jwt(token({'iat':100}),bytes([1])*32,now=100)

    def test_ipc_framing_preserves_method_fallback_error_and_partial_unicode(self):
        class Inert:
            def __init__(self,data):self.parts=iter([data[:10],data[10:]]);self.sent=[]
            def sendall(self,raw):self.sent.append(raw)
            def recv(self,_):return next(self.parts,b'')
        req={'jsonrpc':'2.0','id':7,'method':'engine_getBlobsV4','params':[]}
        response={'jsonrpc':'2.0','id':7,'error':{'code':-32601,'message':'Method not found'}}
        client=Inert(json.dumps(response).encode())
        self.assertEqual(json.loads(transport.exchange(client,req)),response);self.assertEqual(len(client.sent),1)
        for data in (b'{"jsonrpc":"2.0","id":8,"result":null}',
                     b'{"jsonrpc":"2.0","id":7,"result":null}\n{}',
                     b'{"jsonrpc":"2.0","id":7,"id":7,"result":null}'):
            with self.assertRaises(ValueError):transport.exchange(Inert(data),req)

    def test_connected_peer_proof_precedes_every_request_byte(self):
        path=Path('/run/erpc-eth-validator/engine/engine.ipc')
        proof={'contract':'a'*64,'boot_id':'inert-boot','pid':1234,'uid':995,'gid':994,'start':77,
               'socket':{'device':5,'inode':9,'path':str(path)},'expires':130}
        metadata=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=995,st_gid=994,st_dev=5,st_ino=9)
        class Inert:
            def __init__(self,pid=1234,uid=995,gid=994):self.peer=(pid,uid,gid);self.sent=[];self.closed=False
            def settimeout(self,_):pass
            def connect(self,_):pass
            def getsockopt(self,*_):return struct.pack('3i',*self.peer)
            def close(self):self.closed=True
            def sendall(self,raw):self.sent.append(raw)
        with patch.object(transport,'public_file',return_value=proof),patch.object(Path,'lstat',return_value=metadata),\
             patch.object(transport,'generation',return_value=77),patch.object(socket,'SO_PEERCRED',17,create=True):
            good=Inert()
            with patch.object(socket,'socket',return_value=good):
                self.assertIs(transport.connect(path,Path('/inert/proof'),'a'*64,'inert-boot',now=100),good)
            self.assertEqual(good.sent,[])
            for peer in (Inert(pid=2345),Inert(uid=996),Inert(gid=993)):
                with patch.object(socket,'socket',return_value=peer):
                    with self.assertRaises(ValueError):transport.connect(path,Path('/inert/proof'),'a'*64,'inert-boot',now=100)
                self.assertTrue(peer.closed);self.assertEqual(peer.sent,[])
            with patch.object(transport,'generation',return_value=78),patch.object(socket,'socket',return_value=Inert()) as opened:
                with self.assertRaises(ValueError):transport.connect(path,Path('/inert/proof'),'a'*64,'inert-boot',now=100)
                self.assertTrue(opened.return_value.closed)
            with patch.object(socket,'socket') as opened:
                for now,boot,contract in [(140,'inert-boot','a'*64),(0,'inert-boot','a'*64),(100,'other-boot','a'*64),(100,'inert-boot','b'*64)]:
                    with self.assertRaises(ValueError):transport.connect(path,Path('/inert/proof'),contract,boot,now=now)
                opened.assert_not_called()


if __name__=='__main__':unittest.main()
