# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Readiness and real local HTTP/WebSocket wire fixtures; no chain client runs."""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))

@unittest.skipUnless(os.name=='posix','host observer imports the Linux ownership module')
class Observer(unittest.TestCase):
    def setUp(self):
        import observe
        self.module=observe
        self.profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.height=90_000_000;self.stale=False;self.catching=False;self.wrong=False
    def query(self,port,path='/',payload=None):
        stamp=datetime.datetime.fromtimestamp(time.time()-(300 if self.stale else 0),datetime.timezone.utc).isoformat()
        if port==26657:
            return {'result':{'node_info':{'network':self.profile['heimdall_chain_id'],'id':'public-node-id'},'sync_info':{'latest_block_height':str(self.height),'latest_block_time':stamp,'catching_up':self.catching}}}
        if port==1317:
            return {'params':{'chain_params':{'bor_chain_id':'1' if self.wrong else '80002','heimdall_chain_id':self.profile['heimdall_chain_id']}}}
        method=payload['method']
        if method=='eth_chainId':result='0xaa36a7' if port==9545 else '0x13882'
        elif method=='eth_getBlockByNumber':
            result={'hash':self.profile['bor_genesis_hash']} if payload['params'][0]=='0x0' else {'number':hex(self.height),'timestamp':hex(int(time.time()-(300 if self.stale else 0)))}
        elif method=='eth_syncing':result=False
        elif method=='net_peerCount':result='0x10'
        else:result='bor/v2.10.3/linux-amd64/go1.26.8'
        return {'jsonrpc':'2.0','id':1,'result':result}
    def test_actual_urllib_flow_cannot_redirect_a_loopback_observation(self):
        import io
        import email.message
        import urllib.response
        from unittest.mock import patch
        original=self.module.urllib.request.build_opener
        for status in (200,301,302,303,307,308,500):
            seen=[]
            class InertHTTP(self.module.urllib.request.HTTPHandler):
                def http_open(inner,request):
                    seen.append(request.full_url)
                    headers=email.message.Message()
                    if status!=200:headers['Location']='http://127.0.0.1:9545/redirected-fixture'
                    response=urllib.response.addinfourl(io.BytesIO(b'{"fixture":true}'),headers,request.full_url,status)
                    response.msg='OK' if status==200 else 'Redirect'
                    return response
            def build(*handlers):return original(*handlers,InertHTTP())
            with patch.object(self.module.urllib.request,'build_opener',side_effect=build):
                if status==200:self.assertEqual(self.module.http(26657,'/status'),{'fixture':True})
                else:
                    with self.assertRaises(ValueError):self.module.http(26657,'/status')
            self.assertEqual(seen,['http://127.0.0.1:26657/status'])

    def test_progress_is_required_from_both_correct_fresh_networks(self):
        def advance(_):self.height+=3
        result=self.module.status(self.profile,self.query,advance,lambda chain:True)
        self.assertTrue(result['ready'])
        self.assertFalse(self.module.status(self.profile,self.query,lambda _:None,lambda chain:True)['ready'])
        self.catching=True
        self.assertFalse(self.module.heimdall(self.profile,self.query)['ready'])
        self.catching=False;self.stale=True
        self.assertFalse(self.module.heimdall(self.profile,self.query)['ready'])
        with self.assertRaises(ValueError):self.module.parent(self.profile,self.query)
        self.stale=False;self.wrong=True
        with self.assertRaises(ValueError):self.module.heimdall(self.profile,self.query)
    def test_heimdall_progress_remains_visible_while_bor_waits_to_start(self):
        self.catching=True
        def unavailable(port,path='/',payload=None):
            if port==8545:raise ConnectionRefusedError('inert unavailable Bor')
            return self.query(port,path,payload)
        def advance(_):self.height+=5
        def no_ws(_):raise ConnectionRefusedError('inert unavailable websocket')
        value=self.module.status(self.profile,unavailable,advance,no_ws)
        self.assertFalse(value['ready'])
        self.assertTrue(value['heimdall']['available'])
        self.assertTrue(value['heimdall']['advancing'])
        self.assertFalse(value['heimdall']['caught_up'])
        self.assertFalse(value['bor']['available'])
        self.assertTrue(value['parent']['available'])
        self.assertNotIn('inert unavailable',json.dumps(value))

    def test_quantity_and_timestamp_decoders_reject_ambiguous_or_unbounded_values(self):
        for value in (True,1,'0x','0x00','0x'+'f'*1000):
            with self.assertRaises(ValueError):self.module.number(value)
        with self.assertRaises(ValueError):self.module.timestamp('2026-10-26T12:00:00')
        self.assertGreater(self.module.timestamp('2026-10-26T12:00:00.123456789Z'),0)
    def test_real_websocket_exchange_requires_accept_binding_and_correct_chain(self):
        for valid_accept,chain,expected in [(True,'0x13882',True),(True,'0x89',False),(False,'0x13882',None)]:
            server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1)
            errors=[]
            def serve():
                try:
                    with server.accept()[0] as conn:
                        conn.settimeout(3);data=b''
                        while not data.endswith(b'\r\n\r\n'):data+=conn.recv(1)
                        key=next(line.split(':',1)[1].strip() for line in data.decode().split('\r\n') if line.lower().startswith('sec-websocket-key:'))
                        accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode() if valid_accept else 'incorrect-accept'
                        conn.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode())
                        if not valid_accept:return
                        def exact(size):
                            result=b''
                            while len(result)<size:
                                chunk=conn.recv(size-len(result))
                                if not chunk:raise ValueError('test peer closed')
                                result+=chunk
                            return result
                        flags,length=exact(2);self.assertEqual(flags,0x81);self.assertTrue(length&0x80)
                        mask=exact(4);body=exact(length&0x7f)
                        request=json.loads(bytes(value^mask[index%4] for index,value in enumerate(body)))
                        self.assertEqual(request['method'],'eth_chainId')
                        result=json.dumps({'jsonrpc':'2.0','id':1,'result':chain}).encode()
                        conn.sendall(bytes([0x81,len(result)])+result)
                except Exception as error:errors.append(type(error).__name__)
                finally:server.close()
            thread=threading.Thread(target=serve);thread.start();port=server.getsockname()[1]
            def connect(address,timeout):
                self.assertEqual(address,('127.0.0.1',8546))
                return socket.create_connection(('127.0.0.1',port),timeout)
            if expected is None:
                with self.assertRaises(ValueError):self.module.websocket(80002,connect)
            else:self.assertEqual(self.module.websocket(80002,connect),expected)
            thread.join(5);self.assertFalse(thread.is_alive());self.assertFalse(errors)




@unittest.skipUnless(os.name=='posix','validator observations use inert original host authority')
class ValidatorTransport(unittest.TestCase):
    def setUp(self):
        from unittest.mock import Mock,patch
        from types import SimpleNamespace
        import observe,local_tls
        self.module=observe;self.Mock=Mock;self.patch=patch
        self.expected={'role':'validator','owner':'public-fixture'}
        self.installed={'contract':self.expected,'helpers':'a'*64,'profile_sha256':'b'*64}
        self.state=SimpleNamespace(ownership=Mock(),accounts=SimpleNamespace(verify=Mock()),
            proof=SimpleNamespace(listener=Mock(return_value=('original',))),
            read=lambda path:{'contract':self.expected,'ca_sha256':hashlib.sha256(b'inert public CA').hexdigest()},
            protected=lambda path:SimpleNamespace(read_bytes=lambda:b'inert public CA'))
        self.client=Mock();self.response=SimpleNamespace(status=200,read=lambda count:b'{"result":"inert"}')
        self.client.getresponse.return_value=self.response;self.connect=Mock(return_value=self.client)
        with patch.object(local_tls,'client_context',return_value=object()):
            self.query=observe.ValidatorQuery(self.state,self.installed,self.connect)
    def test_actual_private_https_uses_fixed_address_and_refuses_redirects_or_peer_changes(self):
        payload={'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]}
        self.assertEqual(self.query(9545,payload=payload),{'result':'inert'})
        self.assertEqual(self.connect.call_args.args,('127.0.0.10',9545))
        self.client.close.assert_called_once()
        self.response.status=302
        with self.assertRaises(ValueError):self.query(26657,'/status')
        self.assertEqual(self.connect.call_args.args,('127.0.0.13',26657))
        self.response.status=200;self.state.proof.listener.side_effect=[('original',),('replacement',)]
        with self.assertRaises(ValueError):self.query(26657,'/status')
    def test_original_unix_peer_is_required_for_bor_health_without_widening_adapter_methods(self):
        import native_peer,native_authority
        payload={'jsonrpc':'2.0','id':1,'method':'net_peerCount','params':[]}
        def native(component,prove,raw,decode):
            self.assertEqual(component,'bor');self.assertEqual(prove(),{'original':'peer'})
            self.assertEqual(json.loads(raw),payload)
            return decode(b'{"jsonrpc":"2.0","id":1,"result":"0x1"}')
        with self.patch.object(native_authority,'read',return_value={'original':'peer'}) as proof, \
                self.patch.object(native_peer,'rpc',side_effect=native):
            self.assertEqual(self.query(8545,payload=payload)['result'],'0x1')
        proof.assert_called_once_with(self.state,self.expected,'bor','a'*64,'b'*64)
        self.connect.assert_not_called()
        with self.patch.object(native_peer,'rpc') as request:
            for method in ('eth_sendRawTransaction','personal_unlockAccount','bor_getVoteOnHash'):
                with self.assertRaises(ValueError):self.query(8545,payload=dict(payload,method=method))
            request.assert_not_called()
    def test_unix_only_validator_does_not_claim_a_websocket_listener(self):
        fixture=Observer();fixture.setUp()
        profile=dict(fixture.profile,validator={'phase':'observing'})
        def advance(_):fixture.height+=1
        result=self.module.status(profile,fixture.query,advance,None)
        self.assertTrue(result['ready']);self.assertIsNone(result['websocket_ready'])
        result=self.module.status(fixture.profile,fixture.query,advance,None)
        self.assertFalse(result['ready'])


if __name__=='__main__':unittest.main()
