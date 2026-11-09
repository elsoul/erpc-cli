# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed native gateway callers/response binding; no nodes or TLS issuance."""
import email.message
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
import gateway


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class Transport(unittest.TestCase):
    def setUp(self):
        self.shared=load('polygon_gateway_shared',ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py')
        self.expected={'role':'validator','owner':'public-fixture'}
        self.auth={'format':1,'contract':self.expected,'password':'a'*64}
        self.bor=gateway.Bor(self.shared,lambda:{},self.auth,self.expected)
        _,self.Handler=gateway.types(self.shared)

    def handler(self,method,authorization=None):
        instance=object.__new__(self.Handler)
        instance.server=SimpleNamespace(endpoint='bor',role='execution',upstreams=self.bor)
        raw=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':[]}).encode()
        instance.headers=email.message.Message();instance.headers['Content-Length']=str(len(raw))
        for entry in authorization or []:instance.headers['Authorization']=entry
        instance.path='/';instance.rfile=io.BytesIO(raw);instance.reply=Mock()
        return instance

    def test_unknown_duplicate_and_wrong_callers_do_not_connect_to_native(self):
        for credentials in ([],['Basic invalid'],[self.bor.authorization]*2,['Bearer '+self.auth['password']]):
            instance=self.handler('bor_getVoteOnHash',credentials)
            with patch.object(gateway.native_peer,'rpc') as native:instance.do_POST();native.assert_not_called()
            self.assertEqual(instance.reply.call_args.args[0],403)

    def test_authenticated_native_vote_calls_use_connected_peer_and_exact_response_id(self):
        instance=self.handler('bor_getVoteOnHash',[self.bor.authorization])
        def native(component,prove,body,decode):
            self.assertEqual(component,'bor');self.assertIs(prove,self.bor.prove)
            self.assertEqual(json.loads(body)['method'],'bor_getVoteOnHash')
            return decode(b'{"jsonrpc":"2.0","id":1,"result":true}')
        with patch.object(gateway.native_peer,'rpc',side_effect=native):instance.do_POST()
        self.assertEqual(instance.reply.call_args.args,(200,{'jsonrpc':'2.0','id':1,'result':True}))
        def wrong(component,prove,body,decode):return decode(b'{"jsonrpc":"2.0","id":2,"result":true}')
        with patch.object(gateway.native_peer,'rpc',side_effect=wrong):instance.do_POST()
        self.assertEqual(instance.reply.call_args.args[0],502)

    def test_signing_admin_and_unqualified_methods_never_reach_bor(self):
        for method in ('eth_sendRawTransaction','eth_sendTransaction','personal_unlockAccount','admin_addPeer','debug_traceTransaction','miner_start'):
            instance=self.handler(method,[self.bor.authorization])
            with patch.object(gateway.native_peer,'rpc') as native:instance.do_POST();native.assert_not_called()
            self.assertEqual(instance.reply.call_args.args[0],502)

    def test_native_error_payload_is_not_reflected_or_logged(self):
        instance=self.handler('eth_blockNumber',[self.bor.authorization])
        def wrong(component,prove,body,decode):return decode(json.dumps({'jsonrpc':'2.0','id':1,'error':{'code':-32000,'message':'credential-bearing native failure'}}).encode())
        with patch.object(gateway.native_peer,'rpc',side_effect=wrong):instance.do_POST()
        self.assertNotIn('credential-bearing',str(instance.reply.call_args))
        self.assertEqual(instance.reply.call_args.args[1]['error']['message'],'L1 upstream request failed')

    def test_native_256_block_batch_is_bounded_without_broadening_shared_policy(self):
        values=[{'jsonrpc':'2.0','id':index,'method':method,'params':['0x1']}
                for index,method in enumerate(['eth_getHeaderByNumber','eth_getTdByNumber','bor_getAuthor']*256)]
        def native(component,prove,body,decode):
            return decode(json.dumps([{'jsonrpc':'2.0','id':item['id'],'result':None} for item in json.loads(body)]).encode())
        with patch.object(gateway.native_peer,'rpc',side_effect=native):
            self.assertEqual(len(self.bor.execution_request(json.dumps(values).encode())),768)
        with self.assertRaises(self.shared.Rejected):self.shared.rpc_request(json.dumps(values).encode(),gateway.BOR_METHODS)
        for wrong in (values+[dict(values[0],id=768)],values[:100]+[values[0]],
                      [dict(values[0],method='bor_getVoteOnHash')]):
            with patch.object(gateway.native_peer,'rpc') as native:
                with self.assertRaises((ValueError,self.shared.Rejected)):self.bor.execution_request(json.dumps(wrong).encode())
                native.assert_not_called()

    def test_heimdall_get_keeps_native_error_status_and_refuses_request_bodies(self):
        instance=self.handler('eth_blockNumber');instance.server=SimpleNamespace(endpoint='heimdall',upstreams=Mock())
        instance.server.upstreams.request.return_value=(404,b'{"code":5,"message":"not found"}')
        instance.headers=email.message.Message();instance.path='/heimdallv2/bor/span/1'
        instance.do_GET();self.assertEqual(instance.reply.call_args.args[0],404)
        instance.server.upstreams.request.reset_mock();instance.headers['Content-Length']='1';instance.do_GET()
        instance.server.upstreams.request.assert_not_called();self.assertEqual(instance.reply.call_args.args[0],502)

    def test_tls_handshake_is_inside_bounded_worker_and_suppresses_raw_failures(self):
        Server,_=gateway.types(self.shared)
        instance=object.__new__(Server);instance.context=Mock();instance.slots=Mock()
        instance.finish_request=Mock();instance.shutdown_request=Mock();stream=Mock()
        instance.context.wrap_socket.side_effect=ValueError('inert confidential TLS error')
        instance.work(stream,('127.0.0.1',1))
        instance.finish_request.assert_not_called();instance.slots.release.assert_called_once()
        instance.shutdown_request.assert_called_once_with(stream)

    def test_only_fixed_native_uri_can_receive_the_original_authentication(self):
        value=gateway.bor_url(self.auth,self.expected)
        from urllib.parse import urlsplit
        parsed=urlsplit(value)
        self.assertEqual((parsed.scheme,parsed.hostname,parsed.port,parsed.username),('https','127.0.0.11',8545,'heimdall'))
        self.assertEqual(parsed.password,self.auth['password'])
        with self.assertRaises(ValueError):gateway.bor_url(self.auth,dict(self.expected,owner='other'))
        with self.assertRaises(ValueError):gateway.bor_url(dict(self.auth,password='inert\ninvalid'),self.expected)


@unittest.skipUnless(os.name=='posix','custody is a Linux host path with inert encryption')
class Custody(unittest.TestCase):
    def setUp(self):
        fixture=load('polygon_gateway_lifecycle',ROOT/'tests/control.py')
        self.fixture=fixture.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.expected=dict(self.fixture.contract,role='validator')
        self.auth={'format':1,'contract':self.expected,'password':'b'*64}
        self.create=Mock(return_value=self.auth)
        for name in ('phase','stopped'):
            entry=patch.object(self.state,name);entry.start();self.addCleanup(entry.stop)
        entry=patch.object(self.state.accounts,'verify');entry.start();self.addCleanup(entry.stop)
        self.state.path('/etc/credstore.encrypted/polygon').mkdir(parents=True,exist_ok=True)
    def prepare(self):
        return gateway.prepare_auth(self.state,self.expected,'a'*32,{},'b'*64,self.create,
            lambda action,name,raw:b'encrypted:'+raw if action=='encrypt' else raw.removeprefix(b'encrypted:'))

    def test_retry_preserves_original_and_missing_original_does_not_regenerate(self):
        self.assertEqual(self.prepare(),self.auth);cipher=self.state.path(gateway.AUTH).read_bytes()
        self.prepare();self.create.assert_called_once();self.assertEqual(self.state.path(gateway.AUTH).read_bytes(),cipher)
        self.state.path(gateway.AUTH).unlink()
        with self.assertRaises(ValueError):self.prepare()
        self.create.assert_called_once()

    def test_interrupted_publication_reuses_the_exact_staged_original(self):
        import host
        original=host.publish
        def failed(source,destination,*args,**kwargs):
            if destination==self.state.path(gateway.AUTH):raise OSError('inert interrupted publication')
            return original(source,destination,*args,**kwargs)
        with patch.object(host,'publish',side_effect=failed):
            with self.assertRaises(OSError):self.prepare()
        self.assertTrue(self.state.path(gateway.AUTH+'.pending').exists())
        self.assertEqual(self.prepare(),self.auth);self.create.assert_called_once()


@unittest.skipUnless(os.name=='posix','actual runtime authority uses inert Linux proc/NSS observations')
class RuntimeWiring(unittest.TestCase):
    def test_actual_parent_main_connects_owned_observer_and_active_transports(self):
        fixture=load('polygon_gateway_authority_fixture',ROOT/'tests/native_authority.py').Authority()
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        parent=load('polygon_gateway_parent_runtime',ROOT/'templates/scripts/parent.py')
        shared=load('polygon_gateway_runtime_shared',ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py')
        state=fixture.state;expected=fixture.expected;helpers=fixture.installed['helpers']
        credentials=state.path('/run/credentials/polygon-l1-proxy.service');credentials.mkdir(parents=True)
        (credentials/'execution.json').write_text('{"execution":{"url":"https://github.com"}}')
        (credentials/'polygon-bor-auth').write_text(json.dumps({'format':1,'contract':expected,'password':'c'*64}))
        (credentials/'polygon-gateway-tls').write_text(json.dumps({'ca':'inert public CA','certificate':'inert leaf','key':'inert test marker'}))
        original_path=Path
        def path(name):
            value=original_path(name)
            if str(value).startswith(('/etc/','/run/')):return state.path(str(value))
            return value
        import local_tls
        import state as state_module
        for phase in ('observing','active'):
            state.write('/etc/polygon/validator-runtime.json',{'contract':expected,'helpers':helpers,
                'profile':fixture.installed['profile_sha256'],'phase':phase},mode=0o644)
            accounts=SimpleNamespace(runtime=Mock())
            def transport(path):return accounts if path.name=='accounts.py' else shared
            with patch.object(parent,'__file__','/usr/local/lib/erpc/polygon/releases/'+helpers+'/parent.py'), \
                    patch.object(parent,'Path',side_effect=path),patch.object(parent,'transport',side_effect=transport), \
                    patch.object(parent.sys,'argv',['parent.py','sepolia']),patch.object(state_module,'State',return_value=state), \
                    patch.object(parent.Parent,'verify'),patch.object(local_tls,'server_context',return_value=object()), \
                    patch.object(gateway,'serve') as serve:
                parent.main()
            args=serve.call_args.args;upstream=args[1]
            self.assertIsInstance(args[2],gateway.Bor);self.assertIsInstance(args[3],gateway.Heimdall)
            self.assertEqual(upstream.bridge,{'network':'amoy','signer':expected['signer']} if phase=='active' else None)
            upstream.authorize()
            state.path('/etc/polygon/stopped').touch()
            with self.assertRaises(ValueError):upstream.authorize()
            state.path('/etc/polygon/stopped').unlink()


if __name__=='__main__':unittest.main()
