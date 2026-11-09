# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Parent transport failure fixtures; no live provider calls or credentials."""
import importlib.util
import json
import os
import tempfile
import threading
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ParentTransport(unittest.TestCase):
    def setUp(self):
        self.proxy=load('polygon_parent_fixture',ROOT/'templates/scripts/parent.py')
        self.shared=load('polygon_shared_fixture',ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py')
        self.calls=[]
        self.wrong=False
        outer=self
        class Endpoint:
            loopback=False
            tls=True
            port=443
            def __init__(self,value):
                assert value=={'url':'https://github.com'}
            def request(self,method,body):
                query=json.loads(body);outer.calls.append(query)
                result='0xaa36a7' if query['method']=='eth_chainId' else {'hash':outer.shared.L1['sepolia']['block']}
                if outer.wrong: result='0x1'
                return {'jsonrpc':'2.0','id':query['id'],'result':result}
        self.patch=patch.object(self.shared,'Endpoint',Endpoint)
        self.patch.start();self.addCleanup(self.patch.stop)
        self.parent=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia')

    def test_identity_checks_only_the_required_execution_chain_and_genesis(self):
        self.parent.verify()
        self.assertEqual([call['method'] for call in self.calls],['eth_chainId','eth_getBlockByNumber'])
        self.parent.verify()
        self.assertEqual(len(self.calls),2)
        with self.assertRaises(self.shared.Rejected): self.proxy.Parent(self.shared,{'execution':{},'beacon':{}},'sepolia')

    def test_wrong_parent_and_mutating_methods_fail_before_forwarding(self):
        self.wrong=True
        with self.assertRaises(self.shared.Rejected): self.parent.verify()
        self.assertIsNone(self.parent.checked)
        for method in ('eth_sendRawTransaction','eth_sendTransaction','personal_unlockAccount','engine_newPayloadV3','eth_getProof','eth_getTransactionCount'):
            before=len(self.calls)
            with self.assertRaises(self.shared.Rejected):
                self.parent.execution_request(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':[]}).encode())
            self.assertEqual(len(self.calls),before)

    def test_read_queries_preserve_response_binding_and_do_not_expose_provider_diagnostics(self):
        self.parent.verify()
        with patch.object(self.parent.execution,'request',return_value={'jsonrpc':'2.0','id':3,'result':{}}):
            with self.assertRaises(self.shared.Rejected): self.parent.execution_request(b'{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[]}')
        with patch.object(self.parent.execution,'request',return_value={'jsonrpc':'2.0','id':1,'error':{'code':-32000,'message':'provider secret fixture'}}):
            result=self.parent.execution_request(b'{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[]}')
            self.assertNotIn('provider secret fixture',json.dumps(result))

    def test_validator_allowlist_is_local_and_never_changes_ordinary_rpc(self):
        before=self.shared.METHODS
        bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
            {'network':'amoy','signer':'0x'+'ab'*20},authorize=lambda:None)
        query={'jsonrpc':'2.0','id':1,'method':'eth_maxPriorityFeePerGas','params':[]}
        bridge.execution_request(json.dumps(query).encode())
        self.assertEqual(self.calls[-1],query)
        self.assertEqual(self.shared.METHODS,before)
        count=len(self.calls)
        with self.assertRaises(self.shared.Rejected):self.parent.execution_request(json.dumps(query).encode())
        with self.assertRaises(self.shared.Rejected):self.shared.rpc_request(json.dumps(query).encode())
        self.assertEqual(len(self.calls),count)
        for wrong in ({'network':'mainnet','signer':'0x'+'ab'*20},
                {'network':'amoy','signer':'0x'+'ab'*20,'stake':True}):
            with self.assertRaises(self.shared.Rejected):
                self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',wrong)

    def test_validator_endpoint_refuses_loopback_or_plaintext_before_provider_observation(self):
        for changed in ('loopback','tls'):
            with patch.object(self.shared.Endpoint,changed,changed=='loopback'):
                with self.assertRaises(self.shared.Rejected):
                    self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
                        {'network':'amoy','signer':'0x'+'ab'*20})
            self.assertEqual(self.calls,[])
        bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
            {'network':'amoy','signer':'0x'+'ab'*20})
        with self.assertRaises(self.shared.Rejected):
            bridge.execution_request(b'[{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x02"]}]')
        self.assertEqual(self.calls,[])

    def test_observer_requires_financial_grade_parent_tls_without_enabling_financial_methods(self):
        for changed in ('loopback','tls'):
            with patch.object(self.shared.Endpoint,changed,changed=='loopback'):
                with self.assertRaises(self.shared.Rejected):
                    self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',require_public_tls=True)
            self.assertEqual(self.calls,[])
        observer=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',require_public_tls=True)
        observer.verify();self.assertIsNone(observer.bridge)
        count=len(self.calls)
        with self.assertRaises(self.shared.Rejected):
            observer.execution_request(b'{"jsonrpc":"2.0","id":1,"method":"eth_maxPriorityFeePerGas","params":[]}')
        self.assertEqual(len(self.calls),count)

    def test_whole_batch_rejects_financial_call_before_identity_or_forwarding(self):
        bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
            {'network':'amoy','signer':'0x'+'ab'*20})
        allowed={'jsonrpc':'2.0','id':1,'method':'eth_maxPriorityFeePerGas','params':[]}
        for method,params in [('eth_sendRawTransaction',['0x02c0']),('eth_getTransactionCount',['0x'+'cd'*20,'pending']),
                ('eth_estimateGas',[{'from':'0x'+'ab'*20,'to':'0x'+'cd'*20,'input':'0x00'}]),
                ('eth_sendTransaction',[])]:
            forbidden={'jsonrpc':'2.0','id':2,'method':method,'params':params}
            with self.assertRaises(self.shared.Rejected):bridge.execution_request(json.dumps([allowed,forbidden]).encode())
            self.assertEqual(self.calls,[])

    def test_checkpoint_estimation_requires_fresh_admission_before_forwarding(self):
        import checkpoint
        word=lambda value:value.to_bytes(32,'big')
        data=checkpoint.SELECTOR+word(64)+word(128)+word(1)+b'x'+bytes(31)+word(1)+word(1)+word(2)+word(27)
        signer='0x'+'ab'*20
        query={'jsonrpc':'2.0','id':1,'method':'eth_estimateGas','params':[{
            'from':signer,'to':checkpoint.CONTRACTS['amoy']['root'],'input':'0x'+data.hex()}]}
        bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
            {'network':'amoy','signer':signer},authorize=lambda:None)
        with self.assertRaises(self.shared.Rejected):bridge.execution_request(json.dumps(query).encode())
        self.assertNotIn('eth_estimateGas',[call['method'] for call in self.calls])
        def denied():raise ValueError('inert changed stake owner')
        from contextlib import nullcontext
        bridge.financial_guard=nullcontext
        bridge.admit=denied
        with self.assertRaises(ValueError):bridge.execution_request(json.dumps(query).encode())
        self.assertNotIn('eth_estimateGas',[call['method'] for call in self.calls])
        admitted=[];bridge.admit=lambda:admitted.append('fresh')
        bridge.execution_request(json.dumps(query).encode())
        self.assertEqual(admitted,['fresh']);self.assertEqual(self.calls[-1],query)

    @unittest.skipUnless(os.name=='posix','financial serialization uses the actual POSIX directory flock')
    def test_inflight_financial_request_drains_before_exclusive_stop_and_mutation_rejects_new_sends(self):
        import fcntl
        import checkpoint,native_authority,state
        word=lambda value:value.to_bytes(32,'big')
        data=checkpoint.SELECTOR+word(64)+word(128)+word(1)+b'x'+bytes(31)+word(1)+word(1)+word(2)+word(27)
        signer='0x'+'ab'*20
        request=json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_estimateGas','params':[{
            'from':signer,'to':checkpoint.CONTRACTS['amoy']['root'],'input':'0x'+data.hex()}]}).encode()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'opt/erpc').mkdir(parents=True);(root/'etc/polygon').mkdir(parents=True)
            host=state.State(root,owner=os.getuid())
            bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
                {'network':'amoy','signer':signer},authorize=lambda:None,admit=lambda:None,
                financial_guard=lambda:native_authority.financial_lock(host))
            with host.locked():
                with self.assertRaises(BlockingIOError):bridge.execution_request(request)
                self.assertEqual(self.calls,[])
                # Read-only prerequisite checks remain usable during deployment.
                bridge.execution_request(b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}')
            entered=threading.Event();release=threading.Event();errors=[]
            original=bridge.execution.request
            def forward(method,body):
                if json.loads(body)['method']=='eth_estimateGas':
                    entered.set()
                    if not release.wait(5):raise ValueError('inert test deadline')
                return original(method,body)
            def worker():
                try:bridge.execution_request(request)
                except Exception as error:errors.append(error)
            with patch.object(bridge.execution,'request',side_effect=forward):
                thread=threading.Thread(target=worker);thread.start()
                try:
                    self.assertTrue(entered.wait(5))
                    fd=os.open(root/'opt/erpc',os.O_RDONLY)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(fd)
                finally:release.set();thread.join(5)
            self.assertFalse(thread.is_alive());self.assertFalse(errors)
            with host.locked():(root/'etc/polygon/stopped').touch()
            count=len(self.calls)
            with self.assertRaises(ValueError):bridge.execution_request(request)
            self.assertEqual(len(self.calls),count)

    def test_financial_transport_requires_current_authority_before_and_after_identity_probe(self):
        bridge=self.proxy.Parent(self.shared,{'execution':{'url':'https://github.com'}},'sepolia',
            {'network':'amoy','signer':'0x'+'ab'*20})
        query=b'{"jsonrpc":"2.0","id":1,"method":"eth_maxPriorityFeePerGas","params":[]}'
        with self.assertRaises(self.shared.Rejected):bridge.execution_request(query)
        self.assertEqual(self.calls,[])
        revoked=[False]
        def authorize():
            if revoked[0]:raise ValueError('inert revoked activation')
        bridge.authorize=authorize
        def verify():revoked[0]=True
        with patch.object(bridge,'verify',side_effect=verify):
            with self.assertRaises(ValueError):bridge.execution_request(query)
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
