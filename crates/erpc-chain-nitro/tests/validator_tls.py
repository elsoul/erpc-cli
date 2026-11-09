#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""TLS custody/expiry faults; optional real handshake uses public CPython keys.

No certificate or private key is generated here. Optional fixtures must match
CPython4a5632fbf9bf59477c540e3f53fa7cdbeea3e3f5 public test-data hashes.
They are not operational credentials and are never copied into this repository.
"""
import hashlib
import importlib.util
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/validator/node'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
sys.path.insert(0,str(Path(__file__).parent))
from validator_state import StateFailures
import host
import parent_tls
import storage
import upstreams
PUBLIC=None
if len(sys.argv)==3 and sys.argv[1]=='--public-fixtures':
    folder=Path(sys.argv[2]);sys.argv=[sys.argv[0]]
    expected={'allsans':'b6e7f6eeef758dd9f2f3f2645029471f09b8a8eb25670045d9d91fd24c597629',
              'ca':'dc42f71ddb9289969f6895c6c906460eef3f84dc348a831e1381f8c94c89c6d6',
              'alternate':'16285baf776fd9abe7c58c629db7f5a9dd4c8fb6a5a9da4c0631437dfe0156d3'}
    files={'alternate':'keycert3'}
    PUBLIC={name:folder/('arbitrum-public-cpython-'+files.get(name,name)+'.pem') for name in expected}
    for name,path in PUBLIC.items():
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected[name]:raise SystemExit('only the pinned public CPython fixture is accepted')


class Custody(unittest.TestCase):
    def setUp(self):
        StateFailures.setUp(self)
        self.store.reserve(self.contract);self.store.prepare(self.contract,self.intent,self.target,self.stop)
        patch.object(host,'TLS_CUSTODY',self.root/'tls').start();patch.object(host,'namespaces').start()
        self.now=1793100000;patch.object(parent_tls,'time',SimpleNamespace(time=lambda:self.now)).start()
        self.generated=[];self.ciphertexts={};self.expiry={}
        patch.object(parent_tls,'validate',side_effect=self.validate).start()

    def create(self,expected):
        self.generated.append('inert identity')
        ca='INERT PUBLIC CA '+str(len(self.generated));self.expiry[ca]=self.now+365*86400
        return {'contract':expected,'ca':ca,'certificate':'INERT PUBLIC CERT '+ca,'key':'inert fixture material'}

    def validate(self,value,expected,allow_expired=False):
        self.assertEqual(value['contract'],expected)
        expiry=self.expiry[value['ca']]
        if not allow_expired and self.now>=expiry:raise ValueError('inert expired certificate')
        return {'ca_sha256':hashlib.sha256(value['ca'].encode()).hexdigest(),
                'certificate_sha256':hashlib.sha256(value['certificate'].encode()).hexdigest(),
                'not_after':expiry,'public_ca':value['ca'],'public_certificate':value['certificate']}

    def convert(self,action,raw):
        if action=='encrypt':
            ciphertext=('INERT ENCRYPTED '+str(len(self.ciphertexts))).encode();self.ciphertexts[ciphertext]=raw;return ciphertext
        return self.ciphertexts[raw]

    def ensure(self):return parent_tls.ensure(self.store,self.contract,self.intent,self.stop,self.create,self.convert)

    def next_intent(self):
        self.intent='e'*32;self.store.prepare(self.contract,self.intent,self.target,self.stop)

    def test_original_identity_is_reused_and_missing_current_cipher_recovers_its_exact_retained_generation(self):
        first=self.ensure();self.next_intent();second=self.ensure()
        self.assertEqual(first,second);self.assertEqual(len(self.generated),1)
        (host.TLS_CUSTODY/'parent-tls.cred').unlink()
        self.assertEqual(self.ensure(),first);self.assertEqual(len(self.generated),1)

    def test_expiry_refuses_runtime_then_same_owner_preparation_renews_without_touching_wallet(self):
        first=self.ensure();wallet=b'inert original financial wallet receipt'
        storage.write(self.path/'key-origin.json',wallet)
        self.now=first['not_after']+1
        with self.assertRaisesRegex(ValueError,'expired'):parent_tls.sealed(self.store,self.contract)
        self.next_intent();second=self.ensure()
        self.assertNotEqual(first['ca_sha256'],second['ca_sha256']);self.assertEqual(len(self.generated),2)
        self.assertEqual((self.path/'key-origin.json').read_bytes(),wallet)
        self.assertTrue((host.TLS_CUSTODY/('prepare-'+first['intent'])/'parent-tls.cred').exists())

    def test_renewal_lost_receipt_recovers_same_cipher_and_never_regenerates(self):
        first=self.ensure();self.now=first['not_after']-1;self.next_intent()
        original=self.store.put
        def fail(name,value):
            if name=='parent-tls.json':raise OSError('inert lost renewed receipt')
            original(name,value)
        with patch.object(self.store,'put',side_effect=fail),self.assertRaises(OSError):self.ensure()
        ciphertext=(host.TLS_CUSTODY/'parent-tls.cred').read_bytes()
        resumed=self.ensure()
        self.assertEqual(len(self.generated),2);self.assertEqual((host.TLS_CUSTODY/'parent-tls.cred').read_bytes(),ciphertext)
        self.assertNotEqual(first['ca_sha256'],resumed['ca_sha256'])

    def test_orphan_or_cancelled_operation_never_generates_tls_material(self):
        host.TLS_CUSTODY.mkdir();(host.TLS_CUSTODY/'unknown-key').write_text('retain unknown fixture')
        with self.assertRaisesRegex(ValueError,'orphan'):self.ensure()
        self.assertEqual(self.generated,[]);(host.TLS_CUSTODY/'unknown-key').unlink()
        self.store.stop(self.contract,self.stop)
        with self.assertRaises(ValueError):self.ensure()
        self.assertEqual(self.generated,[])


@unittest.skipUnless(PUBLIC is not None,'explicit pinned public CPython TLS fixtures not selected')
class Handshake(unittest.TestCase):
    def server(self,tls=True):
        class Proxy:
            calls=[]
            def execution_request(self,body):
                self.calls.append(body)
                return {'jsonrpc':'2.0','id':1,'result':'0x1'}
        proxy=Proxy()
        if tls:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(PUBLIC['allsans']))
            server=parent_tls.Server(('127.0.0.1',0),upstreams.Handler,proxy,'execution',context)
        else:server=upstreams.Server(('127.0.0.1',0),upstreams.Handler,proxy,'execution')
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return server.server_address[1],proxy

    def request(self,port,ca=None,hostname='127.0.0.1'):
        context=parent_tls.client_context(PUBLIC['ca'].read_text() if ca is None else ca)
        self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        client=http.client.HTTPSConnection(hostname,port,context=context,timeout=2)
        try:
            client.request('POST','/',body=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',headers={'Content-Type':'application/json'})
            reply=client.getresponse();return json.loads(reply.read())
        finally:client.close()

    def test_actual_tls_accepts_the_trusted_ip_identity(self):
        port,proxy=self.server();self.assertEqual(self.request(port)['result'],'0x1');self.assertEqual(len(proxy.calls),1)

    def test_wrong_ca_or_wrong_hostname_is_refused_before_any_rpc_body(self):
        port,proxy=self.server()
        wrong=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',PUBLIC['alternate'].read_text(),re.S).group()
        with self.assertRaises(ssl.SSLError):self.request(port,ca=wrong)
        with self.assertRaises(ssl.SSLError):self.request(port,hostname='localhost')
        self.assertEqual(proxy.calls,[])

    def test_rebound_plain_http_listener_cannot_impersonate_the_financial_parent(self):
        port,proxy=self.server(tls=False)
        with self.assertRaises((ssl.SSLError,TimeoutError)):self.request(port)
        self.assertEqual(proxy.calls,[])


@unittest.skipUnless(PUBLIC is not None and importlib.util.find_spec('cryptography') is not None,
                         'public certificate fixtures and pinned cryptography runtime are required')
class PublicCrypto(unittest.TestCase):
    def test_published_certificate_chain_verifies_and_a_different_issuer_refuses(self):
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        ca=x509.load_pem_x509_certificate(PUBLIC['ca'].read_bytes())
        leaf=x509.load_pem_x509_certificate(PUBLIC['allsans'].read_bytes())
        parent_tls.verify_signature(ca,ca);parent_tls.verify_signature(leaf,ca)
        with self.assertRaises(InvalidSignature):parent_tls.verify_signature(leaf,leaf)

    def test_actual_certificate_builders_keep_issuer_key_out_of_runtime_payload_without_issuing(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID
        public=x509.load_pem_x509_certificate(PUBLIC['ca'].read_bytes()).public_key()
        private_exports=[];builders=[];generated=[]
        class InertKey:
            def __init__(self,name):self.name=name
            def public_key(self):return public
            def private_bytes(self,*_args):private_exports.append(self.name);return self.name.encode()
        ca_key,server_key=InertKey('INERT CA'),InertKey('INERT SERVER')
        def create(curve):
            self.assertIsInstance(curve,ec.SECP256R1)
            generated.append(curve);return ca_key if len(generated)==1 else server_key
        def sign(builder,key,algorithm):
            self.assertIs(key,ca_key);builders.append(builder)
            return SimpleNamespace(public_bytes=lambda _encoding:('INERT CERT '+str(len(builders))).encode())
        with patch.object(ec,'generate_private_key',side_effect=create), \
             patch.object(x509.CertificateBuilder,'sign',sign):
            result=parent_tls.generate({'creation':'a'*32})
        self.assertEqual(private_exports,['INERT SERVER']);self.assertEqual(result['key'],'INERT SERVER')
        self.assertEqual(len(builders),2)
        ca_extensions={type(v.value):v for v in builders[0]._extensions}
        leaf_extensions={type(v.value):v for v in builders[1]._extensions}
        self.assertEqual(ca_extensions[x509.BasicConstraints].value,x509.BasicConstraints(ca=True,path_length=0))
        self.assertFalse(leaf_extensions[x509.BasicConstraints].value.ca)
        self.assertEqual([str(v.value) for v in leaf_extensions[x509.SubjectAlternativeName].value],['127.0.0.1'])
        self.assertEqual(list(leaf_extensions[x509.ExtendedKeyUsage].value),[ExtendedKeyUsageOID.SERVER_AUTH])


if __name__=='__main__':
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in (Custody,Handshake,PublicCrypto))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())
