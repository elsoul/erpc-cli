#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inspect real x509 builders without generating a private key or issuing a cert."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('polygon_local_tls',ROOT/'templates/scripts/local_tls.py')
tls=importlib.util.module_from_spec(spec);spec.loader.exec_module(tls)
PUBLIC=None
if len(sys.argv)==3 and sys.argv[1]=='--public-fixtures':
    folder=Path(sys.argv[2]);sys.argv=[sys.argv[0]]
    PUBLIC=folder/'arbitrum-public-cpython-ca.pem'
    if hashlib.sha256(PUBLIC.read_bytes()).hexdigest()!='dc42f71ddb9289969f6895c6c906460eef3f84dc348a831e1381f8c94c89c6d6':
        raise SystemExit('only the qualified public CPython CA fixture is accepted')


class Authorities(unittest.TestCase):
    def test_no_native_leaf_can_impersonate_the_funded_parent_or_another_service(self):
        self.assertEqual(tls.SERVERS['gateway'],('127.0.0.10','127.0.0.11','127.0.0.12'))
        all_addresses=[value for addresses in tls.SERVERS.values() for value in addresses]
        self.assertEqual(len(all_addresses),len(set(all_addresses)))
        self.assertNotIn('127.0.0.10',tls.SERVERS['comet'])
        self.assertNotIn('127.0.0.10',tls.SERVERS['broker'])

    @unittest.skipUnless(PUBLIC is not None and importlib.util.find_spec('cryptography') is not None,
                         'explicit public fixture and qualified cryptography runtime are required')
    def test_actual_builders_isolate_leaf_keys_sans_and_never_export_the_issuing_key(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID
        public=x509.load_pem_x509_certificate(PUBLIC.read_bytes()).public_key()
        generated=[];exports=[];builders=[]
        class InertKey:
            def __init__(self,name):self.name=name
            def public_key(self):return public
            def private_bytes(self,*_):exports.append(self.name);return self.name.encode()
        def create(curve):
            self.assertIsInstance(curve,ec.SECP256R1)
            key=InertKey('INERT KEY '+str(len(generated)));generated.append(key);return key
        def sign(builder,key,_algorithm):
            self.assertIs(key,generated[0]);builders.append(builder)
            return SimpleNamespace(public_bytes=lambda _:'INERT CERT'.encode())
        with patch.object(ec,'generate_private_key',side_effect=create),patch.object(x509.CertificateBuilder,'sign',sign):
            result=tls.generate({'owner':'a'*26,'role':'validator'})
        self.assertEqual(len(generated),4);self.assertEqual(len(builders),4)
        self.assertEqual(exports,['INERT KEY 1','INERT KEY 2','INERT KEY 3'])
        self.assertEqual(set(result),{'contract','ca','leaves'})
        issuer_key_id=x509.SubjectKeyIdentifier.from_public_key(public).digest
        for builder in builders:
            extensions={type(value.value):value for value in builder._extensions}
            self.assertTrue(extensions[x509.BasicConstraints].critical)
            self.assertTrue(extensions[x509.KeyUsage].critical)
            self.assertEqual(extensions[x509.SubjectKeyIdentifier].value.digest,issuer_key_id)
            self.assertEqual(extensions[x509.AuthorityKeyIdentifier].value.key_identifier,issuer_key_id)
        for index,(role,addresses) in enumerate(tls.SERVERS.items(),1):
            extensions={type(value.value):value.value for value in builders[index]._extensions}
            self.assertEqual([str(value.value) for value in extensions[x509.SubjectAlternativeName]],list(addresses))
            self.assertEqual(list(extensions[x509.ExtendedKeyUsage]),[ExtendedKeyUsageOID.SERVER_AUTH])
            self.assertFalse(extensions[x509.BasicConstraints].ca)
            self.assertEqual(result['leaves'][role]['key'],'INERT KEY '+str(index))
            self.assertLess(builders[index]._not_valid_after,builders[0]._not_valid_after)

    @unittest.skipUnless(PUBLIC is not None,'explicit existing public CA fixture required')
    def test_client_preserves_platform_default_verification_and_only_supplied_trust(self):
        import ssl
        ca=PUBLIC.read_text();context=tls.client_context(ca)
        baseline=ssl.create_default_context(cadata=ca)
        self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertEqual(context.verify_flags,baseline.verify_flags)
        self.assertEqual(context.get_ca_certs(binary_form=True),baseline.get_ca_certs(binary_form=True))
        self.assertEqual(len(context.get_ca_certs(binary_form=True)),1)


@unittest.skipUnless(os.name=='posix','fenced custody fixture uses POSIX host model')
class Custody(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('polygon_tls_signer_fixture',ROOT/'tests/signer.py')
        source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
        self.fixture=source.Staging();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.expected=self.fixture.expected
        self.intent=self.fixture.intent;self.profile=self.fixture.profile;self.helpers=self.fixture.helpers
        self.now=1793100000;self.created=[];self.expiries={};self.material={};self.projected={}
        self.clock=patch.object(tls,'time',SimpleNamespace(time=lambda:self.now));self.clock.start();self.addCleanup(self.clock.stop)
    def create(self,expected):
        ca='INERT PUBLIC CA '+str(len(self.created));self.created.append(ca);self.expiries[ca]=self.now+365*86400
        return {'contract':expected,'ca':ca,'leaves':{role:{'certificate':'INERT CERT '+role+ca,'key':'INERT PRIVATE '+role+ca} for role in tls.SERVERS}}
    def validate(self,value,expected,allow_expired=False):
        self.assertEqual(value['contract'],expected)
        expiry=self.expiries[value['ca']]
        if not allow_expired and self.now>=expiry:raise ValueError('inert expired certificate')
        return {'public_ca':value['ca'],'ca_sha256':hashlib.sha256(value['ca'].encode()).hexdigest(),'not_after':expiry,
            'certificates':{role:{'certificate':leaf['certificate'],'sha256':hashlib.sha256(leaf['certificate'].encode()).hexdigest()} for role,leaf in value['leaves'].items()}}
    def convert(self,action,name,raw):
        if action=='encrypt':
            result=('INERT CIPHERTEXT '+str(len(self.material))).encode();self.material[result]=(name,raw);self.projected[name]=raw;return result
        self.assertEqual(self.material[raw][0],name);return self.material[raw][1]
    def ensure(self):return tls.ensure(self.state,self.expected,self.intent,self.profile,self.helpers,self.create,self.convert,self.validate)
    def next_intent(self):
        self.intent='c'*32;self.state.prepare(self.expected,self.intent,self.profile,self.helpers)
    def test_original_bundle_reuse_and_only_role_specific_leaf_projection(self):
        first=self.ensure();self.next_intent();self.assertEqual(self.ensure(),first);self.assertEqual(len(self.created),1)
        tls.publish_credentials(self.state,self.expected,self.intent,self.profile,self.helpers,self.convert,self.validate)
        result=tls.verify_projection(self.state,self.expected,self.convert,self.validate)
        self.assertEqual(result['source_intent'],first['source_intent'])
        self.assertIn(b'INERT PRIVATE comet',self.projected['comet-private-key'])
        self.assertNotIn(b'INERT PRIVATE gateway',self.projected['comet-private-key'])
        self.assertNotIn(b'INERT PRIVATE broker',self.projected['polygon-gateway-tls'])
        for path in self.state.path(tls.DIRECTORY).rglob('*'):
            if path.is_file():self.assertNotIn(b'INERT PRIVATE',path.read_bytes())
        self.state.path(tls.DIRECTORY+'/comet-private-key').write_bytes(b'inert substitution')
        with self.assertRaises(ValueError):tls.verify_projection(self.state,self.expected,self.convert,self.validate)
    def test_lost_receipt_recovers_same_encrypted_original_without_reissuing(self):
        original=self.state.write
        def fail(name,*args,**kwargs):
            if name==tls.RECORD:raise OSError('inert receipt directory sync failure')
            return original(name,*args,**kwargs)
        with patch.object(self.state,'write',side_effect=fail),self.assertRaises(OSError):self.ensure()
        cipher=self.state.path(tls.DIRECTORY+'/'+self.intent+'/bundle').read_bytes()
        self.next_intent();saved=self.ensure()
        self.assertEqual(len(self.created),1);self.assertEqual(saved['source_intent'],'a'*32)
        self.assertEqual(self.state.path(tls.DIRECTORY+'/'+saved['source_intent']+'/bundle').read_bytes(),cipher)
    def test_expiry_renews_only_under_a_new_fenced_intent_without_touching_signer(self):
        first=self.ensure();self.state.write('/etc/polygon/identity.json',{'original_signer':'retained'})
        self.now=first['not_after']+1
        with self.assertRaises(ValueError):tls.load(self.state,self.expected,convert=self.convert,validator=self.validate)
        self.next_intent();second=self.ensure()
        self.assertNotEqual(first['source_intent'],second['source_intent']);self.assertEqual(len(self.created),2)
        self.assertTrue(self.state.path(tls.DIRECTORY+'/'+first['source_intent']+'/bundle').exists())
        self.assertEqual(self.state.read('/etc/polygon/identity.json'),{'original_signer':'retained'})
    def test_orphan_or_cancelled_creation_never_generates_new_authority(self):
        folder=self.state.path(tls.DIRECTORY);folder.mkdir();(folder/'unknown').write_text('retain unknown material')
        with self.assertRaisesRegex(ValueError,'orphan'):self.ensure()
        self.assertEqual(self.created,[]);(folder/'unknown').unlink()
        self.state.path('/etc/polygon/stopped').write_bytes(b'')
        with self.assertRaises(ValueError):self.ensure()
        self.assertEqual(self.created,[])


if __name__=='__main__':unittest.main()
