# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""TLS custody/control failures with inert issuer and credential primitives only."""
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_validator_tls as tls
from eth_files import atomic,digest,encoded


class Tls(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Accounts();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.c=self.f.c;self.f.install(tls.custody,'machine',lambda:'b'*64);fixtures.accounts.provision(self.state,'validator')
        self.operation='a'*32;self.generated=[];self.decrypts=[];self.now=int(time.time())
        self.f.install(tls.native,'RUN',self.f.root/'volatile');self.f.install(tls.native,'volatile',lambda _:1)
        def crypto(purpose,action,raw):
            if action=='encrypt':return b'inert encrypted transport:'+raw
            self.decrypts.append(purpose);self.assertTrue(raw.startswith(b'inert encrypted transport:'))
            return raw.split(b':',1)[1]
        self.f.install(tls,'crypt',crypto)
        def issue(purpose,stage):
            self.generated.append(purpose);generation=str(len(self.generated))
            for name in tls.MEMBERS:atomic(stage/name,('inert '+purpose+' '+name+' '+generation).encode())
            value={'purpose':purpose,'ip':tls.IPS[purpose],'ca':(stage/'ca.pem').read_text(),
                   'certificate':(stage/'leaf.pem').read_text(),'private_key':(stage/'leaf.key').read_text()}
            return encoded(value),{'not_before':self.now-10,'not_after':self.now+365*24*3600,
                                   'ca_sha256':digest(value['ca'].encode()),'certificate_sha256':digest(value['certificate'].encode())}
        self.f.install(tls,'issue',issue);self.begin()

    def begin(self,force=False):
        self.state.authorize(self.c,self.operation,{'renew_transport':force},'deploy')
        self.state.begin(self.c,self.operation,lambda:None)

    def complete(self):
        self.state.publish(self.c,self.operation,{});self.state.consume(self.c,self.operation)

    def test_purpose_separation_same_cipher_retries_and_issuer_scratch_cleanup(self):
        engine=tls.renew(self.state,self.c,'engine',self.operation);beacon=tls.renew(self.state,self.c,'beacon',self.operation)
        self.assertNotEqual(engine['ca_sha256'],beacon['ca_sha256'])
        self.assertEqual(tls.renew(self.state,self.c,'engine',self.operation),engine)
        self.assertEqual(self.generated,['engine','beacon'])
        self.assertEqual(list((tls.native.RUN/'tls-issuance').iterdir()),[])
        _,material=tls.ready(self.state,self.c,'engine');self.assertEqual(material['ip'],'127.0.0.2')
        with self.assertRaises(ValueError):tls.ready(self.state,self.c,'engine',now=engine['not_after'])

    def test_visible_current_receipt_failure_retries_original_cipher_and_cleans_private_stage(self):
        original=self.state.put
        def fail(name,value):
            original(name,value)
            if name=='tls-engine.json':raise OSError('inert visible current receipt before directory durability')
        with patch.object(self.state,'put',side_effect=fail):
            with self.assertRaises(OSError):tls.renew(self.state,self.c,'engine',self.operation)
        pending=self.state.path('tls-engine-'+self.operation+'.cred').read_bytes()
        self.assertEqual(len(list((tls.native.RUN/'tls-issuance').iterdir())),1)
        tls.renew(self.state,self.c,'engine',self.operation)
        self.assertEqual(self.generated,['engine']);self.assertEqual(self.state.path('tls-engine-'+self.operation+'.cred').read_bytes(),pending)
        self.assertEqual(list((tls.native.RUN/'tls-issuance').iterdir()),[])

    def test_missing_cipher_requires_explicit_new_stopped_recovery_intent(self):
        original=tls.renew(self.state,self.c,'engine',self.operation);self.complete()
        self.state.path('tls-engine-'+self.operation+'.cred').unlink();self.operation='b'*32;self.begin()
        with self.assertRaises(FileNotFoundError):tls.renew(self.state,self.c,'engine',self.operation)
        with self.assertRaises(ValueError):tls.renew(self.state,self.c,'engine',self.operation,True)
        self.assertEqual(self.generated,['engine'])
        self.state.recover(self.c,self.operation,lambda:None);self.operation='c'*32;self.begin(True)
        renewed=tls.renew(self.state,self.c,'engine',self.operation,True)
        self.assertNotEqual(renewed['cipher_sha256'],original['cipher_sha256']);self.assertEqual(self.generated,['engine','engine'])
        self.assertEqual(tls.renew(self.state,self.c,'engine',self.operation,True),renewed)

    def test_cancel_or_foreign_identity_prevents_issuance_and_private_material_access(self):
        self.state.stop(self.c,lambda:None)
        with self.assertRaises(ValueError):tls.renew(self.state,self.c,'engine',self.operation)
        self.assertEqual(self.generated,[])
        self.f.users['ev-validator'].pw_uid=777
        with self.assertRaises(ValueError):tls.receipt(self.state,self.c,'engine')
        self.assertEqual(self.decrypts,[])

    def test_current_receipt_durability_failure_prevents_private_material_before_decryption(self):
        tls.renew(self.state,self.c,'engine',self.operation);self.decrypts.clear();actual=os.fsync
        def fail(fd):
            raise OSError('inert persistent original receipt synchronization failure')
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):tls.ready(self.state,self.c,'engine')
        self.assertEqual(self.decrypts,[])


if __name__=='__main__':unittest.main()
