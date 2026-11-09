#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert parent endpoint/cipher fixtures; no provider request or key action."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/validator/node'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
sys.path.insert(0,str(Path(__file__).parent))
from validator_state import StateFailures
import credentials
import host
import upstreams


class Credentials(unittest.TestCase):
    def setUp(self):
        StateFailures.setUp(self);self.store.reserve(self.contract)
        self.store.prepare(self.contract,self.intent,self.target,self.stop)
        patch.object(host,'UPSTREAM_CUSTODY',self.root/'parent-credentials').start()
        patch.object(host,'namespaces').start()
        self.verify=patch.object(upstreams.Upstreams,'verify').start()
        # A permitted existing repository host is only an inert URL parser
        # fixture here. It is never used as a provider or contacted by this test.
        self.config={'execution':{'url':'https://github.com/inert-rpc'},'beacon':{'url':'https://github.com/inert-beacon'}}
        self.ciphers={};self.actions=[]

    def convert(self,action,raw):
        self.actions.append(action)
        if action=='encrypt':
            cipher=('INERT CIPHERTEXT '+str(len(self.ciphers))).encode();self.ciphers[cipher]=raw;return cipher
        return self.ciphers[raw]

    def install(self):return credentials.install(self.store,self.contract,self.intent,json.dumps(self.config).encode(),self.stop,self.convert)

    def test_private_import_readback_and_ambiguous_retry_preserve_the_same_cipher(self):
        original=self.store.put
        def lost(name,value):
            if name=='upstreams.json':raise OSError('inert lost parent credential receipt')
            original(name,value)
        with patch.object(self.store,'put',side_effect=lost),self.assertRaises(OSError):self.install()
        cipher=(host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes()
        self.assertTrue(self.install()['upstreams_verified']);self.assertEqual(self.actions.count('encrypt'),1)
        self.assertEqual((host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes(),cipher)
        self.assertEqual(credentials.inspect(self.store,self.contract,self.convert),self.config)

    def test_funded_parent_profile_refuses_plain_http_and_explicit_loopback_before_encryption(self):
        self.config['execution']={'url':'http://127.0.0.1:8545','allow_loopback':True}
        with self.assertRaisesRegex(ValueError,'HTTPS'):self.install()
        self.assertEqual(self.actions,[]);self.verify.assert_not_called()
        self.config['execution']={'url':'https://127.0.0.1:8545','allow_loopback':True}
        with self.assertRaisesRegex(ValueError,'HTTPS'):self.install()
        self.assertEqual(self.actions,[])

    def test_same_intent_cannot_change_its_private_input_and_stopped_token_cannot_write(self):
        self.install();original=(host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes()
        self.config['execution']['headers']={'authorization':'Bearer INERT_CHANGED_INPUT'}
        with self.assertRaisesRegex(ValueError,'another secret'):self.install()
        self.assertEqual((host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes(),original)
        self.store.stop(self.contract,self.stop)
        with self.assertRaisesRegex(ValueError,'cancelled'):self.install()


if __name__=='__main__':
    raise SystemExit(not unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Credentials)).wasSuccessful())
