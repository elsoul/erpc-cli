# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real custody publication/durability with inert crypto and NSS; no keys generated."""
import copy
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_validator_custody as custody


def material():
    return {'keystore':{'version':4,'pubkey':'1'*96,'crypto':{name:{'function':'inert-fixture','params':{},'message':''}
            for name in ('kdf','checksum','cipher')}},'password':'inert fixture, not a key'}


class Custody(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Accounts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.expected=self.fixture.c
        self.fixture.install(custody,'machine',lambda:'b'*64)
        fixtures.accounts.provision(self.state,'validator');self.calls=[]
        def native(argv,input_data):
            self.calls.append(argv)
            self.assertEqual(argv,['/usr/bin/systemd-creds',argv[1],'--name='+custody.NAME]+(['--with-key=host'] if argv[1]=='encrypt' else [])+['-','-'])
            if argv[1]=='encrypt':return b'inert cipher fixture:'+input_data
            self.assertTrue(input_data.startswith(b'inert cipher fixture:'));return input_data.split(b':',1)[1]
        self.fixture.install(custody,'run',native)
        self.history=self.state.directory/'inert-native-history';self.history.write_bytes(b'original mutable signing history')

    def test_original_roundtrip_and_recovery_preserve_history_and_never_start(self):
        value=material();record=custody.seal(self.state,self.expected,value)
        path=self.state.path('signer-original.cred');original=path.read_bytes()
        self.assertEqual(custody.reveal(self.state,self.expected),value)
        self.assertEqual(custody.seal(self.state,self.expected,value),record)
        self.assertEqual(len([a for a in self.calls if a[1]=='encrypt']),1)
        path.unlink();restored=custody.restore(self.state,self.expected,original,lambda:None)
        self.assertFalse(restored['signing_started']);self.assertEqual(path.read_bytes(),original)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.history.read_bytes(),b'original mutable signing history')

    def test_foreign_account_or_original_receipt_loss_precedes_decryption(self):
        custody.seal(self.state,self.expected,material());self.calls.clear()
        self.fixture.users['ev-validator'].pw_uid=777
        with self.assertRaises(ValueError):custody.reveal(self.state,self.expected)
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):custody.reveal(self.state,dict(self.expected,owner='another'))
        self.assertEqual(self.calls,[])

    def test_persistent_owner_directory_failure_blocks_every_retry_and_export(self):
        custody.seal(self.state,self.expected,material());self.calls.clear();original=os.fsync
        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert directory durability failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):custody.seal(self.state,self.expected,material())
                with self.assertRaises(OSError):custody.reveal(self.state,self.expected)
        self.assertEqual(self.calls,[])

    def test_visible_receipt_failure_retries_exact_pending_original(self):
        original=self.state.put
        def fail(name,value):
            original(name,value)
            if name=='signer-custody.json':raise OSError('inert visible receipt before directory durability')
        with patch.object(self.state,'put',side_effect=fail):
            with self.assertRaises(OSError):custody.seal(self.state,self.expected,material())
        self.assertTrue(self.state.exists('signer-original.pending'));self.assertFalse(self.state.exists('signer-original.cred'))
        pending=self.state.path('signer-original.pending').read_bytes()
        custody.seal(self.state,self.expected,material())
        self.assertEqual(self.state.path('signer-original.cred').read_bytes(),pending)
        self.assertEqual(len([a for a in self.calls if a[1]=='encrypt']),1)

    def test_unknown_pending_or_replaced_original_is_not_repaired(self):
        pending=self.state.path('signer-original.pending');pending.write_bytes(b'unowned stage')
        with self.assertRaises(ValueError):custody.seal(self.state,self.expected,material())
        self.assertEqual(pending.read_bytes(),b'unowned stage');self.assertEqual(self.calls,[]);pending.unlink()
        custody.seal(self.state,self.expected,material());path=self.state.path('signer-original.cred');original=path.read_bytes()
        path.write_bytes(b'replaced encrypted original')
        stops=[];custody.restore(self.state,self.expected,original,lambda:stops.append('owned signer stopped'))
        self.assertEqual(path.read_bytes(),original);self.assertEqual(stops,['owned signer stopped'])
        quarantined=list(self.state.directory.glob('signer-quarantine-*.cred'))
        self.assertEqual(len(quarantined),1);self.assertEqual(quarantined[0].read_bytes(),b'replaced encrypted original')

    def test_changed_input_or_machine_cannot_replace_original(self):
        custody.seal(self.state,self.expected,material());value=material();value['password']='different inert password'
        with self.assertRaises(ValueError):custody.seal(self.state,self.expected,value)
        owner=self.state.get('owner.json');owner['machine']='c'*64;self.state.put('owner.json',owner)
        with self.assertRaises(ValueError):custody.reveal(self.state,self.expected)

    def test_signing_history_is_separate_from_credential_and_closed_by_network_and_key(self):
        pubkey,_=custody.key_material(material())
        value={'metadata':{'interchange_format_version':'5','genesis_validators_root':custody.ROOTS['hoodi']},
               'data':[{'pubkey':pubkey,'signed_blocks':[],'signed_attestations':[]}]}
        custody.history(value,'hoodi',pubkey,True)
        bad=copy.deepcopy(value);bad['data'][0]['signed_blocks']=[{'slot':'1'}]
        with self.assertRaises(ValueError):custody.history(bad,'hoodi',pubkey,True)
        custody.history(bad,'hoodi',pubkey)
        for slot in [True,'-1',str(2**64),'01']:
            bad['data'][0]['signed_blocks'][0]['slot']=slot
            with self.assertRaises(ValueError):custody.history(bad,'hoodi',pubkey)
        with self.assertRaises(ValueError):custody.history(value,'mainnet',pubkey)


if __name__=='__main__':unittest.main()
