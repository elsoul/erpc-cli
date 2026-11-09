# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert public admission observations; no keys, signing, send or host mutation."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))

@unittest.skipUnless(os.name=='posix','managed host observations import POSIX ownership')
class Admission(unittest.TestCase):
    def setUp(self):
        import admission
        self.module=admission;self.profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.signer='0x'+'a'*40;self.token='0x'+'b'*40;self.identifier=7;self.parent_ids=[7];self.methods=[];self.calls=0;self.reorg=False
        self.validator={'val_id':'7','voting_power':'100000','pub_key':base64.b64encode(b'\x04'+b'a'*64).decode(),'signer':self.signer,'jailed':False}
        self.result={'validator_set':{'validators':[self.validator]}}
    def query(self,port,path='/',payload=None):
        if port==1317:
            if path=='/stake/validators-set':return self.result
            c=self.module.CONTRACTS['amoy'];return {'params':{'chain_params':{'staking_manager_address':c['stake'],'root_chain_address':c['root'],'pol_token_address':'0x'+'c'*40}}}
        self.assertEqual(port,9545);method=payload['method'];self.methods.append(method)
        if method=='eth_getBlockByNumber':
            self.calls+=1;result={'number':'0x64','timestamp':'0x3e8','hash':'0x'+('c' if self.reorg and self.calls>1 else 'd')*64}
        elif method=='eth_call':
            body,tag=payload['params'];self.assertEqual(tag,'0x64')
            self.assertEqual(body['to'],self.module.CONTRACTS['amoy']['stake'])
            method_name=next(name for name,selector in self.module.SELECTORS.items() if body['data'].startswith(selector))
            values={'minimum':[100000*10**18],'fee':[10**18],'capacity':[105],'count':[len(self.parent_ids)],'epoch':[20],
                'nft':[int(self.module.CONTRACTS['amoy']['nft'],16)],'token':[int(self.token,16)],'signer_id':[self.identifier],
                'owner':[int('e'*40,16)],'validator':[100000*10**18,0,1,0,0,int(self.signer,16),0,1],'set':[32,len(self.parent_ids),*self.parent_ids]}[method_name]
            result='0x'+''.join(self.module.word(value) for value in values)
        else:raise AssertionError('not a read-only observation')
        return {'jsonrpc':'2.0','id':1,'result':result}
    def scan(self):
        with patch.object(self.module.observe,'heimdall',return_value={'ready':True,'height':9000000}),patch.object(self.module.observe,'parent'):
            return self.module.snapshot(self.profile,self.signer,self.query,lambda:1200)
    def test_current_finalized_contract_values_and_set_membership_drive_the_report(self):
        result=self.scan();self.assertTrue(result['registered']);self.assertTrue(result['active_on_both_observations'])
        self.assertEqual(result['minimum_deposit_base_units'],str(100000*10**18));self.assertEqual(result['staking_token'],self.token)
        self.assertEqual(result['parent_validator']['owner'],'0x'+'e'*40)
        self.assertFalse(result['application_guarantees_admission']);self.assertEqual(set(self.methods),{'eth_call','eth_getBlockByNumber'})
        self.parent_ids=[];self.assertFalse(self.scan()['active_on_both_observations'])
    def test_unregistered_and_unfinalized_observations_do_not_claim_activation(self):
        self.identifier=0;self.parent_ids=[]
        result=self.scan();self.assertFalse(result['registered']);self.assertFalse(result['active_on_both_observations'])
        self.reorg=True;self.calls=0
        with self.assertRaises(ValueError):self.scan()
    def test_ambiguous_public_fields_and_invalid_membership_fail_closed(self):
        for mutate in ('duplicate','alias','jailed','shortkey'):
            original=copy.deepcopy(self.result)
            if mutate=='duplicate':self.result['validator_set']['validators'].append(copy.deepcopy(self.validator))
            if mutate=='alias':self.result['validator_set']['validators'][0]['pubKey']=self.validator['pub_key']
            if mutate=='jailed':self.result['validator_set']['validators'][0]['jailed']=True
            if mutate=='shortkey':self.result['validator_set']['validators'][0]['pub_key']=base64.b64encode(b'inert').decode()
            with self.assertRaises(ValueError):self.scan()
            self.result=original
        camel={'validatorSet':{'validators':[{'valId':'7','votingPower':'100000','pubKey':self.validator['pub_key'],'signer':self.signer}]}}
        self.assertEqual(self.module.members(camel)[self.signer]['id'],7)
    def test_parent_only_recovery_and_financial_check_never_claim_heimdall_observation(self):
        with patch.object(self.module.observe,'parent'),patch.object(self.module.observe,'heimdall') as local:
            result=self.module.snapshot(self.profile,self.signer,self.query,lambda:1200,parent_only=True)
        local.assert_not_called();self.assertIsNone(result['heimdall_height']);self.assertIsNone(result['active_member'])
        expected={'network':'amoy','signer':self.signer,'stake_owner':'0x'+'e'*40}
        self.module.admitted(result,expected)
        with self.assertRaises(ValueError):self.module.admitted(result,expected,'0x04'+b'a'.hex()*64)
        with self.assertRaises(ValueError):self.module.admitted(result,dict(expected,stake_owner='0x'+'f'*40))
        result['parent_active']=False
        with self.assertRaises(ValueError):self.module.admitted(result,expected)

    def test_abi_array_and_read_method_boundaries_are_explicit(self):
        for value in ('0x','0x00','0x'+self.module.word(64)+self.module.word(0),'0x'+self.module.word(32)+self.module.word(2)+self.module.word(7)*2):
            with self.assertRaises(ValueError):self.module.active_ids(value)
        for method in ('eth_sendRawTransaction','eth_sendTransaction','personal_sign','eth_sign'):
            with self.assertRaises(ValueError):self.module.rpc(method,[],self.query)
        self.assertFalse(self.methods)

if __name__=='__main__':unittest.main()
