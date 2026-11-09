# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed finalized-parent admission semantics; no network, signer or native node."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
SOURCE=Path(__file__).parents[1]/'templates/robinhood-admission/node/observation.py'
spec=importlib.util.spec_from_file_location('robinhood_admission_observation',SOURCE)
observation=importlib.util.module_from_spec(spec);spec.loader.exec_module(observation)


class Admission(unittest.TestCase):
    def setUp(self):
        self.network='testnet';self.validator='0x'+'1'*40;self.now=2000000
        self.calls=[];self.listed=False;self.permissionless=False;self.paused=False;self.reorg=False
        self.foreign_rollup=False;self.foreign_parent=False;self.foreign_genesis=False;self.contract_sender=False
    def rpc(self,method,params):
        self.calls.append((method,params));p=observation.PROFILES[self.network]
        def word(value):return '0x'+format(value,'064x')
        if method=='eth_chainId':return hex(1 if self.foreign_parent else p['parent'])
        if method=='eth_getBlockByNumber':
            if params[0]=='0x0':return {'hash':'0x'+'f'*64 if self.foreign_genesis else p['genesis']}
            return {'number':'0x1234','timestamp':hex(self.now-600),'hash':'0x'+('c' if self.reorg and params[0]!='finalized' else 'b')*64}
        if method=='eth_getCode':
            return '0x01' if params[0]!=self.validator or self.contract_sender else '0x'
        self.assertEqual(method,'eth_call');self.assertEqual(params[1],'0x1234')
        target=params[0]['to'];data=params[0]['data'];selector=data[2:10]
        method=next(key for key,value in observation.SELECTORS.items() if value==selector)
        if method=='rollup':self.assertEqual(target,p['bridge']);return word(int(('0x'+'2'*40) if self.foreign_rollup else p['rollup'],16))
        self.assertEqual(target,p['rollup'])
        if method=='isValidator':self.assertEqual(data[10:],self.validator[2:].rjust(64,'0'))
        values={'chainId':p['child'],'bridge':int(p['bridge'],16),'stakeToken':int(p['stake_asset_address'],16),
                'validatorWhitelistDisabled':int(self.permissionless),'isValidator':int(self.listed),
                'paused':int(self.paused),'baseStake':10**18}
        return word(values[method])
    def observe(self):return observation.observe(self.rpc,self.network,self.validator,self.now)
    def test_both_official_profiles_remain_distinct_and_permissioned_admission_is_not_activation(self):
        for network in observation.PROFILES:
            self.network=network
            for name in ('bridge','rollup','stake_asset_address'):observation.address(observation.PROFILES[network][name])
            result=self.observe();self.assertFalse(result['admitted']);self.assertFalse(result['activation_authorized'])
            self.listed=True;result=self.observe();self.assertTrue(result['admitted'])
            self.assertFalse(result['validator_runtime_verified']);self.assertFalse(result['funding_verified']);self.listed=False
            self.assertEqual(result['child_chain_id'],4663 if network=='mainnet' else 46630)
        self.assertTrue(all(method in ('eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call') for method,_ in self.calls))
    def test_unsigned_administrator_call_encodes_two_dynamic_single_element_arrays(self):
        result=self.observe();intent=observation.prepare(result);raw=intent['calldata'][2:]
        self.assertEqual(raw[:8],'a3ffb772');payload=bytes.fromhex(raw[8:])
        words=[int.from_bytes(payload[index:index+32],'big') for index in range(0,len(payload),32)]
        self.assertEqual(len(payload),192);self.assertEqual(words[:2],[64,128])
        self.assertEqual(words[words[0]//32],1);self.assertEqual(words[words[1]//32],1)
        self.assertEqual(words[3],int(self.validator,16));self.assertEqual(words[5],1)
        self.assertTrue(intent['administrator_selected_externally']);self.assertFalse(intent['financial_action_performed'])
        self.assertTrue(observation.validate(intent,result,self.rpc)['intent_matches_current_observation'])
    def test_wrong_parent_genesis_rollup_or_sender_never_produces_an_intent(self):
        for field in ('foreign_parent','foreign_genesis','foreign_rollup','contract_sender','reorg'):
            setattr(self,field,True)
            with self.subTest(field=field),self.assertRaises(ValueError):self.observe()
            setattr(self,field,False)
    def test_external_intent_cannot_change_recipient_sender_method_or_original_snapshot_scope(self):
        observed=self.observe();original=observation.prepare(observed)
        for key,value in [('network','mainnet'),('rollup','0x'+'2'*40),('validator_address','0x'+'2'*40),
                          ('calldata','0xdeadbeef'),('value','0x1'),('administrator_selected_externally',1),
                          ('contracts_source_commit','0'*40)]:
            wrong=dict(original,**{key:value})
            with self.subTest(key=key),self.assertRaises(ValueError):observation.validate(wrong,observed,self.rpc)
        wrong=copy.deepcopy(original);wrong['snapshot']['observed_at']-=1801
        with self.assertRaises(ValueError):observation.validate(wrong,observed,self.rpc)
        wrong=copy.deepcopy(original);wrong['snapshot']['block_timestamp']=True
        with self.assertRaises(ValueError):observation.validate(wrong,observed,self.rpc)
    def test_saved_snapshot_must_match_the_authenticated_canonical_parent(self):
        observed=self.observe();original=observation.prepare(observed)
        for key,value in [('block_hash','0x'+'c'*64),('block','0x1233'),('block_timestamp',self.now-601)]:
            wrong=copy.deepcopy(original);wrong['snapshot'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):observation.validate(wrong,observed,self.rpc)
        self.reorg=True
        with self.assertRaises(ValueError):observation.validate(original,observed,self.rpc)

    def test_false_abi_boolean_stale_header_and_zero_address_are_refused(self):
        actual=self.rpc
        def invalid(method,params):
            if method=='eth_call' and params[0]['data'][2:10]==observation.SELECTORS['isValidator']:
                return '0x'+format(2,'064x')
            return actual(method,params)
        with self.assertRaises(ValueError):observation.observe(invalid,self.network,self.validator,self.now)
        with self.assertRaises(ValueError):observation.header({'number':'0x1','timestamp':'0x1','hash':'0x'+'b'*64},self.now)
        with self.assertRaises(ValueError):observation.calldata('0x'+'0'*40)


if __name__=='__main__':unittest.main()
