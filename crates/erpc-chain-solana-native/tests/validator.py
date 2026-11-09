# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public API-shaped validator fixtures; no node, signing key or network execution."""
import copy
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/node'))
import native_validator as validator
from native_custody import base58


class PublicRegistration(unittest.TestCase):
    def setUp(self):
        self.expected={'network':'testnet','identity':base58(bytes([7])*32),'vote_account':base58(bytes([8])*32),
            'withdrawer':base58(bytes([9])*32),'bls':base58(bytes([10])*48),'commission':5}
        self.genesis=base58(bytes([11])*32);self.now=1800000000
        self.account={'owner':validator.VOTE_PROGRAM,'executable':False,'lamports':5000,'space':3762,
            'data':{'program':'vote','parsed':{'type':'vote','info':{
                'nodePubkey':self.expected['identity'],'authorizedWithdrawer':self.expected['withdrawer'],
                'blsPubkeyCompressed':self.expected['bls'],'commission':5,'inflationRewardsCommissionBps':500,
                'authorizedVoters':[{'epoch':10,'authorizedVoter':self.expected['identity']}]}}}}
        self.epochs=0;self.calls=[];self.replies={};self.balance=1000;self.rent=4000

    def call(self,network,method,params):
        self.assertEqual(network,'testnet');self.calls.append((method,params))
        if method in self.replies:return self.replies[method]
        if method=='getGenesisHash':return self.genesis
        if method=='getEpochInfo':
            self.epochs+=1;return {'epoch':11,'absoluteSlot':100+self.epochs*10,'slotIndex':10,'slotsInEpoch':432000}
        if method=='getBlockTime':return self.now-1
        if method=='getAccountInfo':return {'context':{'slot':115},'value':self.account}
        if method=='getMinimumBalanceForRentExemption':return self.rent
        if method=='getBalance':return {'context':{'slot':116},'value':self.balance}
        raise AssertionError('unexpected financial or unqualified method '+method)

    def observe(self):return validator.observe(self.expected,self.genesis,self.call,lambda:self.now)

    def test_fresh_epoch_bound_registration_uses_only_public_reserved_accounts_and_exact_amounts(self):
        self.balance=2**64-1
        result=self.observe();self.assertTrue(result['registration_verified'])
        self.assertEqual(result['identity_lamports'],str(2**64-1))
        self.assertEqual(result['current_voter'],self.expected['identity'])
        self.assertEqual(self.calls[3],('getAccountInfo',[self.expected['vote_account'],{'encoding':'jsonParsed','commitment':'finalized','minContextSlot':110}]))
        self.assertEqual(self.calls[5],('getBalance',[self.expected['identity'],{'commitment':'finalized','minContextSlot':115}]))
        self.assertFalse(any('send' in method.lower() for method,_ in self.calls))

    def test_wrong_owner_bls_withdrawer_fractional_commission_and_pending_rotation_refuse(self):
        original=copy.deepcopy(self.account)
        cases=[('owner','other'),('blsPubkeyCompressed',base58(bytes([12])*48)),
               ('authorizedWithdrawer',self.expected['identity']),('commission',True),
               ('inflationRewardsCommissionBps',501),('nodePubkey',self.expected['withdrawer'])]
        for key,value in cases:
            self.account=copy.deepcopy(original)
            target=self.account if key=='owner' else self.account['data']['parsed']['info'];target[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validator.vote_account(self.account,self.expected,11)
        self.account=copy.deepcopy(original)
        self.account['data']['parsed']['info']['authorizedVoters'].append({'epoch':12,'authorizedVoter':self.expected['withdrawer']})
        with self.assertRaises(ValueError):validator.vote_account(self.account,self.expected,11)

    def test_current_voter_is_not_replaced_early_by_future_entry_and_duplicates_refuse(self):
        info=self.account['data']['parsed']['info']
        info['authorizedVoters']=[{'epoch':10,'authorizedVoter':self.expected['withdrawer']},
                                  {'epoch':12,'authorizedVoter':self.expected['identity']}]
        with self.assertRaises(ValueError):validator.vote_account(self.account,self.expected,11)
        self.assertEqual(validator.vote_account(self.account,self.expected,12)['current_voter'],self.expected['identity'])
        info['authorizedVoters'].append(dict(info['authorizedVoters'][1]))
        with self.assertRaises(ValueError):validator.vote_account(self.account,self.expected,12)

    def test_genesis_staleness_context_regression_and_cross_epoch_fail_closed(self):
        for method,value in [('getGenesisHash','wrong'),('getBlockTime',self.now-121),
                             ('getAccountInfo',{'context':{'slot':109},'value':self.account}),
                             ('getBalance',{'context':{'slot':114},'value':1})]:
            self.replies={method:value};self.epochs=0
            with self.subTest(method=method),self.assertRaises(ValueError):self.observe()
        self.replies={};self.epochs=0
        def crossing(network,method,params):
            value=self.call(network,method,params)
            if method=='getEpochInfo' and self.epochs==2:value['epoch']=12
            return value
        with self.assertRaises(ValueError):validator.observe(self.expected,self.genesis,crossing,lambda:self.now)

    def test_rent_identity_balance_and_unsigned_quantity_types_are_not_inferred(self):
        for balance,rent in [(0,4000),(True,4000),(1,5001),(1,0),(1,1.5)]:
            self.balance,self.rent=balance,rent;self.epochs=0
            with self.subTest(balance=balance,rent=rent),self.assertRaises(ValueError):self.observe()
        for bad in ['', '1'*48, 'z'*66, '0'*66]:
            with self.assertRaises(ValueError):validator.bls_key(bad)
        changed=dict(self.expected,identity=self.expected['withdrawer'])
        with self.assertRaises(ValueError):validator.registration(changed)

    def test_active_participation_requires_current_stake_recent_vote_and_original_public_identity(self):
        row={'votePubkey':self.expected['vote_account'],'nodePubkey':self.expected['identity'],
             'commission':5,'epochVoteAccount':True,'activatedStake':5000,'lastVote':128}
        reply={'current':[row],'delinquent':[]}
        def call(network,method,params):
            if method=='getVoteAccounts':
                self.assertEqual(params,[{'commitment':'finalized','votePubkey':self.expected['vote_account'],
                    'keepUnstakedDelinquents':True,'delinquentSlotDistance':128}])
                return reply
            return self.call(network,method,params)
        def observe():
            self.epochs=0
            return validator.participation(self.expected,self.genesis,call,lambda:self.now)
        self.assertTrue(observe()['validator_ready'])
        self.assertEqual(observe()['activated_stake_lamports'],'5000')
        for key,value in [('activatedStake',0),('epochVoteAccount',False),('lastVote',1)]:
            previous=row[key];row[key]=value
            self.assertFalse(observe()['validator_ready']);row[key]=previous
        reply={'current':[],'delinquent':[row]};self.assertFalse(observe()['validator_ready'])
        reply={'current':[],'delinquent':[]};self.assertFalse(observe()['participation_observed'])
        reply={'current':[row],'delinquent':[row]}
        with self.assertRaises(ValueError):observe()
        reply={'current':[dict(row,nodePubkey=self.expected['withdrawer'])],'delinquent':[]}
        with self.assertRaises(ValueError):observe()
        reply={'current':[dict(row,lastVote=10000)],'delinquent':[]}
        with self.assertRaises(ValueError):observe()


if __name__=='__main__':unittest.main()
