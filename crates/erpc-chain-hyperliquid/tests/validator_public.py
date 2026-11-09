# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Source-shaped public observations with no RPC, transaction or funded wallet."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
folder=Path(__file__).parents[1]/'templates/node'
sys.path.insert(0,str(folder))
import erpc_hl_validator_public as observation


class Public(unittest.TestCase):
    def setUp(self):
        self.profile=json.loads((folder/'catalog.json').read_bytes())['networks']['testnet']
        self.identity={'validator':'0x'+'ab'*20,'signer':'0x'+'cd'*20}
        self.entry={'validator':self.identity['validator'],'signer':self.identity['signer'],
                    'isActive':True,'isJailed':False,'stake':1000000000000,'unjailableAfter':None}
        self.rows=[self.entry];self.now=2000000;self.calls=[]
        self.hot={'marginSummary':{'totalRawUsd':'0.01'},'assetPositions':[],'time':self.now}
        self.cold={'marginSummary':{'totalRawUsd':'1'},'assetPositions':[],'time':self.now}
        self.orders=[]

    def post(self,url,body):
        self.assertEqual(url,self.profile['info_url']);self.calls.append(body)
        kind=body['type']
        if kind=='exchangeStatus':return {'time':self.now}
        if kind=='validatorSummaries':return self.rows
        if kind=='openOrders':return self.orders
        if kind=='clearinghouseState':return self.hot if body['user']==self.identity['signer'] else self.cold
        self.fail('non-read-only request')

    def test_jailed_rank_member_is_not_reported_as_consensus_active(self):
        with patch.object(observation,'post',self.post):
            self.assertEqual(observation.registration(self.profile,self.identity,now=self.now)['state'],'active')
            self.entry['isJailed']=True
            status=observation.registration(self.profile,self.identity,now=self.now)
            self.assertEqual(status['state'],'registered_jailed');self.assertFalse(status['active'])
            self.entry['isJailed']=False;self.entry['isActive']=False
            self.assertEqual(observation.registration(self.profile,self.identity,now=self.now)['state'],'registered_inactive')
            self.rows=[]
            self.assertEqual(observation.registration(self.profile,self.identity,now=self.now)['state'],'not_registered')

    def test_duplicate_signer_substitution_and_unknown_status_do_not_become_registered(self):
        for changed in ('duplicate','signer','other-owner','active-type','stake-type'):
            self.setUp()
            if changed=='duplicate':self.rows.append(copy.deepcopy(self.entry))
            if changed=='signer':self.entry['signer']='0x'+'ef'*20
            if changed=='other-owner':self.entry['validator']='0x'+'ef'*20
            if changed=='active-type':self.entry['isActive']=1
            if changed=='stake-type':self.entry['stake']=True
            with self.subTest(change=changed),patch.object(observation,'post',self.post),self.assertRaises(ValueError):
                observation.registration(self.profile,self.identity,now=self.now)

    def test_funding_requires_explicit_ceiling_raw_cash_and_no_trading(self):
        with patch.object(observation,'post',self.post):
            status=observation.funding(self.profile,self.identity,'0.01',now=self.now)
            self.assertFalse(status['funding_by_erpc']);self.assertEqual(status['signer_perps_usdc'],'0.01')
            for change in ('excess','positions','orders','cold-empty','stale','boolean'):
                old_hot,old_cold,old_orders=copy.deepcopy(self.hot),copy.deepcopy(self.cold),list(self.orders)
                if change=='excess':self.hot['marginSummary']['totalRawUsd']='0.010001'
                if change=='positions':self.hot['assetPositions']=[{'inert':'position'}]
                if change=='orders':self.orders=[{'inert':'order'}]
                if change=='cold-empty':self.cold['marginSummary']['totalRawUsd']='0'
                if change=='stale':self.hot['time']=self.now-120001
                if change=='boolean':self.hot['marginSummary']['totalRawUsd']=True
                with self.subTest(change=change),self.assertRaises(ValueError):
                    observation.funding(self.profile,self.identity,'0.01',now=self.now)
                self.hot,self.cold,self.orders=old_hot,old_cold,old_orders

    def test_invalid_decimals_and_clock_values_cannot_supply_funding_authority(self):
        for value in (None,True,1,'NaN','Infinity','1e9','-1','00.1','1.',''):
            with self.subTest(value=value),self.assertRaises(ValueError):observation.money(value)
        for value in (None,True,0,self.now-120001,self.now+30001):
            with self.subTest(value=value),self.assertRaises(ValueError):observation.fresh(value,self.now)


if __name__=='__main__':unittest.main()
