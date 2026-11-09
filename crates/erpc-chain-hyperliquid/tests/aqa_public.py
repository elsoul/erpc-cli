# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Source/API-shaped public fixtures; no signing, network or operational keys."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/aqa'))
import erpc_aqa_public as public


class Association(unittest.TestCase):
    def setUp(self):
        self.now=1_800_000_000_000
        addresses=['0x'+x*40 for x in 'abcde']
        self.identity=dict(zip(('validator','consensus_signer','agent_master','agent','unused'),addresses))
        self.identity.pop('unused');self.identity['agent_name']='erpc-aqa'
        self.contract={'network':'testnet','identity':self.identity}
        self.rows=[{'name':'erpc-aqa','address':self.identity['agent'],'validUntil':None}]
        self.role={'role':'agent','data':{'user':self.identity['agent_master']}}
        self.validators=[{'validator':self.identity['validator'],'signer':self.identity['consensus_signer'],
                          'isActive':True,'isJailed':False}]
        self.time=self.now;self.requests=[]
        def post(network,request):
            self.assertEqual(network,'testnet');self.requests.append(request)
            return {'exchangeStatus':{'time':self.time},'extraAgents':self.rows,'userRole':self.role,
                    'validatorSummaries':self.validators}[request['type']]
        handle=patch.object(public,'post',post);handle.start();self.addCleanup(handle.stop)

    def test_fresh_named_approval_is_not_claimed_as_vote_acceptance(self):
        value=public.observe(self.contract,self.now)
        self.assertTrue(value['validator_active']);self.assertIsNone(value['approval']['valid_until'])
        self.assertIsNone(value['accepted_vote']);self.assertFalse(value['submitted_by_erpc_observer'])
        self.assertIn('not established',value['vote_eligibility'])
        self.assertEqual(self.requests[1],{'type':'extraAgents','user':self.identity['agent_master']})
        self.rows[0]['validUntil']=self.now+86400000
        self.assertEqual(public.observe(self.contract,self.now)['approval']['valid_until'],self.rows[0]['validUntil'])

    def test_replacement_pruning_expiry_duplicate_and_wrong_master_are_refused(self):
        original=copy.deepcopy(self.rows)
        for rows in [[],original*2,[dict(original[0],name='other')],
                     [dict(original[0],address='0x'+'e'*40)],
                     [dict(original[0],validUntil=self.now-1)],
                     [dict(original[0],validUntil=True)]]:
            self.rows=rows
            with self.assertRaises(ValueError):public.observe(self.contract,self.now)
        self.rows=original;self.role={'role':'agent','data':{'user':'0x'+'e'*40}}
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)
        self.role={'role':'user'}
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)

    def test_missing_changed_or_inactive_validator_is_not_misreported(self):
        self.validators[0]['isJailed']=True
        self.assertFalse(public.observe(self.contract,self.now)['validator_active'])
        self.validators[0]['signer']='0x'+'e'*40
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)
        self.validators=[]
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)

    def test_stale_network_and_noncanonical_public_types_refuse(self):
        self.time-=120001
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)
        self.time=self.now;self.rows[0]['address']='0x'+'A'*40
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)
        self.rows[0]['address']=self.identity['agent'];self.rows[0].pop('validUntil')
        with self.assertRaises(ValueError):public.observe(self.contract,self.now)


if __name__=='__main__':unittest.main()
