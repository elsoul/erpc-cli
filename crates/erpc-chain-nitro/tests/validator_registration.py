#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real finalized admission transcript to exact unsigned external funding data."""
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/validator/node'))
sys.path.insert(0,str(Path(__file__).parent))
from validator_admission import Admission, admission
import registration
import abi


class Registration(unittest.TestCase):
    def setUp(self):
        self.observer=Admission(); self.observer.setUp()

    def observe(self): return admission.observe(self.observer.rpc,self.observer.wallet,self.observer.now)

    def test_funding_and_approval_need_matches_the_actual_snapshot_and_original_wallet(self):
        self.observer.balance=100; self.observer.rollup_allowance=1; self.observer.challenge_allowance=0
        value=registration.prepare(self.observe())
        self.assertFalse(value['financial_action_performed']);self.assertTrue(value['signing_required_externally'])
        self.assertEqual(value['weth_shortfall_wei'],'225');self.assertEqual(value['snapshot_block'],'0x100')
        wrap=value['optional_external_wrap']['unsigned_transaction']
        self.assertEqual(wrap,{'chainId':'0x1','from':self.observer.wallet,'to':admission.WETH,'value':hex(225),'data':'0xd0e30db0'})
        for row,amount in zip(value['approvals'],[200,125]):
            self.assertTrue(row['needed']);tx=row['unsigned_transaction']
            self.assertEqual(tx['to'],admission.WETH);self.assertEqual(tx['from'],self.observer.wallet)
            self.assertEqual(int(tx['data'][-64:],16),amount)
            self.assertEqual('0x'+tx['data'][34:74],row['spender'])
        self.assertIsNotNone(value['approvals'][0]['reset_allowance_first'])
        self.assertIsNone(value['approvals'][1]['reset_allowance_first'])
        transfer=value['alternative_external_weth_transfer']['unsigned_transaction']
        self.assertNotIn('from',transfer);self.assertEqual(int(transfer['data'][-64:],16),225)
        self.assertEqual('0x'+transfer['data'][34:74],self.observer.wallet)

    def test_sufficient_allowances_do_not_offer_an_unneeded_approval_transaction(self):
        value=registration.prepare(self.observe())
        self.assertEqual(value['weth_shortfall_wei'],'0')
        self.assertTrue(all(not row['needed'] and row['unsigned_transaction'] is None for row in value['approvals']))
        self.assertFalse(value['gas_adequacy_verified'])

    def test_external_financial_methods_remain_excluded_from_native_sender(self):
        self.observer.balance=0;self.observer.rollup_allowance=0;self.observer.challenge_allowance=0
        value=registration.prepare(self.observe())
        for tx in [*(row['unsigned_transaction'] for row in value['approvals']),
                   value['optional_external_wrap']['unsigned_transaction'],value['alternative_external_weth_transfer']['unsigned_transaction']]:
            with self.assertRaises(ValueError):abi.decode(bytes.fromhex(tx['data'][2:]))


if __name__=='__main__':
    raise SystemExit(not unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Registration)).wasSuccessful())
