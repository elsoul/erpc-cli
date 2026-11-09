# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original ingress reservation on the existing inert NSS fixture."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_gateway_account as gateway
import native_accounts as accounts
import accounts as fixture


class GatewayAccount(unittest.TestCase):
    def setUp(self):
        self.inner=fixture.AccountReservation();self.inner.setUp();self.addCleanup(self.inner.tearDown)
        self.contract=self.inner.contract;self.contract['profile']='agave-native-rpc'
        # The fixture's initial owner must describe this same public contract.
        owner=self.inner.state.get('owner.json');owner['contract']=self.contract;self.inner.state.put('owner.json',owner)
        self.original=accounts.ensure(self.inner.state,self.contract,self.inner.account_command)
        self.core_bytes=(self.inner.state_path/'accounts.json').read_bytes()
        self.old_calls=len(self.inner.calls)
        self.patchers=[patch.object(gateway,'SPECS',{'gateway':('erpc-solana-gateway',str(self.inner.root/'ingress'))}),
                       patch.object(gateway,'root_directory',accounts.root_directory)]
        for item in self.patchers:item.start();self.addCleanup(item.stop)

    def ensure(self):return gateway.ensure(self.inner.state,self.contract,self.inner.account_command)

    def test_distinct_original_gateway_does_not_rewrite_three_core_accounts(self):
        record=self.ensure()
        self.assertNotIn(record['uid'],[item['uid'] for item in self.original.values()])
        self.assertEqual((self.inner.state_path/'accounts.json').read_bytes(),self.core_bytes)
        self.assertEqual(len(self.inner.calls),self.old_calls+2)
        self.assertEqual(self.ensure(),record);self.assertEqual(len(self.inner.calls),self.old_calls+2)
        self.assertEqual(gateway.verify(self.inner.state,self.contract),record)

    def test_failed_reservation_sync_never_creates_a_user_on_retry(self):
        real=accounts.sync_file
        def fail(path):
            if path.name==gateway.INTENT:raise OSError('inert ingress receipt sync failure')
            return real(path)
        with patch.object(accounts,'sync_file',fail):
            for _ in range(2):
                with self.assertRaises(OSError):self.ensure()
        self.assertEqual(len(self.inner.calls),self.old_calls)
        planned=self.inner.state.get(gateway.INTENT)['accounts']['gateway']
        self.assertEqual(self.ensure(),planned)

    def test_named_uid_drift_refuses_runtime_while_original_stop_authority_is_retained(self):
        record=self.ensure()
        self.inner.users[record['name']].pw_uid+=100
        with self.assertRaises(ValueError):gateway.verify(self.inner.state,self.contract)
        with self.assertRaises(ValueError):self.ensure()
        self.assertEqual(gateway.original(self.inner.state,self.contract),record)
        self.assertEqual((self.inner.state_path/'accounts.json').read_bytes(),self.core_bytes)

    def test_unknown_existing_gateway_account_is_not_adopted(self):
        source=copy.copy(next(iter(self.inner.groups.values())))
        source.gr_name='erpc-solana-gateway';self.inner.groups[source.gr_name]=source
        with self.assertRaises(ValueError):self.ensure()
        self.assertFalse((self.inner.state_path/gateway.INTENT).exists())
        self.assertEqual(len(self.inner.calls),self.old_calls)


if __name__=='__main__':unittest.main()
