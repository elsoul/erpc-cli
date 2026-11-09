# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticated observation semantics and bounded boot readiness; no network/node."""
import copy
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/authority'))
import eth_validator_health as health


class Health(unittest.TestCase):
    def test_both_qualified_networks_require_original_genesis_fresh_heads_and_ntp(self):
        now=1000000
        for network,chain in health.CHAIN_IDS.items():
            expected={'network':network}
            replies={'/eth/v1/beacon/genesis':{'data':{'genesis_validators_root':health.custody.ROOTS[network],'genesis_time':'400'}},
                     '/eth/v1/node/syncing':{'data':{'is_syncing':False,'is_optimistic':False,'el_offline':False,
                         'sync_distance':'0','head_slot':str((now-400)//12)}}}
            execution={'eth_chainId':hex(chain),'eth_syncing':False,'eth_getBlockByNumber':{'hash':'0x'+'1'*64,'number':'0x123','timestamp':hex(now)}}
            with patch.object(health,'run',return_value=b'yes\n'),patch.object(health,'rpc',side_effect=lambda _s,_e,m,_p:execution[m]), \
                 patch.object(health,'fetch',side_effect=lambda _s,_e,_p,path:copy.deepcopy(replies[path])):
                self.assertTrue(health.readiness(None,expected,now)['ready'])
                replies['/eth/v1/node/syncing']['data']['is_optimistic']=True
                with self.assertRaises(ValueError):health.readiness(None,expected,now)
                replies['/eth/v1/node/syncing']['data']['is_optimistic']=False
                execution['eth_getBlockByNumber']['timestamp']=hex(now-121)
                with self.assertRaises(ValueError):health.readiness(None,expected,now)
            with patch.object(health,'run',return_value=b'no\n'),patch.object(health,'rpc') as outgoing:
                with self.assertRaises(ValueError):health.readiness(None,expected,now)
                outgoing.assert_not_called()

    def test_boot_retry_never_turns_a_canceled_lease_into_a_sync_wait(self):
        validations=[]
        def validate():
            validations.append(True)
            if len(validations)>1:raise ValueError('inert original lease canceled')
        with patch.object(health,'readiness',side_effect=ValueError('inert sync unavailable')) as observe, \
             patch.object(health.time,'sleep'):
            with self.assertRaisesRegex(ValueError,'lease canceled'):health.wait_ready(None,{},validate)
        self.assertEqual(observe.call_count,1)

    def test_sync_retry_has_a_deadline_and_revalidates_before_success(self):
        calls=[]
        with patch.object(health.time,'monotonic',side_effect=[0,601]),patch.object(health,'readiness',side_effect=ValueError('inert unavailable')):
            with self.assertRaisesRegex(ValueError,'remain unavailable'):health.wait_ready(None,{},lambda:calls.append(True))
        self.assertEqual(calls,[True]);calls=[]
        with patch.object(health.time,'sleep'),patch.object(health,'readiness',side_effect=[ValueError('inert syncing'),{'ready':True}]):
            self.assertTrue(health.wait_ready(None,{},lambda:calls.append(True))['ready'])
        self.assertEqual(calls,[True,True])


if __name__=='__main__':unittest.main()
