# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compose real deployment state transitions with inert native/nginx boundaries."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_runtime_control as control
import native_gateway as gateway
import native_gateway_observer as observer
import deployment as fixture

STATUS=control.status


class RpcCutover(unittest.TestCase):
    def setUp(self):
        self.inner=fixture.Cutover()
        self.inner.fixture_contract=fixture.owner()
        self.inner.fixture_contract.update(profile='agave-native-rpc',vote_account=None,authority_account=None)
        self.inner.setUp();self.addCleanup(self.inner.doCleanups)
        self.contract=self.inner.contract
        self.inner.request.update(mode='rpc',identity=self.contract['identity_account'])
        fixture.deploy.custody.complete.return_value={'public':self.contract['identity_account'],'cipher_sha256':'e'*64}
        self.gateway={'public':'inert gateway receipt'}
        self.install=patch.object(gateway,'install',return_value=self.gateway).start()
        self.stop=patch.object(gateway,'shutdown').start()
        self.start=patch.object(gateway,'start',side_effect=self.started).start()
        self.inner.completed_candidate()

    def started(self,state,contract,receipt,run):
        self.assertTrue(self.inner.running,'native node must start before public ingress')
        self.assertEqual(receipt,self.gateway)
        self.assertEqual(state.guard(contract)['receipt']['gateway'],self.gateway)
        return 333

    def install_runtime(self):
        self.inner.dispatch('begin-runtime')
        return self.inner.dispatch('install-runtime',firewall={'run':'fixture','bundle':'d'*64})

    def test_rpc_cutover_installs_and_starts_ingress_before_consuming_intent(self):
        self.install_runtime()
        self.assertTrue(self.inner.dispatch('activate-runtime')['runtime_started'])
        self.install.assert_called_once();self.start.assert_called_once()
        self.assertIsNone(self.inner.state.get('intent-fence.json')['intent'])
        unit=(fixture.deploy.units.UNITS/fixture.deploy.units.UNIT).read_text()
        self.assertIn('Wants=erpc-solana-gateway.service',unit)
        self.assertIn('--rpc-bind-address 127.0.0.1',unit)

    def test_skipped_ingress_cancels_the_whole_runtime_without_success_consumption(self):
        self.install_runtime()
        self.start.side_effect=ValueError('inert skipped ingress startup condition')
        with self.assertRaisesRegex(ValueError,'skipped ingress'):self.inner.dispatch('activate-runtime')
        self.assertFalse(self.inner.running)
        self.assertFalse(self.inner.state.runtime_is_current())
        self.assertTrue((self.inner.state.directory/'pending.json').exists())
        self.assertIsNone(self.inner.state.get('intent-fence.json')['intent'])
        self.assertGreaterEqual(self.stop.call_count,2)

    def test_public_readiness_cannot_hide_a_failed_gateway_behind_healthy_native_rpc(self):
        self.install_runtime();self.inner.dispatch('activate-runtime')
        active=self.inner.state.guard(self.contract);receipt=active['receipt']
        self.inner.qualified.return_value=(receipt,{},['/inert/native'],{'node':self.inner.plan['node']})
        with patch.object(control.observer,'inspect',return_value={'rpc_ready':True}),\
             patch.object(observer,'inspect',return_value={'rpc_ready':False,'websocket_ready':False}):
            result=STATUS(self.inner.state,self.contract,self.inner.command)
        self.assertFalse(result['rpc_ready']);self.assertTrue(result['native_rpc_ready'])
        self.assertFalse(result['ingress']['websocket_ready'])


if __name__=='__main__':unittest.main()
