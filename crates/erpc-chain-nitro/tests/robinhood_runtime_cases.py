# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Run the real original host/custody/history lifecycle in both sealed RH scopes.

The inherited fixtures model NSS, process observations and encryption; production
Python modules, persistent file operations and scope contracts remain actual.
"""
from pathlib import Path
import sys
import unittest
import tempfile
import os
import hashlib
import builtins
from unittest.mock import patch
sys.dont_write_bytecode=True
NODE=Path(sys.argv.pop(1));NETWORK=sys.argv.pop(1)
sys.path.insert(0,str(NODE))
import control,host,scope,state,storage,volumes,custody,credentials,parent_tls
sys.path.insert(0,str(Path(__file__).parent))
import validator_state,validator_host,validator_wallet_stage,validator_provider_stage,validator_observer,validator_controller,validator_runtime,validator_firewall,validator_artifact


def expected():
    return {'owner':'a'*26,'family':'robinhood','network':NETWORK,'platform':'amd64',
            'role':'defensive-validator','wallet':'0x'+'1'*40,'creation':'b'*32,
            'host_binding':'c'*64,'data_uuid':'00000000-0000-0000-0000-000000000001'}


class ScopedArtifact(validator_artifact.Artifact):
    pass


class ScopedHost(validator_host.Host):
    def setUp(self):
        original=validator_state.StateFailures.setUp
        def configured(fixture):
            original(fixture);fixture.contract=expected()
        with patch.object(validator_state.StateFailures,'setUp',configured):super().setUp()

    def test_original_role_cannot_adopt_one_or_the_other_robinhood_network(self):
        self.initialize();before=(self.owned/'owner.json').read_bytes();calls=len(self.fixture.calls)
        for changes in ({'family':'arbitrum','network':'mainnet','role':'assertion-validator'},
                        {'network':'mainnet' if NETWORK=='testnet' else 'testnet'}):
            with self.assertRaises(ValueError):host.initialize(dict(self.contract,**changes),lambda _:None,self.command,self.fixture.account_command)
            self.assertEqual((self.owned/'owner.json').read_bytes(),before)
            self.assertEqual(len(self.fixture.calls),calls)

    def test_no_legacy_null_or_one_owner_phase_can_authorize_current_role(self):
        self.initialize();owned=state.State(self.owned);original=owned.get('owner.json')
        for phase in (None,'assertion-validator-v1','assertion-validator-v2'):
            owned.put('owner.json',dict(original,phase=phase))
            with self.assertRaises(ValueError):owned.owner(self.contract)
            with self.assertRaises(ValueError):self.initialize()
        owned.put('owner.json',original);self.assertTrue(self.initialize()['initialized'])


class ScopedWallet(validator_wallet_stage.Stage):
    def setUp(self):
        self.expected_override=expected();super().setUp()


class ScopedProvider(validator_provider_stage.Provider):
    def setUp(self):
        self.expected_override=expected();super().setUp()


class ScopedController(validator_controller.Controller):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temporary.name).resolve();self.expected=expected()
        patch.object(storage,'ROOT_UID',os.getuid()).start();patch.object(storage,'TRUST_ANCHOR',self.root).start()
        patch.object(host,'ROOT',self.root/'state').start();patch.object(host,'RUNTIME',self.root/'run').start()
        storage.directory(host.ROOT,create=True);self.controller=control.Control(self.expected);self.controller.state.reserve(self.expected)
        self.target={'phase':'observing','version':scope.VERSION,'commit':scope.COMMIT,'image':scope.IMAGE,'image_id':scope.IMAGE_ID,'helpers_sha256':'a'*64,'config_id':'b'*64}
        patch.object(host,'namespaces').start();patch.object(host,'capacity').start()
        patch.object(control.accounts,'verify',return_value={'node':{'uid':20000,'gid':20000}}).start()
        patch.object(control.container,'image').start();patch.object(control.publication,'profile',return_value=('a'*64,{})).start()
        self.stops=[];patch.object(control.Control,'shutdown',side_effect=lambda:self.stops.append('owned shutdown')).start()


class ScopedRuntime(validator_runtime.Runtime):
    def setUp(self):
        original=validator_state.StateFailures.setUp
        def configured(fixture):original(fixture);fixture.contract=expected()
        with patch.object(validator_state.StateFailures,'setUp',configured):super().setUp()
        for path in self.proc.root.glob('*/cgroup'):
            path.write_text(path.read_text().replace('erpc-arbitrum-','erpc-robinhood-'))


class ScopedFirewall(validator_firewall.Firewall):
    def setUp(self):
        previous=os.umask(0o077);os.umask(previous);self.addCleanup(os.umask,previous)
        self.addCleanup(patch.stopall)
        self.fixture=validator_firewall.fixture.FirewallTests();self.fixture.family='robinhood';self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.root=self.fixture.root.resolve();self.expected=expected()
        patch.object(storage,'ROOT_UID',os.getuid()).start();patch.object(storage,'TRUST_ANCHOR',self.root).start()
        for name,value in {'ROOT':self.root/'state','CONFIG':self.root/'config','RUNTIME':self.root/'run','FIREWALL_HELPER':self.root/'helper.py'}.items():patch.object(host,name,value).start()
        patch.object(host,'namespaces').start()
        storage.directory(host.ROOT,create=True);storage.directory(host.CONFIG,create=True)
        self.controller=control.Control(self.expected);self.controller.state.reserve(self.expected)
        storage.write(host.CONFIG/'contract.json',storage.encode(self.expected))
        raw=(Path(__file__).resolve().parents[2]/'erpc-ops/templates/rpc-firewall.py').read_bytes()
        storage.write(host.FIREWALL_HELPER,raw)
        self.controller.state.put('common-firewall.json',{'contract':self.expected,'sha256':hashlib.sha256(raw).hexdigest()})
        def fixture_exec(code,namespace):
            builtins.exec(code,namespace)
            def selected(family):
                self.assertEqual(family,'robinhood');return self.fixture.control
            namespace['Firewall']=selected
        patch.object(control.runtime,'exec',side_effect=fixture_exec,create=True).start()


class ScopedObserver(validator_observer.Observer):
    def setUp(self):
        super().setUp();self.protocol['admitted']=True
    def rpc(self,method,params):
        return hex(scope.CHILD_ID) if method=='eth_chainId' else super().rpc(method,params)
    def test_ready_native_validation_is_distinct_from_active_staked_participation(self):
        watched=self.observe('observing')
        self.assertTrue(watched['local_validation_ready']);self.assertFalse(watched['validator_ready'])
        self.protocol['is_staked']=False;self.protocol['latest_staked_assertion']=None
        active=self.observe()
        self.assertTrue(active['validator_ready']);self.assertFalse(active['original_wallet_staked'])
        self.assertEqual(active['strategy'],'Defensive')
        for field,value in [('admitted',False),('funding_checks_passed',False),('eth_balance_wei','0')]:
            previous=self.protocol[field];self.protocol[field]=value
            self.assertFalse(self.observe()['validator_ready']);self.protocol[field]=previous


if __name__=='__main__':unittest.main()
