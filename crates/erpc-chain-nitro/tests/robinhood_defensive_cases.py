# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public transcripts/calldata only; no signer creation or transaction submission."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
NODE=Path(sys.argv.pop(1));NETWORK=sys.argv.pop(1)
sys.path.insert(0,str(NODE))
import scope
import admission
import configuration
import registration
import transactions
import abi
import state
import host
import custody
import credentials
import parent_tls
import locking
import observer
import rlp
import crypto
import transport
import upstreams
import json
from contextlib import contextmanager
from types import SimpleNamespace


def word(value):
    if isinstance(value,str):value=int(value[2:],16)
    return value.to_bytes(32,'big')


def encoded(selector,words):return bytes.fromhex(selector)+b''.join(word(value) for value in words)


class Defensive(unittest.TestCase):
    def setUp(self):
        self.wallet='0x'+'1'*40;self.challenge='0x'+'3'*40;self.now=1793700000
        self.header={'number':'0x100','hash':'0x'+'a'*64,'timestamp':hex(self.now-900)}
        self.public=False;self.listed=True;self.staked=False;self.paused=False;self.base=10**18
        self.balance=10**18;self.allowance=10**18;self.gas=10**18;self.changes={};self.calls=[]
        self.wallet_code='0x'

    def rpc(self,method,params):
        self.calls.append((method,params))
        if method=='eth_chainId':return hex(scope.PARENT_ID)
        if method=='eth_getBlockByNumber':return {'hash':scope.PARENT_GENESIS} if params[0]=='0x0' else self.header
        if method=='eth_getCode':return self.wallet_code if params[0]==self.wallet else '0x60006000'
        if method=='eth_getBalance':return hex(self.gas)
        self.assertEqual(method,'eth_call')
        name=next(name for name,value in admission.SELECTORS.items() if params[0]['data'][2:10]==value)
        values={'rollup':scope.ROLLUP,'chainId':scope.CHILD_ID,'bridge':scope.BRIDGE,
            'challengeManager':self.challenge,'assertionChain':scope.ROLLUP,'stakeToken':scope.WETH,
            'challengeGracePeriodBlocks':20,'wasmModuleRoot':123,'paused':int(self.paused),
            'validatorWhitelistDisabled':int(self.public),'isValidator':int(self.listed),'baseStake':self.base,
            'isStaked':int(self.staked),'amountStaked':self.base if self.staked else 0,
            'latestStakedAssertion':99,'withdrawalAddress':self.wallet,'balanceOf':self.balance,'allowance':self.allowance}
        return '0x'+word(self.changes.get(name,values[name])).hex()

    def observe(self):return admission.observe(self.rpc,self.wallet,self.now)

    def assertion(self):
        values=[self.base,1,2,3,self.base,self.challenge,10,20]+[0]*12+[4,self.wallet]
        return encoded('50f32f68',values)

    def test_fixed_family_network_and_physical_custody_do_not_adopt_one_or_the_other_network(self):
        expected={'family':'robinhood','network':NETWORK,'role':'defensive-validator','platform':'amd64',
            'owner':'a'*26,'wallet':self.wallet,'creation':'b'*32,'host_binding':'c'*64,
            'data_uuid':'10000000-0000-0000-0000-000000000001'}
        state.contract(expected)
        for field,value in [('family','arbitrum'),('role','assertion-validator'),('network','testnet' if NETWORK=='mainnet' else 'mainnet')]:
            with self.assertRaises(ValueError):state.contract(dict(expected,**{field:value}))
        self.assertIn(NETWORK,str(host.ROOT));self.assertNotEqual(str(host.ROOT),'/var/lib/erpc-nitro')
        self.assertTrue(all(NETWORK in value for value in (custody.NAME,credentials.NAME,parent_tls.NAME,str(locking.CONTROL))))
        self.assertEqual(scope.OWNER_PHASE,'robinhood-defensive-v1')

    def test_native_profile_is_defensive_only_and_custom_genesis_is_network_specific(self):
        value=configuration.public(self.wallet,'active')
        self.assertEqual(value['node']['staker']['strategy'],'Defensive')
        self.assertEqual(value['chain']['id'],scope.CHILD_ID)
        self.assertFalse(value['node']['bold']['auto-deposit']);self.assertFalse(value['node']['bold']['auto-increase-allowance'])
        self.assertFalse(value['node']['bold']['delegated-staking']['enable'])
        self.assertEqual(value['init']['latest'],'')
        self.assertEqual(value['init'].get('genesis-json-file'),'/config/genesis.json' if NETWORK=='mainnet' else None)
        observing=configuration.public(self.wallet,'observing')
        self.assertEqual(observing['node']['staker']['strategy'],'Watchtower')
        self.assertNotIn('parent-chain-wallet',observing['node']['staker'])

    def test_permissioned_allowlist_is_checked_at_the_original_finalized_parent(self):
        value=self.observe()
        self.assertFalse(value['permissionless']);self.assertTrue(value['allowlisted']);self.assertTrue(value['funding_checks_passed'])
        self.assertEqual(value['external_weth_budget_wei'],str(self.base));self.assertEqual(value['challenge_path_bonds_wei'],[])
        self.assertFalse(value['challenge_sends_enabled']);self.assertFalse(value['activation_authorized'])
        self.assertTrue(all(params[-1]=='0x100' for method,params in self.calls if method in ('eth_call','eth_getBalance','eth_getCode')))
        self.listed=False;self.assertFalse(self.observe()['funding_checks_passed'])
        self.public=True;self.assertTrue(self.observe()['funding_checks_passed'])
        self.paused=True;self.assertFalse(self.observe()['funding_checks_passed'])

    def test_budget_eoa_and_protocol_changes_refuse_or_report_insufficient_funds(self):
        self.base=10**18+1;self.assertFalse(self.observe()['funding_checks_passed'])
        self.base=10**18;self.balance=0;self.assertFalse(self.observe()['funding_checks_passed'])
        self.balance=10**18;self.allowance=0;self.assertFalse(self.observe()['funding_checks_passed'])
        self.wallet_code='0xef0100'+'2'*40
        with self.assertRaises(ValueError):self.observe()
        self.wallet_code='0x'
        for method,value in [('rollup','0x'+'4'*40),('bridge','0x'+'4'*40),('chainId',1),('stakeToken','0x'+'4'*40),('assertionChain','0x'+'4'*40)]:
            self.changes={method:value}
            with self.assertRaises(ValueError):self.observe()

    def test_only_defensive_assertion_and_original_stake_payloads_can_cross_the_policy(self):
        observation=self.observe();call=self.assertion()
        self.assertEqual(transactions.payload(scope.ROLLUP,call,self.wallet,observation),'newStakeOnNewAssertion')
        for change in ({'admitted':False},{'strategy':'MakeNodes'},{'parent_chain_id':2},
                       {'network':'foreign'},{'is_staked':True},{'rollup_paused':True},{'funding_checks_passed':False}):
            with self.assertRaises(ValueError):transactions.payload(scope.ROLLUP,call,self.wallet,dict(observation,**change))
        for recipient in (scope.WETH,self.challenge,'0x4dceb440657f21083db8add07665f8ddbe1dcfc0'):
            with self.assertRaises(ValueError):transactions.payload(recipient,call,self.wallet,observation)
        # Canonical confirmation and challenge calldata decode, but Defensive
        # rejects their families even though MakeNodes uses the same ABI library.
        confirmation=encoded('10b98a35',[1,2]+[0]*6+[3,4,self.base,self.challenge,10,20,5])
        self.assertEqual(abi.decode(confirmation)[1],'confirmAssertion')
        with self.assertRaises(ValueError):transactions.payload(scope.ROLLUP,confirmation,self.wallet,observation)
        edge=encoded('05fae141',[32,0,1,10,2,192,256,2])+b'ab'+bytes(30)+word(3)+b'cde'+bytes(29)
        self.assertEqual(abi.decode(edge)[1],'createLayerZeroEdge')
        with self.assertRaises(ValueError):transactions.payload(self.challenge,edge,self.wallet,observation)
        for selector in ('d0e30db0','095ea7b3','a9059cbb','2e1a7d4d'):
            with self.assertRaises(ValueError):transactions.payload(scope.ROLLUP,encoded(selector,[0]*22),self.wallet,observation)

    def test_type2_chain_sender_and_maximum_gas_charge_are_checked_without_signing(self):
        observation=self.observe()
        integer=lambda value:value.to_bytes(32,'big').lstrip(b'\0')
        fields=[integer(scope.PARENT_ID),b'',b'\x01',b'\x02',b'\x01',bytes.fromhex(scope.ROLLUP[2:]),
                b'',self.assertion(),[],b'',b'\x01',b'\x01']
        encode=lambda value:'0x02'+rlp.encode(value).hex()
        with patch.object(crypto,'keccak',return_value=bytes(32)):
            self.assertEqual(transactions.signed(encode(fields),self.wallet,observation,lambda *_:self.wallet),'newStakeOnNewAssertion')
            with self.assertRaises(ValueError):transactions.signed(encode(fields),self.wallet,observation,lambda *_:'0x'+'2'*40)
            for index,value in [(0,integer(scope.PARENT_ID+1)),(6,b'\x01'),(8,[[bytes(20),[]]]),
                                (4,integer(transactions.MAX_GAS+1)),(3,integer(transactions.MAX_FEE_WEI+1))]:
                bad=list(fields);bad[index]=value
                with self.assertRaises(ValueError):transactions.signed(encode(bad),self.wallet,observation,lambda *_:self.wallet)
            with self.assertRaises(ValueError):transactions.signed(encode(fields),self.wallet,dict(observation,eth_balance_wei='1'),lambda *_:self.wallet)

    def test_actual_transport_enforces_defensive_policy_under_original_authority(self):
        integer=lambda value:value.to_bytes(32,'big').lstrip(b'\0')
        fields=[integer(scope.PARENT_ID),b'',b'\x01',b'\x02',b'\x01',bytes.fromhex(scope.ROLLUP[2:]),
                b'',self.assertion(),[],b'',b'\x01',b'\x01']
        encode=lambda value:'0x02'+rlp.encode(value).hex()
        held=[False];revoked=[False];sent=[]
        @contextmanager
        def authorize():
            if revoked[0]:raise ValueError('inert original generation revoked')
            held[0]=True
            try:yield
            finally:held[0]=False
        def endpoint(method,path='',body=None):
            request=json.loads(body);name=request['method']
            if name=='eth_sendRawTransaction':
                self.assertTrue(held[0]);sent.append(request)
                value='0x'+'a'*64
            else:value=self.rpc(name,request['params'])
            return {'jsonrpc':'2.0','id':request['id'],'result':value}
        inert=SimpleNamespace(tls=True,loopback=False,request=endpoint)
        with patch.object(upstreams,'Endpoint',return_value=inert),patch.object(transport.bounded,'Endpoint',return_value=inert):
            service=transport.Transport({'execution':{},'beacon':{}},self.wallet,'active',authorize)
        def body(value):return json.dumps({'jsonrpc':'2.0','id':7,'method':'eth_sendRawTransaction','params':[encode(value)]}).encode()
        real_signed=transactions.signed
        with patch.object(service,'verify'),patch.object(admission.time,'time',return_value=self.now),             patch.object(crypto,'keccak',return_value=bytes.fromhex('a'*64)),             patch.object(transactions,'signed',side_effect=lambda raw,wallet,observation:real_signed(raw,wallet,observation,lambda *_:self.wallet)):
            self.assertEqual(service.execution_request(body(fields))['result'],'0x'+'a'*64)
            self.assertEqual(len(sent),1);self.assertFalse(held[0])
            for changed in ('admission','funding','observer','revoked','confirmation'):
                self.listed=changed!='admission';self.allowance=0 if changed=='funding' else 10**18
                service.phase='observing' if changed=='observer' else 'active';revoked[0]=changed=='revoked'
                candidate=list(fields)
                if changed=='confirmation':candidate[7]=encoded('10b98a35',[1,2]+[0]*6+[3,4,self.base,self.challenge,10,20,5])
                with self.assertRaises((ValueError,upstreams.Rejected)):service.execution_request(body(candidate))
                self.assertEqual(len(sent),1);self.assertFalse(held[0])

    def test_external_preparation_does_not_request_challenge_allowance_or_broadcast(self):
        self.allowance=0;self.balance=0
        prepared=registration.prepare(self.observe())
        self.assertFalse(prepared['financial_action_performed']);self.assertFalse(prepared['total_lifetime_budget_cap'])
        self.assertEqual(len(prepared['approvals']),1)
        self.assertEqual(prepared['approvals'][0]['spender'],scope.ROLLUP)
        self.assertEqual(prepared['approvals'][0]['unsigned_transaction']['chainId'],hex(scope.PARENT_ID))
        self.assertFalse(prepared['challenge_sends_enabled'])
        self.assertTrue(all(method!='eth_sendRawTransaction' for method,_ in self.calls))


if __name__=='__main__':unittest.main()
