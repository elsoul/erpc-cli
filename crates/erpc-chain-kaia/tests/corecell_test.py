# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public RPC observation shapes and immutable topology; no endpoints contacted."""
import copy
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
path=Path(__file__).parents[1]/'templates/node/corecell.py'
spec=importlib.util.spec_from_file_location('corecell',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Refused(Exception):pass
def require(value,message):
    if not value:raise Refused(message)
class CoreCell(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.process={'Id':'a'*64,'State':{'Running':True,'Pid':345,'StartedAt':'fixture'}}
        self.state={'storage':'full','node_kind':'cn','advertise':'10.1.2.1','peers':['kni://'+'a'*128+'@10.1.2.2:32323?discport=0&ntype=cn','kni://'+'b'*128+'@10.1.2.3:32323?discport=0&ntype=pn'],
            'reward_address':'0x'+'c'*40,'manager_address':'0x'+'d'*40,'staking_address':'0x'+'e'*40,'gc_id':'17',
            'custody_public':{'address':'0x'+'f'*40,'peer_key':'c'*128,'bls_key':'a'*96,'bls_pop':'b'*192}}
        own=self.state['custody_public']['address']
        self.replies={'eth_getBlockByNumber':{'hash':'0x'+'c'*64},'kaia_getCouncil':[own],
            'kaia_getStakingInfo':{'councilNodeAddrs':[own],'councilStakingAddrs':[self.state['staking_address']],
             'councilRewardAddrs':[self.state['reward_address']],'councilStakingAmounts':[5000000]},
            'kaia_getBlsInfos':{own:{'publicKey':'a'*96,'pop':'b'*192,'verifyErr':None}}}
        self.c=SimpleNamespace(require=require,Refused=Refused,check_container=lambda _:copy.deepcopy(self.process),owned_ports=lambda *_:True,rpc=self.rpc)
    def rpc(self,method,params):
        self.calls.append((method,params))
        if method=='eth_call':return '0x'+(format(17,'064x') if params[0]['data']=='0x6d2714db' else '0'*24+self.state['custody_public']['address'][2:])
        return copy.deepcopy(self.replies[method])
    def observe(self):
        def ipc(c,state,method,params):
            public=state['custody_public']
            if method=='admin_nodeInfo':return {'nodeAddress':public['address'],'blsPublicKeyInfo':{'publicKey':public['bls_key'],'pop':public['bls_pop']}}
            return [public['address']]
        with patch.object(m,'ipc',side_effect=ipc):return m.observe(self.c,self.state,{'ready':True,'block':'0x123'})
    def test_public_observer_uses_one_number_and_reports_registration_separately(self):
        report=self.observe();self.assertTrue(report['admission_observed']);self.assertTrue(report['staking_observed']);self.assertTrue(report['bls_observed'])
        self.assertEqual(report['reported_stake_kaia'],5000000)
        self.assertNotIn('eligible',report);self.assertNotIn('manager_verified',report)
        self.assertTrue(all((params[1] if method=='eth_call' else params[0])=='0x123' for method,params in self.calls))
        self.assertFalse(any('send' in method.lower() or 'sign' in method.lower() for method,_ in self.calls))
    def test_no_admission_claim_when_unsynced_or_proxy_and_no_rpc_calls(self):
        self.assertFalse(m.observe(self.c,self.state,{'ready':False})['admission_observed'])
        self.assertFalse(m.observe(self.c,dict(self.state,node_kind='pn'),{'ready':False})['admission_observed'])
        self.assertEqual(self.calls,[])
    def test_external_id_or_manager_metadata_cannot_substitute_for_chain_registration(self):
        self.replies['kaia_getCouncil']=[];self.replies['kaia_getBlsInfos']={}
        report=self.observe();self.assertFalse(report['admission_observed']);self.assertFalse(report['bls_observed'])
        self.assertEqual(report['manager_authority'],'external')
    def test_assigned_gc_id_is_verified_against_the_registered_staking_contract(self):
        report=self.observe();self.assertTrue(report['gc_id_observed']);self.assertEqual(report['onchain_gc_id'],'17')
        self.state['gc_id']='18';self.assertFalse(self.observe()['gc_id_observed'])
        original=self.rpc
        self.c.rpc=lambda method,params: '0x'+'a'*64 if method=='eth_call' and params[0]['data']=='0x139d7fed' else original(method,params)
        self.state['gc_id']='17';self.assertFalse(self.observe()['gc_id_observed'])

    def test_staking_mismatch_and_bls_errors_are_explicitly_not_qualified(self):
        self.replies['kaia_getStakingInfo']['councilRewardAddrs']=['0x'+'a'*40]
        own=self.state['custody_public']['address'];self.replies['kaia_getBlsInfos'][own]['verifyErr']='invalid proof'
        result=self.observe();self.assertFalse(result['staking_observed']);self.assertFalse(result['bls_observed'])
        self.replies['kaia_getBlsInfos'][own].pop('verifyErr')
        self.assertFalse(self.observe()['bls_observed'])
    def test_malformed_parallel_arrays_and_boolean_amounts_fail_closed(self):
        for replacement in ([],[True],[-1],[2**64]):
            self.replies['kaia_getStakingInfo']['councilStakingAmounts']=replacement
            with self.assertRaises(Refused):self.observe()
    def test_replaced_process_listener_or_canonical_block_cannot_authorize(self):
        for boundary in ('process','listener','block'):
            self.setUp()
            def changed(method,params):
                value=self.rpc(method,params)
                if method=='kaia_getBlsInfos':
                    if boundary=='process':self.process['State']['StartedAt']='replacement'
                    elif boundary=='listener':self.c.owned_ports=lambda *_:False
                    else:self.replies['eth_getBlockByNumber']['hash']='0x'+'d'*64
                return value
            self.c.rpc=changed
            with self.assertRaises(Refused):self.observe()
    def test_duplicate_casefolded_council_or_staking_identity_is_refused(self):
        own=self.state['custody_public']['address'];self.replies['kaia_getCouncil']=[own,'0x'+own[2:].upper()]
        with self.assertRaises(Refused):self.observe()
        self.replies['kaia_getCouncil']=[own]
        for key in self.replies['kaia_getStakingInfo']:self.replies['kaia_getStakingInfo'][key]*=2
        with self.assertRaises(Refused):self.observe()
    def test_topology_refuses_self_duplicate_and_implicit_administrative_fields(self):
        m.validate(self.c,self.state);m.configuration(self.c,self.state)
        self.state['custody_public']['peer_key']='a'*128
        with self.assertRaises(Refused):m.configuration(self.c,self.state)
        self.state['peers'][1]=self.state['peers'][0]
        with self.assertRaises(Refused):m.validate(self.c,self.state)
        self.setUp();self.state['node_kind']='pn'
        with self.assertRaises(Refused):m.validate(self.c,self.state)
        for key in ('reward_address','manager_address','staking_address'):self.state[key]=''
        self.state['gc_id']='0';m.validate(self.c,self.state)
    def test_gc_id_is_native_uint256_and_not_a_lossy_host_integer(self):
        for good in ('0','17',str(2**256-1)):
            self.state['gc_id']=good;m.validate(self.c,self.state)
        for bad in ('',True,17,'01','-1',str(2**256)):
            self.state['gc_id']=bad
            with self.assertRaises(Refused):m.validate(self.c,self.state)

class NativeIpc(unittest.TestCase):
    def exercise(self,peer=(345,995,995),reply=None,method='istanbul_getValidators'):
        import stat,struct
        sent=[];closed=[];container={'Id':'a'*64,'State':{'Running':True,'Pid':345,'StartedAt':'fixture'}}
        c=SimpleNamespace(require=require,Refused=Refused,ROOT=Path('/inert/kaia'),check_container=lambda _:container)
        state={'service_uid':995,'service_gid':995}
        metadata=SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=995,st_dev=1,st_ino=2)
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*_):closed.append(True)
            def settimeout(self,value):assert value==10
            def connect(self,path):assert path=='/inert/kaia/data/kaia.ipc'
            def getsockopt(self,*args):return struct.pack('3i',*peer)
            def sendall(self,value):sent.append(value)
            def recv(self,size):return reply if reply is not None else b'{"jsonrpc":"2.0","id":1,"result":[]}\n'
        with patch.object(Path,'lstat',return_value=metadata),patch.object(m.socket,'socket',return_value=Stream()) as create,patch.object(m.socket,'SO_PEERCRED',17,create=True):
            try:result=m.ipc(c,state,method,['0x123'])
            except Exception as error:return sent,closed,type(error),create.call_count
            return sent,closed,result,create.call_count
    def test_kernel_peer_scope_is_required_before_sending_any_native_request(self):
        for peer in ((346,995,995),(345,996,995),(345,995,996)):
            sent,closed,result,count=self.exercise(peer=peer)
            self.assertEqual(sent,[]);self.assertEqual(closed,[True]);self.assertIs(result,Refused)
        sent,closed,result,count=self.exercise()
        self.assertEqual(result,[]);self.assertEqual(closed,[True])
        self.assertIn(b'istanbul_getValidators',sent[0])
    def test_ipc_observer_cannot_invoke_governance_or_accept_ambiguous_response(self):
        sent,closed,result,count=self.exercise(method='istanbul_propose')
        self.assertEqual(count,0);self.assertEqual(sent,[]);self.assertIs(result,Refused)
        for value in (b'{"jsonrpc":"2.0","id":true,"result":[]}\n',b'{"jsonrpc":"2.0","id":1,"result":[],"result":[]}\n',b'{"jsonrpc":"2.0","id":1,"error":{}}\n'):
            self.assertIs(self.exercise(reply=value)[2],Refused)

if __name__=='__main__':unittest.main()
