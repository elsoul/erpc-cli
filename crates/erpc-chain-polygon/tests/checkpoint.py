# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unsigned synthetic encoding fixtures; no transaction signing or submission."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
spec=importlib.util.spec_from_file_location('polygon_checkpoint',ROOT/'templates/scripts/checkpoint.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)


def number(value):return value.to_bytes((value.bit_length()+7)//8,'big')
def encode(value):
    if isinstance(value,int):value=number(value)
    if isinstance(value,list):data=b''.join(encode(item) for item in value);short,long=192,247
    else:
        data=value;short,long=128,183
        if len(data)==1 and data[0]<128:return data
    if len(data)<56:return bytes([short+len(data)])+data
    size=number(len(data));return bytes([long+len(size)])+size+data


class Checkpoint(unittest.TestCase):
    def setUp(self):
        self.signer='0x'+'ab'*20
        self.addCleanup(patch.stopall)
        self.recovery=patch.object(policy.signatures,'sender',return_value=self.signer).start()
        self.hash=patch.object(policy.signatures,'keccak',return_value=bytes(32)).start()
        word=lambda value:value.to_bytes(32,'big')
        # Inert dynamic data/signature words; no actual cryptographic signature.
        self.data=policy.SELECTOR+word(64)+word(128)+word(1)+b'x'+bytes(31)+word(1)+word(1)+word(2)+word(27)
        self.fields=[11155111,7,1000000000,10000000000,500000,
            bytes.fromhex(policy.CONTRACTS['amoy']['root'][2:]),0,self.data,[],0,1,2]
    def transaction(self,fields=None):return '0x'+(b'\x02'+encode(self.fields if fields is None else fields)).hex()
    def call(self,method,params):return policy.allow({'method':method,'params':params},'amoy',self.signer)
    def test_reviewed_native_parent_calls_are_forwardable_without_signing(self):
        self.call('eth_maxPriorityFeePerGas',[])
        self.call('eth_getTransactionCount',[self.signer,'pending'])
        for field in ('input','data'):
            self.call('eth_estimateGas',[{'from':self.signer,'to':policy.CONTRACTS['amoy']['root'],field:'0x'+self.data.hex()}])
        self.call('eth_sendRawTransaction',[self.transaction()])
        # Pinned helper/tx.go retains a zero suggested tip; its positive base
        # fee still produces a positive EIP-1559 fee cap. No signing occurs here.
        zero_tip=list(self.fields);zero_tip[2]=0
        self.call('eth_sendRawTransaction',[self.transaction(zero_tip)])
    def test_signature_is_bound_to_original_wallet_and_canonical_signing_payload(self):
        self.call('eth_sendRawTransaction',[self.transaction()])
        self.hash.assert_called_once_with(b'\x02'+encode(self.fields[:9]))
        self.recovery.assert_called_once_with(bytes(32),0,1,2)
        self.recovery.return_value='0x'+'cd'*20
        with self.assertRaisesRegex(ValueError,'original'):self.call('eth_sendRawTransaction',[self.transaction()])
        self.recovery.side_effect=ValueError('inert malformed public signature')
        with self.assertRaises(ValueError):self.call('eth_sendRawTransaction',[self.transaction()])
    def test_financial_owner_calls_and_other_networks_targets_values_are_refused(self):
        for method in ('eth_sendTransaction','eth_sign','personal_unlockAccount','eth_signTransaction'):
            with self.assertRaises(ValueError):self.call(method,[])
        for index,value in [(0,1),(5,bytes([19])*20),(6,1),(2,policy.TIP_CAP+1),
                (3,policy.FEE_CAP+1),(7,b'\x01'*len(self.data)),(8,[[bytes(20),[]]]),(9,2),(10,0),(11,0)]:
            fields=list(self.fields);fields[index]=value
            with self.assertRaises(ValueError):self.call('eth_sendRawTransaction',[self.transaction(fields)])
    def test_nonce_and_estimate_must_bind_the_dedicated_signer_and_checkpoint(self):
        with self.assertRaises(ValueError):self.call('eth_getTransactionCount',['0x'+'cd'*20,'pending'])
        with self.assertRaises(ValueError):self.call('eth_getTransactionCount',[self.signer,'latest'])
        base={'from':self.signer,'to':policy.CONTRACTS['amoy']['root'],'input':'0x'+self.data.hex()}
        for change in ({'value':'0x1'},{'to':'0x'+'cd'*20},{'from':'0x'+'cd'*20},
                {'data':'0x'+self.data.hex()},{'gas':'0x1'}):
            with self.assertRaises(ValueError):self.call('eth_estimateGas',[dict(base,**change)])
    def test_noncanonical_or_unbounded_signed_encoding_cannot_reach_parent(self):
        for raw in ('0x01','0x02','0x02c0','0x02b80101',self.transaction()+'00','0x'+('11'*(policy.MAX_BYTES+1))):
            with self.assertRaises(ValueError):self.call('eth_sendRawTransaction',[raw])
        fields=list(self.fields);fields[1]=b'\x00\x07'
        with self.assertRaises(ValueError):self.call('eth_sendRawTransaction',[self.transaction(fields)])
        for data in (self.data[:-1],self.data+b'\0',self.data[:4]+bytes(32)+self.data[36:]):
            with self.assertRaises(ValueError):policy.calldata(data)

if __name__=='__main__':unittest.main()
