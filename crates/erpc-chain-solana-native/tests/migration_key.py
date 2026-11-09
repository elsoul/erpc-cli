# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Complete public Vote snapshots and original FD qualification; no live keys."""
import base64
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_key as key
from custody import RAW, PUBLIC, EXPECTED


def pub(byte):return key.base58(bytes([byte])*32)


def row():
    return {'pubkey':pub(9),'account':{'owner':key.VOTE,'executable':False,'lamports':123,'space':3762,
        'data':{'program':'vote','space':3762,'parsed':{'type':'vote','info':{
            'nodePubkey':pub(2),'authorizedWithdrawer':pub(3),'blsPubkeyCompressed':'2'*66,
            'commission':5,'inflationRewardsCommissionBps':500,
            'authorizedVoters':[{'epoch':4,'authorizedVoter':pub(4)},{'epoch':9,'authorizedVoter':pub(5)}],
            'priorVoters':[{'authorizedPubkey':pub(6),'epochOfLastAuthorizedSwitch':1,'targetEpoch':2}]}}}}}


class Classification(unittest.TestCase):
    def setUp(self):self.rows=[row()];self.calls=[];self.time=1800000000;self.epochs=0;self.responses={}
    def call(self,network,method,params):
        self.calls.append((method,params))
        if method in self.responses:return self.responses[method]
        if method=='getGenesisHash':return key.legacy.GENESIS[network]
        if method=='getEpochInfo':self.epochs+=1;return {'epoch':8,'absoluteSlot':100 if self.epochs==1 else 120}
        if method=='getBlockTime':return self.time-1
        if method=='getProgramAccounts':return {'context':{'slot':110},'value':self.rows}
        raise AssertionError('unexpected nonreadonly method')
    def classify(self,candidate=EXPECTED):return key.classify('testnet',candidate,'3'*66,call=self.call,now=lambda:self.time)
    def test_complete_snapshot_excludes_every_current_future_and_reported_prior_role(self):
        result=self.classify();self.assertEqual(result['vote_accounts'],1)
        self.assertEqual(self.calls[2],('getProgramAccounts',[key.VOTE,{'commitment':'finalized','encoding':'jsonParsed','withContext':True,'minContextSlot':100}]))
        for candidate in [pub(v) for v in (2,3,4,5,6,9)]:
            self.epochs=0
            with self.subTest(candidate=candidate),self.assertRaises(ValueError):self.classify(candidate)
    def test_same_native_bls_key_is_excluded_even_when_ed25519_identity_differs(self):
        self.rows[0]['account']['data']['parsed']['info']['blsPubkeyCompressed']='3'*66
        with self.assertRaisesRegex(ValueError,'BLS voting'):self.classify()
        self.epochs=0;self.rows[0]['account']['data']['parsed']['info'].pop('blsPubkeyCompressed')
        with self.assertRaisesRegex(ValueError,'BLS authority metadata'):self.classify()

    def test_original_registered_commission_is_preserved_and_never_guessed(self):
        registered={'identity':pub(2),'vote_account':pub(9),'withdrawer':pub(3)}
        result=key.classify('testnet',EXPECTED,'3'*66,call=self.call,now=lambda:self.time,registered=registered)
        self.assertEqual(result['commission'],5)
        for field,value in [('nodePubkey',pub(7)),('authorizedWithdrawer',pub(7)),('inflationRewardsCommissionBps',501),('commission',False)]:
            self.rows=[row()];self.epochs=0;self.rows[0]['account']['data']['parsed']['info'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                key.classify('testnet',EXPECTED,'3'*66,call=self.call,now=lambda:self.time,registered=registered)
        self.rows=[row()];self.epochs=0;registered['vote_account']=pub(10)
        with self.assertRaisesRegex(ValueError,'absent'):
            key.classify('testnet',EXPECTED,'3'*66,call=self.call,now=lambda:self.time,registered=registered)

    def test_unknown_binary_owner_empty_and_truncated_snapshots_refuse(self):
        original=row()
        cases=[]
        changed=copy.deepcopy(original);changed['account']['owner']=pub(1);cases.append([changed])
        changed=copy.deepcopy(original);changed['account']['data']=['AAAAAQ==','base64'];cases.append([changed])
        changed=copy.deepcopy(original);del changed['account']['data']['parsed']['info']['authorizedWithdrawer'];cases.append([changed])
        cases.extend([[],[original,original]])
        for rows in cases:
            self.rows=rows;self.epochs=0
            with self.assertRaises(ValueError):self.classify()
        self.responses={'getProgramAccounts':[original]}
        with self.assertRaises(ValueError):self.classify()
    def test_only_known_completely_uninitialized_binary_forms_are_accepted(self):
        for size in (0,3731,3762):
            value=row();value['account']['space']=size;value['account']['data']=[base64.b64encode(bytes(size)).decode(),'base64']
            self.rows=[value];self.epochs=0;self.assertEqual(self.classify()['uninitialized_accounts'],1)
        self.rows[0]['account']['data']=[base64.b64encode(bytes(3761)+b'\1').decode(),'base64']
        with self.assertRaises(ValueError):self.classify()
    def test_disabled_rpc_stale_snapshot_and_epoch_change_prevent_classification(self):
        for response in ({'context':{'slot':90},'value':self.rows},{'error':'disabled'}):
            self.responses={'getProgramAccounts':response};self.epochs=0
            with self.assertRaises(ValueError):self.classify()
        self.responses={'getBlockTime':self.time-121};self.epochs=0
        with self.assertRaises(ValueError):self.classify()
        with self.assertRaises(OSError):key.classify('testnet',EXPECTED,call=lambda *_:(_ for _ in ()).throw(OSError('method disabled')))


@unittest.skipIf(os.name!='posix','original file descriptors require POSIX')
class OriginalFile(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(self.temp.name).resolve();self.home=self.root/'home/solv';self.home.mkdir(parents=True)
        (self.root/'proc').mkdir();(self.root/'proc/swaps').write_text('Filename\tType\tSize\tUsed\tPriority\n')
        patch.object(key.resource,'getrlimit',return_value=(0,0)).start()
        patch.object(key.runs,'other_runs_idle',lambda _:None).start()
        self.path=self.home/'unstaked-identity.json';self.path.write_bytes(RAW);self.path.chmod(0o600)
        self.request={'network':'testnet','role':'validator','identity_account':pub(1),'vote_account':pub(9)}
        self.real_lstat=Path.lstat;self.real_fstat=os.fstat;inode=self.path.stat().st_ino
        def metadata(info,path=None):
            values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            values['st_uid']=1001 if path==self.home or info.st_ino==inode else 0
            values['st_gid']=1101 if values['st_uid']==1001 else 0
            if path in self.root.parents:values['st_mode']&=~0o022
            return SimpleNamespace(**values)
        patch.object(key.legacy,'ROOT',self.root).start();patch.object(key.legacy,'validate',return_value={'uid':1001,'gid':1101}).start()
        patch.object(Path,'lstat',lambda p:metadata(self.real_lstat(p),p)).start()
        patch.object(os,'fstat',lambda fd:metadata(self.real_fstat(fd))).start()
    def test_actual_original_file_binding_and_seed_public_mismatch_fail_before_transport(self):
        record,material=key.material(self.request,derive=lambda seed:PUBLIC)
        self.assertEqual(record['public'],EXPECTED);self.assertEqual(record['path'],'/home/solv/unstaked-identity.json')
        self.assertEqual(bytes(material),bytes(json.loads(RAW)));material[:]=bytes(len(material))
        with self.assertRaisesRegex(ValueError,'halves'):key.material(self.request,derive=lambda seed:bytes(32))
        self.request['identity_account']=EXPECTED
        with self.assertRaisesRegex(ValueError,'eligible'):key.material(self.request,derive=lambda seed:PUBLIC)
    def test_memory_preflight_refuses_swap_or_core_before_reading_private_material(self):
        with patch.object(key.resource,'getrlimit',return_value=(1,1)),patch.object(key,'source') as source:
            with self.assertRaises(ValueError):key.material(self.request,derive=lambda seed:PUBLIC)
            source.assert_not_called()
        (self.root/'proc/swaps').write_text('Filename\tType\tSize\tUsed\tPriority\n/inert/swap file 1000 0 -2\n')
        with patch.object(key,'source') as source:
            with self.assertRaises(ValueError):key.material(self.request,derive=lambda seed:PUBLIC)
            source.assert_not_called()

    def test_symlink_hardlink_and_writable_original_key_are_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):key.material(self.request,derive=lambda seed:PUBLIC)
        self.path.chmod(0o600);other=self.home/'alias';os.link(self.path,other)
        with self.assertRaises(ValueError):key.material(self.request,derive=lambda seed:PUBLIC)
        other.unlink();self.path.rename(other);self.path.symlink_to(other.name)
        with self.assertRaises(ValueError):key.material(self.request,derive=lambda seed:PUBLIC)
    def test_public_preflight_has_no_private_result_and_refuses_before_return_on_rpc_failure(self):
        original=key.material
        def qualified(request):
            value,material=original(request,derive=lambda seed:PUBLIC)
            return dict(value,bls_public='3'*66),material
        with patch.object(key.legacy,'inspect',return_value={'source':'qualified'}), \
             patch.object(key,'qualified_material',side_effect=qualified), \
             patch.object(key,'classify',return_value={'scope':'inert public proof','bls_authority_checked':True}):
            result=key.inspect(self.request,pub(3));self.assertEqual(result['custody_source']['public'],EXPECTED)
            self.assertNotIn(RAW.decode(),json.dumps(result))
            with self.assertRaises(ValueError):key.inspect(self.request,EXPECTED)
        with patch.object(key.legacy,'inspect',side_effect=ValueError('source changed')),patch.object(key,'qualified_material') as material:
            with self.assertRaises(ValueError):key.inspect(self.request,pub(3))
            material.assert_not_called()


if __name__=='__main__':unittest.main()
