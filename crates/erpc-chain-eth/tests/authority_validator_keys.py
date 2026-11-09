# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual import orchestration and private filesystem publication, inert Lighthouse."""
import copy
import os
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_validator_runtime as fixtures
from authority_validator_custody import material
import eth_validator_keys as keys
import eth_validator_history as history
import eth_layout as layout
from eth_files import encoded


class Keys(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Runtime();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.c=self.f.c;self.plan=self.f.plan;self.base=self.f.f
        self.data=self.base.root/'data';self.base.install(layout,'ROOTS',{'validator':self.data});layout.prepare(self.state,self.c,self.plan)
        self.base.install(keys.health,'readiness',lambda *_:{'ready':True});self.base.install(keys.health,'validator',lambda *_:None)
        self.calls=[];self.history_value={'metadata':{'interchange_format_version':'5','genesis_validators_root':keys.custody.ROOTS[self.c['network']]},
            'data':[{'pubkey':'0x'+'1'*96,'signed_blocks':[],'signed_attestations':[]}]}
        self.fail_password=False
        def crypto(argv,input_data):
            if argv[1]=='encrypt':return b'inert signer capsule:'+input_data
            self.assertTrue(input_data.startswith(b'inert signer capsule:'));return input_data.split(b':',1)[1]
        self.base.install(keys.custody,'run',crypto);self.base.install(keys.native,'worker',self.native)

    def own(self,path,directory=False):
        if directory:path.mkdir(mode=0o700,parents=True,exist_ok=True)
        else:path.chmod(0o600)
        account=self.plan['users']['ev-validator'];info=path.stat();fixtures.fixtures.hold(self,path)
        self.f.owners[(info.st_dev,info.st_ino)]=(account['uid'],account['gid'])

    def native(self,argv,identity=None,**_):
        self.calls.append(argv);self.assertEqual(identity,self.plan['users']['ev-validator'])
        data=Path(argv[argv.index('--datadir')+1])
        if 'slashing-protection' not in argv:
            self.assertIn('import',argv);self.assertIn('--password-file',argv)
            self.assertTrue(str(data).startswith(str(keys.native.RUN)))
            self.own(data,True);self.own(data/'validators',True)
            temporary=data/'validators'/'validator_definitions.yml';temporary.write_bytes(b'inert native inline password');self.own(temporary)
            if self.fail_password:raise ValueError('inert native password verification failure')
        elif 'import' in argv:
            self.assertEqual(data,self.data/'vc');self.own(data/'validators',True)
            db=data/'validators'/history.DATABASE
            if not db.exists():db.write_bytes(b'SQLite format 3\0'+bytes(4096-16));self.own(db)
        else:
            self.assertIn('--pubkeys',argv);output=Path(argv[argv.index('export')+1]);output.write_bytes(encoded(self.history_value));self.own(output)
        return b''

    def request(self,password=None):
        value=material()
        if password is not None:value['password']=password
        return {'material':dict(value,history=copy.deepcopy(self.history_value)),'new_key':True}

    def imported(self):return keys.import_key(self.state,self.c,self.request(),Path('/inert/lighthouse'),lambda:None)

    def test_real_orchestration_never_places_native_inline_password_in_the_persistent_datadir(self):
        result=self.imported();self.assertFalse(result['signing_started']);self.assertEqual(result['pubkey'],'0x'+'1'*96)
        config=(self.data/'vc/validators/validator_definitions.yml').read_text()
        self.assertIn('voting_keystore_password_path',config);self.assertNotIn(material()['password'],config)
        self.assertNotIn('"voting_keystore_password":',config)
        definitions=self.data/'vc/validators/validator_definitions.yml';info=definitions.stat()
        self.assertEqual(info.st_mode&0o777,0o600)
        self.assertEqual(self.f.owners[(info.st_dev,info.st_ino)],tuple(self.plan['users']['ev-validator'].values()))
        self.assertEqual(list((keys.native.RUN/'custody').iterdir()),[])
        self.assertTrue(self.state.exists('signer-custody.json'));self.assertTrue(self.state.exists('signer-history.json'))
        before=len(self.calls);self.imported();self.assertEqual(len(self.calls),before)
        self.assertFalse(keys.permission(self.state,self.c)['enabled'])

    def test_wrong_password_can_be_corrected_before_original_seal_without_changing_key_or_history(self):
        self.fail_password=True
        with self.assertRaises(ValueError):keys.import_key(self.state,self.c,self.request('inert typo'),Path('/inert/lighthouse'),lambda:None)
        self.assertFalse(self.state.exists('signer-custody.json'));self.assertFalse((self.data/'vc/validators').exists())
        self.assertEqual(list((keys.native.RUN/'custody').iterdir()),[])
        self.fail_password=False;self.imported();self.assertTrue(self.state.exists('signer-custody.json'))

    def test_invalid_envelope_can_be_corrected_only_for_the_same_key_before_seal(self):
        self.fail_password=True
        with self.assertRaises(ValueError):self.imported()
        corrected=self.request();corrected['material']['keystore']['crypto']['cipher']['message']='1'*64
        self.fail_password=False
        keys.import_key(self.state,self.c,corrected,Path('/inert/lighthouse'),lambda:None)
        self.assertTrue(self.state.exists('signer-custody.json'))
        with self.assertRaises(ValueError):self.imported()
        self.assertEqual(self.state.get('signer-import.json')['phase'],'complete')

    def test_missing_established_history_is_never_recreated_by_original_input_retry(self):
        self.imported();database=self.data/'vc/validators'/history.DATABASE;database.unlink();before=len(self.calls)
        with self.assertRaises(FileNotFoundError):self.imported()
        self.assertEqual(len(self.calls),before);self.assertFalse(database.exists())

    def test_changed_key_or_existing_unowned_native_data_refuses_before_private_worker(self):
        path=self.data/'vc'/'unowned';path.write_bytes(b'inert original unknown data')
        with self.assertRaises(ValueError):self.imported()
        self.assertEqual(self.calls,[]);self.assertEqual(path.read_bytes(),b'inert original unknown data');path.unlink()
        self.imported();before=len(self.calls);request=self.request();request['material']['keystore']['pubkey']='2'*96
        with self.assertRaises(ValueError):keys.import_key(self.state,self.c,request,Path('/inert/lighthouse'),lambda:None)
        self.assertEqual(len(self.calls),before)

    def test_original_encrypted_backup_restores_cipher_only_and_preserves_history_and_signer_fence(self):
        self.imported();backup=keys.encrypted_backup(self.state,self.c)
        self.assertNotIn(material()['password'],str(backup));self.assertEqual(set(backup),{'schema','contract','pubkey','ciphertext'})
        original=self.state.get('signer-custody.json');native=self.state.get('signer-history.json')
        keys.cancel(self.state,self.c,True);permission=keys.permission(self.state,self.c)
        self.state.path('signer-original.cred').write_bytes(b'inert corrupt ciphertext')
        stops=[]
        result=keys.restore_backup(self.state,self.c,backup,lambda:stops.append(True))
        self.assertTrue(result['restored']);self.assertFalse(result['signing_started']);self.assertTrue(stops)
        self.assertEqual(self.state.get('signer-custody.json'),original)
        self.assertEqual(self.state.get('signer-history.json'),native)
        self.assertEqual(keys.permission(self.state,self.c),permission)
        before=len(stops);wrong=copy.deepcopy(backup);wrong['contract']['owner']='foreign'
        with self.assertRaises(ValueError):keys.restore_backup(self.state,self.c,wrong,lambda:stops.append(True))
        self.assertEqual(len(stops),before)

    def test_original_history_uses_volume_and_inodes_across_kernel_device_renumbering(self):
        from unittest.mock import patch
        self.imported();record=self.state.get('signer-history.json');original=os.fstat
        inodes={fixtures.fixtures.held(self,path) for path in [self.data,*self.data.rglob('*')]}
        def changed(fd):
            value=list(original(fd))
            if (value[2],value[1]) in inodes:value[2]+=100
            return os.stat_result(value)
        with patch.object(os,'fstat',side_effect=changed):
            self.assertEqual(history.verify_identity(self.state,self.c,self.plan,'0x'+'1'*96),record)
            with patch.object(history.layout,'probe',return_value={'uuid':'22345678-1234-1234-1234-123456789abc','type':'ext4','root':'/'}):
                with self.assertRaises(ValueError):history.verify_identity(self.state,self.c,self.plan,'0x'+'1'*96)
        self.assertEqual(self.state.get('signer-history.json'),record)
        database=self.data/'vc/validators'/history.DATABASE;database.rename(database.with_suffix('.original'))
        database.write_bytes(b'SQLite format 3\0'+bytes(4096-16));self.own(database)
        with self.assertRaises(ValueError):history.verify_identity(self.state,self.c,self.plan,'0x'+'1'*96)

    def key(self,path):info=path.stat();return (info.st_dev,info.st_ino)

    def test_slashing_database_of_another_owner_or_group_is_never_the_original_history(self):
        self.imported();database=self.data/'vc/validators'/history.DATABASE;key=self.key(database);owner=self.f.owners[key]
        record=self.state.path('signer-history.json').read_bytes();before=len(self.calls)
        refused='managed file is indirect, shared, foreign or has unsafe permissions'
        for value,message in [((77,owner[1]),refused),((0,owner[1]),refused),
                              ((owner[0],77),'original native slashing DB ownership, size or filesystem differs')]:
            with self.subTest(owner=value):
                self.f.owners[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,message):self.imported()
                finally:self.f.owners[key]=owner
                self.assertEqual(len(self.calls),before);self.assertEqual(self.state.path('signer-history.json').read_bytes(),record)
        self.assertEqual(self.imported()['state'],'imported');self.assertEqual(len(self.calls),before)

    def test_validators_directory_of_another_owner_never_receives_signer_definitions(self):
        from unittest.mock import patch
        validators=self.data/'vc/validators';account=self.plan['users']['ev-validator'];changes=[(77,account['gid']),(account['uid'],77)]
        def native(argv,identity=None,**kwargs):
            result=self.native(argv,identity=identity,**kwargs)
            if 'slashing-protection' in argv and 'import' in argv and changes:self.f.owners[self.key(validators)]=changes.pop(0)
            return result
        with patch.object(keys.native,'worker',side_effect=native):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError,'original validators directory differs'):self.imported()
                self.assertEqual([path.name for path in validators.iterdir()],[history.DATABASE])
                self.assertFalse(self.state.exists('signer-definition.json'))
                self.assertNotEqual(self.state.get('signer-import.json')['phase'],'complete')
            self.assertEqual(self.imported()['state'],'imported')
        names=sorted(path.name for path in validators.iterdir())
        self.assertEqual(names,sorted([history.DATABASE,'original-keystore.json','validator_definitions.yml']))

    def test_private_stage_of_another_owner_is_kept_instead_of_emptied(self):
        from unittest.mock import patch
        stages=[]
        def native(argv,identity=None,**kwargs):
            result=self.native(argv,identity=identity,**kwargs)
            if 'slashing-protection' not in argv:
                stage=Path(argv[argv.index('--datadir')+1]).parent;stages.append(stage);self.f.owners[self.key(stage)]=(77,identity['gid'])
            return result
        with patch.object(keys.native,'worker',side_effect=native):
            with self.assertRaisesRegex(ValueError,'private stage owner differs'):self.imported()
        stage,=stages;self.assertEqual(list((keys.native.RUN/'custody').iterdir()),[stage])
        self.assertLessEqual({'keystore.json','password','history.json'},{path.name for path in stage.iterdir()})

    def test_native_export_may_minimize_rows_but_never_regress_known_signing_bounds(self):
        self.imported();value=copy.deepcopy(self.history_value)
        value['data'][0]['signed_attestations']=[{'source_epoch':'40','target_epoch':'42','signing_root':None}]
        history.observe(self.state,self.c,self.plan,'0x'+'1'*96,value)
        value['data'][0]['signed_attestations']=[{'source_epoch':'41','target_epoch':'43'}]
        history.observe(self.state,self.c,self.plan,'0x'+'1'*96,value)
        value['data'][0]['signed_attestations']=[]
        with self.assertRaises(ValueError):history.observe(self.state,self.c,self.plan,'0x'+'1'*96,value)


if __name__=='__main__':unittest.main()
