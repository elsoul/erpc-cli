# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Independent retained account input and stock native-profile qualification."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
from authority_validator_custody import material
import eth_validator_migration as migration
try:import yaml
except ImportError:yaml=None


class Original(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Accounts();self.f.setUp();self.addCleanup(self.f.doCleanups)
        plan=fixtures.accounts.provision(self.f.state,'validator');self.plan=plan
        del self.f.users['ev-transport'];del self.f.groups['ev-transport']
        self.f.groups['ev-reth'].gr_mem=[]
        selected={'groups':{key:value for key,value in plan['groups'].items() if key!='ev-transport'},
                  'users':{name:dict(plan['users'][name],home='/home/'+name,shell='/usr/sbin/nologin') for name in migration.OLD_USERS}}
        for name,value in selected['users'].items():self.f.users[name].pw_dir=value['home']
        self.proof={'schema':1,'contract':self.f.c,'machine':'b'*64,'legacy_accounts':selected,'signer_pubkey':'',
                    'records':dict.fromkeys(('passwd','group','machine','opened_sources'),'a'*64),
                    'opened_sources':{'reth':{'version':'v2.8.1','commit':'c'*40},'lighthouse':{'version':'v8.3.2','commit':'d'*40}}}
        self.f.install(migration.custody,'machine',lambda:'b'*64)

    def test_original_numeric_users_and_homes_are_kept_and_only_transport_gets_a_new_reservation(self):
        before=len(self.f.calls);migration.evidence(self.proof,self.f.c);plan=migration.new_plan(self.proof)
        self.assertEqual(len(self.f.calls),before)
        for name in migration.OLD_USERS:
            self.assertEqual(plan['users'][name],self.plan['users'][name]);self.assertEqual(plan['homes'][name],'/home/'+name)
        self.assertEqual(plan['homes']['ev-transport'],'/nonexistent')
        migration.original_identities(self.proof,plan)
        self.f.users['ev-validator'].pw_uid=100
        with self.assertRaises(ValueError):migration.original_identities(self.proof,plan)
        self.assertEqual(len(self.f.calls),before)

    def test_unknown_transport_and_lost_original_identity_are_never_recreated(self):
        original=self.f.users.pop('ev-validator')
        with self.assertRaises(ValueError):migration.new_plan(self.proof)
        self.f.users['ev-validator']=original
        self.f.users['ev-transport']=copy.copy(original);self.f.users['ev-transport'].pw_name='ev-transport'
        with self.assertRaises(ValueError):migration.new_plan(self.proof)

    def test_other_network_machine_or_history_schema_cannot_claim_the_originals(self):
        for key,value in [('schema',True),('machine','f'*64),('contract',dict(self.f.c,owner='foreign'))]:
            wrong=dict(self.proof,**{key:value})
            with self.assertRaises(ValueError):migration.evidence(wrong,self.f.c)
        wrong=copy.deepcopy(self.proof);wrong['opened_sources']['lighthouse']['version']='v8.3.2-unknown'
        with self.assertRaises(ValueError):migration.evidence(wrong,self.f.c)

    @unittest.skipUnless(yaml,'exact YAML interpretation runs in the pinned Ansible environment')
    def test_only_stock_single_local_signer_definitions_are_converted(self):
        secret=material();pubkey='0x'+secret['keystore']['pubkey']
        path=migration.layout.ROOTS['validator']/'vc/validators'/pubkey/'keystore.json'
        row={'enabled':True,'voting_public_key':pubkey,'type':'local_keystore','voting_keystore_path':str(path),
             'voting_keystore_password':secret['password'],'description':''}
        self.assertEqual(migration.native_definitions(json.dumps([row]).encode(),secret,pubkey),[row])
        for key,value in [('type','web3signer'),('enabled',False),('gas_limit',100),('graffiti','custom'),
                          ('voting_keystore_password_path','/another/password'),('voting_public_key','0x'+'2'*96)]:
            changed=dict(row,**{key:value})
            with self.assertRaises(ValueError):migration.native_definitions(json.dumps([changed]).encode(),secret,pubkey)
        with self.assertRaises(ValueError):migration.native_definitions(json.dumps([row,row]).encode(),secret,pubkey)
        with self.assertRaises(ValueError):migration.native_definitions(b'- enabled: true\n  enabled: false\n',secret,pubkey)


@unittest.skipUnless(yaml,'full stock YAML conversion runs with the pinned Ansible runtime')
class Conversion(unittest.TestCase):
    def setUp(self):
        import hashlib,os,shutil
        from authority_validator_keys import Keys
        import eth_validator_engine as engine
        self.k=Keys();self.k.setUp();self.addCleanup(self.k.doCleanups);self.k.imported()
        self.f=self.k.base;self.s=self.k.state;self.c=self.k.c;self.plan=self.k.plan;self.root=self.k.data
        self.original_db=(self.root/'vc/validators/slashing_protection.sqlite').read_bytes()
        self.original_inode=(self.root/'vc/validators/slashing_protection.sqlite').stat().st_ino
        for file in self.s.directory.iterdir():file.unlink()
        import eth_validator_runtime as runtime
        shutil.rmtree(runtime.native.RUN)
        retained={(path.stat().st_dev,path.stat().st_ino) for path in self.root.rglob('*')}
        self.k.f.owners={key:value for key,value in self.k.f.owners.items() if key in retained}
        del self.f.users['ev-transport'];del self.f.groups['ev-transport'];self.f.groups['ev-reth'].gr_mem=[]
        selected={'groups':{name:gid for name,gid in self.plan['groups'].items() if name!='ev-transport'},
                  'users':{name:dict(self.plan['users'][name],home='/home/'+name,shell='/usr/sbin/nologin') for name in migration.OLD_USERS}}
        for name,identity in selected['users'].items():self.f.users[name].pw_dir=identity['home']
        self.proof={'schema':1,'contract':self.c,'machine':'b'*64,'legacy_accounts':selected,'signer_pubkey':'0x'+'1'*96,
                    'records':dict.fromkeys(('passwd','group','machine','opened_sources'),'a'*64),
                    'opened_sources':{'reth':{'version':'v2.8.1','commit':'c'*40},'lighthouse':{'version':'v8.3.2','commit':'d'*40}}}
        self.pubkey=self.proof['signer_pubkey'];self.material=dict(material(),history=self.k.history_value)
        original={'owner':self.c['owner'],'network':self.c['network'],'state':'imported','pubkey':self.pubkey,
                  'material_digest':hashlib.sha256(json.dumps(self.material,sort_keys=True).encode()).hexdigest()}
        def root_file(path,raw,mode=0o600):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
        self.root_file=root_file
        root_file(self.root/'owner.json',json.dumps(original).encode())
        root_file(self.root/'custody.json',json.dumps(self.material).encode())
        folder=self.root/'vc/validators'/self.pubkey;self.k.own(folder,True)
        old=self.root/'vc/validators/original-keystore.json';old.rename(folder/'keystore.json');self.k.own(folder/'keystore.json')
        definitions=[{'enabled':True,'voting_public_key':self.pubkey,'type':'local_keystore',
                      'voting_keystore_path':str(folder/'keystore.json'),'voting_keystore_password':self.material['password'],'description':''}]
        self.definition=self.root/'vc/validators/validator_definitions.yml';self.definition.write_bytes(json.dumps(definitions).encode());self.k.own(self.definition)
        profiles=copy.deepcopy(migration.namespace.PROFILES)
        for name in ('config','opt','helpers'):profiles['validator'][name]=self.f.root/name
        self.f.install(migration.namespace,'PROFILES',profiles)
        system=self.f.root/'systemd';system.mkdir();self.f.install(migration.namespace,'SYSTEMD',system)
        self.f.install(migration,'CONFIG',self.f.root/'legacy-config.json');self.f.install(migration,'CONTROL',self.f.root/'legacy-control')
        self.f.install(migration,'JWT',self.f.root/'legacy-jwt');self.f.install(migration.layout,'topology',lambda _:None)
        pair=profiles['validator']['opt']/'reth-v2.8.1--lighthouse-v8.3.2';pair.mkdir(parents=True)
        root_file(pair/'.verified',('c'*40+' '+'d'*40).encode(),0o644)
        config={'owner':self.c['owner'],'network':self.c['network'],'fee_recipient':'0x'+'2'*40,'pair':str(pair)}
        root_file(migration.CONFIG,json.dumps(config).encode(),0o644)
        self.templates=Path(__file__).parents[1]/'templates/validator'
        root_file(migration.CONTROL,(self.templates/'control.py').read_bytes(),0o755)
        for name,text in migration.known_definitions(config,self.templates).items():root_file(system/name,text.encode(),0o644)
        root_file(migration.JWT,b'1'*64,0o640);entry=migration.JWT.stat();fixtures.hold(self,migration.JWT)
        self.k.f.owners[(entry.st_dev,entry.st_ino)]=(0,selected['groups']['ev-engine'])
        previous=os.lstat;scan=os.scandir
        def metadata(path,*args,**kwargs):
            value=list(previous(path,*args,**kwargs));value[4],value[5]=self.k.f.owners.get((value[2],value[1]),(0,0))
            if Path(path) in self.f.root.parents:value[0]&=~0o022
            return os.stat_result(value)
        self.f.install(os,'lstat',metadata);self.f.install(Path,'lstat',lambda path:metadata(path))
        class Entry:
            def __init__(self,original):self.original=original
            def __getattr__(self,name):return getattr(self.original,name)
            def stat(self,*,follow_symlinks=True):return metadata(self.original.path)
        class Entries(list):
            def __enter__(self):return self
            def __exit__(self,*_):return False
        def entries(path):
            with scan(path) as values:return Entries(Entry(value) for value in values)
        self.f.install(os,'scandir',entries)
        self.f.install(migration.processes,'quiescent',lambda *_:None);self.f.install(migration,'no_loaded_old_helper',lambda:None)
        def crypto(argv,input_data=None,**_):
            self.assertEqual(argv[0],'/usr/bin/systemd-creds');prefix=('inert '+next(v for v in argv if v.startswith('--name='))+':').encode()
            if argv[1]=='encrypt':return prefix+input_data
            self.assertTrue(input_data.startswith(prefix));return input_data[len(prefix):]
        import eth_files
        self.f.install(engine,'run',crypto);self.f.install(migration.custody,'run',crypto);self.f.install(eth_files,'run',crypto)
        self.calls=[]

    def run_native(self,argv,**_):
        self.calls.append(argv)
        if argv[1]=='daemon-reload':return b''
        self.assertEqual(argv[1],'show');path=migration.namespace.SYSTEMD/argv[2]
        return ('LoadState='+('masked' if path.is_symlink() else 'loaded')+'\nActiveState=inactive\nMainPID=0\n').encode()

    def migrate(self):return migration.migrate(self.s,self.c,self.proof,self.templates,self.run_native)

    def key(self,path):info=path.stat();return (info.st_dev,info.st_ino)

    def test_legacy_signer_material_or_data_of_another_account_refuses_before_the_journal(self):
        owners=self.k.f.owners;account=self.plan['users']['ev-validator'];folder=self.root/'vc/validators'/self.pubkey
        beacon=self.plan['users']['ev-beacon'];helper=migration.CONTROL.read_bytes()
        refused='managed file is indirect, shared, foreign or has unsafe permissions';directory='legacy native directory ownership differs'
        child='legacy data child differs from its original numeric account';keystore=folder/'keystore.json'
        for name,path,value,message in [('key directory',folder,(77,account['gid']),directory),
                                        ('key directory',folder,(account['uid'],77),directory),
                                        ('keystore',keystore,(77,account['gid']),refused),('keystore',keystore,(0,account['gid']),refused),
                                        ('keystore',keystore,(account['uid'],77),'legacy private native member differs'),
                                        ('beacon data',self.root/'beacon',(77,beacon['gid']),child),
                                        ('beacon data',self.root/'beacon',(beacon['uid'],77),child),
                                        ('reth data',self.root/'reth',(beacon['uid'],beacon['gid']),child)]:
            with self.subTest(name,owner=value):
                key=self.key(path);owner=owners[key];owners[key]=value;self.calls.clear()
                try:
                    with self.assertRaisesRegex(ValueError,message):self.migrate()
                finally:owners[key]=owner
                self.assertFalse(self.s.exists('owner.json'));self.assertFalse(self.s.exists('legacy-migration.json'))
                self.assertTrue(all(row[1]=='show' for row in self.calls));self.assertEqual(migration.CONTROL.read_bytes(),helper)
                self.assertTrue((self.root/'custody.json').exists());self.assertTrue(self.definition.exists())
        self.assertTrue(self.migrate()['migrated'])

    def test_legacy_engine_secret_of_another_group_is_never_adopted(self):
        owners=self.k.f.owners;key=self.key(migration.JWT);owner=owners[key];raw=migration.JWT.read_bytes()
        for gid in (77,self.plan['groups']['ev-validator']):
            with self.subTest(gid=gid):
                owners[key]=(0,gid)
                try:
                    with self.assertRaisesRegex(ValueError,'legacy original Engine group differs'):self.migrate()
                finally:owners[key]=owner
                self.assertEqual(migration.JWT.read_bytes(),raw)
                self.assertFalse(self.s.exists('engine-original-intent.json'));self.assertFalse(self.s.exists('engine-original.json'))
        self.assertTrue(self.migrate()['migrated']);self.assertFalse(migration.JWT.exists())

    def test_resumed_conversion_rebinds_only_the_original_signing_directory_and_database(self):
        import os
        from unittest.mock import patch
        with patch.object(migration,'no_loaded_old_helper',side_effect=ValueError('inert old helper still loaded')):
            with self.assertRaises(ValueError):self.migrate()
        owners=self.k.f.owners;account=self.plan['users']['ev-validator'];validators=self.root/'vc/validators'
        database=validators/'slashing_protection.sqlite';changed=[];actual=os.fchown
        def recorded(fd,uid,gid):info=os.fstat(fd);changed.append((info.st_dev,info.st_ino));actual(fd,uid,gid)
        directory='original legacy signer directory differs'
        for path,value,message in [(validators,(77,account['gid']),directory),(validators,(account['uid'],77),directory),
                                   (database,(77,account['gid']),'managed file is indirect, shared, foreign or has unsafe permissions'),
                                   (database,(account['uid'],77),'original legacy slashing DB is unavailable')]:
            with self.subTest(path=path.name,owner=value):
                key=self.key(path);owner=owners[key];owners[key]=value
                try:
                    with patch.object(os,'fchown',side_effect=recorded),self.assertRaisesRegex(ValueError,message):self.migrate()
                finally:owners[key]=owner
                self.assertNotIn(self.key(validators),changed);self.assertNotIn(self.key(database),changed)
                self.assertEqual(database.read_bytes(),self.original_db);self.assertFalse(self.s.exists('legacy-signer.json'))
        self.assertTrue(self.migrate()['migrated'])

    def test_signing_directory_or_database_changed_after_its_binding_is_never_normalized(self):
        from unittest.mock import patch
        owners=self.k.f.owners;account=self.plan['users']['ev-validator'];validators=self.root/'vc/validators'
        database=validators/'slashing_protection.sqlite';actual=migration.normalize_database
        refused='managed file is indirect, shared, foreign or has unsafe permissions';directory='legacy signing directory is not the original private directory'
        for path,value,message in [(validators,(77,account['gid']),directory),(validators,(account['uid'],77),directory),
                                   (database,(77,account['gid']),refused),(database,(0,account['gid']),refused),
                                   (database,(account['uid'],77),'legacy original slashing DB is missing or incompatible')]:
            with self.subTest(path=path.name,owner=value):
                key=self.key(path);owner=owners[key]
                # The binding was proved; the object changes before normalization.
                def changed(*args,key=key,value=value):owners[key]=value;return actual(*args)
                try:
                    with patch.object(migration,'normalize_database',side_effect=changed),self.assertRaisesRegex(ValueError,message):self.migrate()
                    self.assertEqual(owners[key],value)
                finally:owners[key]=owner
                self.assertEqual(database.read_bytes(),self.original_db);self.assertEqual(database.stat().st_ino,self.original_inode)
                self.assertFalse(self.s.exists('legacy-signer.json'))
        self.assertTrue(self.migrate()['migrated'])

    def test_actual_conversion_preserves_native_db_and_original_ids_and_disables_legacy_entrypoint(self):
        self.assertFalse(migration.preflight(self.s,self.c,self.proof,self.templates,self.run_native)['already'])
        result=self.migrate();self.assertTrue(result['migrated']);self.assertFalse(result['signing_started'])
        self.assertTrue(migration.CONTROL.is_dir());self.assertEqual(list(migration.CONTROL.iterdir()),[])
        self.assertFalse((self.root/'custody.json').exists());self.assertFalse(self.definition.exists());self.assertFalse(migration.JWT.exists())
        database=self.root/'vc/validators/slashing_protection.sqlite'
        self.assertEqual(database.read_bytes(),self.original_db);self.assertEqual(database.stat().st_ino,self.original_inode)
        self.assertEqual(self.s.get('signer-import.json')['phase'],'legacy');self.assertFalse(self.s.exists('signer-history.json'))
        plan=self.s.get('accounts.json')
        for name in migration.OLD_USERS:self.assertEqual(plan['users'][name],self.plan['users'][name]);self.assertEqual(plan['homes'][name],'/home/'+name)
        self.assertTrue(migration.preflight(self.s,self.c,self.proof,self.templates,self.run_native)['already'])
        self.assertTrue(self.migrate()['already']);self.assertFalse(any(row[1] in ('start','enable') for row in self.calls))

    def test_interruption_after_legacy_fence_resumes_through_actual_preflight(self):
        from unittest.mock import patch
        with patch.object(migration,'no_loaded_old_helper',side_effect=ValueError('inert old helper still loaded')):
            with self.assertRaises(ValueError):self.migrate()
        self.assertTrue(migration.CONTROL.is_dir());self.assertTrue((self.root/'custody.json').exists())
        self.assertFalse(migration.preflight(self.s,self.c,self.proof,self.templates,self.run_native)['already'])
        self.assertTrue(self.migrate()['migrated'])

    def test_interrupted_conversion_keeps_same_native_history_after_device_renumbering(self):
        import os
        from unittest.mock import patch
        with patch.object(migration,'no_loaded_old_helper',side_effect=ValueError('inert previous helper still loaded')):
            with self.assertRaises(ValueError):self.migrate()
        journal=self.s.path('legacy-migration.json').read_bytes();actual=os.fstat
        inodes={fixtures.held(self,path) for path in [self.root,*self.root.rglob('*')]}
        def changed(fd):
            value=list(actual(fd))
            if (value[2],value[1]) in inodes:value[2]+=100
            return os.stat_result(value)
        with patch.object(os,'fstat',side_effect=changed):
            self.assertFalse(migration.preflight(self.s,self.c,self.proof,self.templates,self.run_native)['already'])
            self.assertTrue(self.migrate()['migrated'])
        self.assertEqual(self.s.path('legacy-migration.json').read_bytes(),journal)
        self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').read_bytes(),self.original_db)
        self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').stat().st_ino,self.original_inode)

    def test_qualified_conversion_uses_live_export_and_never_reimports_initial_history(self):
        import eth_validator_keys as keys
        self.migrate();plan=self.s.get('accounts.json')
        source={'pair':'reth-v2.8.1--lighthouse-v8.3.2','reth_commit':'c'*40,'lighthouse_commit':'d'*40,
                'reth_archive':'1'*64,'lighthouse_archive':'2'*64}
        images={'reth':{'sha256':'3'*64},'lighthouse':{'sha256':'4'*64}}
        self.s.authorize(self.c,'e'*32,source,'deploy');self.s.begin(self.c,'e'*32,lambda:None)
        migration.floor.authorize(self.s,self.c,plan,source,images,('lighthouse',))
        self.k.history_value=copy.deepcopy(self.k.history_value)
        self.k.history_value['data'][0]['signed_blocks']=[{'slot':'120','signing_root':None}]
        before=len(self.k.calls)
        self.assertTrue(keys.finish_legacy(self.s,self.c,Path('/inert/lighthouse'),lambda:None))
        self.assertEqual(self.s.get('signer-history.json')['summary']['block_slot'],120)
        self.assertEqual(self.s.get('signer-import.json')['phase'],'complete')
        self.assertTrue(self.s.get('signer-import.json')['ever_authorized'])
        actual=self.k.calls[before:]
        self.assertFalse(any('slashing-protection' in argv and 'import' in argv for argv in actual))
        self.assertFalse(keys.permission(self.s,self.c)['enabled'])
        self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').read_bytes(),self.original_db)
        (self.root/'vc/validators/slashing_protection.sqlite').unlink();before=len(self.k.calls)
        with self.assertRaises(FileNotFoundError):keys.finish_legacy(self.s,self.c,Path('/inert/lighthouse'),lambda:None)
        self.assertEqual(len(self.k.calls),before)

    def test_legacy_live_export_must_cover_known_original_import_bounds_without_reimporting_them(self):
        import hashlib
        import eth_validator_keys as keys
        self.material['history']['data'][0]['signed_blocks']=[{'slot':'50','signing_root':None}]
        self.root_file(self.root/'custody.json',json.dumps(self.material).encode())
        owner=json.loads((self.root/'owner.json').read_bytes())
        owner['material_digest']=hashlib.sha256(json.dumps(self.material,sort_keys=True).encode()).hexdigest()
        self.root_file(self.root/'owner.json',json.dumps(owner).encode())
        self.migrate();plan=self.s.get('accounts.json')
        source={'pair':'reth-v2.8.1--lighthouse-v8.3.2','reth_commit':'c'*40,'lighthouse_commit':'d'*40,
                'reth_archive':'1'*64,'lighthouse_archive':'2'*64}
        images={'reth':{'sha256':'3'*64},'lighthouse':{'sha256':'4'*64}}
        self.s.authorize(self.c,'e'*32,source,'deploy');self.s.begin(self.c,'e'*32,lambda:None)
        migration.floor.authorize(self.s,self.c,plan,source,images,('lighthouse',))
        self.k.history_value=copy.deepcopy(self.k.history_value)
        self.k.history_value['data'][0]['signed_blocks']=[];before=len(self.k.calls)
        with self.assertRaisesRegex(ValueError,'regressed'):keys.finish_legacy(self.s,self.c,Path('/inert/lighthouse'),lambda:None)
        self.assertFalse(self.s.exists('signer-history.json'));self.assertEqual(self.s.get('signer-import.json')['phase'],'legacy')
        self.assertFalse(any('slashing-protection' in argv and 'import' in argv for argv in self.k.calls[before:]))
        self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').read_bytes(),self.original_db)

    def test_visible_journal_sync_failure_retries_original_helper_archive_before_tombstone(self):
        import os,stat
        from unittest.mock import patch
        original=os.fsync
        def failed(fd):
            if self.s.exists('legacy-migration.json') and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('inert persistent original migration journal barrier')
            original(fd)
        original_helper=migration.CONTROL.read_bytes()
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):self.migrate()
                self.assertTrue(migration.CONTROL.is_file())
                self.assertEqual(migration.CONTROL.read_bytes(),original_helper)
                self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').read_bytes(),self.original_db)
        self.assertTrue(self.migrate()['migrated'])
        self.assertEqual(self.s.path('legacy-management.py').read_bytes(),original_helper)
        self.assertTrue(migration.CONTROL.is_dir())
        self.assertFalse(any(row[1] in ('start','enable') for row in self.calls))

    def test_visible_completion_sync_failure_never_recreates_database_or_reports_success(self):
        import os,stat
        from unittest.mock import patch
        original=os.fsync
        def failed(fd):
            if self.s.exists('legacy-migration-complete.json') and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('inert persistent conversion completion barrier')
            original(fd)
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):self.migrate()
                database=self.root/'vc/validators/slashing_protection.sqlite'
                self.assertEqual(database.read_bytes(),self.original_db);self.assertEqual(database.stat().st_ino,self.original_inode)
        self.assertTrue(self.migrate()['already'])
        self.assertTrue(self.s.halted()['retired'])
        self.assertFalse(any(row[1] in ('start','enable') for row in self.calls))

    def test_same_cipher_resume_after_private_receipt_failure_never_recreates_native_history(self):
        from unittest.mock import patch
        real=self.s.put
        def fault(name,value):
            if name=='signer-custody.json':raise OSError('inert original cipher receipt write failure')
            return real(name,value)
        with patch.object(self.s,'put',side_effect=fault):
            with self.assertRaises(OSError):self.migrate()
            with self.assertRaises(OSError):self.migrate()
        before=self.s.path('signer-original.pending').read_bytes();self.migrate()
        self.assertEqual(self.s.path('signer-original.cred').read_bytes(),before)
        self.assertEqual((self.root/'vc/validators/slashing_protection.sqlite').read_bytes(),self.original_db)


if __name__=='__main__':unittest.main()
