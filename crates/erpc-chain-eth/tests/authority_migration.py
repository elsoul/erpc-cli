# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Historical account adoption uses original evidence; all NSS/PID1 effects are inert."""
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures
import eth_migration as migration
import eth_layout as layout
import eth_namespace as namespace
import eth_units as units
import control
import stat


class Migration(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Runtime();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.state=f.state;self.c=f.c;self.plan=f.plan;self.calls=[];self.busy=False
        for path in self.state.directory.iterdir():path.unlink()
        self.proof={'schema':1,'contract':self.c,'machine':'b'*64,'accounts':self.plan,
                    'opened_sources':{'reth':{'version':'v2.8.1','commit':'1'*40},'lighthouse':{'version':'v8.3.2','commit':'2'*40}},
                    'records':{'passwd':'1'*64,'group':'2'*64,'machine':'3'*64,'opened_sources':'4'*64}}
        self.data=f.root/'data';self.data.mkdir(mode=0o750);owners=self.owners={}
        for name,identity in self.plan['users'].items():
            path=self.data/name;path.mkdir(mode=0o750);(path/'inert-database').write_bytes(b'original database')
            info=path.stat();fixtures.fixtures.hold(self,path);owners[(info.st_dev,info.st_ino)]=(identity['uid'],identity['gid'])
        self.jwt=f.root/'config'/'jwt.hex';self.jwt.write_bytes(b'0'*64+b'\n');self.jwt.chmod(0o640)
        old_fstat=os.fstat;old_lstat=Path.lstat
        def descriptor(fd):
            values=list(old_fstat(fd));key=(values[2],values[1])
            if key in owners:values[4],values[5]=owners[key]
            return os.stat_result(values)
        def metadata(path,*args,**kwargs):
            values=list(old_lstat(path,*args,**kwargs));values[4]=0
            if Path(path)==self.jwt:values[5]=self.plan['groups']['ethereum']
            return os.stat_result(values)
        f.install(os,'fstat',descriptor);f.install(Path,'lstat',metadata)
        f.install(layout,'ROOTS',{'rpc':self.data});f.install(layout,'topology',lambda _:None)
        for name in units.UNITS:(namespace.SYSTEMD/name).write_text('[Service]\n# inert original '+name+'\n')
        self.original={name:(namespace.SYSTEMD/name).read_bytes() for name in units.UNITS}

    def native(self,args,**_kwargs):
        self.calls.append(args)
        if args[1]=='show':
            path=namespace.SYSTEMD/args[2]
            status='masked' if path.is_symlink() else 'loaded' if path.exists() else 'not-found'
            return ('LoadState='+status+'\nActiveState='+('active' if self.busy else 'inactive')+'\nMainPID='+('99' if self.busy else '0')+'\n').encode()
        self.assertEqual(args,['/usr/bin/systemctl','daemon-reload']);return b''

    def migrate(self):return migration.migrate(self.state,self.c,self.proof,'b'*64,self.native)

    def assert_native_preserved(self):
        self.assertEqual(self.jwt.read_bytes(),b'0'*64+b'\n')
        for name in self.plan['users']:self.assertEqual((self.data/name/'inert-database').read_bytes(),b'original database')

    def old_journal(self):
        original=self.state.put
        def interrupt(name,value):
            if name=='migration.json':
                original(name,{key:item for key,item in value.items() if key!='filesystem'})
                raise OSError('inert old four-field journal publication interruption')
            return original(name,value)
        with patch.object(self.state,'put',side_effect=interrupt):
            with self.assertRaises(OSError):self.migrate()
        self.assertFalse(self.state.exists('accounts-intent.json'))
        self.assertEqual(set(self.state.get('migration.json')),{'evidence','units','layout','jwt'})
        return self.state.path('migration.json').read_bytes()

    def upgrade_volume(self,proof=None):
        if proof is None:proof={'uuid':'12345678-1234-1234-1234-123456789abc','type':'ext4','root':'/'}
        with patch.object(control,'run',side_effect=self.native):
            return control.dispatch(self.state,self.c,{'action':'upgrade-volume','contract':self.c,'filesystem':proof})

    def test_old_journal_without_account_receipts_has_explicit_stopped_volume_recovery(self):
        original=self.old_journal()
        with self.assertRaisesRegex(ValueError,'independent-evidence'):self.migrate()
        result=self.upgrade_volume();self.assertTrue(result['migration_pending']);self.assertFalse(result['started'])
        self.assertEqual(self.state.path('migration.json').read_bytes(),original)
        self.assertFalse(self.state.exists('accounts-intent.json'))
        for name in units.UNITS:
            self.assertEqual(os.readlink(namespace.SYSTEMD/name),'/dev/null')
            self.assertEqual(self.state.get('migration.json')['units'][name].encode(),self.original[name])
        self.assert_native_preserved();self.assertTrue(self.migrate()['migrated']);self.assert_native_preserved()
        self.assertTrue(self.state.halted()['retired']);self.assertEqual(self.state.path('migration.json').read_bytes(),original)
        self.assertFalse(any(row[1] in ('start','enable') for row in self.calls))

    def test_old_journal_volume_fsync_failure_preserves_original_units_and_source_proof(self):
        original=self.old_journal();actual=os.fsync
        def failure(fd):
            if self.state.exists('migration-volume.json') and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('inert persistent historical volume publication failure')
            actual(fd)
        with patch.object(os,'fsync',side_effect=failure):
            for _ in range(2):
                with self.assertRaises((OSError,ValueError)):self.upgrade_volume()
                with self.assertRaises((OSError,ValueError)):self.migrate()
                self.assertEqual(self.state.path('migration.json').read_bytes(),original)
                for name in units.UNITS:self.assertEqual((namespace.SYSTEMD/name).read_bytes(),self.original[name])
                self.assert_native_preserved()
        self.upgrade_volume();self.migrate();self.assert_native_preserved()
        self.assertEqual(self.state.path('migration.json').read_bytes(),original)

    def test_old_journal_recovery_resumes_an_interrupted_mask_without_executing_legacy_units(self):
        original=self.old_journal();actual=os.symlink;count=[0]
        def fail(*args,**kwargs):
            count[0]+=1
            if count[0]==1:raise OSError('inert old migration unit mask interruption')
            return actual(*args,**kwargs)
        with patch.object(os,'symlink',side_effect=fail):
            with self.assertRaises(OSError):self.upgrade_volume()
        self.assertFalse((namespace.SYSTEMD/sorted(units.UNITS)[0]).exists())
        self.assertEqual(self.state.path('migration.json').read_bytes(),original)
        self.upgrade_volume()
        for name in units.UNITS:self.assertEqual(os.readlink(namespace.SYSTEMD/name),'/dev/null')
        self.assertFalse(any(row[1] in ('start','enable','stop') for row in self.calls))
        self.migrate();self.assert_native_preserved()

    def test_old_journal_foreign_uuid_or_changed_unit_cannot_publish_recovery_authority(self):
        self.old_journal()
        with self.assertRaises(ValueError):self.upgrade_volume({'uuid':'22345678-1234-1234-1234-123456789abc','type':'ext4','root':'/'})
        self.assertFalse(self.state.exists('migration-volume.json'));self.assertFalse(self.state.exists('halt.json'))
        selected=namespace.SYSTEMD/units.UNITS[0];selected.write_bytes(b'preserve unknown unit')
        with self.assertRaises(ValueError):self.upgrade_volume()
        self.assertEqual(selected.read_bytes(),b'preserve unknown unit');self.assertFalse(self.state.exists('migration-volume.json'))
        self.assert_native_preserved()

    def test_actual_migration_uses_history_without_nss_creation_or_native_start(self):
        calls=list(self.fixture.fixture.calls);result=self.migrate()
        self.assertTrue(result['migrated']);self.assertFalse(result['started']);self.assertTrue(self.state.halted()['retired'])
        self.assertEqual(self.fixture.fixture.calls,calls)
        for name in units.UNITS:
            self.assertEqual(os.readlink(namespace.SYSTEMD/name),'/dev/null')
            self.assertEqual(self.state.get('migration.json')['units'][name].encode(),self.original[name])
        layout.verify(self.state,self.c,self.plan);self.assert_native_preserved()
        self.assertTrue(self.migrate()['already']);self.assertEqual(self.fixture.fixture.calls,calls)

    def test_unknown_highest_opened_history_is_not_inferred_and_migrated_floor_blocks_lower_source(self):
        original=self.proof.pop('opened_sources')
        with self.assertRaises(ValueError):self.migrate()
        self.assertEqual(self.calls,[]);self.assertFalse(self.state.exists('owner.json'))
        self.proof['opened_sources']=original;self.migrate()
        source={'pair':'reth-v2.8.0--lighthouse-v8.3.2','reth_commit':'1'*40,'lighthouse_commit':'2'*40,
                'reth_archive':'3'*64,'lighthouse_archive':'4'*64}
        with self.assertRaisesRegex(ValueError,'below.*highest'):migration.source_floor.check(self.state,self.c,source)
        source['pair']='reth-v2.8.1--lighthouse-v8.3.2';migration.source_floor.check(self.state,self.c,source)
        source['reth_commit']='f'*40
        with self.assertRaisesRegex(ValueError,'substitute'):migration.source_floor.check(self.state,self.c,source)
        self.assert_native_preserved()

    def test_current_nss_or_machine_cannot_substitute_for_the_historical_original(self):
        self.fixture.fixture.users['reth'].pw_uid=77
        with self.assertRaises(ValueError):self.migrate()
        self.assertFalse(self.state.exists('owner.json'));self.assertEqual(self.calls,[])
        for name in units.UNITS:self.assertEqual((namespace.SYSTEMD/name).read_bytes(),self.original[name])

    def test_native_directory_of_another_account_is_never_adopted_as_historical_data(self):
        info=(self.data/'reth').stat();key=(info.st_dev,info.st_ino);owner=self.owners[key]
        other=self.owners[fixtures.fixtures.held(self,self.data/'lighthouse')]
        for value in [(77,owner[1]),(owner[0],77),other]:
            with self.subTest(owner=value):
                self.owners[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,'native directory differs from historical numeric owner'):self.migrate()
                finally:self.owners[key]=owner
                self.assertFalse(self.state.exists('owner.json'));self.assertTrue(all(call[1]=='show' for call in self.calls))
                for name in units.UNITS:self.assertEqual((namespace.SYSTEMD/name).read_bytes(),self.original[name])
        self.assertTrue(self.migrate()['migrated']);self.assert_native_preserved()

    def test_active_native_unit_is_refused_without_executing_its_unknown_shutdown(self):
        self.busy=True
        with self.assertRaises(ValueError):self.migrate()
        self.assertFalse(self.state.exists('owner.json'))
        self.assertTrue(all(call[1]=='show' for call in self.calls));self.assert_native_preserved()

    def test_visible_owner_before_migration_journal_can_resume_only_the_same_host(self):
        original=self.state.put
        def interrupted(name,value):
            if name=='migration.json':raise OSError('inert pre-journal interruption')
            original(name,value)
        with patch.object(self.state,'put',side_effect=interrupted):
            with self.assertRaises(OSError):self.migrate()
        self.assertTrue(self.state.exists('owner.json'));self.assertFalse(self.state.exists('migration.json'))
        self.assertTrue(self.migrate()['migrated']);self.assert_native_preserved()

    def test_persistent_journal_durability_failure_never_masks_original_units(self):
        actual=os.fsync
        def failed(fd):
            if self.state.exists('migration.json'):raise OSError('inert persistent original journal durability failure')
            actual(fd)
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):self.migrate()
                for name in units.UNITS:self.assertEqual((namespace.SYSTEMD/name).read_bytes(),self.original[name])
        self.assertTrue(self.migrate()['migrated']);self.assert_native_preserved()

    def test_interruption_after_original_unit_unlink_preserves_archive_and_resumes_mask(self):
        actual=os.symlink;count=[0]
        def failed(*args,**kwargs):
            count[0]+=1
            if count[0]==1:raise OSError('inert mask publication interruption')
            return actual(*args,**kwargs)
        with patch.object(os,'symlink',side_effect=failed):
            with self.assertRaises(OSError):self.migrate()
        self.assertFalse((namespace.SYSTEMD/units.UNITS[0]).exists());self.assertTrue(self.state.exists('migration.json'))
        self.assertTrue(self.migrate()['migrated']);self.assert_native_preserved()


if __name__=='__main__':unittest.main()
