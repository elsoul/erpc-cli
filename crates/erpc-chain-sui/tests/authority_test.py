# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Sui account and namespace failures; all NSS mutations are inert."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / 'templates/jinja/erpc-sui-control.py.j2'


@unittest.skipUnless(os.name == 'posix', 'Linux account authority uses POSIX identities')
class Authority(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader('sui_authority_fixture', str(SOURCE))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.module = importlib.util.module_from_spec(spec); loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); (self.root / 'etc').mkdir()
        self.calls = []; self.users = {}; self.groups = {}
        self.expected = {'network': 'testnet', 'role': 'fullnode', 'genesis': 'a' * 64}
        self.c = self.module.Control(self.root, self.command, owner=os.getuid())
        self.a = self.module.account
        (self.root/'var/lib').mkdir(parents=True);(self.root/'proc').mkdir()
        self.data_owners={};original_lstat=Path.lstat
        def data_metadata(path,*args,**kwargs):
            value=original_lstat(path,*args,**kwargs)
            if path in self.data_owners:
                fields=list(value);fields[4],fields[5]=self.data_owners[path];return os.stat_result(fields)
            return value
        context=patch.object(Path,'lstat',data_metadata);context.start();self.addCleanup(context.stop)
        self.descriptor_changes=[];original_fstat=os.fstat
        def data_descriptor(descriptor):
            info=original_fstat(descriptor);home=self.root/'var/lib/sui'
            try:named=original_lstat(home)
            except FileNotFoundError:return None
            return home if (named.st_dev,named.st_ino)==(info.st_dev,info.st_ino) else None
        def descriptor_metadata(descriptor):
            value=original_fstat(descriptor);path=data_descriptor(descriptor)
            if path in self.data_owners:
                fields=list(value);fields[4],fields[5]=self.data_owners[path];return os.stat_result(fields)
            return value
        def descriptor_owner(descriptor,uid,gid):
            path=data_descriptor(descriptor)
            self.assertIsNotNone(path);self.descriptor_changes.append((descriptor,path,uid,gid))
            self.data_owners[path]=(uid,gid)
        context=patch.object(self.module.os,'fstat',side_effect=descriptor_metadata);context.start();self.addCleanup(context.stop)
        context=patch.object(self.module.os,'fchown',side_effect=descriptor_owner);context.start();self.addCleanup(context.stop)
        def lookup(records, field, value):
            for item in records.values():
                if getattr(item, field) == value: return item
            raise KeyError(value)
        for module, methods, records, prefix in ((self.a.pwd, ('getpwnam','getpwuid','getpwall'),self.users,'pw'),
                (self.a.grp,('getgrnam','getgrgid','getgrall'),self.groups,'gr')):
            for method, handler in (
                (methods[0],lambda value,r=records,p=prefix: lookup(r,p+'_name',value)),
                (methods[1],lambda value,r=records,p=prefix: lookup(r,p+('_uid' if p=='pw' else '_gid'),value)),
                (methods[2],lambda r=records:list(r.values()))):
                context=patch.object(module,method,side_effect=handler); context.start(); self.addCleanup(context.stop)
        context=patch.object(self.a.os,'getgrouplist',side_effect=lambda name,gid:[gid]); context.start(); self.addCleanup(context.stop)

    def command(self, argv, **kwargs):
        if argv == ['/usr/bin/systemctl','--version']:return subprocess.CompletedProcess(argv,0,b'systemd 255 (fixture)\n',b'')
        self.calls.append(argv)
        if argv[0] == '/usr/sbin/groupadd':
            self.groups['sui']=SimpleNamespace(gr_name='sui',gr_gid=int(argv[argv.index('--gid')+1]),gr_mem=[])
        elif argv[0] == '/usr/sbin/useradd':
            self.users['sui']=SimpleNamespace(pw_name='sui',pw_uid=int(argv[argv.index('--uid')+1]),pw_gid=int(argv[argv.index('--gid')+1]),pw_dir='/var/lib/sui',pw_shell='/usr/sbin/nologin')
        else: raise AssertionError('unexpected account command')
        return subprocess.CompletedProcess(argv,0,b'',b'')

    def test_original_receipt_precedes_nss_and_retry_preserves_ids(self):
        result=self.c.prepare_account(self.expected)
        self.assertEqual(result,{'uid':999,'gid':999}); self.assertEqual(len(self.calls),2)
        self.assertEqual(self.c.prepare_account(self.expected),result); self.assertEqual(len(self.calls),2)
        self.assertTrue(self.c.account_record(self.expected)['account_established'])
        self.c.account(self.expected)
        self.assertEqual(json.loads(self.c.path('/etc/sui/contract.json').read_text())['authority_protocol'],3)

    def test_real_fsync_failure_cannot_authorize_nss_before_durable_reservation(self):
        actual=os.fsync
        for failing in range(1,5):
            count=[0]
            def fault(fd):
                count[0]+=1
                if count[0]==failing: raise OSError('inert receipt fsync failure')
                return actual(fd)
            with patch.object(os,'fsync',side_effect=fault):
                with self.assertRaises(OSError): self.c.prepare_account(self.expected)
            self.assertFalse(self.calls)
        result=self.c.prepare_account(self.expected); self.assertEqual(result['uid'],999)

    def test_existing_or_keyed_only_account_and_foreign_primary_gid_are_not_adopted(self):
        self.users['foreign']=SimpleNamespace(pw_name='foreign',pw_uid=4000,pw_gid=999,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        with patch.object(self.a.pwd,'getpwnam',return_value=SimpleNamespace(pw_name='sui')):
            with self.assertRaises(ValueError): self.c.prepare_account(self.expected)
        self.assertFalse(self.calls); self.assertFalse(self.c.path('/etc/sui').exists())
        self.assertEqual(self.c.prepare_account(self.expected)['uid'],998)

    def test_established_identity_drift_and_deletion_never_repair_nss(self):
        self.c.prepare_account(self.expected); original=self.users['sui']; count=len(self.calls)
        for field,value in [('pw_uid',2001),('pw_gid',2001),('pw_dir','/changed'),('pw_shell','/bin/sh')]:
            self.users['sui']=SimpleNamespace(**dict(vars(original),**{field:value}))
            with self.assertRaises(ValueError): self.c.prepare_account(self.expected)
        self.users['sui']=original
        with patch.object(self.a.pwd,'getpwuid',side_effect=OSError('NSS unavailable')):
            with self.assertRaises(OSError): self.c.account(self.expected)
        del self.users['sui']
        with self.assertRaises(ValueError): self.c.prepare_account(self.expected)
        self.assertEqual(len(self.calls),count)

    def test_writable_symlink_nonroot_ancestors_and_dropins_refuse_before_receipt(self):
        bad=self.root/'etc/sui'; bad.mkdir(); bad.chmod(0o777)
        with self.assertRaises(ValueError): self.c.prepare_account(self.expected)
        self.assertEqual(stat.S_IMODE(bad.stat().st_mode),0o777); self.assertFalse(self.calls)
        bad.chmod(0o750); bad.rmdir(); outside=self.root/'outside';outside.mkdir();bad.symlink_to(outside)
        with self.assertRaises(ValueError):self.c.prepare_account(self.expected)
        bad.unlink(); parent=self.root/'usr/local/lib/erpc';parent.mkdir(parents=True);parent.chmod(0o777)
        with self.assertRaises(ValueError):self.c.prepare_account(self.expected)
        parent.chmod(0o755)
        drop=self.root/'etc/systemd/system/sui-node.service.d';drop.mkdir(parents=True)
        (drop/'99-foreign.conf').write_text('[Service]\nExecStart=/inert\n')
        with self.assertRaises(ValueError):self.c.prepare_account(self.expected)
        self.assertFalse(self.calls);self.assertFalse(self.c.path('/etc/sui/original-account.json').exists())

    def test_owner_file_permission_hardlink_and_parent_drift_refused_without_repair(self):
        self.c.prepare_account(self.expected);record=self.c.path('/etc/sui/original-account.json')
        record.chmod(0o666)
        with self.assertRaises(ValueError):self.c.account(self.expected)
        record.chmod(0o600); os.link(record,self.root/'record-link')
        with self.assertRaises(ValueError):self.c.account(self.expected)
        (self.root/'record-link').unlink();record.parent.chmod(0o777)
        with self.assertRaises(ValueError):self.c.contract(self.expected)
        self.assertEqual(len(self.calls),2)

    def legacy_fixture(self, gid=999):
        directory=self.root/'etc/sui';directory.mkdir()
        (directory/'contract.json').write_text(json.dumps(self.expected))
        home=self.root/'var/lib/sui';home.mkdir(parents=True,mode=0o700)
        (self.root/'etc/erpc/sui').mkdir(parents=True)
        self.users['sui']=SimpleNamespace(pw_name='sui',pw_uid=999,pw_gid=gid,pw_dir='/var/lib/sui',pw_shell='/usr/sbin/nologin')
        self.groups['sui']=SimpleNamespace(gr_name='sui',gr_gid=gid,gr_mem=[])
        original=Path.lstat
        def original_owner(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==home:
                fields=list(value);fields[4]=999;fields[5]=gid
                return os.stat_result(fields)
            return value
        context=patch.object(Path,'lstat',original_owner);context.start();self.addCleanup(context.stop)
        def lifecycle(argv,**kwargs):
            if argv == ['/usr/bin/systemctl','--version']:return subprocess.CompletedProcess(argv,0,b'systemd 255 (fixture)\n',b'')
            self.calls.append(argv)
            if argv[:2]==['systemctl','show']:return subprocess.CompletedProcess(argv,0,b'loaded',b'')
            if argv[:2] in (['systemctl','stop'],['systemctl','disable']):return subprocess.CompletedProcess(argv,0,b'',b'')
            raise AssertionError('unexpected legacy migration command')
        self.c.run=lifecycle

    def test_legacy_is_never_adopted_without_explicit_migration_and_original_ids_remain(self):
        self.legacy_fixture()
        with self.assertRaises(ValueError):self.c.prepare_account(self.expected)
        self.assertFalse(self.calls)
        result=self.c.migrate_account(self.expected);self.assertEqual(result,{'uid':999,'gid':999})
        self.assertIn(['systemctl','stop','sui-bootstrap','sui-node'],self.calls)
        self.assertIn(['systemctl','disable','sui-bootstrap','sui-node'],self.calls)
        self.assertTrue(self.c.path('/etc/sui/stopped').exists())
        self.c.account(self.expected)
        self.assertFalse(any(call[0] in ('/usr/sbin/useradd','/usr/sbin/groupadd') for call in self.calls))

    def test_interrupted_secondary_migration_receipt_reuses_atomic_original_reservation(self):
        self.legacy_fixture()
        with patch.object(self.c,'save',side_effect=OSError('inert secondary receipt storage failure')):
            with self.assertRaises(OSError):self.c.migrate_account(self.expected)
        self.assertFalse(self.c.path('/etc/sui/original-account.json').exists())
        self.assertEqual(self.c.account_record(self.expected)['service_uid'],999)
        stored=json.loads(self.c.path('/etc/sui/contract.json').read_text())
        self.assertNotEqual(stored,self.expected)  # Old exact-contract helpers fail closed.
        self.assertEqual(self.c.migrate_account(self.expected),{'uid':999,'gid':999})
        self.assertTrue(self.c.path('/etc/sui/original-account.json').exists())

    def test_legacy_migration_refuses_scope_nss_or_surviving_original_process(self):
        self.legacy_fixture()
        with self.assertRaises(ValueError):self.c.migrate_account(dict(self.expected,network='mainnet'))
        self.assertFalse(self.calls)
        self.users['sui'].pw_shell='/bin/sh'
        with self.assertRaises(ValueError):self.c.migrate_account(self.expected)
        self.assertFalse(self.calls);self.users['sui'].pw_shell='/usr/sbin/nologin'
        process=self.root/'proc/123';process.mkdir()
        original=Path.lstat
        def original_process(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==process:
                fields=list(value);fields[4]=999;return os.stat_result(fields)
            return value
        with patch.object(Path,'lstat',original_process):
            with self.assertRaisesRegex(ValueError,'original Sui process remains'):self.c.migrate_account(self.expected)
        self.assertFalse(self.c.path('/etc/sui/original-account.json').exists())
        self.assertEqual(json.loads(self.c.path('/etc/sui/contract.json').read_text()),self.expected)

    def test_retained_uid_shutdown_ignores_nss_drift_and_refuses_orphans_even_if_unit_missing(self):
        self.c.prepare_account(self.expected)
        (self.root/'proc/123').mkdir(parents=True);(self.root/'etc/erpc/sui').mkdir(parents=True)
        process=self.root/'proc/123';original=Path.lstat
        def original_process(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==process:
                fields=list(value);fields[4]=999;return os.stat_result(fields)
            return value
        self.users['sui'].pw_uid=2001
        def absent(argv,**kwargs):
            self.calls.append(argv);return subprocess.CompletedProcess(argv,0,b'not-found',b'')
        self.c.run=absent
        with patch.object(Path,'lstat',original_process):
            with self.assertRaisesRegex(ValueError,'original Sui process remains'):
                self.c.cancel_and_stop(self.expected,'test-stop',installed_only=True)
        self.assertTrue(self.c.path('/etc/sui/stopped').exists())
        self.assertFalse(any(call[:2]==['nft','delete'] for call in self.calls))
        process.rmdir();self.c.cancel_and_stop(self.expected,'test-stop',installed_only=True)


    def test_actual_credential_condition_refuses_original_or_loaded_recipient_drift_before_grant(self):
        import hashlib
        self.c.prepare_account(self.expected)
        (self.root/'etc/erpc/sui').mkdir(parents=True)
        policy=self.root/'etc/erpc/sui/firewall.nft';policy.write_text('inert protected filter')
        self.c.write('/etc/erpc/sui/confirmed.json',{'contract':self.expected,'file':hashlib.sha256(policy.read_bytes()).hexdigest(),'live':'fixture-filter'})
        recipients={'User':'999','Group':'999','DynamicUser':'no','SupplementaryGroups':''}
        def show(argv,**kwargs):
            if argv == ['/usr/bin/systemctl','--version']:return subprocess.CompletedProcess(argv,0,b'systemd 255 (fixture)\n',b'')
            self.calls.append(argv)
            if argv[:2]==['systemctl','show']:
                key=next(arg.split('=',1)[1] for arg in argv if arg.startswith('--property='))
                return subprocess.CompletedProcess(argv,0,recipients[key].encode(),b'')
            raise AssertionError('unexpected condition command')
        self.c.run=show;grants=[]
        def condition_then_grant():
            self.c.credential_condition(self.expected)
            grants.append(recipients['User'])  # Inert model of source-qualified next PID1 phase.
        with patch.object(self.c,'release'),patch.object(self.module.release_authority,'runtime'),patch.object(self.c,'fingerprint',return_value='fixture-filter'):
            condition_then_grant();self.assertEqual(grants,['999'])
            self.users['sui'].pw_uid=2001
            with self.assertRaises(ValueError):condition_then_grant()
            self.users['sui'].pw_uid=999
            for key,bad in [('User','sui'),('Group','2001'),('DynamicUser','yes'),('SupplementaryGroups','other')]:
                original=recipients[key];recipients[key]=bad
                with self.assertRaises(ValueError):condition_then_grant()
                recipients[key]=original
            self.assertEqual(grants,['999'])
            self.c.write_text('/etc/sui/stopped','cancelled')
            with self.assertRaises(ValueError):condition_then_grant()
            self.assertEqual(grants,['999'])

    def test_native_release_namespace_refuses_redirects_permissions_and_hardlinks(self):
        release=self.root/'opt/sui/testnet-v1.2.3';release.mkdir(parents=True)
        for name in ('sui-node','sui-tool','sui'):(release/name).write_text('inert executable fixture')
        current=release.parent/'current';current.symlink_to('/opt/sui/testnet-v1.2.3')
        self.c.release(self.expected)
        (release/'sui').chmod(0o666)
        with self.assertRaises(ValueError):self.c.release(self.expected)
        (release/'sui').chmod(0o644);os.link(release/'sui',self.root/'native-link')
        with self.assertRaises(ValueError):self.c.release(self.expected)
        (self.root/'native-link').unlink();current.unlink();current.symlink_to('/opt/sui/mainnet-v1.2.3')
        with self.assertRaises(ValueError):self.c.release(self.expected)
        self.assertFalse(self.calls)


    def test_actual_first_and_secondary_fsync_failures_still_stop_disable_and_retain_data(self):
        self.c.prepare_account(self.expected)
        (self.root/'etc/erpc/sui').mkdir(parents=True)
        history=self.root/'var/lib/sui/retained-history';history.write_text('inert original history')
        native_calls=[]
        def lifecycle(argv,**kwargs):
            native_calls.append(argv)
            return subprocess.CompletedProcess(argv,0,b'loaded' if argv[:2]==['systemctl','show'] else b'',b'')
        self.c.run=lifecycle;actual=os.fsync
        for failing in range(1,10):
            for name in ('/etc/sui/stopped','/etc/sui/stopped.pending','/etc/erpc/sui/latest-intent','/etc/erpc/sui/latest-intent.pending'):
                self.c.path(name).unlink(missing_ok=True)
            count=[0];native_calls.clear()
            def fault(fd):
                count[0]+=1
                if count[0]==failing:raise OSError('inert actual fsync fault')
                return actual(fd)
            with patch.object(os,'fsync',side_effect=fault):
                with self.assertRaisesRegex(ValueError,'shutdown attempted'):
                    self.c.cancel_and_stop(self.expected,'test-cancel',installed_only=True)
            self.assertIn(['systemctl','stop','sui-bootstrap','sui-node'],native_calls)
            self.assertIn(['systemctl','disable','sui-bootstrap','sui-node'],native_calls)
            self.assertEqual(history.read_text(),'inert original history')
            self.assertFalse(any(argv[:2]==['nft','delete'] for argv in native_calls))
        native_calls.clear()
        with patch.object(os,'fsync',side_effect=OSError('storage unavailable')) as sync:
            with self.assertRaises(ValueError):self.c.cancel_and_stop(dict(self.expected,network='mainnet'),'foreign')
            sync.assert_not_called()
        self.assertFalse(native_calls)

    def test_original_data_home_drift_is_not_repaired_by_reinitialization(self):
        self.c.prepare_account(self.expected);home=self.root/'var/lib/sui'
        home.chmod(0o777);count=len(self.calls)
        with self.assertRaises(ValueError):self.c.prepare_account(self.expected)
        self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o777)
        self.assertEqual(len(self.calls),count)
        home.chmod(0o700);self.data_owners[home]=(2001,2001)
        with self.assertRaises(ValueError):self.c.account(self.expected)
        self.assertEqual(self.data_owners[home],(2001,2001))


    def test_legacy_migration_preserves_distinct_original_primary_gid(self):
        self.legacy_fixture(gid=998)
        self.assertEqual(self.c.migrate_account(self.expected),{'uid':999,'gid':998})
        self.assertEqual(self.c.account_record(self.expected)['service_gid'],998)
        self.c.account(self.expected)
        self.assertFalse(any(argv[0] in ('/usr/sbin/useradd','/usr/sbin/groupadd') for argv in self.calls))

    def test_unqualified_systemd_refuses_reservation_before_any_nss_write(self):
        def version(argv,**kwargs):
            self.assertEqual(argv,['/usr/bin/systemctl','--version'])
            return subprocess.CompletedProcess(argv,0,b'systemd 256 (inert)\n',b'')
        self.c.run=version
        with self.assertRaisesRegex(ValueError,'systemd 255'):self.c.prepare_account(self.expected)
        self.assertFalse(self.c.path('/etc/sui/original-account.json').exists())
        self.assertFalse(self.users);self.assertFalse(self.groups)


    def test_fresh_root_volume_modes_and_empty_recovery_directory_are_preserved(self):
        for mode in (0o700,0o755):
            for recovery in (False,True):
                with self.subTest(mode=mode,recovery=recovery):
                    fixture=Authority();fixture.setUp()
                    try:
                        home=fixture.root/'var/lib/sui';home.mkdir(mode=mode)
                        lost=home/'lost+found';before=None
                        if recovery:
                            lost.mkdir(mode=0o700);before=lost.stat()
                        account=fixture.c.prepare_account(fixture.expected)
                        self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o700)
                        self.assertEqual(fixture.data_owners[home],(account['uid'],account['gid']))
                        self.assertEqual(len(fixture.descriptor_changes),1)
                        if recovery:
                            after=lost.stat()
                            self.assertEqual((after.st_ino,after.st_uid,after.st_gid,after.st_mode),
                                             (before.st_ino,before.st_uid,before.st_gid,before.st_mode))
                            self.assertFalse(list(lost.iterdir()))
                        (home/'retained-native-data').write_text('inert chain history')
                        self.assertEqual(fixture.c.prepare_account(fixture.expected),account)
                        self.assertEqual((home/'retained-native-data').read_text(),'inert chain history')
                        self.assertEqual(len(fixture.descriptor_changes),1)
                    finally:fixture.doCleanups()

    def test_unknown_or_populated_recovery_content_refuses_before_account_creation(self):
        for kind in ('unknown-file','populated-recovery','writable-recovery','recovery-link','recovery-file'):
            with self.subTest(kind=kind):
                fixture=Authority();fixture.setUp()
                try:
                    home=fixture.root/'var/lib/sui';home.mkdir(mode=0o755)
                    lost=home/'lost+found'
                    if kind=='unknown-file':(home/'unowned-data').write_text('retained')
                    elif kind=='recovery-link':
                        outside=fixture.root/'unrelated';outside.mkdir();lost.symlink_to(outside)
                    elif kind=='recovery-file':lost.write_text('retained')
                    else:
                        lost.mkdir(mode=0o700)
                        if kind=='populated-recovery':(lost/'recovered-inode').write_text('retained')
                        else:lost.chmod(0o777)
                    with self.assertRaises((ValueError,OSError)):fixture.c.prepare_account(fixture.expected)
                    self.assertFalse(fixture.calls);self.assertFalse(fixture.descriptor_changes)
                    self.assertFalse(fixture.c.path('/etc/sui/original-account.json').exists())
                    self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o755)
                    self.assertTrue(any(home.iterdir()))
                finally:fixture.doCleanups()

    def test_foreign_volume_or_recovery_owner_refuses_without_repair(self):
        for foreign in ('home','recovery'):
            fixture=Authority();fixture.setUp()
            try:
                home=fixture.root/'var/lib/sui';home.mkdir(mode=0o755)
                lost=home/'lost+found';lost.mkdir(mode=0o700)
                selected=(home if foreign=='home' else lost).stat();actual=os.fstat
                def wrong_owner(descriptor):
                    info=actual(descriptor)
                    if (info.st_dev,info.st_ino)==(selected.st_dev,selected.st_ino):
                        values=list(info);values[4]=fixture.c.owner+1;return os.stat_result(values)
                    return info
                with patch.object(os,'fstat',side_effect=wrong_owner):
                    with self.assertRaises(ValueError):fixture.c.prepare_account(fixture.expected)
                self.assertFalse(fixture.calls);self.assertFalse(fixture.descriptor_changes)
                self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o755)
            finally:fixture.doCleanups()

    def test_initial_descriptor_change_never_chowns_a_replaced_path(self):
        home=self.root/'var/lib/sui';home.mkdir(mode=0o755)
        original=home.stat();moved=self.root/'retained-qualified-volume';chmod=os.fchmod;changes=[]
        def replace_after_mode(descriptor,mode):
            chmod(descriptor,mode)
            info=os.fstat(descriptor)
            if (info.st_dev,info.st_ino)==(original.st_dev,original.st_ino) and not moved.exists():
                home.rename(moved);home.mkdir(mode=0o755);(home/'foreign-data').write_text('retained')
        def chown_descriptor(descriptor,uid,gid):changes.append((os.fstat(descriptor).st_ino,uid,gid))
        with patch.object(os,'fchmod',side_effect=replace_after_mode),patch.object(os,'fchown',side_effect=chown_descriptor):
            with self.assertRaisesRegex(ValueError,'path was replaced'):self.c.prepare_account(self.expected)
        self.assertEqual(changes,[(original.st_ino,999,999)])
        self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o755)
        self.assertEqual((home/'foreign-data').read_text(),'retained')
        self.assertFalse(self.c.account_record(self.expected)['home_established'])


    def test_unused_legacy_volume_preserves_empty_filesystem_recovery_storage(self):
        self.legacy_fixture()
        lost=self.root/'var/lib/sui/lost+found';lost.mkdir(mode=0o700);original=lost.stat()
        self.assertEqual(self.c.migrate_account(self.expected),{'uid':999,'gid':999})
        self.assertEqual((lost.stat().st_ino,lost.stat().st_uid,lost.stat().st_mode),
                         (original.st_ino,original.st_uid,original.st_mode))
        self.assertFalse(self.descriptor_changes)



    def test_failed_initial_volume_mode_change_retries_the_original_reserved_account(self):
        home=self.root/'var/lib/sui';home.mkdir(mode=0o755);original=home.stat();chmod=os.fchmod
        def failed_data_mode(descriptor,mode):
            info=os.fstat(descriptor)
            if (info.st_dev,info.st_ino)==(original.st_dev,original.st_ino):
                raise OSError('inert initial volume permission failure')
            return chmod(descriptor,mode)
        with patch.object(os,'fchmod',side_effect=failed_data_mode):
            with self.assertRaises(OSError):self.c.prepare_account(self.expected)
        reserved=self.c.account_record(self.expected)
        self.assertTrue(reserved['account_established']);self.assertFalse(reserved['home_established'])
        self.assertEqual(len(self.calls),2);self.assertFalse(self.descriptor_changes)
        self.assertEqual(self.c.prepare_account(self.expected),{'uid':reserved['service_uid'],'gid':reserved['service_gid']})
        self.assertEqual(len(self.calls),2);self.assertEqual(len(self.descriptor_changes),1)
        self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o700)



if __name__ == '__main__': unittest.main()
