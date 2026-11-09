# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Avalanche account and namespace failures; all NSS mutations are inert."""
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
SOURCE = Path(__file__).resolve().parents[1] / 'templates/jinja/control.py'


@unittest.skipUnless(os.name == 'posix', 'Linux account authority uses POSIX identities')
class Authority(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader('avalanchego_authority_fixture', str(SOURCE))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.module = importlib.util.module_from_spec(spec); loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); (self.root / 'etc').mkdir()
        self.calls = []; self.users = {}; self.groups = {}
        self.expected = {'network':'fuji','type':'full','validator':True,'owner':'a'*64}
        self.c = self.module.Control(self.root, self.command, owner=os.getuid())
        self.a = self.module.account
        (self.root/'var/lib').mkdir(parents=True);(self.root/'proc').mkdir();(self.root/'opt/erpc').mkdir(parents=True)
        self.data_owners={};original_lstat=Path.lstat
        def data_metadata(path,*args,**kwargs):
            value=original_lstat(path,*args,**kwargs)
            if path in self.data_owners:
                fields=list(value);fields[4],fields[5]=self.data_owners[path];return os.stat_result(fields)
            return value
        context=patch.object(Path,'lstat',data_metadata);context.start();self.addCleanup(context.stop)
        self.descriptor_changes=[];original_fstat=os.fstat
        def data_descriptor(descriptor):
            info=original_fstat(descriptor)
            for path in (self.root/'var/lib/avalanchego', *(self.root/'var/lib/avalanchego').rglob('*')):
                try:named=original_lstat(path)
                except FileNotFoundError:continue
                if (named.st_dev,named.st_ino)==(info.st_dev,info.st_ino):return path
            return None
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
            self.groups['avalanchego']=SimpleNamespace(gr_name='avalanchego',gr_gid=int(argv[argv.index('--gid')+1]),gr_mem=[])
        elif argv[0] == '/usr/sbin/useradd':
            self.users['avalanchego']=SimpleNamespace(pw_name='avalanchego',pw_uid=int(argv[argv.index('--uid')+1]),pw_gid=int(argv[argv.index('--gid')+1]),pw_dir='/var/lib/avalanchego',pw_shell='/usr/sbin/nologin')
        elif argv[:2]==['systemctl','show']:
            if '--property=LoadState' in argv:return subprocess.CompletedProcess(argv,0,b'loaded',b'')
            if '--property=User' in argv:return subprocess.CompletedProcess(argv,0,b'999',b'')
            if '--property=MainPID' in argv:return subprocess.CompletedProcess(argv,0,b'0',b'')
            raise AssertionError(argv)
        elif argv[:2] not in (['systemctl','stop'],['systemctl','disable']):raise AssertionError(argv)
        return subprocess.CompletedProcess(argv,0,b'',b'')

    def test_original_receipt_precedes_nss_and_retry_preserves_ids(self):
        result=self.c.prepare(self.expected)
        self.assertEqual(result,{'uid':999,'gid':999}); self.assertEqual(len(self.calls),2)
        self.assertEqual(self.c.prepare(self.expected),result); self.assertEqual(len(self.calls),2)
        self.assertTrue(self.c.account_record(self.expected)['account_established'])
        self.c.account(self.expected)
        self.assertEqual(json.loads(self.c.path('/etc/avalanchego/contract.json').read_text())['authority_protocol'],2)

    def test_real_fsync_failure_cannot_authorize_nss_before_durable_reservation(self):
        actual=os.fsync
        for failing in range(1,5):
            count=[0]
            def fault(fd):
                count[0]+=1
                if count[0]==failing: raise OSError('inert receipt fsync failure')
                return actual(fd)
            with patch.object(os,'fsync',side_effect=fault):
                with self.assertRaises(OSError): self.c.prepare(self.expected)
            self.assertFalse(self.calls)
        result=self.c.prepare(self.expected); self.assertEqual(result['uid'],999)

    def test_existing_or_keyed_only_account_and_foreign_primary_gid_are_not_adopted(self):
        self.users['foreign']=SimpleNamespace(pw_name='foreign',pw_uid=4000,pw_gid=999,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        with patch.object(self.a.pwd,'getpwnam',return_value=SimpleNamespace(pw_name='avalanchego')):
            with self.assertRaises(ValueError): self.c.prepare(self.expected)
        self.assertFalse(self.calls); self.assertFalse(self.c.path('/etc/avalanchego').exists())
        self.assertEqual(self.c.prepare(self.expected)['uid'],998)

    def test_established_identity_drift_and_deletion_never_repair_nss(self):
        self.c.prepare(self.expected); original=self.users['avalanchego']; count=len(self.calls)
        for field,value in [('pw_uid',2001),('pw_gid',2001),('pw_dir','/changed'),('pw_shell','/bin/sh')]:
            self.users['avalanchego']=SimpleNamespace(**dict(vars(original),**{field:value}))
            with self.assertRaises(ValueError): self.c.prepare(self.expected)
        self.users['avalanchego']=original
        with patch.object(self.a.pwd,'getpwuid',side_effect=OSError('NSS unavailable')):
            with self.assertRaises(OSError): self.c.account(self.expected)
        del self.users['avalanchego']
        with self.assertRaises(ValueError): self.c.prepare(self.expected)
        self.assertEqual(len(self.calls),count)

    def test_writable_symlink_nonroot_ancestors_and_dropins_refuse_before_receipt(self):
        bad=self.root/'etc/avalanchego'; bad.mkdir(); bad.chmod(0o777)
        with self.assertRaises(ValueError): self.c.prepare(self.expected)
        self.assertEqual(stat.S_IMODE(bad.stat().st_mode),0o777); self.assertFalse(self.calls)
        bad.chmod(0o750); bad.rmdir(); outside=self.root/'outside';outside.mkdir();bad.symlink_to(outside)
        with self.assertRaises(ValueError):self.c.prepare(self.expected)
        bad.unlink(); parent=self.root/'usr/local/lib/erpc';parent.mkdir(parents=True);parent.chmod(0o777)
        with self.assertRaises(ValueError):self.c.prepare(self.expected)
        parent.chmod(0o755)
        drop=self.root/'etc/systemd/system/avalanchego.service.d';drop.mkdir(parents=True)
        (drop/'99-foreign.conf').write_text('[Service]\nExecStart=/inert\n')
        with self.assertRaises(ValueError):self.c.prepare(self.expected)
        self.assertFalse(self.calls);self.assertFalse(self.c.path('/etc/avalanchego/original-account.json').exists())

    def test_owner_file_permission_hardlink_and_parent_drift_refused_without_repair(self):
        self.c.prepare(self.expected);record=self.c.path('/etc/avalanchego/original-account.json')
        record.chmod(0o666)
        with self.assertRaises(ValueError):self.c.account(self.expected)
        record.chmod(0o600); os.link(record,self.root/'record-link')
        with self.assertRaises(ValueError):self.c.account(self.expected)
        (self.root/'record-link').unlink();record.parent.chmod(0o777)
        with self.assertRaises(ValueError):self.c.contract(self.expected)
        self.assertEqual(len(self.calls),2)


    def original_identity(self):
        self.c.prepare(self.expected)
        self.c.write('/etc/avalanchego/generation-started',{'contract':self.expected})
        for name in self.module.NAMES:
            path=self.root/'var/lib/avalanchego/staking'/name
            path.write_bytes(('inert-original-'+name).encode());path.chmod(0o400)
            self.data_owners[path]=(999,999)
        self.c.seal(self.expected)
        values=self.c.verify_identity(self.expected)
        import base64
        return {'expected_hashes':self.c.digests(values),'bundle':{'hashes':self.c.digests(values),'files':{
            name:base64.b64encode(value).decode() for name,value in values.items()}}}

    def test_restore_refuses_changed_named_recipient_before_private_file_write(self):
        envelope=self.original_identity();path=self.root/'var/lib/avalanchego/staking/signer.key';path.unlink()
        original=self.users['avalanchego'];self.users['avalanchego']=SimpleNamespace(**dict(vars(original),pw_uid=2001))
        with self.assertRaises(ValueError):self.c.restore(self.expected,envelope)
        self.assertFalse(path.exists());self.assertFalse(path.with_name('signer.key.restore').exists())
        self.users['avalanchego']=original
        self.c.restore(self.expected,envelope)
        self.assertEqual(self.c.digests(self.c.verify_identity(self.expected)),envelope['expected_hashes'])
        self.assertTrue(self.c.path('/etc/avalanchego/stopped').exists())
        self.assertFalse(any(call[:2]==['systemctl','start'] for call in self.calls))

    def test_restore_refuses_original_uid_writer_even_when_current_name_is_different(self):
        envelope=self.original_identity();path=self.root/'var/lib/avalanchego/staking/signer.key';path.unlink()
        process=self.root/'proc/123';process.mkdir();self.data_owners[process]=(999,999)
        with self.assertRaises(ValueError):self.c.restore(self.expected,envelope)
        self.assertFalse(path.exists())
        self.assertTrue(self.c.path('/etc/avalanchego/stopped').exists())

    def test_cancellation_storage_failure_attempts_all_owned_stops_and_disables(self):
        self.c.prepare(self.expected);self.calls.clear()
        with patch.object(os,'fsync',side_effect=OSError('inert storage failure')):
            with self.assertRaises(ValueError):self.c.cancel(self.expected,'stop')
        for unit in self.module.UNITS:
            self.assertIn(['systemctl','stop',unit],self.calls)
            self.assertIn(['systemctl','disable',unit],self.calls)

    def test_migration_binds_only_verified_existing_bytes_and_original_numeric_profile(self):
        envelope=self.original_identity()
        record=self.c.account_record(self.expected)
        self.c.path('/etc/avalanchego/original-account.json').unlink()
        self.c.path('/etc/avalanchego/identity.json').unlink()
        self.c.write('/etc/avalanchego/contract.json',{k:v for k,v in self.expected.items() if k!='owner'})
        manifest=self.root/'var/lib/avalanchego/staking/identity.json'
        manifest.write_text(json.dumps(envelope['expected_hashes']));manifest.chmod(0o600)
        self.data_owners[manifest]=(999,999)
        self.calls.clear()
        with self.assertRaises(ValueError):self.c.prepare(self.expected)
        self.assertFalse(self.calls)
        bad=dict(envelope['expected_hashes']);bad['signer.key']='a'*64
        with self.assertRaises(ValueError):self.c.migrate(self.expected,bad)
        self.assertFalse(self.calls)
        result=self.c.migrate(self.expected,envelope['expected_hashes'])
        self.assertTrue(result['redeploy_required'])
        self.assertEqual(self.c.account_record(self.expected)['service_uid'],record['service_uid'])
        self.assertEqual(self.c.digests(self.c.verify_identity(self.expected)),envelope['expected_hashes'])
        self.c.migrate(self.expected,envelope['expected_hashes'])
        self.assertFalse(any(call[0] in ('/usr/sbin/useradd','/usr/sbin/groupadd') for call in self.calls))

    def test_explicit_legacy_migration_preserves_missing_key_recovery_from_original_backup(self):
        envelope=self.original_identity()
        self.c.path('/etc/avalanchego/original-account.json').unlink()
        self.c.path('/etc/avalanchego/identity.json').unlink()
        self.c.write('/etc/avalanchego/contract.json',{k:v for k,v in self.expected.items() if k!='owner'})
        manifest=self.root/'var/lib/avalanchego/staking/identity.json'
        manifest.write_text(json.dumps(envelope['expected_hashes']));manifest.chmod(0o600)
        self.data_owners[manifest]=(999,999)
        missing=self.root/'var/lib/avalanchego/staking/signer.key';missing.unlink()
        self.c.migrate(self.expected,envelope['expected_hashes'])
        self.assertFalse(missing.exists())
        self.c.restore(self.expected,envelope)
        self.assertEqual(self.c.digests(self.c.verify_identity(self.expected)),envelope['expected_hashes'])

    def test_verified_legacy_uid_1001_is_preserved_and_a_later_2001_name_cannot_receive_keys(self):
        envelope=self.original_identity()
        self.c.path('/etc/avalanchego/original-account.json').unlink();self.c.path('/etc/avalanchego/identity.json').unlink()
        self.c.write('/etc/avalanchego/contract.json',{k:v for k,v in self.expected.items() if k!='owner'})
        self.users['avalanchego']=SimpleNamespace(pw_name='avalanchego',pw_uid=1001,pw_gid=1001,pw_dir='/var/lib/avalanchego',pw_shell='/usr/sbin/nologin')
        self.groups['avalanchego']=SimpleNamespace(gr_name='avalanchego',gr_gid=1001,gr_mem=[])
        for path in self.data_owners:self.data_owners[path]=(1001,1001)
        manifest=self.root/'var/lib/avalanchego/staking/identity.json'
        manifest.write_text(json.dumps(envelope['expected_hashes']));manifest.chmod(0o600);self.data_owners[manifest]=(1001,1001)
        previous=self.c.run
        def command(argv,**kwargs):
            if argv[:2]==['systemctl','show'] and '--property=User' in argv:return subprocess.CompletedProcess(argv,0,b'avalanchego',b'')
            return previous(argv,**kwargs)
        self.c.run=command
        self.c.migrate(self.expected,envelope['expected_hashes'])
        self.assertEqual(self.c.account_record(self.expected)['service_uid'],1001)
        missing=self.root/'var/lib/avalanchego/staking/signer.key';missing.unlink()
        self.users['avalanchego']=SimpleNamespace(**dict(vars(self.users['avalanchego']),pw_uid=2001))
        changes=len(self.descriptor_changes)
        with self.assertRaises(ValueError):self.c.restore(self.expected,envelope)
        self.assertEqual(len(self.descriptor_changes),changes);self.assertFalse(missing.exists())

    def test_different_inventory_owner_cannot_adopt_or_cancel_the_same_chain_host(self):
        self.c.prepare(self.expected);before=self.c.path('/etc/avalanchego/contract.json').read_bytes()
        other=dict(self.expected,owner='b'*64);self.calls.clear()
        for action in ('prepare','migrate','stop','destroy'):
            with self.assertRaises(ValueError):self.c.dispatch({'action':action,'contract':other,'expected_hashes':{}})
        self.assertFalse(self.calls)
        self.assertEqual(self.c.path('/etc/avalanchego/contract.json').read_bytes(),before)
        self.assertFalse(self.c.path('/etc/avalanchego/stopped').exists())

    def test_restore_resumes_only_original_staged_bytes_after_real_fsync_fault(self):
        envelope=self.original_identity();key=self.root/'var/lib/avalanchego/staking/signer.key';key.unlink()
        actual=os.fsync;attempts=[]
        def fail_pending(fd):
            candidate=key.with_name('signer.key.restore')
            if candidate.exists() and os.fstat(fd).st_ino==candidate.stat().st_ino:
                attempts.append(fd);raise OSError('inert pending key sync failure')
            return actual(fd)
        for _ in range(2):
            with patch.object(os,'fsync',side_effect=fail_pending):
                with self.assertRaises(OSError):self.c.restore(self.expected,envelope)
            self.assertFalse(key.exists())
        self.assertEqual(len(attempts),2)
        self.c.restore(self.expected,envelope)
        self.assertEqual(self.c.digests(self.c.verify_identity(self.expected)),envelope['expected_hashes'])
        self.assertFalse(key.with_name('signer.key.restore').exists())

    def test_partial_original_reservation_still_allows_owned_shutdown_attempts(self):
        self.c.prepare(self.expected)
        self.c.path('/etc/avalanchego/contract.json').unlink()
        self.c.path('/var/lib/avalanchego/staking').rmdir()
        self.calls.clear();self.c.cancel(self.expected,'stop')
        self.assertIn(['systemctl','stop','avalanchego.service'],self.calls)
        wrong=dict(self.expected,network='mainnet');self.calls.clear()
        with self.assertRaises(ValueError):self.c.cancel(wrong,'stop')
        self.assertFalse(self.calls)

    def test_canceled_intent_refuses_late_activation_after_first_fence_failure(self):
        self.c.prepare(self.expected);intent='a'*32
        self.c.write('/etc/avalanchego/lifecycle.json',{'contract':self.expected,'phase':'installed','intent':intent})
        actual=os.fsync;counter=[0]
        def fault(fd):
            counter[0]+=1
            if counter[0]==1:raise OSError('inert first fence failure')
            return actual(fd)
        with patch.object(os,'fsync',side_effect=fault):
            with self.assertRaises(ValueError):self.c.cancel(self.expected,'stop')
        self.calls.clear()
        with self.assertRaises(ValueError):self.c.activate(self.expected,intent)
        self.assertFalse(self.calls)

    def test_native_readonly_completion_precedes_identity_seal(self):
        self.c.prepare(self.expected)
        self.c.write('/etc/avalanchego/generation-started',{'contract':self.expected})
        for name in self.module.NAMES:
            path=self.root/'var/lib/avalanchego/staking'/name
            path.touch(mode=0o600);self.data_owners[path]=(999,999)
        def complete(_):
            for name in self.module.NAMES:
                path=self.root/'var/lib/avalanchego/staking'/name
                path.write_bytes(('inert-'+name).encode());path.chmod(0o400)
        with patch.object(self.module.time,'sleep',side_effect=complete) as sleep:
            self.c.seal(self.expected)
        self.assertEqual(sleep.call_count,1)
        self.c.verify_identity(self.expected)

    def test_consumed_empty_generation_can_retry_only_without_any_original_writer(self):
        self.c.prepare(self.expected)
        self.c.write('/etc/avalanchego/generation-started',{'contract':self.expected})
        process=self.root/'proc/42';process.mkdir();self.data_owners[process]=(999,999)
        with self.assertRaises(ValueError):self.c.authorize(self.expected)
        process.rmdir();self.c.authorize(self.expected)
        self.assertFalse(self.c.path('/etc/avalanchego/generation-started').exists())
        key=self.root/'var/lib/avalanchego/staking/staker.key';key.write_bytes(b'partial inert identity');key.chmod(0o600)
        self.data_owners[key]=(999,999)
        with self.assertRaises(ValueError):self.c.authorize(self.expected)

    def test_actual_installed_main_stop_does_not_require_writable_receipt_storage(self):
        self.c.prepare(self.expected);self.calls.clear()
        previous_umask=os.umask(0o077);os.umask(previous_umask)
        try:
            with patch.object(self.module,'Control',return_value=self.c), patch.object(self.module,'__file__','/usr/local/lib/erpc/avax/control.py'), \
                 patch.object(sys,'argv',['control.py','stop']), patch.object(self.module.os,'geteuid',return_value=0), \
                 patch.object(self.module.resource,'setrlimit'), patch.object(os,'fsync',side_effect=OSError('inert full storage failure')):
                with self.assertRaises(ValueError):self.module.main()
        finally:os.umask(previous_umask)
        for unit in self.module.UNITS:
            self.assertIn(['systemctl','stop',unit],self.calls)
            self.assertIn(['systemctl','disable',unit],self.calls)

if __name__=='__main__':unittest.main()
