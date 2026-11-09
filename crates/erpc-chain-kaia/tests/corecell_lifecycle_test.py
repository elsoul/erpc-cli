# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual owned controller dispatch with deterministic custody and inert native tools."""
import copy
import hashlib
import json
import os
import stat
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import lifecycle_test as fixtures
c=fixtures.c
class CoreLifecycle(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        (c.ROOT/'owner.json').unlink();c.ROOT.rmdir()
        self.request=dict(self.fixture.state,role='validator',node_kind='cn',advertise='10.1.2.1',
            peers=['kni://'+'a'*128+'@10.1.2.2:32323?discport=0&ntype=cn','kni://'+'b'*128+'@10.1.2.3:32323?discport=0&ntype=pn'],
            reward_address='0x'+'d'*40,manager_address='0x'+'e'*40,staking_address='',gc_id='17',intent='b'*32,service_uid=995,service_gid=995)
        c.prepare(dict(self.request,action='prepare'))
        machine=c.TRUST_ANCHOR/'machine-id';machine.write_text('a'*32)
        patch.object(c.custody,'MACHINE_ID',machine).start()
        patch.object(c.custody.secrets,'token_bytes',return_value=hashlib.sha256(b'public core lifecycle fixture').digest()).start()
        patch.object(c,'run',side_effect=self.command).start()
        self.public={'address':'0x'+'f'*40,'peer_key':'c'*128,'bls_key':'a'*96,'bls_pop':'b'*192}
    def command(self,argv,**kwargs):
        if argv[:2]==['systemd-creds','encrypt']:
            path=Path(argv[-1]);path.write_bytes(b'inert sealed:'+kwargs['input']);path.chmod(0o600);return b''
        if argv[:2]==['systemd-creds','decrypt']:return Path(argv[-2]).read_bytes().removeprefix(b'inert sealed:')
        if argv[0]=='timedatectl':return b'yes'
        return self.fixture.command(argv,**kwargs)
    def call(self,action,private=False,**extra):
        return c.locked(dict(self.request,action=action,**extra),custody_mode=private)
    def backed_up(self):
        raw=self.call('custody-create',True)
        self.call('custody-confirm',True,backup_digest=hashlib.sha256(raw).hexdigest(),public=self.public)
        return raw
    def test_visible_custody_receipt_never_bypasses_persistent_root_fsync_failure(self):
        actual=os.fsync;attempts=[];root=c.ROOT.stat();encrypted=[];command=self.command
        def record_command(argv,**kwargs):
            if argv[:2]==['systemd-creds','encrypt']:encrypted.append(kwargs['input'])
            return command(argv,**kwargs)
        def fault(descriptor):
            info=os.fstat(descriptor);owner=c.ROOT/'owner.json'
            if (stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(root.st_dev,root.st_ino)
                    and owner.exists() and 'custody_digest' in json.loads(owner.read_text())):
                attempts.append('root');raise OSError('inert persistent owner directory durability failure')
            return actual(descriptor)
        with patch.object(c,'run',side_effect=record_command),patch.object(os,'fsync',side_effect=fault):
            with self.assertRaises(OSError):self.call('custody-create',True)
            before=c.state_read();pending=c.ROOT/'identity/corecell.pending';cipher=pending.read_bytes()
            first=len(attempts)
            with self.assertRaises(OSError):self.call('custody-create',True)
            self.assertGreater(len(attempts),first)
            self.assertEqual(pending.read_bytes(),cipher)
            self.assertFalse((c.ROOT/'identity/corecell.cred').exists())
        with patch.object(c.custody.secrets,'token_bytes',side_effect=AssertionError('original regenerated')):
            restored=self.call('custody-create',True)
        self.assertEqual(len(encrypted),1);self.assertEqual(restored,encrypted[0])
        self.assertEqual((c.ROOT/'identity/corecell.cred').read_bytes(),cipher)
        self.assertEqual(c.state_read()['custody_digest'],before['custody_digest'])
        self.assertEqual(c.state_read()['custody_cipher'],before['custody_cipher'])

    def test_private_export_resynchronizes_ancestor_and_rejects_stale_custody_receipt(self):
        raw=self.backed_up();path=c.ROOT/'identity/corecell.cred';cipher=path.read_bytes()
        actual=os.fsync;anchor=c.TRUST_ANCHOR.stat()
        def failed_ancestor(descriptor):
            info=os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(anchor.st_dev,anchor.st_ino):
                raise OSError('inert ancestor durability failure')
            return actual(descriptor)
        with patch.object(os,'fsync',side_effect=failed_ancestor):
            for action in ('custody-create','custody-export'):
                with self.assertRaises(OSError):self.call(action,True)
        self.assertEqual(path.read_bytes(),cipher);self.assertEqual(self.call('custody-export',True),raw)
        old=c.state_read();changed=dict(old,custody_digest='f'*64);c.save(changed)
        with patch.object(c,'run',side_effect=AssertionError('stale owner must not decrypt')):
            with self.assertRaises(c.Refused):c.custody.read(c,old)

    def test_original_key_enrollment_can_precede_peers_but_deploy_cannot(self):
        approved=self.request['peers'];self.request['peers']=[]
        state=c.state_read();state['peers']=[];c.save(state)
        raw=self.backed_up();self.assertEqual(self.call('custody-export',True),raw)
        self.call('authorize-deploy')
        with self.assertRaisesRegex(c.Refused,'enroll the original'):self.call('begin-install')
        self.assertEqual(c.state_read()['phase'],'prepared')
        self.request['peers']=approved;self.call('authorize-deploy');self.call('begin-install')
        self.assertEqual(c.state_read()['phase'],'installing')
        self.assertEqual(c.state_read()['target']['peers'],approved)

    def test_missing_backup_refuses_before_install_fence_and_explicit_retry_can_complete(self):
        self.call('authorize-deploy')
        with self.assertRaises(c.Refused):self.call('begin-install')
        self.assertEqual(c.state_read()['phase'],'prepared');self.assertNotIn('target',c.state_read())
        self.backed_up();self.call('begin-install');self.assertEqual(c.state_read()['phase'],'installing')
    def test_custody_exports_only_over_explicit_private_dispatch_and_scope_is_immutable(self):
        raw=self.backed_up()
        with self.assertRaises(c.Refused):self.call('custody-export')
        self.assertEqual(self.call('custody-export',True),raw)
        for change in ({'network':'mainnet'},{'node_kind':'pn'},{'advertise':'10.1.2.9'},{'owner':'foreign'}):
            with self.assertRaises(c.Refused):self.call('custody-export',True,**change)
        self.assertEqual(self.call('custody-export',True),raw)
    def test_stopped_same_host_recovery_preserves_original_and_foreign_capsule_never_stops(self):
        raw=self.backed_up();changed=json.loads(raw);changed['owner']='foreign'
        with patch.object(c,'cancel_and_stop') as stop:
            with self.assertRaises(c.Refused):self.call('custody-restore',True,material=json.dumps(changed))
            stop.assert_not_called()
        path=c.ROOT/'identity/corecell.cred';path.unlink()
        result=self.call('custody-restore',True,material=raw.decode())
        self.assertTrue(result['identity_preserved']);self.assertTrue(c.state_read()['startup_revoked'])
        self.assertEqual(self.call('custody-export',True),raw)
    def test_native_roles_use_correct_executable_flags_without_wallet_unlock_or_governance_http(self):
        self.backed_up()
        for kind in ('cn','pn'):
            state=dict(c.state_read(),node_kind=kind)
            if kind=='pn':state.update(reward_address='',manager_address='',staking_address='',gc_id='0')
            args=c.arguments(state)
            self.assertEqual('--gasless.disable' in args,kind=='cn')
            self.assertIn('--auction.disable',args);self.assertIn('--bls-nodekey=/identity/bls-nodekey',args)
            self.assertTrue(all(not item.startswith(('--unlock','--nodekeyhex','--bls-nodekeyhex','--nodetype')) for item in args))
            self.assertFalse(any('istanbul' in item or 'admin' in item for item in args))
    def test_time_selection_preserves_existing_chrony_and_reports_only_fixed_fallback(self):
        with patch.object(c,'active',side_effect=lambda name:'active' if name=='chrony.service' else 'inactive'):
            self.assertEqual(self.call('time-service'),{'service':'chrony.service','install':False})
        with patch.object(c,'active',return_value='inactive'),patch.object(c,'loaded',return_value=False):
            self.assertEqual(self.call('time-service'),{'service':'systemd-timesyncd.service','install':True})
    def test_updated_configuration_cannot_make_consensus_identity_the_financial_manager(self):
        self.backed_up();state=c.state_read();state['manager_address']=self.public['address']
        with self.assertRaises(c.Refused):c.corecell.configuration(c,state)
    def test_custody_receipt_write_failure_reuses_the_same_staged_original(self):
        original=c.os.fsync;calls=[0]
        def fail(fd):
            calls[0]+=1
            if calls[0]==6:raise OSError('inert receipt fsync failure')
            return original(fd)
        with patch.object(c.os,'fsync',side_effect=fail):
            with self.assertRaises(OSError):self.call('custody-create',True)
        pending=c.ROOT/'identity/corecell.pending';before=pending.read_bytes()
        with patch.object(c.custody.secrets,'token_bytes',side_effect=AssertionError('regenerated original')):
            raw=self.call('custody-create',True)
        self.assertEqual((c.ROOT/'identity/corecell.cred').read_bytes(),before)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),c.state_read()['custody_digest'])

    def test_native_execute_materializes_originals_and_binds_legacy_and_instance_peer_paths(self):
        self.backed_up();state=c.state_read();state.update(service_uid=995,service_gid=995)
        for kind in ('cn','pn'):
            selected=dict(state,node_kind=kind)
            if kind=='pn':selected.update(reward_address='',manager_address='',staking_address='',gc_id='0')
            with patch.object(c,'guard') as guard,patch.object(c.custody,'materialize') as materialize,patch.object(c.os,'execve') as execute:
                c.execute(selected)
                guard.assert_called_once_with(selected)
                materialize.assert_called_once()
                argv=execute.call_args.args[1]
                self.assertIn('--entrypoint=/klaytn-docker-pkg/bin/k'+kind,argv)
                self.assertIn('--user=995:995',argv);self.assertIn('--ulimit=core=0:0',argv)
                self.assertIn('--volume='+str(c.CORE_RUNTIME)+':/identity:ro',argv)
                for name in ('static-nodes.json','trusted-nodes.json'):
                    for prefix in ('','klay/'):
                        self.assertIn('--volume='+str(c.CONF/name)+':/data/'+prefix+name+':ro',argv)
                self.assertFalse(any(value.startswith(('--group-add','--privileged','--nodekeyhex','--bls-nodekeyhex')) for value in argv))

    def test_clock_failure_refuses_consensus_start_but_does_not_block_owned_stop(self):
        self.backed_up();state=c.state_read();state.update(phase='installed',installed=c.pin(state),startup_revoked=False)
        c.save(state)
        with patch.object(c,'run',side_effect=lambda argv,**kwargs:b'no' if argv[0]=='timedatectl' else self.command(argv,**kwargs)):
            with self.assertRaisesRegex(c.Refused,'synchronized host time'):c.guard(state)
            self.assertTrue(self.call('stop')['data_preserved']);self.assertTrue(c.state_read()['startup_revoked'])

if __name__=='__main__':unittest.main()
