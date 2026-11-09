#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit native-v1 upgrade with real records and inert NSS/PID1/native artifacts."""
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import deployment as fixtures
import native_accounts as accounts
import native_source_floor as floor
import native_mounts as mounts
import native_runtime_control as control
import native_files as files
VERIFY=accounts.verify
BUNDLE=None
if len(sys.argv)==3 and sys.argv[1]=='--bundle':
    with tarfile.open(sys.argv[2],mode='r:gz') as archive:
        inventory=json.load(archive.extractfile('inventory.yml'))
        BUNDLE=inventory['all']['hosts']['fixture']
        assert archive.getmember('ansible/solana-native/upgrade-source-authority.yml').isfile()
        assert archive.getmember('node/native_source_floor.py').isfile()
    sys.argv=sys.argv[:1]


class Upgrade(unittest.TestCase):
    def setUp(self):
        self.inner=fixtures.Cutover();self.inner.setUp();self.addCleanup(self.inner.doCleanups)
        patch.object(floor.units,'HELPERS',self.inner.root).start()
        self.inner.completed_candidate();self.inner.dispatch('begin-runtime')
        self.inner.dispatch('install-runtime',firewall={'run':'original','bundle':'d'*64})
        self.inner.dispatch('activate-runtime')
        self.state=self.inner.state;self.contract=self.inner.contract
        self.profile=json.loads(self.inner.raw)['networks'][self.contract['network']]
        # Build the pre-protocol fixture snapshot, as native v1 stored it. The
        # production upgrade never deletes floor records or strips protocol tags.
        self.state.remove(floor.COMPLETE);self.state.remove(floor.PENDING)
        original=self.state.get('accounts.json');original.pop('opening_protocol')
        self.state.put('accounts.json',original);self.state.put('accounts-intent.json',original)
        self.original=original
        self.payload=self.inner.data_paths['ledger']/'data'/'original-db'
        self.payload.write_bytes(b'inert original data, never opened by a node')
        self.document=json.dumps({'schema':1,'client':'agave','network':self.contract['network'],
            'version':self.profile['version'],'commit':self.profile['commit']})
        patch.object(accounts,'verify',side_effect=VERIFY).start()
        patch.object(accounts,'verify_slot',return_value=(None,None)).start()
        patch.object(accounts,'root_directory').start()
        patch.object(mounts,'inspect',return_value={}).start()
        patch.object(control,'systemctl',side_effect=self.inner.command).start()
        self.inner.calls.clear()

    def upgrade(self,document=None):
        return floor.upgrade(self.state,self.contract,self.document if document is None else document,
                             self.profile,self.inner.command)

    def test_native_upgrade_preserves_original_history_and_stops_runtime(self):
        original_active=self.state.get('active.json')
        result=self.upgrade()
        self.assertTrue(result['source_authority_upgraded']);self.assertFalse(result['runtime_started'])
        self.assertIn(['stop',floor.units.UNIT],self.inner.calls)
        self.assertFalse(any(call[0] in ('enable','start') for call in self.inner.calls))
        self.assertEqual(self.state.get('active.json'),original_active)
        self.assertFalse(self.state.runtime_is_current())
        self.assertEqual(self.state.get('accounts.json'),dict(self.original,opening_protocol=1))
        self.assertEqual(self.state.get('accounts-intent.json'),self.state.get('accounts.json'))
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],{name:self.profile[name] for name in floor.MINIMUM})
        self.assertEqual(self.payload.read_bytes(),b'inert original data, never opened by a node')
        self.assertEqual(self.state.get('opening-upgrade.json')['phase'],'complete')
        self.inner.calls.clear();self.inner.running=True
        self.assertTrue(self.upgrade()['already_upgraded'])
        self.assertEqual(self.inner.calls,[]);self.assertTrue(self.inner.running)

    def carried(self, request):
        operation=self.inner.root/'operation';operation.mkdir();lock=self.inner.root/'lock'
        real=os.fstat
        def metadata(fd):
            info=real(fd)
            if lock.exists() and info.st_ino==lock.stat().st_ino:
                values=list(info);values[4]=0;return os.stat_result(values)
            return info
        with patch.object(control,'STATE',self.state.directory),patch.object(control,'OPERATION_ROOT',operation), \
             patch.object(control,'LOCK',lock),patch.object(os,'fstat',side_effect=metadata):
            with self.assertRaisesRegex(ValueError,'sealed'):control.control(request)
            return control.control(request,carried=True)

    def test_actual_controller_carried_route_publishes_helpers_only_after_completed_upgrade(self):
        request={'action':'upgrade-source-authority','contract':self.contract,'original_client_record':self.document}
        result=self.carried(request)
        self.assertTrue(result['source_authority_upgraded'])
        self.assertEqual(self.state.get('helper-revision.json')['revision'],'c'*64)
        self.assertEqual(control.dispatch(self.state,self.contract,{'action':'opening-authority','contract':self.contract})['upgrade_phase'],'complete')

    def test_actual_rust_bundle_carries_the_same_explicit_original_record(self):
        if BUNDLE is None:self.skipTest('Rust bundle is supplied by the actual CLI regression')
        request=BUNDLE['solana_native_request']
        self.assertEqual(request['contract'],self.contract)
        self.assertEqual(json.loads(request['original_client_record']),json.loads(self.document))
        self.assertIn('trusted_imports',BUNDLE['solana_native_loader'])
        self.assertTrue(self.carried(request)['source_authority_upgraded'])

    def test_actual_ansible_task_templates_the_explicit_request_into_the_real_controller(self):
        try:
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:self.skipTest('qualified Ansible runtime is tested separately')
        path=Path(__file__).resolve().parents[1]/'templates/ansible/solana-native/upgrade-source-authority.yml'
        loader=DataLoader();task=loader.load_from_file(str(path))[0]['tasks'][0]
        request={'action':'upgrade-source-authority','contract':self.contract,'original_client_record':self.document}
        variables={'playbook_dir':str(path.parent),'solana_native_loader':'inert external loader','solana_native_request':request}
        rendered=Templar(loader=loader,variables=variables).template(task['ansible.builtin.command'])
        self.assertEqual(rendered['argv'][:4],['/usr/bin/python3','-I','-c','inert external loader'])
        self.assertEqual(Path(rendered['argv'][4]).resolve(),path.parents[2]/'node/native_runtime_control.py')
        self.assertEqual(rendered['argv'][5],'play')
        actual=json.loads(rendered['stdin']);self.assertEqual(actual,request)
        self.assertTrue(self.carried(actual)['source_authority_upgraded'])

    def test_failed_protocol_directory_sync_remains_stopped_and_same_original_upgrade_retries(self):
        real=os.fsync
        def fault(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and self.state.get('accounts.json').get('opening_protocol')==1:
                raise OSError('inert account protocol directory fsync failure')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fault),self.assertRaises(OSError):self.upgrade()
        self.assertFalse(self.inner.running)
        self.assertEqual(self.state.get('accounts.json')['opening_protocol'],1)
        self.assertEqual(self.state.get('opening-upgrade.json')['phase'],'prepared')
        self.assertFalse((self.state.directory/floor.COMPLETE).exists())
        original=self.state.get('opening-upgrade.json')
        changed=json.loads(self.document);changed['commit']='f'*40
        with self.assertRaises(ValueError):self.upgrade(json.dumps(changed))
        self.assertEqual(self.state.get('opening-upgrade.json'),original)
        self.assertTrue(self.upgrade()['source_authority_upgraded'])
        self.assertFalse(any(call[0] in ('start','enable') for call in self.inner.calls))

    def test_unknown_history_network_or_lower_record_refuses_before_stop_and_inventory_conversion(self):
        for key,value in [('schema',True),('client','jito'),('network','testnet'),('version','4.3.1'),('commit','f'*40),('extra','inert private decoy')]:
            request=json.loads(self.document);request[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.upgrade(json.dumps(request))
            self.assertEqual(self.inner.calls,[])
            self.assertEqual(self.state.get('accounts.json'),self.original)
            self.assertFalse((self.state.directory/'opening-upgrade.json').exists())

    def test_floor_commit_failure_keeps_protocol_barrier_and_retries_without_inference(self):
        real=self.state.put
        def fault(name,value):
            if name==floor.COMPLETE:raise OSError('inert floor creation failure')
            return real(name,value)
        with patch.object(self.state,'put',side_effect=fault),self.assertRaises(OSError):self.upgrade()
        self.assertEqual(self.state.get('accounts.json')['opening_protocol'],1)
        with self.assertRaisesRegex(ValueError,'incomplete'):floor.check(self.state,self.contract,floor.from_profile(self.profile))
        self.assertTrue(self.upgrade()['source_authority_upgraded'])
        self.assertEqual(self.payload.read_bytes(),b'inert original data, never opened by a node')

    def test_dangling_original_records_are_not_replaced_or_treated_as_absence(self):
        for name in ('opening-upgrade.json', 'active.json', 'accounts-intent.json', floor.COMPLETE, floor.PENDING):
            with self.subTest(name=name):
                path=self.state.directory/name
                original=path.read_bytes() if path.exists() else None
                if original is not None:path.unlink()
                path.symlink_to(self.inner.root/'missing-original')
                with self.assertRaisesRegex(ValueError,'indirect'):self.upgrade()
                self.assertTrue(path.is_symlink());self.assertEqual(self.inner.calls,[])
                path.unlink()
                if original is not None:path.write_bytes(original);path.chmod(0o600)

    def test_floor_written_before_journal_completion_does_not_authorize_ordinary_opening(self):
        real=self.state.put
        def fault(name,value):
            if name=='opening-upgrade.json' and value['phase']=='complete':
                raise OSError('inert final upgrade journal write failure')
            return real(name,value)
        with patch.object(self.state,'put',side_effect=fault),self.assertRaises(OSError):self.upgrade()
        self.assertTrue((self.state.directory/floor.COMPLETE).exists())
        self.assertFalse(self.inner.running)
        for operation in (floor.check,floor.claim):
            with self.subTest(operation=operation.__name__),self.assertRaisesRegex(ValueError,'incomplete'):
                operation(self.state,self.contract,floor.from_profile(self.profile))
        self.assertTrue(self.upgrade()['source_authority_upgraded'])
        floor.check(self.state,self.contract,floor.from_profile(self.profile))

    def test_completed_upgrade_cannot_reconstruct_missing_or_lowered_history(self):
        self.upgrade()
        original=self.state.get(floor.COMPLETE)
        lowered=dict(original,highest={'version':'4.3.1','commit':'f'*40})
        self.state.put(floor.COMPLETE,lowered)
        with self.assertRaisesRegex(ValueError,'below'):self.upgrade()
        self.state.remove(floor.COMPLETE)
        with self.assertRaisesRegex(ValueError,'missing'):self.upgrade()
        self.assertFalse((self.state.directory/floor.COMPLETE).exists())
        self.assertFalse(any(call[0] in ('start','enable') for call in self.inner.calls))


if __name__=='__main__':unittest.main()
