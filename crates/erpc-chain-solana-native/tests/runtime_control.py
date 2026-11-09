#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual state/unit files with inert systemd, NSS and artifact boundaries."""
import struct
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_runtime_control as control
import native_runtime_unit as units
import native_files as files
import native_state as lifecycle
import native_accounts as accounts
import native_deployment as deployment
from mounts import owner
from source_floor import prepare_fixture


class RuntimeControl(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.addCleanup(patch.stopall); self.root = Path(temporary.name)
        for name in ('HELPERS', 'UNITS', 'RELEASES', 'CUSTODY'):
            path = self.root / name.lower(); path.mkdir(); patch.object(units, name, path).start()
        patch.object(control, 'root_directory', lambda *_args, **_kwargs: None).start()
        patch.object(control, 'read', lambda p, n=1048576: files.read(p, n, os.getuid())).start()
        patch.object(lifecycle, 'read', lambda p, n: files.read(p, n, os.getuid())).start()
        self.quiet = patch.object(control.process.proc, 'assert_quiescent').start()
        patch.object(deployment, 'cancel_builds').start()
        patch.object(control.tuning, 'verify', return_value={}).start()
        self.contract = owner(); self.revision = 'a'*64; self.intent = 'b'*32
        self.catalog_bytes = (Path(__file__).resolve().parents[1] / 'templates/node/catalog.json').read_bytes()
        self.catalog = json.loads(self.catalog_bytes)
        helper = units.HELPERS / self.revision; helper.mkdir(); (helper / 'catalog.json').write_bytes(self.catalog_bytes)
        patch.object(control.helpers, 'verify', side_effect=lambda revision: units.HELPERS / revision).start()
        self.profile = self.catalog['networks']['mainnet']
        public = {'intent': self.intent, 'network': 'mainnet', 'version': self.profile['version'],
                  'commit': self.profile['commit'], 'catalog_sha256': hashlib.sha256(self.catalog_bytes).hexdigest()}
        self.receipt = {'build': {'schema': 1, 'request': public,
                        'source': {key: self.profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')}, 'files': {}},
                        'mode': 'sync', 'identity': '5'*44, 'helper_revision': self.revision,
                        'account': {'uid': 20001, 'gid': 20001}, 'cipher_sha256': 'c'*64, 'firewall': {'run': 'fixture', 'bundle': 'd'*64}}
        self.receipt['unit_sha256'] = hashlib.sha256(units.render(
            self.contract, self.catalog, self.intent, self.revision, 'sync', '5'*44, self.receipt['account']).encode()).hexdigest()
        directory = self.root / 'state'; directory.mkdir(); self.state = lifecycle.State(directory)
        self.state.reserve(self.contract)
        plan = {role: {'name': name, 'home': home, 'shell': accounts.SHELL, 'uid': 20001 + index, 'gid': 20001 + index}
                for index, (role, (name, home)) in enumerate(accounts.SPECS.items())}
        self.state.put('accounts.json', {'contract': self.contract, 'accounts': plan, 'opening_protocol': 1})
        self.plan = plan
        self.data_paths = prepare_fixture(self.state, self.contract, self.root, plan['node'])
        control.source_floor.claim(self.state, self.contract, control.source_floor.from_profile(self.profile))
        self.receipt['unit_sha256'] = hashlib.sha256(units.render(
            self.contract, self.catalog, self.intent, self.revision, 'sync', '5'*44, self.receipt['account']).encode()).hexdigest()
        target = dict(public, mode='sync', identity='5'*44)
        self.state.authorize(self.contract, self.intent, target, 'deploy')
        self.state.begin(self.contract, self.intent, lambda: None)
        self.state.publish(self.contract, self.intent, self.receipt)
        self.state.consume(self.contract, self.intent)
        self.definition = units.render(self.contract, self.catalog, self.intent, self.revision, 'sync', '5'*44, self.receipt['account'])
        (units.UNITS / units.UNIT).write_text(self.definition)
        self.calls = []; self.running = True

    def command(self, args, **_kwargs):
        self.calls.append(args)
        if args[0] == 'show':
            if args[2:] == ['--property=LoadState', '--value']: return 'not-found\n'
            data = {'LoadState': 'loaded', 'ActiveState': 'active' if self.running else 'inactive',
                    'SubState': 'running' if self.running else 'dead', 'MainPID': '123' if self.running else '0',
                    'FragmentPath': str(units.UNITS / units.UNIT), 'DropInPaths': '',
                    'User': '20001', 'Group': '20001', 'NeedDaemonReload': 'no'}
            return ''.join(k + '=' + v + '\n' for k, v in data.items())
        if args[0] == 'stop': self.running = False
        if args[0] == 'start': self.running = True
        return ''

    def dispatch(self, action, **kwargs):
        return control.dispatch(self.state, self.contract, {'action': action, 'contract': self.contract},
                                kwargs.get('run', self.command))

    def test_sync_and_validator_units_have_distinct_credentials_and_native_history_policy(self):
        sync = shlex.split(next(line[10:] for line in self.definition.splitlines() if line.startswith('ExecStart=')))
        self.assertIn('--no-voting', sync); self.assertNotIn('--vote-account', sync)
        self.assertIn('8000-8032', sync); self.assertIn('--no-xdp', sync)
        self.assertIn('--limit-blockstore-size', sync)
        active = units.render(self.contract, self.catalog, self.intent, self.revision, 'validator', self.contract['identity_account'], self.receipt['account'])
        self.assertIn('--require-tower', active); self.assertNotIn('--no-voting', active)
        self.assertIn('--process-ledger-before-services', active)
        self.assertIn('TimeoutStartSec=180\n', active)
        self.assertNotIn('--process-ledger-before-services', sync)
        self.assertNotIn('--do-not-require-vote-history', active)
        self.assertIn('LoadCredentialEncrypted=identity:', active)
        self.assertIn('/validator.cred', active); self.assertIn('/sync.cred', self.definition)
        self.assertIn('ExecStartPre=+/usr/bin/python3 -I -c ', active)
        self.assertIn('ExecCondition=+/usr/bin/python3 -I -c ', active)
        self.assertIn('User=20001\nGroup=20001\n', active)
        self.assertIn('SendSIGKILL=no', active); self.assertIn('CapabilityBoundingSet=\n', active)
        for mode, identity in [('sync', self.contract['identity_account']), ('validator', '5'*44), ('rpc', '5'*44)]:
            with self.assertRaises(ValueError): units.arguments(self.contract, self.catalog, self.intent, mode, identity)

    def test_each_qualified_validator_preserves_native_history_checks_before_services(self):
        for network in ('mainnet', 'testnet'):
            contract = dict(self.contract, network=network)
            argv = units.arguments(contract, self.catalog, self.intent, 'validator', contract['identity_account'])
            self.assertEqual(argv.count('--process-ledger-before-services'), 1)
            self.assertEqual(argv.count('--require-tower'), 1)
            self.assertEqual(argv[argv.index('--tower') + 1], str(units.MOUNTS['ledger'] / 'data'))
            self.assertFalse(any(value in argv for value in ('--no-voting', '--do-not-require-vote-history',
                                                            '--no-wait-for-vote-to-start-leader')))

    def test_active_source_mode_and_public_identity_are_bound_before_host_calls(self):
        active = self.state.guard(self.contract)
        self.assertEqual(control.selected(self.contract, active)[3], self.definition)
        for field, value in [('mode', 'validator'), ('identity', self.contract['identity_account'])]:
            changed = copy.deepcopy(active); changed['target'][field] = value
            with self.assertRaises(ValueError): control.selected(self.contract, changed)
        changed = copy.deepcopy(active); changed['receipt']['build']['request']['commit'] = 'e'*40
        with self.assertRaises(ValueError): control.selected(self.contract, changed)
        self.assertEqual(self.calls, [])

    def test_voting_receipt_cannot_reuse_an_unregistered_sync_approval(self):
        active = self.state.guard(self.contract)
        active['target'].update(mode='validator',identity=self.contract['identity_account'])
        active['receipt'].update(mode='validator',identity=self.contract['identity_account'])
        with self.assertRaisesRegex(ValueError,'registration and native BLS proof'):
            control.selected(self.contract,active)
        self.assertEqual(self.calls,[])

    def test_rpc_profile_cannot_be_promoted_to_a_validator_or_load_financial_accounts(self):
        rpc = dict(self.contract, profile='agave-native-rpc', vote_account=None, authority_account=None)
        argv = units.arguments(rpc, self.catalog, self.intent, 'rpc', rpc['identity_account'])
        self.assertIn('--no-voting', argv); self.assertNotIn('--vote-account', argv)
        self.assertIn('--enable-rpc-transaction-history', argv)
        self.assertIn('--enable-extended-tx-metadata-storage', argv)
        for mode in ('sync', 'validator'):
            with self.assertRaises(ValueError): units.arguments(rpc, self.catalog, self.intent, mode, rpc['identity_account'])
        for name in ('vote_account', 'authority_account'):
            with self.assertRaises(ValueError): units.arguments(dict(rpc, **{name: '3'*44}), self.catalog, self.intent, 'rpc', rpc['identity_account'])

    def test_stop_and_destroy_work_without_runtime_key_mount_or_nss_qualification(self):
        (units.HELPERS / self.revision / 'catalog.json').unlink()
        for action in ('stop', 'destroy'):
            self.running = True; self.calls.clear()
            with patch.object(control, 'qualify', side_effect=AssertionError('custody unavailable')):
                result = self.dispatch(action)
            self.assertTrue(result['data_preserved']); self.assertFalse(self.running)
            self.assertIn(['disable', units.UNIT], self.calls)
            with self.assertRaises(ValueError): self.state.guard(self.contract)
            self.assertTrue((self.state.directory / 'active.json').exists())

    def test_first_fence_write_failure_still_stops_and_disables_without_success(self):
        original = self.state.put
        def failed(name, value):
            if name == 'halt.json': raise OSError('inert unavailable storage')
            original(name, value)
        with patch.object(self.state, 'put', failed):
            with self.assertRaises(OSError): self.dispatch('stop')
        self.assertFalse(self.running); self.assertIn(['disable', units.UNIT], self.calls)
        self.state.guard(self.contract)  # Failed persistence must not be claimed durable.

    def test_failed_service_stop_still_disables_and_preserves_original_records(self):
        before = (self.state.directory / 'active.json').read_bytes()
        def failed(args, **kwargs):
            if args[0] == 'stop': self.calls.append(args); raise ValueError('inert systemd failure')
            return self.command(args, **kwargs)
        with self.assertRaises(ValueError): self.dispatch('stop', run=failed)
        self.assertIn(['disable', units.UNIT], self.calls)
        self.assertEqual((self.state.directory / 'active.json').read_bytes(), before)

    def test_unknown_unit_or_foreign_contract_is_never_stop_authority(self):
        before = self.state.halt()
        with self.assertRaises(ValueError):
            control.dispatch(self.state, self.contract, {'action': 'stop', 'contract': dict(self.contract, name='foreign')}, self.command)
        self.assertEqual(self.state.halt(), before); self.assertEqual(self.calls, [])
        (units.UNITS / units.UNIT).write_text('[Service]\nExecStart=/inert/foreign\n')
        with self.assertRaises(ValueError): self.dispatch('stop')
        self.assertEqual(self.calls, [['show', 'erpc-solana-proof.service', '--property=LoadState', '--value']])

    def test_unknown_dropin_and_stale_manager_definitions_refuse(self):
        folder = units.UNITS / (units.UNIT + '.d'); folder.mkdir(); (folder / '99-foreign.conf').write_text('inert')
        with self.assertRaises(ValueError): self.dispatch('stop')
        self.assertEqual(self.calls, [['show', 'erpc-solana-proof.service', '--property=LoadState', '--value']])
        def stale(args, **kwargs): return self.command(args, **kwargs).replace('NeedDaemonReload=no', 'NeedDaemonReload=yes')
        with self.assertRaises(ValueError): control.service(self.plan['node'], stale)

    def qualification_fixture(self):
        paths = self.data_paths
        # The unit's paths must be regenerated for this temporary fixture.
        self.definition = units.render(self.contract, self.catalog, self.intent, self.revision, 'sync', '5'*44, self.receipt['account'])
        (units.UNITS / units.UNIT).write_text(self.definition)
        node = self.plan['node']
        original_lstat = Path.lstat
        def metadata(path, *args, **kwargs):
            value = original_lstat(path, *args, **kwargs)
            if path in [root / 'data' for root in paths.values()]:
                fields = list(value); fields[4] = node['uid']; fields[5] = node['gid']
                return os.stat_result(fields)
            return value
        patch.object(Path, 'lstat', metadata).start()
        patch.object(control.accounts, 'verify', return_value=dict(self.plan, node=node)).start()
        patch.object(control.host, 'capacity').start()
        self.publication = patch.object(control.publish, 'verify').start()
        self.ingress = patch.object(control, 'firewall').start()
        cipher = units.CUSTODY / 'sync.cred'; cipher.write_bytes(b'inert ciphertext'); cipher.chmod(0o600)
        active = self.state.guard(self.contract)
        active['receipt']['cipher_sha256'] = hashlib.sha256(cipher.read_bytes()).hexdigest()
        active['receipt']['unit_sha256'] = hashlib.sha256(self.definition.encode()).hexdigest()
        self.state.put('active.json', active)
        return paths, cipher

    def test_actual_guard_checks_private_data_and_cipher_before_quiescence(self):
        paths, cipher = self.qualification_fixture()
        control.guard(self.state, self.contract, self.command)
        self.publication.assert_called_once(); self.ingress.assert_called_once()
        self.quiet.assert_called_once_with(self.plan['node']['uid'])
        self.quiet.reset_mock(); cipher.chmod(0o644)
        with self.assertRaises(ValueError): control.guard(self.state, self.contract, self.command)
        self.quiet.assert_not_called(); cipher.chmod(0o600)
        cipher.write_bytes(b'different inert ciphertext')
        with self.assertRaises(ValueError): control.guard(self.state, self.contract, self.command)
        cipher.write_bytes(b'inert ciphertext'); (paths['ledger'] / 'data').chmod(0o755)
        with self.assertRaises(ValueError): control.guard(self.state, self.contract, self.command)
        self.quiet.assert_not_called()

    def test_start_qualifies_before_enable_and_status_binds_the_kernel_proof(self):
        self.qualification_fixture()
        self.dispatch('stop'); self.calls.clear()
        real_inspect = control.observer.inspect
        def inspect(profile, identity, prove):
            replies = {'getGenesisHash': profile['genesis'], 'getIdentity': {'identity': identity},
                       'getVersion': {'solana-core': profile['version']}, 'getHealth': 'ok',
                       'getAccountInfo': {'value': {'data': [base64.b64encode(struct.pack('<QqQQq', 99, 0, 0, 0, 1000)).decode(), 'base64']}}}
            return real_inspect(profile, identity, prove, lambda method, params: replies[method], lambda: 1020)
        with patch.object(control.observer, 'inspect', inspect), patch.object(control.process, 'prove', return_value=(123, 99, 1, 2)) as proved:
            result = self.dispatch('start')
            self.assertTrue(result['observation']['rpc_ready'])
            self.assertEqual(proved.call_count, 2)
            self.assertEqual(proved.call_args.args[:3], (123, self.plan['node']['uid'], self.plan['node']['gid']))
        self.assertIn(['enable', units.UNIT], self.calls)
        self.dispatch('stop'); self.calls.clear()
        with patch.object(control, 'qualify', side_effect=ValueError('inert invalid custody')):
            with self.assertRaises(ValueError): self.dispatch('start')
        self.assertNotIn(['enable', units.UNIT], self.calls)
        self.assertIn(['stop', units.UNIT], self.calls)

    def test_first_condition_checks_actual_original_nss_before_modelled_credentials(self):
        original_verify = accounts.verify
        self.qualification_fixture()
        users = {value['name']: SimpleNamespace(pw_name=value['name'], pw_uid=value['uid'], pw_gid=value['gid'],
                    pw_dir=value['home'], pw_shell=value['shell']) for value in self.plan.values()}
        groups = {value['name']: SimpleNamespace(gr_name=value['name'], gr_gid=value['gid'], gr_mem=[])
                  for value in self.plan.values()}
        # Same runtime name now resolves to a different principal. The original
        # account receipt remains unchanged and actual verify_slot rejects it.
        users['erpc-solana'].pw_uid = 50001; users['erpc-solana'].pw_gid = 50001
        original_service = control.service
        def lookup(values, key, field):
            for value in values.values():
                if getattr(value, field) == key: return value
            raise KeyError(key)
        granted = []
        actual_fstat = os.fstat
        state_inode = self.state.directory.stat().st_ino
        def root_state_metadata(fd):
            info = actual_fstat(fd)
            if info.st_ino == state_inode and stat.S_ISDIR(info.st_mode):
                fields = list(info); fields[4] = 0
                return os.stat_result(fields)
            return info
        with patch.object(accounts, 'verify', original_verify), patch.object(accounts, 'root_directory'), \
             patch.object(accounts.pwd, 'getpwnam', lambda name: users[name]), \
             patch.object(accounts.pwd, 'getpwuid', lambda uid: lookup(users, uid, 'pw_uid')), \
             patch.object(accounts.pwd, 'getpwall', lambda: list(users.values())), \
             patch.object(accounts.grp, 'getgrnam', lambda name: groups[name]), \
             patch.object(accounts.grp, 'getgrgid', lambda gid: lookup(groups, gid, 'gr_gid')), \
             patch.object(accounts.grp, 'getgrall', lambda: list(groups.values())), \
             patch.object(accounts.os, 'getgrouplist', lambda name, gid: [gid]), \
             patch.object(control, 'load', return_value=(self.state, self.contract)), \
             patch.object(control, 'service', side_effect=lambda account, _run: original_service(account, self.command)), \
             patch.object(control.sys, 'platform', 'linux'), patch.object(control.os, 'geteuid', return_value=0), \
             patch.object(control.os, 'fstat', side_effect=root_state_metadata), \
             patch.object(control.resource, 'setrlimit'), patch.object(control.os, 'umask'), \
             patch.object(control.sys, 'argv', ['runtime', 'condition']):
            # v255 service.c writes credentials at start-pre, not at the first
            # ExecCondition. Model only that source-qualified manager ordering;
            # invoke the real controller/NSS verifier before the grant boundary.
            with self.assertRaises(ValueError):
                self.assertEqual(self.definition.count('ExecCondition='), 1)
                control.main()
                granted.append(50001)
            self.assertEqual(granted, [])
            users['erpc-solana'].pw_uid = 20001; users['erpc-solana'].pw_gid = 20001
            control.main()
            granted.append(int(next(line[5:] for line in self.definition.splitlines() if line.startswith('User='))))
        self.assertEqual(granted, [20001])
        self.assertIn('User=20001\nGroup=20001\n', self.definition)

    def test_skipped_condition_is_not_reported_as_an_applied_start(self):
        self.qualification_fixture(); self.dispatch('stop'); self.calls.clear()
        def skipped(args, **kwargs):
            if args[0] == 'start': self.calls.append(args); return ''
            return self.command(args, **kwargs)
        with self.assertRaisesRegex(ValueError, 'condition or service did not start'):
            self.dispatch('start', run=skipped)
        self.assertIn(['disable', units.UNIT], self.calls)
        with self.assertRaises(ValueError): self.state.guard(self.contract)

    def test_pending_observation_does_not_revive_a_stopped_build(self):
        intent = 'e' * 32
        self.state.authorize(self.contract, intent, {'public': 'fixture'}, 'update')
        self.assertTrue(self.dispatch('deployment')['pending']['current'])
        self.dispatch('stop')
        observation = self.dispatch('deployment')
        self.assertEqual(observation['pending']['intent'], intent)
        self.assertFalse(observation['pending']['current'])
        with self.assertRaises(ValueError): self.state.current(self.contract, intent)

    def test_plan_snapshot_reads_public_approval_without_writing_state_or_custody(self):
        access={'controller':'192.0.2.2','ssh_port':22,'management':[],'rpc':[]}
        self.state.put('firewall-preparation-'+self.intent+'.json',
            {'contract':self.contract,'intent':self.intent,'access':access})
        before={path.name:(path.stat().st_ino,path.stat().st_mtime_ns,path.read_bytes())
                for path in self.state.directory.iterdir()}
        result=self.dispatch('deployment')
        self.assertTrue(result['approved']['authorized'])
        self.assertEqual(result['approved']['access'],access)
        self.assertNotIn('receipt',result['approved']);self.assertNotIn('cipher_sha256',json.dumps(result))
        after={path.name:(path.stat().st_ino,path.stat().st_mtime_ns,path.read_bytes())
               for path in self.state.directory.iterdir()}
        self.assertEqual(before,after);self.assertEqual(self.calls,[])
        self.dispatch('stop')
        self.assertFalse(self.dispatch('deployment')['approved']['authorized'])

    def test_logs_use_only_the_owned_fixed_unit_and_bounded_structured_output(self):
        request = {'action': 'logs', 'contract': self.contract, 'lines': 2}
        with patch.object(control.subprocess, 'run', return_value=SimpleNamespace(returncode=0,
                stdout=b'{"MESSAGE":"first"}\n{"MESSAGE":"second"}\n', stderr=b'')) as run:
            result = control.dispatch(self.state, self.contract, request)
            self.assertEqual([value['MESSAGE'] for value in result['entries']], ['first', 'second'])
            self.assertEqual(run.call_args.args[0], ['/usr/bin/journalctl', '--unit=' + units.UNIT,
                '--no-pager', '--output=json', '--lines=2'])
            for lines in [0, 1001, True, '2; touch /tmp/forbidden']:
                with self.assertRaises(ValueError):
                    control.dispatch(self.state, self.contract, dict(request, lines=lines))
            self.assertEqual(run.call_count, 1)
            run.return_value.stdout = b'{"MESSAGE":"first"}\n' * 3
            with self.assertRaises(ValueError): control.dispatch(self.state, self.contract, request)

    def test_receipted_account_and_loaded_numeric_recipient_cannot_be_redirected(self):
        self.qualification_fixture()
        def wrong(args, **kwargs):
            return self.command(args, **kwargs).replace('User=20001', 'User=erpc-solana')
        with self.assertRaises(ValueError): control.service(self.plan['node'], wrong)
        active = self.state.guard(self.contract)
        active['receipt']['account'] = {'uid': 50001, 'gid': 50001}
        changed = units.render(self.contract, self.catalog, self.intent, self.revision, 'sync', '5'*44,
                               active['receipt']['account'])
        active['receipt']['unit_sha256'] = hashlib.sha256(changed.encode()).hexdigest()
        (units.UNITS / units.UNIT).write_text(changed)
        self.state.put('active.json', active)
        with self.assertRaisesRegex(ValueError, 'credential recipient'):
            control.guard(self.state, self.contract, self.command)

    def test_component_logs_bind_builds_to_original_receipts_and_preserve_role_boundaries(self):
        request={'action':'logs','contract':self.contract,'lines':5,'component':'build','intent':self.intent}
        authority=deployment.build_authority(self.contract,self.intent,self.revision,self.plan['builder'])
        self.state.put('build-authority-'+self.intent+'.json',authority)
        with patch.object(control.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')) as run:
            result=control.dispatch(self.state,self.contract,request)
            self.assertEqual(result['units'],['erpc-solana-'+phase+'-'+self.intent+'.service' for phase in ('fetch','compile')])
            self.assertEqual(len(run.call_args.args[0]),6)
            for changed in [dict(request,intent='not-a-token'),dict(request,component='gateway'),
                            dict(request,component='firewall')]:
                with self.assertRaises(ValueError):control.dispatch(self.state,self.contract,changed)
            self.assertEqual(run.call_count,1)
            request.pop('intent');request['component']='firewall'
            self.assertEqual(control.dispatch(self.state,self.contract,request)['units'],['erpc-solana-native-firewall.service'])


if __name__ == '__main__': unittest.main()
