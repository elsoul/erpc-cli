#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Build intent/cache boundaries with real durable state and inert build tools."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_deployment as deploy
import native_files as files
import native_state as lifecycle
import native_runtime_control as control
from mounts import owner
from source_floor import prepare_fixture


class DeploymentFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temporary.name); directory = self.root / 'state'; directory.mkdir()
        self.source = self.root / ('c'*64); self.source.mkdir()
        self.raw = (Path(__file__).resolve().parents[1] / 'templates/node/catalog.json').read_bytes()
        (self.source / 'catalog.json').write_bytes(self.raw)
        patch.object(lifecycle, 'read', lambda path, size: files.read(path, size, os.getuid())).start()
        patch.object(lifecycle, 'sync_file', lambda path: files.sync_file(path, os.getuid())).start()
        patch.object(deploy, 'read', lambda path, size=1048576: files.read(path, size, os.getuid())).start()
        patch.object(deploy, 'sync_file', lambda path: files.sync_file(path, os.getuid())).start()
        patch.object(deploy.helpers, 'verify', return_value=self.source).start()
        patch.object(deploy.helpers, 'publish', return_value='c'*64).start()
        patch.object(deploy.accounts, 'verify', side_effect=lambda *_: self.plan).start()
        patch.object(deploy.jobs, 'TOOLCHAINS', self.root / 'toolchains').start()
        patch.object(deploy, 'root_directory', lambda path, create=False: path.mkdir(exist_ok=True) if create else None).start()
        self.contract = getattr(self, 'fixture_contract', None) or owner(); self.intent = 'a'*32
        self.state = lifecycle.State(directory); self.state.reserve(self.contract)
        plan = {role: {'name': name, 'home': home, 'shell': deploy.accounts.SHELL, 'uid': 20001 + index, 'gid': 20001 + index}
                for index, (role, (name, home)) in enumerate(deploy.accounts.SPECS.items())}
        self.plan = plan
        self.state.put('accounts.json', {'contract': self.contract, 'accounts': plan, 'opening_protocol': 1})
        self.data_paths = prepare_fixture(self.state, self.contract, self.root, plan['node'])
        unit_dir = self.root / 'units'; unit_dir.mkdir(); patch.object(deploy.jobs, 'UNITS', unit_dir).start()
        self.request = {'action': 'authorize-build', 'contract': self.contract, 'intent': self.intent,
                        'mode': 'sync', 'identity': '5'*44, 'operation': 'deploy'}

    def authorize(self): return deploy.authorize(self.state, self.contract, self.request)

    def build_files(self):
        self.authorize()
        authority = deploy.build_authority(self.contract, self.intent, 'c'*64, {'uid': 20002, 'gid': 20002})
        self.state.put('build-authority-' + self.intent + '.json', authority)
        for phase in ('fetch', 'compile'):
            name, value = deploy.jobs.unit('c'*64, self.intent, phase)
            (deploy.jobs.UNITS / name).write_text(value)
        return authority


class Deployment(DeploymentFixture, unittest.TestCase):
    def test_completed_fetch_is_not_restarted_after_compile_took_over(self):
        self.build_files()
        with patch.object(deploy.jobs, 'start', return_value='complete') as start:
            self.assertEqual(deploy.step(self.state,self.contract,self.intent,'fetch')['state'],'complete')
            self.assertEqual(start.call_count,1)
        with patch.object(deploy.jobs, 'start', side_effect=AssertionError('must not restart a completed fetch')):
            self.assertEqual(deploy.step(self.state,self.contract,self.intent,'fetch')['state'],'complete')
            self.state.stop(self.contract,lambda:None)
            with self.assertRaises(ValueError):deploy.step(self.state,self.contract,self.intent,'fetch')
    def test_authorization_and_exact_retry_preserve_approved_runtime_and_halt(self):
        halt = self.state.halt(); first = self.authorize()
        self.assertEqual(first, self.authorize()); self.assertEqual(halt, self.state.halt())
        self.assertFalse(first['runtime_changed']); self.assertFalse((self.state.directory / 'active.json').exists())
        changed = dict(self.request, intent='b'*32)
        with self.assertRaisesRegex(ValueError, 'previous build'): deploy.authorize(self.state, self.contract, changed)

    def test_stop_revokes_late_retry_and_every_phase_before_tool_execution(self):
        self.authorize(); self.state.stop(self.contract, lambda: None)
        with self.assertRaises(ValueError): self.authorize()
        with patch.object(deploy.jobs, 'create') as create, patch.object(deploy.toolchain, 'install') as install:
            with self.assertRaises(ValueError): deploy.step(self.state, self.contract, self.intent, 'prepare')
            with self.assertRaises(ValueError): deploy.install_toolchain(self.state, self.contract, self.intent)
        create.assert_not_called(); install.assert_not_called()

    def test_cancellation_during_public_cache_download_never_reports_ready_or_changes_runtime(self):
        self.authorize()
        def cancelled(*_args): self.state.stop(self.contract, lambda: None)
        with patch.object(deploy.toolchain, 'install', side_effect=cancelled), self.assertRaises(ValueError):
            deploy.install_toolchain(self.state, self.contract, self.intent)
        self.assertFalse((self.state.directory / 'active.json').exists())
        self.assertFalse((self.state.directory / 'cutover.json').exists())

    def test_source_change_and_consensus_activation_are_not_implicit_builds(self):
        with self.assertRaises(ValueError): deploy.authorize(self.state, self.contract, dict(self.request, mode='validator'))
        self.authorize()
        catalog = json.loads(self.raw); catalog['networks']['mainnet']['commit'] = 'f'*40
        (self.source / 'catalog.json').write_bytes(files.encoded(catalog))
        with self.assertRaises(ValueError): deploy.pending(self.state, self.contract, self.intent)

    def test_source_upgrade_cannot_reset_genesis_for_the_original_data(self):
        new = self.root / ('d'*64); new.mkdir()
        catalog = json.loads(self.raw)
        catalog['networks']['mainnet']['genesis'] = catalog['networks']['testnet']['genesis']
        (new / 'catalog.json').write_bytes(files.encoded(catalog))
        self.state.put('active.json', {'receipt': {'helper_revision': 'c'*64, 'mode': 'sync', 'identity': self.request['identity']}})
        with patch.object(deploy.helpers, 'publish', return_value='d'*64), \
             patch.object(deploy.helpers, 'verify', side_effect=lambda revision: self.root / revision):
            with self.assertRaisesRegex(ValueError, 'genesis'): self.authorize()
        self.assertFalse((self.state.directory / 'pending.json').exists())

    def test_actual_controller_toolchain_route_keeps_node_lock_free_and_rejects_foreign_owner(self):
        self.authorize()
        request = {'action': 'toolchain', 'contract': self.contract, 'intent': self.intent}
        with patch.object(control, 'load', return_value=(self.state, self.contract)), \
             patch.object(control, 'root_directory', side_effect=AssertionError('node operation lock must not be acquired')), \
             patch.object(deploy.toolchain, 'install') as install:
            self.assertTrue(control.control(request)['toolchain_ready'])
            install.assert_called_once()
            with self.assertRaises(ValueError): control.control(dict(request, contract=dict(self.contract, name='foreign')))
            self.assertEqual(install.call_count, 1)

    def test_running_role_or_identity_cannot_change_on_update(self):
        self.state.put('active.json', {'receipt': {'helper_revision': 'c'*64, 'mode': 'validator', 'identity': self.contract['identity_account']}})
        with self.assertRaisesRegex(ValueError, 'role or identity'): self.authorize()
        self.assertFalse((self.state.directory / 'pending.json').exists())

    def test_build_publication_is_candidate_only_and_requires_exact_original_source(self):
        self.authorize(); public = deploy.jobs.request(self.raw, self.contract['network'], self.intent)
        profile = json.loads(self.raw)['networks'][self.contract['network']]
        receipt = {'request': public, 'source': {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')}, 'files': {}}
        self.state.put('build-authority-' + self.intent + '.json',
                       deploy.build_authority(self.contract, self.intent, 'c'*64, {'uid': 20002, 'gid': 20002}))
        with patch.object(deploy.jobs, 'finish', return_value=receipt), patch.object(deploy.publication, 'verify') as verify:
            self.assertFalse(deploy.step(self.state, self.contract, self.intent, 'publish')['runtime_changed'])
            self.assertEqual(deploy.candidate(self.state, self.contract, self.intent)[1], receipt)
            verify.assert_called_once()
            receipt['request']['intent'] = 'b'*32
            self.state.put('candidate-' + self.intent + '.json', receipt)
            with self.assertRaises(ValueError): deploy.candidate(self.state, self.contract, self.intent)
        self.assertFalse((self.state.directory / 'active.json').exists())

    def test_builder_failure_does_not_suppress_other_unit_attempt_or_runtime_shutdown(self):
        self.build_files(); calls = []
        def command(args, **_kwargs):
            calls.append(args)
            if args == ['stop', deploy.jobs.unit_name(self.intent, 'fetch')]: raise OSError('inert job-stop fault')
            return ''
        with patch.object(deploy.process, 'assert_quiescent') as quiet, \
             patch.object(deploy.accounts, 'verify', side_effect=AssertionError('stop must not depend on current NSS')):
            with self.assertRaises(ValueError): deploy.cancel_builds(self.state, self.contract, command)
            quiet.assert_called_once_with(20002)
        self.assertIn(['stop', deploy.jobs.unit_name(self.intent, 'compile')], calls)
        with patch.object(deploy, 'cancel_builds', side_effect=ValueError('inert builder refusal')), \
             patch.object(control, 'shutdown') as runtime, self.assertRaises(ValueError):
            control.shutdown_all(self.state, self.contract, command)
        runtime.assert_called_once()

    def test_unknown_unit_bytes_are_not_stopped_but_other_owned_scope_still_is(self):
        self.build_files(); name = deploy.jobs.unit_name(self.intent, 'fetch')
        (deploy.jobs.UNITS / name).write_text('unknown unit')
        calls = []
        def command(args, **_kwargs): calls.append(args); return ''
        with patch.object(deploy.process, 'assert_quiescent'), self.assertRaises(ValueError):
            deploy.cancel_builds(self.state, self.contract, command)
        self.assertNotIn(['stop', name], calls)
        self.assertIn(['stop', deploy.jobs.unit_name(self.intent, 'compile')], calls)

    def test_explicit_abandon_revokes_old_build_and_preserves_running_runtime_generation(self):
        self.build_files(); halt = self.state.halt(); self.state.put('active.json', {'halt': halt['generation']})
        calls = []
        def command(args, **_kwargs): calls.append(args); return ''
        with patch.object(deploy.process, 'assert_quiescent'):
            result = control.dispatch(self.state, self.contract,
                {'action': 'abandon-build', 'contract': self.contract, 'intent': self.intent}, command)
        self.assertFalse(result['runtime_changed']); self.assertTrue(self.state.runtime_is_current())
        self.assertEqual(self.state.halt(), halt); self.assertFalse((self.state.directory / 'pending.json').exists())
        self.assertTrue((self.state.directory / ('abandoned-build-' + self.intent + '.json')).exists())
        with self.assertRaises(ValueError): self.state.current(self.contract, self.intent)
        with self.assertRaisesRegex(ValueError,'permanently canceled'):
            self.state.authorize(self.contract,self.intent,{},'deploy')
        self.assertEqual(len([call for call in calls if call[0] == 'stop']), 2)

    def test_cancellation_write_failure_attempts_both_jobs_without_claiming_success(self):
        self.build_files(); calls = []
        def command(args, **_kwargs): calls.append(args); return ''
        with patch.object(self.state, 'put', side_effect=OSError('inert cancellation storage failure')), \
             patch.object(deploy.process, 'assert_quiescent'), self.assertRaises(OSError):
            deploy.abandon(self.state, self.contract, self.intent, command)
        self.assertEqual(len([call for call in calls if call[0] == 'stop']), 2)
        self.assertTrue((self.state.directory / 'pending.json').exists())

    def test_visible_build_authority_must_be_durable_before_any_unit_is_created(self):
        self.authorize()
        with patch.object(deploy, 'sync_file', side_effect=OSError('inert persistence fault')), \
             patch.object(deploy.jobs, 'create') as create:
            with self.assertRaises(OSError): deploy.step(self.state, self.contract, self.intent, 'prepare')
            with self.assertRaises(OSError): deploy.step(self.state, self.contract, self.intent, 'prepare')
        create.assert_not_called()
        with patch.object(deploy.jobs, 'create') as create:
            self.assertEqual(deploy.step(self.state, self.contract, self.intent, 'prepare')['state'], 'prepared')
        create.assert_called_once()


class Cutover(DeploymentFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        patch.object(deploy.units, 'UNITS', deploy.jobs.UNITS).start()
        patch.object(control, 'root_directory', lambda *_args, **_kw: None).start()
        patch.object(control, 'read', lambda path, size=1048576: files.read(path, size, os.getuid())).start()
        patch.object(deploy.process, 'assert_quiescent').start()
        patch.object(deploy.host, 'capacity', return_value={}).start()
        patch.object(deploy.tuning, 'verify', return_value={}).start()
        patch.object(deploy.publication, 'verify').start()
        self.qualified = patch.object(control, 'qualify', return_value=(None, json.loads(self.raw)['networks'][self.contract['network']], None, None)).start()
        patch.object(control, 'status', return_value={'rpc_ready': False}).start()
        patch.object(deploy.custody, 'complete', return_value={'public': self.request['identity'], 'cipher_sha256': 'e'*64}).start()
        self.firewall = patch.object(control, 'firewall').start()
        self.running = False; self.skip = False; self.calls = []

    def command(self, args, **_kwargs):
        self.calls.append(args)
        if args[0] == 'show':
            if args[-2:] == ['--property=LoadState', '--value']: return 'not-found\n'
            rows = {'LoadState': 'loaded', 'ActiveState': 'active' if self.running else 'inactive',
                    'SubState': 'running' if self.running else 'dead', 'MainPID': '123' if self.running else '0',
                    'FragmentPath': str(deploy.units.UNITS / deploy.units.UNIT), 'DropInPaths': '',
                    'User': '20001', 'Group': '20001', 'NeedDaemonReload': 'no'}
            return ''.join(key + '=' + value + '\n' for key, value in rows.items())
        if args[0] == 'start' and not self.skip: self.running = True
        if args[:2] == ['stop', deploy.units.UNIT]: self.running = False
        return ''

    def test_actual_activation_commits_source_floor_before_any_start(self):
        import native_source_floor as floor
        self.completed_candidate(); self.dispatch('begin-runtime')
        self.dispatch('install-runtime', firewall={'run':'inert','bundle':'d'*64})
        self.assertIsNone(self.state.get(floor.COMPLETE)['highest'])
        original = self.command
        def checked(args, **kwargs):
            if args[0] == 'start':
                profile = json.loads(self.raw)['networks'][self.contract['network']]
                self.assertEqual(self.state.get(floor.COMPLETE)['highest'], floor.from_profile(profile))
            return original(args, **kwargs)
        result = control.dispatch(self.state, self.contract,
            {'action':'activate-runtime','contract':self.contract,'intent':self.intent}, checked)
        self.assertTrue(result['runtime_started'])

    def test_opening_floor_persistence_failure_still_stops_owned_units_and_never_starts(self):
        import native_source_floor as floor
        import stat
        self.completed_candidate(); self.dispatch('begin-runtime')
        self.dispatch('install-runtime', firewall={'run':'inert','bundle':'d'*64})
        self.calls.clear(); real = os.fsync
        def fault(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and (self.state.directory/floor.PENDING).exists():
                raise OSError('inert DB-opening directory fsync failure')
            return real(fd)
        with patch.object(os, 'fsync', side_effect=fault), self.assertRaises(OSError):
            self.dispatch('activate-runtime')
        self.assertFalse(any(call[0] in ('start','enable') for call in self.calls))
        self.assertIn(['stop', deploy.units.UNIT], self.calls)
        expected = floor.from_profile(json.loads(self.raw)['networks'][self.contract['network']])
        self.assertEqual(self.state.get(floor.PENDING)['highest'], expected)
        self.assertIsNone(self.state.get(floor.COMPLETE)['highest'])
        control.dispatch(self.state, self.contract,
            {'action':'recover-cutover','contract':self.contract,'intent':self.intent},self.command)
        self.assertEqual(self.state.get(floor.PENDING)['highest'], expected)
        self.intent='f'*32; self.request=dict(self.request,intent=self.intent)
        self.completed_candidate(); self.dispatch('begin-runtime')
        self.dispatch('install-runtime',firewall={'run':'retry','bundle':'e'*64})
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])

    def completed_candidate(self):
        self.build_files()
        profile = json.loads(self.raw)['networks'][self.contract['network']]
        receipt = {'schema': 1, 'request': deploy.jobs.request(self.raw, self.contract['network'], self.intent),
                   'source': {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')}, 'files': {}}
        self.state.put('candidate-' + self.intent + '.json', receipt)
        (self.state.directory / 'retained-history').write_text('keep original native history')

    def dispatch(self, action, **values):
        return control.dispatch(self.state, self.contract,
            dict(action=action, contract=self.contract, intent=self.intent, **values), self.command)

    def test_complete_candidate_to_cipher_unit_and_observed_start_preserves_history(self):
        self.completed_candidate()
        self.assertTrue(self.dispatch('begin-runtime')['runtime_stopped'])
        self.assertFalse(self.running); self.assertTrue((self.state.directory / 'cutover.json').exists())
        result = self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.assertFalse(result['started']); self.assertFalse(self.running)
        unit = (deploy.units.UNITS / deploy.units.UNIT).read_text()
        self.assertIn('User=20001\nGroup=20001', unit)
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        self.assertTrue(self.running); self.assertIsNone(self.state.get('intent-fence.json')['intent'])
        self.assertFalse((self.state.directory / 'pending.json').exists())
        self.assertEqual((self.state.directory / 'retained-history').read_text(), 'keep original native history')

    def test_configuration_update_reuses_original_published_binary_with_new_cutover(self):
        self.completed_candidate();self.dispatch('begin-runtime')
        self.dispatch('install-runtime',firewall={'run':'inert','bundle':'d'*64})
        self.dispatch('activate-runtime')
        original=self.state.get('active.json')['receipt']['build']
        old_intent=self.intent;self.intent='e'*32
        request=dict(self.request,intent=self.intent,operation='update-config')
        result=deploy.authorize(self.state,self.contract,request)
        self.assertEqual(result['target']['build_intent'],old_intent)
        self.assertEqual(deploy.candidate(self.state,self.contract,self.intent)[1],original)
        with self.assertRaisesRegex(ValueError,'reuses its verified build'):
            deploy.step(self.state,self.contract,self.intent,'prepare')
        self.dispatch('begin-runtime')
        self.dispatch('install-runtime',firewall={'run':'second','bundle':'f'*64})
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        active=self.state.get('active.json')
        self.assertEqual(active['intent'],self.intent)
        self.assertEqual(active['receipt']['build'],original)
        self.assertIn('/'+old_intent+'/bin/agave-validator', (deploy.units.UNITS/deploy.units.UNIT).read_text())

    def test_explicit_deploy_after_destroy_reports_current_authority_and_clears_retirement(self):
        self.completed_candidate();self.dispatch('begin-runtime')
        self.dispatch('install-runtime',firewall={'run':'inert','bundle':'d'*64});self.dispatch('activate-runtime')
        control.dispatch(self.state,self.contract,{'action':'destroy','contract':self.contract},self.command)
        self.assertTrue(self.state.halt()['retired'])
        self.intent='f'*32;self.request=dict(self.request,intent=self.intent)
        self.completed_candidate();self.dispatch('begin-runtime')
        self.dispatch('install-runtime',firewall={'run':'again','bundle':'e'*64})
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        report=control.dispatch(self.state,self.contract,{'action':'deployment','contract':self.contract},self.command)
        self.assertFalse(report['retired']);self.assertTrue(report['approved']['authorized'])
        self.assertTrue(self.running)

    def test_missing_candidate_or_unknown_service_never_stops_or_adopts_it(self):
        self.authorize()
        with self.assertRaises(FileNotFoundError): self.dispatch('begin-runtime')
        self.assertEqual(self.calls, [])
        self.completed_candidate(); self.dispatch('begin-runtime')
        file = deploy.units.UNITS / deploy.units.UNIT; file.write_text('unowned unit')
        self.calls.clear()
        with self.assertRaises(ValueError): self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.assertEqual(file.read_text(), 'unowned unit'); self.assertFalse((self.state.directory / 'runtime-install.json').exists())
        self.assertEqual(self.calls, [])

    def test_failed_unit_publication_remains_fenced_and_same_candidate_retries(self):
        self.completed_candidate(); self.dispatch('begin-runtime')
        with patch.object(deploy, 'atomic', side_effect=OSError('inert unit publication failure')):
            with self.assertRaises(OSError): self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.assertTrue((self.state.directory / 'cutover.json').exists()); self.assertFalse(self.running)
        self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])

    def test_failed_qualification_does_not_open_cutover_gate_and_skipped_start_is_cancelled(self):
        self.completed_candidate(); self.dispatch('begin-runtime')
        self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.qualified.side_effect = ValueError('inert stale firewall or custody')
        with self.assertRaises(ValueError): self.dispatch('activate-runtime')
        self.assertTrue((self.state.directory / 'cutover.json').exists()); self.assertFalse(self.running)
        self.qualified.side_effect = None; self.skip = True
        with self.assertRaisesRegex(ValueError, 'did not start'): self.dispatch('activate-runtime')
        self.assertFalse(self.running); self.assertFalse(self.state.runtime_is_current())
        self.assertIsNone(self.state.get('intent-fence.json')['intent'])
        self.assertIn(['stop', deploy.units.UNIT], self.calls)

    def test_stop_revokes_cutover_before_key_or_service_publication(self):
        self.completed_candidate(); self.dispatch('begin-runtime')
        control.dispatch(self.state, self.contract, {'action': 'stop', 'contract': self.contract}, self.command)
        with self.assertRaises(ValueError): self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        self.assertFalse((deploy.units.UNITS / deploy.units.UNIT).exists())
        self.assertEqual((self.state.directory / 'retained-history').read_text(), 'keep original native history')

    def recovery_fixture(self, phase):
        self.completed_candidate(); self.dispatch('begin-runtime')
        if phase in ('import', 'unit'):
            self.state.put('identity-import-sync.json', {'contract': self.contract, 'intent': self.intent,
                'role': 'sync', 'public': self.request['identity'], 'plaintext_sha256': 'd'*64,
                'pending': 'sync-'+self.intent+'.pending.cred'})
            self.state.put('identity-sync.json', {'contract': self.contract, 'public': self.request['identity'], 'cipher_sha256': 'e'*64})
            (self.root/'retained-ciphertext').write_bytes(b'inert original ciphertext; never decrypted')
        if phase == 'unit': self.dispatch('install-runtime', firewall={'run': 'inert', 'bundle': 'd'*64})
        control.dispatch(self.state, self.contract, {'action': 'stop', 'contract': self.contract}, self.command)
        self.calls.clear()

    def recovery_checks(self, phase):
        self.recovery_fixture(phase)
        saved = {p.name: p.read_bytes() for p in self.state.directory.iterdir()
                 if p.name.startswith(('candidate-', 'identity-sync', 'runtime-install', 'retained-history'))}
        self.assertTrue(self.dispatch('recover-cutover')['recovered'])
        self.assertFalse(self.running); self.assertFalse(any(c[0]=='start' for c in self.calls))
        with self.assertRaisesRegex(ValueError,'permanently canceled'):
            deploy.authorize(self.state,self.contract,self.request)
        for name,raw in saved.items(): self.assertEqual((self.state.directory/name).read_bytes(),raw)
        if phase in ('import', 'unit'):
            self.assertEqual((self.root/'retained-ciphertext').read_bytes(),b'inert original ciphertext; never decrypted')
            self.assertIn('identity-import-sync.json',self.state.get('recovered-cutover-'+self.intent+'.json')['imports'])
            self.assertFalse((self.state.directory/'identity-import-sync.json').exists())
        for action in ('begin-runtime', 'install-runtime', 'activate-runtime'):
            with self.assertRaises((ValueError,FileNotFoundError)):
                self.dispatch(action,**({'firewall':{'run':'old','bundle':'d'*64}} if action=='install-runtime' else {}))
        fresh=dict(self.request,intent='f'*32)
        self.assertEqual(deploy.authorize(self.state,self.contract,fresh)['intent'],fresh['intent'])
        calls=list(self.calls)
        self.assertTrue(self.dispatch('recover-cutover')['already_recovered'])
        self.assertEqual(self.calls,calls)
        self.assertEqual(self.state.current(self.contract,fresh['intent'])['intent'],fresh['intent'])

    def test_explicit_recovery_after_begin_preserves_history_and_allows_only_fresh_deployment(self):
        self.recovery_checks('begin')

    def test_explicit_recovery_after_import_retains_original_receipt_and_ciphertext(self):
        self.recovery_checks('import')

    def test_explicit_recovery_after_unit_publication_retains_original_runtime_authority(self):
        self.recovery_checks('unit')

    def test_recovery_first_storage_failure_still_attempts_all_owned_shutdowns(self):
        self.recovery_fixture('unit')
        with patch.object(os,'fsync',side_effect=OSError('inert total persistence failure')):
            with self.assertRaises(OSError):self.dispatch('recover-cutover')
        self.assertIn(['stop',deploy.units.UNIT],self.calls)
        self.assertTrue((self.state.directory/'cutover.json').exists())
        self.assertTrue(self.dispatch('recover-cutover')['recovered'])

    def interrupted_recovery_removal(self, filename):
        self.recovery_fixture('import');original=self.state.remove
        def fail(name):
            original(name)
            if name==filename:raise OSError('inert visible removal before interrupted completion')
        with patch.object(self.state,'remove',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):self.dispatch('recover-cutover')
                with self.assertRaises(ValueError):deploy.authorize(self.state,self.contract,dict(self.request,intent='f'*32))
        self.assertTrue(self.dispatch('recover-cutover')['recovered'])
        self.assertEqual((self.root/'retained-ciphertext').read_bytes(),b'inert original ciphertext; never decrypted')

    def test_recovery_retries_after_pending_removal_without_reviving_old_commands(self):
        self.interrupted_recovery_removal('pending.json')

    def test_recovery_retries_after_cutover_removal_without_requiring_missing_metadata(self):
        self.interrupted_recovery_removal('cutover.json')

    def test_visible_complete_recovery_needs_durable_barrier_before_new_authority(self):
        self.recovery_fixture('begin');original=deploy.sync_file
        def fail(path):
            if path.name=='cutover-recovery.json' and self.state.get(path.name)['phase']=='complete':
                raise OSError('inert completed recovery persistence failure')
            original(path)
        with patch.object(deploy,'sync_file',side_effect=fail),patch.object(lifecycle,'sync_file',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):self.dispatch('recover-cutover')
                with self.assertRaises(OSError):deploy.authorize(self.state,self.contract,dict(self.request,intent='f'*32))
        self.assertTrue(self.dispatch('recover-cutover')['already_recovered'])
        deploy.authorize(self.state,self.contract,dict(self.request,intent='f'*32))

    def test_wrong_intent_or_foreign_owner_cannot_recover_or_stop_a_cutover(self):
        self.recovery_fixture('begin');before={p.name:p.read_bytes() for p in self.state.directory.iterdir()}
        for request in [dict(action='recover-cutover',contract=self.contract,intent='f'*32),
                        dict(action='recover-cutover',contract=dict(self.contract,name='foreign'),intent=self.intent)]:
            with self.assertRaises(ValueError):control.dispatch(self.state,self.contract,request,self.command)
        self.assertEqual(self.calls,[])
        self.assertEqual({p.name:p.read_bytes() for p in self.state.directory.iterdir()},before)


class ReleaseUpgrade(DeploymentFixture, unittest.TestCase):
    def test_forward_catalog_preserves_active_receipt_and_data_until_explicit_opening(self):
        # Model original public source metadata; no old/new compiler or node runs.
        old = json.loads(self.raw)
        network = self.contract['network']
        profile = old['networks'][network]
        if network == 'mainnet':
            profile.update(version='4.3.2', commit='a203300045b405f86c9c84308b2eae76af69ac3b',
                cargo_lock_sha256='d5ae4d5728e42e45637bee3ea3b9acbb3cc98df20f16e5b2c463f567006030f6',
                rust='1.97.1', rust_manifest_sha256='03569b1886ceb5c05276b50c8431ab111de944cd6140fe1fa7d821dd8e0f29cf')
        else:
            profile.update(version='4.4.0-beta.1', commit='3ad9da2c390eb7ad2630ed15afcd463e72e007a8',
                cargo_lock_sha256='e153bced39cabfc15a4ee99cf8cc2e10952aaf59a13a3b1d1eaa6788a23da024')
        old_raw = files.encoded(old)
        (self.source/'catalog.json').write_bytes(old_raw)
        new = self.root/('d'*64); new.mkdir(); (new/'catalog.json').write_bytes(self.raw)
        previous = deploy.source_floor.from_profile(profile)
        deploy.source_floor.claim(self.state, self.contract, previous)
        build = {'request': deploy.jobs.request(old_raw, network, 'b'*32),
                 'source': {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')}}
        self.state.put('active.json', {'receipt': {'helper_revision':'c'*64, 'mode':'sync',
            'identity': self.request['identity'], 'build': build}})
        original = {}
        for kind, path in self.data_paths.items():
            file = path/'data/original'; file.write_bytes(('inert original '+kind).encode())
            original[file] = (file.read_bytes(), file.stat().st_ino)
        credential = self.root/'original.cred'; credential.write_bytes(b'inert original ciphertext')
        original[credential] = (credential.read_bytes(), credential.stat().st_ino)
        active = (self.state.directory/'active.json').read_bytes(); halt = self.state.halt()
        with patch.object(deploy.helpers, 'publish', return_value='d'*64), \
             patch.object(deploy.helpers, 'verify', side_effect=lambda revision:self.root/revision):
            with self.assertRaisesRegex(ValueError, 'configuration update cannot change native source'):
                deploy.authorize(self.state, self.contract, dict(self.request, operation='update-config'))
            request = dict(self.request, operation='update')
            result = deploy.authorize(self.state, self.contract, request)
            self.assertEqual(result, deploy.authorize(self.state, self.contract, request))
            self.assertFalse(result['runtime_changed'])
            _, _, _, selected = deploy.pending(self.state, self.contract, self.intent)
            self.assertEqual(selected['version'], '4.4.0')
            self.assertEqual(deploy.source_floor.highest(deploy.source_floor.records(self.state,self.contract)), previous)
            self.assertEqual((self.state.directory/'active.json').read_bytes(), active)
            self.assertEqual(self.state.halt(), halt)
            for file, identity in original.items(): self.assertEqual((file.read_bytes(),file.stat().st_ino),identity)
            deploy.source_floor.claim(self.state,self.contract,deploy.source_floor.from_profile(selected))
            with self.assertRaisesRegex(ValueError,'below the original data-opening version'):
                deploy.source_floor.check(self.state,self.contract,previous)


class TestnetReleaseUpgrade(ReleaseUpgrade):
    fixture_contract = dict(owner(), network='testnet')


if __name__ == '__main__': unittest.main()
