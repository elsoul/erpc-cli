# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline fault-injection tests: no services, nodes, keys or network operations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('control', sys.argv.pop(1))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(c, 'ROOT', self.root).start()
        self.config = {'owner': 'destination', 'network': 'hoodi', 'pair': 'qualified', 'fee_recipient': 'public'}
        self.state = {'owner': 'destination', 'network': 'hoodi', 'state': 'prepared'}
        self.pk = '0x' + 'ab' * 48  # deliberately non-signing public fixture
        self.material = {'keystore': {'version': 4, 'pubkey': self.pk[2:], 'crypto': {}},
                         'password': 'fixture-only', 'history': {'metadata': {'interchange_format_version': '5',
                         'genesis_validators_root': c.NETWORKS['hoodi'][1]},
                         'data': [{'pubkey': self.pk, 'signed_blocks': [], 'signed_attestations': []}]}}
        self.calls = []
        patch.object(c, 'ctl', side_effect=lambda action, unit: self.calls.append((action, unit))).start()
        patch.object(c, 'stopped').start()
        patch.object(c, 'ready').start()
        patch.object(c, 'chain_validator', return_value=None).start()
        patch.object(c.pwd, 'getpwnam', return_value=type('User', (), {'pw_uid': 1000})()).start()
        patch.object(c.os, 'chown').start()
        (self.root / 'vc').mkdir()

    def request(self, action, **kwargs):
        return {'action': action, 'owner': 'destination', **kwargs}

    def make_imported(self):
        self.state.update(state='imported', pubkey=self.pk)
        validators = self.root / 'vc/validators'
        validators.mkdir(exist_ok=True)
        (validators / 'slashing_protection.sqlite').write_text('existing-history')
        (validators / 'validator_definitions.yml').write_text('existing-definitions')
        (self.root / 'custody.json').write_text(json.dumps(self.material))
        c.save(self.state)

    def test_actual_fsync_failures_still_quiesce_and_never_export(self):
        self.make_imported()
        original = c.read_json(self.root / 'owner.json')
        original_custody = (self.root / 'custody.json').read_bytes()
        original_history = (self.root / 'vc/validators/slashing_protection.sqlite').read_bytes()
        real_sync = os.fsync
        for action in ('destroy', 'fence-export', 'install-check'):
            for fault in (1, 2):
                with self.subTest(action=action, fault=fault):
                    c.save(original)
                    self.calls.clear()
                    syncs = []
                    def fail_at(fd):
                        syncs.append(fd)
                        if len(syncs) == fault:
                            raise OSError('inert persistence failure')
                        return real_sync(fd)
                    with patch.object(c.os, 'fsync', side_effect=fail_at), patch.object(c, 'lighthouse') as lh:
                        with self.assertRaises(c.Refused):
                            c.locked_dispatch(self.config, self.request(action, destination='next'))
                    lh.assert_not_called()
                    self.assertIn(('stop', c.UNITS[0]), self.calls)
                    self.assertIn(('disable', c.UNITS[0]), self.calls)
                    if action == 'destroy':
                        self.assertEqual(self.calls, [(op, unit) for unit in c.UNITS for op in ('stop', 'disable')])
                    self.assertEqual((self.root / 'custody.json').read_bytes(), original_custody)
                    self.assertEqual((self.root / 'vc/validators/slashing_protection.sqlite').read_bytes(), original_history)

    def test_shutdown_failures_do_not_skip_disable_other_units_or_export(self):
        self.make_imported()
        original = c.read_json(self.root / 'owner.json')
        for action in ('stop', 'destroy', 'fence-export', 'install-check'):
            c.save(original)
            self.calls.clear()
            def failure(operation, unit):
                self.calls.append((operation, unit))
                if operation == 'stop':
                    raise c.Refused('inert shutdown failure')
            with patch.object(c, 'ctl', side_effect=failure), patch.object(c, 'run', return_value=b'loaded'), patch.object(c, 'lighthouse') as lh:
                with self.assertRaises(c.Refused):
                    c.locked_dispatch(self.config, self.request(action, destination='next'))
            lh.assert_not_called()
            self.assertIn(('disable', c.UNITS[0]), self.calls)
            if action in ('stop', 'destroy'):
                self.assertEqual(self.calls, [(op, unit) for unit in c.UNITS for op in ('stop', 'disable')])

    def test_maintenance_retry_resyncs_visible_fence_and_never_publishes_on_failure(self):
        self.make_imported()
        with patch.object(c, 'run', return_value=b'loaded'):
            c.locked_dispatch(self.config, self.request('install-check'))
        before = (self.root / 'owner.json').read_bytes()
        self.calls.clear()
        with patch.object(c.os, 'fsync', side_effect=OSError('persistent disk failure')):
            with self.assertRaises(c.Refused):
                c.locked_dispatch(self.config, self.request('install-check'))
        self.assertEqual((self.root / 'owner.json').read_bytes(), before)
        self.assertIn(('stop', c.UNITS[0]), self.calls)
        with patch.object(c, 'run', return_value=b'loaded'):
            self.assertEqual(c.locked_dispatch(self.config, self.request('install-check'))['state'], 'maintenance')
        c.locked_dispatch(self.config, self.request('install-end'))
        self.assertEqual(c.read_json(self.root / 'owner.json')['state'], 'imported')

    def test_wrong_scope_never_persists_or_shuts_down_even_with_storage_fault(self):
        self.make_imported()
        for config, request in [(dict(self.config, network='mainnet'), self.request('destroy')),
                                (self.config, dict(self.request('fence-export', destination='next'), owner='other'))]:
            with patch.object(c.os, 'fsync', side_effect=OSError('inert fault')) as sync:
                with self.assertRaises(c.Refused):
                    c.locked_dispatch(config, request)
            sync.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_wrong_network_or_history_key_never_invokes_import(self):
        for mutation in ('network', 'key', 'nonempty'):
            bad = copy.deepcopy(self.material)
            if mutation == 'network':
                bad['history']['metadata']['genesis_validators_root'] = c.NETWORKS['mainnet'][1]
            elif mutation == 'key':
                bad['history']['data'][0]['pubkey'] = '0x' + 'cd' * 48
            else:
                bad['history']['data'][0]['signed_blocks'] = [{'slot': '1'}]
            with patch.object(c, 'lighthouse') as lh, self.assertRaises(c.Refused):
                c.dispatch(self.config, self.state, self.request('import', material=bad, new_key=True))
            lh.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_chain_registered_key_cannot_be_claimed_as_new(self):
        c.chain_validator.return_value = {'status': 'pending_initialized'}
        with self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, self.request('import', material=self.material, new_key=True))
        self.assertFalse((self.root / 'owner.json').exists())

    def test_failed_import_is_retryable_without_dropping_history(self):
        def first(config, args):
            validators = self.root / 'vc/validators'
            validators.mkdir(exist_ok=True)
            (validators / 'slashing_protection.sqlite').write_text('already-imported-watermarks')
            raise c.Refused('simulated import failure')
        with patch.object(c, 'lighthouse', side_effect=first), self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, self.request('import', material=self.material, new_key=True))
        self.assertEqual(self.state['state'], 'importing')
        self.assertEqual((self.root / 'vc/validators/slashing_protection.sqlite').read_text(), 'already-imported-watermarks')
        with patch.object(c, 'lighthouse'):
            out = c.dispatch(self.config, self.state, self.request('import', material=self.material, new_key=True))
        self.assertFalse(out['signing_started'])
        self.assertNotIn(('start', c.UNITS[0]), self.calls)
        self.assertEqual((self.root / 'vc/validators/slashing_protection.sqlite').read_text(), 'already-imported-watermarks')
        # A completed import retries without even calling Lighthouse.
        with patch.object(c, 'lighthouse') as lh:
            c.dispatch(self.config, self.state, self.request('import', material=self.material, new_key=True))
        lh.assert_not_called()

    def test_missing_history_is_never_recreated_by_start(self):
        self.make_imported()
        (self.root / 'vc/validators/slashing_protection.sqlite').unlink()
        with self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, self.request('start'))
        self.assertNotIn(('start', c.UNITS[0]), self.calls)
        self.assertFalse((self.root / 'vc/validators/slashing_protection.sqlite').exists())

    def test_fence_persists_even_when_source_shutdown_fails(self):
        self.make_imported()
        with patch.object(c, 'ctl', side_effect=c.Refused('shutdown failed')), self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, self.request('fence-export', destination='next'))
        self.assertEqual(c.read_json(self.root / 'owner.json')['state'], 'fenced')
        with self.assertRaises(c.Refused):
            c.guard(self.config, self.state)
        with self.assertRaises(c.Refused):
            c.fence(self.config, self.state, 'other-destination')

    def test_export_occurs_only_after_confirmed_shutdown(self):
        self.make_imported()
        events = []
        def exported(config, args):
            events.append('export')
            Path(args[-1]).write_text(json.dumps(self.material['history']))
        with patch.object(c, 'stopped', side_effect=lambda: events.append('stopped')), patch.object(c, 'lighthouse', side_effect=exported):
            material = c.fence(self.config, self.state, 'next')
        self.assertEqual(events, ['stopped', 'export'])
        self.assertEqual(material['destination'], 'next')
        self.assertNotIn(('start', c.UNITS[0]), self.calls)

    def test_competing_destination_claims_are_serialized_at_source(self):
        from concurrent.futures import ThreadPoolExecutor
        self.make_imported()
        def exported(config, args):
            Path(args[-1]).write_text(json.dumps(self.material['history']))
        def claim(destination):
            try:
                result = c.locked_dispatch(self.config, self.request('fence-export', destination=destination))
                return result['destination']
            except c.Refused:
                return 'refused'
        with patch.object(c, 'lighthouse', side_effect=exported), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ['one', 'two']))
        self.assertEqual(results.count('refused'), 1)
        chosen = next(value for value in results if value != 'refused')
        self.assertEqual(c.read_json(self.root / 'owner.json')['fenced_to'], chosen)

    def test_destroy_retains_custody_and_database_but_permanently_fences(self):
        self.make_imported()
        before = (self.root / 'custody.json').read_bytes()
        c.dispatch(self.config, self.state, self.request('destroy'))
        self.assertEqual((self.root / 'custody.json').read_bytes(), before)
        self.assertTrue((self.root / 'vc/validators/slashing_protection.sqlite').exists())
        self.assertEqual(self.state['state'], 'fenced')
        with self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, self.request('start'))

    def test_first_deploy_accepts_systemd_not_found_with_nonzero_exit(self):
        absent = subprocess.CompletedProcess(['systemctl'], 1, b'not-found\n', b'')
        with patch.object(c.subprocess, 'run', return_value=absent):
            result = c.dispatch(self.config, self.state, self.request('install-check'))
        self.assertEqual(result['state'], 'maintenance')
        self.assertEqual(self.calls, [])

    def test_maintenance_is_resumable_and_never_starts_a_signer(self):
        self.make_imported()
        with patch.object(c, 'run', return_value=b'loaded'):
            c.dispatch(self.config, self.state, self.request('install-check'))
            c.dispatch(self.config, self.state, self.request('install-check'))
        with self.assertRaises(c.Refused):
            c.guard(self.config, self.state)
        changed = dict(self.config, pair='different')
        with self.assertRaises(c.Refused):
            c.dispatch(changed, self.state, self.request('install-check'))
        c.dispatch(self.config, self.state, self.request('install-end'))
        self.assertEqual(self.state['state'], 'imported')
        self.assertNotIn(('start', c.UNITS[0]), self.calls)

    def test_secret_subprocess_diagnostics_are_not_propagated(self):
        response = subprocess.CompletedProcess(['client'], 1, b'fixture-unlock-material', b'fixture-unlock-material')
        with patch.object(c.subprocess, 'run', return_value=response):
            with self.assertRaises(c.Refused) as caught:
                c.run(['client'])
        self.assertNotIn('fixture-unlock-material', str(caught.exception))

    def test_wrong_inventory_owner_is_rejected_before_service_actions(self):
        with self.assertRaises(c.Refused):
            c.dispatch(self.config, self.state, {'action': 'destroy', 'owner': 'someone-else'})
        self.assertEqual(self.calls, [])


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.config = {'network': 'hoodi'}
        self.genesis = {'genesis_time': '800', 'genesis_validators_root': c.NETWORKS['hoodi'][1]}
        self.sync = {'head_slot': '100', 'is_syncing': False, 'is_optimistic': False,
                     'el_offline': False, 'sync_distance': '0'}
        self.head = {'timestamp': hex(2000)}
        self.chain = hex(560048)
        patch.object(c.time, 'time', return_value=2000).start()
        patch.object(c, 'rpc', side_effect=lambda path: {'data': self.genesis if path.endswith('genesis') else self.sync}).start()
        patch.object(c, 'eth', side_effect=lambda method, params: self.chain if method == 'eth_chainId' else self.head).start()

    def test_network_sync_and_freshness_are_independent_preconditions(self):
        self.assertEqual(c.ready(self.config), self.sync)
        for field in ('is_syncing', 'is_optimistic', 'el_offline'):
            self.sync[field] = True
            with self.assertRaises(c.Refused):
                c.ready(self.config)
            self.sync[field] = False
        self.chain = '0x1'
        with self.assertRaises(c.Refused):
            c.ready(self.config)
        self.chain = hex(560048)
        self.genesis['genesis_validators_root'] = c.NETWORKS['mainnet'][1]
        with self.assertRaises(c.Refused):
            c.ready(self.config)
        self.genesis['genesis_validators_root'] = c.NETWORKS['hoodi'][1]
        self.sync['head_slot'] = '1'
        with self.assertRaises(c.Refused):
            c.ready(self.config)
        self.sync['head_slot'] = '100'
        self.head['timestamp'] = hex(1000)
        with self.assertRaises(c.Refused):
            c.ready(self.config)


class ClockTests(unittest.TestCase):
    def test_actual_rpc_clock_tasks_preserve_chrony_and_install_only_needed_fallback(self):
        import shutil
        try:
            import yaml
        except ImportError:
            self.skipTest('optional pinned Ansible/PyYAML runtime')
        ansible = shutil.which('ansible-playbook')
        if not ansible:
            self.skipTest('optional pinned Ansible runtime')
        templates = Path(c.__file__).resolve().parent.parent
        original = yaml.safe_load((templates / 'ansible/eth-rpc/init.yml').read_text())[0]['tasks']
        begin = next(i for i, task in enumerate(original) if 'ansible.builtin.service_facts' in task)
        selected = original[begin:begin + 4]
        for services, expected, fallback in [
            ({}, 'systemd-timesyncd.service', True),
            ({'chrony.service': {'state': 'running'}}, 'chrony.service', False),
            ({'chrony.service': {'state': 'stopped'}}, 'chrony.service', False),
            ({'chrony.service': {'state': 'stopped'}, 'ntpd.service': {'state': 'running'}}, 'ntpd.service', False),
        ]:
            with self.subTest(services=services), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                play_root = root / 'ansible/eth-rpc'
                play_root.mkdir(parents=True)
                (root / 'validator').mkdir()
                shutil.copyfile(templates / 'validator/time_service.py', root / 'validator/time_service.py')
                tasks = copy.deepcopy(selected)
                tasks[0] = {'ansible.builtin.set_fact': {'ansible_facts': {'services': services}, 'fixture_installed': False}}
                # Only the host-changing package/service modules are inert.
                # The carried command, relative source path, stdin, registered
                # result, condition and templates execute through real Ansible.
                package = tasks[2].pop('ansible.builtin.apt')
                self.assertEqual(package, {'name': 'systemd-timesyncd', 'state': 'present'})
                tasks[2]['ansible.builtin.set_fact'] = {'fixture_installed': True}
                service = tasks[3].pop('ansible.builtin.systemd_service')
                self.assertEqual(service['state'], 'started')
                self.assertIs(service['enabled'], True)
                tasks[3]['ansible.builtin.assert'] = {'that': [
                    '(eth_clock.stdout | from_json).service == fixture_expected',
                    'fixture_installed == fixture_fallback',
                    'fixture_selected == fixture_expected']}
                tasks[3]['vars'] = {'fixture_selected': service['name']}
                play = [{'hosts': 'all', 'gather_facts': False, 'vars': {
                    'fixture_expected': expected, 'fixture_fallback': fallback}, 'tasks': tasks}]
                path = play_root / 'clock-test.yml'
                path.write_text(yaml.safe_dump(play))
                result = subprocess.run([ansible, '-i', 'localhost,', '-c', 'local', str(path)],
                                        capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_existing_daemons_are_preserved_and_absence_installs_fallback(self):
        spec = importlib.util.spec_from_file_location('time_service', Path(c.__file__).with_name('time_service.py'))
        clock = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clock)
        for facts, expected in [
            ({}, 'systemd-timesyncd.service'),
            ({'chrony.service': {'state': 'running'}}, 'chrony.service'),
            ({'chrony.service': {'state': 'stopped'}}, 'chrony.service'),
            ({'chrony.service': {'state': 'stopped'}, 'ntp.service': {'state': 'running'}}, 'ntp.service'),
            ({'systemd-timesyncd.service': {'state': 'running'}}, 'systemd-timesyncd.service'),
        ]:
            chosen = clock.choose(facts)
            self.assertEqual(chosen['service'], expected)
            self.assertEqual(chosen['install_fallback'], expected == 'systemd-timesyncd.service')


if __name__ == '__main__':
    unittest.main()
