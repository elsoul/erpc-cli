# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""NEAR host failure paths using inert files and mocked system tools only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('control', ROOT / 'templates/node/control.py')
c = importlib.util.module_from_spec(spec)
sys.modules['control'] = c
spec.loader.exec_module(c)
# Temporary files model root authority using this unprivileged test account.
c.ROOT_UID = os.getuid()
spec = importlib.util.spec_from_file_location('setup', ROOT / 'templates/node/setup.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.calls = []
        def run(argv, **kwargs):
            self.calls.append(argv)
            output = b''
            if argv[:2] == ['systemctl', 'show']: output = b'not-found'
            return subprocess.CompletedProcess(argv, 0, output, b'')
        self.control = c.Control(self.root, run=run)
        self.control.path('/opt/erpc').mkdir(parents=True)
        self.control.home.mkdir(parents=True)
        network=getattr(self,'network','testnet')
        self.expected = {'owner': 'fixtureowner', 'network': network, 'role': 'rpc',
                         'genesis_hash': c.PINS[network]['genesis_hash']}
        with patch.object(self.control, 'account_snapshot', return_value=([], [])):
            self.control.reserve(self.expected)
        self.addCleanup(patch.stopall)
        patch.object(self.control, 'account', return_value=(20000, 20000)).start()
        self.target = {key: c.PINS[network][key] for key in ('version', 'commit', 'image')}
        directory = self.control.path('/etc/near')
        directory.mkdir(parents=True)
        for kind in ('config', 'genesis'):
            raw = json.dumps({'fixture': kind}).encode()
            (directory / (kind + '.json')).write_bytes(raw)
            self.target[kind + '_sha256'] = self.control.digest(raw)
        self.target['policy_sha256'] = 'a' * 64
        encrypted = self.control.path('/etc/credstore.encrypted/near-node.key')
        encrypted.parent.mkdir(parents=True)
        encrypted.write_bytes(b'inert encrypted fixture')
        encrypted.chmod(0o600)
        self.control.write('identity.json', {'contract': self.expected, 'cipher_sha256': self.control.digest(encrypted.read_bytes()),
                                           'plaintext_sha256': 'b' * 64, 'public_key': 'ed25519:public-fixture'})
        patch.object(self.control, 'firewall_action').start()
        patch.object(self.control, 'capacity').start()
        patch.object(self.control, 'container', return_value=None).start()

    def prepare(self):
        self.control.begin_install(self.expected, self.target, '1' * 32)
        self.control.finish_install(self.expected, self.target, '1' * 32)

    def activate(self):
        self.control.activate(self.expected, {'policy_sha256': self.target['policy_sha256'], 'intent': '1' * 32,
                                             'firewall': {'run': 'r-fixture', 'bundle': 'c' * 64}})

    def test_prepared_files_never_authorize_start_before_exact_firewall_confirmation(self):
        self.prepare()
        for action in ('guard', 'start', 'restart'):
            with self.assertRaises(c.Refused): self.control.dispatch(action, self.expected)
        with self.assertRaises(c.Refused):
            self.control.activate(self.expected, {'policy_sha256': 'd' * 64, 'intent': '1' * 32, 'firewall': {'run': 'r-fixture', 'bundle': 'c' * 64}})
        with patch.object(self.control, 'firewall', side_effect=c.Refused('wrong receipt')):
            with self.assertRaises(c.Refused): self.activate()
        self.assertTrue((self.control.directory / 'installing.json').exists())
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))
        self.activate()
        self.assertEqual(self.control.guard(self.expected), self.target)

    def test_every_mutation_refuses_foreign_owner_network_and_role(self):
        for action in ('reserve', 'begin-install', 'finish-install', 'activate', 'start', 'stop', 'restart', 'retire'):
            for change in ({'owner': 'foreign'}, {'network': 'mainnet', 'genesis_hash': c.PINS['mainnet']['genesis_hash']}, {'role': 'validator'}):
                expected = dict(self.expected, **change)
                with self.assertRaises(c.Refused): self.control.dispatch(action, expected, self.target)
        self.assertEqual(self.calls, [])

    def test_missing_contract_cannot_adopt_orphan_data_credentials_or_receipts(self):
        for artifact in ('/var/lib/near/data', '/etc/near/genesis.json', '/etc/credstore.encrypted/near-node.pending',
                         '/etc/erpc/near/retired', '/var/lib/near/validator_key.json'):
            with tempfile.TemporaryDirectory() as directory:
                control = c.Control(Path(directory))
                path = control.path(artifact); path.parent.mkdir(parents=True, exist_ok=True); path.touch()
                with self.assertRaises(c.Refused): control.reserve(self.expected)

    def test_retry_cannot_change_policy_or_config_under_pending_installation(self):
        self.prepare()
        self.control.begin_install(self.expected, self.target, '1' * 32)
        for field in ('policy_sha256', 'config_sha256'):
            target = dict(self.target, **{field: 'd' * 64})
            with self.assertRaises(c.Refused): self.control.begin_install(self.expected, target, '1' * 32)
        with self.assertRaises(c.Refused): self.control.reserve(self.expected)

    def test_historical_release_remains_readable_but_cannot_start_as_the_current_qualified_runtime(self):
        self.prepare(); self.activate()
        installed = dict(self.target, version='2.13.0', commit='d' * 40,
                         image='nearprotocol/nearcore@sha256:' + 'e' * 64)
        self.control.write('installed.json', installed)
        self.assertEqual(self.control.target(self.expected,installed,qualified=False)['version'],'2.13.0')
        with self.assertRaises(c.Refused):self.control.guard(self.expected)
        self.calls.clear()
        with self.assertRaises(c.Refused):
            self.control.dispatch('start',self.expected,{'policy_sha256':installed['policy_sha256']})
        self.assertFalse(any(call[:2]==['systemctl','start'] for call in self.calls))
        self.control.dispatch('stop',self.expected)
        self.assertEqual(self.control.read('installed.json'),installed)
        with self.assertRaises(c.Refused): self.control.target(self.expected, installed)

    def test_same_version_cannot_replace_another_installed_source_or_image(self):
        for key, value in [('commit', 'e' * 40), ('image', 'nearprotocol/nearcore@sha256:' + 'e' * 64)]:
            self.control.write('installed.json', dict(self.target, **{key: value}))
            with self.assertRaises(c.Refused): self.control.begin_install(self.expected, self.target, '2' * 32)
            self.assertFalse((self.control.directory / 'activation-revoked').exists())
            self.assertEqual(self.calls, [])

    def test_config_genesis_and_peer_identity_changes_block_start(self):
        self.prepare(); self.activate()
        for path in ('/etc/near/config.json', '/etc/near/genesis.json', '/etc/credstore.encrypted/near-node.key'):
            file = self.control.path(path); original = file.read_bytes(); file.write_bytes(b'changed')
            with self.assertRaises(c.Refused): self.control.guard(self.expected)
            file.write_bytes(original)

    def test_failed_shutdown_retains_installation_fence(self):
        with patch.object(self.control, 'stopped', side_effect=c.Refused('failed stop')):
            with self.assertRaises(c.Refused): self.control.begin_install(self.expected, self.target, '1' * 32)
        self.assertTrue((self.control.directory / 'installing.json').exists())

    def test_retirement_fences_before_failed_stop_and_keeps_keys(self):
        self.prepare(); self.activate()
        with patch.object(self.control, 'stopped', side_effect=c.Refused('failed stop')):
            with self.assertRaises(c.Refused): self.control.retire(self.expected)
        with self.assertRaises(c.Refused): self.control.guard(self.expected)
        self.assertTrue(self.control.path('/etc/credstore.encrypted/near-node.key').exists())

    def test_missing_unit_still_stops_exact_owned_container(self):
        running = {'Id': 'f' * 64, 'State': {'Running': True}}
        stopped = {'Id': 'f' * 64, 'State': {'Running': False}}
        with patch.object(self.control, 'container', side_effect=[running, running, stopped]):
            self.control.stopped(self.expected)
        self.assertTrue(any(call[-4:] == ['stop', '--time', '180', 'f' * 64] for call in self.calls))
        with patch.object(self.control, 'container', return_value=running):
            with self.assertRaises(c.Refused): self.control.stopped(self.expected)

    def test_original_identity_receipt_recovers_only_matching_pending_ciphertext(self):
        encrypted = self.control.path('/etc/credstore.encrypted/near-node.key')
        pending = encrypted.with_suffix('.pending'); encrypted.rename(pending)
        s.peer_identity(self.control, self.expected, {}, Path('unused'), 'unused')
        self.assertTrue(encrypted.exists()); self.assertFalse(pending.exists())
        encrypted.rename(pending); pending.write_bytes(b'foreign ciphertext')
        with self.assertRaises(c.Refused): s.peer_identity(self.control, self.expected, {}, Path('unused'), 'unused')
        self.assertFalse(encrypted.exists())

    def test_concurrent_remote_play_refuses_standalone_mutation(self):
        import os
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        try:
            c.fcntl.flock(fd, c.fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError): self.control.dispatch('stop', self.expected)
        finally: os.close(fd)

    def test_ready_requires_owned_socket_genesis_peer_and_fresh_synced_blocks(self):
        from datetime import datetime, timezone
        from io import BytesIO
        self.prepare(); self.activate()
        value = {'chain_id': 'testnet', 'genesis_hash': self.expected['genesis_hash'],
                 'node_public_key': 'ed25519:public-fixture', 'validator_account_id': None,
                 'validator_public_key': None, 'version': {'version': self.target['version'], 'commit': self.target['commit']}, 'protocol_version': 88,
                 'sync_info': {'syncing': False, 'latest_block_height': 500,
                               'latest_block_time': datetime.now(timezone.utc).isoformat()}}
        class Opener:
            def open(self, *_args, **_kwargs): return BytesIO(json.dumps(value).encode())
        original = self.control.command
        def command(*argv, **kwargs):
            if argv[:2] == ('systemctl', 'is-active'):
                return subprocess.CompletedProcess(argv, 0, b'active', b'')
            if argv[0] == 'ss':
                return subprocess.CompletedProcess(argv, 0, b'LISTEN 0 128 127.0.0.1:3030 0.0.0.0:* users:(("neard",pid=123,fd=3))', b'')
            return original(*argv, **kwargs)
        with patch.object(self.control, 'command', side_effect=command), patch.object(self.control, 'container', return_value={'Config': {'User': '20000:20000'}, 'State': {'Running': True, 'Pid': 123}}), patch.object(c.urllib.request, 'build_opener', return_value=Opener()):
            self.assertTrue(self.control.status(self.expected)['ready'])
            with patch.object(self.control, 'container', return_value={'Config': {'User': '22000:22000'}, 'State': {'Running': True, 'Pid': 123}}):
                self.assertFalse(self.control.status(self.expected)['ready'])
            for field, bad in [('chain_id', 'mainnet'), ('genesis_hash', 'wrong'), ('node_public_key', 'foreign'), ('validator_account_id', 'unexpected.near')]:
                old = value[field]; value[field] = bad
                self.assertFalse(self.control.status(self.expected)['ready'])
                value[field] = old
            value['sync_info']['syncing'] = True
            self.assertFalse(self.control.status(self.expected)['ready'])
            value['sync_info']['syncing'] = False
            value['sync_info']['latest_block_time'] = '2020-01-01T00:00:00Z'
            self.assertFalse(self.control.status(self.expected)['ready'])

    def test_boot_cannot_use_new_inventory_policy_on_old_installed_configuration(self):
        self.prepare(); self.activate()
        with self.assertRaises(c.Refused):
            self.control.dispatch('start', self.expected, {'policy_sha256': 'd' * 64})
        self.calls.clear()
        self.control.dispatch('start', self.expected, {'policy_sha256': self.target['policy_sha256']})
        self.assertTrue(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def test_stop_and_new_preparation_invalidate_old_queued_activation(self):
        self.prepare()
        self.control.dispatch('stop', self.expected)
        with self.assertRaises(c.Refused): self.activate()
        self.control.begin_install(self.expected, self.target, '2' * 32)
        self.control.finish_install(self.expected, self.target, '2' * 32)
        with self.assertRaises(c.Refused): self.activate()
        self.control.activate(self.expected, {'policy_sha256': self.target['policy_sha256'], 'intent': '2' * 32,
                                             'firewall': {'run': 'r-new-fixture', 'bundle': 'd' * 64}})

    def test_failed_replacement_intent_or_target_publication_cannot_keep_old_activation(self):
        for broken in ('operation.json', 'installing.json'):
            self.prepare()
            original = self.control.write
            def write(name, value):
                if name == broken: raise OSError('inert interrupted publication')
                return original(name, value)
            with patch.object(self.control, 'write', side_effect=write):
                with self.assertRaises(OSError): self.control.begin_install(self.expected, self.target, '2' * 32)
            self.assertTrue((self.control.directory / 'activation-revoked').exists())
            with self.assertRaises(c.Refused): self.activate()
            with self.assertRaises(c.Refused): self.control.guard(self.expected)
            self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def test_retirement_inspection_failure_keeps_durable_cancel_and_boot_fence(self):
        self.prepare()
        with patch.object(self.control, 'container', side_effect=c.Refused('inert daemon inspection failure')):
            with self.assertRaises(c.Refused): self.control.retire(self.expected)
        self.assertEqual(self.control.read('retired'), {'contract': self.expected})
        with self.assertRaises(c.Refused): self.activate()
        with self.assertRaises(c.Refused): self.control.guard(self.expected, manual=True)
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def test_stop_intent_write_failure_cancels_old_activation_before_shutdown(self):
        self.prepare()
        original = self.control.write
        def write(name, value):
            if name == 'operation.json': raise OSError('inert stopped intent failure')
            return original(name, value)
        with patch.object(self.control, 'write', side_effect=write):
            with self.assertRaisesRegex(c.Refused, 'cancellation was not persisted'): self.control.dispatch('stop', self.expected)
        self.assertEqual(self.control.read('stopped'), {'contract': self.expected})
        with self.assertRaises(c.Refused): self.activate()
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def test_first_and_later_stop_storage_failures_attempt_owned_shutdown_and_keep_keys(self):
        self.prepare(); self.activate()
        original = self.control.write
        key = self.control.path('/etc/credstore.encrypted/near-node.key').read_bytes()
        for action in ('stop', 'retire'):
            for failure in ('first', 'operation.json', 'all'):
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    return subprocess.CompletedProcess(argv, 0, b'loaded' if argv[:2] == ['systemctl', 'show'] else b'', b'')
                def write(name, value):
                    if failure == 'all' or name == ('retired' if action == 'retire' else 'stopped') and failure == 'first' or name == failure:
                        raise OSError('inert private storage detail')
                    return original(name, value)
                with patch.object(self.control, 'write', side_effect=write), patch.object(self.control, 'run', side_effect=run):
                    with self.assertRaisesRegex(c.Refused, 'cancellation was not persisted') as error:
                        self.control.dispatch(action, self.expected)
                self.assertNotIn('private', str(error.exception))
                self.assertEqual(sum(call[:2] == ['systemctl', 'stop'] for call in calls), 1)
                if action == 'retire': self.assertTrue(any(call[:2] == ['systemctl', 'disable'] for call in calls))
                self.assertEqual(self.control.path('/etc/credstore.encrypted/near-node.key').read_bytes(), key)

    def test_stop_fsync_failure_after_rename_still_attempts_shutdown(self):
        self.prepare()
        calls = []
        original = c.os.fsync
        count = [0]
        def failed(fd):
            count[0] += 1
            if count[0] == 2: raise OSError('inert directory durability failure')
            return original(fd)
        with patch.object(c.os, 'fsync', side_effect=failed), patch.object(self.control, 'stopped', side_effect=lambda expected: calls.append(expected)):
            with self.assertRaisesRegex(c.Refused, 'cancellation was not persisted'):
                self.control.dispatch('stop', self.expected)
        self.assertEqual(calls, [self.expected])
        self.assertTrue((self.control.directory / 'stopped').exists())
        with self.assertRaises(c.Refused): self.activate()

    def test_combined_stop_failures_are_explicit_and_foreign_scope_never_stops(self):
        with patch.object(self.control, 'write', side_effect=OSError('inert private storage detail')), \
             patch.object(self.control, 'stopped', side_effect=c.Refused('inert private shutdown detail')) as stopped:
            with self.assertRaisesRegex(c.Refused, 'cancellation could not be persisted and owned shutdown also failed') as error:
                self.control.dispatch('stop', self.expected)
            self.assertNotIn('private', str(error.exception))
            self.assertEqual(stopped.call_count, 1)
            with self.assertRaises(c.Refused): self.control.dispatch('stop', dict(self.expected, owner='foreign'))
            self.assertEqual(stopped.call_count, 1)

    def test_retirement_without_a_unit_is_repeatable_and_keeps_original_credentials(self):
        key = self.control.path('/etc/credstore.encrypted/near-node.key').read_bytes()
        self.control.retire(self.expected)
        self.control.retire(self.expected)
        self.assertEqual(self.control.read('retired'), {'contract': self.expected})
        self.assertEqual(self.control.path('/etc/credstore.encrypted/near-node.key').read_bytes(), key)
        self.assertFalse(any(call[:2] in (['systemctl', 'disable'], ['systemctl', 'start']) for call in self.calls))

    def test_explicit_start_clears_only_a_stopped_completed_installation(self):
        self.prepare(); self.activate()
        self.control.dispatch('stop', self.expected)
        with self.assertRaises(c.Refused): self.control.guard(self.expected)
        self.control.dispatch('start', self.expected, {'policy_sha256': self.target['policy_sha256']})
        self.assertFalse((self.control.directory / 'stopped').exists())
        self.control.guard(self.expected)


class Configuration(unittest.TestCase):
    def test_native_nanosecond_utc_time_and_short_fraction_are_portable(self):
        for value in ('2026-01-01T00:00:00.123456789Z', '2026-01-01T00:00:00.1Z', '2026-01-01T00:00:00+00:00'):
            self.assertIsInstance(c.block_age(value), float)
        for value in ('2026-01-01T00:00:00', '2026-01-01T00:00:00+01:00', '2026-01-01T00:00:00.1234567890Z'):
            with self.assertRaises(c.Refused): c.block_age(value)

    def test_separate_data_volume_and_nested_mount_allocation_cannot_use_parent_free_space(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[:4], ['du', '-s', '-x', '-B1'])
                return subprocess.CompletedProcess(argv, 0, b'0 data', b'')
            control = c.Control(Path(directory), run=run)
            data = control.home / 'data'; data.mkdir(parents=True)
            def usage(path): return type('Usage', (), {'free': 1 if path == data else 4_000_000_000_000})()
            with patch.object(c.shutil, 'disk_usage', side_effect=usage) as measured:
                with self.assertRaises(c.Refused): control.capacity({'network': 'mainnet', 'role': 'rpc'})
                measured.assert_called_once_with(data)
            with patch.object(c.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 100_000_000_000})()):
                # du -x excludes other devices: only data on this volume can
                # offset its bootstrap budget, regardless of nested mount size.
                with self.assertRaises(c.Refused): control.capacity({'network': 'mainnet', 'role': 'rpc'})
            self.assertEqual(len(calls), 2)

    def test_documented_cpu_features_are_required_on_every_processor(self):
        valid = 'flags : cx16 popcnt sse4_1 sse4_2 avx sha_ni\n'
        s.cpu_features(valid * 2)
        for bad in ('', valid.replace('sha_ni', ''), valid + 'flags : avx\n'):
            with self.assertRaises(c.Refused): s.cpu_features(bad)

    def test_configuration_removes_active_validator_debug_and_telemetry_paths(self):
        original = {'rpc': {'addr': '0.0.0.0:3030'}, 'network': {'boot_nodes': ''}, 'tracked_shards': [0], 'gc_num_epochs_to_keep': 11}
        peer = 'ed25519:' + '1' * 31 + '2@8.8.8.8:24567'
        value = s.configuration(original, {'network': 'testnet', 'role': 'rpc'}, False, True, [peer])
        self.assertEqual(value['rpc']['addr'], '127.0.0.1:3030')
        self.assertEqual(value['rpc']['prometheus_addr'], '0.0.0.0:3032')
        self.assertFalse(value['rpc']['enable_debug_rpc'])
        self.assertEqual(value['validator_key_file'], '/etc/near/disabled-validator.json')
        self.assertEqual(value['tracked_shards_config'], 'AllShards')
        self.assertEqual(value['telemetry'], {'endpoints': []})
        self.assertEqual(value['network']['boot_nodes'], peer)
        self.assertEqual(value['gc_num_epochs_to_keep'], 5)
        self.assertNotIn('gc', value)
        with self.assertRaises(c.Refused): s.configuration(original, {'network': 'testnet', 'role': 'rpc'}, False, False, [])

    def test_capacity_distinguishes_initial_sync_from_retained_allocated_database(self):
        control = c.Control()
        for network, initial in [('mainnet', 3_500_000_000_000), ('testnet', 1_400_000_000_000)]:
            with self.assertRaises(c.Refused): control.capacity({'network': network, 'role': 'rpc'}, usage=(initial - 1, 0))
            control.capacity({'network': network, 'role': 'rpc'}, usage=(initial, 0))
            control.capacity({'network': network, 'role': 'rpc'}, usage=(100_000_000_000, initial))
            with self.assertRaises(c.Refused): control.capacity({'network': network, 'role': 'rpc'}, usage=(99_999_999_999, initial))


class ForwardUpgrade(unittest.TestCase):
    def setUp(self):
        self.fixture=Lifecycle('runTest');self.fixture.network='mainnet';self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.control=self.fixture.control;self.expected=self.fixture.expected;self.target=self.fixture.target
        self.old=dict(self.target,**c.PREVIOUS_PINS['mainnet'])
        self.peers=['ed25519:'+'1'*31+'2'+'@8.8.8.8:24567']
        self.bootstrap={'request':{'contract':self.expected,'image':self.old['image'],'policy':self.target['policy_sha256']},'peers':self.peers}
        self.request={'bootstrap_url':'unused','policy_sha256':self.target['policy_sha256'],'allow_pending_upgrade':True}
        self.data=self.control.home/'data/original';self.data.parent.mkdir();self.data.write_bytes(b'inert original database and signer-history bytes')
        self.data_before=(self.data.read_bytes(),self.data.stat().st_ino)
        self.key=self.control.path('/etc/credstore.encrypted/near-node.key');self.key_before=self.key.read_bytes()
        self.seed()

    def seed(self):
        for name in ('activation-revoked','stopped','retired','firewall.json',self.control.upgrade_name(self.expected)):
            self.control.state_path(name).unlink(missing_ok=True)
        self.control.write('installed.json',self.old)
        self.control.write('installing.json',self.old)
        self.control.write('operation.json',{'intent':'1'*32})
        self.control.write('bootstrap.json',self.bootstrap)
        self.fixture.calls.clear()

    def unchanged(self):
        self.assertEqual((self.data.read_bytes(),self.data.stat().st_ino),self.data_before)
        self.assertEqual(self.key.read_bytes(),self.key_before)

    def begin(self,explicit=True):
        with patch.object(s,'observe_bootstrap',side_effect=AssertionError('must retain original peers')):
            self.assertEqual(s.bootstrap(self.control,self.expected,dict(self.request,allow_pending_upgrade=explicit)),self.peers)
        self.control.begin_install(self.expected,self.target,'2'*32,explicit)

    def old_activation_refused(self):
        with self.assertRaises(c.Refused):
            self.control.dispatch('activate',self.expected,{'policy_sha256':self.old['policy_sha256'],
                'intent':'1'*32,'firewall':{'run':'r-original','bundle':'a'*64}})

    def finish(self):
        self.control.finish_install(self.expected,self.target,'2'*32)
        self.control.activate(self.expected,{'policy_sha256':self.target['policy_sha256'],'intent':'2'*32,
            'firewall':{'run':'r-forward','bundle':'b'*64}})
        self.assertEqual(self.control.guard(self.expected)['version'],'2.14.0')
        self.unchanged()

    def test_explicit_forward_update_retains_original_pending_proof_and_native_data(self):
        with self.assertRaises(c.Refused):self.begin(False)
        self.assertEqual(self.control.read('installing.json'),self.old)
        self.assertFalse(self.control.state_path(self.control.upgrade_name(self.expected)).exists())
        self.begin();self.old_activation_refused();self.unchanged()
        history=self.control.upgrade_record(self.expected)
        self.assertEqual(history['from'],self.old);self.assertEqual(history['bootstrap'],self.bootstrap)
        self.begin(False);self.finish()
        self.assertEqual(self.control.upgrade_record(self.expected),history)
        with patch.dict(c.PINS,{'mainnet':dict(c.PINS['mainnet'],**c.PREVIOUS_PINS['mainnet'])}):
            with self.assertRaisesRegex(c.Refused,'downgrade'):
                self.control.begin_install(self.expected,self.old,'3'*32)
        self.unchanged()

    def test_forward_update_refuses_another_source_policy_genesis_or_rewritten_journal(self):
        for key,value in [('commit','e'*40),('image','nearprotocol/nearcore@sha256:'+'e'*64),('version','2.13.0')]:
            self.control.write('installing.json',dict(self.old,**{key:value}))
            with self.assertRaises(c.Refused):self.begin()
            self.assertFalse(self.control.state_path(self.control.upgrade_name(self.expected)).exists())
        self.seed()
        for key in ('policy_sha256','genesis_sha256'):
            with self.assertRaises(c.Refused):
                self.control.begin_install(self.expected,dict(self.target,**{key:'e'*64}),'2'*32,True)
        self.begin()
        path=self.control.upgrade_name(self.expected);history=self.control.read(path)
        history['contract']=dict(self.expected,owner='foreign');self.control.write(path,history)
        self.control.write('bootstrap.json',self.bootstrap)
        with self.assertRaises(c.Refused):self.begin(False)
        self.unchanged()

    def test_each_forward_publication_barrier_preserves_restriction_and_exact_retry(self):
        real=os.fsync;calls=[]
        def count(fd):calls.append(True);return real(fd)
        with patch.object(os,'fsync',side_effect=count):self.begin()
        total=len(calls);self.assertGreaterEqual(total,12)
        for point in range(1,total+1):
            with self.subTest(point=point):
                self.seed();seen=[]
                def fail(fd):
                    seen.append(True)
                    if len(seen)==point:raise OSError('inert forward-publication barrier')
                    return real(fd)
                with patch.object(os,'fsync',side_effect=fail):
                    with self.assertRaises(OSError):self.begin()
                self.old_activation_refused();self.unchanged()
                self.begin();self.finish()
                self.assertEqual(self.control.upgrade_record(self.expected)['bootstrap'],self.bootstrap)

    def test_actual_setup_upgrades_pending_original_without_recreating_identity_or_fetching_genesis(self):
        directory=self.control.path('/etc/near')
        raw=json.dumps({'rpc':{},'network':{},'store':{}}).encode()
        (directory/'source-config.json').write_bytes(raw)
        profile=dict(c.PINS['mainnet'],config_sha256=self.control.digest(raw),genesis_sha256=self.old['genesis_sha256'])
        self.control.write('genesis-source.json',{'network':'mainnet','source_sha256':profile['genesis_sha256']})
        cpu=self.control.path('/proc/cpuinfo');cpu.parent.mkdir();cpu.write_text('flags: cx16 popcnt sse4_1 sse4_2 avx sha_ni\n')
        request=dict(self.request,intent='2'*32,rpc_public=False,metrics_public=False,
                     config_url='unused-verified-cache',genesis_url='unused-verified-cache')
        commands=[]
        def docker(*args):
            commands.append(args)
            self.assertNotIn('init',args,'the original peer key must never be regenerated')
            self.assertTrue(args[0]=='pull' or args[-1]=='--version','no node is run in this fixture')
            value=('neard (release '+profile['version']+') (build fixture) (commit '+profile['commit']+')').encode()
            return subprocess.CompletedProcess(args,0,value,b'')
        with patch.dict(c.PINS,{'mainnet':profile}),patch.object(self.control,'docker',side_effect=docker), \
             patch.object(s,'fetch',side_effect=AssertionError('original authenticated source must be reused')), \
             patch.object(s,'observe_bootstrap',side_effect=AssertionError('original peers must be retained')):
            result=s.prepare(self.control,self.expected,request)
        self.assertEqual(result['version'],'2.14.0');self.assertEqual(len(commands),2)
        self.assertEqual(self.control.read('installed.json'),result)
        self.assertEqual(self.control.upgrade_record(self.expected)['from'],self.old)
        self.old_activation_refused();self.unchanged()
        self.control.activate(self.expected,{'policy_sha256':result['policy_sha256'],'intent':'2'*32,
            'firewall':{'run':'r-prepared-upgrade','bundle':'b'*64}})
        self.assertEqual(self.control.guard(self.expected)['version'],'2.14.0');self.unchanged()


class Bootstrap(unittest.TestCase):
    public = 'ed25519:' + '1' * 31 + '2'

    def response(self):
        return {'active_peers': [{'id': self.public, 'addr': '8.8.8.8:24567'},
                                  {'id': 'ed25519:' + '1' * 31 + '3', 'addr': '1.1.1.1:24567'}],
                'known_producers': [{'peer_id': self.public}]}

    def test_only_reachable_known_producers_become_bounded_public_peers(self):
        self.assertEqual(s.peer_list(self.response()), [self.public + '@8.8.8.8:24567'])
        for address in ('127.0.0.1:24567', '10.0.0.1:24567', '[::1]:24567', '[::ffff:8.8.8.8]:24567', '[fec0::1]:24567', '[::192.168.1.1]:24567',
                        '[3ffe::1]:24567', '[2620:4f:8000::1]:24567',
                        '192.0.0.8:24567', '192.88.99.2:24567', '[100:0:0:1::1]:24567', '[3fff::1]:24567',
                        'localhost:24567', '8.8.8.8:0', 'user@8.8.8.8:24567', '8.8.8.8:24567/path'):
            response = self.response(); response['active_peers'][0]['addr'] = address
            with self.assertRaises(c.Refused): s.peer_list(response)
        with self.assertRaises(c.Refused): s.peer_list({'active_peers': [], 'known_producers': []})
        with self.assertRaises(c.Refused): s.peer_key('ed25519:' + '1' * 32)
        self.assertEqual(s.peer_endpoint('[2606:4700:4700::1111]:24567'), '[2606:4700:4700::1111]:24567')
        with patch.object(s.ipaddress.IPv6Address, 'is_global', property(lambda _: (_ for _ in ()).throw(AssertionError('version-dependent classification must not be used')))):
            self.assertEqual(s.peer_endpoint('[2606:4700:4700::1111]:24567'), '[2606:4700:4700::1111]:24567')
            with self.assertRaises(c.Refused): s.peer_endpoint('[fec0::1]:24567')
            with self.assertRaises(c.Refused): s.peer_endpoint('[::192.168.1.1]:24567')

    def test_network_info_requires_fixed_origin_matching_genesis_and_fresh_status(self):
        import io
        from datetime import datetime, timezone
        expected = {'network': 'testnet', 'genesis_hash': c.PINS['testnet']['genesis_hash']}
        status = {'chain_id': 'testnet', 'genesis_hash': expected['genesis_hash'],
                  'sync_info': {'syncing': False, 'latest_block_time': datetime.now(timezone.utc).isoformat()}}
        response = {'jsonrpc': '2.0', 'id': 'erpc-bootstrap', 'result': self.response()}
        calls = []
        class Body(io.BytesIO):
            status = 200
            headers = {}
        class Opener:
            def open(self, request, **kwargs):
                calls.append(request)
                return Body(json.dumps(status if request.full_url.endswith('/status') else response).encode())
        # Synthetic parser inputs; the opener above prevents every network call.
        origin = lambda scheme, authority: s.urllib.parse.urlunsplit((scheme, authority, '', '', ''))
        endpoint = origin('https', 'rpc.testnet.near.org')
        with patch.object(s.urllib.request, 'build_opener', return_value=Opener()):
            self.assertEqual(s.observe_bootstrap(expected, endpoint), [self.public + '@8.8.8.8:24567'])
            self.assertEqual(json.loads(calls[-1].data)['method'], 'network_info')
            for scheme, host in [('https', 'rpc.mainnet.near.org'), ('http', 'rpc.testnet.near.org'), ('https', 'rpc.testnet.near.org.evil.example'), ('https', 'user@rpc.testnet.near.org')]:
                bad = origin(scheme, host)
                with self.assertRaises(c.Refused): s.observe_bootstrap(expected, bad)
            status['genesis_hash'] = 'wrong'
            with self.assertRaises(c.Refused): s.observe_bootstrap(expected, endpoint)
            status['genesis_hash'] = expected['genesis_hash']; status['sync_info']['latest_block_time'] = '2020-01-01T00:00:00Z'
            with self.assertRaises(c.Refused): s.observe_bootstrap(expected, endpoint)

    def test_interrupted_target_reuses_original_peers_without_contacting_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            control = c.Control(Path(directory)); control.directory.mkdir(parents=True)
            expected = {'network': 'testnet', 'role': 'rpc'}
            request = {'bootstrap_url': 'unused', 'policy_sha256': 'a' * 64}
            peers = [self.public + '@8.8.8.8:24567']
            with patch.object(s, 'observe_bootstrap', return_value=peers) as observe:
                self.assertEqual(s.bootstrap(control, expected, request), peers)
                observe.assert_called_once()
            control.write('installing.json', {'inert': True})
            with patch.object(s, 'observe_bootstrap', side_effect=AssertionError('must preserve original target')):
                self.assertEqual(s.bootstrap(control, expected, request), peers)
                with self.assertRaises(c.Refused): s.bootstrap(control, expected, dict(request, policy_sha256='b' * 64))


if __name__ == '__main__': unittest.main()
