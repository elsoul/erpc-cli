# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Executable host orchestration with real file locks and inert native processes."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/jinja'))
import identity
import observe


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def public(value):
    data = bytes([65]) + bytes([value]) * 20
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    number, text = int.from_bytes(data, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        text = identity.ALPHABET[digit] + text
    return text


OWNER, SIGNER = public(0), public(1)


def account():
    return {'address': OWNER, 'witness_permission': {'type': 'Witness', 'id': 1, 'threshold': 1,
        'keys': [{'address': SIGNER, 'weight': 1}]},
        'owner_permission': {'keys': [{'address': OWNER, 'weight': 1}]},
        'active_permission': [{'keys': [{'address': OWNER, 'weight': 1}]}]}


class Observation(unittest.TestCase):
    def test_delegation_refuses_owner_active_reuse_and_unreviewed_key_schemes(self):
        self.assertTrue(observe.delegation(account(), OWNER, SIGNER))
        for kind in ('owner', 'active', 'threshold', 'scheme'):
            value = account()
            if kind == 'owner': value['owner_permission']['keys'][0]['address'] = SIGNER
            if kind == 'active': value['active_permission'][0]['keys'][0]['address'] = SIGNER
            if kind == 'threshold': value['witness_permission']['threshold'] = True
            if kind == 'scheme': value['witness_permission']['keys'][0]['pq_scheme'] = 1
            with self.assertRaises(ValueError):
                observe.delegation(value, OWNER, SIGNER)

    def test_observer_rejects_wrong_genesis_stale_head_and_mutating_methods(self):
        expected = {'network': 'nile', 'genesis': 'c' * 64, 'owner': OWNER, 'signer': SIGNER}
        def query(network, method, payload=None, local=False):
            if method.endswith('getblockbynum'): return {'blockID': 'c' * 64}
            if method.endswith('getnowblock'): return {'blockID': 'd' * 64, 'block_header': {'raw_data': {'number': 100, 'timestamp': int(time.time() * 1000)}}}
            if method.endswith('listwitnesses'): return {'witnesses': [{'address': OWNER, 'isJobs': True}]}
            if method.endswith('getaccount'): return account()
            return {'chainParameter': [{'key': 'getAccountUpgradeCost', 'value': 9999000000}]}
        value = observe.registration(expected, query)
        self.assertEqual(value['membership'], 'elected')
        self.assertTrue(value['witness_permission_valid'])
        self.assertEqual(value['candidate_fee_sun'], 9999000000)
        with self.assertRaises(ValueError): observe.network_state(dict(expected, genesis='a' * 64), query)
        with self.assertRaises(ValueError): observe.head({'blockID': 'd' * 64, 'block_header': {'raw_data': {'number': 100, 'timestamp': 1}}})
        with patch.object(observe.urllib.request, 'urlopen', side_effect=AssertionError('must not contact network')):
            with self.assertRaises(ValueError): observe.request('nile', 'wallet/broadcasttransaction')

    def test_native_grpc_requires_success_trailer_and_complete_uncompressed_frame(self):
        with tempfile.TemporaryDirectory() as root:
            def temporary(**kwargs): return tempfile.TemporaryDirectory(dir=root)
            for trailers, frame, success in [
                ('grpc-status: 0', b'\x00\x00\x00\x00\x01x', True),
                ('', b'ordinary HTTP 200 error body', False),
                ('grpc-status: 7', b'\x00\x00\x00\x00\x01x', False),
                ('grpc-status: 0\r\ngrpc-status: 0', b'\x00\x00\x00\x00\x01x', False),
                ('grpc-status: 0', bytes(5), False),
                ('grpc-status: 0', b'\x01\x00\x00\x00\x01x', False),
                ('grpc-status: 0', b'\x00\x00\x00\x00\x02x', False),
            ]:
                def run(args, **kwargs):
                    self.assertEqual(kwargs['input'], bytes(5))
                    Path(args[args.index('-D') + 1]).write_text('HTTP/2 200\r\n' + trailers + '\r\n')
                    Path(args[args.index('-o') + 1]).write_bytes(frame)
                    return subprocess.CompletedProcess(args, 0)
                self.assertEqual(observe.grpc(run, temporary), success)

    def test_json_rpc_rejects_wrong_chain_error_and_non_integer_request_id(self):
        expected = {'genesis': 'c' * 64}
        for value, accepted in [
            ({'jsonrpc': '2.0', 'id': 1, 'result': '0xcccccccc'}, True),
            ({'jsonrpc': '2.0', 'id': 1, 'result': '0x2b6653dc'}, False),
            ({'jsonrpc': '2.0', 'id': 1, 'error': {'message': 'not ready'}}, False),
            ({'jsonrpc': '2.0', 'id': True, 'result': '0xcccccccc'}, False),
        ]:
            import io
            with patch.object(observe.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(value).encode())):
                self.assertEqual(observe.json_rpc(expected), accepted)

    def test_launch_password_uses_only_inherited_stdin_and_clean_environment(self):
        launch = load('tron_launch_fixture', ROOT / 'templates/jinja/launch.py')
        for architecture in ('x86_64', 'aarch64'):
            for role in ('fullnode', 'validator'):
                contract = {'architecture': architecture, 'role': role}
                with patch.object(launch.Path, 'read_text', return_value=json.dumps(contract)), \
                     patch.object(launch.os, 'open', return_value=12) as opened, \
                     patch.object(launch.os, 'dup2') as duplicate, \
                     patch.object(launch.os, 'close'), patch.object(launch.os, 'execve') as execute:
                    launch.main()
                    duplicate.assert_called_once_with(12, 0)
                    self.assertEqual(opened.call_args.args[0], '/run/credentials/tron-node.service/witness-password' if role == 'validator' else '/dev/null')
                    program, args, env = execute.call_args.args
                    self.assertEqual(program, launch.JAVA[architecture])
                    self.assertEqual(set(env), {'PATH', 'LANG'})
                    self.assertEqual('--witness' in args, role == 'validator')
                    self.assertIn('-XX:-HeapDumpOnOutOfMemoryError', args)
                    self.assertFalse(any('password' in arg or 'credentials' in arg for arg in args))
                    self.assertEqual('-XX:+UseZGC' in args, architecture == 'aarch64')

    def test_signature_checks_both_network_primary_and_signing_subkey(self):
        verify = load('tron_verify_fixture', ROOT / 'templates/jinja/verify.py')
        primary, signing = 'a' * 40, 'b' * 40
        row = '[GNUPG:] VALIDSIG ' + signing + ' 2026-10-26 1 0 4 0 1 8 00 ' + primary
        verify.signature(row, primary, signing)
        for status, wanted in [(row, 'c' * 40), (row + '\n[GNUPG:] EXPKEYSIG expired', primary),
                               (row + '\n' + row, primary), ('[GNUPG:] GOODSIG untrusted', primary)]:
            with self.assertRaises(ValueError): verify.signature(status, wanted, signing)
        with self.assertRaises(ValueError): verify.signature(row, primary, 'd' * 40)


@unittest.skipUnless(os.name == 'posix', 'remote Linux host operations require POSIX locks')
class ControlPaths(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.module = load('tron_control_fixture', ROOT / 'templates/jinja/control.py')
        self.common = load('common_firewall_fixture', ROOT.parent / 'erpc-ops/templates/rpc-firewall.py')
        self.calls, self.queries = [], []
        self.active, self.live, self.elected, self.clock = False, None, False, True
        self.expected = self.module.expected_contract('nile', 'fullnode', 'c' * 64, 'x86_64', '-', '-', 'i' * 26)
        for directory in ('etc/tron', 'etc/erpc/tron', 'opt/erpc/runs', 'etc/credstore.encrypted', 'run'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.firewall = self.common.Firewall('tron', self.root, self.command)
        self.available, self.allocated = 4_000_000_000_000, 0
        self.control = self.module.Control(self.root, self.command, lambda: self.firewall, self.query,
            lambda data, run: {'available_bytes': self.available, 'allocated_bytes': self.allocated})
        self.file('/etc/tron/contract.json', json.dumps(self.expected))
        self.install()
        self.intent = 'a' * 32
        self.inspector = patch.object(identity, 'inspect', side_effect=lambda text, password, expected, architecture, **kw: expected)
        self.inspector.start()
        self.addCleanup(self.inspector.stop)

    def file(self, name, value):
        target = self.root / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
        return target

    def install(self):
        directory = '/opt/tron/releases/GreatVoyage-Nile-v4.8.2.4-PQ1-build1-x86_64'
        values = {}
        for filename, key in [('FullNode.jar', 'jar_sha256'), ('network.conf', 'config_sha256'), ('erpc/ErpcTronKey.class', 'inspector_sha256')]:
            values[key] = self.module.digest(self.file(directory + '/' + filename, 'inert public artifact ' + key))
        values['node_config_sha256'] = self.module.digest(self.file('/etc/tron/node.conf', 'public operational overrides'))
        values.update(directory=directory, network='nile', architecture='x86_64', genesis='c' * 64, client_version='4.8.2.4.PQ1_build1')
        self.target = dict(network='nile', architecture='x86_64', genesis='c' * 64, version='4.8.2.4.PQ1_build1',
                           tag='GreatVoyage-Nile-v4.8.2.4-PQ1-build1', commit='e' * 40,
                           jar_sha256=values['jar_sha256'], config_sha256=values['config_sha256'])
        values['target'] = self.target
        self.file('/etc/tron/release.json', json.dumps(values))
        self.control.path('/opt/tron/current').symlink_to(self.control.path(directory))

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        output = b''
        if argv[:2] == ['systemctl', 'show']:
            output = (b'1234' if self.active else b'0') if '--property=MainPID' in argv else b'loaded'
        elif argv[:2] == ['systemctl', 'is-active']:
            output = b'active' if self.active else b'inactive'
        elif argv[:2] == ['timedatectl', 'show']:
            output = b'yes' if self.clock else b'no'
        elif argv[:2] == ['systemctl', 'stop'] or argv[:3] == ['systemctl', 'disable', '--now']:
            if 'tron-node' in argv or 'tron-node.service' in argv: self.active = False
        elif argv[:2] in (['systemctl', 'start'], ['systemctl', 'restart']):
            self.control.runtime(self.expected)  # The actual read-only precondition under its parent's lock.
            self.active = True
        elif argv[:3] == ['nft', '-j', 'list']:
            if self.live is None: raise subprocess.CalledProcessError(1, argv)
            output = json.dumps({'nftables': [{'rule': {'policy': self.live, 'counter': {'packets': len(self.calls), 'bytes': 1}}}]}).encode()
        elif argv[:2] == ['nft', 'list']:
            return subprocess.CompletedProcess(argv, 0 if self.live else 1, (self.live or '').encode(), b'')
        elif argv[:2] == ['nft', '-f']:
            self.live = Path(argv[2]).read_text().splitlines()[-1]
        elif argv[:2] == ['nft', 'delete']:
            self.live = None
        elif argv[:2] == ['systemd-creds', 'encrypt']:
            Path(argv[-1]).write_bytes(b'encrypted-fixture:' + kwargs['input'])
        elif argv[:2] == ['systemd-creds', 'decrypt']:
            output = Path(argv[-2]).read_bytes().removeprefix(b'encrypted-fixture:')
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def query(self, network, method, payload=None, local=False):
        self.queries.append((network, method, payload))
        if method.endswith('getblockbynum'): return {'blockID': self.expected['genesis']}
        if method.endswith('getnowblock'): return {'blockID': 'd' * 64, 'block_header': {'raw_data': {'number': 100, 'timestamp': int(time.time() * 1000)}}}
        if method.endswith('getaccount'): return account()
        if method.endswith('listwitnesses'): return {'witnesses': [{'address': OWNER, 'isJobs': self.elected}]}
        return {'chainParameter': []}

    @contextlib.contextmanager
    def lock(self):
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        try:
            self.module.fcntl.flock(fd, self.module.fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def prepare(self, intent=None):
        self.intent = intent or self.intent
        with self.lock(): self.control.dispatch('prepare', self.expected, self.intent, target=self.target)

    def policy(self, suffix='aaaaaa', confirm=True):
        operation = 'r-20261026t120000-' + suffix
        bundle = self.file('/opt/erpc/runs/' + operation + '/bundle.tar.gz', 'inert bundle ' + suffix)
        self.file('/opt/erpc/runs/' + operation + '/bundle/firewall-candidate.nft', 'policy-' + suffix)
        receipt = (operation, self.module.digest(bundle))
        with self.lock():
            self.control.dispatch('guard-phase', self.expected, self.intent, target=self.target)
            self.firewall.dispatch('apply', *receipt)
        if confirm: self.control.dispatch('confirm', self.expected, self.intent, receipt)
        return receipt

    def activate(self, receipt):
        with self.lock(): self.control.dispatch('activate', self.expected, self.intent, receipt, target=self.target)

    def validator(self):
        self.expected = self.module.expected_contract('nile', 'validator', 'c' * 64, 'x86_64', OWNER, SIGNER, 'i' * 26)
        self.file('/etc/tron/contract.json', json.dumps(self.expected))

    def test_manifest_command_uses_deploy_arguments_and_authenticates_actual_files(self):
        sys.path.insert(0, str(ROOT / 'templates/jinja'))
        manifest = load('tron_manifest_fixture', ROOT / 'templates/jinja/manifest.py')
        release = self.control.read('/etc/tron/release.json')
        self.prepare()
        argv = ['manifest.py', release['directory'], self.intent, json.dumps(self.target)]
        original_replace = os.replace
        def replace(source, target):
            original_replace(source, self.control.path(str(target)))
        with patch.object(manifest.sys, 'argv', argv), patch.object(manifest, 'Control', return_value=self.control), \
             patch.object(manifest, 'Path', side_effect=lambda path: self.control.path(path)), \
             patch.object(manifest.os, 'replace', side_effect=replace):
            manifest.main()
            self.control.verify_install(self.expected)
            self.file(release['directory'] + '/network.conf', 'changed upstream fixture')
            before = self.control.path('/etc/tron/release.json').read_bytes()
            with self.assertRaises(ValueError): manifest.main()
            self.assertEqual(self.control.path('/etc/tron/release.json').read_bytes(), before)

    def test_wrong_network_and_orphan_history_cannot_mutate_or_adopt_host(self):
        for operation in ('prepare', 'destroy', 'stop', 'start', 'import', 'confirm'):
            with self.assertRaises(ValueError): self.control.dispatch(operation, dict(self.expected, network='mainnet'), self.intent)
        self.assertFalse(self.calls)
        self.assertFalse(self.queries)
        self.control.path('/etc/tron/contract.json').unlink()
        self.file('/etc/credstore.encrypted/tron/generations/retained', 'retained ciphertext fixture')
        with self.assertRaises(ValueError): self.control.dispatch('guard-init', self.expected)
        self.assertFalse(self.control.path('/etc/tron/contract.json').exists())

    def test_same_network_foreign_inventory_cannot_adopt_stop_update_or_destroy(self):
        foreign = dict(self.expected, inventory_owner='j' * 26)
        for operation in ('guard-init', 'prepare', 'stop', 'destroy', 'start', 'confirm', 'activate', 'guard-phase', 'import', 'restore'):
            before = self.control.path('/etc/tron/contract.json').read_bytes()
            with self.assertRaises(ValueError): self.control.dispatch(operation, foreign, self.intent)
            self.assertEqual(self.control.path('/etc/tron/contract.json').read_bytes(), before)
        self.assertFalse(self.calls)
        self.assertFalse(self.queries)
        self.assertFalse(self.control.path('/etc/tron/preparing').exists())
        with self.assertRaises(ValueError): self.module.expected_contract('nile', 'fullnode', 'c' * 64, 'x86_64', '-', '-', 'not-an-item-id')

    def test_prepare_prompts_have_no_timer_and_start_requires_confirmed_phase(self):
        self.prepare()
        self.assertFalse(any(c[0] in ('nft', 'systemd-run') for c in self.calls))
        with self.assertRaises(ValueError): self.control.dispatch('start', self.expected)
        self.activate(self.policy())
        self.assertTrue(self.active)
        self.control.dispatch('stop', self.expected)
        self.assertFalse(self.active)
        with self.assertRaises(ValueError): self.control.runtime(self.expected)
        self.control.dispatch('start', self.expected)
        self.assertTrue(self.active)

    def test_superseding_or_stopping_rejects_old_activation_even_when_filter_matches(self):
        self.prepare('a' * 32)
        receipt = self.policy()
        self.control.dispatch('stop', self.expected)
        with self.lock():
            with self.assertRaises(ValueError): self.control.dispatch('activate', self.expected, 'a' * 32, receipt)
        self.prepare('b' * 32)
        with self.lock():
            with self.assertRaises(ValueError): self.control.dispatch('guard-phase', self.expected, 'a' * 32)
        self.assertFalse(self.active)

    def test_elected_new_host_is_refused_but_original_same_host_restore_retains_generations(self):
        self.validator()
        self.prepare()
        payload = {'keystore': 'encrypted native fixture', 'password': 'fixture password'}
        self.elected = True
        with self.assertRaises(ValueError): self.control.dispatch('import', self.expected, self.intent, payload=payload)
        self.assertFalse(self.control.path('/etc/tron/identity.json').exists())
        self.elected = False
        self.control.dispatch('import', self.expected, self.intent, payload=payload)
        self.activate(self.policy())
        self.assertTrue(self.active)
        self.elected = True
        self.prepare('b' * 32)
        selected = self.control.path('/etc/credstore.encrypted/tron/current')
        old = selected.resolve()
        (old / 'witness-password').unlink()
        with self.assertRaises(OSError): self.control.dispatch('import', self.expected, self.intent, payload=payload)
        self.control.dispatch('restore', self.expected, self.intent, payload=payload)
        self.assertNotEqual(selected.resolve(), old)
        self.assertTrue(old.exists())
        self.assertFalse(self.active)

    def test_restore_rejects_missing_receipt_and_partial_publication_is_fenced(self):
        self.validator()
        self.prepare()
        payload = {'keystore': 'encrypted native fixture', 'password': 'fixture password'}
        with self.assertRaises(OSError): self.control.dispatch('restore', self.expected, self.intent, payload=payload)
        replace = self.module.os.replace
        def interrupted(source, target):
            if str(target).endswith('/tron/current'): raise OSError('inert interrupted pointer publication')
            return replace(source, target)
        with patch.object(self.module.os, 'replace', side_effect=interrupted):
            with self.assertRaises(OSError): self.control.dispatch('import', self.expected, self.intent, payload=payload)
        self.assertTrue(self.control.path('/etc/tron/identity.json').exists())
        with self.assertRaises(ValueError): self.control.dispatch('start', self.expected)
        self.control.dispatch('restore', self.expected, self.intent, payload=payload)
        self.activate(self.policy())
        self.assertTrue(self.active)

    def test_failed_drain_cannot_replace_client_or_credentials(self):
        self.active = True
        original = self.control.run
        def failed(argv, **kwargs):
            if argv[:2] == ['systemctl', 'stop']:
                return subprocess.CompletedProcess(argv, 0, b'', b'')  # Process still present despite nominal command success.
            return original(argv, **kwargs)
        self.control.run = failed
        with self.assertRaises(ValueError): self.prepare()
        self.assertTrue(self.control.path('/etc/tron/preparing').exists())
        self.assertFalse(any(c[0] in ('systemd-creds', 'nft') for c in self.calls))


    def test_rolled_back_or_queued_old_policy_cannot_activate_new_deployment(self):
        self.prepare('a' * 32)
        first = self.policy(confirm=False)
        self.firewall.dispatch('rollback', *first)
        with self.assertRaises((ValueError, OSError)): self.control.dispatch('confirm', self.expected, 'a' * 32, first)
        with self.assertRaises((ValueError, OSError)): self.activate(first)
        self.assertFalse(self.active)
        self.prepare('b' * 32)
        second = self.policy('bbbbbb', confirm=False)
        # A delayed old callback sees the newer immutable operation and is inert.
        before = list(self.calls)
        self.firewall.dispatch('rollback', *first)
        self.assertEqual(self.calls, before)
        self.control.dispatch('confirm', self.expected, 'b' * 32, second)
        self.activate(second)
        self.assertTrue(self.active)
        with self.assertRaises(ValueError): self.control.dispatch('confirm', self.expected, 'a' * 32, first)

    def test_monotonic_release_floor_rejects_old_cli_and_ambiguous_same_version_before_stopping(self):
        future = dict(self.target, version='4.8.2.4.PQ2_build1', tag='GreatVoyage-Nile-v4.8.2.4-PQ2-build1', commit='f' * 40)
        self.module.transition(self.expected, self.target, future)
        self.active = True
        release = self.control.read('/etc/tron/release.json')
        release['target'] = future
        self.file('/etc/tron/release.json', json.dumps(release))
        with self.assertRaises(ValueError): self.prepare()
        self.assertTrue(self.active)
        self.assertFalse(self.calls)
        self.assertFalse(self.control.path('/etc/tron/preparing').exists())
        release['target'] = self.target
        self.file('/etc/tron/release.json', json.dumps(release))
        with self.lock():
            with self.assertRaises(ValueError): self.control.dispatch('prepare', self.expected, self.intent, target=dict(self.target, commit='f' * 40))
        self.assertTrue(self.active)
        self.assertFalse(self.calls)
        for version in ('4.8.2.4-rc1', '4.8.2.4.PQ1_build01', '4.8.2.4'):
            with self.assertRaises(ValueError): self.module.version_order('nile', version)

    def test_interrupted_future_target_cannot_be_replaced_or_published_by_old_catalog(self):
        future = dict(self.target, version='4.8.2.5.PQ1_build1', tag='GreatVoyage-Nile-v4.8.2.5-PQ1-build1', commit='f' * 40)
        with self.lock(): self.control.dispatch('prepare', self.expected, self.intent, target=future)
        self.control.dispatch('stop', self.expected)
        with self.assertRaises(ValueError): self.prepare('b' * 32)
        with self.lock(): self.control.dispatch('prepare', self.expected, 'c' * 32, target=future)
        before = self.control.path('/etc/tron/release.json').read_bytes()
        with self.lock():
            with self.assertRaises(ValueError): self.control.dispatch('guard-phase', self.expected, 'c' * 32, target=self.target)
            with self.assertRaises(ValueError): self.control.dispatch('activate', self.expected, 'c' * 32, ('r-20261026t120000-aaaaaa', 'f' * 64), target=self.target)
        manifest = load('tron_manifest_mismatch_fixture', ROOT / 'templates/jinja/manifest.py')
        directory = self.control.read('/etc/tron/release.json')['directory']
        with patch.object(manifest, 'Control', return_value=self.control), patch.object(manifest.sys, 'argv', ['manifest.py', directory, 'c' * 32, json.dumps(self.target)]):
            with self.assertRaises(ValueError): manifest.main()
        self.assertEqual(self.control.path('/etc/tron/release.json').read_bytes(), before)
        self.assertFalse(self.active)

    def test_disk_pressure_blocks_resume_activation_start_and_reboot_but_allows_stop_destroy(self):
        self.available = 500_000_000_000
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.control.path('/etc/tron/preparing').exists())
        # A partial 3 TB database on the same volume counts toward bootstrap
        # capacity; demanding 3.5 TB free again would incorrectly reject resume.
        self.allocated = 3_000_000_000_000
        self.prepare()
        receipt = self.policy()
        self.available = self.module.OPERATING_RESERVE - 1
        with self.assertRaises(ValueError): self.activate(receipt)
        self.assertTrue(self.control.path('/etc/tron/preparing').exists())
        self.available = 500_000_000_000
        self.activate(receipt)
        self.assertTrue(self.active)
        self.available = 0
        for operation in ('start', 'restart', 'runtime', 'prepare'):
            with self.assertRaises(ValueError): self.control.dispatch(operation, self.expected, self.intent)
        self.control.dispatch('stop', self.expected)
        self.assertFalse(self.active)
        with self.lock(): self.control.dispatch('destroy', self.expected)
        self.assertFalse(self.active)

    def test_capacity_uses_allocated_bytes_and_rejects_nested_mounts_or_failed_measurement(self):
        from types import SimpleNamespace
        data = self.root / 'var/lib/tron'
        data.mkdir(parents=True)
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            self.assertIn('--block-size=1', args)
            return subprocess.CompletedProcess(args, 0, b'12345\tdata\n', b'')
        with patch.object(self.module.os, 'statvfs', return_value=SimpleNamespace(f_bavail=100, f_frsize=4096)):
            self.assertEqual(self.module.data_capacity(data, run), {'available_bytes': 409600, 'allocated_bytes': 12345})
        (data / 'database').symlink_to(self.root / 'etc', target_is_directory=True)
        with self.assertRaises(ValueError): self.module.data_capacity(data, run)
        self.assertEqual(len(calls), 1)
        (data / 'database').unlink()
        def failed(*args, **kwargs): raise subprocess.CalledProcessError(1, args)
        with self.assertRaises(subprocess.CalledProcessError): self.module.data_capacity(data, failed)

    def test_clock_permission_and_ciphertext_failures_prevent_activation(self):
        self.validator()
        self.prepare()
        payload = {'keystore': 'encrypted native fixture', 'password': 'fixture password'}
        self.clock = False
        with self.assertRaises(ValueError): self.control.dispatch('import', self.expected, self.intent, payload=payload)
        self.assertFalse(self.control.path('/etc/tron/identity.json').exists())
        self.clock = True
        self.control.dispatch('import', self.expected, self.intent, payload=payload)
        receipt = self.policy()
        self.clock = False
        with self.assertRaises(ValueError): self.activate(receipt)
        self.assertTrue(self.control.path('/etc/tron/preparing').exists())
        self.clock = True
        keyfile = self.control.path('/etc/credstore.encrypted/tron/current/witness.json')
        original = keyfile.read_bytes()
        keyfile.write_bytes(b'corrupt fixture')
        with self.assertRaises(ValueError): self.activate(receipt)
        keyfile.write_bytes(original)
        original_query = self.control.query
        def unsafe(network, method, *args, **kwargs):
            result = original_query(network, method, *args, **kwargs)
            if method.endswith('getaccount'): result['owner_permission']['keys'][0]['address'] = SIGNER
            return result
        self.control.query = unsafe
        with self.assertRaises(ValueError): self.activate(receipt)
        self.assertFalse(self.active)
        self.assertTrue(self.control.path('/etc/tron/preparing').exists())

    def test_missing_contract_rejects_any_retained_data_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            control = self.module.Control(root, self.command, lambda: self.firewall, self.query)
            for directory in ('etc/tron', 'var/lib/tron', 'etc/erpc/tron'):
                path = root / directory
                path.mkdir(parents=True, exist_ok=True)
                retained = path / 'retained-history'
                retained.write_text('public inert history')
                with self.assertRaises(ValueError): control.dispatch('guard-init', self.expected)
                self.assertEqual(retained.read_text(), 'public inert history')
                retained.unlink()
            control.dispatch('guard-init', self.expected)
            self.assertFalse(self.calls)

    def test_confirmation_waits_for_lock_and_rechecks_superseding_intent(self):
        self.prepare('a' * 32)
        receipt = self.policy()
        entered, done, outcomes = threading.Event(), threading.Event(), []
        def late():
            entered.set()
            try: self.control.dispatch('confirm', self.expected, 'a' * 32, receipt)
            except ValueError: outcomes.append('refused')
            finally: done.set()
        with self.lock():
            thread = threading.Thread(target=late)
            thread.start()
            self.assertTrue(entered.wait(2))
            self.assertFalse(done.wait(0.05))
            self.control.dispatch('prepare', self.expected, 'b' * 32, target=self.target)
        thread.join(5)
        self.assertEqual(outcomes, ['refused'])
        self.assertTrue(done.is_set())


if __name__ == '__main__':
    unittest.main()
