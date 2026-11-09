# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline failure-path tests. Every network/process operation is mocked."""
import importlib.machinery
import importlib.util
import io
import os
import shutil
import pathlib
import subprocess
import tempfile
import threading
import unittest
import sys
sys.dont_write_bytecode = True
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1] / 'templates' / 'jinja'


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / (name + '.py.j2')))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Probes(unittest.TestCase):
    def test_grpc_requires_protocol_success_not_http_success(self):
        module = load('erpc-sui-status')
        def response(status, body):
            def run(argv, **kwargs):
                self.assertEqual(kwargs['input'], bytes(5))
                self.assertIn('--http2-prior-knowledge', argv)
                pathlib.Path(argv[argv.index('-D') + 1]).write_text('HTTP/2 200\n' + status)
                pathlib.Path(argv[argv.index('-o') + 1]).write_bytes(body)
                return subprocess.CompletedProcess(argv, 0)
            return run
        for trailers, body, wanted in [
            ('grpc-status: 0\n', bytes(6), True),
            ('grpc-status: 14\n', bytes(6), False),
            ('', bytes(6), False),
            ('grpc-status: 0\n', bytes(5), False),
        ]:
            with patch.object(module.subprocess, 'run', side_effect=response(trailers, body)):
                self.assertEqual(module.grpc(), wanted)

    def test_missing_or_failed_metrics_remain_unknown(self):
        module = load('erpc-sui-status')
        with patch.object(module.urllib.request, 'urlopen', side_effect=OSError('offline')):
            self.assertEqual(module.metrics(), {})
        content = b'last_executed_checkpoint 34\nhighest_synced_checkpoint 36\nuptime{version="v",chain_identifier="4c78adac"} 8\n'
        with patch.object(module.urllib.request, 'urlopen', return_value=io.BytesIO(content)):
            self.assertEqual(module.metrics()['chain_id'], '4c78adac')
        with patch.object(module.urllib.request, 'urlopen', return_value=io.BytesIO(b'last_executed_checkpoint NaN\n')):
            self.assertNotIn('last_executed_checkpoint', module.metrics())

    def test_identity_loss_is_never_silently_regenerated(self):
        module = load('erpc-sui-identity')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original_path = pathlib.Path
            def mapped(name):
                return root / str(name).lstrip('/')
            with patch.object(module, 'pathlib') as paths, patch.object(module.subprocess, 'run') as run, patch.object(module.sys, 'argv', ['identity', 'testnet', 'fullnode', 'a' * 64]):
                paths.Path.side_effect = mapped
                marker = mapped('/etc/sui/identity-established')
                marker.parent.mkdir(parents=True)
                marker.touch()
                with self.assertRaises(SystemExit):
                    module.main()
                self.assertEqual(run.call_count, 1)
                self.assertIn("guard-account", run.call_args.args[0])
                run.reset_mock()
                credential = mapped('/etc/credstore.encrypted/sui-network.key')
                credential.parent.mkdir(parents=True)
                credential.write_text('encrypted fixture')
                def reject_decrypt(argv, **kwargs):
                    if argv[0] == 'systemd-creds':
                        raise subprocess.CalledProcessError(1, argv)
                    return subprocess.CompletedProcess(argv, 0)
                run.side_effect = reject_decrypt
                with self.assertRaises(subprocess.CalledProcessError):
                    module.main()
                self.assertEqual(credential.read_text(), 'encrypted fixture')
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0][1], 'decrypt')
                self.assertIsNotNone(original_path)


@unittest.skipUnless(os.name == 'posix', 'remote Linux controller uses POSIX flock')
class ControlPaths(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.module = load('erpc-sui-control')
        self.expected = {'network': 'testnet', 'role': 'fullnode', 'genesis': 'a' * 64}
        self.calls = []
        self.live = 'candidate'
        self.intent = 'b' * 32
        self.control = self.module.Control(self.root, self.command, owner=os.getuid())
        # These existing firewall/recovery cases model the separately exercised
        # original-account/native-release boundary (authority_test.py).
        for method in ('account', 'release', 'credential_condition'):
            context = patch.object(self.control, method, return_value={'service_uid':999,'service_gid':999})
            context.start(); self.addCleanup(context.stop)
        # Source history has separate actual-controller/fault tests in release_test.py.
        context = patch.object(self.module.release_authority, 'recovery_allowed')
        context.start(); self.addCleanup(context.stop)
        context = patch.object(self.module.release_authority, 'runtime')
        context.start(); self.addCleanup(context.stop)
        for path in ['opt/erpc', 'etc/sui', 'etc/erpc/sui', 'var/lib/sui', 'run']:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.file('/etc/sui/contract.json', __import__('json').dumps(self.expected))

    def file(self, path, text):
        target = self.control.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def command(self, argv, **kwargs):
        if argv == ['/usr/bin/systemctl','--version']:return subprocess.CompletedProcess(argv,0,b'systemd 255 (fixture)\n',b'')
        self.calls.append(argv)
        output = b''
        if argv[:3] == ['nft', '-j', 'list']:
            if self.live is None:
                raise subprocess.CalledProcessError(1, argv)
            output = __import__('json').dumps({'nftables': [{'metainfo': {'version': 'test'}}, {'table': {'name': 'erpc_sui', 'handle': 5}}, {'rule': {'policy': self.live, 'counter': {'packets': len(self.calls), 'bytes': 500}}}]}).encode()
        elif argv[:2] == ['nft', '-f']:
            self.live = pathlib.Path(argv[2]).read_text()
        elif argv[:2] == ['nft', 'delete']:
            self.live = None
        if argv[:2] == ['systemctl', 'show']:
            output = b'loaded'
        if argv[:2] == ['systemctl', 'enable']:
            self.assertTrue(self.control.path('/etc/erpc/sui/confirmed.json').exists())
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def candidate(self, intent=None):
        self.intent = intent or self.intent
        self.control.dispatch('begin-intent', self.expected, self.intent)
        self.file('/etc/erpc/sui/pending.nft', self.live)
        self.control.dispatch('arm', self.expected, self.intent)
        self.control.dispatch('capture', self.expected, self.intent)

    def test_wrong_network_refuses_every_mutating_entry_before_process_calls(self):
        wrong = dict(self.expected, network='mainnet')
        for operation in ['guard-init', 'guard', 'confirm', 'rollback', 'load-firewall', 'start', 'stop', 'restart', 'recover-bootstrap']:
            self.calls.clear()
            with self.assertRaises(ValueError):
                self.control.dispatch(operation, wrong)
            self.assertEqual(self.calls, [], operation)
            self.assertEqual(__import__('json').loads(self.control.path('/etc/sui/contract.json').read_text()), self.expected)

    def fail_intent_write(self):
        original = self.control.write_text
        def write(path, *args, **kwargs):
            if path == '/etc/erpc/sui/latest-intent':
                raise OSError('inert cancellation persistence failure')
            return original(path, *args, **kwargs)
        return patch.object(self.control, 'write_text', write)

    def test_first_stop_write_failure_still_attempts_shutdown_without_success(self):
        self.file('/etc/erpc/sui/latest-intent', self.intent)
        for operation in ('stop', 'stop-owned'):
            self.calls.clear()
            with self.fail_intent_write():
                with self.assertRaisesRegex(ValueError, 'shutdown attempted but cancellation'):
                    self.control.dispatch(operation, self.expected)
            self.assertIn(['systemctl', 'stop', 'sui-bootstrap', 'sui-node'], self.calls)
            self.assertFalse(any(call[:2] in (['nft','delete'], ['systemctl','start']) for call in self.calls))
            self.assertEqual(self.control.path('/etc/erpc/sui/latest-intent').read_text(), self.intent)

    def test_carried_destroy_handles_absent_partial_and_removed_services(self):
        self.file('/etc/erpc/sui/latest-intent', self.intent)
        original=self.control.run
        for present in (set(),{'sui-node'},{'sui-bootstrap'},{'sui-node','sui-bootstrap'}):
            current=set(present);self.calls.clear()
            def run(argv,**kwargs):
                if argv[:2]==['systemctl','show']:
                    self.calls.append(argv)
                    return subprocess.CompletedProcess(argv,0,b'loaded' if argv[-1] in current else b'not-found',b'')
                if argv[:2]==['systemctl','stop'] and not set(argv[2:])<=current:
                    raise subprocess.CalledProcessError(5,argv)  # Real systemd refuses nonexistent units.
                return original(argv,**kwargs)
            with patch.object(self.control,'run',side_effect=run):
                self.control.dispatch('stop-owned',self.expected)
                stopped=[call for call in self.calls if call[:2]==['systemctl','stop']]
                self.assertEqual(stopped,[['systemctl','stop',*(unit for unit in ('sui-bootstrap','sui-node') if unit in present)]] if present else [])
                # The play removes unit definitions after this successful phase.
                current.clear();self.calls.clear();self.control.dispatch('stop-owned',self.expected)
                self.assertFalse(any(call[:2]==['systemctl','stop'] for call in self.calls))

    def test_carried_destroy_refuses_unknown_unit_state_and_loaded_shutdown_failure(self):
        self.file('/etc/erpc/sui/latest-intent',self.intent)
        original=self.control.run
        def unknown(argv,**kwargs):
            if argv[:2]==['systemctl','show']:
                self.calls.append(argv);return subprocess.CompletedProcess(argv,0,b'unknown-fixture',b'')
            return original(argv,**kwargs)
        with patch.object(self.control,'run',side_effect=unknown):
            with self.assertRaisesRegex(ValueError,'cannot verify service state'):
                self.control.dispatch('stop-owned',self.expected)
        self.assertFalse(any(call[:2]==['systemctl','stop'] for call in self.calls))
        def failed(argv,**kwargs):
            if argv[:2]==['systemctl','stop']:raise subprocess.CalledProcessError(1,argv)
            return original(argv,**kwargs)
        with patch.object(self.control,'run',side_effect=failed):
            with self.assertRaisesRegex(ValueError,'owned stop or disable failed'):self.control.dispatch('stop-owned',self.expected)
            with self.fail_intent_write():
                with self.assertRaisesRegex(ValueError,'persistence and owned shutdown both failed'):
                    self.control.dispatch('stop-owned',self.expected)

    def test_scope_mismatch_refuses_shutdown_during_storage_failure(self):
        self.file('/etc/erpc/sui/latest-intent', self.intent)
        with self.fail_intent_write():
            for operation in ('stop','stop-owned','prepare-validator','recover-bootstrap'):
                with self.assertRaises(ValueError):
                    self.control.dispatch(operation, dict(self.expected, genesis='c'*64))
        self.assertFalse(self.calls)

    def test_stop_error_with_or_without_storage_error_never_reports_success(self):
        self.file('/etc/erpc/sui/latest-intent', self.intent)
        with patch.object(self.control,'stop',side_effect=subprocess.CalledProcessError(1,['inert-owned-stop'])) as stop:
            with self.fail_intent_write():
                with self.assertRaisesRegex(ValueError,'persistence and owned shutdown both failed'):
                    self.control.dispatch('stop',self.expected)
            self.assertEqual(stop.call_count,1)
            with self.assertRaises(subprocess.CalledProcessError):self.control.dispatch('stop',self.expected)
            self.assertEqual(stop.call_count,2)

    def test_failed_rollback_cancellation_keeps_policy_and_callback_material(self):
        self.candidate();self.calls.clear()
        policy=self.live
        with self.fail_intent_write():
            with self.assertRaisesRegex(ValueError,'shutdown attempted'):
                self.control.dispatch('rollback',self.expected,self.intent)
        self.assertIn(['systemctl','stop','sui-bootstrap','sui-node'],self.calls)
        self.assertEqual(self.live,policy)
        self.assertTrue(self.control.path('/run/erpc-sui-firewall.armed').exists())
        self.assertTrue(self.control.path('/etc/erpc/sui/pending.json').exists())
        # Explicit retry may finish cancellation after storage is repaired.
        self.control.dispatch('rollback',self.expected,self.intent)
        self.assertFalse(self.control.path('/run/erpc-sui-firewall.armed').exists())

    def test_validator_first_marker_failure_still_invalidates_and_stops(self):
        expected=dict(self.expected,role='validator')
        self.file('/etc/sui/contract.json',__import__('json').dumps(expected))
        self.file('/etc/erpc/sui/latest-intent',self.intent)
        original = self.control.write_text
        def fail_marker(path,text):
            if path == '/etc/sui/validator-preparing': raise OSError('inert marker failure')
            return original(path,text)
        with patch.object(self.control,'write_text',side_effect=fail_marker):
            with self.assertRaisesRegex(ValueError,'shutdown attempted'):
                self.control.dispatch('prepare-validator',expected)
        self.assertIn(['systemctl','stop','sui-bootstrap','sui-node'],self.calls)
        self.assertTrue(self.control.path('/etc/erpc/sui/latest-intent').read_text().startswith('key-preparation:'))

    def test_bootstrap_recovery_storage_failure_never_moves_retained_data(self):
        history=self.file('/var/lib/sui/db/live/inert-history','retained history')
        self.file('/etc/erpc/sui/latest-intent',self.intent)
        with patch.object(self.module.shutil,'disk_usage',return_value=type('Usage',(),{'free':4_000_000_000_000})()):
            with self.fail_intent_write():
                with self.assertRaisesRegex(ValueError,'shutdown attempted'):
                    self.control.dispatch('recover-bootstrap',self.expected)
        self.assertEqual(history.read_text(),'retained history')
        self.assertFalse(list(self.control.path('/var/lib/sui').glob('db.quarantine.*')))
        self.assertIn(['systemctl','stop','sui-bootstrap','sui-node'],self.calls)

    def test_rollback_fences_listeners_and_reboot(self):
        self.candidate()
        self.calls.clear()
        self.control.dispatch('rollback', self.expected, self.intent)
        stopped = self.calls.index(['systemctl', 'stop', 'sui-bootstrap', 'sui-node'])
        disabled = self.calls.index(['systemctl', 'disable', 'sui-bootstrap', 'sui-node'])
        removed = self.calls.index(['nft', 'delete', 'table', 'inet', 'erpc_sui'])
        self.assertLess(stopped, disabled); self.assertLess(disabled, removed)
        for operation in ['runtime', 'load-firewall', 'start', 'restart']:
            self.calls.clear()
            with self.assertRaises((ValueError, OSError)):
                self.control.dispatch(operation, self.expected)
            self.assertFalse(any(call[:2] in (['systemctl', 'start'], ['systemctl', 'restart']) for call in self.calls))

    def test_confirmed_live_fingerprint_survives_counters_but_rejects_rule_changes(self):
        self.candidate()
        self.control.dispatch('confirm', self.expected, self.intent)
        self.control.dispatch('runtime', self.expected)
        self.live = 'unreviewed rules'
        with self.assertRaises(ValueError):
            self.control.dispatch('runtime', self.expected)
        self.live = None
        self.control.dispatch('load-firewall', self.expected)
        self.control.dispatch('start', self.expected)
        self.assertIn(['systemctl', 'start', '--no-block', 'sui-bootstrap'], self.calls)

    def test_unmatched_candidate_is_not_confirmed_or_enabled(self):
        self.candidate()
        self.live = 'changed after apply'
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', self.expected, self.intent)
        self.assertFalse(self.control.path('/etc/erpc/sui/confirmed.json').exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'enable'] for c in self.calls))

    def test_delayed_confirmation_cannot_accept_previous_restored_policy(self):
        self.live = 'policy-A'
        self.candidate('a' * 32)
        self.control.dispatch('confirm', self.expected, self.intent)
        self.file('/etc/erpc/sui/previous.nft', 'policy-A')
        self.live = 'policy-B'
        self.candidate('b' * 32)
        self.control.dispatch('rollback', self.expected, self.intent)
        self.assertEqual(self.live, 'policy-A')
        self.calls.clear()
        for operation in ['confirm', 'start-confirmed']:
            with self.assertRaises(ValueError):
                self.control.dispatch(operation, self.expected, 'b' * 32)
        self.assertFalse(any(c[:2] in (['systemctl', 'enable'], ['systemctl', 'start']) for c in self.calls))

    def test_superseding_run_fences_old_confirmation_even_with_identical_rules(self):
        self.candidate('a' * 32)
        self.control.dispatch('confirm', self.expected, 'a' * 32)
        self.control.dispatch('begin-intent', self.expected, 'b' * 32)
        for operation in ['confirm', 'start-confirmed']:
            with self.assertRaises(ValueError):
                self.control.dispatch(operation, self.expected, 'a' * 32)
        self.candidate('b' * 32)
        self.control.dispatch('confirm', self.expected, 'b' * 32)
        with self.assertRaises(ValueError):
            self.control.dispatch('start-confirmed', self.expected, 'a' * 32)
        self.control.dispatch('start-confirmed', self.expected, 'b' * 32)
        self.control.dispatch('stop', self.expected)
        with self.assertRaises(ValueError):
            self.control.dispatch('start-confirmed', self.expected, 'b' * 32)

    def test_waiting_ssh_confirmation_rechecks_intent_under_the_common_lock(self):
        self.candidate('b' * 32)
        lock = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        self.module.fcntl.flock(lock, self.module.fcntl.LOCK_EX)
        entered = threading.Event()
        failures = []
        def delayed_confirm():
            entered.set()
            try:
                self.control.dispatch('confirm', self.expected, 'b' * 32)
            except ValueError as error:
                failures.append(str(error))
        waiter = threading.Thread(target=delayed_confirm)
        try:
            waiter.start()
            self.assertTrue(entered.wait(1))
            waiter.join(0.05)
            self.assertTrue(waiter.is_alive())
            # Simulate a later play while it owns node-run.sh's same lock.
            self.control.dispatch('begin-intent', self.expected, 'c' * 32)
        finally:
            self.module.fcntl.flock(lock, self.module.fcntl.LOCK_UN)
            os.close(lock)
        waiter.join(1)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(failures, ['deployment intent was superseded'])
        self.assertFalse(self.control.path('/etc/erpc/sui/confirmed.json').exists())

    def test_interrupted_live_database_is_quarantined_without_identity_loss(self):
        sentinel = self.file('/var/lib/sui/db/live/store/fixture', 'snapshot data')
        identity = self.file('/etc/credstore.encrypted/sui-network.key', 'encrypted fixture')
        free = shutil._ntuple_diskusage(10**13, 0, 10**13)
        with patch.object(self.module.shutil, 'disk_usage', return_value=free):
            self.control.dispatch('recover-bootstrap', self.expected)
        self.assertFalse(sentinel.exists())
        recovered = list(self.control.path('/var/lib/sui').glob('db.quarantine.*/live/store/fixture'))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].read_text(), 'snapshot data')
        self.assertEqual(identity.read_text(), 'encrypted fixture')
        self.assertFalse(self.control.path('/var/lib/sui/.bootstrap-complete').exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'start'] for c in self.calls))

    def test_recovery_refuses_completed_data_or_insufficient_headroom(self):
        marker = self.file('/var/lib/sui/.bootstrap-complete', '')
        with self.assertRaises(ValueError):
            self.control.dispatch('recover-bootstrap', self.expected)
        self.assertEqual(self.calls, [])
        marker.unlink()
        with patch.object(self.module.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
            with self.assertRaises(ValueError):
                self.control.dispatch('recover-bootstrap', self.expected)
        self.assertEqual(self.calls, [])

    def test_validator_metadata_and_restore_are_bound_to_the_host(self):
        import json
        from types import SimpleNamespace
        self.expected['role'] = 'validator'
        self.file('/etc/sui/contract.json', json.dumps(self.expected))
        metadata = {'info': {'name': 'reserved public metadata'}}
        original = self.file('/etc/sui/validator.json', json.dumps(metadata))
        with patch.object(self.module.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(metadata).encode()))):
            self.control.dispatch('guard-metadata', self.expected)
        with patch.object(self.module.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'{}'))):
            with self.assertRaises(ValueError):
                self.control.dispatch('guard-metadata', self.expected)
        self.assertEqual(json.loads(original.read_text()), metadata)
        self.assertEqual(self.calls, [])
        wrong = dict(self.expected, network='mainnet')
        with self.assertRaises(ValueError):
            self.control.dispatch('restore-validator', wrong)
        self.assertEqual(self.calls, [])
        with patch.object(self.module.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'{}'))):
            self.control.dispatch('restore-validator', self.expected)
        stopped = next(i for i, c in enumerate(self.calls) if c[:2] == ['systemctl', 'stop'])
        restored = next(i for i, c in enumerate(self.calls) if c[-1] == 'restore')
        self.assertLess(stopped, restored)
        self.assertFalse(any(c[:2] == ['systemctl', 'start'] for c in self.calls))

    def test_queued_old_rollback_cannot_mutate_a_new_candidate(self):
        self.live = 'policy-A'
        old_intent = 'a' * 32
        self.candidate(old_intent)
        lock = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        self.module.fcntl.flock(lock, self.module.fcntl.LOCK_EX)
        waiting, finished = threading.Event(), threading.Event()
        failures = []
        def expired():
            waiting.set()
            try:
                self.control.dispatch('rollback', self.expected, old_intent)
            except Exception as error:
                failures.append(error)
            finally:
                finished.set()
        timer = threading.Thread(target=expired)
        timer.start()
        try:
            self.assertTrue(waiting.wait(2))
            self.assertFalse(finished.wait(0.05))
            self.live = 'policy-B'
            self.candidate('b' * 32)
            before = list(self.calls)
        finally:
            os.close(lock)
        timer.join(5)
        self.assertTrue(finished.is_set())
        self.assertFalse(failures)
        self.assertEqual(self.calls, before)
        self.assertEqual(self.live, 'policy-B')
        self.assertEqual(self.control.path('/etc/erpc/sui/latest-intent').read_text(), 'b' * 32)
        self.assertEqual(self.control.path('/run/erpc-sui-firewall.armed').read_text(), 'b' * 32)
        self.control.dispatch('confirm', self.expected, 'b' * 32)
        self.control.dispatch('start-confirmed', self.expected, 'b' * 32)
        callbacks = [c for c in self.calls if c[0] == 'systemd-run']
        self.assertEqual(len(callbacks), 2)
        for callback, intent in zip(callbacks, [old_intent, 'b' * 32]):
            self.assertIn('--unit=erpc-sui-firewall-rollback-' + intent, callback)
            self.assertEqual(callback[-5:], ['rollback', 'testnet', 'fullnode', 'a' * 64, intent])
            self.assertNotIn('/bin/bash', callback)

    def test_legacy_pending_operation_must_settle_before_helper_upgrade(self):
        self.file('/run/erpc-sui-firewall.armed', '')
        with self.assertRaises(ValueError):
            self.control.dispatch('begin-intent', self.expected, 'b' * 32)
        self.assertFalse(self.control.path('/etc/erpc/sui/latest-intent').exists())
        self.assertEqual(self.calls, [])

    def test_credential_preparation_has_no_timer_and_fences_long_prompts(self):
        import hashlib, json
        self.expected['role'] = 'validator'
        self.file('/etc/sui/contract.json', json.dumps(self.expected))
        public = self.file('/etc/sui/validator.json', '{}')
        receipt = {'metadata': hashlib.sha256(public.read_bytes()).hexdigest()}
        for name in ('protocol', 'network', 'worker'):
            encrypted = self.file('/etc/credstore.encrypted/sui-validator/' + name + '.key', 'encrypted fixture ' + name)
            receipt[name] = hashlib.sha256(encrypted.read_bytes()).hexdigest()
        self.file('/etc/sui/validator-identity-established', json.dumps(receipt))
        self.candidate('a' * 32)
        self.control.dispatch('confirm', self.expected, 'a' * 32)
        before_filter = self.control.path('/etc/erpc/sui/firewall.nft').read_bytes()
        self.calls.clear()
        lock = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        try:
            self.module.fcntl.flock(lock, self.module.fcntl.LOCK_EX)
            self.control.dispatch('begin-intent', self.expected, 'b' * 32)
            self.control.dispatch('prepare-validator', self.expected)
        finally:
            os.close(lock)
        self.assertTrue(self.control.path('/etc/sui/validator-preparing').exists())
        self.assertFalse(self.control.path('/run/erpc-sui-firewall.armed').exists())
        self.assertFalse(any(c[0] in ('systemd-run', 'nft') for c in self.calls))
        self.assertIn(['systemctl', 'stop', 'sui-bootstrap', 'sui-node'], self.calls)
        # A prompt may outlive every old timer. No new timer was armed and an
        # already queued callback from the confirmed deployment is inert.
        self.control.dispatch('rollback', self.expected, 'a' * 32)
        for action in ('runtime', 'start', 'restart'):
            with self.assertRaises(ValueError):
                self.control.dispatch(action, self.expected)
        self.assertEqual(self.control.path('/etc/erpc/sui/firewall.nft').read_bytes(), before_filter)
        self.candidate('c' * 32)
        self.control.dispatch('confirm', self.expected, 'c' * 32)
        self.assertFalse(self.control.path('/etc/sui/validator-preparing').exists())
        self.control.dispatch('start-confirmed', self.expected, 'c' * 32)

    def test_timer_creation_failure_recovers_without_leaving_a_live_candidate(self):
        self.control.dispatch('begin-intent', self.expected, self.intent)
        self.file('/etc/erpc/sui/pending.nft', 'candidate')
        normal = self.control.run
        def fail(argv, **kwargs):
            if argv[0] == 'systemd-run':
                raise subprocess.CalledProcessError(1, argv)
            return normal(argv, **kwargs)
        self.control.run = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.control.dispatch('arm', self.expected, self.intent)
        self.assertIsNone(self.live)
        self.assertFalse(self.control.path('/run/erpc-sui-firewall.armed').exists())

    def test_missing_contract_never_adopts_orphan_validator_material(self):
        artifacts = [
            '/etc/credstore.encrypted/sui-validator/protocol.key',
            '/etc/sui/validator-identity-established', '/etc/sui/validator.json',
            '/etc/sui/validator-preparing', '/var/lib/sui/consensus-db/retained-state',
            '/etc/sui/identity-established', '/var/lib/sui/db/staging/retained-state',
        ]
        for artifact in artifacts:
            for role in ('fullnode', 'validator'):
                with self.subTest(artifact=artifact, role=role), tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    (root / 'var/lib').mkdir(parents=True)
                    path = root / artifact.lstrip('/')
                    path.parent.mkdir(parents=True)
                    path.write_text('retained fixture')
                    control = self.module.Control(root, self.command, owner=os.getuid())
                    before = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
                    self.calls.clear()
                    with self.assertRaises(ValueError):
                        control.dispatch('guard-init', dict(self.expected, role=role))
                    self.assertEqual(self.calls, [])
                    self.assertEqual(path.read_text(), 'retained fixture')
                    self.assertEqual(before, sorted(str(p.relative_to(root)) for p in root.rglob('*')))
                    self.assertFalse(control.path('/etc/sui/contract.json').exists())
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / 'var/lib').mkdir(parents=True)
            self.module.Control(pathlib.Path(directory), self.command, owner=os.getuid()).dispatch('guard-init', self.expected)


if __name__ == '__main__':
    unittest.main()
