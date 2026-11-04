# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Run the shipped controller against inert nft/systemd fixtures, never a node."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / 'templates/rpc-firewall.py'

class FirewallTests(unittest.TestCase):
    family = 'eth'
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        spec = importlib.util.spec_from_file_location('avax_firewall', SOURCE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.live, self.calls = None, []
        self.control = self.module.Firewall(self.family, self.root, self.command)
        self.control.directory.mkdir(parents=True)
        self.control.path('/opt/erpc/runs').mkdir(parents=True)

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        output, code = b'', 0
        if argv[:2] == ['systemctl', 'show']:
            output = b'loaded'
        elif argv[:3] == ['nft', '-j', 'list']:
            if self.live is None:
                raise subprocess.CalledProcessError(1, argv)
            output = json.dumps({'nftables':[{'metainfo':{'version':'fixture'}},{'rule':{'handle':42,'rules':self.live,'counter':{'packets':len(self.calls),'bytes':400}}}]}).encode()
        elif argv[:2] == ['nft', 'list']:
            output, code = (self.live.encode(), 0) if self.live else (b'', 1)
        elif argv[:2] == ['nft', '-f']:
            self.live = Path(argv[2]).read_text().splitlines()[-1]
        elif argv[:2] == ['nft', 'delete']:
            self.live = None
        return subprocess.CompletedProcess(argv, code, output, b'')

    def apply(self, suffix, rules):
        operation = 'r-20261026t120000-' + suffix
        run = self.control.path('/opt/erpc/runs/' + operation)
        (run/'bundle').mkdir(parents=True)
        bundle = ('inert immutable bundle ' + suffix).encode()
        (run/'bundle.tar.gz').write_bytes(bundle)
        (run/'bundle/firewall-candidate.nft').write_text(rules)
        digest = self.control.digest(bundle)
        # Same outer lock as node-run.sh, which holds it through the play.
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        try:
            self.module.fcntl.flock(fd, self.module.fcntl.LOCK_EX)
            self.control.dispatch('apply', operation, digest)
        finally:
            os.close(fd)
        return operation, digest

    def test_late_confirmation_cannot_accept_previous_allowlist_after_timeout(self):
        first = self.apply('aaaaaa', 'old-client-allowed')
        self.control.dispatch('confirm', *first)
        second = self.apply('bbbbbb', 'only-new-client-allowed')
        self.control.dispatch('rollback', *second)
        self.assertEqual(self.live, 'old-client-allowed')
        calls = len(self.calls)
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *second)
        self.assertEqual(len(self.calls), calls)
        self.assertEqual(self.control.read('confirmed.json')['operation'], first[0])

    def test_superseded_confirmation_and_queued_old_timer_cannot_change_new_run(self):
        first = self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('confirm', *first)
        second = self.apply('bbbbbb', 'policy-b')
        third = self.apply('cccccc', 'policy-c')
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *second)
        self.control.dispatch('rollback', *second)
        self.assertEqual(self.live, 'policy-c')
        self.control.dispatch('confirm', *third)
        self.control.dispatch('rollback', *third)
        self.control.dispatch('confirm', *third)  # Exact-operation retry only.
        self.assertEqual(self.live, 'policy-c')
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *first)

    def test_wrong_bundle_tampered_pending_and_live_rules_are_rejected(self):
        token = self.apply('aaaaaa', 'policy-a')
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', token[0], 'b' * 64)
        (self.control.directory/'pending.nft').write_text('tampered')
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *token)
        (self.control.directory/'pending.nft').write_text('policy-a')
        self.live = 'tampered-live'
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *token)
        self.assertFalse((self.control.directory/'confirmed.json').exists())

    def test_confirmation_and_rollback_share_the_exclusive_run_lock(self):
        import threading
        token = self.apply('aaaaaa', 'policy-a')
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        command = self.control.run
        def held(argv, **kwargs):
            if argv[:2] == ['systemctl', 'stop']:
                entered.set()
                if not release.wait(5):
                    raise AssertionError('test lock release timeout')
            return command(argv, **kwargs)
        self.control.run = held
        failures = []
        def confirm():
            try:self.control.dispatch('confirm', *token)
            except Exception as error:failures.append(error)
        def rollback():
            try:self.control.dispatch('rollback', *token)
            except Exception as error:failures.append(error)
            finally:done.set()
        confirmer = threading.Thread(target=confirm)
        confirmer.start()
        self.assertTrue(entered.wait(5))
        timer = threading.Thread(target=rollback)
        timer.start()
        self.assertFalse(done.wait(0.1), 'rollback bypassed the operation lock')
        release.set()
        confirmer.join(5);timer.join(5)
        self.assertFalse(failures)
        self.assertTrue(done.is_set())
        self.assertEqual(self.live, 'policy-a')
        self.assertFalse((self.control.directory/'pending.json').exists())


    def test_initial_timeout_cannot_be_confirmed(self):
        token = self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('rollback', *token)
        self.assertIsNone(self.live)
        stopped = next(i for i, call in enumerate(self.calls) if call[:3] == ['systemctl', 'disable', '--now'])
        removed = next(i for i, call in enumerate(self.calls) if call[:2] == ['nft', 'delete'])
        self.assertLess(stopped, removed)
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *token)

    def test_failed_service_stop_retains_filter_on_initial_rollback(self):
        token = self.apply('aaaaaa', 'policy-a')
        command = self.control.run
        def fail_stop(argv, **kwargs):
            if argv[:3] == ['systemctl', 'disable', '--now']:
                raise subprocess.CalledProcessError(1, argv)
            return command(argv, **kwargs)
        self.control.run = fail_stop
        with self.assertRaises(subprocess.CalledProcessError):
            self.control.dispatch('rollback', *token)
        self.assertEqual(self.live, 'policy-a')
        self.assertTrue((self.control.directory/'pending.json').exists())

    def test_invalid_operation_bundle_and_family_are_refused_before_commands(self):
        for operation, bundle in [('r-../../x','a'*64),('r-valid','a'*63),('r-valid','A'*64),('r-valid;id','a'*64)]:
            with self.assertRaises(ValueError):
                self.control.dispatch('confirm', operation, bundle)
        with self.assertRaises(ValueError):
            self.module.Firewall('../escape', self.root, self.command)
        self.assertFalse(self.calls)

    def test_boot_without_confirmed_or_live_policy_refuses_startup(self):
        self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('guard')
        self.live = None  # Kernel rules disappear at reboot; transient timer does too.
        with self.assertRaises(ValueError):
            self.control.dispatch('guard')
        with self.assertRaises(FileNotFoundError):
            self.control.dispatch('load')

    def test_boot_restores_only_confirmed_policy_and_invalidates_interrupted_candidate(self):
        first = self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('confirm', *first)
        second = self.apply('bbbbbb', 'policy-b')
        self.live = None
        self.control.dispatch('load')
        self.assertEqual(self.live, 'policy-a')
        self.control.dispatch('guard')
        with self.assertRaises(ValueError):
            self.control.dispatch('confirm', *second)

    def test_live_guard_does_not_deadlock_service_start_under_ansible_run_lock(self):
        import threading
        self.apply('aaaaaa', 'policy-a')
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        done, failures = threading.Event(), []
        def dependency():
            try: self.control.dispatch('load')
            except Exception as error: failures.append(error)
            finally: done.set()
        self.module.fcntl.flock(fd, self.module.fcntl.LOCK_EX)
        thread = threading.Thread(target=dependency)
        try:
            thread.start()
            self.assertTrue(done.wait(2), 'service dependency blocked on its parent play lock')
        finally:
            os.close(fd)
            thread.join(5)
        self.assertFalse(failures)

    def test_invalid_live_policy_fails_instead_of_deadlocking_its_parent_play(self):
        self.apply('aaaaaa', 'policy-a')
        self.live = 'unexpected-policy'
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        try:
            self.module.fcntl.flock(fd, self.module.fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError):
                self.control.dispatch('load')
        finally:
            os.close(fd)

    def test_unknown_service_state_cannot_remove_filter(self):
        token = self.apply('aaaaaa', 'policy-a')
        command = self.control.run
        def unknown(argv, **kwargs):
            if argv[:2] == ['systemctl', 'show']:
                return subprocess.CompletedProcess(argv, 1, b'', b'')
            return command(argv, **kwargs)
        self.control.run = unknown
        with self.assertRaises(ValueError):
            self.control.dispatch('rollback', *token)
        self.assertEqual(self.live, 'policy-a')

    def test_manual_start_after_stop_cannot_outlive_filter_removal(self):
        token = self.apply('aaaaaa', 'policy-a')
        command = self.control.run
        attempted = []
        def concurrent_start(argv, **kwargs):
            if argv[:2] == ['nft', 'delete']:
                for action in ('guard', 'load'):
                    with self.assertRaises(ValueError):
                        self.control.dispatch(action)
                attempted.append(True)
            return command(argv, **kwargs)
        self.control.run = concurrent_start
        self.control.dispatch('rollback', *token)
        self.assertTrue(attempted)
        self.assertIsNone(self.live)
        with self.assertRaises(ValueError):
            self.control.dispatch('guard')
        retry = self.apply('bbbbbb', 'corrected-policy')
        self.control.dispatch('confirm', *retry)
        self.control.dispatch('guard')

    def test_long_deploy_starts_only_after_confirmation_and_survives_expired_callback(self):
        token = self.apply('aaaaaa', 'policy-a')
        with self.assertRaises(ValueError):
            self.control.dispatch('require-confirmed', *token)
        self.control.dispatch('confirm', *token)
        self.control.dispatch('require-confirmed', *token)
        # The timer callback queues behind a long deployment's real POSIX lock.
        # Advance logical time by invoking it directly; never sleep 120 seconds.
        import threading
        fd = os.open(self.control.path('/opt/erpc'), os.O_RDONLY)
        done, failures = threading.Event(), []
        def expired_timer():
            try: self.control.dispatch('rollback', *token)
            except Exception as error: failures.append(error)
            finally: done.set()
        self.module.fcntl.flock(fd, self.module.fcntl.LOCK_EX)
        timer = threading.Thread(target=expired_timer)
        try:
            timer.start()
            self.assertFalse(done.wait(0.05))
            self.control.dispatch('require-confirmed', *token)
        finally:
            os.close(fd)
            timer.join(5)
        self.assertTrue(done.is_set())
        self.assertFalse(failures)
        self.control.dispatch('require-confirmed', *token)
        self.assertEqual(self.live, 'policy-a')
        next_run = self.apply('bbbbbb', 'policy-b')
        with self.assertRaises(ValueError):
            self.control.dispatch('require-confirmed', *token)
        self.control.dispatch('confirm', *next_run)
        with self.assertRaises(ValueError):
            self.control.dispatch('require-confirmed', *token)

    def test_legacy_services_receive_loaded_guard_before_apply_or_filter_removal(self):
        for unit in self.control.services():
            file = self.control.path('/etc/systemd/system/' + unit)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('[Service]\nExecStart=/bin/false\n')  # Inert legacy unit with no guard.
        command = self.control.run
        loaded = False
        manual_start_succeeded = []
        def service_manager(argv, **kwargs):
            nonlocal loaded
            if argv == ['systemctl', 'daemon-reload']:
                for unit in self.control.services():
                    override = self.control.path('/etc/systemd/system/' + unit + '.d/50-erpc-firewall-guard.conf')
                    self.assertEqual(override.read_text(), self.control.guard_config())
                loaded = True
            if argv[:2] == ['nft', '-f']:
                self.assertTrue(loaded, 'policy changed before legacy service guards were loaded')
            if argv[:2] == ['nft', 'delete']:
                for unit in self.control.services():
                    if loaded:
                        with self.assertRaises(ValueError):
                            self.control.dispatch('guard')
                    else:
                        manual_start_succeeded.append(unit)
            return command(argv, **kwargs)
        self.control.run = service_manager
        token = self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('rollback', *token)
        self.assertFalse(manual_start_succeeded)
        self.assertIsNone(self.live)

    def test_missing_or_modified_override_prevents_filter_removal(self):
        token = self.apply('aaaaaa', 'policy-a')
        unit = self.control.services()[0]
        override = self.control.path('/etc/systemd/system/' + unit + '.d/50-erpc-firewall-guard.conf')
        override.write_text('[Service]\nExecStartPre=\n')
        with self.assertRaises(ValueError):
            self.control.dispatch('rollback', *token)
        self.assertEqual(self.live, 'policy-a')
        self.assertFalse(any(c[:2] == ['nft', 'delete'] for c in self.calls))

    def test_teardown_does_not_remove_filter_when_any_stop_fails(self):
        self.apply('aaaaaa', 'policy-a')
        command = self.control.run
        def fail_stop(argv, **kwargs):
            if argv[:3] == ['systemctl', 'disable', '--now']:
                raise subprocess.CalledProcessError(1, argv)
            return command(argv, **kwargs)
        self.control.run = fail_stop
        with self.assertRaises(subprocess.CalledProcessError):
            self.control.dispatch('teardown')
        self.assertEqual(self.live, 'policy-a')
        with self.assertRaises(ValueError):
            self.control.dispatch('guard')
        self.assertFalse(any(c[:2] == ['nft', 'delete'] for c in self.calls))

    def test_teardown_revokes_cached_manual_start_and_old_timers(self):
        token = self.apply('aaaaaa', 'policy-a')
        self.control.dispatch('confirm', *token)
        command = self.control.run
        attempts = []
        def start_between_stop_and_delete(argv, **kwargs):
            if argv[:2] == ['nft', 'delete']:
                attempts.append(True)
                with self.assertRaises(ValueError):
                    self.control.dispatch('guard')
            return command(argv, **kwargs)
        self.control.run = start_between_stop_and_delete
        self.control.dispatch('teardown')
        self.assertTrue(attempts)
        self.assertIsNone(self.live)
        self.control.dispatch('rollback', *token)
        with self.assertRaises(ValueError):
            self.control.dispatch('load')

class ArcFirewallTests(FirewallTests):
    family = 'arc'

class SolanaFirewallTests(FirewallTests):
    family = 'solana-rpc'

class OptimismFirewallTests(FirewallTests):
    family = 'optimism'

class BaseFirewallTests(FirewallTests):
    family = 'base'

class SoneiumFirewallTests(FirewallTests):
    family = 'soneium'

class ArbitrumFirewallTests(FirewallTests):
    family = 'arbitrum'

class RobinhoodFirewallTests(FirewallTests):
    family = 'robinhood'

class NearFirewallTests(FirewallTests):
    family = 'near'

class TronFirewallTests(FirewallTests):
    family = 'tron'

if __name__ == '__main__':
    unittest.main()
