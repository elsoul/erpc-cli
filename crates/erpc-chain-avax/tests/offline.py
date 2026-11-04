# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline identity failure tests using inert bytes; never run a node or generate keys."""
import sys
sys.dont_write_bytecode = True
import base64
import importlib.util
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'templates/jinja/identity.py'
spec = importlib.util.spec_from_file_location('identity', SOURCE)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        for name, value in [('ROOT', root), ('MANIFEST', root/'identity.json'), ('AUTHORIZED', root/'generation-authorized'), ('STARTED', root/'generation-started')]:
            patcher = patch.object(identity, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        user = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        patcher = patch.object(identity.pwd, 'getpwnam', return_value=user)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_identity(self):
        # Inert fixture strings, intentionally not valid keys or certificates.
        for name in identity.NAMES:
            (identity.ROOT/name).write_bytes(('inert fixture '+name).encode())

    def initialize(self):
        identity.main('authorize')
        identity.main('guard')
        self.fake_identity()
        identity.main('seal')

    def test_generation_can_only_happen_once(self):
        identity.main('authorize')
        identity.main('guard')
        with self.assertRaises(ValueError):
            identity.main('guard')
        with self.assertRaises(ValueError):
            identity.main('authorize')
        self.fake_identity()
        identity.main('seal')
        original = identity.hashes()
        identity.main('guard')
        identity.main('authorize')
        self.assertEqual(original, identity.hashes())
        (identity.ROOT/'signer.key').unlink()
        for action in ('guard', 'authorize', 'backup'):
            with self.assertRaises((ValueError, FileNotFoundError)):
                identity.main(action)

    def test_backup_restore_checks_hashes_stopped_service_and_does_not_start(self):
        self.initialize()
        stdout = io.StringIO()
        with patch('sys.stdout', stdout):
            identity.main('backup')
        bundle = json.loads(stdout.getvalue())
        bundle['expected_hashes'] = bundle['hashes']
        original = identity.hashes()
        (identity.ROOT/'signer.key').unlink()
        def restore(data, active=False):
            stdin = types.SimpleNamespace(buffer=io.BytesIO(json.dumps({'expected_hashes': data['expected_hashes'], 'bundle': {k:v for k,v in data.items() if k != 'expected_hashes'}}).encode()))
            with patch('sys.stdin', stdin), patch.object(identity.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0 if active else 1)) as run, patch('sys.stdout', io.StringIO()):
                identity.main('restore')
                self.assertTrue(all('start' not in call.args[0] for call in run.call_args_list))
        with self.assertRaises(ValueError):
            restore(bundle, active=True)
        broken = json.loads(json.dumps(bundle))
        broken['files']['signer.key'] = base64.b64encode(b'wrong inert data').decode()
        with self.assertRaises(ValueError):
            restore(broken)
        self.assertFalse((identity.ROOT/'signer.key').exists())
        restore(bundle)
        self.assertEqual(original, identity.hashes())
        restore(bundle)  # Idempotent, still no process start.
        bundle['files']['../../escape'] = ''
        with self.assertRaises(ValueError):
            restore(bundle)

    def test_existing_foreign_or_symlink_identity_is_not_adopted(self):
        self.fake_identity()
        with self.assertRaises(ValueError):
            identity.main('authorize')
        (identity.ROOT/'signer.key').unlink()
        (identity.ROOT/'signer.key').symlink_to(identity.ROOT/'staker.key')
        with self.assertRaises(ValueError):
            identity.hashes()


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        spec = importlib.util.spec_from_file_location('avax_firewall', SOURCE.with_name('firewall.py'))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.live, self.calls = None, []
        self.control = self.module.Firewall(self.root, self.command)
        self.control.directory.mkdir(parents=True)
        self.control.path('/opt/erpc/runs').mkdir(parents=True)
        contract = self.control.path('/etc/avalanchego/contract.json')
        contract.parent.mkdir(parents=True)
        contract.write_text(json.dumps({'network':'fuji','validator':False,'type':'full'}))

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        output, code = b'', 0
        if argv[:3] == ['nft', '-j', 'list']:
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


class CapacityTests(unittest.TestCase):
    def test_initial_sync_and_existing_operating_headroom(self):
        spec = importlib.util.spec_from_file_location('capacity', SOURCE.with_name('capacity.py'))
        capacity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capacity)
        for history, minimum in [('full', 900_000_000), ('archive', 13_000_000_000)]:
            with self.assertRaises(ValueError):
                capacity.check(minimum, 100_000_000, history, False)
            capacity.check(minimum, minimum, history, False)
            capacity.check(minimum, 100_000_000, history, True)
            with self.assertRaises(ValueError):
                capacity.check(minimum, 99_999_999, history, True)

    def test_destroy_and_deploy_import_contract_before_mutations(self):
        plays = SOURCE.parents[1] / 'ansible/avax'
        for name in ('init', 'deploy', 'destroy'):
            tasks = (plays/(name+'.yml')).read_text().split('  tasks:\n', 1)[1]
            first = tasks.split('    - name:', 2)[1]
            self.assertIn('import_tasks: tasks/contract.yml', first)
        guard = (plays/'tasks/contract.yml').read_text()
        for field in ('network', 'validator', 'type'):
            self.assertIn("'"+field+"':", guard)


class ReleaseVerificationTests(unittest.TestCase):
    def test_embedded_signer_and_actual_shell_reject_corrupt_signature(self):
        templates = SOURCE.parents[1]
        source = (templates/'ansible/avax/tasks/install.yml').read_text().splitlines()
        start = next(i for i, line in enumerate(source) if 'cmd: |' in line) + 1
        lines = []
        for line in source[start:]:
            if not line.startswith('          '):
                break
            lines.append(line[10:])
        self.assertTrue(lines)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            playbook = root/'ansible/avax'
            playbook.mkdir(parents=True)
            (root/'gpg').mkdir()
            key = root/'gpg/avalanchego.asc'
            shutil.copyfile(templates/'gpg/avalanchego.asc', key)
            home = root/'keyring'
            home.mkdir(mode=0o700)
            public = subprocess.run(['gpg', '--batch', '--homedir', str(home), '--show-keys', '--with-colons', str(key)], capture_output=True, text=True, check=True)
            fingerprint = '5395BDA1129CAC3E74699D07D93080B0C0D5FE8B'
            self.assertIn('fpr:::::::::' + fingerprint + ':', public.stdout)
            (root/'release.tar.gz').write_bytes(b'inert archive bytes, not a node')
            (root/'release.sig').write_bytes(b'corrupt detached signature')
            script = '\n'.join(lines).replace('{{ playbook_dir }}', str(playbook)).replace('{{ avax_opt }}', str(root)).replace('{{ avax_fingerprint }}', fingerprint)
            outcome = subprocess.run(['bash', '-c', script], capture_output=True)
            self.assertNotEqual(outcome.returncode, 0)


if __name__ == '__main__':
    unittest.main()
