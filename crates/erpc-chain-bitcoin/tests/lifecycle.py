# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline host-controller failure injection; no daemon, wallet or network."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bitcoin_control', sys.argv.pop(1))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class HostTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(patch.stopall)
        root = Path(temp.name)
        patch.object(c, 'ROOT', root / 'root').start()
        patch.object(c, 'OPT', root / 'opt').start()
        patch.object(c, 'CONF', root / 'bitcoin.conf').start()
        patch.object(c, 'LOCK', root / 'lock').start()
        c.ROOT.mkdir()
        c.OPT.mkdir()
        self.pin = {'version': '31.1', 'commit': 'a' * 40, 'sha256': 'b' * 64, 'platform': 'x86_64-linux-gnu'}
        self.state = {'owner': 'sourceowner', 'network': 'signet', 'storage': 'full', 'prune_mib': 0, 'phase': 'installed', 'installed': self.pin}
        c.CONF.write_text(c.configuration(self.state))
        (c.ROOT / 'data').mkdir()
        (c.ROOT / 'data/chainstate-fixture').write_text('persistent-state')
        directory = c.release_dir(self.pin)
        directory.mkdir(parents=True)
        (directory / 'verified.json').write_text(json.dumps(self.pin))
        (c.OPT / 'current').symlink_to(directory)
        c.save(self.state)
        self.calls = []
        self.service = 'active'
        self.free = 200_000_000_000
        patch.object(c.shutil, 'disk_usage', side_effect=lambda _: type('Usage', (), {'free': self.free})()).start()
        def run(args, **kwargs):
            self.calls.append(args)
            if args[:2] == ['systemctl', 'stop']:
                self.service = 'inactive'
            if args[:2] == ['systemctl', 'start']:
                self.service = 'active'
            return b'0'
        patch.object(c, 'run', side_effect=run).start()
        patch.object(c, 'loaded', return_value=True).start()
        patch.object(c, 'active', side_effect=lambda: self.service).start()
        patch.object(c, 'cli', side_effect=c.Refused('warming up')).start()

    def request(self, action, **updates):
        return dict(c.contract(self.state), pin=copy.deepcopy(self.pin), action=action, **updates)

    def test_every_mutator_refuses_wrong_owner_network_and_retention_before_any_action(self):
        for action in ['begin-install', 'finish-install', 'start', 'stop', 'restart', 'destroy']:
            for field, wrong in [('owner', 'otherowner'), ('network', 'mainnet'), ('storage', 'pruned')]:
                request = self.request(action)
                request[field] = wrong
                if field == 'storage':
                    request['prune_mib'] = 10240
                before = (c.ROOT / 'owner.json').read_bytes()
                with self.assertRaises(c.Refused):
                    c.locked(request)
                self.assertEqual(self.calls, [])
                self.assertEqual((c.ROOT / 'owner.json').read_bytes(), before)
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_failed_cross_network_init_cannot_stop_or_retire_original_node(self):
        wrong = self.request('prepare')
        wrong.update(owner='newinventoryitem', network='testnet4')
        with self.assertRaises(c.Refused):
            c.locked(wrong)
        for action in ['start', 'stop', 'restart', 'destroy']:
            wrong['action'] = action
            with self.assertRaises(c.Refused):
                c.locked(wrong)
        self.assertEqual(c.read_state()['network'], 'signet')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.service, 'active')

    def test_changed_rpc_config_cannot_be_used_on_start_or_reboot(self):
        c.CONF.write_text(c.CONF.read_text().replace('rpcbind=127.0.0.1', 'rpcbind=0.0.0.0'))
        with self.assertRaises(c.Refused):
            c.guard(self.state)
        for action in ['start', 'stop', 'restart', 'destroy', 'begin-install']:
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(self.calls, [])

    def test_interrupted_update_keeps_install_fence_and_refuses_new_target_or_downgrade(self):
        request = self.request('begin-install')
        request['pin']['version'] = '32.0'
        c.locked(request)
        current = c.read_state()
        self.assertEqual(current['phase'], 'installing')
        with self.assertRaises(c.Refused):
            c.guard(current)
        c.locked(request)  # same target is a safe retry
        for version in ['31.1', '33.0']:
            different = copy.deepcopy(request)
            different['pin']['version'] = version
            with self.assertRaises(c.Refused):
                c.locked(different)
        for action in ['start', 'stop', 'restart', 'destroy']:
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(c.read_state()['installed']['version'], '31.1')
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_failed_stop_during_update_still_blocks_reboot(self):
        with patch.object(c, 'stop', side_effect=c.Refused('shutdown failed')):
            with self.assertRaises(c.Refused):
                c.locked(self.request('begin-install'))
        self.assertEqual(c.read_state()['phase'], 'installing')
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())

    def test_first_install_resumes_without_config_after_download_failure(self):
        c.CONF.unlink()
        fresh = c.contract(self.state)
        fresh['phase'] = 'prepared'
        c.save(fresh)
        with patch.object(c, 'loaded', return_value=False):
            c.locked(self.request('begin-install'))
            self.assertEqual(c.locked(self.request('prepare'))['phase'], 'installing')
            c.locked(self.request('begin-install'))
        self.assertEqual(c.read_state()['phase'], 'installing')
        self.assertEqual(self.calls, [])

    def test_install_completion_needs_exact_verified_target(self):
        c.locked(self.request('begin-install'))
        (c.release_dir(self.pin) / 'verified.json').unlink()
        with self.assertRaises((c.Refused, FileNotFoundError)):
            c.locked(self.request('finish-install'))
        self.assertEqual(c.read_state()['phase'], 'installing')
        (c.release_dir(self.pin) / 'verified.json').write_text(json.dumps(self.pin))
        c.locked(self.request('finish-install'))
        c.guard(c.read_state())
        self.assertNotIn(['systemctl', 'start', c.UNIT], self.calls)

    def test_retire_preserves_data_and_ownership_but_blocks_boot(self):
        c.locked(self.request('destroy'))
        self.assertEqual(c.read_state()['phase'], 'retired')
        self.assertEqual(c.read_state()['owner'], self.state['owner'])
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())
        self.assertEqual(self.service, 'inactive')

    def test_unowned_existing_daemon_is_not_adopted(self):
        (c.ROOT / 'owner.json').unlink()
        with self.assertRaises(c.Refused):
            c.locked(self.request('prepare'))
        self.assertFalse((c.ROOT / 'owner.json').exists())
        self.assertEqual(self.calls, [])

    def test_status_does_not_claim_warmup_rpc_is_ready(self):
        status = c.locked(self.request('status'))
        self.assertFalse(status['rpc_available'])
        self.assertIn('warming up', status['inspection_error'])

    def test_failed_low_space_init_cannot_be_bypassed_by_deploy(self):
        (c.ROOT / 'owner.json').unlink()
        (c.ROOT / 'data/chainstate-fixture').unlink()
        (c.ROOT / 'data').rmdir()
        self.free = 1
        with patch.object(c, 'loaded', return_value=False):
            with self.assertRaises(c.Refused):
                c.locked(self.request('prepare'))
        self.assertFalse((c.ROOT / 'owner.json').exists())
        for action in ('prepare', 'begin-install'):
            with patch.object(c, 'loaded', return_value=False), self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.service, 'active')

    def test_later_low_space_blocks_update_resume_start_and_reboot_without_stopping(self):
        self.free = 1
        before = (c.ROOT / 'owner.json').read_bytes()
        for action in ('prepare', 'begin-install', 'start', 'restart'):
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())
        self.assertEqual(self.calls, [])
        self.assertEqual((c.ROOT / 'owner.json').read_bytes(), before)
        self.free = 200_000_000_000
        c.locked(self.request('begin-install'))
        self.calls.clear()
        self.free = 1
        with self.assertRaises(c.Refused):
            c.locked(self.request('begin-install'))
        self.assertEqual(self.calls, [])
        self.assertEqual(c.read_state()['phase'], 'installing')
        c.locked(self.request('status'))  # inspection stays available

    def test_real_database_allocation_reduces_sync_floor_but_never_operating_headroom(self):
        database = c.ROOT / 'data/signet/blocks'
        database.mkdir(parents=True)
        self.free = 60_000_000_000
        with patch.object(c, 'run', return_value=b'60000000000 database') as measured:
            c.capacity(c.read_state())
            self.assertEqual(measured.call_args.args[0][:3], ['du', '-sx', '-B1'])
            self.free = 49_000_000_000
            with self.assertRaises(c.Refused):
                c.capacity(c.read_state())
        self.free = 200_000_000_000
        database.rmdir()
        database.symlink_to(c.ROOT)
        with self.assertRaises(c.Refused):
            c.capacity(c.read_state())

    def test_large_prune_target_and_unpopulated_installed_state_do_not_skip_sync_floor(self):
        state = c.read_state()
        state.update(storage='pruned', prune_mib=1_000_000)
        self.free = 110_000_000_000
        with self.assertRaises(c.Refused):
            c.capacity(state)
        self.free = 1_200_000_000_000
        c.capacity(state)
        state.update(network='mainnet', storage='full', prune_mib=0)
        self.free = 100_000_000_000
        with self.assertRaises(c.Refused):
            c.capacity(state)  # phase installed alone is never sync evidence

    def test_hostile_dynamic_settings_are_disabled_in_the_real_daemon_unit(self):
        import shlex
        directory = c.ROOT / 'data/signet'
        directory.mkdir()
        hostile = {'rpcbind': ['0.0.0.0'], 'rpcallowip': ['0.0.0.0/0'], 'disablewallet': False, 'prune': 550, 'txindex': False}
        (directory / 'settings.json').write_text(json.dumps(hostile))
        unit = Path(c.__file__).with_name('erpc-bitcoin.service').read_text()
        argv = shlex.split(next(line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('ExecStart=')))
        # Core 31.1 common/init.cpp gates ReadSettingsFile on GetSettingsPath;
        # command-line -nosettings disables that path before dynamic overrides.
        self.assertIn('-nosettings', argv)
        self.assertFalse(any(arg.startswith('-settings=') for arg in argv))
        self.assertIn('-conf=/etc/erpc/bitcoin.conf', argv)
        c.guard(c.read_state())
        self.assertEqual(json.loads((directory / 'settings.json').read_text()), hostile)


class CliBoundaryTests(unittest.TestCase):
    def test_core_string_output_is_not_parsed_as_json(self):
        with patch.object(c, 'run', return_value=(c.NETWORKS['signet'][3] + '\n').encode()):
            self.assertEqual(c.cli('getblockhash', '0'), c.NETWORKS['signet'][3])
        with patch.object(c, 'run', return_value=b'not a hash'):
            with self.assertRaises(c.Refused):
                c.cli('getblockhash', '0')
        with patch.object(c, 'run', return_value=b'{"chain":"signet"}'):
            self.assertEqual(c.cli('getblockchaininfo'), {'chain': 'signet'})


class ArtifactTests(unittest.TestCase):
    def test_bad_archive_digest_is_refused_before_it_can_be_extracted(self):
        import hashlib
        spec = importlib.util.spec_from_file_location('verification', Path(c.__file__).with_name('verify.py'))
        verification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verification)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive-fixture'
            path.write_bytes(b'public non-executable fixture')
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            verification.verify_archive(path, expected)
            path.write_bytes(b'tampered bytes')
            with self.assertRaises(ValueError):
                verification.verify_archive(path, expected)
            alias = path.with_name('alias')
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                verification.verify_archive(alias, expected)


if __name__ == '__main__':
    unittest.main()
