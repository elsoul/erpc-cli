# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual original release controller and files; native clients/NSS/PID1 stay inert."""
import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
SOURCE = Path(__file__).parents[1] / 'templates/jinja'


class Fixture:
    def __init__(self, source=SOURCE):
        self.source = source

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        loader = importlib.machinery.SourceFileLoader('sui_release_fixture', str(self.source / 'erpc-sui-control.py.j2'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.module = importlib.util.module_from_spec(spec); loader.exec_module(self.module)
        self.c = self.module.Control(self.root, owner=os.getuid())
        self.r = self.module.release_authority
        self.r.CATALOG = copy.deepcopy(self.r.CATALOG)
        self.artifacts = {}
        self.expected = {'network': 'testnet', 'role': 'fullnode', 'genesis': 'a' * 64}
        self.record = dict(contract=self.expected, protocol=2, service_uid=999, service_gid=999,
                           account_established=True, home_established=True)
        for name in ('etc/sui', 'etc/erpc/sui', 'opt/sui', 'opt/erpc', 'var/lib/sui', 'proc'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.c.write('/etc/sui/original-account.json', self.record)
        self.c.write('/etc/sui/contract.json', dict(self.expected, original_account=self.record, authority_protocol=3))
        self.r.scope(self.c, self.expected, create=True)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(self.c, 'account', side_effect=lambda expected: self.c.account_record(expected)))
        self.stack.enter_context(patch.object(self.c, 'platform'))
        self.stack.enter_context(patch.object(self.c, 'fingerprint', return_value='inert live filter'))
        self.stopped = self.stack.enter_context(patch.object(self.c, 'stop_installed'))
        self.disabled = self.stack.enter_context(patch.object(self.c, 'disable_installed')) if hasattr(self.c, 'disable_installed') else None
        policy = self.root / 'etc/erpc/sui/firewall.nft'; policy.write_text('inert original filter')
        self.c.write('/etc/erpc/sui/confirmed.json', {'contract': self.expected, 'file': hashlib.sha256(policy.read_bytes()).hexdigest(), 'live': 'inert live filter'})
        data = self.root / 'var/lib/sui/db/live'; data.mkdir(parents=True)
        (data / 'original').write_bytes(b'original inert database; never opened by a native client')
        marker = self.root / 'var/lib/sui/.bootstrap-complete'; marker.touch(mode=0o600)
        self.cipher = self.root / 'ciphertext'; self.cipher.write_bytes(b'original inert encrypted identity')
        self.retained = []
        for name in ('etc/credstore.encrypted/sui-network.key', 'etc/credstore.encrypted/sui-validator/protocol.key',
                     'etc/credstore.encrypted/sui-validator/network.key', 'etc/credstore.encrypted/sui-validator/worker.key',
                     'var/lib/sui/consensus-db/original-history'):
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'inert original sealed credential'); path.chmod(0o600)
            self.retained.append((path, path.read_bytes(), path.stat().st_ino))
        self.original = ((data / 'original').read_bytes(), (data / 'original').stat().st_ino, self.cipher.read_bytes())
        actual_fstat = os.fstat
        def data_owner(descriptor):
            value = actual_fstat(descriptor)
            for relative in ('var/lib/sui/db', 'var/lib/sui/db/live'):
                try: named = (self.root / relative).lstat()
                except FileNotFoundError: continue
                if (named.st_dev, named.st_ino) == (value.st_dev, value.st_ino):
                    values = list(value); values[4] = values[5] = self.record['service_uid']
                    return os.stat_result(values)
            return value
        self.stack.enter_context(patch.object(os, 'fstat', side_effect=data_owner))

        return self

    def __exit__(self, *args):
        self.stack.close(); self.temp.cleanup()

    def artifact(self, version):
        if version in self.artifacts:
            return dict(self.artifacts[version])
        folder = self.root / ('opt/sui/' + version); folder.mkdir(exist_ok=True)
        with tarfile.open(folder / 'release.tgz', 'w:gz') as archive:
            for name in self.r.BINARIES:
                raw = ('inert ' + version + ' ' + name + '; never executed').encode()
                member = tarfile.TarInfo(name); member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw)); (folder / name).write_bytes(raw)
        self.r.CATALOG[version]['x86_64'] = hashlib.sha256((folder / 'release.tgz').read_bytes()).hexdigest()
        value = self.r.source(version, 'x86_64')
        self.r.qualify_artifact(self.c, self.expected, value)
        self.artifacts[version] = dict(value)
        return value

    def select(self, value):
        pointer = self.root / 'opt/sui/current'
        if pointer.is_symlink(): pointer.unlink()
        pointer.symlink_to('/opt/sui/' + value['version'])

    def open(self):
        self.c.dispatch('open-release', self.expected)

    def preserved(self, test):
        path = self.root / 'var/lib/sui/db/live/original'
        test.assertEqual((path.read_bytes(), path.stat().st_ino, self.cipher.read_bytes()), self.original)
        for path, raw, inode in self.retained:
            test.assertEqual((path.read_bytes(), path.stat().st_ino), (raw, inode))

    def bootstrap_only(self):
        # Establish an inert first-bootstrap fixture, not a reset of used data.
        history = self.root / 'var/lib/sui/consensus-db/original-history'
        history.unlink(); history.parent.rmdir()
        self.c.path('/var/lib/sui/.bootstrap-complete').unlink(missing_ok=True)
        self.retained = [entry for entry in self.retained if entry[0] != history]

    def legacy(self):
        assert self.r.claims(self.c, self.expected) == []
        self.c.path(self.r.HISTORY + '/scope.json').unlink()
        self.c.path(self.r.HISTORY).rmdir()
        self.c.write('/etc/sui/contract.json', dict(self.expected, original_account=self.record, authority_protocol=2))

    def validator_receipt(self):
        metadata = b'{"inert":"already-qualified original public metadata"}'
        self.c.path('/etc/sui/validator.json').write_bytes(metadata)
        receipt = {'metadata': hashlib.sha256(metadata).hexdigest()}
        for name in ('protocol', 'network', 'worker'):
            receipt[name] = hashlib.sha256(self.c.path('/etc/credstore.encrypted/sui-validator/' + name + '.key').read_bytes()).hexdigest()
        self.c.write('/etc/sui/validator-identity-established', receipt)

    def confirm_generation(self, value, intent='b' * 32, already_begun=False):
        self.select(value)
        if not already_begun: self.c.begin(self.expected, intent)
        self.c.path('/run').mkdir(exist_ok=True)
        self.c.path('/etc/erpc/sui/pending.nft').write_bytes(b'inert original filter')
        with patch.object(self.c, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            self.c.arm(self.expected, intent)
            self.c.capture(self.expected, intent)
            self.c.confirm(self.expected, intent)


@unittest.skipUnless(os.name == 'posix', 'native authority uses POSIX descriptors')
class Release(unittest.TestCase):
    def test_acquisition_is_not_an_opening_and_native_entry_refuses_previous_source(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1')
            self.assertEqual(f.r.claims(f.c, f.expected), [])
            f.select(old); f.open()
            f.select(new); f.c.runtime(f.expected)
            self.assertEqual(f.r.claims(f.c, f.expected), [old])
            f.open(); f.select(old)
            with self.assertRaisesRegex(ValueError, 'downgrade'): f.c.runtime(f.expected)
            with self.assertRaisesRegex(ValueError, 'downgrade'): f.open()
            f.preserved(self)

    def test_every_opening_sync_failure_retains_floor_and_same_source_retry(self):
        for fault in range(1, 34):
            with self.subTest(fault=fault), Fixture() as f:
                old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1')
                f.select(old); f.open(); f.select(new)
                sync = os.fsync; count = [0]
                def interrupted(fd):
                    count[0] += 1
                    if count[0] >= fault: raise OSError('inert persistent opening durability failure')
                    return sync(fd)
                with patch.object(os, 'fsync', side_effect=interrupted):
                    with self.assertRaises(OSError): f.open()
                f.select(old)
                with self.assertRaises(ValueError): f.open()
                f.select(new); f.open(); f.preserved(self)

    def test_partial_claim_name_fences_downgrade_and_resumes_only_exact_bytes(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1')
            path = f.c.path(f.r.HISTORY + '/' + f.r.event_name(new))
            path.write_bytes(f.r.encoded(new)[:17]); path.chmod(0o600)
            f.select(old)
            with self.assertRaises(ValueError): f.open()
            f.select(new); f.open()
            self.assertEqual(path.read_bytes(), f.r.encoded(new)); f.preserved(self)

    def test_original_scope_and_unknown_claims_never_become_empty_history(self):
        with Fixture() as f:
            value = f.artifact('testnet-v1.83.1'); f.select(value)
            with self.assertRaises(ValueError): f.r.permitted(f.c, dict(f.expected, network='mainnet'), value)
            path = f.c.path(f.r.HISTORY + '/unqualified.opened'); path.write_bytes(b'original'); path.chmod(0o600)
            with self.assertRaises(ValueError): f.open()
            self.assertEqual(path.read_bytes(), b'original'); f.preserved(self)

    def test_fresh_reservation_cannot_adopt_history_after_original_account_loss(self):
        with Fixture() as f:
            original = f.c.path(f.r.HISTORY + '/scope.json').read_bytes()
            f.c.path('/etc/sui/contract.json').unlink()
            f.c.path('/etc/sui/original-account.json').unlink()
            with self.assertRaises(ValueError): f.c.contract(f.expected, initial=True)
            self.assertEqual(f.c.path(f.r.HISTORY + '/scope.json').read_bytes(), original)
            self.assertFalse(f.c.path('/etc/sui/original-account.json').exists())

    def test_changed_binary_is_not_an_opened_qualified_source(self):
        with Fixture() as f:
            value = f.artifact('testnet-v1.83.1'); f.select(value)
            f.c.path('/opt/sui/' + value['version'] + '/sui-node').write_bytes(b'substituted inert bytes')
            with self.assertRaises(ValueError): f.open()
            self.assertEqual(f.r.claims(f.c, f.expected), [])

    def test_installed_original_without_history_requires_explicit_stopped_migration(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); f.select(old)
            f.legacy()
            with self.assertRaisesRegex(ValueError, 'migration'): f.open()
            evidence = dict(format=1, database_state='native-opened', contract=f.expected, service_uid=999, service_gid=999, highest_opened=old)
            result = f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(result['service'], 'stopped'); self.assertGreater(f.stopped.call_count, 0)
            self.assertEqual(json.loads(f.c.path('/etc/sui/contract.json').read_text())['authority_protocol'], 3)
            self.assertEqual(f.r.claims(f.c, f.expected), [old]); f.preserved(self)

    def test_foreign_evidence_does_not_stop_or_adopt_and_partial_history_is_retained(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); f.select(old)
            evidence = dict(format=1, database_state='native-opened', contract=f.expected, service_uid=1000, service_gid=999, highest_opened=old)
            with self.assertRaises(ValueError): f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(f.stopped.call_count, 0); f.preserved(self)

    def test_native_and_bootstrap_units_claim_before_database_execution(self):
        for name in ('sui-node.service.j2', 'sui-bootstrap.service.j2'):
            text = (SOURCE / name).read_text()
            action = 'open-bootstrap' if name.startswith('sui-bootstrap') else 'open-release'
            self.assertIn(' ' + action + ' {{ sui_network }}', text)
            self.assertLess(text.index(' ' + action + ' '), text.index('\nExecStart='))

    def test_retained_legacy_runtime_entry_also_claims_before_native_execution(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1')
            f.select(new); f.c.dispatch('runtime', f.expected)
            self.assertEqual(f.r.claims(f.c, f.expected), [new])
            f.select(old)
            with self.assertRaises(ValueError): f.c.dispatch('runtime', f.expected)
            f.preserved(self)

    def test_opening_lock_refuses_a_competing_claim_without_weakening_history(self):
        with Fixture() as f:
            value = f.artifact('testnet-v1.83.1'); f.select(value)
            with f.r.opening_lock(f.c):
                with self.assertRaises(BlockingIOError): f.open()
            self.assertEqual(f.r.claims(f.c, f.expected), [])
            f.open(); self.assertEqual(f.r.claims(f.c, f.expected), [value])

    def test_migration_durability_failures_keep_originals_and_stop_before_retry(self):
        # Each actual publication position fails persistently until the explicit retry.
        for fault in range(1, 60):
            with self.subTest(fault=fault), Fixture() as f:
                old = f.artifact('testnet-v1.82.2'); f.select(old)
                f.legacy()
                evidence = dict(format=1, database_state='native-opened', contract=f.expected, service_uid=999, service_gid=999, highest_opened=old)
                sync = os.fsync; count = [0]
                def fail_from(fd):
                    count[0] += 1
                    if count[0] >= fault: raise OSError('inert persistent history migration barrier failure')
                    return sync(fd)
                with patch.object(os, 'fsync', side_effect=fail_from):
                    with self.assertRaises((ValueError, OSError)): f.r.migrate(f.c, f.expected, evidence)
                self.assertGreater(f.stopped.call_count, 0)
                f.preserved(self)
                result = f.r.migrate(f.c, f.expected, evidence)
                self.assertEqual(result['service'], 'stopped')
                self.assertEqual(f.r.claims(f.c, f.expected), [old]); f.preserved(self)

    def test_unused_original_can_migrate_only_with_a_proven_empty_data_home(self):
        with Fixture() as f:
            f.legacy()
            evidence = dict(format=1, database_state='never-opened', contract=f.expected, service_uid=999, service_gid=999, highest_opened=None)
            with self.assertRaises(ValueError): f.r.migrate(f.c, f.expected, evidence)
            (f.root / 'var/lib/sui/db/live/original').unlink(); (f.root / 'var/lib/sui/db/live').rmdir(); (f.root / 'var/lib/sui/db').rmdir()
            (f.root / 'var/lib/sui/consensus-db/original-history').unlink(); (f.root / 'var/lib/sui/consensus-db').rmdir()
            f.c.path('/var/lib/sui/.bootstrap-complete').unlink(missing_ok=True)
            result = f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(result['service'], 'stopped'); self.assertEqual(f.r.claims(f.c, f.expected), [])

    def test_already_upgraded_history_cannot_be_migrated_back_to_lower_evidence(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1')
            f.select(new); f.open(); f.select(old)
            evidence = dict(format=1, database_state='native-opened', contract=f.expected, service_uid=999, service_gid=999, highest_opened=old)
            with self.assertRaises(ValueError): f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(f.r.claims(f.c, f.expected), [new]); f.preserved(self)

    def test_native_or_completed_history_cannot_be_recovered_as_fresh_when_marker_is_missing(self):
        for evidence in ('consensus', 'native', 'partial-native', 'completed'):
            with self.subTest(evidence=evidence), Fixture() as f:
                if evidence != 'consensus': f.bootstrap_only()
                value = f.artifact('testnet-v1.83.1'); f.select(value)
                if evidence == 'native':
                    f.c.path('/var/lib/sui/.bootstrap-complete').touch(mode=0o600)
                    f.open()
                    f.c.path('/var/lib/sui/.bootstrap-complete').unlink()
                if evidence == 'partial-native':
                    marker = f.c.path('/etc/sui/native-opened.json'); marker.write_bytes(b''); marker.chmod(0o600)
                if evidence == 'completed': f.c.path('/var/lib/sui/.bootstrap-complete').touch()
                before = f.stopped.call_count
                with self.assertRaises(ValueError): f.c.dispatch('recover-owned', f.expected)
                self.assertEqual(f.stopped.call_count, before)
                self.assertEqual(list(f.c.path('/var/lib/sui').glob('db.quarantine.*')), [])
                f.preserved(self)

    def test_incomplete_bootstrap_explicit_update_keeps_quarantine_and_claims_new_source(self):
        with Fixture() as f:
            f.bootstrap_only(); old = f.artifact('testnet-v1.82.2'); f.select(old)
            f.c.dispatch('open-bootstrap', f.expected)
            self.assertFalse(f.r.native_used(f.c))
            new = f.artifact('testnet-v1.83.1')
            f.r.permitted(f.c, f.expected, new)
            with patch.object(f.module.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(10**13, 0, 10**13)):
                f.c.dispatch('recover-owned', f.expected)
            retained = list(f.c.path('/var/lib/sui').glob('db.quarantine.*/live/original'))
            self.assertEqual(len(retained), 1)
            self.assertEqual((retained[0].read_bytes(), retained[0].stat().st_ino), f.original[:2])
            f.confirm_generation(new)
            f.c.dispatch('open-bootstrap', f.expected)
            self.assertEqual(f.r.claims(f.c, f.expected), [old, new])
            self.assertFalse(f.r.native_used(f.c))
            for path, raw, inode in f.retained:
                self.assertEqual((path.read_bytes(), path.stat().st_ino), (raw, inode))
            self.assertEqual(retained[0].read_bytes(), f.original[0])

    def test_partial_recovery_rename_replays_directory_barriers_before_success(self):
        with Fixture() as f:
            f.bootstrap_only(); old = f.artifact('testnet-v1.82.2'); f.select(old)
            f.c.dispatch('open-bootstrap', f.expected)
            actual = f.c.sync
            home = f.c.path('/var/lib/sui')
            def fail_home(path):
                if path == home: raise OSError('inert quarantine directory durability failure')
                return actual(path)
            with patch.object(f.module.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(10**13, 0, 10**13)):
                with patch.object(f.c, 'sync', side_effect=fail_home):
                    with self.assertRaises(OSError): f.c.dispatch('recover-owned', f.expected)
                    with self.assertRaises(OSError): f.c.dispatch('recover-owned', f.expected)
                self.assertFalse(f.c.path('/var/lib/sui/db').exists())
                f.c.dispatch('recover-owned', f.expected)
            retained = list(home.glob('db.quarantine.*/live/original'))
            self.assertEqual(len(retained), 1)
            self.assertEqual((retained[0].read_bytes(), retained[0].stat().st_ino), f.original[:2])

    def test_downloaded_newer_source_does_not_forge_historical_opening_on_migration(self):
        with Fixture() as f:
            old = f.artifact('testnet-v1.82.2'); new = f.artifact('testnet-v1.83.1'); f.select(new)
            f.legacy()
            evidence = dict(format=1, database_state='native-opened', contract=f.expected,
                            service_uid=999, service_gid=999, highest_opened=old)
            f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(f.r.claims(f.c, f.expected), [old]); f.preserved(self)

    def test_never_opened_original_may_have_a_verified_download_without_a_source_floor(self):
        with Fixture() as f:
            f.bootstrap_only()
            (f.root / 'var/lib/sui/db/live/original').unlink(); (f.root / 'var/lib/sui/db/live').rmdir(); (f.root / 'var/lib/sui/db').rmdir()
            downloaded = f.artifact('testnet-v1.83.1'); f.select(downloaded)
            f.legacy()
            evidence = dict(format=1, database_state='never-opened', contract=f.expected,
                            service_uid=999, service_gid=999, highest_opened=None)
            f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(f.r.claims(f.c, f.expected), [])
            self.assertFalse(f.r.native_used(f.c))

    def test_bootstrap_only_evidence_cannot_weaken_partial_native_use(self):
        with Fixture() as f:
            f.bootstrap_only(); old = f.artifact('testnet-v1.82.2'); f.select(old)
            marker = f.c.path('/etc/sui/native-opened.json'); marker.write_bytes(b''); marker.chmod(0o600)
            evidence = dict(format=1, database_state='bootstrap-only', contract=f.expected,
                            service_uid=999, service_gid=999, highest_opened=old)
            with self.assertRaises(ValueError): f.r.migrate(f.c, f.expected, evidence)
            self.assertEqual(marker.read_bytes(), b''); f.preserved(self)

    def test_verified_bootstrap_completion_replays_every_marker_barrier(self):
        for point in range(1, 10):
            with self.subTest(point=point), Fixture() as f:
                f.bootstrap_only(); value = f.artifact('testnet-v1.83.1'); f.select(value)
                f.c.dispatch('open-bootstrap', f.expected)
                sync = os.fsync; calls = [0]
                def failure(fd):
                    calls[0] += 1
                    if calls[0] >= point: raise OSError('inert completed-bootstrap publication failure')
                    return sync(fd)
                with patch.object(os, 'fsync', side_effect=failure):
                    with self.assertRaises(OSError): f.c.dispatch('complete-bootstrap', f.expected)
                f.c.dispatch('complete-bootstrap', f.expected)
                self.assertTrue(f.c.path('/var/lib/sui/.bootstrap-complete').exists())
                self.assertTrue(f.r.native_used(f.c))
                with self.assertRaises(ValueError): f.c.dispatch('recover-owned', f.expected)
                f.open(); f.preserved(self)

    def test_completion_never_follows_a_replaced_live_directory_or_linked_marker(self):
        for kind in ('directory', 'marker'):
            with self.subTest(kind=kind), Fixture() as f:
                f.bootstrap_only(); value = f.artifact('testnet-v1.83.1'); f.select(value)
                f.c.dispatch('open-bootstrap', f.expected)
                outside = f.root / 'outside'; outside.mkdir()
                sentinel = outside / 'sentinel'; sentinel.write_bytes(b'untouched')
                if kind == 'directory':
                    live = f.c.path('/var/lib/sui/db/live')
                    live.rename(live.with_name('original-live')); live.symlink_to(outside, target_is_directory=True)
                else:
                    empty = outside / 'empty'; empty.touch()
                    os.link(empty, f.c.path('/var/lib/sui/.bootstrap-complete'))
                before = (sentinel.read_bytes(), sentinel.stat().st_ino)
                with self.assertRaises((ValueError, OSError)): f.c.dispatch('complete-bootstrap', f.expected)
                self.assertEqual((sentinel.read_bytes(), sentinel.stat().st_ino), before)
                self.assertFalse((outside / '.bootstrap-complete').exists())


if __name__ == '__main__':
    unittest.main()
