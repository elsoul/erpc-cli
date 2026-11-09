#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute controller functions against inert metadata; no host tools or native keys."""
import importlib.util
import io
import tarfile
import stat
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
DIRECTORY = Path(__file__).resolve().parents[1] / 'templates/node'
sys.path.insert(0, str(DIRECTORY))
import erpc_monad_common as common
import erpc_monad_state as state
import erpc_monad_processes as processes
import erpc_monad_package as package
import erpc_monad_units as units

# Import unchanged controller functions. The executable entrypoint verifies its
# sealed root-owned directory when __name__ is __main__; tests supply a local
# module path and a bounded reader for public catalog fixtures only.
def common_read(path, limit=1048576):
    with open(path, 'rb') as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError('oversized fixture')
    return result

spec = importlib.util.spec_from_file_location('monad_control_fixture', DIRECTORY / 'control.py')
control = importlib.util.module_from_spec(spec)
with patch.object(common, 'read', common_read):
    spec.loader.exec_module(control)


class RawInitializationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [patch.object(control, 'ROOT', self.root),
                        patch.object(control, 'STATE', state.State(self.root)),
                        patch.object(state, 'read', lambda p: common.read(p, owner=os.getuid())),
                        patch.object(control, 'inspect_device', return_value={}),
                        patch.object(control, 'device_access'),
                        patch.object(control, 'quiescent'), patch.object(control, 'hugepages'),
                        patch.object(control, 'flush_device'),
                        patch.object(control, 'native_mpt')]
        for item in self.patches:
            item.start()
        self.c = {'partuuid': 'inert-selected-partition', 'network': 'testnet'}
        self.intent = 'a' * 32
        control.STATE.put('owner.json', {'contract': self.c})
        control.STATE.authorize(self.c, self.intent, {})
        control.STATE.begin(self.c, self.intent, {}, lambda: None)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def test_explicit_first_initialization_happens_once(self):
        with self.assertRaises(ValueError):
            control.initialize_device(self.c, self.intent, False)
        control.native_mpt.assert_not_called()
        control.initialize_device(self.c, self.intent, True)
        control.initialize_device(self.c, self.intent, False)
        control.native_mpt.assert_called_once_with(self.c, create=True)

    def test_interrupted_create_never_repeats_a_mutating_create(self):
        control.native_mpt.side_effect = OSError('inert interrupted initialization')
        with self.assertRaises(OSError):
            control.initialize_device(self.c, self.intent, True)
        with self.assertRaises(ValueError):
            control.initialize_device(self.c, self.intent, True)
        self.assertEqual(control.native_mpt.call_count, 1)
        control.native_mpt.side_effect = None
        control.recover_device(self.c)
        self.assertEqual(control.native_mpt.call_args, unittest.mock.call(self.c))
        control.initialize_device(self.c, self.intent, False)
        self.assertEqual(control.native_mpt.call_count, 2)

    def test_failed_device_flush_never_publishes_completed_initialization(self):
        control.flush_device.side_effect = OSError('inert flush failure')
        with self.assertRaises(OSError):
            control.initialize_device(self.c, self.intent, True)
        self.assertTrue((self.root / 'device-initializing.json').exists())
        self.assertFalse((self.root / 'device-initialized.json').exists())
        with self.assertRaises(ValueError):
            control.initialize_device(self.c, self.intent, True)
        self.assertEqual(control.native_mpt.call_count, 1)

    def test_foreign_scope_stale_intent_and_native_writer_precede_all_raw_writes(self):
        for c, intent in [(dict(self.c, network='mainnet'), self.intent), (self.c, 'b' * 32)]:
            with self.assertRaises(ValueError):
                control.initialize_device(c, intent, True)
        control.quiescent.side_effect = ValueError('inert surviving writer')
        with self.assertRaises(ValueError):
            control.initialize_device(self.c, self.intent, True)
        control.native_mpt.assert_not_called()
        self.assertFalse((self.root / 'device-initializing.json').exists())


class OwnershipOrchestrationTests(unittest.TestCase):
    def test_failed_other_scope_cannot_reach_any_mutator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_fixture = state.State(root)
            owned = {'network': 'mainnet', 'role': 'validator'}
            state_fixture.put('owner.json', {'contract': owned})
            foreign = dict(owned, network='testnet')
            with patch.object(control, 'STATE', state_fixture), \
                 patch.object(state, 'read', lambda p: common.read(p, owner=os.getuid())), \
                 patch.object(control, 'paths'), patch.object(control, 'contract', lambda c: c), \
                 patch.object(control, 'stop_native') as stop, \
                 patch.object(control, 'inspect_device') as inspect, \
                 patch.object(control, 'qualify_native') as qualify, \
                 patch.object(control.identity, 'restore') as restore, \
                 patch.object(control, 'execute') as execute:
                for operation in ('authorize', 'begin', 'stop', 'destroy', 'device-access',
                                  'initialize-device', 'restore-identity', 'firewall-apply',
                                  'firewall-confirm', 'configure', 'finish', 'activate',
                                  'start', 'restart', 'recover-device', 'install-package'):
                    with self.subTest(operation=operation), self.assertRaises(ValueError):
                        control.dispatch({'contract': foreign, 'operation': operation})
                for effect in (stop, inspect, qualify, restore, execute):
                    effect.assert_not_called()
            self.assertEqual({p.name for p in root.iterdir()}, {'owner.json'})

    def test_orphan_native_staging_or_identity_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directories = [root / name for name in ('state', 'config', 'releases', 'helpers')]
            for path in directories:
                path.mkdir()
            with patch.object(control, 'ROOT', directories[0]), \
                 patch.object(control, 'CONFIG', directories[1]), \
                 patch.object(control, 'RELEASES', directories[2]), \
                 patch.object(control, 'HELPERS', directories[3]), \
                 patch.object(control, 'contract', lambda c: c), \
                 patch.object(control, 'owned_directory'), \
                 patch.object(control.namespace,'paths'),patch.object(control.namespace,'fresh'), \
                 patch.object(control.device, 'inspect') as inspect:
                for directory in directories:
                    orphan = directory / 'interrupted-artifact'
                    orphan.write_bytes(b'inert unowned artifact')
                    with self.subTest(directory=directory.name), self.assertRaises(ValueError):
                        control.preflight({})
                    self.assertEqual(orphan.read_bytes(), b'inert unowned artifact')
                    orphan.unlink()
                inspect.assert_not_called()


class NativeProcessTests(unittest.TestCase):
    def test_missing_units_do_not_skip_owned_orphan_shutdown(self):
        calls = []
        def execute(args, **kwargs):
            calls.append(args)
            return types.SimpleNamespace(returncode=0 if 'show' in args else 5,
                                         stdout=b'not-found\n')
        with patch.object(processes, 'execute', execute), \
             patch.object(processes, 'owned', side_effect=[{123: '42'}, {}, {}]), \
             patch.object(processes, 'inspect', return_value='42'), \
             patch.object(os, 'pidfd_open', return_value=9, create=True), \
             patch.object(processes.signal, 'pidfd_send_signal', create=True) as send, \
             patch.object(os, 'close'):
            processes.stop(999, {})
            send.assert_called_once_with(9, processes.signal.SIGTERM)
        self.assertEqual(len(calls), len(processes.UNITS) * 2)

    def test_unknown_writer_or_failed_stop_never_reports_quiescence(self):
        with patch.object(processes, 'execute', return_value=types.SimpleNamespace(returncode=0, stdout=b'')), \
             patch.object(processes, 'owned', side_effect=ValueError('unknown user-owned process')):
            with self.assertRaises(ValueError):
                processes.stop(999, {})
        with patch.object(processes, 'execute', return_value=types.SimpleNamespace(returncode=1, stdout=b'loaded')), \
             patch.object(processes,'owned',return_value={}) as scan:
            with self.assertRaises(ValueError):
                processes.stop(999, {})
            self.assertGreaterEqual(scan.call_count,2)

    def test_failed_unit_stop_still_attempts_every_unit_and_original_pidfd_drain(self):
        calls=[]
        def command(argv,**kwargs):
            calls.append(argv)
            return types.SimpleNamespace(returncode=1,stdout=b'loaded')
        with patch.object(processes,'execute',command), \
             patch.object(processes,'owned',side_effect=[{123:'42'},{},{}]), \
             patch.object(processes,'inspect',return_value='42'), \
             patch.object(os,'pidfd_open',return_value=9,create=True), \
             patch.object(processes.signal,'pidfd_send_signal',create=True) as signal, \
             patch.object(os,'close'),self.assertRaisesRegex(ValueError,'unit stops failed'):
            processes.stop(999,{})
        self.assertEqual(len([call for call in calls if 'stop' in call]),len(processes.UNITS))
        signal.assert_called_once_with(9,processes.signal.SIGTERM)

    def test_deleted_executable_is_still_an_owned_writer_and_missing_live_exe_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / '123'
            proc.mkdir()
            (proc / 'stat').write_text('123 (fixture) ' + ' '.join(['S'] + ['0'] * 18 + ['42']))
            (proc / 'status').write_text('Uid:\t999\t999\t999\t999\n')
            executable = proc / 'exe'
            executable.write_bytes(b'inert executable handle fixture')
            approved = {'/opt/erpc/monad/0.16.5/bin/monad': common.digest(executable.read_bytes())}
            with patch.object(processes.os, 'readlink', return_value='/opt/erpc/monad/0.16.5/bin/monad (deleted)'):
                self.assertEqual(processes.inspect(123, 999, approved, root), '42')
                executable.unlink()
                with self.assertRaises(ValueError):
                    processes.inspect(123, 999, approved, root)
                (proc / 'stat').write_text('123 (fixture) ' + ' '.join(['Z'] + ['0'] * 18 + ['42']))
                self.assertIsNone(processes.inspect(123, 999, approved, root))

    def test_manual_start_refuses_detached_or_deleted_writers_including_gateway(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / '123'
            proc.mkdir()
            (proc / 'stat').write_text('123 (fixture) ' + ' '.join(['S'] + ['0'] * 18 + ['42']))
            (proc / 'cgroup').write_text('0::/system.slice/erpc-monad-execution.service\n')
            with patch.object(processes, 'owned', return_value={123: '42'}), \
                 patch.object(processes.os, 'readlink', return_value='/opt/erpc/monad/0.16.5/bin/monad'):
                processes.start_safe(999, {}, Path('/opt/erpc/monad/0.16.5'), proc_root=root)
                (proc / 'cgroup').write_text('0::/user.slice\n')
                with self.assertRaises(ValueError):
                    processes.start_safe(999, {}, Path('/opt/erpc/monad/0.16.5'), proc_root=root)
            with patch.object(processes, 'owned', return_value={123: '42'}), \
                 patch.object(processes.os, 'readlink', return_value='/usr/sbin/nginx (deleted)'):
                with self.assertRaises(ValueError):
                    processes.start_safe(999, {}, Path('/usr'), gateway=True, proc_root=root)

    def test_archive_member_paths_cannot_escape_private_native_directory(self):
        for path in ['/usr/local/bin/monad', '../../etc/shadow', 'usr/local/bin/../../etc/shadow']:
            with self.assertRaises(ValueError):
                package.extraction_path(path)
        self.assertEqual(package.extraction_path('./usr/local/bin/monad-node'), Path('bin/monad-node'))
        self.assertIsNone(package.extraction_path('./DEBIAN/postinst'))


class PublicationPermissionsTests(unittest.TestCase):
    def test_actual_extraction_and_atomic_publication_ignore_private_umask_only_for_public_files(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            members = [('usr/local/bin/' + name, b'inert native payload') for name in package.BINARIES]
            members += [('usr/local/lib/libfixture.so.1', b'inert shared library')]
            for name, data in members:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            link = tarfile.TarInfo('usr/local/lib/libfixture.so')
            link.type = tarfile.SYMTYPE
            link.linkname = 'libfixture.so.1'
            tar.addfile(link)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = os.umask(0o077)
            try:
                payload = root / 'payload'
                payload.mkdir(mode=0o755)
                self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o700)
                process = types.SimpleNamespace(stdout=io.BytesIO(archive.getvalue()),
                    wait=lambda **_: 0, poll=lambda: 0)
                with patch.object(package.subprocess, 'Popen', return_value=process):
                    package.extract(root / 'inert-package', payload)
                # Evaluate the POSIX other-user access used by both dedicated
                # readers, which are different from the root publication owner.
                for parent in (payload, payload / 'bin', payload / 'lib'):
                    self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
                    self.assertTrue(parent.stat().st_mode & stat.S_IXOTH)
                for name in package.BINARIES:
                    executable = payload / 'bin' / name
                    self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o555)
                    self.assertEqual(executable.stat().st_mode & 0o005, 0o005)
                library = payload / 'lib/libfixture.so.1'
                self.assertEqual(stat.S_IMODE(library.stat().st_mode), 0o444)
                self.assertEqual((payload / 'lib/libfixture.so').read_bytes(), library.read_bytes())
                for name in ('node.toml', 'nginx.conf', 'erpc-monad.service'):
                    common.atomic(root / name, b'inert public configuration', 0o644)
                    self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o644)
                    self.assertTrue((root / name).stat().st_mode & stat.S_IROTH)
                for name in ('identity.json', 'monad-secp.cred', 'owner.json', 'receipt.json'):
                    common.atomic(root / name, b'inert private receipt')
                    self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600)
                    self.assertFalse((root / name).stat().st_mode & 0o077)
            finally:
                os.umask(previous)


class RenderTests(unittest.TestCase):
    def test_all_profiles_have_loopback_backends_outer_credentials_and_guarded_boot(self):
        catalog = json.loads((DIRECTORY / 'catalog.json').read_text())
        for network in ('mainnet', 'testnet'):
            for role in ('rpc', 'validator'):
                c = {'network': network, 'role': role, 'owner': 'a' * 32,
                     'partuuid': 'abcdefab-abcd-abcd-abcd-abcdefabcdef'}
                rendered = units.render(catalog, c, list(range(16)), ['192.0.2.0/24'], ['2001:db8::/32'], {'erpc-monad':{'uid':995,'gid':995},'erpc-monad-proxy':{'uid':996,'gid':996}})
                for key in ('bft', 'execution', 'rpc'):
                    self.assertIn('/usr/bin/python3 -I', rendered['erpc-monad-' + key + '.service'])
                    self.assertIn('LimitCORE=0', rendered['erpc-monad-' + key + '.service'])
                self.assertIn('--rpc-addr 127.0.0.1', rendered['erpc-monad-rpc.service'])
                self.assertNotIn('--password', rendered['erpc-monad-bft.service'])
                self.assertIn('LoadCredentialEncrypted=monad-secp:', rendered['erpc-monad-bft.service'])
                self.assertIn('LoadCredentialEncrypted=monad-bls:', rendered['erpc-monad-bft.service'])
                self.assertEqual(rendered['nginx.conf'].count('deny all;'), 2)
                self.assertNotIn('ConditionPathExists', rendered['erpc-monad-firewall.service'])


if __name__ == '__main__':
    unittest.main()
