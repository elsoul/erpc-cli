# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert proc/cgroup views; no real process is signaled."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
root = Path(__file__).parents[1] / 'templates/node'
sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location('hyperliquid_process_fixture', root / 'erpc_hl_processes.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Processes(unittest.TestCase):
    def test_missing_systemd_unit_still_stops_owned_orphan_through_a_pidfd(self):
        with patch.object(p, 'execute', return_value=SimpleNamespace(stdout=b'not-found')), \
             patch.object(p, 'owned', side_effect=[{123: '99'}, {123: '99'}, {}]), \
             patch.object(p, 'identity', return_value='99'), \
             patch.object(p.os, 'pidfd_open', return_value=7, create=True), \
             patch.object(p.signal, 'pidfd_send_signal', create=True) as send, \
             patch.object(p.select, 'select', return_value=([7], [], [])), patch.object(p.os, 'close'):
            p.stop([995])
            send.assert_called_once_with(7, p.signal.SIGTERM)

    def test_failed_service_shutdown_still_drains_owned_pid_without_claiming_success(self):
        calls = []
        def execute(argv, **kwargs):
            calls.append(argv)
            if argv[1] == 'stop':raise OSError('inert systemd refusal')
            return SimpleNamespace(stdout=b'loaded')
        with patch.object(p,'execute',side_effect=execute), \
             patch.object(p,'owned',side_effect=[{123:'99'},{123:'99'},{}]), \
             patch.object(p,'identity',return_value='99'), \
             patch.object(p.os,'pidfd_open',return_value=7,create=True), \
             patch.object(p.signal,'pidfd_send_signal',create=True) as send, \
             patch.object(p.select,'select',return_value=([7],[],[])),patch.object(p.os,'close'):
            with self.assertRaisesRegex(ValueError,'drain was still attempted'):p.stop([995])
            send.assert_called_once_with(7,p.signal.SIGTERM)
        self.assertEqual(sum(argv[1]=='stop' for argv in calls),len(p.UNITS))
        with patch.object(p,'owned',side_effect=ValueError('foreign cgroup')),patch.object(p,'execute') as execute:
            with self.assertRaises(ValueError):p.stop([995])
            execute.assert_not_called()

    def test_loopback_api_must_be_owned_by_the_native_child_socket_and_process_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);entry=root/'123';entry.mkdir();(entry/'fd').mkdir();(root/'net').mkdir()
            (entry/'stat').write_text('123 (hl-node) '+' '.join(['S']+['0']*18+['99']))
            (entry/'status').write_text('Uid:\t995\t995\t995\t995\n')
            (entry/'cgroup').write_text('0::/system.slice/erpc-hyperliquid-node.service\n')
            executable=root/'hl-node';executable.write_bytes(b'inert nonexecutable fixture')
            (entry/'exe').symlink_to(executable);(entry/'fd/5').symlink_to('socket:[77]')
            row='0: 0100007F:0BB9 00000000:0000 0A 0 0 0 995 0 77\n'
            (root/'net/tcp').write_text('header\n'+row);(root/'net/tcp6').write_text('header\n')
            proof=p.listener(995,3001,root)
            self.assertEqual(proof[0][:2],(123,'99'));self.assertEqual(proof[0][4],('77',))
            (root/'net/tcp').write_text('header\n'+row+row.replace(' 77',' 88'))
            with self.assertRaisesRegex(ValueError,'exclusively'):p.listener(995,3001,root)
            (root/'net/tcp').write_text('header\n'+row)
            (entry/'fd/5').unlink()
            with self.assertRaisesRegex(ValueError,'exclusively'):p.listener(995,3001,root)
            (entry/'fd/5').symlink_to('socket:[77]')
            with patch.object(p,'identity',side_effect=['99','100']):
                with self.assertRaisesRegex(ValueError,'changed'):p.listener(995,3001,root)

    def test_foreign_cgroup_and_reused_pid_are_refused_before_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);entry = root / '123';entry.mkdir()
            (entry / 'stat').write_text('123 (fixture (name)) ' + ' '.join(['S'] + ['0'] * 18 + ['99']))
            (entry / 'status').write_text('Uid:\t995\t995\t995\t995\n')
            (entry / 'cgroup').write_text('0::/system.slice/erpc-hyperliquid-node.service\n')
            self.assertEqual(p.identity(123, 995, root), '99')
            # All four UID fields come from kernel process metadata.
            self.assertEqual(p.owned(995, root), {123: '99'})
            (entry / 'cgroup').write_text('0::/user.slice\n')
            with self.assertRaises(ValueError):p.identity(123, 995, root)
        with patch.object(p, 'execute', return_value=SimpleNamespace(stdout=b'not-found')), \
             patch.object(p, 'owned', return_value={123: '99'}), patch.object(p, 'identity', return_value='100'), \
             patch.object(p.os, 'pidfd_open', return_value=7, create=True), \
             patch.object(p.signal, 'pidfd_send_signal', create=True) as send, patch.object(p.os, 'close'):
            with self.assertRaises(ValueError):p.stop([995])
            send.assert_not_called()

    def test_gateway_observation_requires_original_interpreter_argv_and_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);entry=root/'123';entry.mkdir();(entry/'fd').mkdir();(root/'net').mkdir()
            (entry/'stat').write_text('123 (python3) '+' '.join(['S']+['0']*18+['99']))
            (entry/'status').write_text('Uid:\t996\t996\t996\t996\n')
            (entry/'cgroup').write_text('0::/system.slice/erpc-hyperliquid-rpc.service\n')
            (entry/'exe').symlink_to('/usr/bin/python3');(entry/'fd/5').symlink_to('socket:[77]')
            (root/'net/tcp').write_text('header\n0: 00000000:2161 00000000:0000 0A 0 0 0 996 0 77\n')
            (root/'net/tcp6').write_text('header\n')
            argv=[b'/usr/bin/python3',b'-I',os.fsencode(p.HELPERS/'current/erpc_hl_gateway.py'),os.fsencode(p.CONFIG/'gateway.json'),b'']
            (entry/'cmdline').write_bytes(b'\0'.join(argv))
            self.assertEqual(p.listener(996,8545,root,gateway=True)[0][:2],(123,'99'))
            (entry/'cmdline').write_bytes(b'\0'.join(argv[:2]+[b'/inert/other.py',*argv[3:]]))
            with self.assertRaisesRegex(ValueError,'fixed reviewed helper'):p.listener(996,8545,root,gateway=True)
            (entry/'cmdline').write_bytes(b'\0'.join(argv))
            (entry/'cgroup').write_text('0::/system.slice/erpc-hyperliquid-node.service\n')
            with self.assertRaisesRegex(ValueError,'different owned service'):p.listener(996,8545,root,gateway=True)
            (entry/'cgroup').write_text('0::/system.slice/erpc-hyperliquid-rpc.service\n')
            (entry/'exe').unlink();fake=root/'python3';fake.write_bytes(b'inert nonexecutable')
            (entry/'exe').symlink_to(fake)
            with self.assertRaisesRegex(ValueError,'exclusively'):p.listener(996,8545,root,gateway=True)


if __name__ == '__main__':unittest.main()
