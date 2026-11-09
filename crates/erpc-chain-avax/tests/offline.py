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

SOURCE = Path(__file__).resolve().parents[1] / 'templates/jinja/control.py'
spec = importlib.util.spec_from_file_location('identity', SOURCE)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class CapacityTests(unittest.TestCase):
    def test_initial_sync_and_existing_operating_headroom(self):
        spec = importlib.util.spec_from_file_location('capacity', SOURCE.with_name('capacity.py'))
        capacity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capacity)
        for history, minimum in [('full', 900_000_000), ('archive', 13_000_000_000)]:
            with self.assertRaises(ValueError):
                capacity.check(minimum, 100_000_000, history, 0)
            capacity.check(minimum, minimum, history, 0)
            capacity.check(minimum, 100_000_000, history, minimum)
            with self.assertRaises(ValueError):
                capacity.check(minimum, 99_999_999, history, minimum)

    def test_partial_database_does_not_bypass_initial_budget_or_nested_mount_checks(self):
        spec=importlib.util.spec_from_file_location('capacity_remaining',SOURCE.with_name('capacity.py'))
        c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'data';root.mkdir(mode=0o700)
            db=root/'db/fuji';db.mkdir(parents=True)
            (db/'metadata').write_bytes(b'incomplete bootstrap')
            mounts=Path(directory)/'mountinfo';mounts.write_text('1 0 0:1 / / rw - ext4 /dev/fixture rw\n')
            disk=types.SimpleNamespace(f_blocks=900_000_000,f_frsize=1024,f_bavail=100_000_000)
            with patch.object(c.os,'statvfs',return_value=disk):
                with self.assertRaises(ValueError):c.inspect(root,'full','fuji',os.getuid(),mounts)
            sparse=db/'sparse';sparse.touch()
            with sparse.open('r+b') as stream:stream.truncate(100_000_000)
            self.assertLess(c.allocation(root,'fuji',os.getuid(),mounts),100_000)
            mounts.write_text('1 0 0:1 / / rw - ext4 /dev/fixture rw\n2 1 0:1 / '+str(db)+' rw - ext4 /dev/fixture rw\n')
            with self.assertRaises(ValueError):c.allocation(root,'fuji',os.getuid(),mounts)
            mounts.write_text('1 0 0:1 / / rw - ext4 /dev/fixture rw\n')
            actual=Path.lstat
            def changed(path,*args,**kwargs):
                info=actual(path,*args,**kwargs)
                if path==db:
                    fields=list(info);fields[2]+=1;return os.stat_result(fields)
                return info
            with patch.object(Path,'lstat',changed):
                with self.assertRaises(ValueError):c.allocation(root,'fuji',os.getuid(),mounts)
            (db/'link').symlink_to(db/'metadata')
            with self.assertRaises(ValueError):c.allocation(root,'fuji',os.getuid(),mounts)
        for bad in (True,-1,1.5,'100'):
            with self.assertRaises(ValueError):c.check(900_000_000,900_000_000,'full',bad)

    def test_every_mutating_play_authenticates_scope_before_effects(self):
        plays=SOURCE.parents[1]/'ansible/avax'
        for name in ('init','firewall','destroy'):
            first=(plays/(name+'.yml')).read_text().split('  tasks:\n',1)[1].split('    - name:',2)[1]
            self.assertIn('import_tasks: tasks/contract.yml',first)
        first=(plays/'deploy.yml').read_text().split('  tasks:\n',1)[1].split('    - name:',2)[1]
        self.assertIn("'action':'deploy-check'",first)
        self.assertIn('erpc_fw_confirmed_run',first)
        self.assertIn('erpc_fw_confirmed_bundle',first)
        self.assertIn('avax_intent',first)
        self.assertIn('control.py',(plays/'tasks/contract.yml').read_text())


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
            keyring = root/'keyring'
            keyring.mkdir(mode=0o700)
            public = subprocess.run(['gpg', '--batch', '--homedir', str(keyring), '--show-keys', '--with-colons', str(key)], capture_output=True, text=True, check=True)
            fingerprint = '5395BDA1129CAC3E74699D07D93080B0C0D5FE8B'
            self.assertIn('fpr:::::::::' + fingerprint + ':', public.stdout)
            (root/'release-v1.15.2.tar.gz').write_bytes(b'inert archive bytes, not a node')
            (root/'release-v1.15.2.sig').write_bytes(b'corrupt detached signature')
            script = '\n'.join(lines).replace('{{ playbook_dir }}', str(playbook)).replace('{{ avax_opt }}', str(root)).replace('{{ avax_fingerprint }}', fingerprint).replace('{{ avax_version }}','v1.15.2')
            self.assertNotIn('{{',script)
            self.assertIn(str(root/'release-v1.15.2.sig'),script)
            outcome = subprocess.run(['bash', '-c', script], capture_output=True)
            self.assertNotEqual(outcome.returncode, 0)


if __name__ == '__main__':
    unittest.main()
