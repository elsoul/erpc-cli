# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual Ansible publication modules with inert paths, UID and carried-source trust."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
try:
    import yaml
except ImportError:
    yaml = None
ANSIBLE = shutil.which('ansible-playbook')
SOURCE = Path(__file__).parents[1] / 'templates/node'

@unittest.skipUnless(yaml and ANSIBLE, 'optional pinned Ansible/PyYAML integration runtime')
class Publication(unittest.TestCase):
    def exercise(self, stage, kind):
        with tempfile.TemporaryDirectory(prefix='near-publication-') as temporary:
            root = Path(temporary)
            operation = root / 'operation/node'; operation.mkdir(parents=True)
            source = (SOURCE / 'control.py').read_text()
            source = source.replace("root=Path('/')", 'root=Path(' + repr(str(root)) + ')')
            source = source.replace('ROOT_UID = 0', 'ROOT_UID = ' + str(os.getuid()))
            source = source.replace("if __name__ == '__main__':", "Control.account = lambda self, expected: (20000, 20000)\nControl.account_snapshot = lambda self: ([], [])\nif __name__ == '__main__':")
            # Production carrier is sealed by node-run. This fixture models that
            # boundary; it does not weaken protected destination checks.
            source = source.replace("if __name__ == '__main__':", "trusted_imports = lambda path: None\nif __name__ == '__main__':")
            (operation / 'control.py').write_text(source)
            shutil.copyfile(SOURCE / 'near_validator.py', operation / 'near_validator.py')
            contract = {'owner': 'fixture', 'network': 'testnet', 'role': 'rpc',
                        'genesis_hash': 'FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b'}
            state = root / 'etc/erpc/near/contract.json'
            if stage != 'initial':
                state.parent.mkdir(parents=True)
                state.write_text(json.dumps({'format': 2, 'contract': contract})); state.chmod(0o600)
            before = state.read_bytes() if state.exists() else None
            namespace = root / 'usr/local/lib/erpc'; namespace.mkdir(parents=True)
            helper = namespace / 'near'
            if stage == 'update':
                helper.mkdir(); (helper / 'control.py').write_text('# inert previous release\n')
            if kind == 'writable-ancestor': namespace.chmod(0o777)
            if kind == 'symlink':
                if helper.exists(): shutil.rmtree(helper)
                outside = root / 'outside'; outside.mkdir(); helper.symlink_to(outside)
            play = copy.deepcopy(yaml.safe_load((SOURCE / ('prepare.yml' if stage == 'update' else 'init.yml')).read_text()))
            tasks = play[0]['tasks']; play[0]['become'] = False
            play[0]['tasks'] = [tasks[0], *[task for task in tasks if ('ansible.builtin.file' in task or 'ansible.builtin.copy' in task) and task.get('ansible.builtin.file', {}).get('path') != '/var/lib/near'], tasks[-1]]
            for task in play[0]['tasks']:
                for module in ('ansible.builtin.file', 'ansible.builtin.copy'):
                    if module in task:
                        task[module]['owner'] = str(os.getuid()); task[module]['group'] = str(os.getgid())
                if 'loop' in task:
                    task['loop'] = [item for item in task['loop'] if item['path'] != '/var/lib/near']
            rendered = yaml.safe_dump(play)
            for path in ('/usr/local/lib/erpc/near', '/usr/local/lib/erpc', '/etc/near', '/etc/erpc/near/docker'):
                # Longest path first, avoid replacing a path a second time.
                rendered = rendered.replace(path, '@@' + path.lstrip('/').replace('/', '__') + '@@')
            for path in ('/usr/local/lib/erpc/near', '/usr/local/lib/erpc', '/etc/near', '/etc/erpc/near/docker'):
                rendered = rendered.replace('@@' + path.lstrip('/').replace('/', '__') + '@@', str(root / path.lstrip('/')))
            play = yaml.safe_load(rendered)
            if kind == 'substitution':
                play[0]['tasks'].insert(-1, {'name': 'Inert post-copy substitution', 'ansible.builtin.copy': {
                    'dest': str(helper / 'control.py'), 'content': 'raise RuntimeError("must not execute")\n', 'mode': '0644'}})
            (operation / 'play.yml').write_text(yaml.safe_dump(play))
            variables = {'near_contract': base64.b64encode(json.dumps(contract).encode()).decode()}
            (operation / 'vars.json').write_text(json.dumps(variables))
            result = subprocess.run([ANSIBLE, '-i', 'localhost,', '-c', 'local', str(operation / 'play.yml'),
                                     '-e', '@' + str(operation / 'vars.json')], capture_output=True, text=True, timeout=90, check=False)
            if kind == 'safe':
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((helper / 'control.py').read_text(), source)
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                if kind == 'substitution':
                    self.assertIn('differs from the sealed carried source', result.stdout)
                else:
                    self.assertEqual(state.read_bytes() if state.exists() else None, before)
                    if kind == 'writable-ancestor': self.assertEqual(namespace.stat().st_mode & 0o777, 0o777)
                    if kind == 'symlink': self.assertTrue(helper.is_symlink())

    def test_initial_retry_and_update_use_only_protected_destinations(self):
        for stage in ('initial', 'retry', 'update'):
            for kind in ('safe', 'writable-ancestor', 'symlink'):
                with self.subTest(stage=stage, kind=kind): self.exercise(stage, kind)

    def test_post_copy_source_comparison_precedes_installed_code_execution(self):
        self.exercise('initial', 'substitution')

if __name__ == '__main__': unittest.main()
