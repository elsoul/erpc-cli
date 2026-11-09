#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Run with an isolated venv Python containing the checked-in hash-pinned Ansible.

Only inert local command/stat modules run; no sudo, hosts, nodes or credentials.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PYTHON = sys.executable
assert subprocess.check_output([PYTHON, '-I', '-c', 'import ansible; print(ansible.__version__)'], text=True).strip() == '2.18.19'
spec = importlib.util.spec_from_file_location('runfiles', ROOT / 'crates/erpc-ops/node/run-files.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    poison, home = root / 'poison', root / 'home'
    poison.mkdir()
    home.mkdir()
    marker = root / 'ambient-hook-ran'
    (poison / 'sitecustomize.py').write_text('open(' + repr(str(marker)) + ', "w").write("inert hook")\n')
    shim = root / 'python-isolated'
    shim.write_bytes(module.INTERPRETER)
    shim.chmod(0o700)
    config = root / 'ansible.cfg'
    config.write_bytes((ROOT / 'crates/erpc-ops/node/ansible.cfg').read_bytes())
    inventory = root / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'hosts': {'localfixture': {'ansible_connection': 'local'}}}}))
    play = root / 'probe.yml'
    play.write_text(json.dumps([{'hosts': 'all', 'gather_facts': False,
        'environment': {'HOME': str(home), 'PYTHONPATH': str(poison)},
        'tasks': [{'ansible.builtin.command': {'argv': ['/usr/bin/python3', '-I', '-c',
            'import sys; assert sys.flags.isolated; print("isolated fixture")']}, 'changed_when': False},
            {'ansible.builtin.stat': {'path': str(play)}}]}]))
    env = dict(os.environ, ANSIBLE_CONFIG=str(config), ANSIBLE_PYTHON_INTERPRETER=str(shim),
               ANSIBLE_LOCAL_TEMP=str(root / 'ansible-local'), HOME=str(home), PYTHONPATH=str(poison))
    command = [PYTHON, '-I', '-m', 'ansible.cli.playbook', '-i', str(inventory), str(play)]
    subprocess.run(command, env=env, check=True)
    assert not marker.exists(), 'Ansible or module startup imported ambient code'
    # An unmanaged execution must fail rather than discover an unsafe Python.
    del env['ANSIBLE_PYTHON_INTERPRETER']
    failed = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert failed.returncode != 0, 'unmanaged Ansible unexpectedly selected an interpreter'
    assert not marker.exists()
print('Pinned Ansible controller/module isolation and missing-wrapper refusal verified')
