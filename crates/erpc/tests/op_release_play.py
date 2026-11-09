# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Render actual Rust bundles with the explicitly selected Ansible; execute no units."""
import io
import json
import shlex
import sys
import tarfile

import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()), mode='r:gz') as archive:
    files = {entry.name: archive.extractfile(entry).read().decode()
             for entry in archive if entry.isfile()}
inventory = json.loads(files['inventory.yml'])
hosts = inventory['all']['hosts']
assert len(hosts) == 1
values = next(iter(hosts.values()))
values.update(yaml.safe_load(files['ansible/op/vars.yml']))
values.update(op_uid=1234, op_gid=1234, playbook_dir='/inert/ansible/op')
templar = Templar(loader=DataLoader(), variables=values)
rendered = {role: templar.template(files['jinja/'+role+'.service.j2'], fail_on_undefined=True)
            for role in ('execution', 'consensus')}
commands = {}
for role, unit in rendered.items():
    line = next(line for line in unit.replace('\\\n', '').splitlines()
                if line.startswith('ExecStart='))
    commands[role] = shlex.split(line.removeprefix('ExecStart='))
    assert '{{' not in unit and '{%' not in unit
el, cl = commands['execution'], commands['consensus']
assert el[el.index('--chain')+1] == values['op_execution_chain']
assert '--storage.v2=true' in el
assert ('--full' in el) == (values['op_request']['contract']['history'] == 'full')
assert not any(flag.startswith(('--minimal', '--proofs-history', '--engine.num-state-masking-blocks'))
               or flag.split('=')[0] in {'--rpc-cache.max-bals', '--rpc-cache.cache-computed-bals',
                   '--rpc-cache.prewarm-bals', '--db.balstore-cache-size',
                   '--engine.disable-bal-parallel-execution', '--engine.disable-bal-parallel-state-root',
                   '--engine.disable-bal-batch-io'} for flag in el)
assert el[el.index('--http.addr')+1] == '127.0.0.1'
assert el[el.index('--authrpc.addr')+1] == '127.0.0.1'
if values['op_family'] == 'base':
    assert '/current/base-reth-node' in el[0]
    assert '/current/base-consensus' in cl[0]
else:
    for role, command in commands.items():
        reference = values['op_'+role+'_image']
        assert reference in command
        assert reference.endswith('@sha256:'+values['op_pair'][role]['sha256'])
        assert command[command.index('--user')+1] == '1234:1234'
        assert '--read-only' in command
    assert el[el.index('--p2p-secret-key')+1] == '/peer-key'
    assert '--l1.trustrpc=false' in cl
    assert values['op_pair']['execution']['version'] in ('2.6.1', '2.8.0')
    assert values['op_pair']['consensus']['version'] == '1.19.11'
print('qualified bundle rendered')
