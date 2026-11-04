#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Seal only this operation's protected public configuration; no secret files."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, '/usr/local/lib/erpc')
import rollup_control as c


def record(request):
    state = c.read_state()
    c.check(state, request['contract'])
    c.require(state['phase'] == 'installing' and state['target'] == request['pair'], 'installation lost target ownership')
    conf, _, _ = c.paths(state['contract'])
    files = [conf / name for name in ('network.json', 'nginx.conf')]
    files += [c.LIB / name for name in ('rollup_control.py', 'rollup_status.py', 'rollup_upstreams.py',
                                       'rollup_bootstrap.py', 'rollup_runtime_jwt.py', 'rollup_container.py')]
    files += [Path('/etc/systemd/system') / (name + '.service') for name in c.units(state['contract']).values()]
    if state['contract']['family'] != 'base':
        files.append(conf / 'docker/config.json')
    if (conf / 'base-manifest.json').exists():
        files.append(conf / 'base-manifest.json')
    # The initial downloader regenerates reth.toml. The bootstrap completion
    # transaction seals it before ready; existing databases must retain it.
    if state.get('bootstrap_done'):
        files.append(conf / 'reth.toml')
    hashes = {}
    for path in files:
        c.root_file(path)
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = {'contract': state['contract'], 'pair': state['target'], 'files': hashes}
    c.atomic(conf / 'installation.json', json.dumps(receipt, sort_keys=True).encode(), 0o644)


if __name__ == '__main__':
    try:
        record(json.loads(sys.stdin.buffer.read(1024 * 1024)))
    except Exception:
        print('Protected follower installation could not be recorded', file=sys.stderr)
        sys.exit(1)
