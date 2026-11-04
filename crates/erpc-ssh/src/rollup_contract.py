# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only pre-reservation guard. The carried prepare play checks again under lock."""
import json
import os
import pwd
from pathlib import Path
import re
import subprocess
import sys

def require(condition):
    if not condition:
        raise ValueError("follower ownership rejected")


try:
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536 and os.geteuid() == 0)
    requested = json.loads(raw)
    require(set(requested) == {'owner', 'family', 'network', 'history'})
    networks = {'optimism': {'mainnet', 'sepolia'}, 'base': {'mainnet', 'sepolia'}, 'soneium': {'mainnet', 'minato'}}
    require(requested['family'] in networks and requested['network'] in networks[requested['family']])
    require(requested['history'] in {'full', 'archive'})
    require(isinstance(requested['owner'], str) and (requested['owner'] == '' or re.fullmatch('[a-zA-Z0-9]{1,80}', requested['owner'])))
    path = Path('/etc/erpc/rollup-owner.json')
    if path.exists() or path.is_symlink():
        require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0)
        state = json.loads(path.read_bytes())
        require(state.get('format') == 1 and state['contract'] == requested)
        print(json.dumps({'owned': True, 'phase': state['phase']}))
    else:
        for family in networks:
            for root in ['/etc/erpc', '/var/lib/erpc', '/opt/erpc']:
                candidate = Path(root) / family
                require(not candidate.exists() and not candidate.is_symlink())
            for role in ['execution', 'consensus', 'upstreams', 'rpc', 'bootstrap', 'firewall']:
                result = subprocess.run(['systemctl', 'show', '-p', 'LoadState', '--value', 'erpc-' + family + '-' + role],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                require(result.stdout.strip() == b'not-found' and result.returncode in (0, 1))
        for family in networks:
            for account in ('erpc-' + family, 'erpc-' + family + '-l1'):
                try:
                    pwd.getpwnam(account)
                except KeyError:
                    pass
                else:
                    require(False)
        result = subprocess.run(['ss', '-Hlnut'], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        require(result.returncode == 0)
        reserved = {8545, 8546, 8551, 8555, 8556, 9060, 9545, 6060, 7300, 18545, 15052, 30303, 9200, 9222, 9223}
        for line in result.stdout.decode().splitlines():
            fields = line.split()
            require(len(fields) >= 5)
            port = fields[4].rsplit(':', 1)[-1]
            require(not port.isdecimal() or int(port) not in reserved)
        print(json.dumps({'owned': False, 'phase': 'unowned'}))
except Exception:
    print('Follower host ownership mismatch, unowned state or failed preflight; nothing changed', file=sys.stderr)
    sys.exit(1)
