# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated-host kernel floors, durable configuration and live startup checks."""
from pathlib import Path
import re
import subprocess
from native_files import atomic, read, require, root_directory, sync_directory, sync_file

# Agave core/src/system_monitor_service.rs at a203300045b405f86c9c84308b2eae76af69ac3b
# and 3ad9da2c390eb7ad2630ed15afcd463e72e007a8 requires the first three floors.
# The official validator-start guide also requires fs.nr_open for LimitNOFILE.
MINIMUM = {'net.core.rmem_max': 134217728, 'net.core.wmem_max': 134217728,
           'vm.max_map_count': 1000000, 'fs.nr_open': 1000000}
CONFIG = Path('/etc/sysctl.d/90-erpc-solana-native.conf')


def execute(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'native host tuning operation failed')
    return result.stdout.decode('ascii')


def current(run=execute):
    values = {}
    for key in MINIMUM:
        raw = run(['/usr/sbin/sysctl', '-n', key]).strip()
        require(re.fullmatch('[0-9]{1,19}', raw) is not None, 'invalid kernel tuning observation')
        values[key] = int(raw)
    return values


def definition(values):
    require(isinstance(values, dict) and set(values) == set(MINIMUM)
            and all(type(values[key]) is int and MINIMUM[key] <= values[key] < 2**63 for key in MINIMUM),
            'native tuning receipt differs from its qualified policy')
    return ('# Managed by ERPC for this dedicated native Solana host.\n'
            + ''.join(key + ' = ' + str(values[key]) + '\n' for key in MINIMUM)).encode()


def configure(state, contract, run=execute):
    state.owner(contract)
    root_directory(CONFIG.parent)
    receipt = state.directory / 'tuning.json'
    if receipt.exists():
        saved = state.get('tuning.json')
        require(set(saved) == {'contract', 'values'} and saved['contract'] == contract,
                'native tuning belongs to another host')
        content = definition(saved['values'])
    else:
        require(not CONFIG.exists() and not CONFIG.is_symlink(), 'unowned native tuning cannot be replaced')
        observed = current(run)
        saved = {'contract': contract, 'values': {key: max(observed[key], floor) for key, floor in MINIMUM.items()}}
        content = definition(saved['values'])
        state.put('tuning.json', saved)
    # Re-establish the original receipt's durability before a retry changes host settings.
    sync_file(receipt); sync_directory(state.directory)
    if CONFIG.exists() or CONFIG.is_symlink():
        require(read(CONFIG, 16384) == content, 'managed native tuning was changed')
        sync_file(CONFIG); sync_directory(CONFIG.parent)
    else:
        atomic(CONFIG, content, 0o644)
    # Apply only our closed file; never execute arbitrary operator sysctl.d content.
    run(['/usr/sbin/sysctl', '-p', str(CONFIG)])
    observed = current(run)
    require(all(observed[key] >= saved['values'][key] for key in MINIMUM), 'kernel did not accept native tuning')
    return {'configured': True, 'values': observed}


def verify(state, contract, run=execute):
    state.owner(contract)
    saved = state.get('tuning.json')
    require(set(saved) == {'contract', 'values'} and saved['contract'] == contract,
            'native tuning belongs to another host')
    root_directory(CONFIG.parent)
    require(read(CONFIG, 16384) == definition(saved['values']), 'managed native tuning was changed')
    observed = current(run)
    require(all(observed[key] >= floor for key, floor in MINIMUM.items()), 'native kernel tuning is below its required floor')
    require(run(['/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value']).strip() == 'yes',
            'native node requires a synchronized system clock')
    return observed
