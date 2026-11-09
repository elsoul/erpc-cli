# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Loaded service receipts and original container/PID shutdown, independent of NSS."""
import scope
import hashlib
import os
import signal
import time
import container
import host
import processes
from storage import read, require

NAMES = scope.SERVICES
FIXED = ('FragmentPath', 'DropInPaths', 'User', 'Group', 'ExecCondition', 'ExecStartPre', 'ExecStart',
         'ExecStop', 'ExecStartPost', 'LoadCredentialEncrypted', 'NoNewPrivileges', 'UMask')
DYNAMIC = ('LoadState', 'ActiveState', 'SubState', 'MainPID')


def show(role, run=host.command):
    require(role in NAMES, 'unknown original validator component')
    raw = run(['/usr/bin/systemctl', 'show', NAMES[role], '--property='+','.join((*FIXED, *DYNAMIC))], allowed=(0, 1))
    result = {}
    for line in raw.decode('utf-8').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in (*FIXED, *DYNAMIC) and key not in result, 'ambiguous loaded service observation')
        result[key] = value
    require(result.get('LoadState') in ('loaded', 'not-found'), 'service load state is not known')
    return result


def loaded(state, expected, role, run=host.command):
    state.owner(expected); host.namespaces()
    result = show(role, run)
    if result['LoadState'] == 'not-found': return None
    record = state.get('units.json')
    require(record.get('contract') == expected and role in record.get('units', {}),
            'loaded service has no original publication receipt')
    saved = record['units'][role]
    require(set(FIXED) <= set(result) and {key: result[key] for key in FIXED} == saved['loaded']
            and result['FragmentPath'] == str(host.UNITS/NAMES[role])
            and result['User'] == '0' and result['Group'] == '0'
            and hashlib.sha256(read(host.UNITS/NAMES[role], 262144)).hexdigest() == saved['sha256'],
            'loaded service differs from the original root credential recipient or checked entrypoint')
    return result


def running(state, expected, role, run=host.command):
    value = loaded(state, expected, role, run)
    require(value is not None and value.get('ActiveState') == 'active' and value.get('SubState') == 'running'
            and value.get('MainPID', '').isdecimal() and int(value['MainPID']) > 1,
            'original service did not enter active/running after its credential condition')
    return int(value['MainPID'])


def transport(state, expected, records, run=host.command, listeners=True, starting=False):
    if starting:
        value = loaded(state, expected, 'transport', run)
        require(value is not None and value.get('ActiveState') in ('active', 'activating')
                and value.get('MainPID', '').isdecimal() and int(value['MainPID']) > 1,
                'original parent transport has not entered startup')
        pid = int(value['MainPID'])
    else: pid = running(state, expected, 'transport', run)
    record = state.get('transport-process.json')
    require(record.get('contract') == expected and record.get('account') == records['transport']
            and record.get('pid') == pid and record.get('generation') == state.fence()['generation'],
            'parent listener has no original runtime generation')
    proof = processes.snapshot(pid, record['account'], record['executable'], record['argv'],
                               {'/system.slice/'+NAMES['transport']})
    require(proof['start_time'] == record['start_time'], 'parent transport PID was reused')
    require(processes.owned_pids({records['transport']['uid']}) == {pid}, 'untracked original parent transport process remains')
    if listeners: processes.listeners(pid, records['transport']['uid'], (18545, 15052))
    return proof


def terminate_transport(record):
    """Use a kernel PID handle; never signal a numeric PID after reuse."""
    pid = record['pid']
    before = processes.snapshot(pid, record['account'], record['executable'], record['argv'],
                                {'/system.slice/'+NAMES['transport']})
    require(before['start_time'] == record['start_time'], 'original parent transport PID was replaced')
    descriptor = os.pidfd_open(pid, 0)
    try:
        require(processes.identity(pid)['start_time'] == record['start_time'], 'parent PID changed before acquiring its kernel handle')
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
    finally: os.close(descriptor)


def stop_container(record, run=host.command):
    if container.find(record['container_id'], run) is None: return
    target = record['target']; installed = container.image(target, run)
    value = container.observe('container', record['container_id'], run)
    identity = container.qualify(value, record['contract'], record['generation'], target, record['account'], installed)
    require(identity == record['container_id'], 'original container was replaced')
    if value['State']['Running']:
        # The exact original immutable container is the shutdown scope; never
        # signal other processes merely because their UID matches the account.
        run(container.cli('stop', '--time=180', identity), timeout=200)
    after = container.observe('container', identity, run)
    container.qualify(after, record['contract'], record['generation'], target, record['account'], installed)
    require(after['State']['Running'] is False and after['State']['Pid'] == 0, 'owned container did not stop')


def shutdown(state, expected, records, run=host.command, terminate=terminate_transport):
    state.owner(expected)
    failures = []
    for name, stop in [('container.json', lambda value: stop_container(value, run)),
                       ('transport-process.json', terminate)]:
        if not (state.root/name).exists(): continue
        try:
            value = state.get(name)
            require(value.get('contract') == expected, 'retained runtime receipt belongs to another owner')
            if name == 'transport-process.json':
                require(value.get('account') == records['transport'], 'original parent runtime account differs')
                try: current=processes.identity(value['pid'])
                except FileNotFoundError: continue
                if current['start_time']!=value['start_time']: continue  # Original exited; never signal a reused PID.
            else: require(value.get('account') == records['node'], 'original native runtime account differs')
            stop(value)
        except Exception: failures.append(name)
    # Stop only an authenticated loaded unit. Missing units are normal after
    # interrupted initialization. NSS drift does not affect original receipts.
    for role in ('node', 'transport'):
        try:
            value = loaded(state, expected, role, run)
            if value and value.get('ActiveState') not in ('inactive', 'failed'):
                run(['/usr/bin/systemctl', 'stop', NAMES[role]], timeout=240)
        except Exception: failures.append(role)
    deadline = time.monotonic()+5
    while True:
        try: processes.quiescent(records); break
        except ValueError:
            if time.monotonic() >= deadline: failures.append('original processes'); break
            time.sleep(0.05)
    require(not failures, 'original validator shutdown could not be completely verified')
    return {'stopped': True, 'data_retained': True, 'identity_retained': True}
