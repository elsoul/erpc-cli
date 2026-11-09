#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Generation-bound native writers, separate identities and scoped graceful drain."""
import os
import signal
import time

from arc_files import Refused, require
from arc_process import process, properties

UNITS = {'execution': 'erpc-arc-validator-execution.service',
         'consensus': 'erpc-arc-validator-consensus.service',
         'bootstrap': 'erpc-arc-validator-bootstrap.service'}


def account(state, component):
    return state['accounts']['consensus' if component == 'consensus' else 'execution']


def matches(context, state, component, observed, runtime, stopping=False):
    expected = runtime[component]
    number = str(account(state, component))
    primary = str(state['accounts']['engine']) if component == 'execution' else number
    path = context.path(expected['binary'])
    if not stopping:
        before = path.stat()
        require(not observed['deleted'] and observed['inode'] == [before.st_dev, before.st_ino],
                'original Arc validator native image was replaced or deleted')
    require(observed['uids'] == [number] * 4 and observed['gids'] == [primary] * 4 and
            set(observed['groups']) == {number, str(state['accounts']['engine'])} and
            observed['exe'] == str(path) and observed['image'] == expected['sha256'] and
            observed['argv'] == expected['argv'] and
            observed['cgroup'] == '/system.slice/' + UNITS[component],
            'Arc validator process differs from original identity, image, argv or cgroup')
    return observed


def running(context, state, component, runtime):
    before = properties(context, UNITS[component])
    require(before['LoadState'] == 'loaded' and before['ActiveState'] == 'active' and
            before.get('SubState') == 'running' and before['MainPID'].isdecimal() and
            int(before['MainPID']) > 1, 'original Arc validator component is not running')
    observed = matches(context, state, component, process(context, int(before['MainPID'])), runtime)
    require(properties(context, UNITS[component]) == before, 'Arc validator unit changed during observation')
    return observed


def candidates(context, state):
    numbers = {state['accounts'][role] for role in ('execution', 'consensus')}
    require(all(type(number) is int and 100 <= number <= 2147483647 and number != 65534
                for number in numbers), 'original validator process identity is unavailable')
    found = []
    for path in context.path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid():
            continue
        try:
            status = (path / 'status').read_text()
            require(len(status) <= 1048576, 'process credential observation exceeds its bound')
            credentials = [line.split(':', 1)[1].split() for line in status.splitlines() if line.startswith('Uid:')]
            require(len(credentials) == 1 and len(credentials[0]) == 4 and
                    all(value.isdecimal() for value in credentials[0]), 'process UID observation is incomplete')
            cgroup = (path / 'cgroup').read_text()
            # /proc directory ownership can become root when a process is not
            # dumpable; actual UID fields remain authoritative for orphan discovery.
            if any(int(value) in numbers for value in credentials[0]) or any('/' + unit in cgroup for unit in UNITS.values()):
                found.append(process(context, int(path.name)))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise Refused('original validator process inventory is unreadable') from None
    return found


def snapshot_child(context, state, observed, runtime):
    """Shutdown-only recognition of the pinned manifest.rs execution child.

    The two forms are the native `download --help` preflight and the exact
    `build_execution_argv` download. The final manifest URL is opaque native
    metadata, never contacted or accepted as a controller destination here.
    This adapts the reviewed Arc follower classifier to distinct original UIDs.
    """
    if not all(name in runtime for name in ('execution', 'bootstrap')):
        return False
    parent = runtime['bootstrap']['argv']
    if (len(parent) != 10 or parent[1:3] != ['download', '--chain'] or
            parent[4] != '--el-profile' or parent[5] != 'minimal' or
            parent[6] != '--execution-path' or parent[8] != '--consensus-path'):
        return False
    native = runtime['execution']
    prefix = [native['binary'], 'download', '--chain', parent[3], '--datadir',
              parent[7], '--minimal', '--manifest-url']
    arguments = observed['argv']
    form = arguments == [native['binary'], 'download', '--help'] or (
        len(arguments) == 9 and arguments[:8] == prefix and isinstance(arguments[8], str) and
        0 < len(arguments[8]) <= 8192 and not any(character in arguments[8] for character in '\r\n\0'))
    uid = str(state['accounts']['execution'])
    return (form and observed['uids'] == [uid] * 4 and observed['gids'] == [uid] * 4 and
            set(observed['groups']) == {uid, str(state['accounts']['engine'])} and
            observed['image'] == native['sha256'] and observed['exe'] == str(context.path(native['binary'])) and
            observed['cgroup'] == '/system.slice/' + UNITS['bootstrap'])


def classify(context, state, observed, runtimes):
    for runtime in runtimes:
        if snapshot_child(context, state, observed, runtime):
            return 'bootstrap'
        for component in UNITS:
            if component not in runtime:
                continue
            try:
                matches(context, state, component, observed, runtime, stopping=True)
                return component
            except (Refused, KeyError):
                continue
    raise Refused('unrecognized process occupies an original validator identity or cgroup')


def quiescent(context, state, selected, runtimes):
    for observed in candidates(context, state):
        require(classify(context, state, observed, runtimes) not in selected,
                'original Arc validator writer is still present')
    for component in selected:
        value = properties(context, UNITS[component])
        require(value['MainPID'] == '0' and value['ActiveState'] in ('inactive', 'failed'),
                'original Arc validator unit is not quiescent')


def signal_owned(context, state, selected, runtimes):
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
            'original validator shutdown requires Linux generation-bound signaling')
    for observed in candidates(context, state):
        component = classify(context, state, observed, runtimes)
        if component not in selected:
            continue
        descriptor = os.pidfd_open(observed['pid'], 0)
        try:
            require(process(context, observed['pid']) == observed,
                    'original validator process changed before shutdown')
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        finally:
            os.close(descriptor)


def stop(context, state, selected, runtimes):
    failures = []
    for component in ('consensus', 'execution', 'bootstrap'):
        if component not in selected:
            continue
        try:
            context.unit_proof(state, component, historical=True)
            result = context.command('/usr/bin/systemctl', 'stop', UNITS[component], check=False)
            require(result.returncode == 0, 'native validator service stop failed')
        except Exception:
            try:
                observed = properties(context, UNITS[component])
                require(observed['LoadState'] == 'not-found' and observed['ActiveState'] == 'inactive' and
                        observed['MainPID'] == '0', 'native validator unit cannot be authenticated')
            except Exception:
                failures.append('owned unit shutdown was not established')
    try:
        signal_owned(context, state, selected, runtimes)
        deadline = time.monotonic() + 300
        while candidates(context, state):
            remaining = [classify(context, state, value, runtimes) for value in candidates(context, state)]
            if not any(component in selected for component in remaining):
                break
            require(time.monotonic() < deadline, 'original validator native drain timed out')
            time.sleep(1)
        quiescent(context, state, selected, runtimes)
    except Exception:
        failures.append('original native writer drain was not established')
    require(not failures, 'Arc validator shutdown incomplete; data, original identity, history and ingress retained')
