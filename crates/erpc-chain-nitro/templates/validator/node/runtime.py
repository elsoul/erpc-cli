# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native Docker and bounded parent transport service entrypoints."""
from contextlib import contextmanager, redirect_stdout
import scope
import os
import io
from pathlib import Path
import subprocess
import sys
import threading
import time
import accounts
import authority
import container
import credentials
import crypto
import custody
import history
import host
import locking
import processes
import publication
import parent_tls
import services
import transport
import upstreams
from state import State
from storage import decode, directory, read, require


def original():
    expected = decode(read(host.CONFIG/'contract.json', 16384))
    state = State(host.ROOT, host.RUNTIME/'cancelled-state.json'); state.owner(expected)
    return state, expected


def common(state, expected, action, operation=None, bundle=None):
    import hashlib
    state.owner(expected); host.namespaces()
    saved = state.get('common-firewall.json'); raw = read(host.FIREWALL_HELPER, 1048576)
    require(saved == {'contract': expected, 'sha256': hashlib.sha256(raw).hexdigest()},
            'common firewall helper differs from its original publication')
    namespace = {'__name__': 'erpc_validator_common_firewall', '__file__': str(host.FIREWALL_HELPER)}
    exec(compile(raw, str(host.FIREWALL_HELPER), 'exec'), namespace)
    # The common confirm helper prints a human acknowledgement. Keep the
    # controller's stdout a single compact JSON response.
    with redirect_stdout(io.StringIO()):
        namespace['Firewall'](scope.FAMILY).dispatch(action, operation, bundle)


def condition(role):
    require(role in ('node', 'transport'), 'unknown credential recipient')
    state, expected = original(); target = state.guard(expected)
    records = accounts.verify(state, expected)
    publication.verify(state, expected, target); host.capacity(state, expected)
    from installer import verify_config
    verify_config(state, expected, target)
    loaded = services.loaded(state, expected, role)
    require(loaded is not None, 'original runtime unit is missing')
    credentials.sealed(state, expected); parent_tls.sealed(state, expected)
    if target['phase'] == 'active':
        crypto.self_test()
        custody.sealed(state, expected)
        history.verify(state, expected, records['node'], lambda: processes.quiescent({'node': records['node']}))
    processes.quiescent({role: records[role]})
    common(state, expected, 'guard')
    if role == 'node': services.transport(state, expected, records)
    return state, expected, target, records


def credential(role, name):
    unit = services.NAMES[role]
    path = Path('/run/credentials')/unit
    require(os.environ.get('CREDENTIALS_DIRECTORY') == str(path), 'credential recipient directory differs')
    directory(path)
    return read(path/name, 131072)


def prepare(role):
    with locking.locked(host.RUNTIME/'startup.lock'):
        state, expected, target, records = condition(role)
        if role == 'node' and target['phase'] == 'active':
            custody.stage_runtime(state, expected, records, credential('node', custody.NAME),
                                  lambda account: processes.quiescent({'node': account}))
        return {'prepared': role}


def node():
    with locking.locked(host.RUNTIME/'startup.lock'):
        state, expected, target, records = condition('node')
        account = records['node']; generation = state.fence()['generation']
        container.client(); container.engine(); installed = container.image(target)
        if (state.root/'container.json').exists():
            previous = state.get('container.json'); services.stop_container(previous)
            if container.find(previous['container_id']) is not None:
                host.command(container.cli('rm', previous['container_id']))
        # The immutable reservation is durable before Docker creates a name.
        reservation = {'contract': expected, 'generation': generation, 'target': target, 'account': account}
        state.put('container-intent.json', reservation)
        raw = container.find()
        if raw is None:
            raw = host.command(container.create_args(expected, generation, target, account)).decode().strip()
        value = container.observe('container', raw)
        identity = container.qualify(value, expected, generation, target, account, installed)
        record = dict(reservation, container_id=identity); state.put('container.json', record)
        require(state.guard(expected) == target and state.fence()['generation'] == generation,
                'native launch was cancelled during container publication')
        if target['phase'] == 'active': authority.grant(state, expected, records)
        process = subprocess.Popen(container.cli('start', '--attach', identity), stdin=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        try:
            deadline = time.monotonic()+60
            while True:
                require(process.poll() is None, 'native container exited before original PID qualification')
                value = container.observe('container', identity)
                if value['State']['Running']:
                    container.prove(record, listeners=False); break
                require(time.monotonic() < deadline, 'native container did not enter its original runtime')
                time.sleep(0.1)
        except BaseException:
            try: services.stop_container(record)
            finally: process.wait(timeout=200)
            raise
    return process.wait()


def parent():
    with locking.locked(host.RUNTIME/'startup.lock'):
        state, expected, target, records = condition('transport')
        record = records['transport']; group = record['gid']
        raw = credential('transport', credentials.NAME)
        config = upstreams.strict_json(raw)
        tls = parent_tls.load(state, expected, raw=credential('transport', parent_tls.NAME))
        tls_context = parent_tls.server_context(tls)
        authority.initialize(group)
        current_generation = state.fence()['generation']
        @contextmanager
        def observing():
            raise ValueError('observer cannot acquire financial transaction authority')
            yield
        authorize = authority.acquire(group, expected, current_generation, target) if target['phase'] == 'active' else observing
        proxy = transport.Transport(config, expected['wallet'], target['phase'], authorize)
        pid = os.getpid(); identity = processes.identity(pid)
        require(os.geteuid() == 0 and os.getegid() == 0 and isinstance(sys.orig_argv, list),
                'parent transport must begin as the root credential recipient')
        executable = os.readlink(Path('/proc')/str(pid)/'exe')
        require(executable == '/usr/bin/python3.12', 'parent transport interpreter differs from Ubuntu24.04')
        value = {'contract': expected, 'generation': current_generation, 'account': record,
                 'pid': pid, 'start_time': identity['start_time'], 'executable': executable, 'argv': list(sys.orig_argv)}
        state.put('transport-process.json', value)
        os.environ.clear(); os.environ.update({'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': record['home']})
        os.setgroups([]); os.setgid(record['gid']); os.setuid(record['uid'])
        require(os.getuid() == record['uid'] and os.geteuid() == record['uid']
                and os.getgid() == record['gid'] and os.getegid() == record['gid'] and not os.getgroups(),
                'parent transport failed to drop to its original numeric account')
        proxy.verify()
        execution = parent_tls.Server(('127.0.0.1', 18545), upstreams.Handler, proxy, 'execution', tls_context)
        try: beacon = parent_tls.Server(('127.0.0.1', 15052), upstreams.Handler, proxy, 'beacon', tls_context)
        except BaseException: execution.server_close(); raise
    thread = threading.Thread(target=execution.serve_forever, daemon=True); thread.start()
    try: beacon.serve_forever()
    finally:
        execution.shutdown(); execution.server_close(); beacon.server_close()
    return 0


def stop_component(role):
    state, expected = original(); records = accounts.retained(state, expected)
    # Caller may already own STARTUP while systemctl stops this service. Do not
    # acquire it again here; the controller fenced and serialized the drain.
    if role == 'node' and (state.root/'container.json').exists():
        services.stop_container(state.get('container.json'))
    elif role == 'transport':
        authority.revoke(records['transport']['gid'])
    else: require(role in ('node', 'transport'), 'unknown stop component')
    return {'stopping': role}


def ready(role):
    require(role == 'transport', 'only parent transport has a prerequisite readiness barrier')
    state, expected = original(); records = accounts.verify(state, expected)
    deadline = time.monotonic()+60
    while True:
        state.guard(expected)
        try:
            services.transport(state, expected, records, starting=True)
            return {'transport_ready': True}
        except Exception:
            require(time.monotonic() < deadline, 'owned parent listener did not become ready')
            time.sleep(0.1)
