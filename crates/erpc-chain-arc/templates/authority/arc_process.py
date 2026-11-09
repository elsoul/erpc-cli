#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original native-process observations and scoped shutdown without NSS rediscovery."""
import hashlib
import os
import signal
import stat
import time
from arc_files import Refused, require

UNITS = {'execution': 'arc-execution.service', 'consensus': 'arc-consensus.service',
         'snapshots': 'arc-snapshots.service'}
BINARIES = {'execution': 'arc-node-execution', 'consensus': 'arc-node-consensus',
            'snapshots': 'arc-snapshots'}


def properties(c, unit):
    result = c.command('/usr/bin/systemctl', 'show', unit, '--no-pager',
                       '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,ExecMainStatus,Result',
                       check=False)
    require(result.returncode == 0, 'Arc unit observation is unavailable')
    props = {}
    for line in result.stdout.decode('utf-8', 'strict').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in props, 'ambiguous Arc unit observation')
        props[key] = value
    require(all(key in props for key in ('LoadState', 'ActiveState', 'MainPID', 'ControlGroup')),
            'incomplete Arc unit observation')
    return props


def process(c, pid):
    require(type(pid) is int and pid > 1, 'invalid original Arc process identifier')
    root = c.path('/proc') / str(pid)
    start = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    fields = {}
    for line in (root / 'status').read_text().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields[key] = value.split()
    require(all(key in fields for key in ('Uid', 'Gid', 'Groups')), 'Arc process credentials are unavailable')
    exe = root / 'exe'
    target = os.readlink(exe)
    require(target.startswith('/'), 'Arc process image path is unavailable')
    deleted = target.endswith(' (deleted)')
    if deleted:
        target = target[:-10]
    info = exe.stat()
    key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    cache = getattr(c, 'image_cache', {})
    image = cache.get(key)
    if image is None:
        with open(exe, 'rb') as stream:
            hasher = hashlib.sha256()
            for block in iter(lambda: stream.read(1048576), b''):
                hasher.update(block)
        after = exe.stat()
        require(key == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'Arc process image changed while hashed')
        image = hasher.hexdigest()
        cache[key] = image
    argv = (root / 'cmdline').read_bytes().split(b'\0')
    require(argv[-1] == b'', 'Arc process argv is incomplete')
    argv = [part.decode('utf-8', 'strict') for part in argv[:-1]]
    cgroups = (root / 'cgroup').read_text().splitlines()
    require(len(cgroups) == 1 and cgroups[0].startswith('0::/'), 'Arc requires unified cgroup process authority')
    again = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    require(start == again, 'Arc process generation changed during observation')
    return {'pid': pid, 'start': start, 'uids': fields['Uid'], 'gids': fields['Gid'],
            'groups': fields['Groups'], 'exe': target, 'image': image,
            'inode': [info.st_dev, info.st_ino], 'argv': argv, 'cgroup': cgroups[0][3:], 'deleted': deleted}


def matches(c, state, component, observed, runtime, shutdown=False):
    uid, gid = str(state['service_uid']), str(state['service_gid'])
    expected = runtime[component]
    path = c.path(expected['binary'])
    if not shutdown:
        info = path.stat()
        require(not observed['deleted'] and observed['inode'] == [info.st_dev, info.st_ino],
                'Arc running image was deleted or substituted')
    require(observed['uids'] == [uid] * 4 and observed['gids'] == [gid] * 4 and
            set(observed['groups']) <= {gid} and observed['exe'] == str(path)
            and observed['image'] == expected['sha256'] and observed['argv'] == expected['argv']
            and observed['cgroup'] == '/system.slice/' + UNITS[component],
            'Arc native process is not the original account/image/argv/cgroup')
    return observed


def running(c, state, component, runtime):
    before = properties(c, UNITS[component])
    require(before['LoadState'] == 'loaded' and before['ActiveState'] == 'active' and
            before['MainPID'].isdecimal() and int(before['MainPID']) > 1,
            'original Arc component is not active')
    record = matches(c, state, component, process(c, int(before['MainPID'])), runtime)
    after = properties(c, UNITS[component])
    require(before == after, 'Arc native unit changed during observation')
    return record


def candidates(c, state):
    uid = state.get('service_uid')
    require(type(uid) is int and 100 <= uid <= 2147483647 and uid != 65534,
            'original Arc process identity is missing')
    rows = []
    for entry in c.path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            metadata = entry.lstat()
            groups = (entry / 'cgroup').read_text()
            args = (entry / 'cmdline').read_bytes()
            if (metadata.st_uid == uid or any(unit in groups for unit in UNITS.values()) or
                    args.split(b'\0', 1)[0].rsplit(b'/', 1)[-1] in {name.encode() for name in BINARIES.values()}):
                rows.append(process(c, int(entry.name)))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise Refused('original Arc process inventory cannot be inspected') from None
    return rows


def snapshot_child(c, state, observed, runtime):
    """Pinned snapshots/manifest.rs launches this execution-image download child.

    This recognizes shutdown authority only, never runtime readiness. The native
    manifest URL is an opaque final argv value; this function never contacts it.
    """
    if not all(component in runtime for component in ('snapshots', 'execution')):
        return False
    native = runtime['execution']
    parent = runtime['snapshots']['argv']
    if len(parent) != 10 or parent[1:3] != ['download', '--chain'] or parent[4] != '--el-profile':
        return False
    uid, gid = str(state['service_uid']), str(state['service_gid'])
    args = observed['argv']
    prefix = [native['binary'], 'download', '--chain', parent[3],
              '--datadir', parent[7], '--' + parent[5], '--manifest-url']
    shape = args == [prefix[0], 'download', '--help'] or (
        len(args) == 9 and args[:8] == prefix and isinstance(args[8], str) and
        0 < len(args[8]) <= 8192 and not any(char in args[8] for char in '\r\n\0'))
    return (shape and observed['uids'] == [uid] * 4 and observed['gids'] == [gid] * 4 and
            set(observed['groups']) <= {gid} and observed['image'] == native['sha256'] and
            observed['exe'] == str(c.path(native['binary'])) and
            observed['cgroup'] == '/system.slice/' + UNITS['snapshots'])


def classify(c, state, observed, runtimes):
    matches_found = []
    for runtime in runtimes:
        if snapshot_child(c, state, observed, runtime):
            matches_found.append('snapshots')
        for component in UNITS:
            if component not in runtime:
                continue
            try:
                matches(c, state, component, observed, runtime, shutdown=True)
                matches_found.append(component)
            except (Refused, FileNotFoundError):
                continue
    require(matches_found and len(set(matches_found)) == 1,
            'unidentified original-account Arc writer remains; data and filtering are retained')
    return matches_found[0]


def quiescent(c, state, selected, runtimes):
    for row in candidates(c, state):
        component = classify(c, state, row, runtimes)
        require(component not in selected, 'an original Arc writer remains')


def signal_original(c, state, selected, runtimes):
    rows = candidates(c, state)
    if not rows:
        return
    require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
            'Linux pidfd support is required for retained original-process shutdown')
    for record in rows:
        component = classify(c, state, record, runtimes)
        if component not in selected:
            continue
        fd = os.pidfd_open(record['pid'], 0)
        try:
            again = process(c, record['pid'])
            require(again == record, 'Arc process generation changed before shutdown')
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)


def stop(c, state, selected, runtimes, unit_proof):
    failures = []
    for component in ('consensus', 'execution', 'snapshots'):
        if component not in selected:
            continue
        unit = UNITS[component]
        try:
            unit_proof(component, historical=True)
            result = c.command('/usr/bin/systemctl', 'stop', unit, check=False)
            if result.returncode:
                failures.append('unit stop failed')
        except Exception:
            try:
                absent = properties(c, unit)
                require(absent['LoadState'] == 'not-found' and absent['ActiveState'] == 'inactive'
                        and absent['MainPID'] == '0', 'unproven Arc service remains loaded')
            except Exception:
                failures.append('unit could not be authenticated for shutdown')
    # Missing/changed units do not erase original process authority. Unknown writers
    # are never killed; matching retained native processes use generation-bound pidfds.
    try:
        signal_original(c, state, selected, runtimes)
        deadline = time.monotonic() + 300
        while True:
            waiting = [classify(c, state, row, runtimes) for row in candidates(c, state)]
            if not any(component in selected for component in waiting):
                break
            require(time.monotonic() < deadline, 'original Arc processes did not exit')
            time.sleep(1)
    except Exception:
        failures.append('original writer drain incomplete')
    require(not failures, 'Arc shutdown incomplete; original state, data and filtering retained')
