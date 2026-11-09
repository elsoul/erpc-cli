# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Root-side build job preparation. Long build workers never hold the node lock."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory
from native_state import token
import native_toolchain as toolchain
from native_entrypoint import build_command

JOBS = Path('/var/lib/erpc-solana-build/jobs')
HELPERS = Path('/usr/local/lib/erpc/solana-native/releases')
TOOLCHAINS = Path('/opt/erpc/solana/toolchains')
UNITS = Path('/etc/systemd/system')


def request(catalog_bytes, network, intent):
    token(intent)
    catalog = json_value(catalog_bytes)
    require(network in ('mainnet', 'testnet'), 'invalid source-build network')
    profile = catalog['networks'][network]
    return {'schema': 1, 'network': network, 'intent': intent, 'commit': profile['commit'],
            'version': profile['version'], 'catalog_sha256': hashlib.sha256(catalog_bytes).hexdigest()}


def unit_name(intent, phase):
    token(intent)
    require(phase in ('fetch', 'compile'), 'invalid build phase')
    return 'erpc-solana-' + phase + '-' + intent + '.service'


def unit(helper_revision, intent, phase):
    require(re.fullmatch('[a-f0-9]{64}', helper_revision), 'invalid immutable helper revision')
    name = unit_name(intent, phase)
    work = JOBS / intent / 'work'
    helper = HELPERS / helper_revision / 'native_build.py'
    network = phase == 'fetch'
    families = 'AF_UNIX AF_INET AF_INET6' if network else 'AF_UNIX'
    return name, f'''[Unit]
Description=ERPC isolated Agave {phase}
After=network-online.target
Wants=network-online.target
RequiresMountsFor={work} {TOOLCHAINS}
[Service]
Type=oneshot
RemainAfterExit=yes
User=erpc-solana-build
Group=erpc-solana-build
WorkingDirectory={work}
ExecStart=/usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 {build_command(helper)} {phase} {intent}
TimeoutStartSec={'1800' if network else '14400'}
TimeoutStopSec=120
KillMode=control-group
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork={'false' if network else 'true'}
RestrictAddressFamilies={families}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths={work}
MemoryMax=48G
MemorySwapMax=0
CPUQuota=200%
IOWeight=10
Nice=10
TasksMax=1024
LimitNOFILE=65536
LimitCORE=0
'''


def create(state, contract, intent, helper_revision, builder=None):
    """Called under the short root operation lock after ownership/preflight checks."""
    require(isinstance(helper_revision, str) and re.fullmatch('[a-f0-9]{64}', helper_revision),
            'invalid immutable helper revision')
    pending = state.current(contract, intent)
    root_directory(HELPERS / helper_revision)
    catalog_bytes = read(HELPERS / helper_revision / 'catalog.json', 65536)
    public = request(catalog_bytes, contract['network'], intent)
    require(all(pending['target'][key] == public[key] for key in ('network', 'commit', 'version', 'catalog_sha256')),
            'source build is not the currently authorized target')
    profile = json_value(catalog_bytes)['networks'][contract['network']]
    toolchain.verify(TOOLCHAINS / profile['rust'], profile)
    builder = pwd.getpwnam('erpc-solana-build') if builder is None else builder
    require(builder.pw_uid != 0 and builder.pw_gid != 0 and builder.pw_shell in ('/sbin/nologin', '/usr/sbin/nologin')
            and builder.pw_dir == '/var/lib/erpc-solana-build', 'build account differs from its reserved profile')
    root_directory(JOBS, create=True)
    directory = JOBS / intent
    root_directory(directory, create=True)
    path = directory / 'request.json'
    if path.exists():
        require(json_value(read(path, 16384)) == public, 'build intent cannot be reused for another target')
    else:
        require(not any(directory.iterdir()), 'unowned interrupted build job exists')
        atomic(path, encoded(public), 0o444)
    work = directory / 'work'
    if not work.exists():
        work.mkdir(mode=0o700)
        os.chown(work, builder.pw_uid, builder.pw_gid)
        os.chmod(work, 0o700)
        sync_directory(work)
        sync_directory(directory)
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == builder.pw_uid
            and info.st_gid == builder.pw_gid and info.st_mode & 0o7777 == 0o700,
            'build workspace has unexpected ownership')
    root_directory(UNITS)
    for phase in ('fetch', 'compile'):
        name, text = unit(helper_revision, intent, phase)
        file = UNITS / name
        if file.exists() or file.is_symlink():
            require(read(file) == text.encode(), 'existing build unit differs from its immutable request')
        else:
            atomic(file, text.encode(), 0o644)
    state.current(contract, intent)
    return public


def systemctl(args):
    result = subprocess.run(['/usr/bin/systemctl', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150, check=False,
        env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'})
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'source-build service operation failed')
    return result.stdout.decode('utf-8')


def inspect(intent, phase, run=systemctl):
    name = unit_name(intent, phase)
    text = run(['show', name, '--property=LoadState,ActiveState,SubState,Result,MainPID,ExecMainStatus,FragmentPath,DropInPaths,User,Group,NeedDaemonReload'])
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, 'ambiguous source-build service metadata')
        fields[key] = value
    require(fields.get('LoadState') == 'loaded' and fields.get('FragmentPath') == str(UNITS / name)
            and fields.get('DropInPaths') == '' and fields.get('User') == 'erpc-solana-build'
            and fields.get('Group') == 'erpc-solana-build' and fields.get('NeedDaemonReload') == 'no',
            'source-build unit authority differs')
    if fields.get('ActiveState') == 'active' and fields.get('SubState') == 'exited':
        require(fields.get('Result') == 'success' and fields.get('MainPID') == '0'
                and fields.get('ExecMainStatus') == '0', 'source-build phase did not complete successfully')
        return 'complete'
    if fields.get('ActiveState') == 'activating':
        require(fields.get('MainPID', '').isdigit(), 'invalid source-build process identity')
        return 'running' if int(fields['MainPID']) > 0 else 'queued'
    if fields.get('ActiveState') == 'inactive':
        return 'inactive'
    return 'failed'


def idle_units(run=systemctl):
    """Reject queued jobs as well as live PIDs before another job or publication."""
    listing = run(['list-units', '--all', '--plain', '--no-legend', '--no-pager', '--type=service',
                   'erpc-solana-fetch-*.service', 'erpc-solana-compile-*.service'])
    names = set()
    for line in listing.splitlines():
        fields = line.split()
        require(len(fields) >= 4 and re.fullmatch(r'erpc-solana-(fetch|compile)-[a-f0-9]{32}\.service', fields[0])
                and fields[0] not in names, 'unexpected source-build service listing')
        names.add(fields[0])
        require(fields[1] == 'loaded' and (fields[2], fields[3]) in (('inactive', 'dead'), ('failed', 'failed')),
                'a source-build service remains queued, active or stopping')


def start(state, contract, intent, phase, helper_revision, quiescent, run=systemctl):
    """Root caller holds the operation lock; quiescent checks all dedicated-UID processes."""
    state.current(contract, intent)
    name, text = unit(helper_revision, intent, phase)
    require(read(UNITS / name) == text.encode(), 'source-build service definition changed')
    public = json_value(read(JOBS / intent / 'request.json', 16384))
    require(public['intent'] == intent and public['network'] == contract['network'], 'source-build request scope differs')
    run(['daemon-reload'])
    observed = inspect(intent, phase, run)
    if observed in ('running', 'queued', 'complete', 'failed'):
        return observed
    if phase == 'compile':
        require(inspect(intent, 'fetch', run) == 'complete', 'source dependencies must be fetched first')
        run(['stop', unit_name(intent, 'fetch')])
    idle_units(run)
    quiescent()
    state.current(contract, intent)
    run(['start', '--no-block', name])
    return 'submitted'


def finish(state, contract, intent, helper_revision, run=systemctl):
    """Publish one completed candidate without changing the approved runtime."""
    import native_process
    import native_publish
    state.current(contract, intent)
    require(isinstance(helper_revision, str) and re.fullmatch('[a-f0-9]{64}', helper_revision),
            'invalid immutable helper revision')
    root_directory(HELPERS / helper_revision)
    catalog_bytes = read(HELPERS / helper_revision / 'catalog.json', 65536)
    catalog = json_value(catalog_bytes)
    public = request(catalog_bytes, contract['network'], intent)
    require(json_value(read(JOBS / intent / 'request.json', 16384)) == public,
            'source-build request changed before publication')
    builder = pwd.getpwnam('erpc-solana-build')
    require(builder.pw_uid != 0 and builder.pw_gid != 0
            and builder.pw_shell in ('/sbin/nologin', '/usr/sbin/nologin')
            and builder.pw_dir == '/var/lib/erpc-solana-build', 'compiler account changed before publication')
    for phase in ('fetch', 'compile'):
        name, text = unit(helper_revision, intent, phase)
        require(read(UNITS / name) == text.encode(), 'source-build unit changed before publication')
        inspect(intent, phase, run)
    completion = JOBS / intent / 'compile-completed.json'
    completed = {'request': public, 'helper_revision': helper_revision, 'uid': builder.pw_uid, 'gid': builder.pw_gid}
    if completion.exists():
        require(json_value(read(completion, 16384)) == completed, 'compiler completion belongs to another request')
    else:
        require(inspect(intent, 'compile', run) == 'complete', 'compiler has not completed successfully')
        # Save successful-unit evidence before stopping RemainAfterExit units.
        # A disk failure cannot discard this evidence and silently authorize a
        # result produced by an incomplete or failed compiler on the next try.
        atomic(completion, encoded(completed))
    for phase in ('fetch', 'compile'):
        run(['stop', unit_name(intent, phase)])
    def quiescent():
        idle_units(run)
        native_process.assert_quiescent(builder.pw_uid)
    return native_publish.publish(state, contract, intent, JOBS / intent / 'work',
                                  public, catalog, builder.pw_uid, quiescent)
