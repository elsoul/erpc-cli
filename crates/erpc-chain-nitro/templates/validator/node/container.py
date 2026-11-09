# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed Docker content/configuration proof before native process authority.

Only Docker's root daemon on its fixed local socket is used. A name or matching
JSON-RPC reply is never process ownership. Native binaries are not executed by
qualification tests. The retained configuration supports shutdown after NSS drift.
"""
import scope
import json
import re
import stat
import host
import processes
import protocol
from storage import decode, directory, encode, read, require, write

NAME = 'erpc-'+scope.NAMESPACE
BINARY = '/usr/local/bin/nitro'
CLIENT = host.CONFIG / 'docker-client'
LABEL = 'org.erpc.'+scope.NAMESPACE+'.'


def cli(*args):
    return ['/usr/bin/docker', '--host=unix:///run/docker.sock', '--config=' + str(CLIENT), *args]


def client():
    directory(host.CONFIG, create=True)
    directory(CLIENT, create=True, mode=0o700)
    expected = b'{}\n'; path = CLIENT / 'config.json'
    if not path.exists(): write(path, expected)
    require({p.name for p in CLIENT.iterdir()} == {'config.json'} and read(path, mode=0o600) == expected,
            'Docker client credentials, plugins or external contexts are not allowed')


def observe(kind, identity, run=host.command):
    require(kind in ('container', 'image') and isinstance(identity, str), 'invalid Docker object observation')
    raw = run(cli('inspect', '--type=' + kind, identity), maximum=4*1024*1024)
    value = decode(raw)
    require(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), 'ambiguous Docker object')
    return value[0]


def engine(run=host.command):
    value = decode(run(cli('info', '--format', '{{json .}}')))
    require(value.get('OSType') == 'linux' and value.get('Architecture') in ('x86_64', 'amd64')
            and value.get('CgroupDriver') == 'systemd' and value.get('CgroupVersion') == '2'
            and isinstance(value.get('SecurityOptions'), list)
            and not any('rootless' in v or 'userns' in v for v in value['SecurityOptions']),
            'validator requires rootful Docker with original host IDs and systemd cgroup v2')
    return value


def image(target, run=host.command):
    protocol.target(target)
    value = observe('image', target['image'], run)
    require(value.get('Id') == target['image_id'] and value.get('Os') == 'linux'
            and value.get('Architecture') == 'amd64' and target['image'].removeprefix('docker.io/') in value.get('RepoDigests', []),
            'installed image does not match the reviewed platform manifest and config')
    config = value.get('Config')
    require(isinstance(config, dict) and isinstance(config.get('Env'), list)
            and all(isinstance(v, str) and '=' in v for v in config['Env']), 'image environment metadata is unavailable')
    return value


def arguments(phase):
    require(phase in ('observing', 'active'), 'unknown native validator phase')
    config = '/config/node.json' + (',/run/wallet.json' if phase == 'active' else '')
    return ['--conf.file=' + config]


def labels(expected, generation, target):
    return {LABEL+key: value for key, value in {
        'owner': expected['owner'], 'creation': expected['creation'], 'wallet': expected['wallet'],
        'host-binding': expected['host_binding'], 'data-uuid': expected['data_uuid'],
        'generation': generation, 'helpers': target['helpers_sha256'], 'config': target['config_id'],
        'phase': target['phase']}.items()}


def mounts(phase):
    result = [(str(host.DATA), '/data', False), (str(host.CONFIG/'public'), '/config', True)]
    if phase == 'active': result.append((str(host.RUNTIME/'wallet/wallet.json'), '/run/wallet.json', True))
    return result


def create_args(expected, generation, target, account):
    protocol.target(target)
    args = ['create', '--name='+NAME, '--pull=never', '--network=host', '--userns=host',
            '--ipc=private', '--cgroupns=private', '--init=false',
            '--user='+str(account['uid'])+':'+str(account['gid']), '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--restart=no', '--stop-timeout=180',
            '--entrypoint='+BINARY, '--workdir=/data', '--env=HOME=/data',
            '--env=SSL_CERT_FILE=/config/parent-ca.pem', '--env=SSL_CERT_DIR=/etc/ssl/certs',
            '--log-driver=local', '--log-opt=max-size=20m', '--log-opt=max-file=5',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=2147483648,mode=1777']
    for key, value in sorted(labels(expected, generation, target).items()): args += ['--label='+key+'='+value]
    for source, destination, readonly in mounts(target['phase']):
        args += ['--mount=type=bind,src='+source+',dst='+destination+(',readonly' if readonly else '')]
    return cli(*args, target['image'], *arguments(target['phase']))


def qualify(value, expected, generation, target, account, image_value, running=False):
    protocol.target(target)
    identity = value.get('Id')
    require(isinstance(identity, str) and re.fullmatch('[0-9a-f]{64}', identity)
            and value.get('Name') == '/'+NAME and value.get('Image') == target['image_id'],
            'container identity or immutable image differs')
    config, options, status = value.get('Config', {}), value.get('HostConfig', {}), value.get('State', {})
    require(config.get('Image') == target['image'] and config.get('User') == str(account['uid'])+':'+str(account['gid'])
            and config.get('Entrypoint') == [BINARY] and config.get('Cmd') == arguments(target['phase'])
            and config.get('WorkingDir') == '/data' and not config.get('OpenStdin') and not config.get('Tty'),
            'native argv, numeric recipient or execution interface differs')
    for key, wanted in labels(expected, generation, target).items():
        require(config.get('Labels', {}).get(key) == wanted, 'container is not the original deployment generation')
    base = {entry.split('=', 1)[0]: entry.split('=', 1)[1] for entry in image_value['Config']['Env']}
    base['HOME'] = '/data'
    base['SSL_CERT_FILE'] = '/config/parent-ca.pem'; base['SSL_CERT_DIR'] = '/etc/ssl/certs'
    actual = config.get('Env')
    require(isinstance(actual, list) and all(isinstance(v, str) and '=' in v for v in actual)
            and len(actual) == len(base)
            and {entry.split('=', 1)[0]: entry.split('=', 1)[1] for entry in actual} == base,
            'native environment adds unreviewed code or credential sources')
    require(options.get('NetworkMode') == 'host' and options.get('UsernsMode') == 'host'
            and options.get('ReadonlyRootfs') is True and not options.get('Privileged')
            and options.get('CapDrop') == ['ALL'] and not options.get('CapAdd')
            and options.get('SecurityOpt') == ['no-new-privileges'] and not options.get('GroupAdd')
            and not options.get('Devices') and not options.get('DeviceRequests')
            and not options.get('VolumesFrom') and not options.get('Links') and not options.get('PortBindings')
            and not options.get('Binds') and not options.get('PidMode') and not options.get('CgroupParent')
            and options.get('IpcMode')=='private' and options.get('CgroupnsMode')=='private' and options.get('Init') is False
            and not options.get('UTSMode') and not options.get('DeviceCgroupRules')
            and not options.get('ExtraHosts') and not options.get('Sysctls')
            and options.get('LogConfig')=={'Type':'local','Config':{'max-size':'20m','max-file':'5'}}
            and options.get('RestartPolicy', {}).get('Name') == 'no'
            and options.get('Tmpfs') == {'/tmp': 'rw,nosuid,nodev,size=2147483648,mode=1777'},
            'container isolation or additional host authority differs')
    observed = value.get('Mounts')
    require(isinstance(observed, list) and len(observed) == len(mounts(target['phase'])), 'container mount set differs')
    rows = []
    for mount in observed:
        require(mount.get('Type') == 'bind' and mount.get('Propagation') == 'rprivate'
                and type(mount.get('RW')) is bool, 'container mount is not a private exact bind')
        rows.append((mount.get('Source'), mount.get('Destination'), not mount['RW']))
    require(sorted(rows) == sorted(mounts(target['phase'])), 'container exposes unreviewed host files or writable config')
    require(type(status.get('Running')) is bool and type(status.get('Pid')) is int
            and not status.get('Paused') and not status.get('Restarting') and not status.get('Dead'),
            'container state cannot be safely qualified')
    if running: require(status['Running'] and status['Pid'] > 1, 'owned native container is not running')
    return identity


def prove(record, run=host.command, listeners=True):
    require(isinstance(record, dict) and set(record) == {'contract', 'generation', 'target', 'account', 'container_id'},
            'native container ownership receipt is missing')
    target = record['target']; installed = image(target, run)
    value = observe('container', record['container_id'], run)
    identity = qualify(value, record['contract'], record['generation'], target, record['account'], installed, running=True)
    require(identity == record['container_id'], 'container ID was replaced')
    pid = value['State']['Pid']; account = record['account']
    proof = processes.snapshot(pid, account, BINARY, [BINARY, *arguments(target['phase'])],
                               {'/system.slice/docker-'+identity+'.scope'})
    processes.container_members(account, pid, proof['cgroup'])
    if listeners: processes.listeners(pid, account['uid'], (8547, 8548, 8549, 6070))
    again = observe('container', identity, run)
    qualify(again, record['contract'], record['generation'], target, account, installed, running=True)
    require(again['State']['Pid'] == pid and processes.identity(pid)['start_time'] == proof['start_time'],
            'native runtime changed during listener qualification')
    return dict(proof, container_id=identity)


def find(identity=None, run=host.command):
    selector = 'name=^/'+NAME+'$' if identity is None else 'id='+identity
    if identity is not None: require(re.fullmatch('[0-9a-f]{64}', identity), 'invalid original container ID')
    raw = run(cli('container', 'ls', '--all', '--no-trunc', '--quiet', '--filter', selector), maximum=4096)
    values = raw.decode('ascii').splitlines()
    require(len(values) <= 1 and all(re.fullmatch('[0-9a-f]{64}', value) for value in values),
            'ambiguous original container namespace')
    if identity is not None and values: require(values == [identity], 'container ID lookup differs')
    return values[0] if values else None
