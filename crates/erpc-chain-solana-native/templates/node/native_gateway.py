# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated unprivileged HTTP/WebSocket ingress; no native identity credential."""
import hashlib
import os
import re
from pathlib import Path
import stat
from native_files import atomic, read, require, root_directory, sync_directory, sync_file
from native_entrypoint import runtime_command
import native_gateway_account as identities
import native_helpers as helpers
import native_process as processes

UNIT = 'erpc-solana-gateway.service'
UNITS = Path('/etc/systemd/system')
CONFIG = Path('/etc/erpc/solana-native-gateway.conf')
BINARY = Path('/usr/sbin/nginx')
RUN = Path('/run/erpc-solana-gateway')


def distribution_mask(state, contract):
    state.owner(contract)
    require(state.get('gateway-distribution.json') == {'contract': contract, 'unit': 'nginx.service'},
            'distribution nginx suppression belongs to another host')
    root_directory(UNITS)
    path = UNITS / 'nginx.service'
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(path) == '/dev/null',
            'distribution nginx must remain persistently masked')


def distribution_service(run, masked):
    root_directory(UNITS)
    path = UNITS / 'nginx.service'
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(path) == '/dev/null',
                'an unmanaged nginx unit override cannot be adopted')
    raw = run(['show', 'nginx.service', '--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths,UnitFileState'], allowed=(0, 1))
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in values, 'ambiguous distribution nginx service metadata')
        values[key] = value
    require(values.get('LoadState') in ('not-found', 'loaded', 'masked')
            and values.get('ActiveState') in ('inactive', 'failed') and values.get('MainPID') == '0'
            and values.get('DropInPaths') == ''
            and values.get('FragmentPath') in ('', '/dev/null', '/lib/systemd/system/nginx.service', '/usr/lib/systemd/system/nginx.service'),
            'an active or unmanaged distribution nginx service must be resolved by its owner')
    if masked:
        require(path.is_symlink() and values.get('LoadState') == 'masked' and values.get('UnitFileState') == 'masked',
                'distribution nginx is not persistently masked before package or runtime use')


def package(state, contract, run, prepare=False):
    require(contract['profile'] == 'agave-native-rpc', 'only RPC hosts install nginx')
    identities.verify(state, contract)
    distribution_service(run, masked=not prepare)
    expected = {'contract': contract, 'unit': 'nginx.service'}
    path = state.directory / 'gateway-distribution.json'
    if path.exists(): require(state.get(path.name) == expected, 'distribution nginx suppression authority differs')
    else:
        require(prepare, 'distribution nginx suppression was not reserved')
        state.put(path.name, expected)
    sync_file(path); sync_directory(state.directory)
    if not prepare: distribution_mask(state, contract)
    return {'distribution_unit': 'nginx.service', 'suppression_reserved': True, 'masked': not prepare}


def arguments():
    return [str(BINARY), '-c', str(CONFIG), '-g', 'daemon off;']


def configuration(access):
    from native_firewall import access as checked
    checked(access, True)
    allowed = ['127.0.0.1/32', '::1/128', *access['rpc']]
    acl = '\n'.join('    allow ' + value + ';' for value in allowed) + '\n    deny all;'
    # ERPC ingress policy, not a claimed Agave throughput or API-size limit.
    # Ordinary nginx master/workers all run as the reserved unprivileged UID.
    return f'''worker_processes 2;
pid {RUN}/nginx.pid;
error_log stderr warn;
events {{ worker_connections 8192; }}
http {{
  access_log off;
  server_tokens off;
  client_body_temp_path {RUN}/body;
  proxy_temp_path {RUN}/proxy;
  fastcgi_temp_path {RUN}/fastcgi;
  scgi_temp_path {RUN}/scgi;
  uwsgi_temp_path {RUN}/uwsgi;
  client_max_body_size 10m;
  client_header_timeout 10s;
  client_body_timeout 30s;
  send_timeout 60s;
  keepalive_timeout 65s;
  limit_conn_zone $binary_remote_addr zone=per_client:10m;
  limit_req_zone $binary_remote_addr zone=per_client_rate:10m rate=1000r/s;
  limit_conn per_client 1024;
  limit_req zone=per_client_rate burst=2000 nodelay;
  limit_conn_status 429;
  limit_req_status 429;
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
  server {{
    listen 0.0.0.0:7211;
    listen [::]:7211 ipv6only=on;
{acl}
    location / {{
      proxy_http_version 1.1;
      proxy_set_header Host 127.0.0.1;
      proxy_set_header Connection '';
      proxy_pass http://127.0.0.1:8899;
      proxy_connect_timeout 5s;
      proxy_read_timeout 60s;
      proxy_buffering off;
    }}
  }}
  server {{
    listen 0.0.0.0:7212;
    listen [::]:7212 ipv6only=on;
{acl}
    location / {{
      proxy_http_version 1.1;
      proxy_set_header Host 127.0.0.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_pass http://127.0.0.1:8900;
      proxy_connect_timeout 5s;
      proxy_read_timeout 3600s;
      proxy_buffering off;
    }}
  }}
}}
'''.encode()


def definition(account, revision):
    identities.accounts.validate_plan({'gateway': account}, identities.SPECS)
    helpers.verify(revision)
    entry = runtime_command(helpers.RELEASES / revision / 'native_runtime_control.py')
    return f'''[Unit]
Description=ERPC isolated Solana HTTP and WebSocket ingress
Requires=erpc-solana.service erpc-solana-native-firewall.service
After=erpc-solana.service erpc-solana-native-firewall.service
PartOf=erpc-solana.service
[Service]
Type=exec
User={account['uid']}
Group={account['gid']}
ExecCondition=+{entry} gateway-condition
ExecStartPre=+{entry} gateway-guard
ExecStart={BINARY} -c {CONFIG} -g "daemon off;"
RuntimeDirectory=erpc-solana-gateway
RuntimeDirectoryMode=0700
KillMode=control-group
KillSignal=SIGQUIT
TimeoutStopSec=60
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths={RUN}
LimitNOFILE=65536
LimitCORE=0
TasksMax=32
[Install]
WantedBy=multi-user.target
'''.encode()


def binary_digest():
    root_directory(BINARY.parent)
    raw = read(BINARY, 64 * 1024 * 1024)
    require(BINARY.lstat().st_mode & 0o111 and raw, 'distribution ingress executable is missing')
    return hashlib.sha256(raw).hexdigest()


def overrides():
    path = UNITS / (UNIT + '.d')
    if path.exists() or path.is_symlink():
        root_directory(path)
        require(all(item.name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new')
                    for item in path.iterdir()), 'native ingress has an unknown service override')
        for item in path.iterdir(): read(item)


def verify(state, contract, receipt):
    distribution_mask(state, contract)
    account = identities.verify(state, contract)
    require(isinstance(receipt, dict) and set(receipt) == {
        'account', 'helper_revision', 'access', 'unit_sha256', 'config_sha256', 'binary_sha256', 'distribution_version'}
        and receipt['account'] == account, 'native ingress receipt or original account differs')
    require(isinstance(receipt['distribution_version'],str)
            and re.fullmatch('[0-9][A-Za-z0-9.+:~_-]{0,127}',receipt['distribution_version']),
            'native ingress package version is missing')
    unit = definition(account, receipt['helper_revision'])
    config = configuration(receipt['access'])
    root_directory(UNITS); root_directory(CONFIG.parent); overrides()
    require(hashlib.sha256(unit).hexdigest() == receipt['unit_sha256']
            and hashlib.sha256(config).hexdigest() == receipt['config_sha256']
            and read(UNITS / UNIT) == unit and read(CONFIG) == config,
            'native ingress configuration differs from its approved receipt')
    require(binary_digest() == receipt['binary_sha256'], 'distribution ingress binary changed; explicitly update configuration')
    return account


def service(account, run):
    raw = run(['show', UNIT,
        '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,User,Group,NeedDaemonReload'])
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, 'ambiguous ingress service metadata')
        fields[key] = value
    require(fields.get('LoadState') == 'loaded' and fields.get('FragmentPath') == str(UNITS / UNIT)
            and fields.get('DropInPaths') in ('', str(UNITS / (UNIT + '.d/50-erpc-firewall-guard.conf')))
            and fields.get('User') == str(account['uid']) and fields.get('Group') == str(account['gid'])
            and fields.get('NeedDaemonReload') == 'no', 'loaded ingress service authority differs')
    require(fields.get('MainPID', '').isdecimal(), 'invalid ingress process identity')
    fields['MainPID'] = int(fields['MainPID'])
    return fields


def shutdown(state, contract, run):
    if contract['profile'] != 'agave-native-rpc': return
    state.owner(contract)
    if not (state.directory / identities.RECEIPT).exists():
        require(not (UNITS / UNIT).exists() and not (UNITS / UNIT).is_symlink(), 'unowned ingress service exists')
        require(run(['show', UNIT, '--property=LoadState', '--value'], allowed=(0, 1)).strip() == 'not-found',
                'unowned ingress service remains loaded')
        return
    account = identities.original(state, contract)
    allowed = []
    for name in ('active.json', 'runtime-install.json', 'gateway-install.json'):
        if (state.directory / name).exists():
            value = state.get(name)
            if name != 'active.json': require(value['contract'] == contract, 'ingress shutdown installation belongs to another host')
            receipt = value['receipt'] if name == 'gateway-install.json' else value['receipt'].get('gateway')
            if receipt is not None:
                require(receipt['account'] == account, 'ingress shutdown original account differs')
                allowed.append(receipt['unit_sha256'])
    root_directory(UNITS); overrides()
    if not (UNITS / UNIT).exists() and not (UNITS / UNIT).is_symlink():
        require(run(['show', UNIT, '--property=LoadState', '--value'], allowed=(0, 1)).strip() == 'not-found',
                'ingress service remains loaded without its original file')
        processes.assert_quiescent(account['uid']); return
    require(hashlib.sha256(read(UNITS / UNIT)).hexdigest() in allowed, 'unknown ingress unit cannot be adopted or stopped')
    run(['daemon-reload']); service(account, run)
    failures = []
    for action in ('stop', 'disable'):
        try: run([action, UNIT], timeout=90)
        except Exception: failures.append(action)
    try:
        actual = service(account, run)
        require(actual['ActiveState'] in ('inactive', 'failed') and actual['MainPID'] == 0,
                'native ingress remains active')
        processes.assert_quiescent(account['uid'])
    except Exception: failures.append('quiescence')
    require(not failures, 'native ingress shutdown could not be confirmed')


def run_directory(state, contract, account):
    require(identities.original(state, contract) == account, 'ingress runtime directory lacks original authority')
    root_directory(RUN.parent)
    if not RUN.exists() and not RUN.is_symlink():
        RUN.mkdir(mode=0o700)
    info = RUN.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o7777 == 0o700, 'native ingress runtime directory differs')
    if (info.st_uid, info.st_gid) == (0, 0):
        # Only the empty directory left between mkdir and chown can resume.
        # The root-only /run parent prevents the service UID replacing this name.
        require(not any(RUN.iterdir()), 'unowned ingress runtime directory is not empty')
        os.chown(RUN, account['uid'], account['gid'], follow_symlinks=False)
    current = RUN.lstat()
    require((current.st_dev,current.st_ino) == (info.st_dev,info.st_ino)
            and current.st_uid == account['uid'] and current.st_gid == account['gid'],
            'native ingress runtime directory ownership differs')
    sync_directory(RUN); sync_directory(RUN.parent)


def install(state, contract, intent, revision, run, command):
    operation = state.current(contract, intent)
    cutover = state.get('cutover.json')
    require(all(cutover[key] == operation[key] for key in ('intent', 'halt', 'target')),
            'native ingress installation requires the current stopped cutover')
    require(contract['profile'] == 'agave-native-rpc' and operation['target']['mode'] == 'rpc'
            and operation['target']['helper_revision'] == revision, 'native ingress requires the current RPC deployment')
    preparation = state.get('firewall-preparation-' + intent + '.json')
    require(preparation['contract'] == contract and preparation['intent'] == intent
            and preparation['helper_revision'] == revision, 'native ingress policy differs from the requested deployment')
    account = identities.verify(state, contract)
    shutdown(state, contract, run); processes.assert_quiescent(account['uid'])
    raw_config = configuration(preparation['access']); raw_unit = definition(account, revision)
    version = command(['/usr/bin/dpkg-query', '--show', '--showformat=${Version}', 'nginx']).strip()
    require(re.fullmatch('[0-9][A-Za-z0-9.+:~_-]{0,127}',version), 'distribution ingress package version is unavailable')
    receipt = {'account': account, 'helper_revision': revision, 'access': preparation['access'],
        'unit_sha256': hashlib.sha256(raw_unit).hexdigest(), 'config_sha256': hashlib.sha256(raw_config).hexdigest(),
        'binary_sha256': binary_digest(), 'distribution_version': version}
    root_directory(CONFIG.parent)
    if CONFIG.exists() or CONFIG.is_symlink():
        allowed = []
        for name in ('active.json', 'runtime-install.json', 'gateway-install.json'):
            if (state.directory / name).exists():
                value = state.get(name)
                if name != 'active.json': require(value['contract'] == contract, 'ingress configuration belongs to another host')
                old = value['receipt'] if name == 'gateway-install.json' else value['receipt'].get('gateway')
                if old is not None: allowed.append(old['config_sha256'])
        require(hashlib.sha256(read(CONFIG)).hexdigest() in allowed, 'unknown ingress configuration cannot be overwritten')
    state.put('gateway-install.json', {'contract': contract, 'intent': intent, 'receipt': receipt})
    sync_file(state.directory / 'gateway-install.json'); sync_directory(state.directory)
    atomic(CONFIG, raw_config, 0o644); atomic(UNITS / UNIT, raw_unit, 0o644)
    run_directory(state, contract, account)
    # Configuration checking runs with the original numeric unprivileged identity;
    # nginx never interprets gateway-writable temporary paths as root.
    command(['/usr/bin/setpriv', '--reuid', str(account['uid']), '--regid', str(account['gid']),
             '--clear-groups', '--no-new-privs', *arguments(), '-t'])
    verify(state, contract, receipt); state.current(contract, intent)
    return receipt


def start(state, contract, receipt, run):
    package(state, contract, run)
    account = verify(state, contract, receipt)
    run(['daemon-reload'])
    before = service(account, run)
    if before['ActiveState'] in ('inactive', 'failed'):
        processes.assert_quiescent(account['uid'])
    run(['enable', UNIT]); run(['start', UNIT], timeout=90)
    actual = service(account, run)
    require(actual['ActiveState'] == 'active' and actual['SubState'] == 'running' and actual['MainPID'] > 0,
            'native ingress condition or service did not start')
    return actual['MainPID']


def guard(state, contract, run):
    from native_runtime_control import qualify
    package(state, contract, run)
    active = state.guard(contract)
    qualify(state, contract, active)
    account = verify(state, contract, active['receipt']['gateway'])
    service(account, run); processes.assert_quiescent(account['uid'])
    require(state.guard(contract) == active, 'native ingress activation changed during startup')
