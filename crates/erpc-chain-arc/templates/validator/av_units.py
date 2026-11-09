#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated numeric validator units; retained definitions authorize shutdown only.

Receipt publication/proof derives from reviewed Arc70, with its own namespace.
"""
from arc_files import digest, require
from av_files import HOME, ROOT
from av_process import UNITS
import av_helpers as helpers
import av_policy
import av_state
import av_loaded
import arc_release as release

ENGINE_RUN = '/run/erpc-arc-validator-engine'


def make(c, state, target, policy, folder, helper_hash):
    av_policy.validate(state, policy)
    # The official source describes local signing as non-production. Production
    # remote custody, authenticated transport and typed signing history must be
    # qualified before a unit can expose an active consensus signer.
    require(policy['phase'] == 'observer',
            'production Arc remote-signing authority is not yet qualified; local activation is refused')
    source = release.qualify(c, target)
    network = av_state.NETWORKS[state['contract']['network']]
    native = release.directory(target)
    metrics = '0.0.0.0' if policy['monitoring_allow'] else '127.0.0.1'
    execution = [native + '/arc-node-execution', 'node', '--chain', network['chain'],
                 '--datadir', HOME + '/execution', '--minimal', '--disable-discovery']
    if policy['execution_peers']:
        execution += ['--trusted-peers', ','.join(policy['execution_peers']), '--tx-propagation-policy', 'Trusted']
    else:
        execution += ['--arc.tx.relays', ','.join(endpoint['http'] for endpoint in network['follow'])]
    execution += ['--ipcpath', ENGINE_RUN + '/reth.ipc', '--ipc.permissions', '0o660',
                  '--auth-ipc', '--auth-ipc.path', ENGINE_RUN + '/auth.ipc', '--enable-arc-rpc',
                  '--metrics', metrics + ':9001', '--log.file.max-files', '0']
    consensus = [native + '/arc-node-consensus', 'start', '--home', HOME + '/consensus', '--minimal',
                 '--private-key', '/run/credentials/' + UNITS['consensus'] + '/arc-validator-key',
                 '--moniker', 'erpc-arc-validator', '--eth-socket', ENGINE_RUN + '/reth.ipc',
                 '--execution-socket', ENGINE_RUN + '/auth.ipc', '--rpc.addr', '127.0.0.1:31000',
                 '--execution-persistence-backpressure', '--execution-persistence-backpressure-threshold=16',
                 '--metrics', metrics + ':29000']
    if policy['sentry_peers']:
        consensus += ['--p2p.persistent-peers', ','.join(policy['sentry_peers']), '--p2p.persistent-peers-only']
        consensus += ['--no-consensus']
    else:
        require(policy['phase'] == 'observer', 'validator activation requires approved sentries')
        consensus += ['--follow']
        for endpoint in network['follow']:
            consensus += ['--follow.endpoint', endpoint['http'] + ',wss=' + endpoint['ws']]
    bootstrap = [native + '/arc-snapshots', 'download', '--chain', network['chain'], '--el-profile', 'minimal',
                 '--execution-path', HOME + '/bootstrap/execution', '--consensus-path', HOME + '/bootstrap/consensus']
    runtime, units = {}, {}
    for component, args in {'execution': execution, 'consensus': consensus, 'bootstrap': bootstrap}.items():
        require(all(isinstance(arg, str) and arg and not any(char.isspace() or char in '%"\\' for char in arg)
                    for arg in args), 'unsafe Arc validator native argument')
        image = args[0].rsplit('/', 1)[1]
        runtime[component] = {'binary': args[0], 'sha256': source['images'][image], 'argv': args}
        number = state['accounts']['consensus' if component == 'consensus' else 'execution']
        # The EL's primary group owns Engine IPC sockets. The containing directory
        # gives the CL traversal only, so CL cannot replace/rebind those paths.
        gid = state['accounts']['engine'] if component == 'execution' else number
        lines = ['# Managed original Arc validator authority', '[Unit]',
                 'Description=Arc validator ' + component, 'After=network-online.target',
                 'Wants=network-online.target', 'StartLimitIntervalSec=0']
        if component != 'bootstrap':
            lines += ['Requires=erpc-arc-validator-firewall.service', 'After=erpc-arc-validator-firewall.service']
        if component == 'consensus':
            lines += ['Requires=' + UNITS['execution'], 'After=' + UNITS['execution']]
        lines += ['[Service]', 'Type=' + ('oneshot' if component == 'bootstrap' else 'simple'),
                  'User=' + str(number), 'Group=' + str(gid),
                  'SupplementaryGroups=' + str(number) + ' ' + str(state['accounts']['engine']),
                  'LimitCORE=0', 'UMask=' + ('0007' if component == 'execution' else '0077'),
                  'ExecCondition=+' + helpers.systemd_command(folder, helper_hash, 'condition', component),
                  'ExecStartPre=+' + helpers.systemd_command(folder, helper_hash, 'guard', component),
                  'WorkingDirectory=' + HOME, 'Environment=RUST_LOG=info']
        if component == 'execution':
            lines += ['RuntimeDirectory=erpc-arc-validator-engine', 'RuntimeDirectoryMode=0710',
                      'RuntimeDirectoryPreserve=restart', 'SuccessExitStatus=143']
        if component == 'consensus':
            lines += ['LoadCredentialEncrypted=arc-validator-key:' + ROOT + '/consensus-key.cred']
        if component == 'bootstrap':
            lines += ['Environment=ARC_EXECUTION_BINARY=' + native + '/arc-node-execution',
                      'ExecStartPost=+' + helpers.systemd_command(folder, helper_hash, 'bootstrap-complete', component),
                      'TimeoutStartSec=infinity']
        lines += ['ExecStart=' + ' '.join(args), 'KillMode=control-group', 'KillSignal=SIGTERM',
                  'SendSIGKILL=no', 'TimeoutStopSec=300', 'LimitNOFILE=1048576',
                  'StandardOutput=journal', 'StandardError=journal', 'SyslogIdentifier=arc-validator-' + component,
                  'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
                  'ReadWritePaths=' + HOME + '/' + component + ' ' + ROOT + ' -' + ENGINE_RUN,
                  'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectKernelTunables=yes',
                  'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectControlGroups=yes',
                  'ProtectClock=yes', 'ProtectHostname=yes', 'RestrictSUIDSGID=yes',
                  'RestrictNamespaces=yes', 'RestrictRealtime=yes', 'LockPersonality=yes',
                  'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', 'CapabilityBoundingSet=',
                  'SystemCallArchitectures=native']
        if component != 'bootstrap':
            lines += ['Restart=on-failure', 'RestartSec=10', '[Install]', 'WantedBy=multi-user.target']
        units[component] = '\n'.join(lines) + '\n'
    return units, runtime

def record_name(sha):
    require(isinstance(sha, str) and len(sha) == 64 and all(ch in '0123456789abcdef' for ch in sha),
            'invalid original Arc unit digest')
    return '/etc/erpc/arc-validator/authority/units/' + sha + '.json'


def publish(c, state, units, runtime, target):
    require(set(units) == set(UNITS) and set(runtime) == set(UNITS), 'incomplete Arc native unit set')
    c.mkdir('/etc/erpc/arc-validator/authority/units')
    hashes = {}
    for component, text in units.items():
        sha = digest(text.encode())
        receipt = {'contract': state['contract'], 'component': component, 'sha256': sha,
                   'text': text, 'runtime': runtime, 'source': target}
        location = record_name(sha)
        if c.protected(location, missing=True).exists():
            require(c.json(location) == receipt, 'original Arc unit receipt differs')
        c.write(location, receipt)
        hashes[component] = sha
    # Retain every previous receipt: an interrupted publication must still be stoppable.
    state['units'], state['runtime'], state['source'] = hashes, runtime, target
    c.save(state)
    c.sync(c.ROOT)
    for component, text in units.items():
        c.write_bytes('/etc/systemd/system/' + UNITS[component], text.encode(), 0o644)
    c.command('/usr/bin/systemctl', 'daemon-reload')


def proof(c, state, component, historical=False):
    require(component in UNITS, 'unknown Arc component')
    raw = c.read('/etc/systemd/system/' + UNITS[component])
    sha = digest(raw)
    receipt = c.json(record_name(sha), private=True)
    require(receipt.get('contract') == state['contract'] and receipt.get('component') == component and
            receipt.get('sha256') == sha and receipt.get('text', '').encode() == raw,
            'Arc unit is not an original definition')
    if not historical:
        require(state.get('units', {}).get(component) == sha,
                'old Arc unit may be stopped but cannot start')
    return av_loaded.proof(c, state, receipt, UNITS[component])


def publish_firewall(c, state, text):
    sha = digest(text.encode())
    c.mkdir(ROOT + '/units')
    receipt = {'contract': state['contract'], 'component': 'firewall', 'text': text,
               'sha256': sha, 'runtime': {}}
    c.write(record_name(sha), receipt)
    state['firewall_unit'] = sha
    c.save(state)
    c.write_bytes('/etc/systemd/system/erpc-arc-validator-firewall.service', text.encode(), 0o644)


def firewall_proof(c, state):
    unit = 'erpc-arc-validator-firewall.service'
    raw = c.read('/etc/systemd/system/' + unit)
    sha = digest(raw)
    receipt = c.json(record_name(sha), private=True)
    require(state.get('firewall_unit') == sha and receipt.get('contract') == state['contract'] and
            receipt.get('component') == 'firewall' and receipt.get('text', '').encode() == raw and
            receipt.get('sha256') == sha, 'original firewall unit receipt differs')
    return av_loaded.proof(c, state, receipt, unit, firewall=True)


def historical_runtimes(c, state):
    folder = c.protected('/etc/erpc/arc-validator/authority/units', missing=True, directory=True)
    if not folder.exists():
        return []
    result = []
    for path in folder.iterdir():
        require(path.name.endswith('.json') or path.name.endswith('.json.pending'), 'unknown Arc unit receipt')
        if path.name.endswith('.pending'):
            continue
        receipt = c.json('/etc/erpc/arc-validator/authority/units/' + path.name, private=True)
        require(receipt.get('contract') == state['contract'] and
                digest(receipt['text'].encode()) == receipt['sha256'] and path.name == receipt['sha256'] + '.json',
                'original Arc shutdown authority changed')
        result.append(receipt['runtime'])
    return result
