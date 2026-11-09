#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric credential recipients; historical units authorize shutdown only."""
import os
from arc_files import digest, encoded, require
import arc_helpers as helpers
import arc_protocol as protocol
import arc_release as release
from arc_process import UNITS


def make(c, state, target, policy, folder, helper_hash):
    source = release.qualify(c, target)
    protocol.policy(policy, state['contract'])
    network = protocol.NETWORKS[state['contract']['network']]
    home = '/var/lib/arc'
    native = release.directory(target)
    public = '0.0.0.0' if policy['rpc_allow'] else '127.0.0.1'
    metrics = '0.0.0.0' if policy['monitoring_allow'] else '127.0.0.1'
    pruned = state['contract']['rpc_type'] != 'archive'
    provider = state['contract']['rpc_type'] == 'provider'
    api = 'eth,net,web3,rpc' + (',debug,trace' if policy['debug_api'] else '')
    execution = [native + '/arc-node-execution', 'node', '--chain', network['chain'],
                 '--datadir', home + '/execution']
    if pruned:
        execution += ['--full']
    execution += (['--trusted-peers', ','.join(policy['trusted_peers']), '--tx-propagation-policy', 'Trusted']
                  if provider else ['--disable-discovery', '--arc.tx.relays', ','.join(endpoint['http'] for endpoint in network['follow'])])
    execution += ['--ipcpath', '/run/arc/reth.ipc', '--auth-ipc', '--auth-ipc.path', '/run/arc/auth.ipc',
                  '--http', '--http.addr', public, '--http.port', '8545', '--http.api', api,
                  '--ws', '--ws.addr', public, '--ws.port', '8546', '--ws.api', api,
                  '--public-api', '--metrics', metrics + ':9001', '--log.file.max-files', '0', '--enable-arc-rpc']
    consensus = [native + '/arc-node-consensus', 'start', '--home', home + '/consensus',
                 '--private-key', '/run/credentials/arc-consensus.service/consensus-key']
    if pruned:
        consensus += ['--full']
    consensus += ['--eth-socket', '/run/arc/reth.ipc', '--execution-socket', '/run/arc/auth.ipc',
                  '--rpc.addr', '127.0.0.1:31000']
    if provider:
        consensus += ['--p2p.persistent-peers', ','.join(policy['sentry_peers']),
                      '--p2p.persistent-peers-only', '--no-consensus']
    else:
        consensus += ['--follow']
        for endpoint in network['follow']:
            consensus += ['--follow.endpoint', endpoint['http'] + ',wss=' + endpoint['ws']]
    consensus += ['--execution-persistence-backpressure', '--execution-persistence-backpressure-threshold=16',
                  '--metrics', metrics + ':29000']
    snapshot = [native + '/arc-snapshots', 'download', '--chain', network['chain'],
                '--el-profile', 'full' if pruned else 'archive',
                '--execution-path', home + '/bootstrap/execution', '--consensus-path', home + '/bootstrap/consensus']
    argv = {'execution': execution, 'consensus': consensus, 'snapshots': snapshot}
    runtime, units = {}, {}
    for component, args in argv.items():
        image = args[0].rsplit('/', 1)[1]
        require(all(isinstance(arg, str) and arg and not any(char.isspace() or char in '%"\\' for char in arg)
                    for arg in args), 'unsafe Arc unit argument')
        runtime[component] = {'binary': args[0], 'sha256': source['images'][image], 'argv': args}
        startup = helpers.systemd_command(folder, helper_hash, 'condition', component)
        guard = helpers.systemd_command(folder, helper_hash, 'guard', component)
        lines = ['# Managed original Arc authority', '[Unit]', 'Description=Arc original ' + component,
                 'After=network-online.target', 'Wants=network-online.target', 'StartLimitIntervalSec=0']
        if component != 'snapshots':
            lines += ['Requires=erpc-arc-firewall.service', 'After=erpc-arc-firewall.service']
        if component == 'consensus':
            lines += ['Requires=arc-execution.service', 'After=arc-execution.service']
        lines += ['[Service]', 'Type=' + ('oneshot' if component == 'snapshots' else 'simple'),
                  'User=' + str(state['service_uid']), 'Group=' + str(state['service_gid']),
                  'SupplementaryGroups=', 'LimitCORE=0', 'UMask=0077',
                  'ExecCondition=+' + startup, 'ExecStartPre=+' + guard,
                  'WorkingDirectory=' + home, 'Environment=RUST_LOG=info']
        if component == 'execution':
            lines += ['RuntimeDirectory=arc', 'RuntimeDirectoryMode=0700', 'RuntimeDirectoryPreserve=restart']
        if component == 'consensus':
            lines += ['LoadCredentialEncrypted=consensus-key:/etc/credstore.encrypted/arc-consensus-key']
        if component == 'snapshots':
            lines += ['Environment=ARC_EXECUTION_BINARY=' + native + '/arc-node-execution',
                      'ExecStartPost=+' + helpers.systemd_command(folder, helper_hash, 'snapshot-complete', component),
                      'TimeoutStartSec=infinity']
        lines += ['ExecStart=' + ' '.join(args), 'KillMode=control-group', 'KillSignal=SIGTERM',
                  'SendSIGKILL=no', 'TimeoutStopSec=300', 'LimitNOFILE=1048576',
                  'StandardOutput=journal', 'StandardError=journal', 'SyslogIdentifier=arc-' + component]
        if component != 'snapshots':
            lines += ['Restart=on-failure', 'RestartSec=10']
        if component == 'execution':
            lines += ['SuccessExitStatus=143']
        writable = home + ('/bootstrap' if component == 'snapshots' else '/' + component)
        lines += ['NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
                  'ReadWritePaths=' + writable + ' /etc/erpc/arc/authority -/run/arc',
                  'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectKernelTunables=yes',
                  'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectControlGroups=yes',
                  'ProtectClock=yes', 'ProtectHostname=yes', 'RestrictSUIDSGID=yes',
                  'RestrictNamespaces=yes', 'RestrictRealtime=yes', 'LockPersonality=yes',
                  'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', 'CapabilityBoundingSet=',
                  'SystemCallArchitectures=native']
        if component != 'snapshots':
            lines += ['[Install]', 'WantedBy=multi-user.target']
        units[component] = '\n'.join(lines) + '\n'
    return units, runtime


def record_name(sha):
    require(isinstance(sha, str) and len(sha) == 64 and all(ch in '0123456789abcdef' for ch in sha),
            'invalid original Arc unit digest')
    return '/etc/erpc/arc/authority/units/' + sha + '.json'


def publish(c, state, units, runtime, target):
    require(set(units) == set(UNITS) and set(runtime) == set(UNITS), 'incomplete Arc native unit set')
    c.mkdir('/etc/erpc/arc/authority/units')
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
    return receipt


def historical_runtimes(c, state):
    folder = c.protected('/etc/erpc/arc/authority/units', missing=True, directory=True)
    if not folder.exists():
        return []
    result = []
    for path in folder.iterdir():
        require(path.name.endswith('.json') or path.name.endswith('.json.pending'), 'unknown Arc unit receipt')
        if path.name.endswith('.pending'):
            continue
        receipt = c.json('/etc/erpc/arc/authority/units/' + path.name, private=True)
        require(receipt.get('contract') == state['contract'] and
                digest(receipt['text'].encode()) == receipt['sha256'] and path.name == receipt['sha256'] + '.json',
                'original Arc shutdown authority changed')
        result.append(receipt['runtime'])
    return result
