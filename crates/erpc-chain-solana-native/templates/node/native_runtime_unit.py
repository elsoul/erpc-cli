# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed native invocation and service policy, selected from the carried catalog."""
from pathlib import Path
import re
from native_contract import KEYS, MOUNTS, public_key, validate
from native_entrypoint import runtime_command
from native_files import require
from native_state import token

UNIT = 'erpc-solana.service'
UNITS = Path('/etc/systemd/system')
RELEASES = Path('/opt/erpc/solana/releases')
HELPERS = Path('/usr/local/lib/erpc/solana-native/releases')
CUSTODY = Path('/var/lib/erpc-solana/custody')
CREDENTIAL = Path('/run/credentials') / UNIT / 'identity'
# Both pinned releases require a range width >=26. The older documentation's
# 8000-8020 example is too narrow; this bounded ERPC profile uses 32 ports.
PORT_RANGE = '8000-8032'


def arguments(contract, catalog, build_intent, mode, identity, migration=None):
    validate(contract); token(build_intent); public_key(identity)
    require(mode in ('sync', 'validator', 'rpc')
            and (mode == 'rpc') == (contract['profile'] == 'agave-native-rpc'),
            'unsupported native runtime mode or role transition')
    profile = catalog['networks'][contract['network']]
    require(mode not in ('validator', 'rpc') or identity == contract['identity_account'],
            'native runtime must use the original identity')
    require(mode != 'sync' or identity not in [contract[name] for name in KEYS],
            'synchronization cannot load a registered or financial identity')
    validators = profile['known_validators']
    require(isinstance(validators, list) and validators and len(validators) <= 16
            and len(set(validators)) == len(validators), 'invalid qualified bootstrap identities')
    for key in validators: public_key(key)
    require(identity not in validators, 'runtime identity conflicts with a bootstrap validator')
    entrypoints = profile['entrypoints']
    require(isinstance(entrypoints, list) and entrypoints and len(entrypoints) <= 8
            and len(set(entrypoints)) == len(entrypoints), 'invalid qualified gossip rendezvous')
    suffix = 'mainnet-beta' if contract['network'] == 'mainnet' else 'testnet'
    require(all(isinstance(value, str) and re.fullmatch(r'entrypoint[2-5]?\.' + suffix + r'\.solana\.com:8001', value)
                for value in entrypoints), 'gossip rendezvous differs from the fixed network')
    binary = RELEASES / build_intent / 'bin/agave-validator'
    argv = [str(binary), '--identity', str(CREDENTIAL), '--ledger', str(MOUNTS['ledger'] / 'data'),
            '--accounts', str(MOUNTS['accounts'] / 'data'), '--snapshots', str(MOUNTS['snapshots'] / 'data'),
            '--tower', str(MOUNTS['ledger'] / 'data'), '--log', '-', '--no-xdp',
            '--gossip-port', '8001', '--dynamic-port-range', PORT_RANGE,
            '--rpc-port', '8899', '--rpc-bind-address', '127.0.0.1', '--private-rpc', '--full-rpc-api',
            '--only-known-rpc', '--expected-genesis-hash', public_key(profile['genesis']),
            '--limit-blockstore-size']
    for value in entrypoints: argv.extend(['--entrypoint', value])
    for value in validators: argv.extend(['--known-validator', value])
    if mode in ('sync', 'rpc'):
        argv.append('--no-voting')
        if mode == 'rpc': argv.extend(['--enable-rpc-transaction-history', '--enable-extended-tx-metadata-storage'])
    else:
        # Both native pins restore Tower and signed vote history in
        # ProcessBlockStore.process(). Complete this before starting services;
        # native first-account exceptions remain the client's responsibility.
        # Never supply a vote-history bypass flag.
        argv.extend(['--vote-account', contract['vote_account'], '--require-tower',
                     '--process-ledger-before-services'])
    if migration is not None:
        import native_migration_settings as settings
        settings.checked(migration)
        argv.remove('--limit-blockstore-size')
        argv.extend(migration['arguments'])
        if migration['overrides'] is not None:
            argv.extend(['--staked-nodes-overrides', str(settings.OVERRIDES)])
    require(all(re.fullmatch('[A-Za-z0-9/_.:=,-]+', value) for value in argv),
            'native invocation contains service expansion or shell syntax')
    return argv


def render(contract, catalog, build_intent, helper_revision, mode, identity, account, migration=None):
    require(isinstance(helper_revision, str) and re.fullmatch('[a-f0-9]{64}', helper_revision),
            'invalid native runtime helper revision')
    require(isinstance(account, dict) and set(account) == {'uid', 'gid'}
            and all(type(value) is int and 20000 <= value <= 60000 for value in account.values())
            and account['uid'] == account['gid'], 'invalid original native runtime account')
    argv = arguments(contract, catalog, build_intent, mode, identity, migration)
    helper = HELPERS / helper_revision / 'native_runtime_control.py'
    writable = ' '.join(str(path / 'data') for path in MOUNTS.values())
    mounts = ' '.join(str(path) for path in MOUNTS.values())
    ingress = 'Wants=erpc-solana-gateway.service\n' if mode == 'rpc' else ''
    startup = 'TimeoutStartSec=180\n' if mode == 'validator' else ''
    # In qualified systemd v255, the first ExecCondition has no
    # EXEC_WRITE_CREDENTIALS flag; ExecStartPre does. Validate original NSS
    # authority there before any plaintext grant, then recheck before exec.
    # Numeric recipients also prevent a later name-to-different-UID lookup
    # from redirecting credentials. This cannot prevent an administrator from
    # reassigning the original numeric UID itself after authentication.
    return f'''[Unit]
Description=ERPC isolated native Solana runtime
Requires=erpc-solana-native-firewall.service
After=network-online.target erpc-solana-native-firewall.service
Wants=network-online.target
{ingress}RequiresMountsFor={mounts}
[Service]
Type=exec
{startup}User={account['uid']}
Group={account['gid']}
WorkingDirectory=/var/lib/erpc-solana
LoadCredentialEncrypted=identity:{CUSTODY / (mode + '.cred')}
ExecCondition=+{runtime_command(helper)} condition
ExecStartPre=+{runtime_command(helper)} guard
ExecStart={' '.join(argv)}
KillMode=control-group
KillSignal=SIGTERM
SendSIGKILL=no
TimeoutStopSec=1800
Restart=on-failure
RestartSec=30
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
ReadWritePaths={writable}
LimitNOFILE=1000000
LimitMEMLOCK=infinity
LimitNICE=-20
LimitCORE=0
TasksMax=16384
[Install]
WantedBy=multi-user.target
'''
