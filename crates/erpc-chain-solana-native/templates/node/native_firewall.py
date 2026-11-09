# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Short policy application, followed by confirmation over a fresh SSH session."""
import hashlib
import contextlib
import io
import ipaddress
from pathlib import Path
import re
import runpy
import stat
from native_files import atomic, read, require, root_directory, sync_file, sync_directory
from native_entrypoint import runtime_command
from native_state import token
import native_helpers as helpers

HELPER = Path('/usr/local/lib/erpc/rpc-firewall.py')
DIRECTORY = Path('/etc/erpc/solana-native')
UNIT = Path('/etc/systemd/system/erpc-solana-native-firewall.service')
SOURCE = Path(__file__).absolute().parent.parent
NAMES = {'pending.json', 'confirmed.json', 'pending.nft', 'firewall.nft', 'previous.nft',
         'startup-revoked'}


def access(value, rpc):
    require(isinstance(value, dict) and set(value) == {'controller', 'ssh_port', 'management', 'rpc'},
            'invalid native access policy fields')
    controller = ipaddress.ip_address(value['controller'])
    require(str(controller) == value['controller'] and not controller.is_unspecified
            and not controller.is_multicast, 'invalid observed SSH controller address')
    port = value['ssh_port']
    require(type(port) is int and 1 <= port <= 65535
            and port not in (7211, 7212, 8899, 8900) and not 8000 <= port <= 8032,
            'SSH port conflicts with the native node profile')
    for name in ('management', 'rpc'):
        values = value[name]
        require(isinstance(values, list) and len(values) <= 64
                and all(isinstance(item, str) for item in values)
                and len(set(values)) == len(values), 'invalid native access list')
        for item in values:
            network = ipaddress.ip_network(item, strict=True)
            minimum = 8 if network.version == 4 else 32
            require(str(network) == item and network.prefixlen >= minimum
                    and not network.network_address.is_unspecified
                    and not network.network_address.is_multicast
                    and (network.version == 4 or network.network_address.ipv4_mapped is None),
                    'invalid native client network')
    require(rpc or not value['rpc'], 'validator profile cannot publish RPC ingress')
    return value


def policy(value, rpc):
    value = access(value, rpc)
    rules = ['table inet erpc_solana_native {', ' chain input {',
             '  type filter hook input priority -10; policy accept;',
             '  iifname "lo" accept', '  ct state established,related accept']
    for address in [value['controller'], *value['management']]:
        family = 'ip6' if ':' in address else 'ip'
        rules.append(f'  {family} saddr {address} tcp dport {value["ssh_port"]} accept')
    rules.append(f'  tcp dport {value["ssh_port"]} drop')
    rules.append('  tcp dport { 8899, 8900 } drop')
    for address in value['rpc']:
        family = 'ip6' if ':' in address else 'ip'
        rules.append(f'  {family} saddr {address} tcp dport {{ 7211, 7212 }} accept')
    rules.extend(['  tcp dport { 7211, 7212 } drop', '  tcp dport 8000-8032 accept',
                  '  udp dport 8000-8032 accept', ' }', '}', ''])
    # Add/create the owned table, then replace only that table. Other host policy
    # and its ordering remain visible to the operator; no global ruleset flush.
    return ('table inet erpc_solana_native\ndelete table inet erpc_solana_native\n'
            + '\n'.join(rules)).encode()


def protected_state(create=False):
    root_directory(DIRECTORY, create=create, mode=0o700)
    require(DIRECTORY.lstat().st_mode & 0o7777 == 0o700, 'native firewall state is not private')
    for path in DIRECTORY.iterdir():
        require(path.name in NAMES or (path.name.endswith('.new') and path.name[:-4] in NAMES),
                'unknown native firewall state file')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o7777 == 0o600,
                'native firewall state file has unsafe type or mode')
        read(path)


def installed(state, contract):
    state.owner(contract)
    authority = state.get('firewall-authority.json')
    require(set(authority) == {'contract', 'helper_sha256', 'unit_sha256', 'previous_unit_sha256'}
            and authority['contract'] == contract, 'native firewall authority differs')
    for path, key in [(HELPER, 'helper_sha256'), (UNIT, 'unit_sha256')]:
        root_directory(path.parent)
        require(hashlib.sha256(read(path)).hexdigest() == authority[key], 'native firewall installation changed')
    override = UNIT.with_name(UNIT.name + '.d')
    if override.exists() or override.is_symlink():
        root_directory(override)
        require(not any(override.iterdir()), 'native firewall has an unknown override')
    protected_state()
    return runpy.run_path(str(HELPER), run_name='erpc_native_firewall')['Firewall']('solana-native')


def prepare(state, contract, request, run):
    require(set(request) == {'action', 'contract', 'intent', 'access', 'source_sha256'}
            and request['action'] == 'firewall-prepare' and request['contract'] == contract,
            'invalid native firewall preparation')
    intent = token(request['intent']); operation = state.current(contract, intent)
    # A policy rollback can stop every fixed listener. Establish ownership before
    # adding guards or arming that rollback, even on the first deployment.
    owned = {'erpc-solana.service': [], 'erpc-solana-gateway.service': []}
    for name in ('active.json', 'runtime-install.json', 'gateway-install.json'):
        if (state.directory / name).exists():
            value = state.get(name)
            if name == 'gateway-install.json':
                require(value['contract'] == contract, 'ingress installation belongs to another host')
                owned['erpc-solana-gateway.service'].append(value['receipt']['unit_sha256'])
            else:
                owned['erpc-solana.service'].append(value['receipt']['unit_sha256'])
                gateway = value['receipt'].get('gateway')
                if gateway is not None: owned['erpc-solana-gateway.service'].append(gateway['unit_sha256'])
    for name, digests in owned.items():
        path = UNIT.parent / name
        if path.exists() or path.is_symlink():
            root_directory(path.parent)
            require(hashlib.sha256(read(path)).hexdigest() in digests,
                    'firewall cannot adopt or fence an unknown listener service')
        else:
            require(run(['/usr/bin/systemctl', 'show', name, '--property=LoadState', '--value'],
                        allowed=(0, 1)).strip() == 'not-found',
                    'firewall listener remains loaded without its original file')
    value = access(request['access'], contract['profile'] == 'agave-native-rpc')
    digest = request['source_sha256']
    require(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest), 'invalid firewall source digest')
    root_directory(SOURCE)
    raw = read(SOURCE / 'rpc-firewall.py')
    require(hashlib.sha256(raw).hexdigest() == digest, 'carried firewall source differs')
    revision = operation['target']['helper_revision']
    helpers.verify(revision)
    command = runtime_command(helpers.RELEASES / revision / 'native_runtime_control.py')
    unit = ('[Unit]\nDescription=ERPC native Solana verified access policy\nBefore=erpc-solana.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=' + command + ' firewall-load\n'
            '[Install]\nWantedBy=multi-user.target\n').encode()
    authority = {'contract': contract, 'helper_sha256': digest, 'unit_sha256': hashlib.sha256(unit).hexdigest(),
                 'previous_unit_sha256': None}
    root_directory(HELPER.parent, create=True); root_directory(UNIT.parent)
    if (state.directory / 'firewall-authority.json').exists():
        previous = state.get('firewall-authority.json')
        require(previous['contract'] == contract, 'native firewall belongs to another host')
        authority['previous_unit_sha256'] = (previous['previous_unit_sha256']
            if previous['unit_sha256'] == authority['unit_sha256'] else previous['unit_sha256'])
    else: previous = None
    for path, key in [(HELPER, 'helper_sha256'), (UNIT, 'unit_sha256')]:
        if path.exists() or path.is_symlink():
            actual = hashlib.sha256(read(path)).hexdigest()
            # The shared, already protected helper can predate this dedicated
            # profile. A pre-existing boot unit needs its original receipt.
            require(path == HELPER or (previous is not None
                    and actual in (previous[key], previous['previous_unit_sha256'])),
                    'unknown native firewall boot unit')
    override = UNIT.with_name(UNIT.name + '.d')
    if override.exists() or override.is_symlink():
        root_directory(override); require(not any(override.iterdir()), 'native firewall has an unknown override')
    protected_state(create=True)
    preparation = {'contract': contract, 'intent': intent, 'access': value, 'source_sha256': digest,
                   'helper_revision': revision}
    name = 'firewall-preparation-' + intent + '.json'
    if (state.directory / name).exists():
        require(state.get(name) == preparation, 'resume the original firewall policy before changing it')
    else: state.put(name, preparation)
    sync_file(state.directory / name); sync_directory(state.directory)
    state.put('firewall-authority.json', authority)
    atomic(HELPER, raw, 0o700); atomic(UNIT, unit, 0o644)
    atomic(SOURCE / 'firewall-candidate.nft', policy(value, contract['profile'] == 'agave-native-rpc'))
    run(['/usr/sbin/nft', '-c', '-f', str(SOURCE / 'firewall-candidate.nft')])
    operation_root = SOURCE.parent
    archive = read(operation_root / 'bundle.tar.gz', 32 * 1024 * 1024)
    archive_digest = hashlib.sha256(archive).hexdigest()
    installed(state, contract).dispatch('apply', operation_root.name, archive_digest)
    state.current(contract, intent)
    run(['/usr/bin/systemctl', 'daemon-reload'])
    run(['/usr/bin/systemctl', 'enable', UNIT.name])
    return {'run': operation_root.name, 'bundle': archive_digest, 'confirmation_required': True}


def confirm(state, contract, request):
    require(set(request) == {'action', 'contract', 'intent', 'run', 'bundle'}
            and request['action'] == 'firewall-confirm' and request['contract'] == contract,
            'invalid native firewall confirmation')
    state.current(contract, token(request['intent']))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        installed(state, contract).dispatch('confirm', request['run'], request['bundle'])
    require(output.getvalue() == 'firewall=confirmed\n', 'unexpected native firewall confirmation result')
    state.current(contract, request['intent'])
    return {'firewall_confirmed': True, 'run': request['run'], 'bundle': request['bundle']}
