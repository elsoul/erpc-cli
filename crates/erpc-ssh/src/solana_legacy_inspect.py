# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only legacy evidence. Never execute a legacy unit, script or key tool."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path('/')
GENESIS = {'mainnet': '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
           'testnet': '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY'}
PUBLIC = r'[1-9A-HJ-NP-Za-km-z]{32,44}'
HASH = r'[a-f0-9]{64}'
BUS_OBJECT = '/org/freedesktop/systemd1/unit/solv_2eservice'
EXEC_PROPERTIES = ('ExecStartEx', 'ExecStartPreEx', 'ExecStartPostEx', 'ExecConditionEx',
                   'ExecReloadEx', 'ExecStopEx', 'ExecStopPostEx')
SERVICE_PROPERTIES = ('LoadState', 'FragmentPath', 'DropInPaths', 'Type', 'User', 'Group', 'WorkingDirectory',
                      'MainPID', 'ControlPID', 'ActiveState', 'SubState', 'NeedDaemonReload',
                      'InvocationID', 'ControlGroup')
# Loaded declarations from the carried managed templates. Hashes avoid exporting
# even their public metrics-password strings through an inspection response.
ENVIRONMENT_SHA256 = {'mainnet': '77451a7aa13062f94189d995e9e30063cd2ce65b9b5edc4533adf2a7b2f7bd02',
                      'testnet': '612374c594a7a38b20cbfa5b7090697026f6b24aee10075e56fa0ab0d6795bd7'}
POLICY_PROPERTIES = {
    'Environment': ('as', None), 'EnvironmentFiles': ('a(sb)', []),
    'PassEnvironment': ('as', []), 'UnsetEnvironment': ('as', []),
    'ExecSearchPath': ('as', []), 'SupplementaryGroups': ('as', []),
    'RootDirectory': ('s', ''), 'RootImage': ('s', ''), 'PAMName': ('s', ''),
    'DynamicUser': ('b', False), 'PrivateNetwork': ('b', False),
    'PrivateUsers': ('b', False), 'PrivateMounts': ('b', False),
    'Restart': ('s', 'always'), 'RestartMode': ('s', 'normal'),
    'RestartUSec': ('t', 1000000), 'ExitType': ('s', 'main'),
    # systemd v255 dbus-kill.c/kill.c and dbus-service.c; Ubuntu's
    # standard 90-second stop budget, never an arbitrary root-owned hook.
    'KillMode': ('s', 'control-group'), 'KillSignal': ('i', 15),
    'RestartKillSignal': ('i', 15), 'FinalKillSignal': ('i', 9),
    'SendSIGKILL': ('b', True), 'SendSIGHUP': ('b', False),
    'TimeoutStopUSec': ('t', 90000000), 'TimeoutStopFailureMode': ('s', 'terminate'),
    'WatchdogUSec': ('t', 0), 'WatchdogSignal': ('i', 6),
}
DATA_PATHS = {'accounts': '/mnt/accounts', 'ledger': '/mnt/ledger', 'snapshots': '/mnt/snapshot'}
TARGET_PATHS = {kind: '/mnt/erpc-solana-' + kind for kind in DATA_PATHS}
# Conservative ERPC capacity policy: count logical bytes including repeated hard
# links, and keep 64 GiB free. A live estimate is not a stopped-copy authorization.
COPY_HEADROOM = 64 * 1024**3
TARGET_MINIMUM = {'accounts': 900_000_000_000, 'ledger': 900_000_000_000, 'snapshots': 450_000_000_000}
UUID = r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}'
# Exact carried common firewall48 external-entry program and managed drop-ins.
# A source-composition regression rederives these digests from rpc-firewall.py.
FIREWALL_PROGRAM = '4237ef2ab982581e89e64562f87a79d1fdeb6594b6f24bf54a26aba21530666f'
FIREWALL_DROPINS = ('ea4e7a3158c08b503593b8249392dcc8593b2c533b920ccdf39d7db574efacb2',
                    '66dcf83d4cca31ff8d053e505b095934eefa3d9f9fb61d1aede431a6fc5f5de4')
DROPIN = '/etc/systemd/system/solv.service.d/50-erpc-firewall-guard.conf'



def require(ok, message):
    if not ok: raise ValueError(message)


def unique(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate request field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(request):
    require(isinstance(request, dict) and set(request) - {'target_volumes','artifact_evidence','settings_sha256','host_identity','keygen_evidence','commission'} == {
        'network', 'role', 'identity_account', 'vote_account', 'historical',
        'management_user', 'source_sha256', 'source_history'}, 'invalid legacy inspection fields')
    require(request['network'] in GENESIS and request['role'] in ('rpc', 'validator'),
            'unsupported legacy network or role')
    require(isinstance(request['identity_account'], str) and re.fullmatch(PUBLIC, request['identity_account']),
            'invalid original public identity')
    require(request['vote_account'] is None or isinstance(request['vote_account'], str)
            and re.fullmatch(PUBLIC, request['vote_account']), 'invalid original vote account')
    require(request['role'] != 'rpc' or request['vote_account'] is None, 'RPC cannot select a vote account')
    require(isinstance(request['management_user'], str)
            and re.fullmatch('[a-z][a-z0-9_-]{0,31}', request['management_user'])
            and request['management_user'] not in ('root', 'solv'), 'a separate nonroot management login is required')
    require(isinstance(request['source_sha256'], str) and re.fullmatch(HASH, request['source_sha256']),
            'invalid public source binding')
    if 'settings_sha256' in request:
        require(isinstance(request['settings_sha256'],str) and re.fullmatch(HASH,request['settings_sha256']),
                'invalid original settings binding')
    history = request['source_history']
    require(isinstance(history, dict) and set(history) == {'document_sha256', 'highest'}
            and isinstance(history['document_sha256'], str) and re.fullmatch(HASH, history['document_sha256'])
            and isinstance(history['highest'], dict) and set(history['highest']) == {'version', 'commit'},
            'invalid original source-history evidence')
    highest = history['highest']
    require(isinstance(highest['version'], str) and len(highest['version']) <= 128
            and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', highest['version'])
            and isinstance(highest['commit'], str) and re.fullmatch('[a-f0-9]{40}', highest['commit']),
            'original source history lacks a canonical version or commit')
    for field, maximum in (('artifact_evidence',4*1024**3),('keygen_evidence',128*1024**2)):
        if field not in request:continue
        build=request[field]
        require(isinstance(build,dict) and set(build)=={'document_sha256','network','source','executable_sha256','executable_bytes'}
                and build['network']==request['network'] and isinstance(build['source'],dict)
                and set(build['source'])=={'version','commit','cargo_lock_sha256','rust','rust_manifest_sha256'},
                'independent original artifact evidence is incomplete')
        source=build['source']
        require(source.get('version')==highest['version'] and source.get('commit')==highest['commit']
                and isinstance(source.get('rust'),str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',source['rust'])
                and all(isinstance(value,str) and re.fullmatch(HASH,value) for value in
                    (build['document_sha256'],build['executable_sha256'],source['cargo_lock_sha256'],source['rust_manifest_sha256']))
                and build['executable_sha256']!='0'*64 and type(build['executable_bytes'])is int
                and 0<build['executable_bytes']<=maximum,'original build/source artifact fields are invalid')
    evidence = request['historical']
    require(isinstance(evidence, dict) and set(evidence) == {'uid', 'gid', 'machine_id_sha256', 'source'}
            and all(type(evidence[key]) is int and 0 < evidence[key] < 2**31 for key in ('uid', 'gid')),
            'invalid original numeric account evidence')
    require(isinstance(evidence['source'], dict) and set(evidence['source']) == {'passwd', 'group', 'machine_id'},
            'invalid historical source digests')
    require(all(isinstance(value, str) and re.fullmatch(HASH, value)
                for value in [evidence['machine_id_sha256'], *evidence['source'].values()]),
            'invalid historical digest')
    if 'target_volumes' in request:
        targets = request['target_volumes']
        require(isinstance(targets, dict) and set(targets) == set(DATA_PATHS)
                and all(isinstance(value, str) and re.fullmatch(UUID, value) for value in targets.values())
                and len(set(targets.values())) == 3, 'copy targets require three distinct canonical UUIDs')
    if 'commission' in request:
        require(request['commission'] is None if request['role']=='rpc' else type(request['commission'])is int and 0<=request['commission']<=100,
                'original commission policy is invalid')
    if 'host_identity' in request:
        key = request['host_identity']; rpc = request['role'] == 'rpc'
        require(isinstance(key,dict) and set(key)=={'role','path','uid','gid','inode','bytes','mtime_ns','public','bls_public'}
                and key['role']==('rpc' if rpc else 'sync')
                and key['path']==('/home/solv/rpc-identity.json' if rpc else '/home/solv/unstaked-identity.json')
                and key['uid']==evidence['uid'] and key['gid']==evidence['gid']
                and all(type(key[name])is int and key[name]>0 for name in ('uid','gid','inode','bytes','mtime_ns'))
                and key['bytes']<=4096 and isinstance(key['public'],str) and re.fullmatch(PUBLIC,key['public'])
                and (key['public']==request['identity_account'] if rpc else key['public']!=request['identity_account'])
                and key['public']!=request['vote_account'] and isinstance(key['bls_public'],str)
                and re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{1,66}',key['bls_public']), 'original host-only key descriptor differs')
    return evidence


def read_public(relative, uid=0, maximum=65536):
    path = ROOT / relative
    require(not relative.startswith('/') and '..' not in Path(relative).parts, 'invalid fixed inspection path')
    for parent in reversed(path.parents):
        info = parent.lstat()
        # The old runtime owns its home; all higher ancestors stay root-owned.
        allowed = (0, uid) if parent == ROOT / 'home/solv' else (0,)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and not info.st_mode & 0o022,
                'legacy inspection ancestor differs')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, uid)
                and before.st_nlink == 1 and not before.st_mode & 0o022,
                'legacy inspection file authority differs')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        require(len(raw) <= maximum and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'legacy public file changed during inspection')
        return raw


def accounts(request, evidence, management_uid=None):
    uid, gid = evidence['uid'], evidence['gid']
    users, groups = pwd.getpwall(), grp.getgrall()
    selected = [value for value in users if value.pw_name == 'solv' or value.pw_uid == uid]
    require(len(selected) == 1, 'original Solv user is absent or aliased')
    user = selected[0]
    require(user.pw_name == 'solv' and user.pw_uid == uid and user.pw_gid == gid
            and user.pw_dir == '/home/solv' and user.pw_shell == '/bin/bash'
            and pwd.getpwnam('solv') == user and pwd.getpwuid(uid) == user,
            'current Solv identity differs from original evidence')
    require(not any(value.pw_name != 'solv' and value.pw_gid == gid for value in users),
            'original Solv primary group is shared')
    selected = [value for value in groups if value.gr_name == 'solv' or value.gr_gid == gid]
    require(len(selected) == 1, 'original Solv group is absent or aliased')
    group = selected[0]
    require(group.gr_name == 'solv' and group.gr_gid == gid and set(group.gr_mem) <= {'solv'}
            and grp.getgrnam('solv') == group and grp.getgrgid(gid) == group,
            'current Solv group differs from original evidence')
    manager = pwd.getpwnam(request['management_user'])
    require(manager.pw_uid not in (0, uid) and manager.pw_gid != gid
            and pwd.getpwuid(manager.pw_uid) == manager
            and len([value for value in users if value.pw_uid == manager.pw_uid]) == 1
            and ((management_uid is None and os.environ.get('SUDO_USER') == manager.pw_name
                  and os.environ.get('SUDO_UID') == str(manager.pw_uid))
                 or type(management_uid) is int and management_uid == manager.pw_uid),
            'inspection did not use the separate original management login')
    machine = read_public('etc/machine-id', maximum=34).strip(b'\r\n')
    require(re.fullmatch(b'[a-f0-9]{32}', machine) and machine != b'0' * 32
            and digest(machine) == evidence['machine_id_sha256'], 'host differs from historical machine identity')
    return {'uid': uid, 'gid': gid, 'management_uid': manager.pw_uid,
            'machine_id_sha256': evidence['machine_id_sha256']}


def startup(raw, request):
    """Parse a restricted argv representation, never shell evaluation."""
    require(len(raw) <= 65536, 'legacy startup script is too large')
    text = raw.decode('utf-8')
    require(text.startswith('#!/bin/bash\n'), 'legacy startup shell differs')
    body = text.partition('\n')[2].replace('\\\n', ' ')
    words = body.split()
    require(words[:2] == ['exec', 'agave-validator'] and len(words) <= 512
            and all(re.fullmatch(r'[A-Za-z0-9/_.:=,+-]+', word) for word in words),
            'legacy startup uses unsupported shell expressions or client')
    singles = {'--no-voting', '--only-known-rpc', '--no-port-check', '--no-xdp', '--private-rpc',
               '--full-rpc-api', '--enable-rpc-transaction-history', '--enable-extended-tx-metadata-storage',
               '--require-tower', '--process-ledger-before-services', '--no-skip-initial-accounts-db-clean',
               '--no-wait-for-vote-to-start-leader'}
    values = {'--identity', '--vote-account', '--log', '--accounts', '--ledger', '--snapshots',
              '--tower', '--entrypoint', '--known-validator', '--staked-nodes-overrides', '--expected-genesis-hash', '--expected-shred-version',
              '--dynamic-port-range', '--rpc-port', '--rpc-bind-address', '--gossip-port',
              '--wal-recovery-mode', '--use-snapshot-archives-at-startup', '--limit-ledger-size', '--limit-blockstore-size'}
    result = {}; index = 2
    while index < len(words):
        flag = words[index]; index += 1
        require(flag in singles | values, 'legacy startup declares an unsupported feature')
        value = True
        if flag in values:
            require(index < len(words) and not words[index].startswith('--'), 'legacy option lacks its value')
            value = words[index]; index += 1
        require(flag not in result or flag in ('--entrypoint', '--known-validator'), 'legacy option is ambiguous')
        result.setdefault(flag, []).append(value)
    expected = {'--identity': '/home/solv/identity.json', '--accounts': '/mnt/accounts',
                '--ledger': '/mnt/ledger', '--snapshots': '/mnt/snapshot',
                '--expected-genesis-hash': GENESIS[request['network']]}
    for flag, value in expected.items():
        require(result.get(flag) == [value], 'legacy data path, identity path or network differs')
    fixed = {'--staked-nodes-overrides': ('overrides.yml',), '--log': ('/home/solv/solana-validator.log', '-'), '--tower': ('/mnt/ledger',),
             '--rpc-port': ('8899',), '--gossip-port': ('8001',),
             '--rpc-bind-address': ('127.0.0.1', '0.0.0.0'),
             '--wal-recovery-mode': ('skip_any_corrupted_record',),
             '--use-snapshot-archives-at-startup': ('when-newest', 'always', 'never')}
    for flag, choices in fixed.items():
        require(flag not in result or result[flag][0] in choices, 'legacy option value is not qualified')
    for flag in ('--limit-ledger-size', '--limit-blockstore-size', '--expected-shred-version'):
        require(flag not in result or re.fullmatch('[0-9]{1,12}', result[flag][0]),
                'legacy numeric setting is invalid')
    if '--dynamic-port-range' in result:
        value = result['--dynamic-port-range'][0]
        require(re.fullmatch('[0-9]{4,5}-[0-9]{4,5}', value), 'legacy port range is invalid')
        low, high = map(int, value.split('-'))
        require(1024 <= low < high <= 65535 and high - low >= 26, 'legacy port range is invalid')
    suffix = 'mainnet-beta' if request['network'] == 'mainnet' else 'testnet'
    require(all(re.fullmatch(r'entrypoint[2-5]?\.' + suffix + r'\.solana\.com:8001', value)
                for value in result.get('--entrypoint', [])), 'legacy bootstrap endpoint is not qualified')
    require(all(re.fullmatch(PUBLIC, value) for value in result.get('--known-validator', [])),
            'legacy bootstrap identity is invalid')
    mode = 'sync' if '--no-voting' in result else 'validator'
    if request['role'] == 'rpc':
        require(mode == 'sync' and '--vote-account' not in result, 'legacy RPC is configured for voting')
        mode = 'rpc'
    elif mode == 'validator':
        require(request['vote_account'] is not None and result.get('--vote-account') == [request['vote_account']],
                'legacy vote account differs from original inventory')
    else:
        require('--vote-account' not in result, 'legacy synchronization has conflicting voting configuration')
    require('--no-wait-for-vote-to-start-leader' not in result or mode == 'rpc',
            'legacy voting or synchronization history bypass is not qualified')
    require(not ('--limit-ledger-size' in result and '--limit-blockstore-size' in result),
            'legacy ledger retention options conflict')
    overrides = None
    if '--staked-nodes-overrides' in result:
        require(request['role'] == 'validator' and request['network'] == 'mainnet',
                'legacy staked override profile is not qualified')
        overrides = staked_overrides(read_public('home/solv/overrides.yml', uid=request['historical']['uid'], maximum=16384))
    return {'mode': mode, 'overrides': overrides, 'argv_sha256': digest(json.dumps(words[2:], separators=(',', ':')).encode()),
            'script_sha256': digest(raw), 'options': result}



def staked_overrides(raw):
    """The carried managed YAML subset, never arbitrary YAML constructors.

    Agave's pinned admin_rpc_service.rs deserializes staked_map_id into
    HashMap<Pubkey,u64>. Retain exact public bytes as original provenance.
    """
    require(isinstance(raw, bytes) and 0 < len(raw) <= 16384, 'legacy staked override exceeds its bound')
    text = raw.decode('ascii'); lines = text.splitlines()
    require(text == '\n'.join(lines) + '\n' and 2 <= len(lines) <= 65
            and lines[0] == 'staked_map_id:', 'legacy staked override structure is not qualified')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; seen = {}
    for line in lines[1:]:
        match = re.fullmatch(r'  ([1-9A-HJ-NP-Za-km-z]{32,44}): (0|[1-9][0-9]{0,19})', line)
        require(match is not None, 'legacy staked override entry is not qualified')
        key, amount = match.groups(); number = 0
        for letter in key: number = number * 58 + alphabet.index(letter)
        length = len(key) - len(key.lstrip('1')) + (number.bit_length() + 7) // 8
        require(length == 32 and key not in seen and int(amount) < 2**64,
                'legacy staked override key or amount is invalid')
        seen[key] = int(amount)
    canonical = 'staked_map_id:\n' + ''.join('  ' + key + ': ' + str(seen[key]) + '\n' for key in sorted(seen))
    return {'path': '/home/solv/overrides.yml', 'sha256': digest(raw), 'canonical_text': canonical}


VALUES = {'--wal-recovery-mode': ('skip_any_corrupted_record',),
          '--use-snapshot-archives-at-startup': ('when-newest', 'always', 'never')}
NUMERIC = ('--limit-ledger-size', '--limit-blockstore-size', '--expected-shred-version')
SINGLES = ('--no-port-check', '--no-skip-initial-accounts-db-clean')
CHANGES = ['original data paths move to independently reserved copied volumes',
           'native service uses isolated original numeric accounts and encrypted credentials',
           'RPC binds loopback behind the authenticated native gateway',
           'gossip and dynamic ports use the fixed native ingress profile',
           'bootstrap identities and entrypoints use the fixed native network catalog',
           'voting remains disabled until separate original registration and history validation']


def runtime_settings(startup):
    require(isinstance(startup, dict) and startup.get('mode') in ('rpc', 'sync', 'validator'),
            'original startup policy is missing')
    options = startup.get('options')
    require(isinstance(options, dict), 'original option evidence is missing')
    result = []; changes = list(CHANGES)
    require(not all(key in options for key in NUMERIC[:2]), 'original retention options conflict')
    for key in (*VALUES, *NUMERIC, *SINGLES):
        if key not in options: continue
        row = options[key]
        require(isinstance(row, list) and len(row) == 1, 'original setting is ambiguous')
        value = row[0]
        if key in SINGLES:
            require(value is True, 'original boolean setting differs'); result.append(key)
        else:
            require(isinstance(value, str), 'original setting has an invalid type')
            if key in VALUES: require(value in VALUES[key], 'original setting is not qualified')
            else: require(re.fullmatch('[0-9]{1,12}', value), 'original numeric setting differs')
            result.extend([key, value])
    if '--no-wait-for-vote-to-start-leader' in options:
        require(startup['mode'] == 'rpc' and options['--no-wait-for-vote-to-start-leader'] == [True],
                'voting history bypass cannot be migrated')
        changes.append('remove no-wait-for-vote-to-start-leader; retain native rooted-vote leader safety')
    override = startup.get('overrides')
    require(('--staked-nodes-overrides' in options) == (override is not None),
            'original staked override evidence is incomplete')
    if override is not None:
        require(isinstance(override, dict) and set(override) == {'path','sha256','canonical_text'}
                and override['path'] == '/home/solv/overrides.yml' and isinstance(override['sha256'], str)
                and re.fullmatch(HASH, override['sha256']) and isinstance(override['canonical_text'], str),
                'original staked override evidence changed')
        canonical = staked_overrides(override['canonical_text'].encode('ascii'))
        require(canonical['canonical_text'] == override['canonical_text'], 'original staked override is not canonical')
        require(options['--staked-nodes-overrides'] == ['overrides.yml'], 'original override path differs')
    return {'schema': 1, 'arguments': result, 'overrides': override, 'changes': changes}


def settings_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"))

def command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120 if argv==['/usr/bin/systemctl','stop','solv.service'] else 20, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'legacy service observation failed')
    return result.stdout.decode('utf-8')


def dropins(request):
    directory=ROOT/'etc/systemd/system/solv.service.d'
    if not directory.exists() and not directory.is_symlink():return None
    info=directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'legacy service overrides are unprotected')
    entries=list(directory.iterdir())
    require(request['role']=='rpc' and len(entries)<=2 and all(entry.name in
            ('50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new') for entry in entries),
            'legacy service has an unknown override')
    result={}
    for entry in entries:
        raw=read_public('etc/systemd/system/solv.service.d/'+entry.name)
        require(digest(raw) in FIREWALL_DROPINS,'legacy service override differs from the qualified ingress guard')
        result[entry.name]=digest(raw)
    return result


def firewall_guard(record):
    if record==['/usr/bin/python3',['/usr/bin/python3','-I','/usr/local/lib/erpc/rpc-firewall.py','solana-rpc','guard'],['privileged']]:return 'legacy'
    if isinstance(record,list) and len(record)==3 and record[0]=='/usr/bin/python3' and record[2]==['privileged']:
        argv=record[1]
        if len(argv)==6 and argv[:3]==['/usr/bin/python3','-I','-c'] and argv[4:]==['solana-rpc','guard'] and digest(argv[3].encode())==FIREWALL_PROGRAM:return 'external'
    return None


def loaded_commands(request, service, run):
    # systemd v255 Exec*Ex and busctl's typed JSON representation. No command
    # property is executed; unknown hooks remain a reason not to adopt a unit.
    # Source: systemd v255 db11bab38ccf1ed257f310d29070843d4c58ea01,
    # src/busctl/busctl.c json_transform_variant and src/shared/exec-util.c.
    raw = run(['/usr/bin/busctl', '--system', '--json=short', 'get-property',
               'org.freedesktop.systemd1', BUS_OBJECT, 'org.freedesktop.systemd1.Service',
               *EXEC_PROPERTIES])
    lines = raw.splitlines()
    require(len(lines) == len(EXEC_PROPERTIES), 'loaded command properties are incomplete')
    commands = {}
    for name, line in zip(EXEC_PROPERTIES, lines):
        value = unique(line)
        require(isinstance(value, dict) and set(value) == {'type', 'data'}
                and value['type'] == 'a(sasasttttuii)' and isinstance(value['data'], list)
                and len(value['data']) <= (2 if name=='ExecStartPreEx' else 1), 'loaded command property has an unsupported shape')
        records = value['data']
        if records:
            normalized=[]
            for record in records:
                require(isinstance(record,list) and len(record)==10 and isinstance(record[0],str)
                        and all(isinstance(record[index],list) and all(isinstance(v,str) for v in record[index]) for index in (1,2))
                        and all(type(v)is int and v>=0 for v in record[3:]),'loaded command record is malformed')
                normalized.append(record[:3])
                if name=='ExecStartEx' and service['ActiveState']=='active':
                    require(record[7]==int(service['MainPID']),'loaded launch PID differs from the running invocation')
            commands[name]=normalized[0] if len(normalized)==1 else normalized
        else:commands[name]=None
    require(commands['ExecStartEx'] == ['/home/solv/start-validator.sh', ['/home/solv/start-validator.sh'], []],
            'loaded service does not execute the original startup script')
    for name in ('ExecStartPostEx', 'ExecConditionEx', 'ExecReloadEx', 'ExecStopEx', 'ExecStopPostEx'):
        require(commands[name] is None, 'loaded service has an unsupported lifecycle hook')
    before=commands['ExecStartPreEx']
    if before is not None:
        rows=[before] if isinstance(before[0],str) else before
        guards=[firewall_guard(record) for record in rows]
        require(request['role']=='rpc' and None not in guards and len(set(guards))==len(guards),
                'loaded service has an unsupported preparation hook')
    return digest(json.dumps(commands, sort_keys=True, separators=(',', ':')).encode())


def loaded_policy(request, run):
    # Typed properties are qualified against systemd v255 db11bab38ccf1ed257f310d29070843d4c58ea01:
    # src/core/dbus-execute.c bus_exec_vtable and src/core/dbus-service.c bus_service_vtable.
    # This does not read referenced environment files or the process environment.
    raw = run(['/usr/bin/busctl', '--system', '--json=short', 'get-property',
               'org.freedesktop.systemd1', BUS_OBJECT, 'org.freedesktop.systemd1.Service',
               *POLICY_PROPERTIES])
    lines = raw.splitlines()
    require(len(lines) == len(POLICY_PROPERTIES), 'loaded execution policy is incomplete')
    observed = {}
    for (name, (kind, expected)), line in zip(POLICY_PROPERTIES.items(), lines):
        value = unique(line)
        require(isinstance(value, dict) and set(value) == {'type', 'data'} and value['type'] == kind,
                'loaded execution policy has an unsupported shape')
        data = value['data']
        if name == 'Environment':
            require(isinstance(data, list) and len(data) == 2 and all(isinstance(v, str) for v in data)
                    and digest(json.dumps(sorted(data), separators=(',', ':')).encode()) == ENVIRONMENT_SHA256[request['network']],
                    'legacy service environment differs from its qualified declarations')
            observed[name] = ENVIRONMENT_SHA256[request['network']]
        else:
            require(type(data) is type(expected) and data == expected,
                    'legacy execution policy differs from its qualified declarations')
            observed[name] = data
    return digest(json.dumps(observed, sort_keys=True, separators=(',', ':')).encode())


def loaded_dependencies(request, run):
    """Closed loaded Unit edges: retirement must not invoke another custom job."""
    empty=('Requisite','BindsTo','PartOf','Upholds','RequiredBy','RequisiteOf','BoundBy','ConsistsOf','UpheldBy',
           'OnSuccess','OnSuccessOf','OnFailure','OnFailureOf','Triggers','TriggeredBy',
           'PropagatesReloadTo','ReloadPropagatedFrom','PropagatesStopTo','StopPropagatedFrom','JoinsNamespaceOf')
    allowed={name:set() for name in empty}
    allowed.update(Requires={'sysinit.target','system.slice','-.mount','home.mount'},Wants=set(),
        WantedBy={'multi-user.target'},Before={'shutdown.target'},
        After={'sysinit.target','basic.target','network.target','system.slice','-.mount','home.mount','systemd-journald.socket'},
        Conflicts={'shutdown.target'},ConflictedBy={'shutdown.target'},RequiresMountsFor={'/home/solv'})
    if request['role']=='rpc':
        allowed['Requires'].add('erpc-solana-rpc-firewall.service')
        allowed['After'].add('erpc-solana-rpc-firewall.service')
    fixed={'DefaultDependencies':('b',True),'StopWhenUnneeded':('b',False),'RefuseManualStop':('b',False),
        'FailureAction':('s','none'),'SuccessAction':('s','none'),'StartLimitAction':('s','none'),'JobTimeoutAction':('s','none')}
    names=[*allowed,*fixed]
    raw=run(['/usr/bin/busctl','--system','--json=short','get-property','org.freedesktop.systemd1',
             BUS_OBJECT,'org.freedesktop.systemd1.Unit',*names])
    rows=raw.splitlines();require(len(rows)==len(names),'loaded unit dependency observation is incomplete')
    observed={}
    for name,row in zip(names,rows):
        value=unique(row)
        require(isinstance(value,dict) and set(value)=={'type','data'},'invalid loaded unit dependency type')
        data=value['data']
        if name in allowed:
            require(value['type']=='as' and isinstance(data,list) and len(data)<=64
                    and all(isinstance(item,str) for item in data) and len(data)==len(set(data))
                    and set(data)<=allowed[name],'legacy unit has an unqualified dependency or stop side effect')
            observed[name]=sorted(data)
        else:
            kind,expected=fixed[name]
            require(value['type']==kind and type(data)is type(expected) and data==expected,
                    'legacy unit has an unqualified failure or manual-stop policy')
            observed[name]=data
    require('network.target' in observed['After'],'legacy network ordering is absent')
    return digest(json.dumps(observed,sort_keys=True,separators=(',',':')).encode())


def service_properties(run, allow_reload=False):
    output = run(['/usr/bin/systemctl', 'show', 'solv.service', '--property=' + ','.join(SERVICE_PROPERTIES)])
    observed = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in SERVICE_PROPERTIES and key not in observed, 'legacy service properties are ambiguous')
        observed[key] = value
    require(set(observed) == set(SERVICE_PROPERTIES) and observed['LoadState'] == 'loaded'
            and observed['FragmentPath'] == '/etc/systemd/system/solv.service'
            and observed['DropInPaths'] in ('',DROPIN) and observed['User'] == 'solv'
            and observed['Type'] == 'simple'
            and observed['Group'] in ('', 'solv') and observed['WorkingDirectory'] == '/home/solv'
            and observed['NeedDaemonReload'] in (('no','yes') if allow_reload else ('no',)) and observed['ControlPID'] == '0',
            'legacy service differs from its stable managed configuration')
    require(re.fullmatch('[0-9]{1,10}', observed['MainPID']), 'legacy main PID is invalid')
    if observed['ActiveState'] == 'active':
        require(observed['SubState'] == 'running' and int(observed['MainPID']) > 0
                and re.fullmatch('[a-f0-9]{32}', observed['InvocationID'])
                and observed['InvocationID'] != '0' * 32
                and observed['ControlGroup'] == '/system.slice/solv.service',
                'legacy service is not a stable running invocation')
    else:
        require((observed['ActiveState'], observed['SubState']) in (('inactive', 'dead'), ('failed', 'failed'))
                and observed['MainPID'] == '0', 'legacy service is transitioning or has a residual main PID')
    return observed


def process_bytes(directory, name, maximum=65536):
    fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source: raw = source.read(maximum + 1)
    require(len(raw) <= maximum, 'legacy process metadata exceeds its bound')
    return raw


def generation(directory):
    before, separator, after = process_bytes(directory, 'stat', 16384).rpartition(b') ')
    parts = after.split()
    require(separator and before.split(b' (', 1)[0] == directory.name.encode()
            and len(parts) >= 20 and parts[19].isdigit(), 'legacy process generation is malformed')
    return int(parts[19])


def effective_environment(directory, service, network, executable):
    """Read bounded effective bytes, emit only a digest; never log an env value."""
    raw=process_bytes(directory,'environ',65536)
    require(raw.endswith(b'\0'),'legacy effective environment is incomplete')
    entries=raw[:-1].split(b'\0');require(0<len(entries)<=64,'legacy effective environment exceeds its bound')
    environment={}
    for entry in entries:
        key,separator,value=entry.partition(b'=')
        require(separator and re.fullmatch(b'[A-Z_][A-Z_0-9]{0,63}',key) and key not in environment
                and len(value)<=4096,'legacy effective environment is malformed or duplicated')
        environment[key]=value
    declared=[]
    for key in (b'PATH',b'SOLANA_METRICS_CONFIG'):
        require(key in environment,'legacy native environment lacks its qualified declarations')
        declared.append((key+b'='+environment[key]).decode('utf-8'))
    require(digest(json.dumps(sorted(declared),separators=(',',':')).encode())==ENVIRONMENT_SHA256[network],
            'effective native declarations differ from the qualified service')
    fixed={b'HOME':b'/home/solv',b'USER':b'solv',b'LOGNAME':b'solv',b'SHELL':b'/bin/bash',b'PWD':b'/home/solv',
           b'INVOCATION_ID':service['InvocationID'].encode(),b'SYSTEMD_EXEC_PID':directory.name.encode()}
    optional={b'LANG',b'LC_ALL',b'SHLVL',b'_',b'JOURNAL_STREAM',b'MEMORY_PRESSURE_WATCH',b'MEMORY_PRESSURE_WRITE'}
    require(set(environment)<=set(fixed)|optional|{b'PATH',b'SOLANA_METRICS_CONFIG'},
            'native effective environment contains an unqualified behavior or injection setting')
    for key,value in fixed.items():
        if key in environment:require(environment[key]==value,'native effective environment differs from original identity')
    for key in (b'LANG',b'LC_ALL'):
        if key in environment:require(environment[key] in (b'C',b'C.UTF-8',b'en_US.UTF-8'),
                                     'legacy native locale is not qualified')
    if b'SHLVL' in environment:require(environment[b'SHLVL'] in (b'0',b'1'),'unqualified legacy shell nesting')
    if b'_' in environment:require(environment[b'_'] in (b'agave-validator',executable.encode(),
        b'/home/solv/.local/share/solana/install/active_release/bin/agave-validator'),'unqualified legacy executable environment')
    if b'JOURNAL_STREAM' in environment:
        require(re.fullmatch(b'[0-9]+:[0-9]+',environment[b'JOURNAL_STREAM']),'invalid native journal binding')
        selected=tuple(map(int,environment[b'JOURNAL_STREAM'].split(b':')))
        streams=[(directory/'fd'/str(number)).stat() for number in (1,2)]
        require(any((item.st_dev,item.st_ino)==selected for item in streams),'native journal environment differs from its live descriptor')
    if b'MEMORY_PRESSURE_WATCH' in environment:
        require(environment[b'MEMORY_PRESSURE_WATCH'] in (b'/dev/null',b'/sys/fs/cgroup/system.slice/solv.service/memory.pressure'),
                'native pressure environment leaves its original cgroup')
    if b'MEMORY_PRESSURE_WRITE' in environment:
        import base64
        require(environment.get(b'MEMORY_PRESSURE_WATCH')==b'/sys/fs/cgroup/system.slice/solv.service/memory.pressure',
                'native pressure value has no original cgroup')
        decoded=base64.b64decode(environment[b'MEMORY_PRESSURE_WRITE'],validate=True)
        require(re.fullmatch(b'some [1-9][0-9]{0,7} [1-9][0-9]{0,7}\0',decoded),
                'native pressure protocol differs from systemd255')
    return digest(raw)


def image_identity(info):
    # Runtime observations, not a persistent filesystem identity across boots.
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def process_observation(service, launch, evidence, network, build=None):
    pid = int(service['MainPID'])
    if pid == 0: return None  # Absence of MainPID is not proof of account quiescence.
    directory = ROOT / 'proc' / str(pid)
    require(not directory.is_symlink(), 'indirect legacy process directory')
    first = generation(directory)
    metadata = {}
    for line in process_bytes(directory, 'status').splitlines():
        key, separator, value = line.partition(b':')
        if key not in (b'Uid', b'Gid', b'CapEff', b'CapPrm', b'CapAmb', b'CapInh'): continue
        require(separator and key not in metadata, 'ambiguous legacy process ownership')
        metadata[key] = value.strip()
    for name, expected in ((b'Uid', evidence['uid']), (b'Gid', evidence['gid'])):
        values = metadata.get(name, b'').split()
        require(len(values) == 4 and all(v.isdigit() and int(v) == expected for v in values),
                'legacy process numeric identity differs from original evidence')
    for name in (b'CapEff', b'CapPrm', b'CapAmb', b'CapInh'):
        value = metadata.get(name, b'')
        require(re.fullmatch(b'[a-fA-F0-9]{1,16}', value) and int(value, 16) == 0,
                'legacy process retains unsupported capabilities')
    require(process_bytes(directory, 'cgroup', 16384) == b'0::/system.slice/solv.service\n',
            'legacy process is outside its original service cgroup')
    for namespace in ('mnt', 'pid', 'user', 'net'):
        running = (directory / 'ns' / namespace).stat()
        observer = (ROOT / 'proc/self/ns' / namespace).stat()
        require((running.st_dev, running.st_ino) == (observer.st_dev, observer.st_ino),
                'legacy process is in another namespace')
    executable = directory / 'exe'
    path = os.readlink(executable)
    built=path=='/home/solv/agave/target/release/agave-validator'
    packaged=path.startswith('/home/solv/.local/share/solana/install/releases/') and path.endswith('/solana-release/bin/agave-validator')
    require((built or packaged) and re.fullmatch('[A-Za-z0-9/_.+-]+', path) and '..' not in Path(path).parts,
            'legacy executable is outside its managed Agave build or release layout')
    raw = process_bytes(directory, 'cmdline')
    require(raw.endswith(b'\0'), 'legacy process arguments are incomplete')
    argv = [value.decode('utf-8') for value in raw[:-1].split(b'\0')]
    require(argv and argv[0] in ('agave-validator', path)
            and digest(json.dumps(argv[1:], separators=(',', ':')).encode()) == launch['argv_sha256'],
            'running legacy arguments differ from the inspected startup script')
    # /proc/PID/exe is the one intentional kernel-link follow. Hash the opened
    # image without executing it. Native version/source qualification is separate.
    descriptor = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        # Cargo c980f4866141969fab6254a680546a277789d6f0 link_targets
        # publishes Linux deps outputs by hardlink into target/release. These
        # are public code aliases, not private key files. Authenticate this
        # opened image and retain every metadata field through observation.
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, evidence['uid'])
                and (before.st_nlink >= 1 if built else before.st_nlink == 1)
                and 0 < before.st_size <= 4 * 1024**3
                and not before.st_mode & 0o6022, 'legacy executable file authority differs')
        checksum = hashlib.sha256(); count = 0
        while True:
            part = source.read(1024 * 1024)
            if not part: break
            count += len(part); require(count <= before.st_size, 'legacy executable grew during observation')
            checksum.update(part)
        after = os.fstat(source.fileno())
        require(count == before.st_size and image_identity(before) == image_identity(after),
                'legacy executable changed during observation')
    matches=build is not None and checksum.hexdigest()==build['executable_sha256'] and count==build['executable_bytes']
    require(build is None or matches,'current executable differs from independently retained original build evidence')
    environment=effective_environment(directory,service,network,path)
    require(generation(directory) == first and os.readlink(executable) == path,
            'legacy process changed during observation')
    current = executable.stat()
    require(image_identity(current) == image_identity(before), 'legacy process image or metadata changed')
    return {'pid': pid, 'start_ticks': first, 'device': before.st_dev, 'inode': before.st_ino,
            'image_sha256': checksum.hexdigest(), 'image_bytes': count, 'native_source_verified': False,
            'effective_environment_sha256':environment,'artifact_evidence_matches':matches,
            'source_layout':'managed-agave-build' if built else 'managed-release'}


def mount_table():
    """Read current Linux mount identity; do not mount or interpret a shell path."""
    raw = process_bytes(ROOT / 'proc/self', 'mountinfo', 4 * 1024 * 1024).decode('utf-8')
    result = []
    ids = set()
    def unescape(value):
        substitutions = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
        require(not re.search(r'\\(?!040|011|012|134)', value), 'unsupported original mount escape')
        return re.sub(r'\\(040|011|012|134)', lambda match: substitutions[match[1]], value)
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and fields.count('-') == 1, 'invalid original mount table')
        separator = fields.index('-')
        require(separator >= 6 and len(fields) == separator + 4 and fields[0].isdigit() and fields[1].isdigit()
                and fields[0] not in ids and re.fullmatch('[0-9]+:[0-9]+', fields[2]), 'invalid original mount identity')
        ids.add(fields[0]); point = unescape(fields[4])
        require(point.startswith('/') and '..' not in point.split('/') and '.' not in point.split('/'),
                'noncanonical original mount point')
        result.append({'id': fields[0], 'device': tuple(map(int, fields[2].split(':'))),
            'root': unescape(fields[3]), 'point': Path(point), 'options': fields[5].split(','),
            'fs': fields[separator + 1], 'super_options': fields[separator + 3].split(',')})
    require(result, 'original mount table is empty')
    return result


def storage_observation(evidence):
    before = mount_table()
    uuid_directory = ROOT / 'dev/disk/by-uuid'
    for parent in (uuid_directory, *uuid_directory.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'original UUID namespace is not protected')
    identifiers = {}
    for index, entry in enumerate(uuid_directory.iterdir()):
        require(index < 4096, 'original UUID namespace exceeds its bound')
        if not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', entry.name): continue
        link = entry.lstat()
        require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0, 'original UUID link is not root-managed')
        device = entry.stat()  # Intentional root-managed udev link to a block device.
        require(stat.S_ISBLK(device.st_mode), 'original UUID does not resolve to a block device')
        identifiers.setdefault((os.major(device.st_rdev), os.minor(device.st_rdev)), []).append(entry.name)
    result = {}
    for kind, name in DATA_PATHS.items():
        point = Path(name); path = ROOT / name.lstrip('/')
        selected = [entry for entry in before if entry['point'] == point]
        require(len(selected) == 1, 'original data volume is missing or overmounted')
        entry = selected[0]
        require(entry['root'] == '/' and entry['fs'] in ('ext4', 'xfs')
                and all('rw' in entry[key] and 'ro' not in entry[key] for key in ('options', 'super_options'))
                and not any(point in other['point'].parents for other in before)
                and sum(other['device'] == entry['device'] for other in before) == 1,
                'original data volume has an unsupported filesystem or mount alias')
        for ancestor in (path, *path.parents):
            info = ancestor.lstat()
            allowed = (0, evidence['uid']) if ancestor in (path, ROOT / 'mnt') else (0,)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and not info.st_mode & 0o022,
                    'original data path ownership differs')
        info = path.lstat()
        require(info.st_uid == evidence['uid'] and info.st_gid == evidence['gid']
                and (os.major(info.st_dev), os.minor(info.st_dev)) == entry['device'],
                'original data filesystem differs from its numeric owner or mount')
        uuids = identifiers.get(entry['device'], [])
        require(len(uuids) == 1, 'original filesystem UUID is absent or ambiguous')
        result[kind] = {'uuid': uuids[0], 'device': list(entry['device']), 'inode': info.st_ino,
                        'mount_id': entry['id'], 'fs': entry['fs'], 'uid': info.st_uid, 'gid': info.st_gid}
    require(len({value['uuid'] for value in result.values()}) == 3 and mount_table() == before,
            'original data mounts changed during inspection')
    return result


def copy_preflight(targets, evidence, sources, run):
    """Inspect separately prepared volumes and conservative live copy size only."""
    before = mount_table()
    require(not set(targets.values()) & {source['uuid'] for source in sources.values()},
            'copy targets must not reuse an original data filesystem')
    result = {}
    for kind, name in TARGET_PATHS.items():
        path = ROOT / name.lstrip('/'); point = Path(name)
        selected = [entry for entry in before if entry['point'] == point]
        require(len(selected) == 1, 'copy target is missing or overmounted')
        entry = selected[0]
        require(entry['root'] == '/' and entry['fs'] in ('ext4', 'xfs')
                and all('rw' in entry[key] and 'ro' not in entry[key] for key in ('options', 'super_options'))
                and not any(point in other['point'].parents for other in before)
                and sum(other['device'] == entry['device'] for other in before) == 1,
                'copy target has an unsupported filesystem or mount alias')
        for ancestor in (path, *path.parents):
            info = ancestor.lstat()
            allowed = (0, evidence['uid']) if ancestor == ROOT / 'mnt' else (0,)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and not info.st_mode & 0o022,
                    'copy target path is not protected')
        identifier = ROOT / 'dev/disk/by-uuid' / targets[kind]
        link = identifier.lstat(); block = identifier.stat()
        info = path.lstat()
        require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0 and stat.S_ISBLK(block.st_mode)
                and (os.major(block.st_rdev), os.minor(block.st_rdev)) == entry['device']
                and (os.major(info.st_dev), os.minor(info.st_dev)) == entry['device']
                and entry['device'] not in {tuple(source['device']) for source in sources.values()},
                'copy target is not the requested separate filesystem')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), 'copy target changed while opening')
            names = os.listdir(fd)
            require(not names or names == ['lost+found'], 'copy target contains existing data')
            if names:
                recovery = os.open('lost+found', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    recovered = os.fstat(recovery)
                    require(recovered.st_uid == 0 and recovered.st_mode & 0o7777 == 0o700
                            and recovered.st_dev == opened.st_dev and not os.listdir(recovery),
                            'copy target recovery directory is not empty or protected')
                finally: os.close(recovery)
            source = ROOT / DATA_PATHS[kind].lstrip('/')
            raw = run(['/usr/bin/du', '-sx', '--apparent-size', '--block-size=1', '--count-links', str(source)])
            words = raw.split()
            require(len(words) == 2 and words[0].isdigit() and len(words[0]) <= 20
                    and words[1] == str(source), 'original data size estimate is unavailable')
            logical = int(words[0]); usage = shutil.disk_usage(path)
            required = logical + COPY_HEADROOM
            require(usage.total >= TARGET_MINIMUM[kind] and usage.free >= required,
                    'copy target lacks capacity for original logical bytes and operating headroom')
            current = path.lstat()
            require((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                    == (info.st_dev, info.st_ino, info.st_uid, info.st_mode) and os.listdir(fd) == names,
                    'copy target changed during preflight')
            result[kind] = {'uuid': targets[kind], 'inode': info.st_ino, 'fs': entry['fs'],
                            'logical_source_bytes': logical, 'required_free_bytes': required,
                            'free_bytes': usage.free, 'total_bytes': usage.total}
        finally: os.close(fd)
    require(mount_table() == before, 'copy mounts changed during preflight')
    return {'requested_volumes': targets, 'targets': result, 'source_retained': True,
            'requires_stopped_recheck': True, 'copy_authorized': False,
            'parent_ownership_transition_required': (ROOT / 'mnt').lstat().st_uid != 0}


def inspect(request, run=command, management_uid=None):
    evidence = validate(request)
    original = accounts(request, evidence, management_uid)
    unit = read_public('etc/systemd/system/solv.service')
    script = read_public('home/solv/start-validator.sh', uid=evidence['uid'])
    launch = startup(script, request)
    settings = runtime_settings(launch); settings_sha256 = settings_digest(settings)
    require('settings_sha256' not in request or request['settings_sha256'] == settings_sha256,
            'original configuration differs from the approved migration plan')
    overrides=dropins(request)
    observed = service_properties(run)
    require(observed['DropInPaths']=='' or overrides is not None and '50-erpc-firewall-guard.conf' in overrides,
            'loaded service override has no qualified original file')
    commands = loaded_commands(request, observed, run)
    policy = loaded_policy(request, run)
    dependencies=loaded_dependencies(request,run)
    storage = storage_observation(evidence)
    copy = copy_preflight(request['target_volumes'], evidence, storage, run) if 'target_volumes' in request else None
    process = process_observation(observed, launch, evidence, request['network'],request.get('artifact_evidence'))
    require(service_properties(run) == observed and loaded_commands(request, observed, run) == commands
            and loaded_policy(request, run) == policy and loaded_dependencies(request,run)==dependencies
            and storage_observation(evidence) == storage
            and read_public('etc/systemd/system/solv.service') == unit
            and read_public('home/solv/start-validator.sh', uid=evidence['uid']) == script
            and startup(script, request) == launch and dropins(request)==overrides,
            'legacy service or source changed during inspection')
    # No proof of safe shutdown, data adoption or history compatibility is made
    # by observing these public inputs. Those need the subsequent migration phase.
    return {'schema': 1, 'source_sha256': request['source_sha256'], 'read_only': True,
            'settings': settings, 'settings_sha256': settings_sha256,
            'original_source_history': request['source_history'],'original_build_evidence':request.get('artifact_evidence'),
            'original_keygen_evidence':request.get('keygen_evidence'),
            'execution_authorized': False, 'historical_account_matches': True,
            'original': original, 'unit_sha256': digest(unit), 'startup': launch,'dropins':overrides,
            'storage': storage,
            'copy_preflight': copy,
            'service': {'active_state': observed['ActiveState'], 'main_pid': int(observed['MainPID']),
                'invocation_id': observed['InvocationID'], 'commands_sha256': commands,
                'execution_policy_sha256': policy, 'dependencies_sha256':dependencies, 'process': process},
            'remaining_checks': ['native-source-history', 'effective-environment-compatibility',
                'storage-and-voting-history', 'exclusive-identity', 'stopped-writer-reconciliation',
                'original-custody', 'separate-management-retention']}


def main():
    require(os.geteuid() == 0, 'legacy public inspection requires sudo')
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536, 'legacy request exceeds its bound')
    result = inspect(unique(raw))
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Legacy Solv public inspection failed; preserve the existing configuration', file=sys.stderr)
        raise SystemExit(1)
