#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Root-owned native lifecycle. No financial proof signing or broadcast occurs here."""
import fcntl
import errno
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import re
import resource
import stat
import sys

# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS

if __name__ == "__main__":
    trusted_imports(Path(__file__).absolute().parent)

from erpc_monad_common import (ROOT, CONFIG, RELEASES, RUN, HELPERS, Refused, address, atomic, digest,
                    execute, fsync_dir, json_bytes, owned_directory, public_key, read, require,
                    token, unique_json)
import erpc_monad_device as device
import erpc_monad_identity as identity
import erpc_monad_package as package
import erpc_monad_processes as processes
from erpc_monad_state import State
import erpc_monad_setup as setup
import erpc_monad_units as units
import erpc_monad_observe as observe
import erpc_monad_accounts as accounts
import erpc_monad_namespace as namespace

CATALOG = unique_json(read(Path(__file__).parent / 'catalog.json'))
STATE = State(ROOT)
ZERO = '0x' + '0' * 40


def contract(value):
    require(isinstance(value, dict) and set(value) == {
        'owner', 'network', 'role', 'partuuid', 'public_ip', 'name_record_sequence', 'secp', 'bls', 'beneficiary', 'auth_address'},
        'invalid immutable contract')
    token(value['owner'])
    require(type(value['name_record_sequence']) is int and 0 < value['name_record_sequence'] < 2**64,
            'name-record sequence must be a positive uint64')
    require(value['network'] in CATALOG['networks'] and value['role'] in ('rpc', 'validator'),
            'unsupported network or role')
    device.partuuid(value['partuuid'])
    ip = ipaddress.IPv4Address(value['public_ip'])
    excluded = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
                '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24',
                '192.88.99.0/24', '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15',
                '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3')
    require(str(ip) == value['public_ip'] and not any(ip in ipaddress.ip_network(n) for n in excluded),
            'advertised peer IP must be public unicast IPv4')
    for kind in ('secp', 'bls'):
        public_key(value[kind], kind)
    for name in ('beneficiary', 'auth_address'):
        address(value[name])
        require((value[name] == ZERO) == (value['role'] == 'rpc'), 'role and financial addresses differ')
    return value


def target(value):
    require(isinstance(value, dict) and set(value) == {'version', 'consensus_commit', 'execution_commit'},
            'invalid release target')
    require(value['version'] == CATALOG['version']
            and value['consensus_commit'] == CATALOG['consensus_commit']
            and value['execution_commit'] == CATALOG['execution_commit'], 'release is not qualified by this controller')
    return value


def paths():
    namespace.paths()
    owned_directory(ROOT)
    owned_directory(CONFIG)
    owned_directory(RELEASES)


def firewall(action,*values):
    # This controller is already externally authenticated. Authenticate the
    # standalone shared helper before interpreting its descriptor-bound bytes.
    import types
    namespace.file(namespace.FIREWALL)
    raw=read(namespace.FIREWALL)
    module=types.ModuleType('erpc_monad_common_firewall')
    module.__file__=str(namespace.FIREWALL)
    exec(compile(raw,str(namespace.FIREWALL),'exec'),module.__dict__)
    selected=module.Firewall('monad')
    if action in ('apply','confirm'):
        return getattr(selected,action)(*values)  # Caller already owns /opt/erpc.
    return selected.dispatch(action,*values)


def expected_keys(c):
    return {k: c[k] for k in ('secp', 'bls')}


def original_accounts():
    result=STATE.get('accounts.json')
    accounts.account_plan(result)
    require(STATE.get('account-reservation.json')==result,'completed numeric authority differs from its reservation')
    return result


def account():
    expected=original_accounts()
    accounts.accounts(expected)
    return accounts.account_slot(accounts.NATIVE,expected[accounts.NATIVE])[0]


def gateway_account():
    expected=original_accounts()
    accounts.accounts(expected)
    return accounts.account_slot(accounts.GATEWAY,expected[accounts.GATEWAY])[0]


def gateway_processes():
    path = ROOT / 'gateway.json'
    return {'/usr/sbin/nginx': STATE.get('gateway.json')['sha256']} if path.exists() else {}


def release_dir(version=None):
    return RELEASES / (version or CATALOG['version'])


def release_receipt():
    return unique_json(read(release_dir() / 'receipt.json'))


def approved_processes():
    approved = {}
    for directory in RELEASES.iterdir():
        if not directory.is_dir() or directory.is_symlink():
            raise Refused('untrusted release directory')
        receipt_file = directory / 'receipt.json'
        if receipt_file.exists():
            recorded = unique_json(read(receipt_file))
            for name in processes_names():
                rel = 'bin/' + name
                if rel in recorded['files']:
                    approved[str(directory / rel)] = recorded['files'][rel]
    return approved


def processes_names():
    return ('monad', 'monad-node', 'monad-rpc', 'monad-mpt', 'monad-keystore',
            'monad-sign-name-record', 'monad-debug-node')


def stop_native(retire=False):
    original=original_accounts()
    failures=[]
    for name,approved in ((accounts.NATIVE,approved_processes),(accounts.GATEWAY,gateway_processes)):
        try:processes.stop(original[name]['uid'],approved())
        except Exception:failures.append(name)
    if retire:
        for unit in processes.UNITS:
            try:execute(['/usr/bin/systemctl','disable',unit])
            except Exception:failures.append(unit)
    require(not failures,'owned native shutdown or retirement could not be completed')


def quiescent():
    processes.quiescent(account().pw_uid, approved_processes())
    processes.quiescent(gateway_account().pw_uid, gateway_processes())


def capacity(initial=False):
    # Filesystem data and the raw execution partition have separate contracts.
    data = ROOT / 'data'
    require(data.is_dir() and not data.is_symlink(), 'data directory is missing or redirected')
    stats = os.statvfs(data)
    allocation = execute(['/usr/bin/du', '--one-file-system', '--summarize', '--block-size=1', str(data)])
    allocated = int(allocation.stdout.split()[0])
    needed = max(50_000_000_000, 450_000_000_000 - allocated)
    require(stats.f_blocks * stats.f_frsize >= 490_000_000_000
            and stats.f_bavail * stats.f_frsize >= needed,
            'data filesystem needs a 500 GB-class volume and sufficient remaining synchronization space')


def hardware():
    require(sys.version_info >= (3, 12), 'Monad requires the Ubuntu 24.04 Python 3.12 interpreter')
    require(os.uname().machine == 'x86_64', 'Monad package is qualified for x86_64 only')
    os_release = Path('/etc/os-release').read_text()
    require('ID=ubuntu' in os_release and 'VERSION_ID="24.04"' in os_release, 'Monad requires Ubuntu 24.04')
    smt = Path('/sys/devices/system/cpu/smt/active')
    require(smt.exists() and smt.read_text().strip() == '0', 'disable SMT in firmware before deployment')
    virtual = execute(['/usr/bin/systemd-detect-virt'], check=False)
    require(virtual.returncode == 1 and virtual.stdout.strip() == b'none', 'Monad requires bare metal')
    memory = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemTotal:'))
    cpus = sorted(os.sched_getaffinity(0))
    require(memory >= 30_000_000 and len(cpus) >= 16, 'Monad requires at least 32 GB RAM and 16 physical CPUs')
    return cpus[:16]


def inspect_device(c, blank=False):
    seen = device.inspect(c['partuuid'], blank=blank)
    owner = STATE.check(c)
    device.same_device(owner['device'], seen)
    return seen


def device_access(observed):
    info = Path(observed['path']).stat()
    require(info.st_uid == 0 and info.st_gid == account().pw_gid and info.st_mode & 0o7777 == 0o660,
            'partition permissions differ from the dedicated native group')
    try:
        attributes = os.listxattr(observed['path'])
    except OSError as error:
        if error.errno != errno.EOPNOTSUPP:
            raise
        attributes = []
    require('system.posix_acl_access' not in attributes, 'extended device ACL is outside the reserved profile')


def qualify_native():
    directory = release_dir()
    recorded = release_receipt()
    qualified = {key: CATALOG[key] for key in ('version', 'consensus_commit', 'execution_commit')}
    qualified['package_sha256'] = CATALOG['package']['sha256']
    require(recorded.get('release') == qualified, 'native release receipt differs from this catalog')
    package.check(directory, recorded)
    return directory


def verify_key(data, kind):
    user = account()
    return identity.recover(data, kind, release_dir() / 'bin/monad-keystore', user.pw_uid, user.pw_gid)


def read_identity(c):
    return identity.check(CONFIG, expected_keys(c), verify_key)


def preflight(c):
    """No ownership write before checking an existing remote contract or orphans."""
    contract(c)
    namespace.paths()
    for directory in (ROOT, CONFIG, RELEASES, HELPERS):
        if directory.exists() or directory.is_symlink():
            owned_directory(directory)
    if (ROOT / 'owner.json').exists():
        STATE.check(c)
        require(not (ROOT / 'installed.json').exists() and not (ROOT / 'installing.json').exists(),
                'initialized deployment must use deploy/update rather than repeating init')
        return {'existing': True}
    namespace.fresh()
    for directory in (ROOT, CONFIG, RELEASES, HELPERS):
        require(not directory.is_symlink() and (not directory.exists() or not any(directory.iterdir())),
                'unowned Monad artifacts exist; automatic adoption is refused')
    for name in ('monad', accounts.NATIVE,accounts.GATEWAY):
        require(accounts.lookup(pwd.getpwnam,name) is None and accounts.lookup(grp.getgrnam,name) is None,
                'unowned dedicated account or group already exists')
    require(not Path('/usr/local/bin/monad-node').exists() and not Path('/usr/local/bin/monad').exists(),
            'unowned vendor Monad installation exists; use a clean dedicated host')
    require(execute(['/usr/bin/systemctl', 'is-active', 'nginx.service'], check=False).returncode != 0,
            'an existing nginx service is active; use a dedicated host')
    device.inspect(c['partuuid'], blank=True)
    hardware()
    return {'existing': False}


def reserve(c):
    existing = preflight(c)['existing']
    if not existing:
        observed = device.inspect(c['partuuid'], blank=True)
        owned_directory(ROOT, True)
        STATE.put('owner.json', {'contract': c, 'device': observed})
    else:
        inspect_device(c)
    return STATE.check(c)


def check_ready(c, *, intent=None, manual=False):
    paths()
    installed = STATE.guard(c, intent, manual)
    original=account()
    setup.verify_data(STATE,c,original.pw_uid,original.pw_gid)
    if c['role'] == 'validator':
        clock = execute(['/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value']).stdout.strip()
        require(clock == b'yes', 'validator startup requires a synchronized host clock')
    device_access(inspect_device(c))
    capacity()
    qualify_native()
    read_identity(c)
    if c['role'] == 'rpc':
        require(not setup.admitted_keys(CATALOG, c), 'RPC-intent identity appears in an official validator epoch set')
    require((ROOT / 'device-initialized.json').exists(), 'raw TrieDB initialization is not complete')
    for filename, checksum in installed['receipt']['configuration'].items():
        require(digest(read(Path(filename))) == checksum, 'installed configuration or unit changed')
    firewall('guard')
    return installed


def initialize_device(c, intent, explicit):
    STATE.current(c, intent)
    require((ROOT / 'installing.json').exists(), 'device initialization requires an installing target')
    device_access(inspect_device(c))
    quiescent()
    complete, pending = ROOT / 'device-initialized.json', ROOT / 'device-initializing.json'
    if complete.exists():
        require(STATE.get('device-initialized.json')['partuuid'] == c['partuuid'], 'device receipt differs')
        return
    require(explicit is True, 'first TrieDB initialization requires explicit --initialize-device')
    require(not pending.exists(), 'device initialization was interrupted; use recover-device without reformatting')
    inspect_device(c, blank=True)
    STATE.put('device-initializing.json', {'partuuid': c['partuuid'], 'intent': intent,
                                         'release': CATALOG['version']})
    # No truncate, grow, create-empty, partition or NVMe-format operation exists.
    hugepages()
    native_mpt(c, create=True)
    flush_device(c)
    STATE.put('device-initialized.json', {'partuuid': c['partuuid'], 'release': CATALOG['version']})


def hugepages():
    # Match the package's node0 hugepage recommendation, never reduce a larger reservation.
    for size, count in ((1048576, 4), (2048, 2048)):
        path = Path('/sys/devices/system/node/node0/hugepages') / ('hugepages-' + str(size) + 'kB') / 'nr_hugepages'
        require(path.exists(), 'required hardware hugepage size is unavailable')
        if int(path.read_text().strip()) < count:
            path.write_text(str(count))
        require(int(path.read_text().strip()) >= count, 'insufficient contiguous memory for recommended hugepages')


def flush_device(c):
    observed = inspect_device(c)
    fd = os.open(observed['path'], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISBLK(info.st_mode) and str(os.major(info.st_rdev)) + ':' + str(os.minor(info.st_rdev)) == observed['major_minor'],
                'device changed before durable initialization publication')
        os.fsync(fd)
    finally:
        os.close(fd)


def native_mpt(c, create=False):
    user = account()
    executable = qualify_native() / 'bin/monad-mpt'
    env = dict(__import__('erpc_monad_common').ENV, LD_LIBRARY_PATH=str(executable.parent.parent / 'lib'))
    args = [str(executable), '--storage', '/dev/disk/by-partuuid/' + c['partuuid']]
    if create:
        args += ['--create']
    result = __import__('subprocess').run(args, stdout=__import__('subprocess').PIPE,
        stderr=__import__('subprocess').PIPE, env=env, user=user.pw_uid, group=user.pw_gid,
        extra_groups=[], timeout=300, check=False)
    require(result.returncode == 0 and b'MPT database on storages:' in result.stdout,
            'native TrieDB validation failed; device is preserved')


def recover_device(c):
    STATE.check(c)
    quiescent()
    inspect_device(c)
    require((ROOT / 'device-initializing.json').exists() and not (ROOT / 'device-initialized.json').exists(),
            'recover-device applies only to interrupted initial creation')
    native_mpt(c)
    flush_device(c)
    STATE.put('device-initialized.json', {'partuuid': c['partuuid'], 'release': CATALOG['version'],
                                         'recovered_read_only': True})
    return {'device': 'validated without writes', 'service': 'stopped'}


def started():
    expected=original_accounts()
    for name in ('execution','bft','rpc','gateway'):
        account=expected[accounts.GATEWAY if name=='gateway' else accounts.NATIVE]
        raw=execute(['/usr/bin/systemctl','show','erpc-monad-'+name+'.service',
                     '--property=ActiveState,SubState,MainPID,User,Group']).stdout
        require(len(raw)<=4096,'native startup observation exceeds its bound')
        rows={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=')
            require(separator and key not in rows,'ambiguous native startup observation')
            rows[key]=value
        require(set(rows)=={'ActiveState','SubState','MainPID','User','Group'}
                and rows['ActiveState']=='active' and rows['SubState']=='running'
                and rows['MainPID'].isascii() and rows['MainPID'].isdigit() and int(rows['MainPID'])>0
                and rows['User']==str(account['uid']) and rows['Group']==str(account['gid']),
                'native unit did not start under its original numeric authority')


def dispatch(request):
    require(isinstance(request, dict), 'invalid controller request')
    c = contract(request['contract'])
    operation = request['operation']
    if operation == 'preflight':
        return preflight(c)
    if operation == 'reserve':
        return reserve(c)
    namespace.paths(runtime=operation not in ('stop','destroy'))
    STATE.check(c)
    if operation in ('stop','destroy'):
        STATE.cancel(c,operation=='destroy',lambda:stop_native(retire=operation=='destroy'))
        return {'stopped':True,'retired':operation=='destroy','device_preserved':True}
    if operation=='recover-data-filesystem':
        require((ROOT/'stopped').exists() and STATE.get('operation.json').get('intent') is None,
                'stop the original node durably before filesystem identity recovery')
        quiescent()
        user=account()
        return setup.upgrade_data_identity(STATE,c,user.pw_uid,user.pw_gid,request.get('original_uuid'))
    if operation=='provision-accounts':
        require(not (ROOT/'installed.json').exists() and not (ROOT/'installing.json').exists(),
                'established runtime cannot create replacement account authority')
        return {'accounts':accounts.provision_accounts(STATE)}
    if operation=='verified-accounts':
        expected=original_accounts();accounts.accounts(expected)
        return {'accounts':expected}
    if operation=='publish-helpers':
        namespace.publish(Path(__file__).resolve().parent)
        return {'published':True}
    paths()
    if operation == 'authorize':
        # The installed helper permits bounded future metadata; the carried
        # helper qualifies that target before installation. Old catalogs must
        # not prevent the CLI delivering a newly reviewed controller.
        value = request['target']
        require(set(value) == {'version', 'consensus_commit', 'execution_commit'}
                and re.fullmatch('[0-9]{1,5}\\.[0-9]{1,5}\\.[0-9]{1,5}', value['version'])
                and all(re.fullmatch('[a-f0-9]{40}', value[k]) for k in ('consensus_commit', 'execution_commit')),
                'invalid target metadata')
        STATE.authorize(c, request['intent'], value)
        return {'authorized': request['intent']}
    if operation == 'device-access':
        user = account()
        observed = inspect_device(c)
        os.chown(observed['path'], 0, user.pw_gid)
        os.chmod(observed['path'], 0o660)
        try:
            os.removexattr(observed['path'], 'system.posix_acl_access')
        except OSError as error:
            if error.errno not in (errno.ENODATA, errno.EOPNOTSUPP):
                raise
        device_access(observed)
        return {'device_access': 'dedicated native group'}
    if operation in ('prepared', 'confirmed'):
        STATE.current(c, request['intent'])
        require(STATE.get('installing.json')['intent'] == request['intent'], 'preparation target differs')
        if operation == 'confirmed':
            firewall('require-confirmed',request['run'],request['bundle'])
        return {'prepared': True}
    if operation in ('prepare-data','install-package'):
        target(request['target'])
        if request.get('initial') is True:
            require(not (ROOT / 'installed.json').exists(), 'init cannot change an installed node')
        else:
            STATE.current(c, request['intent'])
            require(STATE.get('installing.json')['intent'] == request['intent'], 'installing intent differs')
        if operation=='prepare-data':
            # Recheck both original UIDs after all preceding package/account
            # work and before any native-owned pathname can be mutated.
            quiescent()
            user=account()
            setup.prepare_data(STATE,c,user.pw_uid,user.pw_gid,final=request.get('initial') is not True)
            return {'native_data_prepared':True}
        setup.install_package(CATALOG)
        return {'package_verified': CATALOG['version']}
    if operation == 'status':
        report = observe.health(c)
        report['stopped'] = (ROOT / 'stopped').exists()
        report['retired'] = (ROOT / 'retired').exists()
        report['installing'] = (ROOT / 'installing.json').exists()
        report['activation_revoked'] = (ROOT / 'activation-revoked').exists()
        report['ready'] = report['ready'] and not any(report[k] for k in ('stopped', 'retired', 'installing', 'activation_revoked'))
        if report['ready']:
            try:
                check_ready(c)
            except Exception:
                report['ready'] = False
                report['readiness_error'] = 'identity, configuration, device or confirmed policy could not be verified'
        return report
    if operation == 'registration-preflight':
        require(c['role'] == 'validator', 'registration requires validator intent')
        check_ready(c)
        require(not setup.admitted_keys(CATALOG, c), 'identity already appears in retained validator epochs; observe its existing registration')
        return {'recent_epoch_membership': False, 'historical_registration_absence_proven': False}
    if operation == 'registration-status':
        return observe.registration(c, request['validator_id'])
    if operation in ('firewall-apply', 'firewall-confirm'):
        STATE.current(c, request['intent'])
        require(STATE.get('installing.json')['intent'] == request['intent'], 'firewall intent differs')
        firewall('apply' if operation=='firewall-apply' else 'confirm',request['run'],request['bundle'])
        return {'firewall': 'applied' if operation.endswith('apply') else 'confirmed'}
    if operation == 'configure':
        STATE.current(c, request['intent'])
        require(STATE.get('installing.json')['intent'] == request['intent'], 'configuration intent differs')
        firewall('require-confirmed',request['run'],request['bundle'])
        qualify_native()
        quiescent()
        read_identity(c)
        cpus = hardware()
        user = account()
        original = identity.decrypt(read(CONFIG / 'monad-secp.cred'), 'secp')
        setup.configure_node(CATALOG, c, original, user.pw_uid, user.pw_gid)
        gateway_account()
        nginx = Path('/usr/sbin/nginx')
        require(nginx.stat().st_uid == 0 and not nginx.stat().st_mode & 0o022, 'untrusted distribution nginx binary')
        STATE.put('gateway.json', {'sha256': package.hash_file(nginx)})
        configuration = units.install(CATALOG, c, cpus, request['rpc_allow'], request['monitoring_allow'],original_accounts())
        STATE.put('configuration.json', {'configuration': configuration, 'intent': request['intent']})
        execute(['/usr/bin/systemctl', 'daemon-reload'])
        return {'configured': True}
    if operation == 'finish':
        STATE.current(c, request['intent'])
        configured = STATE.get('configuration.json')
        require(configured['intent'] == request['intent'], 'configuration receipt was superseded')
        require((ROOT / 'device-initialized.json').exists(), 'TrieDB initialization is incomplete')
        firewall('require-confirmed',request['run'],request['bundle'])
        STATE.finish(c, request['intent'], {'configuration': configured['configuration']})
        return {'installed': True}
    if operation == 'recover-device':
        return recover_device(c)
    if operation in ('import-identity', 'restore-identity'):
        quiescent()
        qualify_native()
        if operation == 'import-identity':
            STATE.current(c, request['intent'])
            if not (CONFIG / 'identity.json').exists():
                require(not setup.admitted_keys(CATALOG, c),
                        'already-admitted keys require a separately reviewed migration with source-host fencing')
            identity.import_once(CONFIG, json_bytes(request['identity']), expected_keys(c), verify_key)
        else:
            require((ROOT / 'stopped').exists() or (ROOT / 'retired').exists(), 'explicit stop required before restoration')
            identity.restore(CONFIG, json_bytes(request['identity']), expected_keys(c), verify_key)
        return {'public': expected_keys(c), 'service': 'stopped'}
    if operation == 'begin':
        accounts.accounts(original_accounts())
        target(request['target'])
        hardware()
        capacity()
        inspect_device(c)
        STATE.begin(c, request['intent'], request['target'], stop_native)
        return {'installing': True}
    if operation == 'initialize-device':
        initialize_device(c, request['intent'], request.get('explicit'))
        return {'device_initialized': True}
    if operation == 'check-identity':
        qualify_native()
        read_identity(c)
        return {'public': expected_keys(c), 'original_bytes_match': True}
    if operation == 'guard':
        check_ready(c)
        return {'authorized': True}
    if operation in ('start', 'restart', 'activate'):
        if operation == 'restart':
            STATE.cancel(c, False, stop_native)
        manual = operation != 'activate' and (ROOT / 'stopped').exists()
        check_ready(c, intent=request.get('intent') if operation == 'activate' else None, manual=manual)
        processes.start_safe(account().pw_uid, approved_processes(), release_dir())
        processes.start_safe(gateway_account().pw_uid, gateway_processes(), Path('/usr'), gateway=True)
        if manual:
            STATE.manual_ready(c)
        try:
            execute(['/usr/bin/systemctl', 'enable', 'erpc-monad-memory.service', 'erpc-monad-firewall.service',
                     'erpc-monad-execution.service', 'erpc-monad-bft.service', 'erpc-monad-rpc.service',
                     'erpc-monad-gateway.service', 'erpc-monad-cleanup.timer'])
            execute(['/usr/bin/systemctl', 'start', 'erpc-monad-execution.service', 'erpc-monad-bft.service',
                     'erpc-monad-rpc.service', 'erpc-monad-gateway.service', 'erpc-monad-cleanup.timer'], timeout=300)
            started()
        except Exception:
            STATE.cancel(c,False,stop_native)
            raise
        if operation == 'activate':
            STATE.consume(c, request['intent'])
        return {'service_started': True, 'registration_submitted': False}
    raise Refused('unsupported Monad controller operation')


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(os.geteuid() == 0, 'root is required')
    namespace.paths(runtime=False)
    if len(sys.argv) == 3 and sys.argv[1] == 'memory':
        owned_directory(ROOT)
        c = STATE.get('owner.json')['contract']
        require(c['owner'] == token(sys.argv[2]), 'memory unit ownership differs')
        STATE.guard(c)
        hugepages()
        return
    if len(sys.argv)==3 and sys.argv[1]=='firewall-load':
        c=STATE.get('owner.json')['contract']
        require(c['owner']==token(sys.argv[2]),'firewall unit ownership differs')
        firewall('load')
        return
    if len(sys.argv) == 3 and sys.argv[1] in ('condition','guard'):
        owned_directory(ROOT)
        c = STATE.get('owner.json')['contract']
        require(c['owner'] == token(sys.argv[2]), 'unit ownership differs')
        print(json.dumps(dispatch({'contract': c, 'operation': 'guard'})))
        return
    if len(sys.argv) == 5 and sys.argv[1] == 'logs':
        c = STATE.get('owner.json')['contract']
        require(c['owner'] == token(sys.argv[2]) and sys.argv[4] in ('follow', 'once'), 'journal ownership differs')
        lines = int(sys.argv[3])
        require(0 <= lines <= 10000, 'invalid journal bound')
        args = ['/usr/bin/journalctl', '--no-pager', '-o', 'short-iso', '-n', str(lines)]
        for unit in processes.UNITS:
            args += ['-u', unit]
        if sys.argv[4] == 'follow':
            args.append('-f')
        os.execve(args[0], args, __import__('erpc_monad_common').ENV)
    require(sys.argv[1:] in ([], ['within-run']), 'invalid controller invocation')
    data = sys.stdin.buffer.read(65537)
    require(len(data) <= 65536, 'controller input exceeds limit')
    request = unique_json(data)
    if sys.argv[1:] == ['within-run']:
        print(json.dumps(dispatch(request), separators=(',', ':')))
        return
    lock = Path('/opt/erpc')
    owned_directory(lock, True)
    fd = os.open(lock, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        print(json.dumps(dispatch(request), separators=(',', ':')))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        sys.exit(255 if len(sys.argv)>1 and sys.argv[1]=='condition' else 1)
    except Exception:
        print('Monad operation failed; sensitive native output was withheld', file=sys.stderr)
        sys.exit(255 if len(sys.argv)>1 and sys.argv[1]=='condition' else 1)
