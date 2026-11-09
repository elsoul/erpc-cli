# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Host contract, closed deployment inputs and startup verification for RPC only."""
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import shutil
import stat

import erpc_hl_artifact as artifact
import erpc_hl_processes as processes
import erpc_hl_public as public
import erpc_hl_setup as setup
import erpc_hl_units as units
from erpc_hl_common import ROOT, CONFIG, HELPERS, RELEASES, RUNTIME_FILES, RUNTIME_PROFILES, atomic, digest, execute, fsync_dir, json_bytes, owned_directory, read, require, token, unique_json
from erpc_hl_state import State
from erpc_hl_trust import trusted_release

SOURCE = Path(__file__).absolute().parent
SYSTEMD = Path('/etc/systemd/system')
FIREWALL_ROOT = Path('/etc/erpc/hyperliquid')


def protected_file(path):
    owned_directory(path.parent)
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022, 'privileged file is foreign, linked or writable')


def owned_units():
    return (*processes.UNITS, 'erpc-hyperliquid-firewall.service')


def protected_tree(path):
    pending = [path]
    count = 0
    while pending:
        directory = pending.pop()
        owned_directory(directory)
        for entry in directory.iterdir():
            count += 1
            require(count <= 10000, 'privileged runtime namespace exceeds its expected bounds')
            if entry == HELPERS / 'current':
                trusted_release(str(HELPERS), [list(profile) for profile in RUNTIME_PROFILES])
            elif entry == HELPERS / 'current.pending':
                info = entry.lstat()
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0,
                        'unowned interrupted helper publication')
                target = Path(os.readlink(entry))
                require(target.parent == HELPERS / 'releases' and re.fullmatch('[a-f0-9]{64}', target.name),
                        'interrupted publication leaves the closed release namespace')
                protected_tree(target)
                profiles=[profile for profile in RUNTIME_PROFILES if set(child.name for child in target.iterdir()) == set(profile)]
                require(len(profiles)==1
                        and digest(b''.join(read(target / name) for name in profiles[0])) == target.name,
                        'interrupted publication does not select a complete verified runtime')
            elif entry.is_dir() and not entry.is_symlink():
                pending.append(entry)
            else:
                protected_file(entry)


def contract(value):
    require(isinstance(value, dict), 'a complete immutable contract is required')
    fields={'owner','network','role','public_ip'}
    if value.get('role')=='validator':fields.add('validator')
    require(set(value)==fields,'a complete immutable contract is required')
    token(value['owner'])
    require(value['network'] in ('mainnet', 'testnet') and value['role'] in ('rpc','validator'),
            'unsupported Hyperliquid role or network')
    public.public_ipv4(value['public_ip'])
    if value['role']=='validator':
        import erpc_hl_validator
        erpc_hl_validator.public_identity(value)
    return value


def policy(value):
    require(isinstance(value, dict) and set(value) == {'rpc_allow', 'management_allow'},
            'a complete public ingress policy is required')
    result = {name: setup.allow(values) for name, values in value.items()}
    require(all('/0' not in value for value in result['management_allow']),
            'management ingress cannot allow every address')
    return result


def helper_digest():
    value = hashlib.sha256()
    for name in RUNTIME_FILES:
        value.update(read(SOURCE / name))
    return value.hexdigest()


def qualified(request, exact=True):
    c = contract(request.get('contract'))
    target = request.get('target')
    fields={'id','sha256','signed_at','helper_sha','config_id'}
    if c['role']=='validator':fields.add('mode')
    require(isinstance(target, dict) and set(target) == fields,
            'a complete supervisor/configuration target is required')
    for name in ('sha256', 'helper_sha', 'config_id'):
        require(isinstance(target[name], str) and re.fullmatch('[a-f0-9]{64}', target[name]),
                'invalid bounded target digest')
    require(target['id'] == 'visor-' + target['sha256'][:16]
            and type(target['signed_at']) is int and 0 < target['signed_at'] < 4102444800,
            'invalid supervisor signature identity')
    selected = policy(request.get('policy'))
    if c['role']=='validator':
        require(target['mode'] in ('follower','validator') and not selected['rpc_allow'],
                'validator preparation requires an explicit mode and closed public RPC ingress')
    require(digest(json_bytes(selected)) == target['config_id'], 'policy differs from its authorized digest')
    catalog = unique_json(read(SOURCE / 'catalog.json'))
    profile = catalog['networks'][c['network']]
    if exact:
        require(all(target[name] == profile['supervisor'][name] for name in ('id', 'sha256', 'signed_at'))
                and target['helper_sha'] == helper_digest(), 'target is not qualified by this carried runtime')
    return c, target, selected, catalog, profile


def protected_paths(create=False):
    """Authenticate all privileged destinations before any copy or mkdir."""
    for path in (ROOT, CONFIG, HELPERS, RELEASES, FIREWALL_ROOT, SYSTEMD):
        if create:
            mode = 0o711 if path == ROOT else (0o700 if path == FIREWALL_ROOT else 0o755)
            owned_directory(path, create=True, mode=mode)
            if path != FIREWALL_ROOT:
                for parent in [*path.parents, path]:
                    require(parent.stat().st_mode & 0o001,
                            'public runtime path needs search permission for its dedicated reader')
        else:
            probe = path
            while not probe.exists() and not probe.is_symlink():
                probe = probe.parent
            owned_directory(probe)
    for path in (CONFIG, HELPERS, RELEASES, FIREWALL_ROOT):
        if path.exists():
            protected_tree(path)
    if HELPERS.parent.exists():
        protected_file(HELPERS.parent / 'rpc-firewall.py')
    if SYSTEMD.exists():
        for name in owned_units():
            protected_file(SYSTEMD / name)
            directory = SYSTEMD / (name + '.d')
            if directory.exists() or directory.is_symlink():
                owned_directory(directory)
                for entry in directory.iterdir():
                    require(entry.name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new'),
                            'unknown service override requires explicit operator recovery')
                    protected_file(entry)


def hardware(c):
    values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                  if '=' in line)
    require(values.get('ID', '').strip('"') == 'ubuntu'
            and values.get('VERSION_ID', '').strip('"') == '24.04'
            and platform.machine() == 'x86_64' and Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
            'the reviewed host requires Ubuntu24.04, x86_64 and unified cgroup v2')
    memory = next((line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                   if line.startswith('MemTotal:')), '')
    require(memory.isdigit() and int(memory) >= 120_000_000
            and len(os.sched_getaffinity(0)) >= (32 if c['role']=='validator' else 16),
            'native role requires 128 GB memory and its documented available CPU count')


def preflight(request):
    c, _, _, _, _ = qualified(request)
    protected_paths()
    state = State(ROOT)
    if (ROOT / 'owner.json').exists():
        state.check(c)
        return {'reserved': True}
    require(not ROOT.exists() or not any(ROOT.iterdir()), 'unowned data or lifecycle state cannot be adopted')
    import erpc_hl_validator
    erpc_hl_validator.fresh_namespace()
    for path in (CONFIG, HELPERS, RELEASES, FIREWALL_ROOT):
        require(not path.exists() and not path.is_symlink(), 'unowned runtime artifacts require explicit recovery')
    for name in owned_units():
        for path in (SYSTEMD / name, SYSTEMD / (name + '.d')):
            require(not path.exists() and not path.is_symlink(), 'unowned boot-unit artifacts cannot be adopted')
    for lookup in (pwd.getpwnam, grp.getgrnam):
        for name in (setup.NATIVE, setup.GATEWAY):
            try:
                lookup(name)
            except KeyError:
                continue
            raise ValueError('an unowned dedicated account or group already exists')
    for name in owned_units():
        result = execute(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', name], check=False)
        require(result.stdout.strip() == b'not-found', 'unowned Hyperliquid unit exists or cannot be inspected')
    hardware(c)
    setup.capacity(validator=c['role']=='validator')
    return {'reserved': False}


def reserve(request):
    existing = preflight(request)
    if existing['reserved']:
        return existing
    c = contract(request['contract'])
    state = State(ROOT)
    owned_directory(ROOT, create=True)
    # Native HOME is a child, while owner/intent files remain root0600. Permit
    # pathname traversal without exposing a listing of private controller state.
    os.chmod(ROOT, 0o711)
    state.put('owner.json', {'contract': c})
    return {'reserved': True}


def recorded_accounts():
    expected = State(ROOT).get('accounts.json')
    return setup.accounts(expected)


def stop_owned(retire=False):
    state = State(ROOT)
    if (ROOT / 'accounts.json').exists():
        record = state.get('accounts.json')
    elif (ROOT / 'account-reservation.json').exists():
        record = state.get('account-reservation.json')
    else:
        # No process/unit can have been published before numeric reservation.
        # A conflicting service is not adopted merely to make retirement pass.
        for name in processes.UNITS:
            result = execute(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', name], check=False)
            require(result.stdout.strip() == b'not-found', 'unreserved runtime needs explicit operator recovery')
        return
    require(set(record) == {setup.NATIVE, setup.GATEWAY}, 'dedicated account ownership is unavailable')
    require(all(isinstance(item, dict) and set(item) == {'uid', 'gid'}
                and type(item['uid']) is int and type(item['gid']) is int
                and 100 <= item['uid'] <= 999 and 100 <= item['gid'] <= 999
                for item in record.values()), 'invalid original dedicated identities')
    # Do not lose the original UID when an account entry is altered. Native
    # process identity/cgroup verification still refuses unrelated processes.
    failed = False
    try:
        processes.stop([record[name]['uid'] for name in (setup.NATIVE, setup.GATEWAY)])
    except Exception:
        failed = True
    if retire:
        for name in processes.UNITS:
            try:
                execute(['/usr/bin/systemctl', 'disable', name])
            except Exception:
                failed = True
    require(not failed, 'owned shutdown or retirement disable failed; original data is retained')


def public_receipt(receipt, network):
    expected_names = {'visor.json', 'public-ip', 'gateway.json', 'gossip.json'}
    required = {str(CONFIG / name) for name in expected_names if name != 'gossip.json' or network == 'mainnet'}
    required.update(str(CONFIG / 'gnupg' / name) for name in ('pubring.kbx', 'trustdb.gpg'))
    required.update(str(Path('/etc/systemd/system') / name) for name in
                    (*processes.UNITS, 'erpc-hyperliquid-firewall.service'))
    require(isinstance(receipt, dict) and set(receipt) == required,
            'public configuration receipt is incomplete or belongs to another network')
    for name, expected in receipt.items():
        path = Path(name)
        allowed = ((path.parent == CONFIG and path.name in expected_names)
                   or (path.parent == CONFIG / 'gnupg' and path.name in ('pubring.kbx', 'trustdb.gpg'))
                   or (path.parent == Path('/etc/systemd/system') and path.name in
                       (*processes.UNITS, 'erpc-hyperliquid-firewall.service')))
        require(allowed and isinstance(expected, str) and re.fullmatch('[a-f0-9]{64}', expected),
                'public configuration receipt names an unexpected file')
        owned_directory(path.parent)
        mode = 0o444 if path.parent == CONFIG / 'gnupg' else 0o644
        require(path.lstat().st_mode & 0o7777 == mode and digest(read(path)) == expected,
                'public configuration content or reader permissions changed after activation')


def firewall_token(receipt):
    require(isinstance(receipt, dict) and set(receipt) == {'run', 'bundle'}
            and isinstance(receipt['run'], str) and re.fullmatch('[a-z0-9-]{1,80}', receipt['run'])
            and isinstance(receipt['bundle'], str) and re.fullmatch('[a-f0-9]{64}', receipt['bundle']),
            'exact confirmed firewall receipt required')


def common_firewall():
    # Entry into this module already used the external complete-release loader.
    # Authenticate and read the standalone common helper from an opened regular
    # file; never execute a replaceable script merely to obtain its own guard.
    path = HELPERS.parent / 'rpc-firewall.py'
    owned_directory(path.parent)
    source = read(path)
    namespace = {'__name__': 'erpc_hyperliquid_firewall', '__file__': str(path),
                 '__package__': None, '__spec__': None, '__cached__': None}
    exec(compile(source, str(path), 'exec'), namespace)
    return namespace['Firewall']('hyperliquid')


def firewall(receipt):
    firewall_token(receipt)
    common_firewall().require_confirmed(receipt['run'], receipt['bundle'])


def firewall_operation(c, intent, receipt, action):
    require(action in ('apply', 'confirm'), 'unsupported firewall lifecycle phase')
    firewall_token(receipt)
    state = State(ROOT)
    operation = state.current(c, intent)
    require(state.get('prepared.json')['operation'] == operation, 'firewall target was not prepared')
    # Both phases already own the common lock, through the carried play or
    # controller respectively. Calling the class avoids a nested flock and
    # keeps native cancellation and confirmation inside one critical section.
    controller = common_firewall()
    operation_method = controller.apply if action == 'apply' else controller.confirm
    operation_method(receipt['run'], receipt['bundle'])
    state.current(c, intent)
    return {'firewall': action, 'confirmed': action == 'confirm'}


def ready(c, intent=None, manual=False):
    protected_paths()
    state = State(ROOT)
    installed = state.guard(contract(c), intent, manual)
    target = installed['operation']['target']
    catalog = unique_json(read(SOURCE / 'catalog.json'))
    profile = catalog['networks'][c['network']]
    require(target['helper_sha'] == helper_digest()
            and all(target[name] == profile['supervisor'][name] for name in ('id', 'sha256', 'signed_at')),
            'installed runtime differs from the loaded qualification')
    accounts = recorded_accounts()
    setup.storage_mounts()
    setup.capacity(accounts[setup.NATIVE],validator=c['role']=='validator')
    artifact.check(RELEASES / target['id'], profile['supervisor'], catalog['public_key'])
    receipt = installed['receipt']
    require(set(receipt) == {'configuration', 'firewall'}, 'installed startup receipt is incomplete')
    public_receipt(receipt['configuration'], c['network'])
    firewall(receipt['firewall'])
    if target.get('mode')=='validator':
        import erpc_hl_validator as validator
        import erpc_hl_validator_public as observations
        validator.identity(c)
        validator.native_path(c)
        result=observations.registration(profile,c['validator'])
        require(result['registered'],'original validator registration is unavailable')
    return installed, accounts, profile


def started(c,mode):
    State(ROOT).check(c)
    identities=recorded_accounts()
    selected=[('erpc-hyperliquid-node.service',setup.NATIVE)]
    if mode!='validator':selected.append(('erpc-hyperliquid-rpc.service',setup.GATEWAY))
    for unit,name in selected:
        raw=execute(['/usr/bin/systemctl','show',unit,
            '--property=LoadState,ActiveState,SubState,MainPID,User,Group,Result']).stdout
        require(len(raw)<=4096,'native startup observation exceeds its bound')
        rows={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=')
            require(separator and key not in rows,'ambiguous native startup observation')
            rows[key]=value
        expected=identities[name]
        require(set(rows)=={'LoadState','ActiveState','SubState','MainPID','User','Group','Result'}
                and rows['LoadState']=='loaded' and rows['Result']=='success'
                and rows['ActiveState']=='active' and rows['SubState']=='running'
                and rows['MainPID'].isascii() and rows['MainPID'].isdigit() and int(rows['MainPID'])>0
                and rows['User']==str(expected['uid']) and rows['Group']==str(expected['gid']),
                'native startup was skipped, failed or is not running under its original numeric identity')


def publish_helpers(expected):
    require(helper_digest() == expected, 'carried runtime differs from its authorized digest')
    owned_directory(HELPERS / 'releases', create=True, mode=0o755)
    destination = HELPERS / 'releases' / expected
    stage = HELPERS / 'releases' / (expected + '.partial')
    if not destination.exists():
        if stage.exists() or stage.is_symlink():
            protected_tree(stage)
            shutil.rmtree(stage)
        owned_directory(stage, create=True, mode=0o700)
        for name in RUNTIME_FILES:
            atomic(stage / name, read(SOURCE / name), 0o644)
        os.chmod(stage, 0o755)
        fsync_dir(stage)
        os.rename(stage, destination)
        fsync_dir(destination.parent)
    protected_tree(destination)
    require(set(path.name for path in destination.iterdir()) == set(RUNTIME_FILES),
            'installed runtime contains unexpected files')
    for name in RUNTIME_FILES:
        require(read(destination / name) == read(SOURCE / name), 'installed runtime content differs')
    pending = HELPERS / 'current.pending'
    if pending.exists() or pending.is_symlink():
        info = pending.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0, 'unowned helper publication pointer')
        pending.unlink()
    pending.symlink_to(destination, target_is_directory=True)
    os.replace(pending, HELPERS / 'current')
    fsync_dir(HELPERS)
    require(trusted_release(str(HELPERS), [list(RUNTIME_FILES)]) == str(destination),
            'published runtime failed external authentication')


def initialize(request):
    c, target, _, _, _ = qualified(request)
    reserve(request)
    state = State(ROOT)
    require(not (ROOT / 'installed.json').exists() and not (ROOT / 'installing.json').exists(),
            'retained installation requires deploy rather than initialization')
    protected_paths(create=True)
    identities = setup.provision_accounts(state)
    processes.quiescent([item['uid'] for item in identities.values()])
    setup.native_directories(identities[setup.NATIVE])
    publish_helpers(target['helper_sha'])
    state.check(c)
    return {'initialized': True, 'network': c['network'], 'role': c['role']}


def prepare(request):
    c, target, selected, catalog, profile = qualified(request)
    protected_paths()
    state = State(ROOT)
    state.check(c)
    identities = recorded_accounts()
    setup.capacity(identities[setup.NATIVE],validator=c['role']=='validator')
    intent = token(request.get('intent'))
    mode=target.get('mode','follower')
    if mode=='validator':
        qualify_activation(c,profile,state,identities,target)
    operation = state.begin(c, intent, target, stop_owned)
    protected_paths(create=True)
    setup.native_directories(identities[setup.NATIVE])
    if mode=='validator':
        import erpc_hl_validator
        erpc_hl_validator.native_path(c,create=True)
    release = artifact.install(RELEASES, profile, catalog['public_key'])
    peers_file = ROOT / 'peers.json'
    if peers_file.exists():
        peers_record = state.get('peers.json')
        require(peers_record.get('network') == c['network'], 'retained peer observation differs from the network')
        peers = peers_record['peers']
    else:
        peers = public.root_peers(profile)
        state.put('peers.json', {'network': c['network'], 'peers': peers})
    publish_helpers(target['helper_sha'])
    receipt = setup.install_configuration(c, profile, selected['rpc_allow'], peers,identities,mode=mode)
    receipt.update(setup.public_gnupg(release))
    public_receipt(receipt, c['network'])
    state.current(c, intent)
    state.put('prepared.json', {'operation': operation, 'configuration': receipt})
    execute(['/usr/bin/systemctl', 'daemon-reload'])
    if mode=='validator':execute(['/usr/bin/systemctl','disable','erpc-hyperliquid-rpc.service'])
    return {'prepared': True, 'supervisor': target['id'], 'child_update_policy': 'vendor-managed'}


def owned_observation(profile,identities,gateway=True):
    uid=identities[setup.NATIVE]['uid'];before=processes.listener(uid,3001)
    gateway_uid=identities[setup.GATEWAY]['uid']
    gateway_before=processes.listener(gateway_uid,8545,gateway=True) if gateway else None
    observation=public.observe(profile)
    require(processes.listener(uid,3001)==before
            and (not gateway or processes.listener(gateway_uid,8545,gateway=True)==gateway_before),
            'native or gateway listener changed during observation')
    images=processes.observed_images(uid)
    visor=[item for item in images if item['name']=='hl-visor']
    require(visor and all(item['sha256']==profile['supervisor']['sha256'] for item in visor),
            'observed supervisor differs from its qualified pinned bytes')
    return observation,images


def qualify_activation(c,profile,state,identities,target):
    import erpc_hl_validator as validator
    import erpc_hl_validator_public as observations
    require((ROOT/'installed.json').exists(),'complete the owned follower deployment before validator activation')
    validator.identity(c)
    membership=observations.registration(profile,c['validator'])
    require(membership['registered'],'external registration must complete before validator activation')
    installed=state.get('installed.json')
    if installed['operation']['target'].get('mode')!='validator':
        authorized={'contract':c,'target':target,'follower_receipt':installed}
        proof=ROOT/'validator-activation.json'
        if proof.exists():
            if state.get('validator-activation.json')==authorized:
                # A previous rename may have become visible before directory
                # fsync failed. Restore durability before follower shutdown.
                state.put('validator-activation.json',authorized)
                return
            require(not (ROOT/'installing.json').exists(),
                    'initial activation retry differs from its synchronized original follower')
            # Explicit recovery followed by a newly completed healthy follower
            # may qualify a different target; never reuse the earlier proof.
        observations.funding(profile,c['validator'],c['validator']['max_hot_usdc'])
        require(membership['jailed'] is True,'first activation requires the externally registered jailed signer')
        public_receipt(installed['receipt']['configuration'],c['network'])
        observed,_=owned_observation(profile,identities)
        require(observed['ready'],'first validator activation requires the owned synchronized follower')
        state.put('validator-activation.json',authorized)


def import_validator(request):
    import erpc_hl_validator as validator
    import erpc_hl_validator_public as observations
    c=contract(request.get('contract'));State(ROOT).check(c)
    recorded_accounts()
    identity=validator.public_identity(c)
    catalog=unique_json(read(SOURCE/'catalog.json'));profile=catalog['networks'][c['network']]
    # A third party can send funds to a public address. A later unsolicited
    # transfer must not revoke already-established same-host recovery authority.
    if not (ROOT/'validator-identity.json').exists():
        observations.funding(profile,identity,identity['max_hot_usdc'])
    value=request.get('key_file')
    require(isinstance(value,str) and len(value)<=4096,'bounded original native credential required on stdin')
    return validator.import_original(c,value.encode(),restore=request.get('restore'),
        unhosted=request.get('keys_unhosted'),stop=stop_owned)


def observe(c):
    protected_paths()
    state = State(ROOT)
    state.check(contract(c))
    phase = 'initialized'
    for name, value in (('installed.json', 'installed'), ('installing.json', 'preparing'),
                        ('stopped', 'stopped'), ('retired', 'retired')):
        if (ROOT / name).exists():
            phase = value
    result = {'ready': False, 'network': c['network'], 'role': c['role'], 'phase': phase,
              'child_update_policy': 'vendor-managed'}
    try:
        installed, identities, profile = ready(c)
        mode=installed['operation']['target'].get('mode','follower')
        observation,images=owned_observation(profile,identities,gateway=mode!='validator')
        result.update(observation, supervisor=installed['operation']['target']['id'], images=images)
        if c['role']=='validator':
            import erpc_hl_validator_public as observations
            membership=observations.registration(profile,c['validator'])
            result.update(mode=mode,node_ready=observation['ready'],validator=membership,
                          ready=observation['ready'] and mode=='validator' and membership['active'])
    except Exception:
        result['ready']=False
        result['inspection_error'] = 'startup requirements or owned native readiness could not be verified'
    if c['role']=='validator' and 'validator' not in result:
        try:
            import erpc_hl_validator_public as observations
            profile=unique_json(read(SOURCE/'catalog.json'))['networks'][c['network']]
            result['validator']=observations.registration(profile,c['validator'])
        except Exception:
            result['validator']={'state':'unknown','registered':None,'active':None}
    return result
