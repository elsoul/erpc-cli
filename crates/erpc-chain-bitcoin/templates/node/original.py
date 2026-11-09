# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Bitcoin account and filesystem authority.

Compiled before control.py into the single carried/installed controller. No
neighbor module is imported at privileged runtime. Names are only allocation
labels; startup and retained shutdown use the recorded original numeric IDs.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import stat

ACCOUNT_NAME = 'erpc-bitcoin'
MACHINE_FILE = Path('/etc/machine-id')


def public_user(value):
    return {'name':value.pw_name,'uid':value.pw_uid,'gid':value.pw_gid,
            'home':value.pw_dir,'shell':value.pw_shell}


def public_group(value):
    return {'name':value.gr_name,'gid':value.gr_gid,'members':sorted(value.gr_mem)}


def lookup(call, value):
    try: return call(value)
    except KeyError: return None


def account_namespace():
    users = [public_user(value) for value in pwd.getpwall()]
    groups = [public_group(value) for value in grp.getgrall()]
    require(len({value['name'] for value in users}) == len(users) and
            len({value['name'] for value in groups}) == len(groups), 'ambiguous account enumeration')
    return users, groups


def original_record(name):
    path = ROOT / name
    protected(path)
    require(path.stat().st_size <= 65536, 'original authority record is oversized')
    return json.loads(path.read_bytes())


def original_write(name, value):
    atomic(ROOT / name, json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def account_shape(record):
    require(isinstance(record,dict) and set(record)=={'name','uid','gid','home','shell'} and
            record['name'] in (ACCOUNT_NAME,'bitcoin') and
            type(record['uid']) is int and 0 < record['uid'] < 2**31 and
            type(record['gid']) is int and 0 < record['gid'] < 2**31 and
            isinstance(record['home'],str) and Path(record['home']).is_absolute() and
            '..' not in Path(record['home']).parts and record['shell']=='/usr/sbin/nologin',
            'invalid original Bitcoin account record')
    return record


def observed_account(record, missing=False):
    """Reconcile both enumeration and keyed NSS APIs; never assume they agree."""
    account_shape(record)
    users, groups = account_namespace()
    user_by_name = lookup(pwd.getpwnam,record['name'])
    user_by_id = lookup(pwd.getpwuid,record['uid'])
    group_by_name = lookup(grp.getgrnam,record['name'])
    group_by_id = lookup(grp.getgrgid,record['gid'])
    selected_users = [row for row in users if row['name']==record['name'] or row['uid']==record['uid']]
    selected_groups = [row for row in groups if row['name']==record['name'] or row['gid']==record['gid']]
    group = {'name':record['name'],'gid':record['gid'],'members':[]}
    if user_by_name is None and user_by_id is None and not selected_users:
        require(missing, 'original Bitcoin user disappeared')
        user_present = False
    else:
        require(user_by_name is not None and user_by_id is not None and
                public_user(user_by_name)==record and public_user(user_by_id)==record and
                selected_users==[record], 'original Bitcoin numeric user was reassigned')
        user_present = True
    if group_by_name is None and group_by_id is None and not selected_groups:
        require(missing, 'original Bitcoin group disappeared')
        group_present = False
    else:
        require(group_by_name is not None and group_by_id is not None and
                public_group(group_by_name)==group and public_group(group_by_id)==group and
                selected_groups==[group], 'original Bitcoin numeric group was reassigned')
        group_present = True
    require(not any(row['gid']==record['gid'] and row['name']!=record['name'] for row in users) and
            not any(record['name'] in row['members'] for row in groups),
            'Bitcoin group membership is not dedicated')
    if user_present:
        require(group_present and set(os.getgrouplist(record['name'],record['gid']))=={record['gid']},
                'original Bitcoin supplementary groups changed')
    return user_present, group_present


def account_plan():
    users, groups = account_namespace()
    require(not any(row['name']==ACCOUNT_NAME for row in users+groups) and
            lookup(pwd.getpwnam,ACCOUNT_NAME) is None and lookup(grp.getgrnam,ACCOUNT_NAME) is None,
            'a receipt-free Bitcoin runtime account already exists')
    used = {row['uid'] for row in users} | {row['gid'] for row in users} | {row['gid'] for row in groups}
    for value in range(20000,60000):
        if value not in used and lookup(pwd.getpwuid,value) is None and lookup(grp.getgrgid,value) is None:
            return {'name':ACCOUNT_NAME,'uid':value,'gid':value,
                    'home':str(ROOT/'data'),'shell':'/usr/sbin/nologin'}
    raise Refused('no unused dedicated numeric Bitcoin account is available')


def account_reserve(state):
    expected = contract(state)
    path = ROOT/'account-intent.json'
    if path.exists() or path.is_symlink():
        intent = original_record(path.name)
        require(set(intent)=={'contract','account'} and intent['contract']==expected,
                'original Bitcoin account reservation belongs to another owner')
        observed_account(intent['account'],missing=True)
    else:
        intent = {'contract':expected,'account':account_plan()}
        original_write(path.name,intent)
    # Repeat the barrier even after an earlier rename whose directory fsync
    # failed. No NSS creation may precede durable original numeric reservation.
    synchronize(path); synchronize(ROOT)
    return intent['account']


def account_ensure(state):
    if (ROOT/'account.json').exists() or (ROOT/'account.json').is_symlink():
        record = verified_account(state)
        synchronize(ROOT/'account.json'); synchronize(ROOT)
        return record
    record = account_reserve(state)
    user, group = observed_account(record,missing=True)
    if not group:
        run(['/usr/sbin/groupadd','--system','--gid',str(record['gid']),record['name']])
        user, group = observed_account(record,missing=True)
        require(group, 'original Bitcoin group creation is incomplete')
    if not user:
        run(['/usr/sbin/useradd','--system','--uid',str(record['uid']),'--gid',str(record['gid']),
             '--home-dir',record['home'],'--no-create-home','--shell',record['shell'],
             '--no-user-group','--no-log-init',record['name']])
    observed_account(record)
    original_write('account.json',{'contract':contract(state),'account':record})
    return record


def retained_account(state):
    value = original_record('account-intent.json')
    require(set(value)=={'contract','account'} and value['contract']==contract(state),
            'original Bitcoin account scope changed')
    return account_shape(value['account'])


def verified_account(state):
    record = retained_account(state)
    require(original_record('account.json')=={'contract':contract(state),'account':record},
            'original Bitcoin account creation is incomplete')
    observed_account(record)
    return record


def volume_observation(path):
    probe = path
    while not probe.exists() and not probe.is_symlink():
        probe = probe.parent
    before = probe.lstat()
    require(stat.S_ISDIR(before.st_mode), 'original volume probe is not a real directory')
    rows = json.loads(run(['/usr/bin/findmnt','--json','--target',str(probe),
                          '--output','UUID,FSTYPE,OPTIONS']))
    require(set(rows)=={'filesystems'} and isinstance(rows['filesystems'],list) and
            len(rows['filesystems'])==1, 'original volume has ambiguous mount identity')
    value = rows['filesystems'][0]
    require(set(value)=={'uuid','fstype','options'} and value['fstype'] in ('ext4','xfs') and
            isinstance(value['uuid'],str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value['uuid']) and
            any(char not in '0-' for char in value['uuid']) and isinstance(value['options'],str) and
            'rw' in value['options'].split(',') and 'ro' not in value['options'].split(','),
            'Bitcoin storage requires a writable original ext4/xfs filesystem UUID')
    after = probe.lstat()
    require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),
            'Bitcoin storage changed during filesystem observation')
    return {'uuid':value['uuid'],'fstype':value['fstype'],'device':after.st_dev}


def mount_topology():
    probe = ROOT
    while not probe.exists() and not probe.is_symlink(): probe = probe.parent
    value = json.loads(run(['/usr/bin/findmnt','--json','--submounts','--target',str(probe),'--output','TARGET']))
    require(set(value)=={'filesystems'} and isinstance(value['filesystems'],list),
            'Bitcoin mount topology is unavailable')
    pending = list(value['filesystems']); seen = []
    while pending:
        row = pending.pop()
        require(isinstance(row,dict) and set(row) <= {'target','children'} and isinstance(row.get('target'),str),
                'invalid Bitcoin mount topology')
        path = Path(row['target'])
        require(path.is_absolute() and os.path.normpath(str(path))==str(path), 'invalid mount target')
        if path==ROOT or ROOT in path.parents:
            require(path in (ROOT,ROOT/'data') and path not in seen,
                    'nested or stacked Bitcoin storage mounts are refused')
            seen.append(path)
        children = row.get('children',[])
        require(isinstance(children,list), 'invalid descendant mount list')
        pending.extend(children)


def persistent_volume(observed):
    return {name:observed[name] for name in ('uuid','fstype')}


def fresh_directory(path, allowed=()):
    protected(path,directory=True,missing=True)
    if not path.exists(): return
    require(set(child.name for child in path.iterdir()) <= {'lost+found',*allowed},
            'unknown Bitcoin storage content requires explicit original recovery')
    recovered = path/'lost+found'
    if recovered.exists() or recovered.is_symlink():
        protected(recovered,directory=True)
        require(not any(recovered.iterdir()), 'filesystem recovery content must be preserved and inspected')


def initial_layout():
    fresh_directory(ROOT,allowed=('data',))
    fresh_directory(ROOT/'data')
    mount_topology()
    root, data = volume_observation(ROOT), volume_observation(ROOT/'data')
    return {'root':persistent_volume(root),'data':persistent_volume(data),
            'root_inode':ROOT.lstat().st_ino if ROOT.exists() else None,
            'data_inode':(ROOT/'data').lstat().st_ino if (ROOT/'data').exists() else None}


def verify_layout(state):
    layout = state.get('layout')
    require(isinstance(layout,dict) and set(layout)=={'root','data','root_inode','data_inode'} and
            type(layout['root_inode']) is int and layout['root_inode']>0,
            'original Bitcoin filesystem identity is unavailable; explicit legacy migration is required')
    mount_topology()
    root, data = volume_observation(ROOT), volume_observation(ROOT/'data')
    require(persistent_volume(root)==layout['root'] and persistent_volume(data)==layout['data'] and
            ROOT.lstat().st_ino==layout['root_inode'], 'original Bitcoin ROOT or DATA filesystem was replaced')
    if layout['data_inode'] is not None:
        require(type(layout['data_inode']) is int and layout['data_inode']>0 and
                (ROOT/'data').is_dir() and not (ROOT/'data').is_symlink() and
                (ROOT/'data').lstat().st_ino==layout['data_inode'], 'original Bitcoin DATA inode changed')
    return root, data


def prepare_data(state, account):
    if state.get('data_ready') is True:
        verified_data(state,account)
        return
    _, volume = verify_layout(state)
    path = ROOT/'data'
    if state['layout']['data_inode'] is None:
        fresh_directory(path)
        path.mkdir(mode=0o700,exist_ok=True)
        synchronize(ROOT)
        require(path.lstat().st_dev==volume['device'], 'new DATA is on an unexpected filesystem')
        state['layout']['data_inode'] = path.lstat().st_ino
        save(state)
    # The original inode must be durable before granting the service account
    # access; a previous post-rename sync failure must not bypass that barrier.
    synchronize(ROOT/'owner.json'); synchronize(ROOT)
    before = path.lstat()
    require(stat.S_ISDIR(before.st_mode) and before.st_ino==state['layout']['data_inode'] and
            before.st_dev==volume['device'] and before.st_uid in (ROOT_UID,account['uid']) and
            before.st_gid in (ROOT_GID,account['gid']) and not before.st_mode&0o022,
            'original Bitcoin DATA ownership differs before provisioning')
    if not state.get('data_ready'):
        require(set(child.name for child in path.iterdir()) <= {'lost+found'},
                'uninitialized original DATA contains unknown native history')
        recovered = path/'lost+found'
        if recovered.exists() or recovered.is_symlink():
            protected(recovered,directory=True)
            require(not any(recovered.iterdir()), 'original DATA recovery content must be preserved')
    descriptor = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino), 'original DATA changed while opening')
        os.fchown(descriptor,account['uid'],account['gid'])
        os.fchmod(descriptor,0o700)
        os.fsync(descriptor)
        current = path.lstat()
        require((current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino), 'original DATA changed during provisioning')
    finally: os.close(descriptor)
    synchronize(ROOT)
    state['data_ready'] = True
    save(state)


def verified_data(state, account):
    _, volume = verify_layout(state)
    require(state.get('data_ready') is True, 'original Bitcoin DATA provisioning is incomplete')
    metadata = (ROOT/'data').lstat()
    require(metadata.st_dev==volume['device'] and metadata.st_uid==account['uid'] and
            metadata.st_gid==account['gid'] and metadata.st_mode&0o7777==0o700,
            'original Bitcoin DATA ownership or private mode changed')
    return volume


def machine_identity():
    protected(MACHINE_FILE)
    require(MACHINE_FILE.stat().st_size <= 128, 'invalid machine identity size')
    raw = MACHINE_FILE.read_bytes().strip()
    require(re.fullmatch(b'[a-f0-9]{32}',raw) and raw!=b'0'*32, 'original machine identity is unavailable')
    return hashlib.sha256(raw).hexdigest()


def original_runtime(state, account_required=True):
    require(state.get('origin') in ('fresh','verified-legacy') and
            isinstance(state.get('host_binding'),str) and re.fullmatch('[a-f0-9]{64}',state['host_binding']) and
            state.get('machine_sha256')==machine_identity(),
            'original host authority is unavailable or changed; explicit legacy migration is required')
    require(ROOT.lstat().st_mode&0o7777==0o755, 'original Bitcoin root traversal mode changed')
    verify_layout(state)
    if account_required:
        account = verified_account(state)
        verified_data(state,account)
        return account
    return None


def retained_origin(state):
    require(state.get('origin') in ('fresh','verified-legacy') and
            state.get('machine_sha256')==machine_identity(), 'original host authority changed')
    layout=state.get('layout')
    require(isinstance(layout,dict) and isinstance(layout.get('root'),dict), 'original ROOT receipt is missing')
    observed=volume_observation(ROOT)
    require(persistent_volume(observed)==layout['root'] and ROOT.lstat().st_ino==layout['root_inode'],
            'original ROOT authority was replaced; no service mutation is authorized')


def data_before_accounts(state):
    verify_layout(state)
    data = ROOT/'data'
    if not data.exists() and not data.is_symlink(): return
    info = data.lstat()
    record = retained_account(state) if (ROOT/'account-intent.json').exists() else None
    allowed = {(ROOT_UID,ROOT_GID)}
    if record is not None: allowed.add((record['uid'],record['gid']))
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid) in allowed and not info.st_mode&0o022,
            'prepared Bitcoin DATA ownership is unproven; account creation refused')


def recover_initial_owner(request):
    pending = ROOT/'owner.json.new'
    if not pending.exists() and not pending.is_symlink(): return
    value = original_record(pending.name)
    expected = set(contract(request)) | {'phase','origin','layout','machine_sha256','data_ready','source_started'}
    require(set(value)==expected and value['phase']=='v3:prepared' and value['origin']=='fresh' and
            value['data_ready'] is False and value['source_started'] is False,
            'unproven pending owner must be retained for explicit recovery')
    value['phase']='prepared'
    check(value,request)
    original_runtime(value,account_required=False)
    fresh_directory(ROOT,allowed=('data','owner.json.new'))
    fresh_directory(ROOT/'data')
    require(not loaded() and not loaded('bitcoind'), 'an unowned runtime appeared during initial reservation')
    synchronize(pending); synchronize(ROOT)
    os.replace(pending,ROOT/'owner.json')
    synchronize(ROOT)


def runtime_scope(state):
    return {'contract':contract(state),'machine_sha256':state['machine_sha256'],
            'layout':state['layout'],'account':retained_account(state)}


def native_key(pin):
    release_pin({'pin':pin})
    return hashlib.sha256(json.dumps(pin,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def native_releases(state, optional=False):
    path = ROOT/'native-releases.json'
    if not path.exists() and not path.is_symlink():
        require(optional, 'original native source receipts are missing')
        return {'scope':runtime_scope(state),'releases':{}}
    value = original_record(path.name)
    require(set(value)=={'scope','releases'} and value['scope']==runtime_scope(state) and
            isinstance(value['releases'],dict) and len(value['releases'])<=128,
            'original native source history differs')
    for key,row in value['releases'].items():
        require(set(row)=={'pin','daemon_sha256','client_sha256'} and native_key(row['pin'])==key and
                all(isinstance(row[field],str) and re.fullmatch('[a-f0-9]{64}',row[field])
                    for field in ('daemon_sha256','client_sha256')), 'invalid original native image receipt')
    return value


def register_native(state, pin, daemon, client):
    value = native_releases(state,optional=True)
    row = {'pin':pin,'daemon_sha256':daemon,'client_sha256':client}
    for saved in value['releases'].values():
        require(saved['pin']['platform']==pin['platform'], 'original native architecture cannot change')
        if version(saved['pin']['version'])==version(pin['version']):
            require(saved==row, 'same-version native source substitution is refused')
    value['releases'][native_key(pin)] = row
    require(len(value['releases'])<=128, 'original native source history exceeds its bound')
    original_write('native-releases.json',value)
    synchronize(ROOT/'native-releases.json'); synchronize(ROOT)


def source_floor(state):
    releases = native_releases(state)
    floor = None
    for name in ('source-floor.pending.json','source-floor.json'):
        path = ROOT/name
        if not path.exists() and not path.is_symlink(): continue
        value = original_record(name)
        require(set(value)=={'scope','source'} and value['scope']==runtime_scope(state) and
                value['source'] in releases['releases'], 'original opened-source floor is unavailable or foreign')
        selected = releases['releases'][value['source']]['pin']
        if floor is None or version(selected['version'])>version(floor['version']): floor=selected
        elif version(selected['version'])==version(floor['version']):
            require(selected==floor, 'ambiguous original opened-source identity')
    require(floor is not None or state.get('source_started') is False,
            'original opened-source floor is missing; automatic DB adoption is refused')
    return floor


def check_source_floor(state, pin, new_open=False):
    floor = source_floor(state)
    if floor is None:
        require(new_open and state.get('origin')=='fresh', 'native DB opening has no durable source floor')
        return
    require(version(pin['version'])>=version(floor['version']), 'native database source downgrade is refused')
    if version(pin['version'])==version(floor['version']):
        require(pin==floor, 'same-version opened source substitution is refused')
    return floor


def reserve_source(state):
    pin = state['installed']
    check_source_floor(state,pin,new_open=True)
    value = {'scope':runtime_scope(state),'source':native_key(pin)}
    require(value['source'] in native_releases(state)['releases'], 'unverified native source cannot open original data')
    if state.get('source_started') is False:
        require(set(path.name for path in (ROOT/'data').iterdir()) <= {'lost+found'},
                'unexpected unrecorded native history requires explicit recovery')
    original_write('source-floor.pending.json',value)
    synchronize(ROOT/'source-floor.pending.json'); synchronize(ROOT)
    original_write('source-floor.json',value)
    synchronize(ROOT/'source-floor.json'); synchronize(ROOT)


def verified_native(state):
    pin = state['installed']
    row = native_releases(state)['releases'].get(native_key(pin))
    require(row is not None, 'installed source lacks its original authenticated image receipt')
    for name,field in (('bitcoind','daemon_sha256'),('bitcoin-cli','client_sha256')):
        path=release_dir(pin)/'bin'/name
        protected(path)
        require(path.stat().st_mode&0o7777==0o755 and image_hash(path)==row[field],
                'original native executable bytes changed')
    return row
