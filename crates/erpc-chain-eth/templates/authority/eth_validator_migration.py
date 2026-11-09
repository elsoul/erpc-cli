# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit original-validator evidence; current NSS never supplies original IDs."""
import fcntl
import os
from pathlib import Path
import re
import stat
from eth_files import atomic,checked_file,digest,encoded,read,require,root_directory,synchronize,unique
import eth_accounts as accounts
import eth_layout as layout
import eth_namespace as namespace
import eth_process as processes
import eth_source_floor as floor
import eth_validator_custody as custody
import eth_validator_units as units

CONTROL=Path('/usr/local/lib/erpc/eth-validator-control')
CONFIG=Path('/etc/erpc/eth-validator.json')
JWT=Path('/etc/erpc/eth-validator-jwt')
OLD_USERS=('ev-reth','ev-beacon','ev-validator')
OLD_UNITS=(units.UNITS[0],units.UNITS[2],units.UNITS[3])
PROC=Path('/proc')


def evidence(value,expected):
    require(isinstance(value,dict) and set(value)=={'schema','contract','machine','legacy_accounts','opened_sources','records','signer_pubkey'}
            and type(value['schema'])is int and value['schema']==1 and value['contract']==expected
            and value['machine']==custody.machine(),'original validator evidence belongs to another host')
    require(isinstance(value['signer_pubkey'],str) and (value['signer_pubkey']=='' or re.fullmatch('0x[a-f0-9]{96}',value['signer_pubkey'])),
            'original inventory signer identity is invalid')
    selected=value['legacy_accounts']
    require(isinstance(selected,dict) and set(selected)=={'users','groups'} and set(selected['users'])==set(OLD_USERS)
            and set(selected['groups'])==set(OLD_USERS)|{'ev-engine'},'original validator account backup is incomplete')
    ids=[]
    for name,identity in selected['users'].items():
        require(isinstance(identity,dict) and set(identity)=={'uid','gid','home','shell'}
                and type(identity['uid'])is int and 100<=identity['uid']<=999
                and identity['gid']==selected['groups'][name] and identity['shell']=='/usr/sbin/nologin'
                and identity['home'] in ('/nonexistent','/home/'+name),'unsupported historical validator account')
        ids.append(identity['uid'])
    gids=list(selected['groups'].values())
    require(len(set(ids))==3 and len(set(gids))==4 and all(type(gid)is int and 100<=gid<=999 for gid in gids),
            'original validator users/groups are not isolated')
    require(isinstance(value['records'],dict) and set(value['records'])=={'passwd','group','machine','opened_sources'}
            and all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in value['records'].values()),
            'independent original backup record digests are required')
    floor.historical(value['opened_sources']);return selected


def original_identities(proof,plan=None):
    """Every original identity must still exist; never recreate a lost signer UID."""
    legacy=proof['legacy_accounts'];users,groups=accounts.snapshot()
    for name,identity in legacy['users'].items():
        wanted=(name,identity['uid'],identity['gid'],identity['home'],identity['shell'])
        named=accounts.lookup(accounts.pwd.getpwnam,name);numbered=accounts.lookup(accounts.pwd.getpwuid,identity['uid'])
        matches=[row for row in users if row.pw_name==name or row.pw_uid==identity['uid']]
        require(accounts.user_fields(named)==wanted and accounts.user_fields(numbered)==wanted and len(matches)==1
                and accounts.user_fields(matches[0])==wanted,'historical original validator account changed or disappeared')
        allowed={identity['gid']}|({legacy['groups']['ev-engine']} if name!='ev-validator' else set())
        require(set(os.getgrouplist(name,identity['gid']))==allowed,'original validator supplementary authority changed')
    for name,gid in legacy['groups'].items():
        named=accounts.lookup(accounts.grp.getgrnam,name);numbered=accounts.lookup(accounts.grp.getgrgid,gid)
        matches=[row for row in groups if row.gr_name==name or row.gr_gid==gid]
        require(named is not None and named.gr_gid==gid and len(matches)==1
                and accounts.group_fields(named)==accounts.group_fields(numbered)==accounts.group_fields(matches[0]),
                'historical original validator group changed')
        allowed={'ev-reth','ev-beacon'} if name=='ev-engine' else {name}
        if name=='ev-reth' and plan is not None:allowed.add('ev-transport')
        require(set(named.gr_mem)<=allowed and all(row.pw_name in OLD_USERS for row in users if row.pw_gid==gid),
                'original validator group is shared with an unrelated account')
    if plan is not None:accounts.verify(plan,partial=True)


def new_plan(proof):
    original_identities(proof);users,groups=accounts.snapshot();name='ev-transport'
    require(accounts.lookup(accounts.pwd.getpwnam,name) is None and accounts.lookup(accounts.grp.getgrnam,name) is None
            and all(row.pw_name!=name for row in users) and all(row.gr_name!=name for row in groups),
            'unknown transport identity cannot be adopted by migration')
    used={row.pw_uid for row in users}|{row.pw_gid for row in users}|{row.gr_gid for row in groups}
    numbers=[n for n in range(999,99,-1) if n not in used and accounts.lookup(accounts.pwd.getpwuid,n) is None and accounts.lookup(accounts.grp.getgrgid,n) is None]
    require(numbers,'no unused numeric transport identity is available');number=numbers[0]
    legacy=proof['legacy_accounts']
    plan={'schema':1,'role':'validator','groups':dict(legacy['groups'],**{name:number}),
          'users':{user:{key:identity[key] for key in ('uid','gid')} for user,identity in legacy['users'].items()},
          'homes':{user:identity['home'] for user,identity in legacy['users'].items()}}
    plan['users'][name]={'uid':number,'gid':number};plan['homes'][name]='/nonexistent'
    return accounts.validate(plan,'validator')


def stopped(run,plan):
    for name in OLD_UNITS:
        raw=run(['/usr/bin/systemctl','show',name,'--property=LoadState,ActiveState,MainPID'])
        values={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=');require(separator and key not in values,'ambiguous original legacy service metadata');values[key]=value
        require(values.get('LoadState') in ('loaded','masked','not-found') and values.get('MainPID')=='0'
                and values.get('ActiveState') in ('inactive','failed'),
                'stop original legacy clients independently before explicit authority migration')
    processes.quiescent(plan,{})


def known_definitions(config,templates):
    require(config['network'] in units.CHECKPOINT,'unknown original validator network')
    replacements={'eth_opt':str(namespace.PROFILES['validator']['opt']),'ev_root':str(layout.ROOTS['validator']),
                  'ev_network':config['network'],'ev_fee_recipient':config['fee_recipient'],
                  'ev_checkpoint[ev_network]':units.CHECKPOINT[config['network']]}
    result={}
    for name,template in zip(OLD_UNITS,('execution','beacon','validator')):
        text=read(templates/(template+'.service.j2'),65536).decode()
        for key,value in replacements.items():text=text.replace('{{ '+key+' }}',value)
        require('{{' not in text and '}}' not in text,'legacy unit template has unsupported selectors')
        result[name]=text
    return result


def native_definitions(raw,material,pubkey):
    """Only the old stock single-local-key profile can be converted automatically."""
    import yaml
    require(len(raw)<=128*1024,'legacy definitions exceed their bound')
    class Closed(yaml.SafeLoader):pass
    def mapping(loader,node):
        result={}
        for key,value in node.value:
            key=loader.construct_object(key);require(isinstance(key,str) and key not in result,'ambiguous legacy definition field')
            result[key]=loader.construct_object(value)
        return result
    Closed.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
    value=yaml.load(raw,Loader=Closed)
    require(isinstance(value,list) and len(value)==1 and isinstance(value[0],dict),'legacy validator definitions are not one original key')
    item=value[0];required={'enabled','voting_public_key','type','voting_keystore_path','voting_keystore_password'}
    optional={'description','graffiti','suggested_fee_recipient','gas_limit','builder_proposals','builder_boost_factor','prefer_builder_proposals','voting_keystore_password_path'}
    require(required<=set(item) and set(item)<=required|optional and item['enabled'] is True
            and item['voting_public_key']==pubkey and item['type']=='local_keystore'
            and item['voting_keystore_path']==str(layout.ROOTS['validator']/'vc'/'validators'/pubkey/'keystore.json')
            and item['voting_keystore_password']==material['password']
            and item.get('description','')==(material['keystore'].get('description') or '')
            and all(item.get(key) is None for key in optional-{'description'}),
            'legacy signing profile has custom authority/settings; preserve it instead of replacing it')
    return value


def private_native(relative,identity,limit=128*1024):
    """Read one known private VC member through original numeric-owned directories."""
    parts=Path(relative).parts;require(parts and all(part not in ('','..','.') for part in parts),'invalid original native path')
    parent=root_directory(layout.ROOTS['validator']);device=os.fstat(parent).st_dev
    try:
        for component in ('vc',*parts[:-1]):
            child=os.open(component,layout.FLAGS,dir_fd=parent)
            try:
                info=os.fstat(child)
                require(info.st_dev==device and info.st_uid==identity['uid'] and info.st_gid in (0,identity['gid'])
                        and stat.S_IMODE(info.st_mode)==0o700,'legacy native directory ownership differs')
            except BaseException:os.close(child);raise
            os.close(parent);parent=child
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno());checked_file(info,owner=identity['uid'],mode=0o600)
            require(info.st_dev==device and info.st_gid in (0,identity['gid']) and info.st_size<=limit,'legacy private native member differs')
            raw=stream.read(limit+1);require(len(raw)<=limit,'legacy member grew beyond its bound');return raw
    finally:os.close(parent)


def scope(expected,proof):
    config=unique(read(CONFIG,65536,mode=0o644))
    owner=unique(read(layout.ROOTS['validator']/'owner.json',65536,mode=0o600))
    require(isinstance(config,dict) and isinstance(owner,dict)
            and all(value.get('owner')==expected['owner'] and value.get('network')==expected['network'] for value in (config,owner))
            and owner.get('pubkey')==proof['signer_pubkey'],'legacy host scope or original inventory signer differs')
    return config,owner


def inspect(expected,proof,templates,run):
    legacy=evidence(proof,expected);original_identities(proof);namespace.paths('validator');layout.topology('validator')
    config,owner=scope(expected,proof)
    require(isinstance(config,dict) and set(config)=={'owner','network','fee_recipient','pair'}
            and config['owner']==expected['owner'] and config['network']==expected['network']
            and isinstance(config['fee_recipient'],str) and re.fullmatch('0x[a-f0-9]{40}',config['fee_recipient'])
            and config['fee_recipient']!='0x'+'0'*40,
            'legacy public configuration differs from original inventory authority')
    require(isinstance(owner,dict) and {'owner','network','state','pubkey'}<=set(owner)
            and set(owner)<={'owner','network','state','pubkey','material_digest','fenced_to'}
            and owner['owner']==expected['owner'] and owner['network']==expected['network']
            and owner['state'] in ('prepared','imported','fenced'),
            'legacy custody is incomplete, custom or belongs to another original owner')
    pair=Path(config['pair']);require(pair.parent==namespace.PROFILES['validator']['opt'],'legacy executable pair escapes its namespace')
    match=re.fullmatch(r'reth-(v[0-9]+\.[0-9]+\.[0-9]+)--lighthouse-(v[0-9]+\.[0-9]+\.[0-9]+)',pair.name)
    require(match is not None,'legacy pair is not a qualified stable version')
    commits=read(pair/'.verified',256).decode().split()
    require(len(commits)==2 and all(re.fullmatch('[a-f0-9]{40}',v) for v in commits),'legacy pair lacks its original source markers')
    for client,version,commit in zip(floor.CLIENTS,match.groups(),commits):
        recorded=proof['opened_sources'][client]
        floor.compare(dict(recorded,archive=None,binary=None),{'version':version,'commit':commit,'archive':None,'binary':None})
    wanted=known_definitions(config,templates)
    for name,text in wanted.items():require(read(namespace.SYSTEMD/name,65536)==text.encode(),'legacy service has custom settings; preserve it instead of replacing it')
    require(read(CONTROL,128*1024)==read(templates/'control.py',128*1024),'legacy management helper is not the supported original version')
    temporary={'schema':1,'role':'validator','users':{name:{key:row[key] for key in ('uid','gid')} for name,row in legacy['users'].items()},'groups':legacy['groups']}
    stopped(run,temporary)
    return config,owner,wanted


def preflight(state,expected,proof,templates,run):
    evidence(proof,expected);scope(expected,proof)
    if state.exists('legacy-migration.json'):
        state.check(expected);journal=state.get('legacy-migration.json')
        require(journal['evidence']==proof,'resume the original legacy evidence without replacing it')
        plan=accounts.validate(journal['plan'],'validator');original_identities(proof,plan)
        if state.exists('legacy-migration-complete.json'):
            require(state.get('legacy-migration-complete.json')['records']==proof['records'],'completed legacy conversion differs')
            return {'original_legacy_scope_verified':True,'already':True,'runtime_started':False}
        namespace.paths('validator');layout.topology('validator');stopped(run,plan)
        original_data(state,expected,plan,journal)
        for name,text in journal['units'].items():
            path=namespace.SYSTEMD/name
            if path.is_symlink():require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','legacy service mask changed')
            elif path.exists():require(read(path,65536)==text.encode(),'legacy service changed during conversion')
        if CONTROL.exists() and CONTROL.is_dir() and not CONTROL.is_symlink():
            descriptor=root_directory(CONTROL)
            try:require(not os.listdir(descriptor),'legacy helper tombstone has unknown code')
            finally:os.close(descriptor)
        elif CONTROL.exists() or CONTROL.is_symlink():
            require(digest(read(CONTROL,128*1024))==journal['helper_sha256'],'legacy helper changed during conversion')
    else:inspect(expected,proof,templates,run)
    return {'original_legacy_scope_verified':True,'already':False,'runtime_started':False}


def original_data(state,expected,plan,journal):
    from eth_migration import stable_layout
    current=data_record(expected,plan)
    require(stable_layout(current)==stable_layout(journal['layout']),'original legacy data binding changed')
    descriptor=root_directory(layout.ROOTS['validator'])
    try:require(layout.probe(layout.ROOTS['validator'],descriptor)==layout.filesystem(journal['filesystem']),
                'original legacy filesystem UUID/type changed')
    finally:os.close(descriptor)
    synchronize(state.path('legacy-migration.json'))


def observed_filesystem():
    descriptor=root_directory(layout.ROOTS['validator'])
    try:return layout.probe(layout.ROOTS['validator'],descriptor)
    finally:os.close(descriptor)


def data_record(expected,plan):
    root=root_directory(layout.ROOTS['validator'])
    try:
        info=os.fstat(root);require(stat.S_IMODE(info.st_mode)==0o711,'legacy original data root mode differs')
        require(set(os.listdir(root))<={'owner.json','control.lock','custody.json','reth','beacon','vc','lost+found'},
                'legacy data root contains unrecognized original material')
        if 'lost+found' in os.listdir(root):
            recovery=os.open('lost+found',layout.FLAGS,dir_fd=root)
            try:
                entry=os.fstat(recovery);require(entry.st_dev==info.st_dev and entry.st_uid==0 and not entry.st_mode&0o022 and not os.listdir(recovery),
                                                'legacy filesystem recovery directory is not empty and protected')
            finally:os.close(recovery)
        children={}
        for name,user in layout.USERS['validator'].items():
            child=os.open(name,layout.FLAGS,dir_fd=root)
            try:
                node=os.fstat(child);identity=plan['users'][user]
                require(node.st_dev==info.st_dev and node.st_uid==identity['uid'] and node.st_gid==identity['gid']
                        and stat.S_IMODE(node.st_mode)==0o700,'legacy data child differs from its original numeric account')
                children[name]=layout.binding(node)
            finally:os.close(child)
        return dict(layout.expected(expected,plan),binding=layout.binding(info),mode=0o711,children=children)
    finally:os.close(root)


def normalize_database(state,expected,plan):
    """Original old helper could leave the validators directory's GID as root."""
    identity=plan['users']['ev-validator'];vc=layout.open_native(state,expected,plan,'vc')
    try:
        directory=os.open('validators',layout.FLAGS,dir_fd=vc)
        try:
            info=os.fstat(directory)
            require(info.st_dev==os.fstat(vc).st_dev and info.st_uid==identity['uid'] and info.st_gid in (0,identity['gid'])
                    and stat.S_IMODE(info.st_mode)==0o700,'legacy signing directory is not the original private directory')
            os.fchown(directory,identity['uid'],identity['gid']);os.fsync(directory)
            fd=os.open('slashing_protection.sqlite',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            try:
                info=os.fstat(fd);checked_file(info,owner=identity['uid'],mode=0o600)
                require(info.st_dev==os.fstat(directory).st_dev and info.st_gid in (0,identity['gid']) and info.st_size>=4096
                        and os.read(fd,16)==b'SQLite format 3\0','legacy original slashing DB is missing or incompatible')
                os.fchown(fd,identity['uid'],identity['gid']);os.fsync(fd);os.fsync(directory);os.fsync(vc)
            finally:os.close(fd)
        finally:os.close(directory)
    finally:os.close(vc)
    import eth_validator_history as history
    return history.identity(state,expected,plan,durable=True)


def disable_old(state,journal,run):
    old_root=layout.ROOTS['validator'];owner=unique(read(old_root/'owner.json',65536,mode=0o600))
    fenced=dict(journal['owner'],state='fenced',fenced_to='original-authority-upgrade')
    require(owner in (journal['owner'],fenced),'legacy signer ownership changed during conversion')
    atomic(old_root/'owner.json',encoded(fenced));synchronize(old_root/'owner.json')
    directory=root_directory(namespace.SYSTEMD)
    try:
        for name,text in journal['units'].items():
            path=namespace.SYSTEMD/name
            if path.is_symlink():require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','legacy service mask changed')
            elif not path.exists():os.symlink('/dev/null',name,dir_fd=directory)
            else:
                require(read(path,65536)==text.encode(),'legacy service changed before masking')
                os.unlink(name,dir_fd=directory);os.symlink('/dev/null',name,dir_fd=directory)
            os.fsync(directory)
    finally:os.close(directory)
    run(['/usr/bin/systemctl','daemon-reload'])
    parent=root_directory(CONTROL.parent)
    try:
        if CONTROL.exists() and CONTROL.is_dir() and not CONTROL.is_symlink():
            descriptor=root_directory(CONTROL)
            try:require(not os.listdir(descriptor),'legacy helper tombstone contains unexpected code')
            finally:os.close(descriptor)
        else:
            if CONTROL.exists() or CONTROL.is_symlink():
                require(digest(read(CONTROL,128*1024))==journal['helper_sha256'],'legacy helper changed before retirement')
                os.unlink(CONTROL.name,dir_fd=parent)
            os.mkdir(CONTROL.name,0o700,dir_fd=parent)
        os.fsync(parent)
    finally:os.close(parent)


def no_loaded_old_helper():
    """A queued old SSH helper must finish its fenced request before conversion completes."""
    count=0
    for path in PROC.iterdir():
        if not path.name.isdecimal():continue
        count+=1;require(count<=1000000,'process namespace exceeds its bound')
        try:
            credentials=processes.credentials(path)
            if 0 not in credentials['Uid']:continue
            argv=processes.bounded(path/'cmdline',131072).split(b'\0')
            require(str(CONTROL).encode() not in argv,'an old management helper is still loaded; let it exit and repeat the same migration')
        except (FileNotFoundError,ProcessLookupError):continue


def database_binding(plan):
    identity=plan['users']['ev-validator'];root=root_directory(layout.ROOTS['validator'])
    descriptors=[root]
    try:
        for name in ('vc','validators'):
            fd=os.open(name,layout.FLAGS,dir_fd=descriptors[-1]);descriptors.append(fd);info=os.fstat(fd)
            require(info.st_uid==identity['uid'] and info.st_gid in (0,identity['gid']) and info.st_dev==os.fstat(root).st_dev
                    and stat.S_IMODE(info.st_mode)==0o700,'original legacy signer directory differs')
        directory=descriptors[-1]
        fd=os.open('slashing_protection.sqlite',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory);descriptors.append(fd)
        info=os.fstat(fd);checked_file(info,owner=identity['uid'],mode=0o600)
        require(info.st_gid in (0,identity['gid']) and info.st_dev==os.fstat(root).st_dev and info.st_size>=4096
                and os.read(fd,16)==b'SQLite format 3\0','original legacy slashing DB is unavailable')
        return {'inode':info.st_ino,'directory_inode':os.fstat(directory).st_ino}
    finally:
        for fd in reversed(descriptors):os.close(fd)


def legacy_material(owner,plan):
    if not owner['pubkey']:
        require(owner['state']=='prepared' and not (layout.ROOTS['validator']/'custody.json').exists(),
                'legacy empty signer has unresolved custody')
        return None,None
    require(owner['state'] in ('imported','fenced'),'complete original legacy key import required')
    raw=read(layout.ROOTS['validator']/'custody.json',16*1024*1024+128*1024,mode=0o600);material=unique(raw)
    require(isinstance(material,dict) and {'keystore','password','history'}<=set(material)
            and set(material)<={'keystore','password','history','source','destination'},'legacy original material fields differ')
    import hashlib,json
    require(hashlib.sha256(json.dumps(material,sort_keys=True).encode()).hexdigest()==owner.get('material_digest'),
            'legacy original custody does not match its retained import receipt')
    pubkey,_=custody.key_material({key:material[key] for key in ('keystore','password')})
    require(pubkey==owner['pubkey'],'legacy original consensus key differs')
    custody.history(material['history'],owner['network'],pubkey)
    definitions=private_native('validators/validator_definitions.yml',plan['users']['ev-validator'])
    native_definitions(definitions,material,pubkey)
    actual=unique(private_native('validators/'+pubkey+'/keystore.json',plan['users']['ev-validator']))
    require(actual==material['keystore'],'legacy native keystore differs from the original encrypted input')
    return material,definitions


def archived_definitions(state,raw=None):
    from eth_files import run
    path=state.path('legacy-definitions.cred');record='legacy-definitions.json'
    if not state.exists(record):
        require(isinstance(raw,bytes) and 0<len(raw)<=128*1024,'original private definition archive required')
        desired={'sha256':digest(raw)}
        if state.exists('legacy-definitions-intent.json'):require(state.get('legacy-definitions-intent.json')==desired,'original private archive input changed')
        else:
            require(not state.exists(path.name),'unowned private archive cannot be adopted')
            state.put('legacy-definitions-intent.json',desired)
        synchronize(state.path('legacy-definitions-intent.json'))
        if not state.exists(path.name):
            cipher=run(['/usr/bin/systemd-creds','encrypt','--name=erpc-ethereum-legacy-definitions','--with-key=host','-','-'],input_data=raw)
            require(0<len(cipher)<=512*1024,'legacy encrypted archive exceeds its bound');atomic(path,cipher)
        cipher=read(path,512*1024,mode=0o600);synchronize(path)
        restored=run(['/usr/bin/systemd-creds','decrypt','--name=erpc-ethereum-legacy-definitions','-','-'],input_data=cipher)
        require(restored==raw,'legacy private archive readback differs')
        state.put(record,dict(desired,cipher_sha256=digest(cipher)))
    saved=state.get(record);synchronize(state.path(record));cipher=read(path,512*1024,mode=0o600)
    require(digest(cipher)==saved['cipher_sha256'],'legacy encrypted archive changed');synchronize(path)
    restored=run(['/usr/bin/systemd-creds','decrypt','--name=erpc-ethereum-legacy-definitions','-','-'],input_data=cipher)
    require(len(restored)<=128*1024 and digest(restored)==saved['sha256'] and (raw is None or restored==raw),'original legacy archive differs')
    return restored


def migrate(state,expected,proof,templates,run):
    """Sealed caller holds the common operation lock; no legacy code is executed."""
    evidence(proof,expected);namespace.paths('validator');layout.topology('validator')
    if state.exists('legacy-migration-complete.json'):
        complete=state.get('legacy-migration-complete.json')
        require(complete['contract']==expected and complete['records']==proof['records'],'original migration evidence changed')
        plan=accounts.validate(state.get('accounts.json'),'validator');accounts.verify(plan);layout.verify(state,expected,plan)
        for client in floor.CLIENTS:
            rows=floor.records(state,expected,client);require(rows,'original migrated source history is missing')
            for row in rows:floor.compare(row['pin'],dict(proof['opened_sources'][client],archive=None,binary=None))
        synchronize(state.path('legacy-migration-complete.json'))
        return {'migrated':True,'already':True,'signing_started':False,'data_preserved':True}
    scope(expected,proof)
    if state.exists('owner.json'):state.check(expected)
    old_root=layout.ROOTS['validator'];root=root_directory(old_root)
    try:fd=os.open('control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=root)
    finally:os.close(root)
    with os.fdopen(fd,'rb') as lock:
        checked_file(os.fstat(lock.fileno()),mode=0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if state.exists('legacy-migration.json'):
            journal=state.get('legacy-migration.json');require(journal['evidence']==proof,'resume the same independently retained original records')
            plan=accounts.validate(journal['plan'],'validator');original_identities(proof,plan)
        else:
            config,owner,definitions=inspect(expected,proof,templates,run);plan=new_plan(proof)
            stopped(run,plan);material,private=legacy_material(owner,plan)
            if state.exists('owner.json'):
                require(state.check(expected)['machine']==proof['machine'] and set(p.name for p in state.directory.iterdir())=={'owner.json'},
                        'established new authority cannot be replaced by legacy migration')
            journal={'evidence':proof,'plan':plan,'owner':owner,'config':config,'units':definitions,
                     'helper_sha256':digest(read(CONTROL,128*1024)),'jwt_sha256':digest(read(JWT,128,mode=0o640)),'layout':data_record(expected,plan),
                     'filesystem':observed_filesystem(),'database':None if material is None else database_binding(plan),
                     'custody_sha256':None if material is None else digest(read(old_root/'custody.json',16*1024*1024+128*1024,mode=0o600)),
                     'definitions_sha256':None if private is None else digest(private)}
            state.reserve(expected,proof['machine']);state.put('legacy-migration.json',journal)
        archive=state.path('legacy-management.py')
        if not state.exists(archive.name):
            raw=read(CONTROL,128*1024);require(digest(raw)==journal['helper_sha256'],'original management source is unavailable for archival')
            atomic(archive,raw)
        require(digest(read(archive,128*1024,mode=0o600))==journal['helper_sha256'],'original management archive changed')
        synchronize(archive)
        state.check(expected);synchronize(state.path('owner.json'));synchronize(state.path('legacy-migration.json'))
        stopped(run,plan);original_data(state,expected,plan,journal)
        disable_old(state,journal,run);no_loaded_old_helper();stopped(run,plan)
        accounts.persist(state,plan);accounts.provision(state,'validator')
        state.put('layout.json',journal['layout']);synchronize(state.path('layout.json'))
        layout.upgrade(state,expected,plan,journal['filesystem'])
        state.put('layout-intent.json',{key:value for key,value in journal['layout'].items() if key not in ('mode','children')})
        synchronize(state.path('layout-intent.json'));floor.migrate(state,expected,proof['opened_sources'])
        import eth_validator_engine as engine
        if JWT.exists() or JWT.is_symlink():
            jwt=read(JWT,128,mode=0o640);require(JWT.lstat().st_gid==plan['groups']['ev-engine'],'legacy original Engine group differs')
            require(digest(jwt)==journal['jwt_sha256'],'original legacy Engine material changed')
            engine.value(state,expected,create=True,legacy=jwt)
        else:require(digest(engine.value(state,expected))==journal['jwt_sha256'],'restored original Engine authority differs')
        remove_original_root_file(JWT,journal['jwt_sha256'],0o640)
        if journal['database'] is not None:
            require(database_binding(plan)==journal['database'],'original legacy slashing DB was replaced')
            require(normalize_database(state,expected,plan)==journal['database'],'original native history identity changed')
            finish_custody_conversion(state,expected,journal)
        else:
            vc=layout.open_native(state,expected,plan,'vc')
            try:require(not os.listdir(vc),'legacy prepared signer contains unowned private state')
            finally:os.close(vc)
        import eth_validator_keys as keys
        keys.cancel(state,expected,retire=journal['owner']['state']=='fenced',destination=journal['owner'].get('fenced_to'))
        state.stop(expected,lambda:stopped(run,plan),retire=True)
        revision=namespace.publish('validator')
        state.put('legacy-migration-complete.json',{'contract':expected,'records':proof['records'],'helper_revision':revision})
        synchronize(state.path('legacy-migration-complete.json'))
        return {'migrated':True,'already':False,'signing_started':False,'data_preserved':True,'retired':True,'helper_revision':revision,'next':'deploy supporting clients, then review original signer readiness before explicit start'}


def remove_original_root_file(path,expected_sha,mode):
    descriptor=root_directory(path.parent)
    try:
        if path.exists() or path.is_symlink():
            require(digest(read(path,16*1024*1024+128*1024,mode=mode))==expected_sha,'legacy original file changed before encrypted conversion')
            os.unlink(path.name,dir_fd=descriptor)
        os.fsync(descriptor)
    finally:os.close(descriptor)


def finish_custody_conversion(state,expected,journal):
    """Preserve original material encrypted; never initialize a new slashing DB."""
    root=layout.ROOTS['validator'];path=root/'custody.json';plan=journal['plan'];pubkey=journal['owner']['pubkey']
    if path.exists() or path.is_symlink():
        raw=read(path,16*1024*1024+128*1024,mode=0o600);require(digest(raw)==journal['custody_sha256'],'original legacy custody bytes changed')
        material=unique(raw);observed,_=custody.key_material({key:material[key] for key in ('keystore','password')})
        require(observed==pubkey,'original legacy key changed')
        historical=custody.history(material['history'],expected['network'],pubkey)
        wanted={'history':material['history'],'source':material.get('source'),'destination':material.get('destination')}
        if state.exists('legacy-history-input.json'):require(state.get('legacy-history-input.json')==wanted,'original legacy input history differs')
        else:state.put('legacy-history-input.json',wanted)
        synchronize(state.path('legacy-history-input.json'))
        custody.seal(state,expected,{key:material[key] for key in ('keystore','password')})
    else:
        material=custody.reveal(state,expected);saved=state.get('legacy-history-input.json')
        material.update(saved);historical=custody.history(material['history'],expected['network'],pubkey)
        synchronize(state.path('legacy-history-input.json'))
    try:private=private_native('validators/validator_definitions.yml',plan['users']['ev-validator'])
    except FileNotFoundError:private=archived_definitions(state)
    require(digest(private)==journal['definitions_sha256'],'original legacy definitions changed')
    native_definitions(private,material,pubkey);archived_definitions(state,private)
    desired={'contract':expected,'pubkey':pubkey,'database':journal['database'],'records':journal['evidence']['records']}
    if state.exists('legacy-signer.json'):require(state.get('legacy-signer.json')==desired,'legacy native signing authority changed')
    else:state.put('legacy-signer.json',desired)
    synchronize(state.path('legacy-signer.json'))
    imported={'contract':expected,'pubkey':pubkey,'keystore_sha256':digest(encoded(material['keystore'])),
              'history_sha256':digest(historical),'source_owner':material.get('source'),'phase':'legacy','ever_authorized':True}
    if state.exists('signer-import.json'):require(state.get('signer-import.json')==imported,'legacy signer initialization changed')
    else:state.put('signer-import.json',imported)
    synchronize(state.path('signer-import.json'))
    remove_original_root_file(path,journal['custody_sha256'],0o600)
    directory=layout.descendant(state,expected,plan,'vc','validators')
    try:
        name='validator_definitions.yml'
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:fd=None
        if fd is not None:
            with os.fdopen(fd,'rb') as stream:
                checked_file(os.fstat(stream.fileno()),owner=plan['users']['ev-validator']['uid'],mode=0o600)
                raw=stream.read(128*1024+1);require(digest(raw)==journal['definitions_sha256'],'legacy definitions changed before encrypted archival')
            os.unlink(name,dir_fd=directory)
        os.fsync(directory)
    finally:os.close(directory)
