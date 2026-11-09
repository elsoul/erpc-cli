# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit historical-account migration; never infer original IDs from current NSS."""
import hashlib
import os
import re
import stat
from eth_files import read,require,root_directory,synchronize
import eth_accounts as accounts
import eth_layout as layout
import eth_namespace as namespace
import eth_process as processes
import eth_units as units
import eth_source_floor as source_floor


def evidence(value,expected,machine):
    require(isinstance(value,dict) and set(value)=={'schema','contract','machine','accounts','records','opened_sources'}
            and value['schema']==1 and value['contract']==expected and value['machine']==machine,
            'historical host evidence differs from the independently pinned original host')
    accounts.validate(value['accounts'],'rpc');accounts.verify(value['accounts'])
    require(set(value['records'])=={'passwd','group','machine','opened_sources'} and all(isinstance(digest,str) and re.fullmatch('[a-f0-9]{64}',digest)
            for digest in value['records'].values()),'original backup record digests required')
    source_floor.historical(value['opened_sources'])
    return value


def inactive(run):
    for name in units.UNITS:
        raw=run(['/usr/bin/systemctl','show',name,'--property=LoadState,ActiveState,MainPID'])
        values={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=');require(separator and key not in values,'ambiguous legacy unit state');values[key]=value
        require(values.get('LoadState') in ('loaded','masked','not-found') and values.get('MainPID')=='0'
                and (values.get('ActiveState') in ('inactive','failed') or
                     (name=='erpc-eth-firewall.service' and values.get('ActiveState')=='active')),
                'stop original native services independently before explicit migration; no unknown service is executed here')


def layout_record(state,expected,plan):
    wanted=layout.expected(expected,plan);root=layout.ROOTS['rpc'];directory=root_directory(root)
    try:
        info=os.fstat(directory);require(stat.S_IMODE(info.st_mode) in (0o750,0o755,0o711),'legacy root permissions differ')
        children={};nonempty=[]
        for name,user in layout.USERS['rpc'].items():
            child=os.open(name,layout.FLAGS,dir_fd=directory)
            try:
                entry=os.fstat(child);who=plan['users'][user]
                require(entry.st_uid==who['uid'] and entry.st_gid==who['gid'] and entry.st_dev==info.st_dev
                        and stat.S_IMODE(entry.st_mode) in (0o700,0o750),'native directory differs from historical numeric owner')
                children[name]=layout.binding(entry);nonempty.append(bool(os.listdir(child)))
            finally:os.close(child)
        require(all(nonempty),'legacy migration requires retained native data; restore the original host backup for incomplete legacy initialization')
        return dict(wanted,binding=layout.binding(info),mode=0o711,children=children)
    finally:os.close(directory)


def stable_layout(record):
    """Compare original inodes without making a historical device number an ID."""
    return dict(record,binding={'inode':record['binding']['inode']},
                children={name:{'inode':value['inode']} for name,value in record['children'].items()})


def journal_volume(state,expected,journal):
    if 'filesystem' in journal:return layout.filesystem(journal['filesystem'])
    require(state.exists('migration-volume.json'),
            'original interrupted migration requires explicit independent-evidence volume upgrade')
    value=state.get('migration-volume.json')
    require(set(value)=={'contract','journal','filesystem'} and value['contract']==expected and value['journal']==journal,
            'original migration volume evidence differs')
    synchronize(state.path('migration-volume.json'))
    return layout.filesystem(value['filesystem'])


def upgrade_pending_volume(state,expected,proof,machine,run):
    """Recover only the original incomplete legacy journal; never run unknown units."""
    layout.filesystem(proof);require(state.check(expected)['machine']==machine,'original migration belongs to another host')
    require(not state.exists('migration-complete.json') and not any(state.exists(name) for name in ('pending.json','cutover.json','recovery.json','active.json')),
            'original legacy migration is not an incomplete stopped conversion')
    journal=state.get('migration.json')
    require(isinstance(journal,dict) and set(journal) in ({'evidence','units','layout','jwt'},
                                                       {'evidence','units','layout','jwt','filesystem'}),
            'unknown original legacy migration journal')
    original=evidence(journal['evidence'],expected,machine);plan=original['accounts']
    require(set(journal['units'])==set(units.UNITS),'original legacy unit archive differs')
    inactive(run);processes.quiescent(plan,{})
    current=layout_record(state,expected,plan)
    require(stable_layout(current)==stable_layout(journal['layout']),'original interrupted migration data changed')
    descriptor=root_directory(layout.ROOTS['rpc'])
    try:require(layout.probe(layout.ROOTS['rpc'],descriptor)==proof,'independent original filesystem evidence differs')
    finally:os.close(descriptor)
    layout.topology('rpc')
    for name,text in journal['units'].items():
        path=namespace.SYSTEMD/name
        if path.is_symlink():require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','original legacy mask differs')
        elif path.exists():require(read(path,262144).decode()==text,'original legacy unit changed')
        # An interrupted unlink-before-mask is a known migration journal state.
    path=namespace.PROFILES['rpc']['config']/'jwt.hex';raw=read(path,128,mode=0o640)
    require(journal['jwt']=={'contract':expected,'gid':plan['groups']['ethereum'],'sha256':hashlib.sha256(raw).hexdigest()}
            and path.lstat().st_gid==plan['groups']['ethereum'] and re.fullmatch(b'[a-f0-9]{64}\n?',raw),
            'original migration engine authority differs')
    if state.exists('accounts-intent.json'):require(state.get('accounts-intent.json')==plan,'original pending numeric accounts differ')
    if state.exists('accounts.json'):require(state.get('accounts.json')==plan,'original established numeric accounts differ')
    if state.exists('layout.json'):
        require(state.get('layout.json')==journal['layout'],'original established layout differs')
        for client in source_floor.CLIENTS:
            for row in source_floor.records(state,expected,client):
                source_floor.compare(row['pin'],dict(original['opened_sources'][client],archive=None,binary=None))
    if 'filesystem' in journal:require(layout.filesystem(journal['filesystem'])==proof,'original migration UUID cannot change')
    state.stop(expected,lambda:processes.quiescent(plan,{}),retire=True)
    synchronize(state.path('owner.json'));synchronize(state.path('migration.json'));synchronize(path)
    wanted={'contract':expected,'journal':journal,'filesystem':proof}
    if state.exists('migration-volume.json'):require(state.get('migration-volume.json')==wanted,'original migration volume proof cannot change')
    else:state.put('migration-volume.json',wanted)
    synchronize(state.path('migration-volume.json'))
    # Old legacy units do not consult the new cancellation receipt. Preserve
    # their original bytes in the journal and durably mask them before claiming
    # stopped recovery across reboot, without executing an unknown ExecStop.
    mask_original_units(journal,run);processes.quiescent(plan,{})
    return {'upgraded':True,'started':False,'retired':True,'data_preserved':True,'migration_pending':True,'filesystem':proof}


def mask_original_units(journal,run):
    # Preserve original unit bytes before masking. No ExecStop from an unknown
    # historical unit is invoked, and no native writer is adopted by its name.
    descriptor=root_directory(namespace.SYSTEMD)
    try:
        for name,text in journal['units'].items():
            path=namespace.SYSTEMD/name
            try:info=path.lstat()
            except FileNotFoundError:
                os.symlink('/dev/null',name,dir_fd=descriptor);os.fsync(descriptor);continue
            if stat.S_ISLNK(info.st_mode):
                require(info.st_uid==0 and os.readlink(path)=='/dev/null','migration unit selector changed')
            else:
                require(read(path,262144).decode()==text,'historical unit changed during migration')
                os.unlink(name,dir_fd=descriptor)
                os.symlink('/dev/null',name,dir_fd=descriptor)
            os.fsync(descriptor)
    finally:os.close(descriptor)
    run(['/usr/bin/systemctl','daemon-reload']);inactive(run)


def migrate(state,expected,proof,machine,run):
    proof=evidence(proof,expected,machine);namespace.paths('rpc');layout.topology('rpc')
    plan=proof['accounts']
    if state.exists('migration-complete.json'):
        state.check(expected);record=state.get('migration-complete.json')
        require(record['contract']==expected and record['records']==proof['records'],'completed original migration evidence differs')
        for client in source_floor.CLIENTS:
            rows=source_floor.records(state,expected,client)
            require(rows,'original migrated source floor is missing')
            for row in rows:source_floor.compare(row['pin'],dict(proof['opened_sources'][client],archive=None,binary=None))
        synchronize(state.path('migration-complete.json'))
        return {'migrated':True,'already':True,'started':False,'data_preserved':True}
    inactive(run);processes.quiescent(plan,{})
    if state.exists('migration.json'):
        journal=state.get('migration.json');require(journal['evidence']==proof,'historical migration retry changed its original evidence')
    else:
        if state.exists('owner.json'):
            require(state.check(expected)['machine']==machine and set(p.name for p in state.directory.iterdir())=={'owner.json'},
                    'an established authority cannot be replaced by a legacy migration')
        originals={}
        for name in units.UNITS:
            path=namespace.SYSTEMD/name
            require(path.exists() and not path.is_symlink(),'original legacy unit must be retained as a protected ordinary file')
            originals[name]=read(path,262144).decode()
        old_layout=layout_record(state,expected,plan)
        path=namespace.PROFILES['rpc']['config']/'jwt.hex';raw=read(path,128,mode=0o640)
        require(re.fullmatch(b'[a-f0-9]{64}\n?',raw) and path.lstat().st_gid==plan['groups']['ethereum'],
                'existing private engine JWT does not match the historical group')
        jwt={'contract':expected,'gid':plan['groups']['ethereum'],'sha256':hashlib.sha256(raw).hexdigest()}
        descriptor=root_directory(layout.ROOTS['rpc'])
        try:volume=layout.probe(layout.ROOTS['rpc'],descriptor)
        finally:os.close(descriptor)
        journal={'evidence':proof,'units':originals,'layout':old_layout,'jwt':jwt,'filesystem':volume}
        state.reserve(expected,machine)
        state.put('migration.json',journal)
    state.check(expected);synchronize(state.path('owner.json'));synchronize(state.path('migration.json'))
    descriptor=root_directory(layout.ROOTS['rpc'])
    try:require(layout.probe(layout.ROOTS['rpc'],descriptor)==journal_volume(state,expected,journal),'historical migration filesystem changed')
    finally:os.close(descriptor)
    mask_original_units(journal,run);processes.quiescent(plan,{})
    accounts.verify(plan);accounts.persist(state,plan,True)
    recorded=layout_record(state,expected,plan)
    require(stable_layout(recorded)==stable_layout(journal['layout']),'native data binding changed during original migration')
    recorded=journal['layout']
    root=root_directory(layout.ROOTS['rpc'])
    try:
        os.fchmod(root,0o711);os.fsync(root)
        for name in layout.USERS['rpc']:
            child=os.open(name,layout.FLAGS,dir_fd=root)
            try:
                require(os.fstat(child).st_ino==recorded['children'][name]['inode'] and os.fstat(child).st_dev==os.fstat(root).st_dev,
                        'native directory changed before permission publication')
                os.fchmod(child,0o700);os.fsync(child)
            finally:os.close(child)
        os.fsync(root)
    finally:os.close(root)
    state.put('layout.json',recorded);synchronize(state.path('layout.json'))
    layout.upgrade(state,expected,plan,journal_volume(state,expected,journal))
    source_floor.migrate(state,expected,proof['opened_sources'])
    state.put('layout-intent.json',{key:value for key,value in recorded.items() if key not in ('mode','children')})
    path=namespace.PROFILES['rpc']['config']/'jwt.hex'
    require(hashlib.sha256(read(path,128,mode=0o640)).hexdigest()==journal['jwt']['sha256'],'original engine JWT changed during migration')
    synchronize(path);state.put('engine-jwt.json',journal['jwt']);synchronize(state.path('engine-jwt.json'))
    # Retained data is never overwritten with a fresh snapshot. This is an
    # authority to resume native validation/sync, not a claim of chain readiness.
    state.put('snapshot.json',{'contract':expected,'mode':'retained-native-data','records':proof['records']})
    state.stop(expected,lambda:processes.quiescent(plan,{}),retire=True)
    revision=namespace.publish('rpc')
    state.put('migration-complete.json',{'contract':expected,'records':proof['records'],'helper_revision':revision})
    synchronize(state.path('migration-complete.json'))
    return {'migrated':True,'started':False,'retired':True,'data_preserved':True,'helper_revision':revision}
