# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stable original ROOT/DATA filesystem authority, separate from kernel dev numbers.

Legacy upgrades preserve the original receipt values and bind their exact hashes.
A different-filesystem legacy ROOT requires independent historical UUID evidence;
today's filesystem is never silently adopted as that missing history.
"""
import hashlib
import stat
from state import OWNER_PHASE, LEGACY_OWNER_PHASE
from storage import decode, encode, read, require, synchronize

NAME = 'volume-authority.json'
ORIGIN = 'volume-upgrade-origin.json'
SCHEMA = 'erpc-nitro-original-volumes-v1'
ORIGINALS = ('owner.json', 'storage-layout.json', 'accounts-intent.json', 'accounts.json',
             'data-intent.json', 'data.json', 'key-origin.json', 'signer-activated.json', 'active.json')


def inode(record):
    require(isinstance(record, dict) and set(record) in ({'inode'}, {'device', 'inode'}) and
            type(record.get('inode')) is int and record['inode'] > 0, 'invalid original directory receipt')
    if 'device' in record:
        require(type(record['device']) is int and record['device'] >= 0, 'invalid legacy directory observation')
    return record['inode']


def stable(info):
    return {'inode': info.st_ino}


def same(info, record, device):
    return info.st_dev == device and info.st_ino == inode(record)


def shape(value):
    require(isinstance(value, dict) and set(value) == {'uuid', 'fstype'} and
            isinstance(value['uuid'], str) and value['fstype'] in ('ext4', 'xfs'),
            'invalid original filesystem identity')
    import re
    require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['uuid']) and
            any(char not in '0-' for char in value['uuid']), 'invalid original filesystem UUID')
    return value


def persistent(observed):
    return shape({key: observed[key] for key in ('uuid', 'fstype')})


def observations(expected, run=None):
    import host
    run = host.command if run is None else run
    host.no_nested_mounts(host.ROOT, run)
    root = host.filesystem_identity(host.ROOT, run)
    data = host.filesystem_identity(host.DATA, run)
    require(data['uuid'] == expected['data_uuid'], 'original validator DATA filesystem was replaced')
    return {'root': root, 'data': data}


def verify(state, expected, run=None):
    import host
    state.owner(expected)
    require((state.root/NAME).exists() or (state.root/NAME).is_symlink(),
            'original volume authority is missing; use the explicit stopped upgrade')
    value = state.get(NAME)
    require(set(value) == {'schema', 'contract', 'root', 'data', 'root_inode', 'origin'} and
            value['schema'] == SCHEMA and value['contract'] == expected,
            'original volume authority is missing or belongs to another scope')
    validate_origin(state, expected, value)
    current = observations(expected, run)
    require(persistent(current['root']) == shape(value['root']) and
            persistent(current['data']) == shape(value['data']) and
            type(value['root_inode']) is int and value['root_inode'] > 0 and
            host.ROOT.lstat().st_ino == value['root_inode'], 'original ROOT or DATA volume identity changed')
    if (state.root/'data.json').exists():
        saved=state.get('data.json'); info=host.DATA.lstat()
        require(set(saved)=={'contract','uid','gid','directory'} and saved['contract']==expected and
                stat.S_ISDIR(info.st_mode) and info.st_uid==saved['uid'] and info.st_gid==saved['gid'] and
                info.st_mode&0o7777==0o700 and same(info,saved['directory'],current['data']['device']),
                'original DATA directory or numeric ownership changed')
    return current


def validate_origin(state, expected, value):
    origin=value['origin']
    require(isinstance(origin,dict),'original volume origin is unavailable')
    if origin.get('kind')=='fresh':
        require(set(origin)=={'kind','layout_sha256'} and
                hashlib.sha256(read(state.root/'storage-layout.json',mode=0o600)).hexdigest()==origin['layout_sha256'],
                'original filesystem layout receipt changed')
        layout=state.get('storage-layout.json')
        require(set(layout)=={'contract','root','data','filesystems'} and layout['contract']==expected and
                layout['filesystems']=={'root':value['root'],'data':value['data']} and
                inode(layout['root'])==value['root_inode'],'original volume scope differs from its first layout')
    else:
        require(set(origin)=={'kind','receipt_sha256'} and origin['kind']=='legacy-upgrade',
                'unknown original volume origin')
        raw=read(state.root/ORIGIN,mode=0o600); captured=decode(raw)
        require(hashlib.sha256(raw).hexdigest()==origin['receipt_sha256'] and captured.get('schema')==SCHEMA and
                captured.get('contract')==expected and set(captured)=={'schema','contract','proof','receipts','filesystems'},
                'legacy volume origin receipt changed')
        require(captured['filesystems']=={'root':value['root'],'data':value['data']},
                'upgraded filesystem identity differs from its original qualification')
        rows=captured['receipts']
        require(isinstance(rows,dict) and {'owner.json','storage-layout.json'} <= set(rows) <= set(ORIGINALS),
                'legacy origin receipt set differs')
        for name,row in rows.items():
            require(set(row)=={'value','sha256'} and hashlib.sha256(encode(row['value'])).hexdigest()==row['sha256'],
                    'legacy original receipt hash differs')
        require(rows['owner.json']['value']=={'phase':LEGACY_OWNER_PHASE,'contract':expected} and
                rows['storage-layout.json']['value']['contract']==expected and
                inode(rows['storage-layout.json']['value']['root'])==value['root_inode'],
                'legacy original owner or root inode differs')
        layout=rows['storage-layout.json']['value']
        if layout['data'] is not None: inode(layout['data'])
        if captured['proof'] is not None:
            root_volume=historical_root(captured['proof'],inode(layout['root']))
        else:
            require(isinstance(layout['data'],dict) and 'device' in layout['root'] and
                    layout['root']['device']==layout['data'].get('device'),
                    'legacy original ROOT has no verified filesystem scope')
            root_volume={'uuid':expected['data_uuid'],'fstype':value['data']['fstype']}
        require(root_volume==value['root'],'original ROOT proof differs from upgraded authority')


def reserve(state, expected, run=None):
    """Called only after original layout reservation and before NSS mutation."""
    import host
    require(state.owner(expected)['phase'] == OWNER_PHASE,
            'legacy original volumes require explicit stopped authority upgrade')
    if (state.root/NAME).exists():
        verify(state, expected, run); synchronize(state.root/NAME); return
    layout = state.get('storage-layout.json')
    require(set(layout) == {'contract', 'root', 'data', 'filesystems'} and layout['contract'] == expected,
            'original layout is unavailable for filesystem reservation')
    current = observations(expected, run)
    require(layout['filesystems']=={key:persistent(current[key]) for key in ('root','data')},
            'original prepared filesystem UUID changed')
    require(same(host.ROOT.lstat(), layout['root'], current['root']['device']),
            'original ROOT changed before volume reservation')
    value = {'schema': SCHEMA, 'contract': expected, 'root': persistent(current['root']),
             'data': persistent(current['data']), 'root_inode': inode(layout['root']),
             'origin': {'kind': 'fresh', 'layout_sha256': hashlib.sha256(read(state.root/'storage-layout.json',mode=0o600)).hexdigest()}}
    state.put(NAME, value); verify(state, expected, run); synchronize(state.root/NAME)


def originals(state):
    result = {}
    for name in ORIGINALS:
        if not (state.root/name).exists(): continue
        raw = read(state.root/name, mode=0o600)
        result[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'value': decode(raw)}
    require(all(name in result for name in ('owner.json', 'storage-layout.json')),
            'original legacy ownership/layout records are unavailable')
    return result


def historical_root(proof, expected_inode):
    require(isinstance(proof, dict) and set(proof) == {'uuid', 'fstype', 'inode', 'record_sha256'} and
            type(proof['inode']) is int and proof['inode'] > 0 and proof['inode'] == expected_inode,
            'independent original ROOT volume record is missing or differs')
    import re
    require(isinstance(proof['record_sha256'], str) and re.fullmatch('[0-9a-f]{64}',proof['record_sha256']),
            'original ROOT evidence hash is missing')
    return shape({key: proof[key] for key in ('uuid', 'fstype')})


def qualify_upgrade(state, expected, records, proof, quiet, run=None):
    """Read-only qualification while the original runtime is already fenced/drained."""
    import host
    import history
    require(state.owner(expected)['phase']==LEGACY_OWNER_PHASE,'only original legacy volumes use this upgrade proof')
    quiet()
    fence=state.fence()
    require(fence['stopped'] and fence['intent'] is None, 'volume upgrade requires an explicit stopped original runtime')
    captured=originals(state)
    layout=captured['storage-layout.json']['value']
    require(set(layout)=={'contract','root','data'} and layout['contract']==expected,
            'legacy original layout scope differs')
    current=observations(expected,run)
    root_inode=inode(layout['root'])
    require(same(host.ROOT.lstat(),layout['root'],current['root']['device']), 'legacy original ROOT inode changed')
    old_data=layout['data']
    if proof is not None:
        root_volume=historical_root(proof,root_inode)
    else:
        # Only co-recorded ROOT and prepared DATA observations establish that
        # the known original DATA UUID also scoped ROOT. Never guess separate FS.
        require(isinstance(old_data,dict) and 'device' in old_data and 'device' in layout['root'] and
                old_data['device']==layout['root']['device'],
                'independent historical ROOT UUID record is required for this legacy layout')
        root_volume={'uuid':expected['data_uuid'],'fstype':current['data']['fstype']}
    require(shape(root_volume)==persistent(current['root']), 'historical original ROOT filesystem differs')
    data_receipt=captured.get('data.json',captured.get('data-intent.json'))
    require(data_receipt is not None,'legacy original DATA receipt is missing')
    saved=data_receipt['value'];account=records['node']
    if old_data is not None:
        require(inode(old_data)==inode(saved.get('directory')),'legacy prepared DATA and ownership receipts disagree')
    require(set(saved)=={'contract','uid','gid','directory'} and saved['contract']==expected and
            saved['uid']==account['uid'] and saved['gid']==account['gid'] and saved['directory'] is not None,
            'legacy DATA account or original directory receipt differs')
    metadata=host.DATA.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==account['uid'] and metadata.st_gid==account['gid'] and
            metadata.st_mode&0o7777==0o700 and same(metadata,saved['directory'],current['data']['device']),
            'legacy original DATA ownership or inode changed')
    if captured.get('active.json',{}).get('value',{}).get('target',{}).get('phase')=='active':
        require('signer-activated.json' in captured,'original active signing history receipt is missing')
    if 'signer-activated.json' in captured:
        old=captured['signer-activated.json']['value']
        require(old.get('contract')==expected and old.get('account')==account,'original signer history scope differs')
        history.matches(old['history'],history.inspect(account,current['data']['device']))
    quiet()
    require(observations(expected,run)==current, 'volume observations changed during original qualification')
    return captured,current,root_volume,root_inode


def upgrade(state, expected, records, proof, quiet, run=None):
    """Persist a hash-bound stopped upgrade; never generate identity or start units."""
    quiet(); fence=state.fence()
    require(fence['stopped'] and fence['intent'] is None,'volume upgrade requires stopped original authority')
    if state.owner(expected)['phase']==OWNER_PHASE and not (state.root/ORIGIN).exists():
        reserve(state,expected,run);verify(state,expected,run)
        if proof is not None:
            current=state.get(NAME)
            require(historical_root(proof,current['root_inode'])==current['root'],'provided ROOT record differs from original authority')
        return {'volume_authority':'original','stopped':True,'runtime_started':False}
    origin_path=state.root/ORIGIN
    if origin_path.exists():
        origin=state.get(ORIGIN)
        require(set(origin)=={'schema','contract','proof','receipts','filesystems'} and origin['schema']==SCHEMA and
                origin['contract']==expected and origin['proof']==proof,'original volume upgrade request differs')
        synchronize(origin_path)
    else:
        require(not (state.root/NAME).exists() and not (state.root/NAME).is_symlink(),
                'unrecognized upgraded volume authority has no original receipt')
        captured,current,root_volume,_=qualify_upgrade(state,expected,records,proof,quiet,run)
        origin={'schema':SCHEMA,'contract':expected,'proof':proof,'receipts':captured,
                'filesystems':{'root':root_volume,'data':persistent(current['data'])}}
        state.put(ORIGIN,origin);synchronize(origin_path)
    if state.owner(expected)['phase']==OWNER_PHASE and (state.root/NAME).exists():
        verify(state,expected,run);synchronize(state.root/NAME);synchronize(state.root/'owner.json')
        return {'volume_authority':'original','stopped':True,'runtime_started':False}
    captured,current,root_volume,root_inode=qualify_upgrade(state,expected,records,proof,quiet,run)
    # The cancellation fence changes on retry; the original custody/history and
    # source receipts above do not. Preserve their exact pre-upgrade bytes/hash.
    require(captured==origin['receipts'] and origin['filesystems']=={'root':root_volume,'data':persistent(current['data'])},
            'original legacy receipts or filesystems changed during volume upgrade')
    value={'schema':SCHEMA,'contract':expected,'root':root_volume,'data':persistent(current['data']),
           'root_inode':root_inode,'origin':{'kind':'legacy-upgrade','receipt_sha256':hashlib.sha256(read(origin_path,mode=0o600)).hexdigest()}}
    if (state.root/NAME).exists() or (state.root/NAME).is_symlink():
        require(state.get(NAME)==value,'existing volume authority differs from the original upgrade')
    state.put(NAME,value);synchronize(state.root/NAME);verify(state,expected,run);quiet()
    state.put('owner.json',{'phase':OWNER_PHASE,'contract':expected})
    synchronize(state.root/'owner.json')
    return {'volume_authority':'original','stopped':True,'runtime_started':False}
