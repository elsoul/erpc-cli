# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit stopped adoption of independently recorded original Bitcoin authority.

The public record must come from historical operator records, not from today's
mutable NSS or current mount numbers. Unsupported/unproven hosts remain intact.
"""


def migration_record(state, request):
    value=request.get('original')
    require(isinstance(value,dict) and set(value)=={'schema','contract','machine_sha256','layout','account',
            'highest_source','daemon_sha256','client_sha256'} and value['schema']=='erpc-bitcoin-original-v1',
            'explicit original Bitcoin history record is required')
    expected=contract(request)
    require('host_binding' in expected and value['contract']==expected,
            'historical Bitcoin contract or original SSH host differs')
    require(value['machine_sha256']==machine_identity(), 'historical original machine differs')
    account=account_shape(value['account'])
    require(account['name']=='bitcoin', 'only the known legacy Bitcoin account profile is supported')
    observed_account(account)
    candidate=dict(state,**expected,origin='verified-legacy',layout=value['layout'],
                   machine_sha256=value['machine_sha256'],data_ready=True,source_started=True)
    verify_layout(candidate);verified_data(candidate,account)
    pin=qualified_pin({'pin':value['highest_source']})
    require(state.get('installed')==pin, 'historical highest opened source differs; no downgrade or inferred history is allowed')
    require((OPT/'current').is_symlink() and (OPT/'current').resolve()==release_dir(pin).resolve(),
            'legacy native source selection differs')
    marker=release_dir(pin)/'verified.json';protected(marker)
    require(json.loads(marker.read_bytes())==pin, 'legacy release marker differs from historical source')
    for name,field in (('bitcoind','daemon_sha256'),('bitcoin-cli','client_sha256')):
        path=release_dir(pin)/'bin'/name;protected(path)
        require(isinstance(value[field],str) and re.fullmatch('[a-f0-9]{64}',value[field]) and
                path.stat().st_mode&0o7777==0o755 and image_hash(path)==value[field],
                'legacy native bytes differ from independently recorded original images')
    return value,candidate,account


def migration_barrier(value):
    path=ROOT/'migration.json'
    if path.exists() or path.is_symlink():
        prior=original_record(path.name)
        require(isinstance(prior,dict) and set(prior)=={'original','legacy_owner','legacy_owner_sha256'} and
                prior['original']==value and isinstance(prior['legacy_owner'],str) and
                hashlib.sha256(prior['legacy_owner'].encode()).hexdigest()==prior['legacy_owner_sha256'],
                'original migration record changed or is incomplete')
    else:
        require(not any((ROOT/name).exists() or (ROOT/name).is_symlink() for name in
                ('account-intent.json','account.json','native-releases.json','source-floor.pending.json','source-floor.json')),
                'receipt-free partial original authority cannot be adopted')
        raw=(ROOT/'owner.json').read_text()
        prior={'original':value,'legacy_owner':raw,'legacy_owner_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        original_write(path.name,prior)
    synchronize(path);synchronize(ROOT)
    return prior


def migrate_original(state, request):
    require(state.get('origin') in (None,'verified-legacy'), 'fresh original authority is not a legacy migration')
    value,candidate,account=migration_record(state,request)
    try:
        receipt=migration_barrier(value)
    except Exception:
        # Eligibility and exact old owner are already proven. A failed record
        # publication must not skip graceful shutdown of the known old service.
        cancellation(state)
        raise
    old=json.loads(receipt['legacy_owner'])
    require(all(old.get(key)==state.get(key) for key in ('owner','network','storage','prune_mib','installed')),
            'legacy owner/source changed during migration recovery')
    cancellation(state,retire=state['phase']=='retired')
    legacy_quiet()
    observed_account(account)
    verify_layout(candidate);verified_data(candidate,account)
    # A migration never recreates or changes an account, DATA, database, cookie,
    # or native image. Only the already-proven ROOT traversal mode is prepared.
    root_volume,_=verify_layout(candidate)
    descriptor=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(descriptor)
        require(before.st_uid==ROOT_UID and before.st_ino==candidate['layout']['root_inode'] and
                before.st_dev==root_volume['device'] and before.st_mode&0o7777 in (0o700,0o755),
                'original legacy ROOT changed before its explicit mode transition')
        os.fchmod(descriptor,0o755);os.fsync(descriptor)
        after=ROOT.lstat()
        require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino), 'original ROOT changed during migration')
    finally:os.close(descriptor)
    synchronize(ROOT.parent)
    for name in ('account-intent.json','account.json'):
        expected={'contract':contract(candidate),'account':account}
        if (ROOT/name).exists() or (ROOT/name).is_symlink():
            require(original_record(name)==expected, 'original account migration receipt changed')
        else:original_write(name,expected)
        synchronize(ROOT/name);synchronize(ROOT)
    register_native(candidate,value['highest_source'],value['daemon_sha256'],value['client_sha256'])
    floor={'scope':runtime_scope(candidate),'source':native_key(value['highest_source'])}
    # This is the only explicit historical adoption path. Never disguise an
    # opened legacy database as a fresh empty source_started=False directory.
    for name in ('source-floor.pending.json','source-floor.json'):
        if (ROOT/name).exists() or (ROOT/name).is_symlink():
            require(original_record(name)==floor, 'retained highest opened source differs from historical migration')
        else:original_write(name,floor)
        synchronize(ROOT/name);synchronize(ROOT)
    candidate.update(stopped=True,intent=None,generation=generation(state),phase=state['phase'],
                     migration_sha256=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    save(candidate);synchronize(ROOT/'owner.json');synchronize(ROOT)
    return {'migrated':True,'service':'stopped','data_preserved':True,'source_preserved':True,
            'original_uid':account['uid'],'original_gid':account['gid'],'deployment_required':True}
