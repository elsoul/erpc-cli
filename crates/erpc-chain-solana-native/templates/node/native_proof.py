# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline native BLS public derivation under the original proof-only account."""
import hashlib
import re
import stat
from pathlib import Path
from native_files import atomic,read,require,root_directory,sync_file,sync_directory
from native_state import token
from native_entrypoint import proof_command
import native_accounts as accounts
import native_custody as custody
import native_deployment as deployment
import native_helpers as helpers
import native_process as processes
import native_runtime_unit as runtime
from native_validator import bls_key

UNIT='erpc-solana-proof.service'
RECEIPT='validator-proof-install.json'
CREDENTIAL=Path('/run/credentials')/UNIT/'identity'
OUTPUT=Path('/var/lib/erpc-solana/state')


def definition(account,revision,build_intent,intent,output):
    token(build_intent);token(intent)
    require(re.fullmatch('[a-f0-9]{64}',revision) and set(account)=={'uid','gid'}
            and type(account['uid']) is int and account['uid']==account['gid'] and 20000<=account['uid']<=60000,
            'original native proof recipient required')
    require(output==OUTPUT/('bls-public-'+intent+'.txt'),'fixed native public output required')
    command=proof_command(helpers.RELEASES/revision/'native_runtime_control.py')
    binary=runtime.RELEASES/build_intent/'bin/solana-keygen'
    return f'''[Unit]
Description=Derive the original validator BLS public key without network access
[Service]
Type=oneshot
User={account['uid']}
Group={account['gid']}
WorkingDirectory=/
LoadCredentialEncrypted=identity:{custody.CUSTODY}/validator.cred
ExecCondition=+{command} proof-condition
ExecStartPre=+{command} proof-guard
ExecStart=/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 {binary} bls_pubkey {CREDENTIAL}
StandardOutput=truncate:{output}
StandardError=null
UMask=0077
LimitCORE=0
LimitFSIZE=4096
TimeoutStartSec=60
TimeoutStopSec=30
KillMode=control-group
SendSIGKILL=no
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryMax=512M
TasksMax=32
'''


def validate_receipt(state,contract,record):
    state.owner(contract)
    require(set(record)=={'contract','intent','helper_revision','build_intent','account','cipher_sha256','unit_sha256','keygen_sha256'}
            and record['contract']==contract,'native proof ownership differs')
    token(record['intent']);token(record['build_intent'])
    identities=state.get('accounts.json')
    require(identities['contract']==contract,'native proof account belongs to another host')
    accounts.validate_plan(identities['accounts'])
    require(record['account']=={key:identities['accounts']['proof'][key] for key in ('uid','gid')},
            'native proof recipient differs from original reservation')
    for name in ('helper_revision','cipher_sha256','unit_sha256','keygen_sha256'):
        require(isinstance(record[name],str) and re.fullmatch('[a-f0-9]{64}',record[name]),'invalid native proof digest')
    return record


def owned(state,contract):
    return validate_receipt(state,contract,state.get(RECEIPT))


def retained_name(record):
    return 'validator-proof-owned-'+record['unit_sha256']+'.json'


def retain(state,contract,record):
    """Immutable shutdown authority for each exact generated definition."""
    validate_receipt(state,contract,record)
    name=retained_name(record);path=state.directory/name
    if path.exists() or path.is_symlink():
        require(state.get(name)==record,'retained native proof authority changed')
    else:state.put(name,record)
    # A visible archive is not sufficient after a failed rename/fsync. Never
    # replace current authority until its original and candidate are durable.
    sync_file(path);sync_directory(state.directory)


def shutdown_receipt(state,contract):
    root_directory(runtime.UNITS)
    digest=hashlib.sha256(read(runtime.UNITS/UNIT)).hexdigest()
    path=state.directory/('validator-proof-owned-'+digest+'.json')
    record=validate_receipt(state,contract,state.get(path.name)) if path.exists() or path.is_symlink() else owned(state,contract)
    require(record['unit_sha256']==digest,'native proof unit changed')
    return record


def unit_file(record):
    root_directory(runtime.UNITS)
    overrides=runtime.UNITS/(UNIT+'.d')
    if overrides.exists() or overrides.is_symlink():
        root_directory(overrides);require(not any(overrides.iterdir()),'unknown native proof unit override')
    require(hashlib.sha256(read(runtime.UNITS/UNIT)).hexdigest()==record['unit_sha256'],'native proof unit changed')


def service(record,run):
    raw=run(['show',UNIT,'--property=LoadState,FragmentPath,DropInPaths,User,Group,NeedDaemonReload,MainPID,ActiveState,Result,ExecMainStatus'])
    fields={}
    for line in raw.splitlines():
        key,separator,value=line.partition('=');require(separator and key not in fields,'ambiguous native proof service metadata');fields[key]=value
    require(fields.get('LoadState')=='loaded' and fields.get('FragmentPath')==str(runtime.UNITS/UNIT)
            and fields.get('DropInPaths')=='' and fields.get('NeedDaemonReload')=='no'
            and fields.get('User')==str(record['account']['uid']) and fields.get('Group')==str(record['account']['gid']),
            'loaded proof unit has different original authority')
    return fields


def stop(state,contract,run):
    state.owner(contract)
    identities=state.get('accounts.json');require(identities['contract']==contract,'proof shutdown ownership differs')
    accounts.validate_plan(identities['accounts']);uid=identities['accounts']['proof']['uid']
    path=runtime.UNITS/UNIT
    if not path.exists() and not path.is_symlink():
        require(run(['show',UNIT,'--property=LoadState','--value'],allowed=(0,1)).strip()=='not-found',
                'proof service remains loaded without its original definition')
        processes.assert_quiescent(uid);return
    record=shutdown_receipt(state,contract);unit_file(record)
    run(['daemon-reload']);service(record,run)
    failed=False
    try:run(['stop',UNIT],timeout=40)
    except Exception:failed=True
    try:processes.assert_quiescent(uid)
    except Exception:failed=True
    require(not failed,'original native proof process has not stopped')


def guard(state,contract,run,plaintext=False):
    record=owned(state,contract)
    require(contract['profile']=='agave-native','RPC hosts cannot load registered validator identity')
    operation,build=deployment.candidate(state,contract,record['intent'])
    cutover=state.get('cutover.json')
    require(all(cutover[k]==operation[k] for k in ('intent','halt','target'))
            and operation['target']['mode']=='validator' and operation['target']['identity']==contract['identity_account']
            and operation['target']['build_intent']==record['build_intent']
            and operation['target']['helper_revision']==record['helper_revision'],
            'native proof no longer owns its original activation cutover')
    identities=accounts.verify(state,contract)
    require(record['account']=={key:identities['proof'][key] for key in ('uid','gid')},'native proof account changed')
    identity=custody.complete(state,contract,'validator')
    require(identity['public']==contract['identity_account'] and identity['cipher_sha256']==record['cipher_sha256']
            and build['files']['solana-keygen']['sha256']==record['keygen_sha256'],'native proof source or original custody changed')
    unit_file(record);service(record,run);processes.assert_quiescent(record['account']['uid'])
    if plaintext:
        root_directory(CREDENTIAL.parent.parent)
        directory=CREDENTIAL.parent.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid in (0,record['account']['uid'])
                and not directory.st_mode&0o022,'native proof credential namespace differs')
        info=CREDENTIAL.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,record['account']['uid']) and info.st_nlink==1
                and stat.S_IMODE(info.st_mode) in (0o400,0o440),'native proof credential delivery differs')
        raw=read(CREDENTIAL,4096,info.st_uid)
        require(hashlib.sha256(raw).hexdigest()==identity['plaintext_sha256'],'native proof received a different identity')
    return record


def derive(state,contract,intent,run):
    operation,build=deployment.candidate(state,contract,intent)
    require(contract['profile']=='agave-native' and operation['target']['mode']=='validator'
            and operation['target']['identity']==contract['identity_account'],'native proof requires explicit validator activation')
    cutover=state.get('cutover.json')
    require(all(cutover[k]==operation[k] for k in ('intent','halt','target')),'native proof requires stopped cutover')
    identities=accounts.verify(state,contract);account={key:identities['proof'][key] for key in ('uid','gid')}
    stop(state,contract,run)
    identity=custody.complete(state,contract,'validator')
    require(identity['public']==contract['identity_account'],'native proof original identity differs')
    revision=operation['target']['helper_revision'];build_intent=operation['target']['build_intent']
    helpers.verify(revision)
    output=OUTPUT/('bls-public-'+token(intent)+'.txt')
    require(OUTPUT==state.directory,'native proof output namespace differs from original state')
    root_directory(OUTPUT)
    if output.exists() or output.is_symlink():
        previous=owned(state,contract)
        require(previous['intent']==intent,'unowned native public output cannot be truncated')
        read(output,4096)
        require(stat.S_IMODE(output.lstat().st_mode)==0o600,'native public output is not private original state')
    unit=definition(account,revision,build_intent,intent,output)
    record={'contract':contract,'intent':intent,'helper_revision':revision,'build_intent':build_intent,'account':account,
            'cipher_sha256':identity['cipher_sha256'],'unit_sha256':hashlib.sha256(unit.encode()).hexdigest(),
            'keygen_sha256':build['files']['solana-keygen']['sha256']}
    if (state.directory/RECEIPT).exists() or (state.directory/RECEIPT).is_symlink():
        retain(state,contract,owned(state,contract))
    retain(state,contract,record)
    state.put(RECEIPT,record);sync_file(state.directory/RECEIPT);sync_directory(state.directory)
    root_directory(runtime.UNITS);atomic(runtime.UNITS/UNIT,unit.encode(),0o644)
    sync_file(runtime.UNITS/UNIT);sync_directory(runtime.UNITS)
    run(['daemon-reload']);guard(state,contract,run)
    try:
        run(['start',UNIT],timeout=75)
        result=service(record,run)
        require(result.get('Result')=='success' and result.get('ExecMainStatus')=='0'
                and result.get('MainPID')=='0' and result.get('ActiveState')=='inactive',
                'native public-key derivation did not complete')
        processes.assert_quiescent(account['uid']);state.current(contract,intent)
        public=bls_key(read(output,128).decode('ascii').strip())
        evidence=dict(record,bls=public)
        state.put('validator-proof-'+intent+'.json',evidence)
        return evidence
    finally:stop(state,contract,run)
