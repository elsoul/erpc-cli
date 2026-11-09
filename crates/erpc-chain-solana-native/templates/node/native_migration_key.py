# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only original host-key classification, before reservation or retirement.

No key is printed. A full finalized Vote-program snapshot classifies only the
selected cluster at observation time; it is not a universal authority or balance
claim. A provider error, oversized response or unknown account format refuses.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import resource
import subprocess
import time
import urllib.request
import native_migration_inspect as legacy
import native_migration_bls as bls
import native_migration_runs as runs

PUBLIC = {'mainnet': 'https://api.mainnet-beta.solana.com', 'testnet': 'https://api.testnet.solana.com'}
VOTE = 'Vote111111111111111111111111111111111111111'
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
PKCS8 = bytes.fromhex('302e020100300506032b657004220420')
SPKI = bytes.fromhex('302a300506032b6570032100')
MAXIMUM = 128 * 1024 * 1024
require = legacy.require


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError('original key classification redirect refused')


def public_key(value):
    require(isinstance(value, str) and 32 <= len(value) <= 44 and all(c in ALPHABET for c in value), 'invalid public authority')
    number = 0
    for character in value: number = number * 58 + ALPHABET.index(character)
    require(len(value) - len(value.lstrip('1')) + (number.bit_length() + 7) // 8 == 32, 'invalid public authority width')
    return value


def base58(value):
    number = int.from_bytes(value, 'big'); text = ''
    while number:
        number, index = divmod(number, 58); text = ALPHABET[index] + text
    return '1' * (len(value) - len(value.lstrip(b'\0'))) + text


def uint(value):
    require(type(value) is int and 0 <= value < 2**64, 'invalid public snapshot integer'); return value


def rpc(network, method, params):
    require(network in PUBLIC and method in ('getGenesisHash', 'getEpochInfo', 'getBlockTime', 'getProgramAccounts'), 'unqualified original-key observation')
    request = urllib.request.Request(PUBLIC[network], data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}, separators=(',', ':')).encode(),
        headers={'Content-Type':'application/json','Accept-Encoding':'identity'})
    maximum = MAXIMUM if method == 'getProgramAccounts' else 65536
    started = time.monotonic(); raw = bytearray()
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=8) as response:
        require(response.status == 200 and response.headers.get('Content-Encoding', 'identity') == 'identity', 'original authority snapshot unavailable')
        while True:
            chunk = response.read(min(65536, maximum + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
            require(len(raw) <= maximum and time.monotonic() - started <= 45, 'original authority snapshot exceeds its bound')
    value = legacy.unique(raw)
    require(isinstance(value, dict) and value.get('jsonrpc') == '2.0' and type(value.get('id')) is int
            and value['id'] == 1 and set(value) == {'jsonrpc','id','result'}, 'complete original authority snapshot required')
    return value['result']


def account_authorities(row):
    require(isinstance(row, dict) and set(row) == {'pubkey','account'}, 'unknown vote snapshot row')
    address = public_key(row['pubkey']); account = row['account']
    require(isinstance(account, dict) and account.get('owner') == VOTE and account.get('executable') is False, 'unknown vote snapshot owner')
    space = uint(account.get('space')); uint(account.get('lamports')); data = account.get('data')
    authorities = {address}
    if isinstance(data, list):
        require(len(data) == 2 and data[1] == 'base64' and isinstance(data[0], str) and len(data[0]) <= 5016,
                'unknown unparsed vote account')
        raw = base64.b64decode(data[0], validate=True)
        # Both pinned vote-interface implementations reject variant zero as a
        # usable V4 vote state. Accept only completely empty/all-zero storage,
        # not unknown historical binary records or partially decoded authority.
        require(len(raw) == space and space in (0, 3731, 3762) and not any(raw), 'unparsed vote authority cannot be classified')
        return authorities, True
    require(isinstance(data, dict) and data.get('program') == 'vote' and uint(data.get('space')) == space,
            'parsed vote program or size differs')
    parsed = data.get('parsed'); require(isinstance(parsed, dict) and parsed.get('type') == 'vote', 'unknown vote account type')
    info = parsed.get('info'); require(isinstance(info, dict), 'vote authority fields missing')
    authorities.update(public_key(info.get(key)) for key in ('nodePubkey','authorizedWithdrawer'))
    voters = info.get('authorizedVoters')
    require(isinstance(voters, list) and len(voters) <= 64, 'unknown voter schedule')
    epochs = set()
    for voter in voters:
        require(isinstance(voter, dict) and set(voter) == {'epoch','authorizedVoter'}, 'unknown voter schedule entry')
        epoch = uint(voter['epoch']); require(epoch not in epochs, 'duplicate scheduled voter epoch'); epochs.add(epoch)
        authorities.add(public_key(voter['authorizedVoter']))
    # Exclude any reported prior voter too. Pinned V4 JSON conversion drops
    # this historical list, so this is not a proof of all past authorities.
    prior = info.get('priorVoters')
    require(isinstance(prior, list) and len(prior) <= 64, 'unknown historical voter schedule')
    for voter in prior:
        require(isinstance(voter, dict) and set(voter) == {'authorizedPubkey','epochOfLastAuthorizedSwitch','targetEpoch'}, 'unknown historical voter entry')
        uint(voter['epochOfLastAuthorizedSwitch']); uint(voter['targetEpoch'])
        authorities.add(public_key(voter['authorizedPubkey']))
    return authorities, False


def bls_public(value):
    require(isinstance(value,str) and 1<=len(value)<=66 and all(c in ALPHABET for c in value), 'invalid BLS public authority')
    number=0
    for character in value:number=number*58+ALPHABET.index(character)
    require(number>0 and len(value)-len(value.lstrip('1'))+(number.bit_length()+7)//8==48,'invalid BLS public authority width')
    return value


def classify(network, candidate, candidate_bls=None, call=rpc, now=time.time, registered=None):
    public_key(candidate); started = now()
    if candidate_bls is not None:bls_public(candidate_bls)
    require(call(network,'getGenesisHash',[]) == legacy.GENESIS[network], 'original key observation genesis differs')
    before = call(network,'getEpochInfo',[{'commitment':'finalized'}]); require(isinstance(before,dict), 'original epoch unavailable')
    epoch = uint(before.get('epoch')); first = uint(before.get('absoluteSlot'))
    snapshot = call(network,'getProgramAccounts',[VOTE,{'commitment':'finalized','encoding':'jsonParsed','withContext':True,'minContextSlot':first}])
    require(isinstance(snapshot,dict) and set(snapshot) == {'context','value'} and isinstance(snapshot['context'],dict), 'complete vote snapshot context required')
    slot = uint(snapshot['context'].get('slot')); rows = snapshot['value']
    require(slot >= first and isinstance(rows,list) and 1 <= len(rows) <= 32768, 'vote snapshot is empty, stale or too large')
    seen = set(); empty = 0; commission = None
    if registered is not None:
        require(isinstance(registered,dict) and set(registered)=={'identity','vote_account','withdrawer'}, 'original public registration is required')
        for value in registered.values():public_key(value)
    for row in rows:
        authorities, uninitialized = account_authorities(row); address = row['pubkey']
        require(address not in seen and candidate not in authorities, 'original host key is a registered or historical voting authority')
        if not uninitialized:
            info=row['account']['data']['parsed']['info']
            require('blsPubkeyCompressed' in info, 'vote snapshot lacks BLS authority metadata')
            if info['blsPubkeyCompressed'] is not None:
                require(bls_public(info['blsPubkeyCompressed']) != candidate_bls, 'original host key is a registered BLS voting authority')
        if registered is not None and address==registered['vote_account']:
            require(not uninitialized,'original vote account is uninitialized')
            info=row['account']['data']['parsed']['info']
            require(info['nodePubkey']==registered['identity'] and info['authorizedWithdrawer']==registered['withdrawer'],
                    'original vote account belongs to different public authorities')
            commission=uint(info.get('commission'))
            require(commission<=100 and uint(info.get('inflationRewardsCommissionBps'))==commission*100,
                    'original vote commission is outside the native integer profile')
        seen.add(address); empty += int(uninitialized)
    require(registered is None or commission is not None, 'original vote registration is absent from the complete snapshot')
    after = call(network,'getEpochInfo',[{'commitment':'finalized','minContextSlot':slot}]); require(isinstance(after,dict), 'original epoch unavailable')
    final = uint(after.get('absoluteSlot')); timestamp = uint(call(network,'getBlockTime',[final]))
    require(uint(after.get('epoch')) == epoch and slot <= final <= first + 300 and -30 <= now()-timestamp <= 120
            and 0 <= now()-started <= 60, 'original authority classification is no longer fresh')
    return {'network':network,'genesis':legacy.GENESIS[network],'public':candidate,'epoch':epoch,'slot':slot,'finalized_slot':final,
            'block_time':timestamp,'commission':commission,'bls_authority_checked':candidate_bls is not None,'vote_accounts':len(rows),'uninitialized_accounts':empty,
            'scope':'selected finalized cluster snapshot; no universal authority or balance claim'}


def source(request):
    evidence = legacy.validate(request); uid, gid = evidence['uid'], evidence['gid']
    role = 'rpc' if request['role'] == 'rpc' else 'sync'
    path = legacy.ROOT / 'home/solv' / ('rpc-identity.json' if role == 'rpc' else 'unstaked-identity.json')
    for parent in reversed(path.parents):
        info = parent.lstat(); expected = (0,uid) if parent == path.parent else (0,)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in expected and not info.st_mode & 0o022, 'original identity parent changed')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid and info.st_mode & 0o7777 == 0o600
            and info.st_nlink == 1 and 0 < info.st_size <= 4096, 'original identity is not a private original regular file')
    metadata = {'role':role,'path':'/home/solv/'+path.name,'uid':uid,'gid':gid,'inode':info.st_ino,
                'bytes':info.st_size,'mtime_ns':info.st_mtime_ns}
    if 'host_identity' in request:
        require(metadata == {k:v for k,v in request['host_identity'].items() if k not in ('public','bls_public')}, 'approved original identity file changed')
    return path, metadata


def private_environment():
    require(resource.getrlimit(resource.RLIMIT_CORE) == (0,0), 'private original observation requires disabled core dumps')
    swaps = legacy.read_public('proc/swaps', maximum=65536).decode('ascii').splitlines()
    require(swaps and swaps[0].split() == ['Filename','Type','Size','Used','Priority'] and len(swaps) == 1,
            'private original observation requires swap disabled before migration')


def material(request, derive=None):
    private_environment()
    path, metadata = source(request); before = path.lstat()
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    raw = bytearray(); key = bytearray(); returned = False
    try:
        opened = os.fstat(fd); require((opened.st_dev,opened.st_ino) == (before.st_dev,before.st_ino), 'original identity inode changed')
        while len(raw) <= 4096:
            chunk = os.read(fd,4097-len(raw))
            if not chunk:break
            raw.extend(chunk)
        require(len(raw) <= 4096, 'original identity exceeded its bound')
        values = legacy.unique(raw)
        require(isinstance(values,list) and len(values) == 64 and all(type(v) is int and 0 <= v <= 255 for v in values), 'invalid original identity representation')
        key = bytearray(values); values[:] = [0] * len(values)
        if derive is None:
            result = subprocess.run(['/usr/bin/openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=PKCS8+key[:32],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            require(result.returncode == 0 and len(result.stdout) == 44 and result.stdout.startswith(SPKI), 'original identity derivation failed')
            derived = result.stdout[len(SPKI):]
        else: derived = derive(key[:32])
        require(derived == key[32:], 'original seed/public halves differ')
        public = public_key(base58(derived))
        require('host_identity' not in request or public == request['host_identity']['public'], 'approved original identity changed')
        require((metadata['role'] != 'rpc' or public == request['identity_account'])
                and (metadata['role'] != 'sync' or public != request['identity_account'])
                and public != request['vote_account'], 'original key is not an eligible host-only identity')
        after = os.fstat(fd); current = path.lstat()
        require((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_uid,after.st_gid,after.st_mode,after.st_nlink) ==
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_uid,before.st_gid,before.st_mode,before.st_nlink)
                and (current.st_dev,current.st_ino) == (opened.st_dev,opened.st_ino) and source(request)[1] == metadata,
                'original private identity changed during validation')
        returned = True
        return metadata | {'public':public}, key
    finally:
        raw[:] = b'\0'*len(raw)
        if not returned:key[:] = b'\0'*len(key)
        os.close(fd)


def qualified_material(request):
    private_environment()
    with bls.artifact(request) as image:
        candidate,key=material(request)
        try:
            candidate['bls_public']=bls.derive(image,key)
            require('host_identity' not in request or candidate==request['host_identity'], 'approved original BLS identity changed')
            return candidate,key
        except Exception:
            key[:]=bytes(len(key));raise


def inspect(request, withdrawer):
    # Complete source/process/ownership validation precedes even local key read.
    require((request.get('role') == 'rpc' and withdrawer is None)
            or (request.get('role') == 'validator' and public_key(withdrawer)), 'original withdrawal authority required')
    legacy.validate(request);runs.other_runs_idle(legacy.command)
    observed = legacy.inspect(request); candidate, key = qualified_material(request)
    try:
        require(candidate['public'] != withdrawer, 'original host key is a recorded withdrawal authority')
        registered = None if request['role']=='rpc' else {'identity':request['identity_account'],'vote_account':request['vote_account'],'withdrawer':withdrawer}
        proof = classify(request['network'],candidate['public'],candidate['bls_public'],registered=registered)
        require(proof.get('bls_authority_checked') is True, 'original BLS artifact qualification is required before migration')
        require(source(request)[1] == {k:v for k,v in candidate.items() if k not in ('public','bls_public')}, 'original key path changed after classification')
        return {'inspection':observed,'custody_source':candidate,'authority_observation':proof}
    finally:key[:] = b'\0'*len(key)
