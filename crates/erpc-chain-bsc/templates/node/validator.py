# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Owned BSC hot-key material; financial operator keys never enter this host."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

NAMES = ('bsc-consensus-pass', 'bsc-vote-pass')
MAX_FILE = 262144
ROOT_UID = 0


def durable_directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def private_run(c, argv, body=None, pass_fds=(), identity=None):
    # Passwords travel through pipes/inherited sealed descriptors only. Tool
    # diagnostics are intentionally never relayed as user-visible error text.
    credentials={}
    if identity is not None:
        uid,gid=identity
        c.require(all(type(value)is int and 100<=value<=65534 for value in identity), 'invalid unprivileged custody account')
        credentials={'user':uid,'group':gid,'extra_groups':[],'cwd':str(c.ROOT/'signing-stage')}
    result = subprocess.run(argv, input=body, stdin=None if body is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
                            check=False, pass_fds=pass_fds, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}, **credentials)
    c.require(result.returncode == 0 and len(result.stdout) <= MAX_FILE, 'BSC custody command failed; signing stays fenced')
    return result.stdout


def descriptor(value):
    fd = os.memfd_create('bsc-password', os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, value); os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except Exception:
        os.close(fd); raise


def decrypt(c, custody, name):
    entry = custody['credentials'][name]
    raw = base64.b64decode(entry['ciphertext'], validate=True)
    c.require(hashlib.sha256(raw).hexdigest() == entry['sha256'], 'BSC encrypted credential receipt differs')
    password = private_run(c, ['systemd-creds','decrypt','--name='+name,'-','-'],raw)
    c.require(re.fullmatch(b'[a-f0-9]{64}', password), 'BSC credential cannot be recovered on this host')
    return password


def credential_intent(c, state):
    custody = state.get('custody')
    if custody is None:
        c.require(not (c.ROOT/'signing-stage').exists() and not (c.ROOT/'signer').exists(), 'unowned signer material cannot be adopted')
        private_run(c, ['systemd-creds','setup'])
        credentials = {}
        for name in NAMES:
            plain = secrets.token_hex(32).encode()
            cipher = private_run(c, ['systemd-creds','encrypt','--with-key=host','--name='+name,'-','-'],plain)
            c.require(cipher, 'BSC credential encryption returned no data')
            credentials[name] = {'ciphertext':base64.b64encode(cipher).decode(),'sha256':hashlib.sha256(cipher).hexdigest()}
        custody = {'phase':'preparing','credentials':credentials}
        state['custody'] = custody
        # All credentials are durable together before a client can create a key.
        c.save(state)
    c.require(isinstance(custody,dict) and custody.get('phase') in ('preparing','sealed') and
              isinstance(custody.get('credentials'),dict) and set(custody['credentials']) == set(NAMES), 'invalid BSC custody receipt')
    return custody


def files(c, directory):
    c.require(directory.is_dir() and not directory.is_symlink(), 'BSC signer directory is missing or unsafe')
    result = {}
    for path in sorted(directory.rglob('*')):
        c.require(not path.is_symlink(), 'BSC signer links are refused')
        if path.is_dir(): continue
        c.require(path.is_file() and 0 < path.stat().st_size <= MAX_FILE, 'BSC signer file is invalid or oversized')
        result[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    c.require(0 < len(result) <= 32, 'unexpected BSC signer file set')
    return result


def account_quiet(c,state):
    for entry in c.PROC.iterdir():
        if not entry.name.isdigit():continue
        try:owner=entry.stat().st_uid
        except (FileNotFoundError,ProcessLookupError):
            c.require(not entry.exists(), 'cannot establish custody account quiescence');continue
        c.require(owner!=state['service_uid'], 'dedicated node account still has a process; custody remains fenced')


def stage_access(c,state,grant):
    stage=c.ROOT/'signing-stage'
    c.require(stage.is_dir() and not stage.is_symlink(), 'unsafe custody staging directory')
    # Reclaim the top-level directory before inspecting descendants. Managed
    # clients are already stopped; grant access only immediately before spawn.
    os.chown(stage,ROOT_UID,0 if ROOT_UID==0 else state['service_gid']);stage.chmod(0o700)
    for path in stage.rglob('*'):
        c.require(not path.is_symlink() and (path.is_file() or path.is_dir()), 'custody staging links/special files are refused')
        os.chown(path,state['service_uid'] if grant else ROOT_UID,state['service_gid'])
        path.chmod(0o700 if path.is_dir() else 0o600)
    if grant:os.chown(stage,state['service_uid'],state['service_gid'])


def geth(c, state, password, args):
    selected=dict(state,**state.get('target',{}));binary=c.binary(selected)
    asset=c.release(selected)['binaries'][state['platform']]
    c.require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size==asset['size'] and
              c.bootstrap.digest(binary,'sha256')==asset['sha256'], 'custody client differs from its reviewed artifact')
    account_quiet(c,state);stage_access(c,state,True)
    fd = descriptor(password)
    try:
        os.fchown(fd,state['service_uid'],state['service_gid']);os.fchmod(fd,0o400)
        args = [value.replace('@PASSWORD@','/proc/self/fd/'+str(fd)) for value in args]
        return private_run(c,[str(binary),*args],pass_fds=(fd,),identity=(state['service_uid'],state['service_gid']))
    finally:
        os.close(fd)
        account_quiet(c,state);stage_access(c,state,False)


def json_files(c, directory):
    if not directory.exists(): return []
    c.require(directory.is_dir() and not directory.is_symlink(), 'unsafe BSC key staging')
    result = []
    for path in directory.iterdir():
        c.require(path.is_file() and not path.is_symlink() and (re.fullmatch(r'UTC--[0-9TZ:.+-]+--[a-fA-F0-9]{40}',path.name) if directory.name == 'consensus' else re.fullmatch(r'keystore-[a-z0-9-]+\.json',path.name)) and
                  0 < path.stat().st_size <= MAX_FILE, 'unexpected BSC key staging file')
        result.append((path,json.loads(path.read_text())))
    c.require(len(result) <= 1, 'one consensus and one vote identity are required')
    return result


def provision(c, state):
    custody = credential_intent(c,state)
    if custody['phase'] == 'sealed':
        publish(c,state); return
    stage = c.ROOT/'signing-stage'
    c.require(not stage.is_symlink(), 'unsafe signer stage')
    stage.mkdir(mode=0o700,exist_ok=True)
    account_quiet(c,state);stage_access(c,state,False)
    consensus_password = decrypt(c,custody,NAMES[0])
    vote_password = decrypt(c,custody,NAMES[1])
    consensus_dir = stage/'consensus'
    if not json_files(c,consensus_dir):
        geth(c,state,consensus_password,['account','new','--datadir',str(stage),'--keystore',str(consensus_dir),'--password','@PASSWORD@'])
    consensus = json_files(c,consensus_dir)
    c.require(len(consensus) == 1, 'consensus key creation did not complete')
    address = consensus[0][1].get('address')
    c.require(isinstance(address,str) and re.fullmatch('[a-fA-F0-9]{40}',address) and int(address,16) != 0 and
              '0x'+address.lower() != state['operator'], 'invalid or conflicting consensus identity')
    vote_dir = stage/'bls/keystore'
    if not json_files(c,vote_dir):
        geth(c,state,vote_password,['bls','account','new','--datadir',str(stage),'--blspassword','@PASSWORD@'])
    vote = json_files(c,vote_dir)
    c.require(len(vote) == 1, 'vote key creation did not complete')
    pubkey = vote[0][1].get('pubkey')
    c.require(isinstance(pubkey,str) and re.fullmatch('[a-f0-9]{96}',pubkey), 'invalid vote identity')
    # A crash after writing the encrypted keystore but before wallet import is
    # recoverable without generating a replacement vote key. Import is deduplicated
    # by the pinned client's keymanager, then the complete wallet is inspected.
    geth(c,state,vote_password,['bls','account','import','--datadir',str(stage),'--blspassword','@PASSWORD@',
                              '--importedaccountpassword','@PASSWORD@',str(vote[0][0])])
    listed = geth(c,state,vote_password,['bls','account','list','--datadir',str(stage),'--blspassword','@PASSWORD@'])
    listed = re.sub(rb'\x1b\[[0-9;]*m',b'',listed)
    c.require(re.findall(rb'\[BLS public key\]\s+0x([a-f0-9]{96})',listed) == [pubkey.encode()], 'wallet vote identity differs from its single keystore')
    chain = '56' if state['network'] == 'mainnet' else '97'
    proof = geth(c,state,vote_password,['bls','account','generate-proof','--datadir',str(stage),'--blspassword','@PASSWORD@',
                                     '--chain-id',chain,state['operator'],pubkey])
    matches = re.findall(rb'^Proof: (0x[a-f0-9]{192})\s*$',proof,re.M)
    c.require(len(matches) == 1, 'possession proof did not complete')
    manifest = files(c,stage)
    for relative in manifest:
        path=stage/relative
        path.chmod(0o600)
        with path.open('rb') as stream: os.fsync(stream.fileno())
    for directory in sorted([p for p in stage.rglob('*') if p.is_dir()],key=lambda p:len(p.parts),reverse=True):
        durable_directory(directory)
    durable_directory(stage)
    custody.update(phase='sealed',consensus='0x'+address.lower(),vote=pubkey,proof=matches[0].decode(),files=manifest)
    c.save(state)
    publish(c,state)


def publish(c,state):
    custody=state['custody'];stage=c.ROOT/'signing-stage';signer=c.ROOT/'signer'
    if custody.get('published'):
        guard(c,state);return
    if not signer.exists():
        c.require(files(c,stage) == custody['files'], 'staged signing material differs from its durable receipt')
        os.replace(stage,signer);durable_directory(c.ROOT)
    c.require(files(c,signer) == custody['files'], 'signing material differs before publication')
    # The node can read encrypted keystores but cannot rewrite them, even by
    # creating another hard link through its writable database directory.
    for path in [signer,*signer.rglob('*')]:
        c.require(not path.is_symlink(), 'unsafe signer publication path')
        os.chown(path,ROOT_UID,state['service_gid']);path.chmod(0o550 if path.is_dir() else 0o440)
        if path.is_dir():durable_directory(path)
        else:
            with path.open('rb') as stream:os.fsync(stream.fileno())
    custody['published']=True;c.save(state)
    guard(c,state)


def guard(c,state):
    custody=state.get('custody');signer=c.ROOT/'signer'
    c.require(isinstance(custody,dict) and custody.get('phase') == 'sealed' and custody.get('published') is True, 'BSC signing identities are not published')
    c.require(files(c,signer) == custody.get('files'), 'BSC signing material is missing or changed; explicit recovery required')
    for path in [signer,*signer.rglob('*')]:
        mode=0o550 if path.is_dir() else 0o440
        info=path.stat()
        c.require(info.st_uid == ROOT_UID and info.st_gid == state['service_gid'] and info.st_mode & 0o777 == mode,
                  'BSC signer permissions changed; recovery required')
    for name in NAMES: decrypt(c,custody,name)


def configuration(c,state):
    raw=(c.CONF/'config.toml').read_bytes()
    c.require(hashlib.sha256(raw).hexdigest()==c.release(state)['config_sha256'], 'official configuration pin differs')
    lines=raw.decode('utf-8').splitlines(keepends=True)
    starts=[i for i,line in enumerate(lines) if line.strip()=='[Node]']
    c.require(len(starts)==1, 'qualified configuration must contain one Node section')
    start=starts[0]+1;end=next((i for i in range(start,len(lines)) if lines[i].lstrip().startswith('[')),len(lines))
    body=lines[start:end]
    for field in ('HTTPHost','WSHost'):
        matches=[line for line in body if re.match(r'^\s*'+field+r'\s*=',line)]
        c.require(len(matches)<=1, 'ambiguous qualified RPC listener configuration')
        body=[line for line in body if not re.match(r'^\s*'+field+r'\s*=',line)]
    return ''.join(lines[:start]+['HTTPHost = ""\n','WSHost = ""\n']+body+lines[end:]).encode()


def write_configuration(c,state):
    value=configuration(c,state);path=c.CONF/'validator.toml';temporary=path.with_suffix('.new')
    c.require(not path.is_symlink() and not temporary.is_symlink(), 'unsafe validator configuration path')
    fd=os.open(temporary,os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(value);stream.flush();os.fchmod(stream.fileno(),0o644);os.fsync(stream.fileno())
    os.replace(temporary,path);durable_directory(c.CONF)


def runtime_arguments(c,state,base):
    guard(c,state)
    forbidden=('--http','--ws','--config=','--keystore=','--mine=','--vote=','--cache=','--history.logs=')
    args=[value for value in base if not value.startswith(forbidden)]
    descriptors=[]
    try:
        for name in NAMES:
            fd=descriptor(decrypt(c,state['custody'],name));descriptors.append(fd)
            os.fchown(fd,state['service_uid'],state['service_gid']);os.fchmod(fd,0o400)
            os.set_inheritable(fd,True)
        public=state['custody'];signer=c.ROOT/'signer'
        args.extend(['--config='+str(c.CONF/'validator.toml'),'--keystore='+str(signer/'consensus'),'--unlock='+public['consensus'],
                     '--miner.etherbase='+public['consensus'],'--mine=false','--vote=true','--history.logs.disable',
                     '--cache='+('18000' if state['network']=='mainnet' else '10000'),
                     '--password=/proc/self/fd/'+str(descriptors[0]),'--blspassword=/proc/self/fd/'+str(descriptors[1]),
                     '--blswallet='+str(signer/'bls/wallet'),'--vote-journal-path='+str(c.ROOT/'data/voteJournal')])
        return args,descriptors
    except Exception:
        for fd in descriptors:os.close(fd)
        raise


def public(state):
    custody=state.get('custody',{})
    return {key:custody[key] for key in ('consensus','vote','proof') if key in custody}


# Selectors are Keccak-256 of the exact view signatures, also checked by Rust.
STAKE_HUB = '0x0000000000000000000000000000000000002002'
REGISTRATION_SELECTORS = {'consensus':'059ddd22','vote':'6f8e2fa4','basic':'cbb04d9d'}


def registration(c,state,block="latest"):
    operator=state['operator']
    c.require(re.fullmatch('0x[a-f0-9]{40}',operator), 'invalid public operator')
    argument='0'*24+operator[2:]
    results={}
    for name,selector in REGISTRATION_SELECTORS.items():
        value=c.rpc('eth_call',[{'to':STAKE_HUB,'data':'0x'+selector+argument},block])
        c.require(isinstance(value,str) and len(value)<=258 and re.fullmatch('0x(?:[a-fA-F0-9]{2})*',value), 'invalid registration response')
        results[name]=bytes.fromhex(value[2:])
    consensus=results['consensus'];vote=results['vote'];basic=results['basic']
    c.require(len(consensus)==32 and consensus[:12]==bytes(12), 'invalid registered consensus encoding')
    c.require(len(vote) in (64,128) and int.from_bytes(vote[:32],'big')==32, 'invalid registered vote encoding')
    length=int.from_bytes(vote[32:64],'big')
    c.require((length==0 and len(vote)==64) or (length==48 and len(vote)==128 and vote[112:]==bytes(16)), 'invalid registered vote length')
    c.require(len(basic)==96 and int.from_bytes(basic[32:64],'big') in (0,1), 'invalid registration state encoding')
    created=int.from_bytes(basic[:32],'big');jailed=int.from_bytes(basic[32:64],'big')==1;jail_until=int.from_bytes(basic[64:],'big')
    c.require(created<2**64 and jail_until<2**64, 'invalid registration timestamp')
    if created==0:
        c.require(consensus==bytes(32) and length==0 and not jailed and jail_until==0, 'inconsistent absent registration')
    else:
        c.require(consensus!=bytes(32) and length==48 and any(vote[64:112]), 'incomplete registered identities')
    observed_consensus='0x'+consensus[12:].hex();observed_vote=vote[64:64+length].hex()
    identity=state['custody']
    matching=created>0 and observed_consensus==identity['consensus'] and observed_vote==identity['vote']
    return {'registered':matching,'jailed':jailed,'jail_until':jail_until,
            'identity_conflict':created>0 and not matching,'created':created}


def election(c,state,head):
    block_hash=head.get('hash')
    c.require(isinstance(block_hash,str) and re.fullmatch('0x[a-fA-F0-9]{64}',block_hash), 'BSC head hash unavailable')
    snapshot=c.rpc('parlia_getSnapshotAtHash',[block_hash])
    c.require(isinstance(snapshot,dict) and type(snapshot.get('number'))is int and snapshot['number']==int(head['number'],16) and
              snapshot.get('hash')==block_hash and isinstance(snapshot.get('validators'),dict) and 0<len(snapshot['validators'])<=256,
              'BSC epoch validator snapshot unavailable')
    elected={}
    for consensus,info in snapshot['validators'].items():
        c.require(isinstance(consensus,str) and re.fullmatch('0x[a-fA-F0-9]{40}',consensus) and isinstance(info,dict), 'invalid epoch validator identity')
        vote=info.get('vote_address')
        c.require(isinstance(vote,list) and len(vote)==48 and all(type(x)is int and 0<=x<=255 for x in vote), 'epoch vote identity unavailable')
        c.require(consensus.lower() not in elected, 'duplicate epoch validator identity')
        elected[consensus.lower()]=bytes(vote).hex()
    consensus=state['custody']['consensus'];vote=state['custody']['vote']
    return {'consensus_elected':consensus in elected,'vote_elected':elected.get(consensus)==vote,'snapshot_block':snapshot['number']}


def journal(c,state,initialize=False):
    """Inspect the pinned native JSON WAL without deleting or repairing history.

    Geth uses tidwall/wal v1.1.7, fsync enabled, and retains512 vote records.
    START remnants are verified too. Unrecognized/partial records quarantine the
    signer; they are never silently skipped as the native reader may do.
    """
    path=c.ROOT/'data/voteJournal'
    c.require(not path.is_symlink(), 'unsafe native vote journal')
    if not state.get('journal_bound'):
        c.require(initialize, 'missing vote history cannot be adopted')
        if not state.get('journal_creating'):
            c.require(not path.exists(), 'unowned native vote history cannot be adopted')
            state['journal_creating']=True;c.save(state)
        if path.exists():
            c.require(path.is_dir() and all(p.name=='00000000000000000001' and p.is_file() and not p.is_symlink() and p.stat().st_size==0 for p in path.iterdir()), 'interrupted journal creation contains foreign history')
        else:path.mkdir(mode=0o700)
        first=path/'00000000000000000001'
        if not first.exists():
            fd=os.open(first,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
            try:os.fsync(fd)
            finally:os.close(fd)
        os.chown(first,state['service_uid'],state['service_gid']);os.chown(path,state['service_uid'],state['service_gid'])
        durable_directory(path);durable_directory(path.parent)
        state.update(journal_bound=True,journal_checkpoint=0);state.pop('journal_creating',None);c.save(state)
    c.require(path.is_dir(), 'native vote journal missing; signing remains fenced')
    entries=list(path.iterdir());c.require(0<len(entries)<=32, 'native vote journal segment set is invalid')
    total=0;maximum=0;count=0;segments=[]
    for segment in sorted(entries):
        c.require(re.fullmatch('[0-9]{20}(?:\\.START)?',segment.name) and int(segment.name[:20])>0 and segment.is_file() and not segment.is_symlink(), 'unexpected native journal artifact; inspection required')
        total+=segment.stat().st_size;c.require(total<=8*1024*1024, 'native vote history exceeds the reviewed bound')
        raw=segment.read_bytes()
        c.require(not raw or raw.endswith(b'\n'), 'partial native vote history; recovery required')
        if not raw:c.require(segment.name=='00000000000000000001', 'ambiguous empty native journal segment')
        expected=int(segment.name[:20]);indices=[]
        for line in raw.splitlines():
            record=json.loads(line);c.require(isinstance(record,dict) and set(record)=={'index','data'}, 'malformed native vote journal record')
            c.require(record['index']==str(expected) and isinstance(record['data'],str) and record['data'].startswith('+'), 'native journal order or encoding differs')
            value=json.loads(record['data'][1:]);c.require(isinstance(value,dict) and set(value)=={'VoteAddress','Signature','Data'}, 'malformed native vote envelope')
            for name,size in (('VoteAddress',48),('Signature',96)):
                field=value[name];c.require(isinstance(field,list) and len(field)==size and all(type(x)is int and 0<=x<=255 for x in field), 'malformed native vote identity/signature')
            c.require(bytes(value['VoteAddress']).hex()==state['custody']['vote'], 'native vote history belongs to another signer')
            data=value['Data'];c.require(isinstance(data,dict) and set(data)=={'SourceNumber','SourceHash','TargetNumber','TargetHash'}, 'malformed native vote range')
            for name in ('SourceNumber','TargetNumber'):
                c.require(type(data[name])is int and 0<=data[name]<2**64, 'invalid native vote height')
            c.require(data['SourceNumber']<data['TargetNumber'], 'invalid native vote ordering')
            for name in ('SourceHash','TargetHash'):
                c.require(isinstance(data[name],str) and re.fullmatch('0x[a-fA-F0-9]{64}',data[name]), 'invalid native vote block hash')
            c.require(expected<2**64, 'native vote journal index exceeds uint64')
            indices.append(expected);expected+=1;count+=1
            c.require(count<=4096, 'unexpected native vote history length')
        segments.append((segment.name,indices))
    # tidwall/wal.load sorts names, then discards every segment preceding START
    # before renaming START. Old pre-truncation copies cannot fill holes in the
    # effective history the native client will actually reload.
    starts=[index for index,(name,_) in enumerate(segments) if name.endswith('.START')]
    c.require(len(starts)<=1, 'ambiguous native front-truncation recovery')
    effective=segments[starts[0]:] if starts else segments
    previous=None;retained=[]
    for name,indices in effective:
        c.require(indices or (len(effective)==1 and name=='00000000000000000001'), 'empty effective native journal segment')
        for index in indices:
            c.require(previous is None or index==previous+1, 'native vote history has missing or conflicting segments')
            retained.append(index);previous=index
    if retained:
        maximum=retained[-1]
        c.require(retained[0]<=max(1,maximum-511), 'native recent vote window is incomplete')
    checkpoint=state.get('journal_checkpoint',0)
    c.require(type(checkpoint)is int and 0<=checkpoint<2**64 and maximum>=checkpoint, 'native vote history regressed behind the stopped checkpoint')
    return maximum


def peer_identity(c,state):
    path=c.ROOT/'identity/nodekey'
    c.require(path.is_file() and not path.is_symlink() and path.stat().st_size==64, 'owned peer identity is missing or unsafe')
    raw=path.read_bytes()
    c.require(re.fullmatch(b'[a-f0-9]{64}',raw) and hashlib.sha256(raw).hexdigest()==state.get('identity_sha256'), 'owned peer identity differs')
    return raw


def restore_peer(c,state,raw,pending):
    directory=c.ROOT/'identity';path=directory/'nodekey';temporary=directory/'nodekey.recovery-new'
    c.require(not directory.is_symlink() and (not directory.exists() or directory.is_dir()) and not path.is_symlink() and not temporary.is_symlink(), 'unsafe peer recovery path')
    directory.mkdir(mode=0o755,exist_ok=True)
    c.require(directory.stat().st_uid==ROOT_UID and directory.stat().st_mode & 0o022==0, 'peer directory must remain root controlled')
    directory.chmod(0o755)
    if path.exists() and path.is_file() and path.read_bytes()==raw:return
    retained=c.ROOT/(pending['retained']+'-peer')
    if path.exists():
        c.require(path.is_file() and not retained.exists(), 'inspect retained peer identity before retrying')
        os.rename(path,retained);os.chown(retained,ROOT_UID,0 if ROOT_UID==0 else state['service_gid']);retained.chmod(0o600);durable_directory(c.ROOT)
    fd=os.open(temporary,os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fchown(stream.fileno(),state['service_uid'],state['service_gid']);os.fsync(stream.fileno())
    os.replace(temporary,path);durable_directory(directory)


def export_backup(c,state):
    guard(c,state)
    signer=c.ROOT/'signer'
    material={'format':1,'owner':state['owner'],'network':state['network'],'operator':state['operator'],
              'identities':public(state),'peer':base64.b64encode(peer_identity(c,state)).decode(),'files':{name:base64.b64encode((signer/name).read_bytes()).decode() for name in state['custody']['files']},
              'passwords':{name:decrypt(c,state['custody'],name).decode() for name in NAMES}}
    raw=json.dumps(material,sort_keys=True,separators=(',',':'))
    c.require(len(raw.encode())<=65536, 'BSC custody backup exceeds the concealed-field bound')
    return raw


def confirm_backup(c,state,digest):
    expected=hashlib.sha256(export_backup(c,state).encode()).hexdigest()
    c.require(isinstance(digest,str) and digest==expected, 'BSC backup acknowledgement differs from owned material')
    state.update(backup_digest=expected,backup_confirmed=True);c.save(state)


def restore(c,state,raw):
    """Restore only this established owner's identical keys; never its journal."""
    c.require(isinstance(raw,str) and len(raw.encode())<=65536 and state.get('backup_confirmed') is True and
              hashlib.sha256(raw.encode()).hexdigest()==state.get('backup_digest'), 'backup is not the acknowledged same-owner custody bundle')
    value=json.loads(raw)
    c.require(isinstance(value,dict) and set(value)=={'format','owner','network','operator','identities','peer','files','passwords'} and
              value['format']==1 and (value['owner'],value['network'],value['operator'])==(state['owner'],state['network'],state['operator']) and
              value['identities']==public(state), 'backup identity differs from the established owner')
    c.require(isinstance(value['passwords'],dict) and set(value['passwords'])==set(NAMES) and
              isinstance(value['files'],dict) and set(value['files'])==set(state['custody']['files']), 'backup file/credential set differs')
    # Missing history cannot be replaced by a key-only recovery, even if the key
    # backup is otherwise authentic. All writers were stopped by the caller.
    journal(c,state)
    peer=base64.b64decode(value['peer'],validate=True)
    c.require(re.fullmatch(b'[a-f0-9]{64}',peer) and hashlib.sha256(peer).hexdigest()==state.get('identity_sha256'), 'backup peer identity differs')
    decoded={}
    for name,encoded in value['files'].items():
        parts=Path(name).parts
        c.require(parts and not Path(name).is_absolute() and all(part not in ('.','..') for part in parts) and str(Path(name))==name and '\\' not in name,
                  'unsafe backup path')
        content=base64.b64decode(encoded,validate=True)
        c.require(0<len(content)<=MAX_FILE and hashlib.sha256(content).hexdigest()==state['custody']['files'][name], 'backup key material differs')
        decoded[name]=content
    stage=c.ROOT/'signing-stage';signer=c.ROOT/'signer'
    pending=state.get('custody_recovery')
    if pending is None:
        c.require(not stage.exists() and not stage.is_symlink(), 'inspect retained signer stage before recovery')
        private_run(c,['systemd-creds','setup'])
        credentials={}
        for name in NAMES:
            plain=value['passwords'][name]
            c.require(isinstance(plain,str) and re.fullmatch('[a-f0-9]{64}',plain), 'invalid backup password')
            cipher=private_run(c,['systemd-creds','encrypt','--with-key=host','--name='+name,'-','-'],plain.encode())
            credentials[name]={'ciphertext':base64.b64encode(cipher).decode(),'sha256':hashlib.sha256(cipher).hexdigest()}
        pending={'phase':'staging','digest':state['backup_digest'],'credentials':credentials,'retained':'signer-retained-'+secrets.token_hex(8)}
        state['custody_recovery']=pending;c.save(state)
    c.require(isinstance(pending,dict) and pending.get('phase') in ('staging','publishing') and pending.get('digest')==state['backup_digest'] and
              isinstance(pending.get('retained'),str) and re.fullmatch('signer-retained-[a-f0-9]{16}',pending['retained']), 'recovery intent differs')
    if pending['phase']=='publishing':
        c.require(state['custody']['credentials']==pending['credentials'], 'recovery credential receipt differs')
        publish(c,state)
    else:
        c.require(not stage.is_symlink(), 'unsafe recovery stage')
        stage.mkdir(mode=0o700,exist_ok=True)
        allowed=set(decoded)|{name+'.recovery-new' for name in decoded}
        for path in stage.rglob('*'):
            c.require(not path.is_symlink() and (path.is_dir() or (path.is_file() and str(path.relative_to(stage)) in allowed)), 'unexpected recovery stage artifact')
        for name,content in decoded.items():
            path=stage/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            if path.exists():
                c.require(path.is_file() and path.read_bytes()==content, 'retained recovery file differs')
                continue
            temporary=path.with_name(path.name+'.recovery-new')
            c.require(not temporary.is_symlink() and (not temporary.exists() or temporary.is_file()), 'unsafe recovery temporary file')
            fd=os.open(temporary,os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path);durable_directory(path.parent)
        for directory in sorted([p for p in stage.rglob('*') if p.is_dir()],key=lambda p:len(p.parts),reverse=True):durable_directory(directory)
        durable_directory(stage);durable_directory(c.ROOT)
        c.require(not signer.is_symlink(), 'unsafe established signer path')
        if signer.exists():
            quarantine=c.ROOT/pending['retained']
            c.require(not quarantine.exists(), 'retained custody destination already exists')
            os.rename(signer,quarantine);durable_directory(c.ROOT)
        pending['phase']='publishing'
        state['custody'].update(credentials=pending['credentials'],published=False);c.save(state)
        publish(c,state)
    restore_peer(c,state,peer,pending)
    c.require(hashlib.sha256(export_backup(c,state).encode()).hexdigest()==state['backup_digest'], 'recovered material differs from acknowledged backup')
    state.pop('custody_recovery');c.save(state)
