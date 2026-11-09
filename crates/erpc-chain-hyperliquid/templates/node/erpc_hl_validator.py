# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original consensus-hot credential custody; never sign or broadcast financial actions."""
import os
import base64
from pathlib import Path
import re
import stat
import tempfile
from erpc_hl_common import ROOT, atomic, digest, execute, fsync_dir, json_bytes, owned_directory, read, require, unique_json
from erpc_hl_state import State
import erpc_hl_setup as setup
import erpc_hl_processes as processes
from erpc_hl_validator_public import money

CREDENTIALS = Path('/etc/credstore.encrypted')
NAME = 'erpc-hyperliquid-consensus.json'
ACTIVE = CREDENTIALS / NAME
DECRYPTED = Path('/run/credentials/erpc-hyperliquid-node.service') / NAME
ROOT_UID = 0
PUBLIC_DER_PREFIX = bytes.fromhex('3056301006072a8648ce3d020106052b8104000a034200')
PLACEHOLDER = b'{"key":"systemd-credential-required"}\n'


def public_identity(contract):
    require(contract.get('role') == 'validator', 'consensus custody requires the validator contract')
    value = contract.get('validator')
    require(isinstance(value, dict) and set(value) == {'validator','signer','signer_public_key','max_hot_usdc'},
            'complete original validator identities are required')
    for name in ('validator','signer'):
        require(isinstance(value[name], str) and re.fullmatch('0x[a-f0-9]{40}', value[name])
                and value[name] != '0x'+'0'*40, 'canonical original public address required')
    require(value['validator'] != value['signer'] and isinstance(value['signer_public_key'], str)
            and re.fullmatch('04[a-f0-9]{128}', value['signer_public_key']),
            'cold validator and dedicated consensus-hot identities must be distinct')
    require(isinstance(value['max_hot_usdc'],str)
            and re.fullmatch(r'(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?',value['max_hot_usdc'])
            and money(value['max_hot_usdc'])>0,'explicit positive dedicated hot-balance ceiling required')
    return value


def material(raw, contract):
    identity = public_identity(contract)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 4096, 'bounded original native key object required')
    value = unique_json(raw)
    require(isinstance(value, dict) and set(value) == {'key'} and isinstance(value['key'], str),
            'native key object must contain only its original key field')
    text = value['key']
    if text.startswith('0x'): text = text[2:]
    require(re.fullmatch('[a-fA-F0-9]{64}', text), 'invalid native consensus scalar encoding')
    # SEC1 ECPrivateKey parameters name secp256k1. OpenSSL receives secret bytes
    # through stdin and returns only its public point; never use --key argv.
    scalar = bytes.fromhex(text)
    der = bytes.fromhex('302e0201010420') + scalar + bytes.fromhex('a00706052b8104000a')
    public = execute(['/usr/bin/openssl','ec','-inform','DER','-pubout','-outform','DER'],input_data=der).stdout
    require(public == PUBLIC_DER_PREFIX + bytes.fromhex(identity['signer_public_key']),
            'native consensus key differs from the original public point')
    return digest(raw)


def fresh_namespace():
    if not CREDENTIALS.exists() and not CREDENTIALS.is_symlink(): return
    owned_directory(CREDENTIALS)
    require(not any(path.name==NAME or path.name.startswith(NAME+'.')
                    or path.name.startswith('.erpc-hl-consensus-') for path in CREDENTIALS.iterdir()),
            'unowned consensus ciphertext or interrupted custody staging cannot be adopted')


def private_file(path):
    owned_directory(path.parent)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1
            and info.st_mode & 0o077 == 0 and 0 < info.st_size <= 65536,
            'encrypted consensus credential is indirect, foreign, shared or oversized')
    return read(path, limit=65536)


def receipt(contract):
    state = State(ROOT)
    state.check(contract)
    public_identity(contract)
    value = state.get('validator-identity.json')
    require(isinstance(value, dict) and set(value) == {'contract','plaintext_sha256','cipher_sha256','pending_file'}
            and value['contract'] == contract
            and all(isinstance(value[name],str) and re.fullmatch('[a-f0-9]{64}',value[name])
                    for name in ('plaintext_sha256','cipher_sha256'))
            and isinstance(value['pending_file'],str) and re.fullmatch(r'\.erpc-hl-consensus-[A-Za-z0-9_-]+',value['pending_file']),
            'original consensus receipt is missing or malformed')
    return value


def identity(contract):
    expected = receipt(contract)
    require(digest(private_file(ACTIVE)) == expected['cipher_sha256'],
            'original consensus ciphertext is missing or changed; explicit original-key recovery required')
    return expected


def recover_publication(contract):
    expected = receipt(contract)
    if ACTIVE.exists() and digest(private_file(ACTIVE)) == expected['cipher_sha256']:
        fsync_dir(CREDENTIALS)
        return expected
    candidate = CREDENTIALS / expected['pending_file']
    require(digest(private_file(candidate)) == expected['cipher_sha256'],
            'interrupted consensus publication lacks its matching original ciphertext')
    os.replace(candidate, ACTIVE)
    fsync_dir(CREDENTIALS)
    return identity(contract)


def retain_ciphertext():
    if not ACTIVE.exists() and not ACTIVE.is_symlink(): return
    raw = private_file(ACTIVE)
    old = CREDENTIALS / (NAME + '.previous.' + digest(raw))
    if old.exists() or old.is_symlink():
        require(private_file(old) == raw, 'retained original ciphertext differs')
    else:
        atomic(old, raw, 0o600)  # Independent inode, never a hardlink to ACTIVE.
    fsync_dir(CREDENTIALS)


def import_original(contract, raw, *, restore, unhosted, stop):
    state = State(ROOT)
    state.check(contract)
    setup.accounts(state.get('accounts.json'))
    require(type(restore) is bool and type(unhosted) is bool, 'explicit custody choices required')
    plaintext = material(raw, contract)
    installed = (ROOT/'validator-identity.json').exists()
    if installed:
        original = receipt(contract)
        require(original['plaintext_sha256'] == plaintext,
                'recovery may restore only the original native credential bytes')
        if not restore:
            state.cancel(contract, False, stop)
            recover_publication(contract)
            return {'custody':'original','restored':False}
    else:
        require(unhosted and not restore, 'first import requires a dedicated key not hosted elsewhere')
        require(not ACTIVE.exists() and not ACTIVE.is_symlink(), 'unowned consensus ciphertext cannot be adopted')
    pending = {'contract':contract,'plaintext_sha256':plaintext}
    if (ROOT/'validator-import.json').exists():
        require(state.get('validator-import.json') == pending, 'another original-key import is incomplete')
    # All independent cancellation writes and owned drain must finish before
    # publishing a replacement credential or changing the original receipt.
    state.cancel(contract, False, stop)
    state.put('validator-import.json', pending)
    owned_directory(CREDENTIALS,create=True,mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix='.erpc-hl-consensus-',dir=CREDENTIALS)
    os.close(descriptor)
    candidate = Path(name)
    keep = False
    try:
        execute(['/usr/bin/systemd-creds','encrypt','--name='+NAME,'-',str(candidate)],input_data=raw)
        os.chmod(candidate,0o600)
        encrypted = private_file(candidate)
        recovered=execute(['/usr/bin/systemd-creds','decrypt','--name='+NAME,str(candidate),'-']).stdout
        require(material(recovered,contract)==plaintext,
                'encrypted original credential failed private read-back verification')
        descriptor = os.open(candidate,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        fsync_dir(CREDENTIALS)
        retain_ciphertext()
        expected = {'contract':contract,'plaintext_sha256':plaintext,'cipher_sha256':digest(encrypted),
                    'pending_file':candidate.name}
        # Once publication is attempted, an I/O failure may hide whether the
        # receipt already references this candidate. Preserve opaque ciphertext
        # instead of deleting recovery material on an ambiguous write/read.
        keep = True
        state.put('validator-identity.json',expected)
        os.replace(candidate,ACTIVE)
        fsync_dir(CREDENTIALS)
        state.put('validator-import.json',pending)
        identity(contract)
        return {'custody':'original','restored':restore}
    finally:
        if not keep: candidate.unlink(missing_ok=True)


def verify_runtime(contract):
    expected = identity(contract)
    accounts = State(ROOT).get('accounts.json')
    setup.accounts(accounts)
    native_uid = accounts[setup.NATIVE]['uid']
    # This path is systemd's per-service decrypted credential namespace.
    fd = os.open(DECRYPTED,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info = os.fstat(source.fileno())
        # systemd255 first sets0400, then may grant the service UID a named
        # read ACL; its mask is reflected as0440 by stat. No write/other bits.
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4096
                and info.st_uid in (ROOT_UID,native_uid) and stat.S_IMODE(info.st_mode) in (0o400,0o440),
                'runtime consensus credential is not a bounded regular file')
        raw = source.read(4097)
    require(material(raw,contract) == expected['plaintext_sha256'],
            'runtime consensus credential differs from its original bytes')
    return {'custody':'original','signer':contract['validator']['signer']}


def private_filesystem(directory,descriptor):
    """Observe the complete original native volume; never persist kernel IDs."""
    setup.storage_mounts()
    before=os.fstat(descriptor);path=directory.lstat()
    require(stat.S_ISDIR(path.st_mode) and (before.st_dev,before.st_ino)==(path.st_dev,path.st_ino),
            'native private-state pathname changed during observation')
    result=execute(['/usr/bin/findmnt','--task','1','--json','--target',str(ROOT),
                    '--output','UUID,FSTYPE,FSROOT,MAJ:MIN,OPTIONS'],timeout=30)
    require(0<len(result.stdout)<=65536,'native filesystem observation exceeds its bound')
    value=unique_json(result.stdout)
    require(isinstance(value,dict) and set(value)=={'filesystems'} and isinstance(value['filesystems'],list)
            and len(value['filesystems'])==1 and isinstance(value['filesystems'][0],dict),
            'original native filesystem is ambiguous')
    value=value['filesystems'][0];identifier=value.get('uuid');number=value.get('maj:min')
    require(isinstance(identifier,str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',identifier)
            and any(char not in '0-' for char in identifier) and value.get('fstype') in ('ext4','xfs')
            and value.get('fsroot')=='/' and isinstance(value.get('options'),str)
            and 'rw' in value['options'].split(',') and isinstance(number,str) and re.fullmatch('[0-9]+:[0-9]+',number),
            'native private state requires an identified writable ext4/XFS filesystem root')
    major,minor=map(int,number.split(':'));after=directory.lstat()
    require(os.makedev(major,minor)==before.st_dev==ROOT.lstat().st_dev
            and (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),
            'native filesystem changed during observation')
    return {'uuid':identifier,'filesystem':value['fstype'],'filesystem_root':value['fsroot']}


def native_path(contract, create=False, original_uuid=None):
    """Retain original private-state directory and a nonsecret bind destination.

    Preparation holds the global operation lock and has stopped all writers.
    Startup checks run through systemd's privileged precondition, outside its
    native process's read-only credential bind mount.
    """
    state=State(ROOT);state.check(contract);identity(contract)
    accounts=state.get('accounts.json');setup.accounts(accounts)
    native=accounts[setup.NATIVE]
    recovering=original_uuid is not None
    if recovering:
        require(not create and isinstance(original_uuid,str)
                and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',original_uuid)
                and any(char not in '0-' for char in original_uuid),'independently recorded original filesystem UUID is required')
        require((ROOT/'stopped').exists() and state.get('operation.json').get('intent') is None,
                'explicit durable stop is required before private filesystem recovery')
    if create or recovering: processes.quiescent([entry['uid'] for entry in accounts.values()])
    # Existing storage validation opens these ancestors without following links.
    opened,complete=setup.storage_descriptor(native)
    try:
        require(complete,'native follower data is not initialized')
        parent=os.open('..',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=opened)
    finally:os.close(opened)
    directory=setup.HOME/'hl/hyperliquid_data'
    current=directory.parent.lstat();held=os.fstat(parent)
    if (current.st_dev,current.st_ino)!=(held.st_dev,held.st_ino):
        os.close(parent);raise ValueError('native private parent changed after original storage validation')
    fd=None
    try:
        if create:
            try:os.mkdir(directory.name,0o700,dir_fd=parent)
            except FileExistsError:pass
        child=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            info=os.fstat(child)
            require(info.st_dev==os.fstat(parent).st_dev and info.st_uid in (ROOT_UID,native['uid'])
                    and stat.S_IMODE(info.st_mode)==0o700,'native private-state directory is indirect or foreign')
            filesystem=private_filesystem(directory,child)
            observed={'format':2,'contract':contract,'account':native,'filesystem':filesystem,'inode':info.st_ino}
            recorded=ROOT/'validator-native-path.json';pending=ROOT/'validator-native-path.pending.json'
            migration=None
            if recorded.exists():
                saved=state.get(recorded.name)
                if recovering:
                    require(filesystem['uuid']==original_uuid,'supplied original UUID does not match private native state')
                    migration_file=ROOT/'validator-native-volume-upgrade.json'
                    if saved==observed:
                        require(migration_file.exists(),'no original legacy filesystem upgrade exists to retry')
                        migration=state.get(migration_file.name)
                        require(isinstance(migration,dict) and set(migration)=={'format','contract','original_receipt','original_sha256','upgraded'}
                                and type(migration['format'])is int and migration['format']==1 and migration['contract']==contract
                                and migration['upgraded']==observed and isinstance(migration['original_receipt'],str)
                                and len(migration['original_receipt'])<=1048576,'completed private filesystem recovery differs')
                        original=base64.b64decode(migration['original_receipt'],validate=True)
                        require(digest(original)==migration['original_sha256'] and unique_json(original).get('contract')==contract,
                                'retained original private filesystem receipt changed')
                    else:
                        require(saved=={'contract':contract,'device':saved.get('device'),'inode':info.st_ino}
                                and type(saved.get('device'))is int and saved['device']>=0 and type(saved.get('inode'))is int,
                                'legacy private-state inode or original scope differs; no history adoption')
                        original=read(recorded)
                        require(unique_json(original)==saved,'legacy private filesystem receipt changed during observation')
                        migration={'format':1,'contract':contract,'original_receipt':base64.b64encode(original).decode(),
                                   'original_sha256':digest(original),'upgraded':observed}
                        if migration_file.exists():require(state.get(migration_file.name)==migration,
                            'interrupted private filesystem recovery belongs to another original receipt or UUID')
                else:require(saved==observed,
                        'original private-state directory changed or legacy receipt needs explicit UUID recovery; no automatic history reset')
            else:
                require(create,'original private-state ownership receipt is missing')
                if (ROOT/'installed.json').exists():
                    require(state.get('installed.json')['operation']['target'].get('mode')!='validator',
                            'established validator history cannot be re-reserved')
                if pending.exists():require(state.get(pending.name)==observed,'interrupted private-state publication belongs to another original filesystem or directory')
                else:state.put(pending.name,observed)
                # Re-establish durable authority before numeric handoff or even
                # the non-secret native bind destination can be published.
                descriptor=os.open(pending,os.O_RDONLY|os.O_NOFOLLOW)
                try:os.fsync(descriptor)
                finally:os.close(descriptor)
                fsync_dir(ROOT)
            if create and info.st_uid==ROOT_UID:
                require(not os.listdir(child),'unknown root-owned native private state cannot be adopted')
                os.fchown(child,native['uid'],native['gid'])
                info=os.fstat(child)
            require(info.st_uid==native['uid'] and info.st_gid==native['gid'],
                    'native private-state identity changed')
            if create:
                try:
                    os.stat('node_config.json',dir_fd=child,follow_symlinks=False)
                except FileNotFoundError:
                    require(not recorded.exists(),'established native configuration destination is missing')
                    # The original dedicated writers were proven quiescent;
                    # this is public placeholder material, never a private key.
                    # Atomic publication cannot leave a partial target behind.
                    atomic(directory/'node_config.json',PLACEHOLDER,0o600)
            if fd is None:fd=os.open('node_config.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=child)
            marker=os.fstat(fd)
            require(stat.S_ISREG(marker.st_mode) and marker.st_uid==ROOT_UID and marker.st_nlink==1
                    and stat.S_IMODE(marker.st_mode)==0o600 and marker.st_size==len(PLACEHOLDER),
                    'native configuration is not the owned nonsecret credential destination')
            os.lseek(fd,0,os.SEEK_SET)
            require(os.read(fd,len(PLACEHOLDER)+1)==PLACEHOLDER,
                    'unknown existing native key configuration cannot be overwritten')
            require(private_filesystem(directory,child)==filesystem,'native original volume changed before publication')
            if recovering:
                # Preserve exact previous public authority before publication.
                # No key, native byte, owner or signing-history mutation occurs.
                state.put(migration_file.name,migration)
                require((ROOT/'stopped').exists() and state.get('operation.json').get('intent') is None
                        and private_filesystem(directory,child)==filesystem
                        and state.get(recorded.name)==saved,'private filesystem recovery was superseded')
            if create or recovering:
                os.fsync(fd);os.fsync(child);os.fsync(parent)
                state.put('validator-native-path.json',observed)
            return str(directory/'node_config.json')
        finally:os.close(child)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
