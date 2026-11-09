# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Native conversion of the dedicated hot signer, with no owner transactions.

The authenticated Bor importer creates its standard-scrypt V3 keystore; the
Heimdall importer creates the fork's native secp256k1eth FilePV key. Conversion
runs in a private tmpfs home and an isolated network namespace. No client starts,
no transaction is signed, and no plaintext key is passed in argv/environment.
"""
import base64
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile

from configure import client
from state import canonical,unique

FILES=('bor-signer.json','bor-password','heimdall-validator-key.json')
MAX_FILE=65536


def secret_scalar(value):
    if not isinstance(value,str):raise ValueError('expected a concealed raw dedicated signer')
    raw=value[2:] if value.startswith('0x') else value
    if not re.fullmatch('[a-fA-F0-9]{64}',raw):raise ValueError('invalid dedicated signer encoding')
    number=int(raw,16)
    # secp256k1 group order; validate before handing any native program input.
    if not 0<number<int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',16):
        raise ValueError('dedicated signer scalar is outside the native curve')
    return bytes.fromhex(raw)


def address(value):
    if not isinstance(value,str) or not re.fullmatch('0x[a-fA-F0-9]{40}',value) or int(value[2:],16)==0:
        raise ValueError('invalid public signer address')
    return value.lower()


def public_key(raw):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    return ec.derive_private_key(int.from_bytes(raw,'big'),ec.SECP256K1()).public_key().public_bytes(
        Encoding.X962,PublicFormat.UncompressedPoint)


def public_address(point):
    from signatures import keccak
    if not isinstance(point,bytes) or len(point)!=65 or point[0]!=4:raise ValueError('invalid original signer public encoding')
    return '0x'+keccak(point[1:])[-20:].hex()


@contextmanager
def private_descriptor(value):
    descriptor=os.memfd_create('polygon-native-import',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor,0o600)
        with os.fdopen(os.dup(descriptor),'wb') as stream:stream.write(value)
        os.lseek(descriptor,0,os.SEEK_SET)
        fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        yield descriptor
    finally:os.close(descriptor)


def bounded(path):
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
            or info.st_mode&0o077 or info.st_size>MAX_FILE):
        raise ValueError('native private output has unsafe ownership, type, mode or size')
    with path.open('rb') as stream:value=stream.read(MAX_FILE+1)
    if len(value)>MAX_FILE:raise ValueError('native private output exceeded its bound')
    return value


def checked_material(raw,signer,heimdall,bor,derive=public_key):
    expected=address(signer)
    native=json.loads(heimdall,object_pairs_hook=unique)
    account=json.loads(bor,object_pairs_hook=unique)
    if (set(native)!={'address','pub_key','priv_key'} or not isinstance(native['address'],str)
            or native['address'].lower()!=expected[2:]
            or set(native['pub_key'])!={'type','value'} or set(native['priv_key'])!={'type','value'}
            or native['pub_key']['type']!='cometbft/PubKeySecp256k1eth'
            or native['priv_key']['type']!='cometbft/PrivKeySecp256k1eth'):
        raise ValueError('native validator key does not match the dedicated signer')
    private=base64.b64decode(native['priv_key']['value'],validate=True)
    public=base64.b64decode(native['pub_key']['value'],validate=True)
    if private!=raw or len(public)!=65 or public[0]!=4 or public!=derive(raw):
        raise ValueError('native validator private/public key conversion differs')
    if (type(account.get('version')) is not int or account['version']!=3
            or account.get('address','').lower()!=expected[2:]):
        raise ValueError('native Bor account differs from the dedicated signer')
    crypto=account.get('crypto')
    if not isinstance(crypto,dict) or crypto.get('cipher')!='aes-128-ctr' or crypto.get('kdf')!='scrypt':
        raise ValueError('native Bor keystore is not the reviewed V3 format')
    params=crypto.get('kdfparams',{})
    # StandardScryptN/P from the authenticated Bor account-import implementation.
    if any(type(params.get(name)) is not int or params[name]!=number for name,number in
            (('n',262144),('r',8),('p',1),('dklen',32))):
        raise ValueError('native Bor keystore does not use standard scrypt parameters')
    for field,size in [('ciphertext',64),('mac',64)]:
        if not re.fullmatch('[a-f0-9]{'+str(size)+'}',crypto.get(field,'')):
            raise ValueError('native Bor keystore cryptographic field is malformed')
    if (not re.fullmatch('[a-f0-9]{32}',crypto.get('cipherparams',{}).get('iv',''))
            or not re.fullmatch('[a-f0-9]{64}',params.get('salt',''))):
        raise ValueError('native Bor keystore salt or IV is malformed')
    return {'signer':expected,'public_key':'0x'+public.hex()}


def convert(state,profile,bor,heimdalld,raw,signer,app,
            descriptor=private_descriptor,temporary=tempfile.TemporaryDirectory,derive=public_key):
    """Return plaintext native credentials only to the caller's encryption phase.

    `app` is the complete reviewed, loopback-only Heimdall configuration. The
    root command's persistent pre-run reads it even for import-validator-key.
    The network namespace prevents that setup from reaching any chain endpoint.
    """
    if not isinstance(raw,bytes) or len(raw)!=32:raise ValueError('invalid dedicated signer input')
    address(signer)
    mounted=state.command('/usr/bin/findmnt','--noheadings','--output','FSTYPE','--target','/run')
    if mounted.stdout.strip()!=b'tmpfs':raise ValueError('private native conversion requires /run tmpfs')
    state.protected('/run')
    with temporary(prefix='polygon-signer-',dir='/run') as folder:
        base=Path(folder)
        if base.is_symlink() or base.stat().st_mode&0o077:raise ValueError('native conversion directory is not private')
        home=base/'heimdall';(home/'config').mkdir(parents=True,mode=0o700)
        (home/'config/client.toml').write_text(client(profile))
        environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':folder,'LANG':'C.UTF-8','TMPDIR':folder}
        def native(arguments,**options):
            result=state.run(['/usr/bin/unshare','--net','--',*arguments],cwd=folder,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=180,
                env=environment,umask=0o077,**options)
            if result.returncode:raise ValueError('dedicated signer native conversion failed')
        native([str(heimdalld),'init','erpc-polygon-signer','--home',str(home),
            '--chain',profile['network'],'--chain-id',profile['heimdall_chain_id']])
        # The private initialized home is never published or used as consensus
        # history; the caller preserves its separately established original home.
        (home/'config/app.toml').write_text(app)
        password=secrets.token_hex(48).encode()
        with descriptor(raw.hex().encode()) as fd:
            source='/proc/self/fd/'+str(fd)
            native([str(bor),'account','import','--datadir',str(base/'bor'),'--keystore',str(base/'keystore'),source],
                input=password+b'\n',pass_fds=(fd,))
            os.lseek(fd,0,os.SEEK_SET)
            native([str(heimdalld),'import-validator-key',source,'--home',str(home),'--chain',profile['network']],
                input=b'',pass_fds=(fd,))
        keys=list((base/'keystore').iterdir())
        if len(keys)!=1:raise ValueError('native import did not produce exactly one Bor account')
        bor_key=bounded(keys[0]);heimdall_key=bounded(base/'priv_validator_key.json')
        public=checked_material(raw,signer,heimdall_key,bor_key,derive)
        return public,{'bor-signer.json':bor_key,'bor-password':password,
                       'heimdall-validator-key.json':heimdall_key}


STAGED_DIR='/etc/credstore.encrypted/polygon/validator-staged'
STAGED=STAGED_DIR+'/key'
STAGE_RECEIPT=STAGED_DIR+'/receipt.json'


def stage(state,expected,intent,profile,helpers,value,derive=public_key,identify=public_address):
    """Bind one original controller-generated key while startup remains fenced."""
    import artifacts
    import host
    import identity
    if expected.get('role')!='validator':raise ValueError('RPC ownership cannot accept a financial signer')
    state.phase(expected,intent,profile,helpers)
    state.namespaces();state.accounts.verify(expected);state.stopped()
    if not state.path('/etc/polygon/preparing').exists():raise ValueError('signer staging requires a stopped preparation')
    raw=secret_scalar(value)
    point=derive(raw);public='0x'+point.hex()
    if not re.fullmatch('0x04[a-f0-9]{128}',public):raise ValueError('invalid native hot-signer public key')
    if identify(point)!=expected['signer']:raise ValueError('protected signer input differs from its immutable public address')
    if state.path('/etc/credstore.encrypted/polygon/original').exists():
        original=identity.receipt(state,expected)
        if original.get('validator')!={'signer':expected['signer'],'public_key':public}:
            raise ValueError('the retained original hot key cannot be replaced')
        return {'original_reused':True}
    directory=state.protected(STAGED_DIR,missing=True)
    if directory.exists():
        previous=state.read(STAGE_RECEIPT)
        if (previous.get('contract')!=expected or previous.get('public_key')!=public
                or previous.get('cipher_sha256')!=artifacts.digest(state.protected(STAGED))):
            raise ValueError('the original pending signer cannot be replaced')
        # Rebind the same original ciphertext only after the new preparation
        # intent has already been durably established and ownership checked.
        previous['intent']=intent;state.write(STAGE_RECEIPT,previous)
        return {'signer_staged':True,'original_pending_reused':True}
    pending=state.protected(STAGED_DIR+'.pending',missing=True)
    if pending.exists():shutil.rmtree(pending)  # Unpublished, never consumed by native clients.
    pending.mkdir(mode=0o700)
    try:
        state.command('systemd-creds','encrypt','--name=validator-input','-',str(pending/'key'),input=raw.hex().encode(),timeout=60)
        (pending/'key').chmod(0o600)
        record={'contract':expected,'public_key':public,'cipher_sha256':artifacts.digest(pending/'key'),'intent':intent}
        (pending/'receipt.json').write_bytes(canonical(record));(pending/'receipt.json').chmod(0o600)
        # The encrypted original and public ownership receipt become visible
        # together. A crash cannot leave an adoptable unbound ciphertext.
        host.publish(pending,directory,tree=True,stop=state.root)
    finally:
        if pending.exists():shutil.rmtree(pending)
    return {'signer_staged':True}


def material(state,expected,intent,profile,bor,heimdalld,app,converter=convert):
    """Read only the original staged key, then authenticate native conversion."""
    import artifacts
    if expected.get('role')!='validator':raise ValueError('RPC ownership has no hot signer')
    state.phase(expected,intent,profile);state.stopped()
    if not state.path('/etc/polygon/preparing').exists():raise ValueError('native signer conversion requires a preparation fence')
    record=state.read(STAGE_RECEIPT)
    cipher=state.protected(STAGED)
    if (record.get('contract')!=expected or record.get('intent')!=intent
            or artifacts.digest(cipher)!=record.get('cipher_sha256')):
        raise ValueError('original pending signer is unavailable or belongs to another intent')
    result=state.run(['systemd-creds','decrypt','--name=validator-input',str(cipher),'-'],
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=False,timeout=60,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'})
    if result.returncode or len(result.stdout)!=64:raise ValueError('original pending signer cannot be decrypted')
    try:raw=secret_scalar(result.stdout.decode('ascii'))
    except (ValueError,UnicodeError):raise ValueError('original pending signer has invalid private encoding') from None
    public,credentials=converter(state,profile,bor,heimdalld,raw,expected['signer'],app)
    if public.get('public_key')!=record.get('public_key'):
        raise ValueError('native signer differs from the original staged public key')
    return public,credentials


def clear_staged(state,expected):
    import host
    import identity
    # Cleanup may follow only durable original publication. A failed cleanup is
    # harmless on retry and cannot authorize regenerating or reassigning a key.
    identity.receipt(state,expected)
    directory=state.protected(STAGED_DIR,missing=True)
    if not directory.exists():return
    if set(path.name for path in directory.iterdir())-{'key','receipt.json'}:
        raise ValueError('unknown pending custody content cannot be removed')
    for path in (STAGED,STAGE_RECEIPT):host.unlink(state.protected(path,missing=True),state.root)
    directory.rmdir();host.sync_parents(directory.parent,state.root)
