# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original dedicated agent, encrypted exact dotenv input and same-host recovery."""
import os
from pathlib import Path
import re
import secrets
import stat
from erpc_aqa_common import ROOT,CONFIG,UNIT,atomic,digest,execute,fsync_dir,json_bytes,owned_directory,read,require,unique_json
import erpc_aqa_accounts as accounts

CREDENTIALS=CONFIG/'credentials'
ACTIVE=CREDENTIALS/'agent.cred'
DECRYPTED=Path('/run/credentials')/UNIT/'.env'
PUBLIC_DER_PREFIX=bytes.fromhex('3056301006072a8648ce3d020106052b8104000a034200')


def material(raw,contract):
    require(contract.get('network') in ('mainnet','testnet'),'explicit original publisher network required')
    require(isinstance(raw,bytes) and 0<len(raw)<=4096,'bounded original agent key object required')
    value=unique_json(raw)
    require(isinstance(value,dict) and set(value)=={'key'} and isinstance(value['key'],str),
            'agent custody requires exactly one original key')
    text=value['key'];text=text[2:] if text.startswith('0x') else text
    require(re.fullmatch('[a-fA-F0-9]{64}',text),'invalid original agent scalar encoding')
    secret=bytes.fromhex(text)
    der=bytes.fromhex('302e0201010420')+secret+bytes.fromhex('a00706052b8104000a')
    point=execute(['/usr/bin/openssl','ec','-inform','DER','-pubout','-outform','DER'],input_data=der).stdout
    require(point==PUBLIC_DER_PREFIX+bytes.fromhex(contract['identity']['agent_public_key']),
            'concealed agent differs from its original public point')
    # There is no arbitrary dotenv syntax, multikey form or parent-file fallback.
    return b'PUBLISHER_PRIVATE_KEY=0x'+secret.hex().encode()+b'\nNETWORK='+contract['network'].encode()+b'\nRUST_LOG=off\n'


def private(path):
    owned_directory(CREDENTIALS)
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=65536,
            'original agent ciphertext is indirect, foreign, shared or oversized')
    return read(path,65536)


def synchronize(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:os.fsync(fd)
    finally:os.close(fd)
    for parent in (path.parent,*path.parent.parents):fsync_dir(parent)


def receipt(state,contract):
    state.check(contract)
    result=state.get('agent-identity.json')
    require(set(result)=={'contract','original_sha256','dotenv_sha256','cipher_sha256','pending'}
            and result['contract']==contract
            and all(isinstance(result[key],str) and re.fullmatch('[a-f0-9]{64}',result[key])
                    for key in ('original_sha256','dotenv_sha256','cipher_sha256'))
            and isinstance(result['pending'],str) and re.fullmatch(r'\.pending-[a-f0-9]{32}',result['pending']),
            'original agent receipt is missing or differs')
    return result


def identity(state,contract):
    expected=receipt(state,contract)
    require(digest(private(ACTIVE))==expected['cipher_sha256'],'original encrypted agent is missing or changed')
    return expected


def recover_publication(state,contract):
    expected=receipt(state,contract)
    # Retry never treats a visible owner/identity rename as durable authority.
    synchronize(ROOT/'owner.json');synchronize(ROOT/'agent-identity.json')
    present=ACTIVE.exists() or ACTIVE.is_symlink()
    if not present or digest(private(ACTIVE))!=expected['cipher_sha256']:
        candidate=CREDENTIALS/expected['pending']
        require(digest(private(candidate))==expected['cipher_sha256'],'original pending encrypted agent is unavailable')
        synchronize(candidate);os.replace(candidate,ACTIVE)
    synchronize(ACTIVE)
    return identity(state,contract)


def import_original(state,contract,raw,restore,unhosted,stop):
    state.check(contract);accounts.accounts(state.get('accounts.json'))
    require(type(restore)is bool and type(unhosted)is bool,'explicit original-key custody choices required')
    dotenv=material(raw,contract);original=digest(raw)
    established=(ROOT/'agent-identity.json').exists()
    if established:
        saved=receipt(state,contract)
        require(saved['original_sha256']==original and saved['dotenv_sha256']==digest(dotenv),
                'agent recovery must use exactly the original concealed bytes')
        if not restore:
            state.cancel(contract,False,stop);recover_publication(state,contract)
            return {'custody':'original','restored':False}
    else:
        require(unhosted and not restore,'initial custody needs a dedicated key not used by another publisher')
        require(not ACTIVE.exists() and not ACTIVE.is_symlink(),'unowned encrypted agent cannot be adopted')
    pending={'contract':contract,'original_sha256':original,'dotenv_sha256':digest(dotenv)}
    if (ROOT/'agent-import.json').exists():
        require(state.get('agent-import.json')==pending,'another original agent import is incomplete')
    elif CREDENTIALS.exists():
        require(not any(CREDENTIALS.iterdir()),'unowned agent staging cannot be adopted')
    state.cancel(contract,False,stop)
    state.put('agent-import.json',pending);synchronize(ROOT/'owner.json');synchronize(ROOT/'agent-import.json')
    owned_directory(CREDENTIALS,True)
    candidate=CREDENTIALS/('.pending-'+secrets.token_hex(16))
    execute(['/usr/bin/systemd-creds','encrypt','--with-key=host','--name=.env','-',candidate],input_data=dotenv)
    os.chmod(candidate,0o600);encrypted=private(candidate);synchronize(candidate)
    observed=execute(['/usr/bin/systemd-creds','decrypt','--name=.env',candidate,'-']).stdout
    require(observed==dotenv,'encrypted original dotenv failed private read-back verification')
    if ACTIVE.exists():
        old=private(ACTIVE);previous=CREDENTIALS/('previous-'+digest(old)+'.cred')
        if previous.exists():require(private(previous)==old,'retained original agent ciphertext changed')
        else:atomic(previous,old)
        synchronize(previous)
    expected=dict(pending,cipher_sha256=digest(encrypted),pending=candidate.name)
    state.put('agent-identity.json',expected)
    recover_publication(state,contract)
    return {'custody':'original','restored':restore}


def runtime_bytes(expected,uid):
    fd=os.open(DECRYPTED,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,uid) and info.st_nlink==1
                and stat.S_IMODE(info.st_mode) in (0o400,0o440) and info.st_size<=4096,
                'exact native dotenv credential is unavailable or indirect')
        raw=source.read(4097)
    require(digest(raw)==expected['dotenv_sha256'],'runtime dotenv differs from the original encrypted input')
    return raw
