# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original encrypted signer material. Slashing history is never restored from this blob.

The controller must establish quiescence before changing native import/runtime
files. This module only publishes a root-private encrypted original, bound to
its immutable host/account receipt, and never starts Lighthouse.
"""
import os
import re
from pathlib import Path
from eth_files import atomic,digest,encoded,read,require,root_directory,run,synchronize,unique
import eth_accounts as accounts

NAME='erpc-ethereum-validator-original'
LIMIT=128*1024
CIPHER_LIMIT=512*1024
ROOTS={
    'mainnet':'0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95',
    'hoodi':'0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f',
}


def key_material(value):
    require(isinstance(value,dict) and set(value)=={'keystore','password'},'closed original signer material required')
    key=value['keystore'];password=value['password']
    require(isinstance(key,dict) and type(key.get('version'))is int and key['version']==4
            and isinstance(key.get('pubkey'),str) and re.fullmatch('[a-fA-F0-9]{96}',key['pubkey'])
            and isinstance(key.get('crypto'),dict),'invalid original EIP-2335 keystore')
    for part in ('kdf','checksum','cipher'):
        row=key['crypto'].get(part)
        require(isinstance(row,dict) and isinstance(row.get('function'),str) and isinstance(row.get('params'),dict)
                and isinstance(row.get('message'),str),'incomplete original EIP-2335 crypto module')
    require(isinstance(password,str) and 0<len(password.encode())<=4096 and not any(c in password for c in '\x00\r\n'),
            'invalid original validator password file')
    raw=encoded(value);require(len(raw)<=LIMIT,'original signer input exceeds its bound')
    return '0x'+key['pubkey'].lower(),raw


def history(value,network,pubkey,fresh=False):
    require(network in ROOTS and isinstance(value,dict) and set(value)=={'metadata','data'},'closed original history required')
    meta=value['metadata'];rows=value['data']
    require(isinstance(meta,dict) and meta.get('interchange_format_version')=='5'
            and meta.get('genesis_validators_root')==ROOTS[network]
            and isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict) and rows[0].get('pubkey')==pubkey,
            'original slashing history key or network differs')
    require(set(rows[0])=={'pubkey','signed_blocks','signed_attestations'},'unknown original signing history fields')
    for name,fields in [('signed_blocks',('slot',)),('signed_attestations',('source_epoch','target_epoch'))]:
        entries=rows[0][name]
        require(isinstance(entries,list) and len(entries)<=250000 and (not fresh or not entries),
                'fresh validator import cannot carry previous signing history')
        for entry in entries:
            require(isinstance(entry,dict) and set(fields)<=set(entry) and set(entry)<=set(fields)|{'signing_root'},
                    'invalid original signing record')
            for field in fields:
                number=entry[field]
                require(isinstance(number,str) and re.fullmatch('0|[1-9][0-9]{0,19}',number)
                        and int(number)<=2**64-1,'invalid original signing record number')
            if len(fields)==2:require(int(entry[fields[0]])<=int(entry[fields[1]]),'invalid source/target history epochs')
            root=entry.get('signing_root')
            require(root is None or (isinstance(root,str) and re.fullmatch('0x[a-fA-F0-9]{64}',root)),
                    'invalid original signing root')
    raw=encoded(value);require(len(raw)<=16*1024*1024,'original slashing history exceeds its bound')
    return raw


def machine():
    raw=read(Path('/etc/machine-id'),128).strip()
    require(re.fullmatch(b'[a-f0-9]{32}',raw),'original host machine identity is unavailable')
    return digest(raw)


def authority(state,expected):
    owner=state.check(expected)
    require(owner['machine']==machine(),'original signer authority belongs to another machine')
    require(expected['role']=='validator','signer custody requires the original validator role')
    plan=accounts.validate(state.get('accounts.json'),'validator')
    require(state.get('accounts-intent.json')==plan,'original signer account receipts differ')
    accounts.verify(plan)
    # Resync all original authority before any decrypt/export/native handoff,
    # including visible rename results after interrupted directory fsync.
    for name in ('owner.json','accounts-intent.json','accounts.json'):synchronize(state.path(name))
    return {'contract':expected,'machine':owner['machine'],'accounts':plan}


def crypt(action,value):
    require(action in ('encrypt','decrypt'),'invalid original credential operation')
    argv=['/usr/bin/systemd-creds',action,'--name='+NAME]
    if action=='encrypt':argv.append('--with-key=host')
    result=run(argv+['-','-'],input_data=value)
    require(0<len(result)<=(CIPHER_LIMIT if action=='encrypt' else LIMIT),'original credential result exceeds its bound')
    return result


def receipt(state,binding):
    value=state.get('signer-custody.json')
    require(isinstance(value,dict) and set(value)=={'authority','pubkey','material_sha256','cipher_sha256'}
            and value['authority']==binding and isinstance(value['pubkey'],str) and re.fullmatch('0x[a-f0-9]{96}',value['pubkey'])
            and all(isinstance(value[k],str) and re.fullmatch('[a-f0-9]{64}',value[k]) for k in ('material_sha256','cipher_sha256')),
            'original encrypted signer receipt differs')
    require(state.get('signer-custody-intent.json')=={k:value[k] for k in ('authority','pubkey','material_sha256')},
            'original encrypted signer intent differs')
    synchronize(state.path('signer-custody-intent.json'));synchronize(state.path('signer-custody.json'))
    return value


def cipher_bytes(state,record):
    path=state.path('signer-original.cred')
    if not state.exists(path.name):
        pending=state.path('signer-original.pending')
        raw=read(pending,CIPHER_LIMIT,mode=0o600)
        require(digest(raw)==record['cipher_sha256'],'original pending signer ciphertext differs')
        synchronize(pending);os.replace(pending,path)
    raw=read(path,CIPHER_LIMIT,mode=0o600)
    require(digest(raw)==record['cipher_sha256'],'original signer ciphertext differs')
    synchronize(path)
    return raw


def reveal(state,expected):
    binding=authority(state,expected);record=receipt(state,binding)
    value=unique(crypt('decrypt',cipher_bytes(state,record)));pubkey,raw=key_material(value)
    require(pubkey==record['pubkey'] and digest(raw)==record['material_sha256'],
            'original decrypted signer material differs')
    return value


def seal(state,expected,value):
    binding=authority(state,expected);pubkey,raw=key_material(value)
    wanted={'authority':binding,'pubkey':pubkey,'material_sha256':digest(raw)}
    if state.exists('signer-custody.json'):
        record=receipt(state,binding)
        require(all(record[k]==v for k,v in wanted.items()),'a different signer cannot replace original custody')
        # Verify the encrypted original on retries; never regenerate it from a
        # newly supplied password after receipt publication.
        require(encoded(reveal(state,expected))==raw,'original custody retry differs')
        return record
    pending=state.path('signer-original.pending')
    require(not state.exists('signer-original.cred'),'unowned original signer ciphertext cannot be adopted')
    if state.exists('signer-custody-intent.json'):
        require(state.get('signer-custody-intent.json')==wanted,'interrupted signer custody belongs to another input')
    else:
        require(not state.exists(pending.name),'unowned signer staging cannot be adopted')
        state.put('signer-custody-intent.json',wanted)
    synchronize(state.path('signer-custody-intent.json'))
    if not state.exists(pending.name):atomic(pending,crypt('encrypt',raw))
    cipher=read(pending,CIPHER_LIMIT,mode=0o600)
    require(encoded(unique(crypt('decrypt',cipher)))==raw,'interrupted signer ciphertext does not match original input')
    synchronize(pending)
    record=dict(wanted,cipher_sha256=digest(cipher));state.put('signer-custody.json',record)
    receipt(state,binding);cipher_bytes(state,record)
    return record


def restore(state,expected,cipher,quiescent):
    binding=authority(state,expected);record=receipt(state,binding)
    require(isinstance(cipher,bytes) and 0<len(cipher)<=CIPHER_LIMIT and digest(cipher)==record['cipher_sha256'],
            'restore requires the exact original encrypted signer blob')
    value=unique(crypt('decrypt',cipher));pubkey,raw=key_material(value)
    require(pubkey==record['pubkey'] and digest(raw)==record['material_sha256'],'restored original signer material differs')
    paths=[state.path('signer-original.cred'),state.path('signer-original.pending')]
    needs_change=not state.exists(paths[0].name)
    existing={}
    for path in paths:
        if state.exists(path.name):
            existing[path]=read(path,CIPHER_LIMIT,mode=0o600)
            needs_change=needs_change or existing[path]!=cipher
    if needs_change:
        quiescent()
        for path,old in existing.items():
            if old==cipher:continue
            # Explicit same-original restoration preserves corrupt bytes in the
            # root-private authority namespace before replacing a credential.
            # It never follows or repairs foreign/linked/nonprivate entries.
            quarantine=state.path('signer-quarantine-'+digest(old)+'.cred')
            if state.exists(quarantine.name):require(read(quarantine,CIPHER_LIMIT,mode=0o600)==old,'original restore quarantine differs')
            else:atomic(quarantine,old)
            synchronize(quarantine)
            directory=root_directory(state.directory)
            try:os.unlink(path.name,dir_fd=directory);os.fsync(directory)
            finally:os.close(directory)
        if not state.exists(paths[0].name):
            if not state.exists(paths[1].name):atomic(paths[1],cipher)
            cipher_bytes(state,record)
    cipher_bytes(state,record)
    # No account, cancellation, native DB, original history, or service state is
    # changed. Restoration cannot grant activation or resurrect deleted history.
    return {'restored':True,'pubkey':pubkey,'signing_started':False}
