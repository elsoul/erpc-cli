# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Once-only original Engine JWT, encrypted and never included in public state."""
import os
import re
from eth_files import atomic,digest,read,require,run,synchronize
import eth_validator_custody as custody
import eth_validator_native as native

NAME='erpc-ethereum-validator-engine'


def crypt(action,raw):
    args=['/usr/bin/systemd-creds',action,'--name='+NAME]
    if action=='encrypt':args.append('--with-key=host')
    result=run(args+['-','-'],input_data=raw)
    require(0<len(result)<=16384,'original Engine credential exceeds its bound');return result


def value(state,expected,create=False,legacy=None):
    authority=custody.authority(state,expected);path=state.path('engine-original.cred');pending=state.path('engine-original.pending')
    if state.exists('engine-original.json'):
        record=state.get('engine-original.json')
        require(set(record)=={'authority','cipher_sha256','material_sha256'} and record['authority']==authority,
                'original Engine credential receipt differs')
        synchronize(state.path('engine-original.json'))
        if not state.exists(path.name):
            raw=read(pending,16384,mode=0o600);require(digest(raw)==record['cipher_sha256'],'original pending Engine ciphertext differs')
            synchronize(pending);os.replace(pending,path)
        cipher=read(path,16384,mode=0o600);require(digest(cipher)==record['cipher_sha256'],'original Engine ciphertext differs')
        synchronize(path);raw=crypt('decrypt',cipher)
        require(re.fullmatch(b'[a-f0-9]{64}\n?',raw) and digest(raw)==record['material_sha256'],'original Engine credential material differs')
        return raw
    require(create and not state.exists(path.name),'original Engine credential is missing; do not create a replacement')
    desired={'authority':authority,'legacy_sha256':None if legacy is None else digest(legacy)}
    if state.exists('engine-original-intent.json'):
        require(state.get('engine-original-intent.json')==desired,'interrupted Engine initialization differs')
    else:
        require(not state.exists(pending.name),'unowned Engine staging cannot be adopted')
        state.put('engine-original-intent.json',desired)
    synchronize(state.path('engine-original-intent.json'))
    if not state.exists(pending.name):
        raw=native.worker(['/usr/bin/openssl','rand','-hex','32']) if legacy is None else legacy
        require(re.fullmatch(b'[a-f0-9]{64}\n?',raw),'invalid original Engine secret')
        atomic(pending,crypt('encrypt',raw))
    cipher=read(pending,16384,mode=0o600);synchronize(pending);raw=crypt('decrypt',cipher)
    require(re.fullmatch(b'[a-f0-9]{64}\n?',raw) and (legacy is None or raw==legacy),'interrupted original Engine material differs')
    record={'authority':authority,'cipher_sha256':digest(cipher),'material_sha256':digest(raw)}
    state.put('engine-original.json',record);synchronize(state.path('engine-original.json'))
    os.replace(pending,path);synchronize(path);return raw
