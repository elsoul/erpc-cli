# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original unregistered RPC-node identities, generated once into private tmpfs."""
import hashlib
import host
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from artifacts import digest
from configure import client
from state import canonical,unique

FILES=('bor-nodekey','heimdall-node-key.json','heimdall-validator-key.json')


def files(expected):
    return (*FILES,'bor-signer.json','bor-password','heimdall-observer-key.json') if expected.get('role')=='validator' else FILES


def bor_identity():
    # OpenSSL-backed distribution cryptography, not a home-grown scalar RNG.
    # This is P2P identity only; Bor mining/account unlock remain disabled.
    from cryptography.hazmat.primitives.asymmetric import ec
    key=ec.generate_private_key(ec.SECP256K1())
    private=key.private_numbers().private_value
    public=key.public_key().public_numbers()
    return format(private,'064x').encode(),format(public.x,'064x')+format(public.y,'064x')


def receipt(state,expected,require_public=True):
    original=state.protected('/etc/credstore.encrypted/polygon/original',missing=True)
    if original.is_symlink() or not original.is_dir():raise ValueError('original identity directory is missing or redirected')
    value=state.read('/etc/credstore.encrypted/polygon/original/receipt.json')
    if value.get('contract')!=expected or set(value.get('ciphertexts',{}))!=set(files(expected)):
        raise ValueError('original node identity belongs to another inventory/network')
    for name in files(expected):
        path=state.protected('/etc/credstore.encrypted/polygon/original/'+name)
        if path.is_symlink() or not path.is_file() or digest(path)!=value['ciphertexts'][name]:
            raise ValueError('original node identity is missing or changed; no implicit regeneration')
    if expected.get('role')=='validator':
        from signer import address
        signer=value.get('validator',{})
        if signer.get('signer')!=address(expected.get('signer')) or not isinstance(signer.get('public_key'),str):
            raise ValueError('original hot signer differs from immutable validator ownership')
        import re
        if not re.fullmatch('0x04[a-f0-9]{128}',signer['public_key']):raise ValueError('invalid original validator public key')
    if digest(state.protected('/etc/credstore.encrypted/polygon/original/initial-state.json'))!=value.get('initial_state_sha256'):
        raise ValueError('original initialization state differs')
    phase=state.read('/etc/credstore.encrypted/polygon/original/home-state.json')
    if phase.get('contract')!=expected or phase.get('identity_sha256')!=hashlib.sha256(canonical(value)).hexdigest() or phase.get('state') not in ('uninitialized','initialized'):
        raise ValueError('original identity initialization receipt is missing or changed')
    if require_public and state.read('/etc/polygon/identity.json')!=value:
        raise ValueError('original public identity receipt differs')
    return value


def initialize(state,expected,heimdalld,profile,generate_bor=bor_identity,temporary=tempfile.TemporaryDirectory,validator=None):
    state.ownership(expected)
    state.stopped()
    if not state.path('/etc/polygon/preparing').exists():
        raise ValueError('node identity initialization requires a fenced preparation')
    original=state.protected('/etc/credstore.encrypted/polygon/original',missing=True)
    if original.exists():
        value=receipt(state,expected,require_public=False)
        public=state.path('/etc/polygon/identity.json')
        if public.exists() and state.read('/etc/polygon/identity.json')!=value:
            raise ValueError('original identity cannot change during reinstallation')
        state.write('/etc/polygon/identity.json',value)
        return value
    if original.is_symlink() or any(state.path(p).exists() for p in
            ('/etc/polygon/activation.json','/var/lib/polygon/heimdall','/var/lib/polygon/bor/data')):
        raise ValueError('retained activation/history has no original identity; explicit recovery required')
    if expected.get('role')=='validator':
        import signer
        if (not isinstance(validator,tuple) or len(validator)!=2 or validator[0].get('signer')!=expected['signer']
                or set(validator[1])!=set(signer.FILES)):
            raise ValueError('fresh validator identity requires verified native hot-signer material')
    elif validator is not None:raise ValueError('RPC identities cannot import financial keys')
    parent=original.parent
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    pending=parent/'original.pending'
    if pending.is_symlink():raise ValueError('identity staging must be a private real directory')
    if pending.exists():shutil.rmtree(pending)  # Never published and never started.
    pending.mkdir(mode=0o700)
    try:
        with temporary(prefix='polygon-native-init-',dir='/run') as folder:
            home=Path(folder)/'heimdall'
            (home/'config').mkdir(parents=True,mode=0o700)
            (home/'config/client.toml').write_text(client(profile))
            result=state.run([str(heimdalld),'init','erpc-polygon-'+expected['network'],
                '--home',str(home),'--chain',expected['network'],'--chain-id',profile['heimdall_chain_id']],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=120,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':folder,'LANG':'C.UTF-8'})
            if result.returncode:raise ValueError('native RPC identity initialization failed')
            material={}
            for source,destination in [('node_key.json','heimdall-node-key.json'),('priv_validator_key.json','heimdall-validator-key.json')]:
                with (home/'config'/source).open('rb') as stream:value=stream.read(16385)
                if len(value)>16384:raise ValueError('native identity exceeded its size bound')
                parsed=json.loads(value,object_pairs_hook=unique)
                if not isinstance(parsed,dict) or not isinstance(parsed.get('priv_key'),dict):
                    raise ValueError('native initialization did not produce a private identity')
                material[destination]=value
            initial=(home/'data/priv_validator_state.json').read_bytes()
            initial_value=json.loads(initial,object_pairs_hook=unique)
            if (str(initial_value.get('height'))!='0' or type(initial_value.get('round')) is not int
                    or type(initial_value.get('step')) is not int or initial_value['round']!=0 or initial_value['step']!=0
                    or initial_value.get('signature') or initial_value.get('signbytes')):
                raise ValueError('native fresh RPC initialization unexpectedly contains signing history')
            (pending/'initial-state.json').write_bytes(initial)
            material['bor-nodekey'],bor_public=generate_bor()
            public={'contract':expected,'bor_node_id':bor_public,'ciphertexts':{},'initial_state_sha256':hashlib.sha256(initial).hexdigest()}
            if validator is not None:
                public['validator']=validator[0]
                material['heimdall-observer-key.json']=material['heimdall-validator-key.json']
                material.update(validator[1])
            for name in files(expected):
                state.command('systemd-creds','encrypt','--name='+name,'-',str(pending/name),input=material[name])
                public['ciphertexts'][name]=digest(pending/name)
            (pending/'receipt.json').write_bytes(canonical(public))
            (pending/'home-state.json').write_bytes(canonical({'contract':expected,'identity_sha256':hashlib.sha256(canonical(public)).hexdigest(),'state':'uninitialized'}))
            # Receipt and all ciphertexts publish in one rename. A crash before
            # rename cannot authorize startup; after rename retry reuses them.
            host.publish(pending,original,tree=True,stop=state.root)
            state.write('/etc/polygon/identity.json',public)
        return receipt(state,expected)
    finally:
        if pending.exists():shutil.rmtree(pending)


def home(state,expected,profile):
    original=receipt(state,expected)
    recorded=state.read('/etc/credstore.encrypted/polygon/original/home-state.json')
    initialized={'contract':expected,'identity_sha256':hashlib.sha256(canonical(original)).hexdigest(),'state':'initialized'}
    destination=state.protected('/var/lib/polygon/heimdall',missing=True)
    if destination.is_symlink():raise ValueError('Heimdall home cannot be redirected')
    if destination.exists():
        if not (destination/'erpc-home.json').is_file():
            raise ValueError('existing Heimdall history lacks its initialization receipt')
        saved=json.loads((destination/'erpc-home.json').read_text(),object_pairs_hook=unique)
        history=destination/'data/priv_validator_state.json'
        if saved!=expected or history.is_symlink() or not history.is_file() or history.stat().st_nlink!=1:
            raise ValueError('Heimdall signing history or ownership is missing; never reset it')
        if expected.get('role')=='validator':
            observer=destination/'data/priv_validator_observer_state.json'
            if observer.is_symlink() or not observer.is_file() or observer.stat().st_nlink!=1:
                raise ValueError('original observer history is missing; explicit recovery required')
        state.write('/etc/polygon/history.json',initialized)
        state.write('/etc/credstore.encrypted/polygon/original/home-state.json',initialized)
        return
    if recorded['state']!='uninitialized' or state.path('/etc/polygon/history.json').exists() or state.path('/etc/polygon/activation.json').exists():
        raise ValueError('activated Heimdall home is missing; no implicit history reset')
    stage=destination.with_name('heimdall.pending')
    if stage.is_symlink():raise ValueError('home staging cannot be a symlink')
    if stage.exists():shutil.rmtree(stage)  # Never published to the node.
    (stage/'config').mkdir(parents=True,mode=0o750)
    (stage/'data').mkdir(mode=0o700)
    # This initialization is usable once for the retained original identity.
    # A validator must first supply verified native hot-signer material; neither
    # role may reset a previously published signing state.
    initial=state.path('/etc/credstore.encrypted/polygon/original/initial-state.json').read_bytes()
    (stage/'data/priv_validator_state.json').write_bytes(initial)
    if expected.get('role')=='validator':
        # Separate histories: initial sync never loads the dedicated hot key and
        # activation never repurposes or resets the observer's signing state.
        (stage/'data/priv_validator_observer_state.json').write_bytes(initial)
    for name,target in [('priv_validator_key.json','heimdall-validator-key.json'),('node_key.json','heimdall-node-key.json')]:
        (stage/'config'/name).symlink_to('/run/credentials/polygon-heimdall.service/'+target)
    (stage/'erpc-home.json').write_bytes(canonical(expected))
    host.publish(stage,destination,tree=True,stop=state.root)
    state.write('/etc/polygon/history.json',initialized)
    state.write('/etc/credstore.encrypted/polygon/original/home-state.json',initialized)


def history(state,expected):
    original=receipt(state,expected)
    initialized={'contract':expected,'identity_sha256':hashlib.sha256(canonical(original)).hexdigest(),'state':'initialized'}
    if (state.read('/etc/polygon/history.json')!=initialized
            or state.read('/etc/credstore.encrypted/polygon/original/home-state.json')!=initialized
            or state.read('/var/lib/polygon/heimdall/erpc-home.json')!=expected):
        raise ValueError('consensus history has not been initialized for this exact original identity')
    file=state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json')
    if file.is_symlink() or not file.is_file() or file.stat().st_nlink!=1:
        raise ValueError('original mutable consensus history is missing; automatic reset is refused')
    if expected.get('role')=='validator':
        observer=state.path('/var/lib/polygon/heimdall/data/priv_validator_observer_state.json')
        if observer.is_symlink() or not observer.is_file() or observer.stat().st_nlink!=1:
            raise ValueError('original observer history is missing; implicit reset refused')
    return initialized
