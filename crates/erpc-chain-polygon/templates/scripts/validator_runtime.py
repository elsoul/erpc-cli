# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stopped validator dependency publication, distinct from activation or readiness."""
import hashlib
import json
from pathlib import Path
import broker_runtime
import configure
import gateway
import install
import local_tls
from state import canonical,profile_digest

APP='/etc/credstore.encrypted/polygon/native-app.toml'
RECORD='/etc/polygon/validator-dependencies.json'
PUBLIC='/etc/polygon/validator-runtime.json'
NATIVE_KEY='/etc/credstore.encrypted/polygon/heimdall-runtime-key.json'


def require(value,message):
    if not value:raise ValueError(message)


def app(expected,profile,bor_auth,broker_auth):
    import broker
    phase=profile['validator']['phase']
    require(expected.get('role')=='validator' and phase in ('observing','active'),
            'native dependency override requires an explicit validator phase')
    # Pinned helper.InitHeimdallConfig --app unmarshals a flat CustomConfig;
    # this is not app.toml's [custom] table. No secret URL is public metadata.
    return configure.toml({'eth_rpc_url':'https://127.0.0.10:9545',
        'bor_rpc_url':gateway.bor_url(bor_auth,expected),'comet_bft_rpc_url':'https://127.0.0.13:26657',
        'heimdall_rest_server':'https://127.0.0.12:1317',
        'amqp_url':broker.native_url(broker_auth,expected) if phase=='active' else '',
        'main_chain_gas_fee_cap':500000000000,'main_chain_gas_tip_cap':10000000000}).encode()



def key_binding(state,expected,profile,verify_plaintext=True):
    import hmac
    import identity
    original=identity.receipt(state,expected)
    source='heimdall-validator-key.json' if profile['validator']['phase']=='active' else 'heimdall-observer-key.json'
    ciphertext=state.protected(NATIVE_KEY).read_bytes()
    require(0<len(ciphertext)<=65536,'native runtime key projection exceeds its bound')
    if verify_plaintext:
        raw=local_tls.transform(state,'decrypt',source,state.protected('/etc/credstore.encrypted/polygon/original/'+source).read_bytes())
        projected=local_tls.transform(state,'decrypt','heimdall-validator-key.json',ciphertext)
        require(hmac.compare_digest(raw,projected),'native runtime projection differs from its original phase identity')
    return {'source':source,'source_cipher_sha256':original['ciphertexts'][source],
        'runtime_cipher_sha256':hashlib.sha256(ciphertext).hexdigest()}


def publish_key(state,expected,intent,profile,helpers):
    import identity
    state.phase(expected,intent,profile,helpers);state.stopped();state.accounts.verify(expected)
    identity.receipt(state,expected)
    source='heimdall-validator-key.json' if profile['validator']['phase']=='active' else 'heimdall-observer-key.json'
    raw=local_tls.transform(state,'decrypt',source,state.protected('/etc/credstore.encrypted/polygon/original/'+source).read_bytes())
    local_tls.write_bytes(state,NATIVE_KEY,local_tls.transform(state,'encrypt','heimdall-validator-key.json',raw))
    state.phase(expected,intent,profile,helpers);state.stopped()
    return key_binding(state,expected,profile)


def private(state,expected,intent,profile,helpers):
    state.phase(expected,intent,profile,helpers);state.stopped();state.accounts.verify(expected)
    tls=local_tls.ensure(state,expected,intent,profile,helpers)
    local_tls.publish_credentials(state,expected,intent,profile,helpers)
    auth=gateway.prepare_auth(state,expected,intent,profile,helpers)
    original=broker_runtime.prepare(state,expected,intent,profile,helpers)
    raw=app(expected,profile,auth,original)
    local_tls.write_bytes(state,APP,local_tls.transform(state,'encrypt','native-app.toml',raw))
    state.phase(expected,intent,profile,helpers);state.stopped()
    value={'contract':expected,'profile':profile_digest(profile),'helpers':helpers,
        'phase':profile['validator']['phase'],'local_tls_source':tls['source_intent'],
        'app_cipher_sha256':hashlib.sha256(state.protected(APP).read_bytes()).hexdigest(),
        'bor_auth':state.read('/etc/polygon/bor-auth.json'),
        'broker_auth':state.read(broker_runtime.RECORD)}
    return value


def verify(state,expected,installed):
    state.ownership(expected);state.accounts.verify(expected)
    saved=state.read(RECORD);profile=installed['profile'];helpers=installed['helpers']
    projections=local_tls.verify_projection(state,expected)
    value={'contract':expected,'profile':profile_digest(profile),'helpers':helpers,
        'phase':profile['validator']['phase'],'local_tls_source':projections['source_intent'],
        'app_cipher_sha256':hashlib.sha256(state.protected(APP).read_bytes()).hexdigest(),
        'bor_auth':state.read('/etc/polygon/bor-auth.json'),
        'broker_auth':state.read(broker_runtime.RECORD),'native_key':key_binding(state,expected,profile)}
    require(saved==value,'native private dependency publication is incomplete or belongs to another phase')
    for name,path in (('bor_auth',gateway.AUTH),('broker_auth',broker_runtime.CIPHER)):
        require(value[name]=={'contract':expected,'cipher_sha256':hashlib.sha256(state.protected(path).read_bytes()).hexdigest()},
                'native original dependency credential changed')
    public={key:value[key] for key in ('contract','helpers','profile','phase')}
    require(state.read(PUBLIC)==public,'native dependency gateway publication differs')
    return value


def finalize(controller,request):
    expected,profile=controller.phase(request)
    require(expected['role']=='validator','RPC preparation cannot publish a signing runtime')
    state=controller.state;helpers=controller.helpers;intent=request['intent']
    state.stopped();state.accounts.verify(expected);controller.upstream(expected,profile)
    # The explicit transition path publishes this authorization before an
    # active target is permitted. It is never inferred from a supplied key.
    if profile['validator']['phase']=='active':
        import validator_activation
        validator_activation.require_permit(state,expected,intent,profile,helpers,credential=True)
        validator_activation.current(state,expected,profile,controller.source)
    value=private(state,expected,intent,profile,helpers)
    installed=install.prepare(state,expected,intent,profile,request['advertise'],controller.source)
    require(installed['helpers']==helpers,'validator finalization replaced the intended helper revision')
    if profile['validator']['phase']=='active':
        validator_activation.current(state,expected,profile,controller.source)
    value['native_key']=publish_key(state,expected,intent,profile,helpers)
    state.write(RECORD,value)
    state.write(PUBLIC,{key:value[key] for key in ('contract','helpers','profile','phase')},mode=0o644)
    token=broker_runtime.Container(state,expected).prepare(intent,profile,helpers)
    state.phase(expected,intent,profile,helpers);state.stopped()
    verify(state,expected,installed)
    return {'prepared':True,'profile':profile_digest(profile),'helpers':helpers,'broker_token':token,
        'runtime_accounts':state.accounts.verify(expected),'phase':profile['validator']['phase'],
        'activated':False,'ready':False}


def bor_files(state,expected,installed):
    """Called by the verified root prestart guard; only active gets the V3 file."""
    import identity
    state.ownership(expected);accounts=state.accounts.verify(expected)
    original=identity.receipt(state,expected)
    account=accounts['bor'];state.protected('/run')
    base=broker_runtime.directory(state,'/run/erpc-polygon-validator',account['gid'])
    require({path.name for path in base.iterdir()}<={'bor-keystore'},'unknown private validator runtime cannot be adopted')
    directory=broker_runtime.directory(state,'/run/erpc-polygon-validator/bor-keystore',account['gid'])
    phase=installed['profile']['validator']['phase']
    if phase=='observing':
        require(not any(directory.iterdir()),'observing runtime cannot inherit an active signer keystore')
        return {'signer_delivered':False}
    require(phase=='active' and set(path.name for path in directory.iterdir())<={'original.json','original.json.pending'},
            'active keystore namespace contains unknown material')
    source='/etc/credstore.encrypted/polygon/original/bor-signer.json'
    cipher=state.protected(source).read_bytes()
    require(hashlib.sha256(cipher).hexdigest()==original['ciphertexts']['bor-signer.json'],
            'original Bor signer ciphertext changed')
    raw=local_tls.transform(state,'decrypt','bor-signer.json',cipher)
    value=json.loads(raw)
    require(type(value.get('version')) is int and value['version']==3
            and value.get('address','').lower()==expected['signer'][2:],
            'runtime Bor keystore does not match the original dedicated signer')
    broker_runtime.private_file(state,directory/'original.json',raw,state.owner,account['gid'],0o440)
    state.accounts.verify(expected)
    return {'signer_delivered':True}


def custody_groups(state,expected):
    import re
    tls=state.read(local_tls.RECORD)
    require(tls.get('contract')==expected and isinstance(tls.get('source_intent'),str)
            and re.fullmatch('[a-f0-9]{32}',tls['source_intent']),'original TLS generation is unavailable')
    return {
        'tls':(local_tls.RECORD,local_tls.DIRECTORY+'/'+tls['source_intent']+'/bundle',local_tls.BUNDLE_NAME),
        'bor_auth':('/etc/polygon/bor-auth.json',gateway.AUTH,gateway.AUTH_NAME),
        'broker_auth':(broker_runtime.RECORD,broker_runtime.CIPHER,broker_runtime.NAME),
    }


def backup_custody(state,expected):
    import base64
    records={};ciphertexts={}
    for kind,(record,path,_name) in custody_groups(state,expected).items():
        value=state.read(record);raw=state.protected(path).read_bytes()
        require(value.get('contract')==expected and 0<len(raw)<=131072
                and value.get('cipher_sha256')==hashlib.sha256(raw).hexdigest(),
                'original validator dependency custody is incomplete')
        records[kind]=value;ciphertexts[kind]=base64.b64encode(raw).decode()
    return {'format':1,'contract':expected,'records':records,'ciphertexts':ciphertexts}


def restore_custody(state,expected,backup):
    """Restore only ciphertexts still named by the retained original receipts."""
    import base64
    import broker
    state.ownership(expected);state.stopped()
    groups=custody_groups(state,expected)
    require(isinstance(backup,dict) and set(backup)=={'format','contract','records','ciphertexts'}
            and type(backup['format']) is int and backup['format']==1 and backup['contract']==expected
            and set(backup['records'])==set(groups) and set(backup['ciphertexts'])==set(groups),
            'backup does not contain this original validator dependency custody')
    restored={}
    for kind,(record,path,name) in groups.items():
        retained=state.read(record)
        if retained!=backup['records'][kind]:
            require(kind=='tls','immutable dependency credentials changed since the backup')
            # A stale backup must never roll back a later legitimate TLS renewal.
            local_tls.load(state,expected,allow_expired=True)
            continue
        encoded=backup['ciphertexts'][kind]
        require(isinstance(encoded,str) and len(encoded)<=180000,'dependency backup exceeds its bound')
        cipher=base64.b64decode(encoded,validate=True)
        require(0<len(cipher)<=131072 and hashlib.sha256(cipher).hexdigest()==retained.get('cipher_sha256'),
                'dependency ciphertext does not match its retained original receipt')
        raw=local_tls.transform(state,'decrypt',name,cipher)
        from state import unique
        value=json.loads(raw,object_pairs_hook=unique)
        if kind=='tls':
            public=local_tls.validate(value,expected,allow_expired=True)
            require(all(retained.get(key)==item for key,item in public.items()),'backup TLS public authority changed')
        elif kind=='bor_auth':gateway.credential(value,expected)
        else:broker.credential(value,expected)
        restored[path]=cipher
    # All scopes/decryptions pass before any original ciphertext is restored.
    state.stopped()
    for path,raw in restored.items():
        directory=state.protected(str(Path(path).parent),missing=True)
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        local_tls.write_bytes(state,path,raw)
    return {'dependency_ciphertexts_restored':len(restored)}
