# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only admission authorizes a stopped transition, never a stake transaction."""
import hashlib
import json
import admission
import identity
import install
import native_authority
import observe
import parent
from state import canonical,executable,monotonic,profile_digest,target,unique

PERMIT='/etc/polygon/validator-admission.json'


def require(value,message):
    if not value:raise ValueError(message)


def parent_query(shared,credential,network):
    transport=parent.Parent(shared,credential,'mainnet' if network=='mainnet' else 'sepolia',require_public_tls=True)
    transport.verify()
    def query(port,path='/',payload=None):
        require(port==9545 and path=='/' and isinstance(payload,dict)
                and payload.get('method') in ('eth_chainId','eth_getBlockByNumber','eth_call','eth_getBalance'),
                'admission transport cannot issue native or financial mutations')
        return transport.execution_request(canonical(payload))
    return query


def owned_observer(controller,expected,installed,original):
    state=controller.state;native_authority.fenced(state)
    before={name:state.proof.listener(name,installed) for name in ('parent','heimdall','bor')}
    query=observe.ValidatorQuery(state,installed,admission=True)
    ready=observe.status(installed['profile'],query,controller.sleep,None)
    require(ready['ready'],'first activation requires a healthy original observing node')
    import broker_runtime
    broker=broker_runtime.Container(state,expected);broker.health(broker.token(broker.record()))
    result=admission.snapshot(installed['profile'],expected['signer'],query)
    admission.admitted(result,expected,original['validator']['public_key'])
    require(all(state.proof.listener(name,installed)==value for name,value in before.items()),
            'original observer changed during admission qualification')
    native_authority.fenced(state)
    return result



def cancellation(state):
    markers={}
    for name in ('stopped','retired'):
        path=state.protected('/etc/polygon/'+name,missing=True)
        if path.exists():
            info=path.stat();markers[name]=[info.st_ino,info.st_mtime_ns,info.st_ctime_ns]
    if not markers:return None
    return {'markers':markers,'intent':state.read('/etc/polygon/intent.json').get('intent')}


def authorize(controller,request):
    """Protected stdin may carry the next provider; no host secret rotates yet."""
    state=controller.state;expected=controller.expected(request['contract'])
    require(expected['role']=='validator','RPC nodes cannot authorize a financial role')
    profile=executable(expected,request['profile'])
    require(profile['validator']['phase']=='active','active authorization requires an explicit active target')
    import configure
    shared=parent.transport(controller.source/'upstreams.py')
    configure.validator_peers(profile['validator'],lambda address:shared.address_allowed(str(address),False))
    import re
    intent,helpers=request.get('intent'),request.get('helpers')
    require(isinstance(intent,str) and re.fullmatch('[a-f0-9]{32}',intent)
            and isinstance(helpers,str) and re.fullmatch('[a-f0-9]{64}',helpers),
            'activation authorization lacks its immutable target operation')
    state.ownership(expected);state.namespaces();state.accounts.verify(expected)
    identity.history(state,expected);original=identity.receipt(state,expected)
    original_hash=hashlib.sha256(canonical(original)).hexdigest()
    previous=state.read(PERMIT) if state.path(PERMIT).exists() else None
    retained=isinstance(previous,dict) and type(previous.get('format')) is int and previous.get('format')==1 and previous.get('contract')==expected
    retained=retained and previous.get('identity_sha256')==original_hash and previous.get('observer_verified') is True
    # Unit sealing is deliberately later than native/config publication. A
    # retained original permit can recover that exact stopped interruption,
    # without treating a changed existing unit receipt as an absent receipt.
    try:installed=install.installed(state,expected,'status')
    except (ValueError,FileNotFoundError):
        require(retained,'unsealed history cannot authorize a first signer')
        raw=state.read('/etc/polygon/installed.json')
        require(state.protected('/etc/polygon/preparing',missing=True).exists(),
                'only a fenced unfinished installation may recover')
        state.stopped()
        installed=install.installed(state,expected,'status',require_units='units' in raw,pending_configuration=True)
        pending=state.read('/etc/polygon/intent.json')
        monotonic(expected,installed['profile'],target(expected,pending['profile']))
        monotonic(expected,pending['profile'],profile)
        install.pending_units(state,expected,installed)
    require(installed['profile'].get('validator',{}).get('phase') in ('observing','active'),
            'first activation cannot adopt a fresh or unrelated history')
    if retained:
        # A cancelled/interrupted transition may be retried with a new intent,
        # but only the original observed key/history plus a fresh parent check.
        admitted=previous.get('observer_admission')
        admission.admitted(admitted,expected,original['validator']['public_key'])
    else:
        require(installed['profile']['validator']['phase']=='observing',
                'active history without its original admission proof requires explicit recovery')
        admitted=owned_observer(controller,expected,installed,original)
    credential=request.get('credential')
    shared=parent.transport(controller.source/'upstreams.py')
    query=parent_query(shared,credential,expected['network'])
    current=admission.snapshot(profile,expected['signer'],query,parent_only=True)
    admission.admitted(current,expected)
    identity.history(state,expected)
    require(hashlib.sha256(canonical(identity.receipt(state,expected))).hexdigest()==original_hash,
            'original signer changed during authorization')
    value={'format':1,'contract':expected,'profile':profile_digest(profile),'helpers':helpers,'intent':intent,
        'cancellation':cancellation(state),
        'identity_sha256':original_hash,'observer_verified':True,'observer_admission':admitted,
        'parent_admission':current,'configuration_sha256':hashlib.sha256(canonical(credential)).hexdigest()}
    state.write(PERMIT,value)  # Durable evidence BEFORE preparation can stop the observer.
    return {'active_target_authorized':True,'observer_verified':True,'registered':True,
        'activated':False,'ready':False,'transaction_submission':'none; registration and funding remain external'}


def require_permit(state,expected,intent,profile,helpers,credential=False,before_prepare=False):
    require(expected['role']=='validator' and profile['validator']['phase']=='active','not an active validator target')
    value=state.read(PERMIT)
    original=identity.receipt(state,expected);identity.history(state,expected)
    require(type(value.get('format')) is int and value['format']==1,'unsupported original activation authorization')
    if before_prepare:require(value.get('cancellation')==cancellation(state),'active preparation was cancelled after its authorization')
    require(value.get('contract')==expected and value.get('intent')==intent and value.get('profile')==profile_digest(profile)
            and value.get('helpers')==helpers and value.get('observer_verified') is True
            and value.get('identity_sha256')==hashlib.sha256(canonical(original)).hexdigest(),
            'active target differs from its original observed key/history or authorization')
    admission.admitted(value.get('observer_admission'),expected,original['validator']['public_key'])
    admission.admitted(value.get('parent_admission'),expected)
    if credential:
        require(state.read('/etc/polygon/upstream.json').get('configuration_sha256')==value.get('configuration_sha256'),
                'active preparation imported a provider different from its admission observation')
    return value


def current(state,expected,profile,source):
    """Fresh parent eligibility, using only the imported original TLS provider."""
    import local_tls
    cipher=state.protected('/etc/credstore.encrypted/polygon/execution.json').read_bytes()
    require(0<len(cipher)<=65536,'parent ciphertext exceeds its bound')
    receipt=state.read('/etc/polygon/upstream.json')
    require(receipt.get('contract')==expected and receipt.get('parent')==profile['parent']
            and receipt.get('cipher_sha256')==hashlib.sha256(cipher).hexdigest(),
            'parent eligibility provider differs from the original imported scope')
    credential=json.loads(local_tls.transform(state,'decrypt','execution.json',cipher),object_pairs_hook=unique)
    require(receipt.get('configuration_sha256')==hashlib.sha256(canonical(credential)).hexdigest(),
            'parent admission configuration differs from its original import')
    shared=parent.transport(source/'upstreams.py')
    query=parent_query(shared,credential,expected['network'])
    return admission.admitted(admission.snapshot(profile,expected['signer'],query,parent_only=True),expected)


def registration(controller,request):
    state=controller.state;expected=controller.expected(request['contract'])
    action=request.get('registration_action')
    require(expected['role']=='validator' and action in ('prepare','validate','status'),
            'unsupported read-only registration operation')
    state.ownership(expected);state.accounts.verify(expected)
    original=identity.receipt(state,expected);identity.history(state,expected)
    installed=controller.installation(expected,'status')
    result={'network':expected['network'],'phase':installed['profile']['validator']['phase'],
        'stake_owner':expected['stake_owner'],'dedicated_signer':expected['signer'],
        'signer_public_key':original['validator']['public_key'],'eligible':False,
        'transaction_submission':'external only','application_guarantees_admission':False}
    try:
        query=observe.ValidatorQuery(state,installed,admission=True)
        observed=admission.snapshot(installed['profile'],expected['signer'],query)
        result['observation']=observed
        try:
            admission.admitted(observed,expected,original['validator']['public_key']);result['eligible']=True
        except ValueError:pass
    except Exception:result['observation']='unavailable; finish original observer synchronization and verify the parent provider'
    if action=='prepare':
        observed=result['observation'] if isinstance(result['observation'],dict) else {}
        # The fixed native helper StakeFor passes the full65-byte public key.
        # It also signs with GetPrivKey; never run that owner operation on this
        # managed hot-key host. Supply these public data to an external owner tool.
        result.update(prepared=True,external_registration={
            'ethereum_chain_id':1 if expected['network']=='mainnet' else 11155111,
            'staking_manager':admission.CONTRACTS[expected['network']]['stake'],
            'method':'stakeFor(address,uint256,uint256,bool,bytes)',
            'user':expected['stake_owner'],'signerPubkey':original['validator']['public_key'],
            'staking_token':observed.get('staking_token'),
            'minimum_stake_base_units':observed.get('minimum_deposit_base_units'),
            'minimum_heimdall_fee_base_units':observed.get('minimum_heimdall_fee_base_units'),
            'required_owner_choices':['admission approval','stake amount','Heimdall fee','acceptDelegation'],
            'owner_actions':['verify live contract bounds and slot/admission','approve only the selected token amount externally',
                'sign and submit registration externally','fund only the dedicated checkpoint-fee signer separately'],
            'managed_host_owner_key':False})
    return result
