# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public validator observations only; no signer, transaction builder or submission."""
import base64
import re
import time
import observe

# Official genesis-contracts reference, checked 2026-10-27. These are proxies.
CONTRACTS={
    'mainnet':{'stake':'0x5e3ef299fddf15eaa0432e6e66473ace8c13d908','root':'0x86e4dc95c7fbdbf52e33d563bbdb00823894c287','nft':'0x47cbe25bbdb40a774cc37e1da92d10c2c7ec897f'},
    'amoy':{'stake':'0x4ae8f648b1ec892b6cc68c89cc088583964d08be','root':'0xbd07d7e1e93c8d4b2a261327f3c28a8ea7167209','nft':'0x72cf5618142eb369e75ec6529a907e9a6fe99bb7'},
}
# Method IDs from pinned Heimdall v0.12.2 contracts/stakemanager/stakemanager.go.
SELECTORS={'minimum':'0x41b3d185','fee':'0xfba58f34','capacity':'0x4fd101d7',
    'count':'0x7f952d95','signer_id':'0x3862da0b','validator':'0x35aa2e44',
    'owner':'0x6352211e','set':'0x0209fdd0','nft':'0x31c2273b','token':'0xfc0c546a','epoch':'0x900cf0cf'}


def address(value):
    if not isinstance(value,str) or not re.fullmatch('0x[0-9a-fA-F]{40}',value) or int(value,16)==0:
        raise ValueError('expected a nonzero public EVM address')
    return value.lower()


def word(value):
    if type(value) is not int or not 0<=value<2**256:raise ValueError('invalid ABI integer')
    return format(value,'064x')


def decode(value,count=1):
    if not isinstance(value,str) or not re.fullmatch('0x[0-9a-fA-F]{'+str(count*64)+'}',value):
        raise ValueError('contract response has an unexpected ABI length')
    return [int(value[index:index+64],16) for index in range(2,len(value),64)]


def abi_address(value):
    if value>>160:raise ValueError('noncanonical ABI address')
    return address('0x'+format(value,'040x'))


def field(value,name,alias):
    present=[key for key in (name,alias) if key in value]
    if len(present)!=1:raise ValueError('missing or ambiguous protobuf public field')
    return value[present[0]]


def decimal(value):
    if not isinstance(value,str) or not re.fullmatch('0|[1-9][0-9]{0,19}',value):
        raise ValueError('invalid public protobuf integer')
    result=int(value)
    if result>=2**64:raise ValueError('protobuf integer exceeds uint64')
    return result


def active_ids(value):
    if not isinstance(value,str) or len(value)>2+(1002*64) or not re.fullmatch('0x(?:[a-fA-F0-9]{64}){2,1002}',value):
        raise ValueError('invalid bounded validator ID array')
    words=decode(value,(len(value)-2)//64)
    if words[0]!=32 or words[1]!=len(words)-2:raise ValueError('noncanonical ABI array')
    values=words[2:]
    if any(identifier==0 for identifier in values) or len(set(values))!=len(values):
        raise ValueError('invalid or repeated parent validator ID')
    return set(values)


def members(response):
    values=field(response,'validator_set','validatorSet').get('validators')
    if not isinstance(values,list) or len(values)>1000:raise ValueError('unbounded validator set')
    by_signer={};ids=set()
    for value in values:
        signer=address(value.get('signer'))
        identifier=decimal(field(value,'val_id','valId'))
        power=decimal(field(value,'voting_power','votingPower'))
        public=base64.b64decode(field(value,'pub_key','pubKey'),validate=True)
        if (signer in by_signer or identifier in ids or identifier==0 or power==0
                or value.get('jailed',False) is not False or power>=2**63 or len(public)!=65 or public[0]!=4):
            raise ValueError('invalid or ambiguous active validator identity')
        ids.add(identifier);by_signer[signer]={'id':identifier,'voting_power':str(power),'public_key':'0x'+public.hex()}
    return by_signer


def rpc(method,params,query):
    if method not in ('eth_call','eth_getBlockByNumber','eth_getBalance'):
        raise ValueError('admission observer never sends transactions')
    value=query(9545,payload={'jsonrpc':'2.0','id':1,'method':method,'params':params})
    if value.get('jsonrpc')!='2.0' or type(value.get('id')) is not int or value['id']!=1 or 'error' in value or 'result' not in value:
        raise ValueError('parent observation binding failed')
    return value['result']


def snapshot(profile,signer,query,clock=time.time,parent_only=False):
    signer=address(signer);network=profile.get('network')
    if network not in CONTRACTS:raise ValueError('unsupported admission network')
    expected=CONTRACTS[network]
    if type(parent_only) is not bool:raise ValueError('invalid admission observation scope')
    local=None
    if not parent_only:
        local=observe.heimdall(profile,query)
        if not local['ready']:raise ValueError('admission requires a fresh synchronized sentry')
        params=query(1317,'/chainmanager/params')['params']['chain_params']
        if (address(params.get('staking_manager_address'))!=expected['stake']
                or address(params.get('root_chain_address'))!=expected['root']):
            raise ValueError('current Heimdall contract addresses differ from the reviewed network')
    observe.parent(profile,query)
    block=rpc('eth_getBlockByNumber',['finalized',False],query)
    height=observe.number(block.get('number'));stamp=observe.number(block.get('timestamp'));block_hash=block.get('hash')
    if height==0 or not -30<=clock()-stamp<=3600 or not isinstance(block_hash,str) or not re.fullmatch('0x[a-f0-9]{64}',block_hash):
        raise ValueError('parent finalized snapshot is missing or stale')
    tag=hex(height)
    def call(name,argument='',count=1):
        result=rpc('eth_call',[{'to':expected['stake'],'data':SELECTORS[name]+argument},tag],query)
        return decode(result,count)
    minimum,fee,capacity,count,epoch=(call(name)[0] for name in ('minimum','fee','capacity','count','epoch'))
    if minimum==0 or not 0<capacity<=1000 or count>1000:raise ValueError('unsupported live admission bounds')
    if abi_address(call('nft')[0])!=expected['nft']:raise ValueError('staking ownership NFT differs from reviewed network')
    token=abi_address(call('token')[0])
    identifier=call('signer_id',word(int(signer,16)))[0]
    parent_validator=None
    if identifier:
        native=call('validator',word(identifier),8)
        if abi_address(native[5])!=signer or native[7]>255:raise ValueError('registered signer identity differs')
        parent_validator={'id':str(identifier),'stake_base_units':str(native[0]),'activation_epoch':str(native[2]),
            'deactivation_epoch':str(native[3]),'jail_time':str(native[4]),'status_code':native[7],
            'owner':abi_address(call('owner',word(identifier))[0])}
    current=None if parent_only else members(query(1317,'/stake/validators-set')).get(signer)
    # Never use /stake/validator-status's ambiguous is_old field: the pinned
    # handler returns IsCurrentValidatorByAddress under that misleading name.
    parent_set=active_ids(rpc('eth_call',[{'to':expected['stake'],'data':SELECTORS['set']},tag],query))
    if len(parent_set)!=count:raise ValueError('parent validator count/set disagree at the same finalized block')
    coherent=current is not None and identifier==current['id'] and identifier in parent_set
    again=rpc('eth_getBlockByNumber',[tag,False],query)
    if again.get('hash')!=block_hash:raise ValueError('parent snapshot changed during observation')
    return {'network':network,'signer':signer,'parent_finalized_height':str(height),'parent_finalized_hash':block_hash,
        'heimdall_height':None if local is None else str(local['height']),'staking_manager':expected['stake'],'staking_nft':expected['nft'],'staking_token':token,
        'minimum_deposit_base_units':str(minimum),'minimum_heimdall_fee_base_units':str(fee),'capacity':capacity,'current_count':count,
        'epoch':str(epoch),'parent_active':identifier in parent_set,'registered':identifier!=0,'parent_validator':parent_validator,'active_member':current,
        'active_on_both_observations':coherent,'application_guarantees_admission':False,'transaction_submission':'external only'}


def admitted(value,expected,public_key=None):
    """Registration ownership is distinct from the funded checkpoint signer."""
    if not isinstance(value,dict):raise ValueError('original admission observation is missing')
    native=value.get('parent_validator')
    if (value.get('network')!=expected['network'] or value.get('signer')!=expected['signer']
            or value.get('registered') is not True or value.get('parent_active') is not True
            or not isinstance(native,dict) or native.get('owner')!=expected['stake_owner']):
        raise ValueError('original signer is not currently admitted for the separate stake owner')
    if public_key is not None:
        current=value.get('active_member')
        if (value.get('active_on_both_observations') is not True or not isinstance(current,dict)
                or current.get('public_key')!=public_key or str(current.get('id'))!=native.get('id')):
            raise ValueError('healthy original observer has not accepted this exact admitted public key')
    return value
