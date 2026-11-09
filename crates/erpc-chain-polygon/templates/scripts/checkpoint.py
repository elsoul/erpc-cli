# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Narrow native bridge forwarding policy; never constructs or signs a transaction.

The pinned Heimdall bridge emits EIP-1559 submitCheckpoint calls. Its parent
transport accepts that format only, to the reviewed network's RootChain proxy,
with zero transferred value. Registration, token approval and stake-owner calls
remain external. This is a forwarding boundary, not a restriction on what an
Ethereum private key could authorize outside this managed process.
"""
import re
import signatures
from admission import CONTRACTS,address

SELECTOR=bytes.fromhex('4e43e495')
MAX_BYTES=262144
FEE_CAP=500000000000
TIP_CAP=10000000000


def encoded(value):
    if not isinstance(value,str) or not value.startswith('0x') or len(value)>2+MAX_BYTES*2 or not re.fullmatch('0x(?:[a-fA-F0-9]{2})+',value):
        raise ValueError('invalid bounded transaction encoding')
    return bytes.fromhex(value[2:])


def calldata(value):
    raw=encoded(value) if isinstance(value,str) else value
    if not isinstance(raw,bytes) or not 132<=len(raw)<=MAX_BYTES or raw[:4]!=SELECTOR:
        raise ValueError('only native submitCheckpoint calldata is allowed')
    data=raw[4:]
    def word(offset):
        if offset<0 or offset+32>len(data):raise ValueError('truncated checkpoint ABI')
        return int.from_bytes(data[offset:offset+32],'big')
    if word(0)!=64:raise ValueError('noncanonical checkpoint data offset')
    length=word(64)
    padded=(length+31)//32*32
    signature_offset=96+padded
    if length==0 or word(32)!=signature_offset or any(data[96+length:signature_offset]):
        raise ValueError('noncanonical checkpoint dynamic data')
    count=word(signature_offset)
    if not 1<=count<=1000 or len(data)!=signature_offset+32+count*96:
        raise ValueError('checkpoint signatures are absent, excessive or truncated')
    return raw


def rlp(raw):
    """Decode a bounded canonical RLP tree, rejecting overlong lengths/integers."""
    items=0
    def item(offset,limit,depth):
        nonlocal items
        items+=1
        if items>64 or depth>4 or offset>=limit:raise ValueError('invalid transaction RLP bounds')
        prefix=raw[offset];start=offset+1
        if prefix<128:return bytes([prefix]),start
        is_list=prefix>=192
        short=192 if is_list else 128
        long=247 if is_list else 183
        if prefix<=long:length=prefix-short
        else:
            size=prefix-long
            if size>4 or start+size>limit or raw[start]==0:raise ValueError('invalid RLP length')
            length=int.from_bytes(raw[start:start+size],'big');start+=size
            if length<56:raise ValueError('overlong RLP length')
        end=start+length
        if end>limit:raise ValueError('truncated RLP item')
        if not is_list:
            value=raw[start:end]
            if length==1 and value[0]<128:raise ValueError('overlong RLP byte')
            return value,end
        values=[]
        while start<end:
            child,start=item(start,end,depth+1);values.append(child)
        return values,end
    value,end=item(0,len(raw),0)
    if end!=len(raw):raise ValueError('trailing transaction RLP')
    return value


def integer(value,maximum=(1<<256)-1):
    if not isinstance(value,bytes) or len(value)>32 or value[:1]==b'\0':raise ValueError('noncanonical RLP integer')
    result=int.from_bytes(value,'big')
    if result>maximum:raise ValueError('transaction integer exceeds its bound')
    return result


def encode_rlp(value):
    if isinstance(value, list):
        payload = b''.join(encode_rlp(item) for item in value); short, long = 192, 247
    elif isinstance(value, bytes):
        payload = value; short, long = 128, 183
        if len(value) == 1 and value[0] < 128: return value
    else: raise ValueError('invalid canonical transaction field')
    if len(payload) < 56: return bytes([short+len(payload)])+payload
    length = len(payload).to_bytes((len(payload).bit_length()+7)//8, 'big')
    return bytes([long+len(length)])+length+payload


def transaction(value,network,signer):
    if network not in CONTRACTS:raise ValueError('unsupported checkpoint network')
    raw=encoded(value)
    if raw[:1]!=b'\x02':raise ValueError('native bridge requires EIP-1559 transactions')
    fields=rlp(raw[1:])
    if not isinstance(fields,list) or len(fields)!=12:raise ValueError('unexpected EIP-1559 field count')
    chain,nonce,tip,fee,gas,to,amount,data,access,parity,r,s=fields
    if (integer(chain)!=(1 if network=='mainnet' else 11155111)
            or to!=bytes.fromhex(CONTRACTS[network]['root'][2:]) or integer(amount)!=0
            or integer(tip)>TIP_CAP or not 0<integer(fee)<=FEE_CAP or integer(tip)>integer(fee)
            or not 0<integer(gas,(1<<64)-1)<=30000000 or integer(nonce,(1<<64)-1)>=(1<<63)
            or access!=[] or integer(parity)>1 or integer(r)==0 or integer(s)==0):
        raise ValueError('native checkpoint transaction authority differs')
    calldata(data)
    recovered=signatures.sender(signatures.keccak(b'\x02'+encode_rlp(fields[:9])),integer(parity),integer(r),integer(s))
    if recovered!=address(signer):raise ValueError('checkpoint signature does not belong to the original dedicated wallet')
    return raw


def allow(call,network,signer):
    """Validate only the bridge's extra parent methods, before any forwarding."""
    if network not in CONTRACTS:raise ValueError('unsupported checkpoint network')
    signer=address(signer);method=call.get('method');params=call.get('params')
    if method=='eth_maxPriorityFeePerGas':
        if params!=[]:raise ValueError('unexpected tip request arguments')
    elif method=='eth_getTransactionCount':
        if not isinstance(params,list) or len(params)!=2 or address(params[0])!=signer or params[1]!='pending':
            raise ValueError('native bridge nonce must belong to the dedicated signer')
    elif method=='eth_estimateGas':
        if not isinstance(params,list) or len(params)!=1 or not isinstance(params[0],dict):
            raise ValueError('unexpected native gas estimation arguments')
        value=params[0]
        if (set(value)-{'from','to','input','data','value'} or address(value.get('from'))!=signer
                or address(value.get('to'))!=CONTRACTS[network]['root'] or value.get('value','0x0')!='0x0'
                or ('input' in value)==('data' in value)):
            raise ValueError('only the dedicated checkpoint gas estimate is allowed')
        calldata(value.get('input',value.get('data')))
    elif method=='eth_sendRawTransaction':
        if not isinstance(params,list) or len(params)!=1:raise ValueError('expected one native signed checkpoint')
        transaction(params[0],network,signer)
    else:raise ValueError('unsupported checkpoint forwarding method')
