# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded public-chain observations. No transaction creation, signing or broadcast."""
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from identity import address, unique_object

ENDPOINTS = {
    'mainnet': 'https://api.trongrid.io',
    'nile': 'https://nile.trongrid.io',
}
METHODS = {
    'wallet/getblockbynum', 'wallet/getnowblock', 'wallet/getnodeinfo',
    'wallet/listwitnesses', 'wallet/getaccount', 'wallet/getchainparameters',
    'walletsolidity/getnowblock',
}
LIMIT = 16 * 1024 * 1024


class FixedDestination(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        fp.close()
        raise ValueError('fixed TRON observations cannot follow redirects')


def open_fixed(request):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),FixedDestination())
    try:return opener.open(request,timeout=8)
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError('fixed TRON observation failed') from None


def request(network, method, payload=None, local=False):
    if network not in ENDPOINTS or method not in METHODS:
        raise ValueError('unsupported TRON read-only observation')
    base = 'http://127.0.0.1:8090' if local else ENDPOINTS[network]
    data = json.dumps(payload or {}).encode()
    if len(data) > 4096:
        raise ValueError('oversized TRON observation request')
    req = urllib.request.Request(base + '/' + method, data=data,
                                 headers={'Content-Type': 'application/json'})
    with open_fixed(req) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('TRON observation exceeded the response limit')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or 'Error' in value or 'Error:' in value:
        raise ValueError('TRON observation did not return usable state')
    return value


def public_address(value):
    if isinstance(value, str) and len(value) == 42:
        raw = bytes.fromhex(value)
        if raw[0] != 65:
            raise ValueError('unsupported account address prefix')
        return raw
    return address(value)


def integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('invalid chain-state integer')
    return value


def delegation(account, owner, signer):
    """Support the documented single dedicated ECDSA Witness-key profile only."""
    wanted, signing = address(owner), address(signer)
    if wanted == signing or public_address(account.get('address')) != wanted:
        raise ValueError('owner and signer must be distinct and match the queried account')
    witness = account.get('witness_permission', {})
    if witness.get('type') not in ('Witness', 1) or integer(witness.get('id')) != 1:
        raise ValueError('a dedicated Witness permission is required')
    keys = witness.get('keys')
    if integer(witness.get('threshold'), 1) != 1 or not isinstance(keys, list) or len(keys) != 1:
        raise ValueError('only a single Witness key with threshold one is supported')
    key = keys[0]
    if set(key) != {'address', 'weight'} or integer(key.get('weight'), 1) != 1 or public_address(key.get('address')) != signing:
        raise ValueError('Witness permission does not match the reserved ECDSA signer')
    owner_permission = account.get('owner_permission')
    active_permissions = account.get('active_permission')
    if not isinstance(owner_permission, dict) or not isinstance(active_permissions, list):
        raise ValueError('Owner/Active permissions could not be inspected')
    for permission in [owner_permission] + active_permissions:
        if not isinstance(permission, dict) or not isinstance(permission.get('keys'), list) or not permission['keys']:
            raise ValueError('invalid Owner/Active permission structure')
        for entry in permission.get('keys', []):
            if public_address(entry.get('address')) == signing:
                raise ValueError('the Witness signer also has Owner/Active authority; import refused')
    return True


def head(block, fresh=True):
    raw = block['block_header']['raw_data']
    height = integer(raw.get('number'), 1)
    stamp = integer(raw.get('timestamp'), 1)
    identifier = block['blockID']
    if not isinstance(identifier, str) or len(identifier) != 64:
        raise ValueError('block identifier is missing')
    bytes.fromhex(identifier)
    age = time.time() - stamp / 1000
    if fresh and not -30 <= age <= 120:
        raise ValueError('public TRON head is stale or in the future')
    return {'height': height, 'timestamp_ms': stamp, 'age_seconds': age, 'block_id': identifier}


def network_state(expected, query=request):
    network = expected['network']
    genesis = query(network, 'wallet/getblockbynum', {'num': 0})
    if genesis.get('blockID') != expected['genesis']:
        raise ValueError('public endpoint genesis differs from the reserved network')
    return head(query(network, 'wallet/getnowblock'))


def registration(expected, query=request):
    tip = network_state(expected, query)
    owner = address(expected['owner'])
    address(expected['signer'])
    members = query(expected['network'], 'wallet/listwitnesses', {'visible': True}).get('witnesses')
    if not isinstance(members, list):
        raise ValueError('witness set was not returned')
    matches = [w for w in members if public_address(w.get('address')) == owner]
    if len(matches) > 1:
        raise ValueError('duplicate witness account in response')
    witness = matches[0] if matches else None
    account = query(expected['network'], 'wallet/getaccount', {'address': expected['owner'], 'visible': True})
    try:
        permission = delegation(account, expected['owner'], expected['signer'])
        permission_error = None
    except (ValueError, TypeError, KeyError, AttributeError):
        permission, permission_error = False, 'dedicated Witness-only permission is missing, unsupported or mismatched'
    response = query(expected['network'], 'wallet/getchainparameters')
    params = response.get('chainParameter')
    if not isinstance(params, list):
        raise ValueError('chain parameters were not returned')
    parameters = {}
    for item in params:
        if item.get('key') in ('getAccountUpgradeCost', 'getMaintenanceTimeInterval'):
            if item['key'] in parameters:
                raise ValueError('duplicate chain parameter')
            parameters[item['key']] = integer(item.get('value', 0))
    if witness is not None and 'isJobs' in witness and type(witness['isJobs']) is not bool:
        raise ValueError('invalid election state')
    return {
        'head': tip, 'membership': 'not-registered' if witness is None else 'elected' if witness.get('isJobs', False) else 'candidate',
        'witness_permission_valid': permission, 'permission_error': permission_error,
        'candidate_fee_sun': parameters.get('getAccountUpgradeCost'),
        'maintenance_interval_ms': parameters.get('getMaintenanceTimeInterval'),
        'votes': None if witness is None else integer(witness.get('voteCount', 0)),
        'total_produced': None if witness is None else integer(witness.get('totalProduced', 0)),
        'total_missed': None if witness is None else integer(witness.get('totalMissed', 0)),
        'production': 'membership and account counters do not prove production by this particular host',
    }


def local_state(expected, query=request, sleep=time.sleep):
    network = expected['network']
    genesis = query(network, 'wallet/getblockbynum', {'num': 0}, local=True)
    if genesis.get('blockID') != expected['genesis']:
        raise ValueError('local node genesis differs from its reserved network')
    first = head(query(network, 'wallet/getnowblock', local=True), fresh=False)
    sleep(4)  # One TRON slot is three seconds; process liveness alone is insufficient.
    latest = head(query(network, 'wallet/getnowblock', local=True), fresh=False)
    public = network_state(expected, query)
    info = query(network, 'wallet/getnodeinfo', local=True)
    gap = public['height'] - latest['height']
    progressing = latest['height'] > first['height']
    recent = -30 <= latest['age_seconds'] <= 120
    return {'local': latest, 'public': public, 'advancing': progressing,
            'head_gap': gap, 'code_version': info.get('configNodeInfo', {}).get('codeVersion'),
            'active_peers': info.get('activeConnectCount'),
            'chain_ready': progressing and recent and -2 <= gap <= 20}


def grpc(run=subprocess.run, temporary=tempfile.TemporaryDirectory):
    with temporary(prefix='tron-grpc-', dir='/run') as directory:
        header, body = Path(directory) / 'headers', Path(directory) / 'body'
        result = run(['/usr/bin/curl','--disable','--noproxy','*', '--silent', '--show-error', '--http2-prior-knowledge',
                      '--max-time', '8', '--max-filesize', str(LIMIT), '-D', str(header), '-o', str(body),
                      '-H', 'content-type: application/grpc', '-H', 'te: trailers', '--data-binary', '@-',
                      'http://127.0.0.1:50051/protocol.Wallet/GetNowBlock'],
                     input=bytes(5), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                     env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'})
        if result.returncode:
            return False
        lines = header.read_text().splitlines()
        statuses = [line.split(':', 1)[1].strip() for line in lines if line.lower().startswith('grpc-status:')]
        responses = [line.split()[:2] for line in lines if line.startswith('HTTP/')]
        frame = body.read_bytes()
        return responses == [['HTTP/2', '200']] and statuses == ['0'] and len(frame) > 5 and frame[0] == 0 and int.from_bytes(frame[1:5], 'big') == len(frame) - 5


def json_rpc(expected):
    request = urllib.request.Request('http://127.0.0.1:8545/jsonrpc',
        data=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
        headers={'Content-Type': 'application/json'})
    with open_fixed(request) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        return False
    value = json.loads(raw, object_pairs_hook=unique_object)
    return 'error' not in value and value.get('jsonrpc') == '2.0' and type(value.get('id')) is int and value['id'] == 1 and value.get('result') == '0x' + expected['genesis'][-8:]
