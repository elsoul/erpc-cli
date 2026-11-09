# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only loopback readiness after kernel process/socket authorization.

RPC readiness does not establish validator registration or activation. Those
require their independent public-account checks and explicit custody transition.
"""
import base64
import struct
import time
import urllib.error
import urllib.request
from native_files import Refused, encoded, json_value, require

PORT = 8899
MAXIMUM_AGE = 120
CLOCK = 'SysvarC1ock11111111111111111111111111111111'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, response, *_args, **_kwargs):
        response.close()
        raise ValueError('native observation cannot redirect')


def rpc(method, params, port=None):
    port = PORT if port is None else port
    require(type(port) is int and port in (PORT, 7211), 'unsupported native observation port')
    request = urllib.request.Request('http://127.0.0.1:' + str(port),
        data=encoded({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
        headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            require(response.status == 200, 'native RPC observation failed')
            raw = response.read(1048577)
    except urllib.error.HTTPError as error:
        error.close()
        raise Refused('native RPC observation failed') from None
    require(len(raw) <= 1048576, 'native RPC response exceeds its bound')
    body = json_value(raw)
    require(isinstance(body, dict) and body.get('jsonrpc') == '2.0'
            and type(body.get('id')) is int and body['id'] == 1
            and 'result' in body and 'error' not in body, 'native RPC observation unavailable')
    return body['result']


def finalized_clock(call):
    """The slot and time of the finalized bank, from its Clock sysvar.

    getBlockTime answers only on a node that keeps transaction history, which a
    node that only syncs does not.
    """
    reply = call('getAccountInfo', [CLOCK, {'commitment': 'finalized', 'encoding': 'base64'}])
    # A reply of any other shape raises here, and inspect refuses it.
    data = reply['value']['data']
    require(len(data) == 2 and data[1] == 'base64', 'finalized clock unavailable')
    slot, _, _, _, timestamp = struct.unpack('<QqQQq', base64.b64decode(data[0], validate=True))
    return slot, timestamp


def inspect(profile, public_identity, prove, call=rpc, now=time.time):
    """The supplied closure proves the fixed runtime before AND after its replies."""
    result = {'rpc_ready': False}
    try:
        before = prove()
        require(call('getGenesisHash', []) == profile['genesis'], 'native RPC genesis differs')
        identity = call('getIdentity', [])
        require(isinstance(identity, dict) and identity.get('identity') == public_identity,
                'native RPC identity differs')
        version = call('getVersion', [])
        require(isinstance(version, dict) and version.get('solana-core') == profile['version'],
                'native RPC version differs')
        require(call('getHealth', []) == 'ok', 'native node is not healthy')
        slot, timestamp = finalized_clock(call)
        age = int(now()) - timestamp
        require(-30 <= age <= MAXIMUM_AGE, 'finalized native observation is stale')
        require(prove() == before, 'native process changed during RPC observation')
        result.update(rpc_ready=True, identity=public_identity, version=profile['version'],
                      finalized_slot=slot, finalized_age_seconds=age)
    except Exception:
        # Native errors and arbitrary response bodies never reach logs or output.
        result['inspection_error'] = 'owned runtime, identity, network, version or finalized synchronization unavailable'
    return result
