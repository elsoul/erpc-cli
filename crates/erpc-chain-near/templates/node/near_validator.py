# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated consensus custody and bounded read-only staking-pool observations."""
import base64
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

FACTORIES = {'mainnet': 'poolv1.near', 'testnet': 'pool.f863973.m0'}
ENDPOINTS = {'mainnet': 'https://rpc.mainnet.near.org', 'testnet': 'https://rpc.testnet.near.org'}
FACTORY_CODE = 'FjtxkkaKDKCW1F6HgsuYvnQ9GMxrzhnkQwCm52G9gYuA'
# Observed deployed legacy factory's embedded pool module, also observed on chain.
# These identities do not assert a reproducible correspondence to a source commit.
POOL_CODE = 'J1arLz48fgXcGyCPVckFwLnewNH6j1uw79thsvwqGYTY'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate object field')
        result[key] = value
    return result


def account(value):
    if not isinstance(value, str) or not 2 <= len(value) <= 64 or not re.fullmatch(r'[a-z0-9]+(?:[._-][a-z0-9]+)*', value):
        raise ValueError('invalid NEAR account')
    return value


def decode(value, length):
    if not isinstance(value, str) or not value.startswith('ed25519:'):
        raise ValueError('dedicated key must use Ed25519')
    encoded = value[8:]
    if not 1 <= len(encoded) <= 90: raise ValueError('invalid key size')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    for char in encoded: number = number * 58 + alphabet.index(char)
    raw = b'\0' * (len(encoded) - len(encoded.lstrip('1'))) + number.to_bytes((number.bit_length() + 7) // 8, 'big')
    if len(raw) != length: raise ValueError('invalid canonical key size')
    return raw


def reservation(expected):
    factory = FACTORIES[expected['network']]
    pool = account(expected['validator_account'])
    owner = account(expected['owner_account'])
    suffix = '.' + factory
    if not pool.endswith(suffix) or not pool[:-len(suffix)] or '.' in pool[:-len(suffix)] or pool == owner:
        raise ValueError('validator must use the reviewed factory and a separate owner')
    decode(expected['staking_public_key'], 32)
    fee = expected['commission_basis_points']
    if type(fee) is not int or not 0 <= fee <= 10000:
        raise ValueError('commission must be explicit basis points')


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,38}', value) or int(value) >= 2 ** 128:
        raise ValueError('invalid canonical yoctoNEAR amount')
    return int(value)


def request(network, method, params):
    if network not in ENDPOINTS or method not in ('status', 'block', 'query', 'validators'):
        raise ValueError('unsupported read-only observation')
    if method == 'query' and params.get('request_type') not in ('view_account', 'view_access_key_list', 'call_function'):
        raise ValueError('unsupported read-only query')
    body = json.dumps({'jsonrpc': '2.0', 'id': 'erpc-validator', 'method': method, 'params': params}).encode()
    if len(body) > 4096: raise ValueError('oversized observation input')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs): raise ValueError('observation redirects refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(ENDPOINTS[network], data=body,
        headers={'Content-Type': 'application/json', 'Accept-Encoding': 'identity'})
    with opener.open(req, timeout=15) as response:
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise ValueError('observation is not successful raw JSON')
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024: raise ValueError('oversized observation response')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or value.get('jsonrpc') != '2.0' or value.get('id') != 'erpc-validator':
        raise ValueError('mismatched observation response')
    if 'error' in value:
        error = value['error']
        if (method == 'query' and params.get('request_type') == 'view_account'
                and isinstance(error, dict) and error.get('cause', {}).get('name') == 'UNKNOWN_ACCOUNT'):
            return None
        raise ValueError('public observation did not return usable state')
    if 'result' not in value: raise ValueError('missing observation result')
    return value['result']


def observe(expected, block_age, query=request, balances=False):
    reservation(expected)
    network = expected['network']
    status = query(network, 'status', [])
    sync = status['sync_info']
    if status.get('chain_id') != network or status.get('genesis_hash') != expected['genesis_hash']:
        raise ValueError('public observer network differs')
    if sync['syncing'] is not False or not -120 <= block_age(sync['latest_block_time']) <= 300:
        raise ValueError('public observer is stale or syncing')
    block = sync['latest_block_hash']
    if not isinstance(block, str) or not re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', block):
        raise ValueError('invalid observed block identity')
    header = query(network, 'block', {'block_id': block}).get('header', {})
    epoch = header.get('epoch_id')
    if header.get('hash') != block or header.get('height') != sync['latest_block_height'] or not isinstance(epoch, str) or not re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', epoch):
        raise ValueError('observed block/epoch identity differs')
    def state(account_id, kind='view_account', method=None, args=None):
        params = {'request_type': kind, 'block_id': block, 'account_id': account_id}
        if method is not None:
            params.update(method_name=method, args_base64=base64.b64encode(json.dumps(args or {}).encode()).decode())
        value = query(network, 'query', params)
        if value is None and kind == 'view_account': return None
        if not isinstance(value, dict) or value.get('block_hash') != block:
            raise ValueError('state observation belongs to another block')
        if method is None: return value
        raw = value.get('result')
        if not isinstance(raw, list) or len(raw) > 65536 or any(type(b) is not int or not 0 <= b <= 255 for b in raw):
            raise ValueError('invalid bounded contract view result')
        return json.loads(bytes(raw), object_pairs_hook=unique)
    factory = FACTORIES[network]
    factory_state = state(factory)
    if not factory_state or factory_state.get('code_hash') != FACTORY_CODE:
        raise ValueError('factory code differs from the reviewed deployed identity')
    minimum = state(factory, 'call_function', 'get_min_attached_balance')
    if quantity(minimum) == 0: raise ValueError('factory minimum is not positive')
    owner_keys = state(expected['owner_account'], 'view_access_key_list').get('keys')
    if not isinstance(owner_keys, list) or not owner_keys:
        raise ValueError('external owner access keys could not be established')
    for key in owner_keys:
        if not isinstance(key, dict) or not isinstance(key.get('public_key'), str):
            raise ValueError('invalid external owner key entry')
        if key['public_key'] == expected['staking_public_key']:
            raise ValueError('consensus signer also has owner account authority')
    pool = state(expected['validator_account'])
    paused = None
    owner_balance = None
    if pool is not None:
        if pool.get('code_hash') != POOL_CODE:
            raise ValueError('pool code differs from the reviewed factory deployment')
        if state(expected['validator_account'], 'view_access_key_list').get('keys') != []:
            raise ValueError('pool has account access keys outside the factory profile')
        for method, wanted in [('get_owner_id', expected['owner_account']), ('get_staking_key', expected['staking_public_key'])]:
            if state(expected['validator_account'], 'call_function', method) != wanted:
                raise ValueError('on-chain pool owner or consensus key differs')
        fee = state(expected['validator_account'], 'call_function', 'get_reward_fee_fraction')
        if not isinstance(fee, dict) or set(fee) != {'numerator', 'denominator'} or any(type(v) is not int for v in fee.values()):
            raise ValueError('unsupported pool commission representation')
        if not 0 <= fee['numerator'] <= fee['denominator'] or fee['denominator'] <= 0 or fee['numerator'] * 10000 != expected['commission_basis_points'] * fee['denominator']:
            raise ValueError('pool commission differs from the reservation')
        paused = state(expected['validator_account'], 'call_function', 'is_staking_paused')
        if type(paused) is not bool: raise ValueError('invalid pool pause status')
        if balances:
            args = {'account_id': expected['owner_account']}
            owner_balance = {}
            for label, method in [('staked_yocto', 'get_account_staked_balance'), ('unstaked_yocto', 'get_account_unstaked_balance')]:
                amount = state(expected['validator_account'], 'call_function', method, args)
                quantity(amount)
                owner_balance[label] = amount
            available = state(expected['validator_account'], 'call_function', 'is_account_unstaked_balance_available', args)
            if type(available) is not bool: raise ValueError('invalid withdrawal availability')
            owner_balance['withdrawal_available'] = available
    # Native block-id lookup only supports the final block of a completed epoch.
    # An explicit epoch ID also supports the current epoch and binds this query
    # to the observed header instead of silently selecting a newer epoch.
    validators = query(network, 'validators', {'epoch_id': epoch})
    membership = {}
    for field in ('current_validators', 'next_validators', 'current_proposals'):
        entries = validators.get(field)
        if not isinstance(entries, list) or len(entries) > 10000:
            raise ValueError('validator epoch observation is missing or oversized')
        matches = []
        for entry in entries:
            if not isinstance(entry, dict): raise ValueError('invalid validator epoch entry')
            same_account = entry.get('account_id') == expected['validator_account']
            same_key = entry.get('public_key') == expected['staking_public_key']
            if same_account != same_key: raise ValueError('validator account or consensus key is used by another identity')
            if same_account: matches.append(entry)
        if len(matches) > 1: raise ValueError('duplicate validator epoch entry')
        membership[field] = bool(matches)
    return {'block_hash': block, 'epoch_id': epoch, 'height': sync['latest_block_height'], 'factory': factory,
            'factory_code_hash': FACTORY_CODE, 'minimum_deposit_yocto': minimum,
            'pool_exists': pool is not None, 'pool_code_hash': None if pool is None else POOL_CODE,
            'staking_paused': paused, 'owner_balance': owner_balance, **membership}


def key_material(control, expected, raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096: raise ValueError('invalid key file size')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {'account_id', 'public_key', 'secret_key'}:
        raise ValueError('invalid native consensus key file')
    if value['account_id'] != expected['validator_account'] or value['public_key'] != expected['staking_public_key']:
        raise ValueError('consensus key identity differs')
    public, secret = decode(value['public_key'], 32), decode(value['secret_key'], 64)
    derived = control.command('/usr/bin/openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER',
                              data=bytes.fromhex('302e020100300506032b657004220420') + secret[:32]).stdout
    if derived != bytes.fromhex('302a300506032b6570032100') + public or secret[32:] != public:
        raise ValueError('consensus key does not derive its reserved public identity')


def identity(control, expected):
    receipt = control.read('validator-identity.json')
    if receipt.get('contract') != expected:
        raise ValueError('validator identity belongs to another owner')
    encrypted = control.path('/etc/credstore.encrypted/near-validator.key')
    if receipt.get('cipher_sha256') != control.file_digest(encrypted):
        raise ValueError('original validator credential is missing or changed; explicit restoration required')
    return receipt


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def retain_generation(control, encrypted, old, digest):
    # Retained ciphertext uses its own inode. A crash before replacement must
    # leave the active original a private single-link file that can be retried.
    if old.exists() or old.is_symlink():
        if control.file_digest(old) != digest:
            raise ValueError('retained credential generation differs')
        return
    source = os.open(encrypted, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source, 'rb') as file:
        control.file_info(os.fstat(file.fileno()), private=True, limit=65536)
        raw = file.read(65537)
    if len(raw) > 65536 or control.digest(raw) != digest:
        raise ValueError('credential generation changed during retention')
    fd, name = tempfile.mkstemp(prefix='.near-validator.', dir=encrypted.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            control.file_info(os.fstat(output.fileno()), private=True)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, old)
        sync_directory(encrypted.parent)
    finally:
        temporary.unlink(missing_ok=True)


def import_key(control, expected, request, block_age):
    control.contract(expected)
    control.account(expected)
    if expected['role'] != 'validator' or not isinstance(request, dict) or set(request) != {'key_file', 'keys_unhosted', 'restore', 'intent', 'policy_sha256'}:
        raise ValueError('invalid consensus import request')
    if type(request['restore']) is not bool or type(request['keys_unhosted']) is not bool or not isinstance(request['key_file'], str):
        raise ValueError('invalid consensus import flags')
    raw = request['key_file'].encode()
    key_material(control, expected, raw)
    receipt_file = control.directory / 'validator-identity.json'
    established = receipt_file.exists()
    digest = control.digest(raw)
    if established:
        receipt = control.read('validator-identity.json')
        if receipt.get('contract') != expected or receipt.get('plaintext_sha256') != digest:
            raise ValueError('only the exact original native credential can be restored')
        if not request['restore']:
            control.prepared(expected, request['policy_sha256'], request['intent'])
            control.stopped(expected)
            recover_publication(control, expected)
            return {'identity_verified': True}
        control.write('activation-revoked', {'reason': 'validator restoration'})
        control.write('stopped', {'contract': expected})
        control.write('operation.json', {'intent': None})
        control.stopped(expected)
    else:
        if request['restore'] or not request['keys_unhosted']:
            raise ValueError('first import requires an explicitly unhosted dedicated key')
        control.prepared(expected, request['policy_sha256'], request['intent'])
        if (control.home / 'data').exists():
            raise ValueError('first validator import cannot adopt an existing database')
        if control.path('/etc/credstore.encrypted/near-validator.key').exists():
            raise ValueError('unreceipted validator credential cannot be adopted')
        control.stopped(expected)
    observed = observe(expected, block_age)
    if not established and (observed['current_validators'] or observed['next_validators']):
        raise ValueError('already-active identity requires a reviewed source-fencing migration')
    pending = {'contract': expected, 'plaintext_sha256': digest}
    if (control.directory / 'validator-import.json').exists() and control.read('validator-import.json') != pending:
        raise ValueError('another consensus import is incomplete')
    control.write('validator-import.json', pending)
    encrypted = control.path('/etc/credstore.encrypted/near-validator.key')
    control.directory_guard(encrypted.parent, create=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.near-validator.', dir=encrypted.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        # systemd-creds refuses an existing output file; the root-only parent
        # prevents other users from racing this random name after unlink.
        candidate.unlink()
        control.command('systemd-creds', 'encrypt', '--with-key=host', '--name=validator-key.json', '-', str(candidate), data=raw)
        os.chmod(candidate, 0o600)
        with candidate.open('rb') as saved: os.fsync(saved.fileno())
        sync_directory(encrypted.parent)
        # Old encrypted generations remain available for explicit same-host recovery.
        if encrypted.exists():
            old_digest = control.file_digest(encrypted)
            old = encrypted.with_name('near-validator.previous.' + old_digest)
            retain_generation(control, encrypted, old, old_digest)
        receipt = {'contract': expected, 'plaintext_sha256': digest,
                   'cipher_sha256': control.file_digest(candidate), 'pending_file': candidate.name}
        control.write('validator-identity.json', receipt)
        os.replace(candidate, encrypted)
        sync_directory(encrypted.parent)
        control.remove('validator-import.json')
        return {'identity_verified': True, 'restored': established, 'registration': observed}
    finally:
        # A published receipt owns this candidate; keep it if replacement failed.
        if not receipt_file.exists() or control.read('validator-identity.json').get('pending_file') != candidate.name:
            candidate.unlink(missing_ok=True)


def recover_publication(control, expected):
    receipt = control.read('validator-identity.json')
    if receipt.get('contract') != expected: raise ValueError('validator receipt owner differs')
    encrypted = control.path('/etc/credstore.encrypted/near-validator.key')
    pending = receipt.get('pending_file', '')
    if not isinstance(pending, str) or not re.fullmatch(r'\.near-validator\.[a-z0-9_]{8}', pending):
        raise ValueError('invalid pending credential name')
    candidate = encrypted.parent / pending
    if candidate.exists():
        if control.file_digest(candidate) != receipt['cipher_sha256']:
            raise ValueError('interrupted credential does not match its receipt')
        os.replace(candidate, encrypted)
        sync_directory(encrypted.parent)
    verified = identity(control, expected)
    if (control.directory / 'validator-import.json').exists():
        if control.read('validator-import.json') != {'contract': expected, 'plaintext_sha256': receipt['plaintext_sha256']}:
            raise ValueError('interrupted import metadata differs from the original credential')
        control.remove('validator-import.json')
    return verified
