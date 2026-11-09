# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Add an independent non-signing ingress identity without rewriting core accounts."""
from pathlib import Path
import native_accounts as accounts
from native_files import require, root_directory

SPECS = {'gateway': ('erpc-solana-gateway', '/var/lib/erpc-solana-gateway')}
INTENT = 'gateway-account-intent.json'
RECEIPT = 'gateway-account.json'


def original(state, contract):
    state.owner(contract)
    value = state.get(RECEIPT)
    require(set(value) == {'contract', 'accounts'} and value['contract'] == contract,
            'native ingress account belongs to another host')
    accounts.validate_plan(value['accounts'], SPECS)
    return value['accounts']['gateway']


def verify(state, contract):
    require(contract['profile'] == 'agave-native-rpc', 'only RPC hosts have a public ingress account')
    record = original(state, contract)
    accounts.verify_slot(record)
    root_directory(Path(record['home']))
    return record


def ensure(state, contract, run=accounts.execute):
    state.owner(contract)
    require(contract['profile'] == 'agave-native-rpc', 'validator hosts cannot reserve public ingress')
    if (state.directory / RECEIPT).exists():
        record = verify(state, contract)
        value = {'contract': contract, 'accounts': {'gateway': record}}
        records = {RECEIPT: value}
        if (state.directory / INTENT).exists(): records[INTENT] = value
        accounts.synchronize(state, contract, records)
        return record
    if (state.directory / INTENT).exists():
        value = state.get(INTENT)
        require(set(value) == {'contract', 'accounts'} and value['contract'] == contract,
                'native ingress reservation belongs to another host')
    else:
        value = {'contract': contract, 'accounts': accounts.plan_new(state, contract, SPECS)}
        state.put(INTENT, value)
    accounts.validate_plan(value['accounts'], SPECS)
    record = value['accounts']['gateway']
    accounts.verify_slot(record, missing=True)
    accounts.synchronize(state, contract, {INTENT: value})
    user, group = accounts.verify_slot(record, missing=True)
    if group is None:
        run(['/usr/sbin/groupadd', '--system', '--gid', str(record['gid']), record['name']])
    if user is None:
        run(['/usr/sbin/useradd', '--system', '--no-create-home', '--no-user-group', '--no-log-init',
            '--uid', str(record['uid']), '--gid', str(record['gid']), '--home-dir', record['home'],
            '--shell', record['shell'], record['name']])
    accounts.verify_slot(record)
    root_directory(Path(record['home']), create=True)
    state.put(RECEIPT, value)
    accounts.synchronize(state, contract, {INTENT: value, RECEIPT: value})
    return verify(state, contract)
