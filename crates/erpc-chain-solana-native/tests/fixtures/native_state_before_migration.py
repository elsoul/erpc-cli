# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Deployment cancellation is independent of the last approved running release.

A long source build cannot hold the node-operation lock. Its continuation must
match both the latest intent fence and the halt generation captured at request
creation. Only cutover blocks the currently approved runtime; stop revokes both.
"""
from pathlib import Path
import re
import secrets
from native_files import Refused, atomic, encoded, json_value, read, require, sync_directory, sync_file


def token(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value), 'invalid operation identity')
    return value


class State:
    def __init__(self, directory):
        self.directory = directory

    def get(self, name):
        return json_value(read(self.directory / name, 1048576))

    def put(self, name, value):
        atomic(self.directory / name, encoded(value))

    def remove(self, name):
        (self.directory / name).unlink(missing_ok=True)
        sync_directory(self.directory)

    def reserve(self, contract):
        """Caller validates an otherwise clean dedicated host before this write."""
        path = self.directory / 'owner.json'
        if not path.exists():
            require(not any(self.directory.iterdir()), 'unowned native lifecycle state exists')
            self.put('owner.json', {'contract': contract, 'initial_halt': secrets.token_hex(16), 'initialized': False})
        owner = self.get('owner.json')
        require(set(owner) == {'contract', 'initial_halt', 'initialized'}
                and type(owner['initialized']) is bool and owner['contract'] == contract,
                'immutable host contract differs')
        if not owner['initialized']:
            # Nothing may install keys, build or run before reserve completes.
            require(all(path.name in ('owner.json', 'halt.json', 'intent-fence.json')
                        or re.fullmatch(r'\.erpc-[a-f0-9]{32}', path.name)
                        for path in self.directory.iterdir()), 'incomplete initialization has unexpected state')
            halt = {'generation': token(owner['initial_halt']), 'retired': False}
            fence = {'intent': None, 'halt': halt['generation']}
            for name, expected in [('halt.json', halt), ('intent-fence.json', fence)]:
                if (self.directory / name).exists():
                    require(self.get(name) == expected, 'interrupted initialization differs')
                else:
                    self.put(name, expected)
            self.put('owner.json', dict(owner, initialized=True))
        self.owner(contract)
        self.halt()
        self.get('intent-fence.json')

    def owner(self, contract):
        value = self.get('owner.json')
        require(value['contract'] == contract and value['initialized'] is True,
                'host ownership differs or initialization is incomplete')
        return value

    def halt(self):
        value = self.get('halt.json')
        require(set(value) == {'generation', 'retired'} and type(value['retired']) is bool,
                'invalid halt generation')
        token(value['generation'])
        return value

