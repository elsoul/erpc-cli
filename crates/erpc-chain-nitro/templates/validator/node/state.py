# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Immutable original validator ownership and independent cancellation authority."""
import scope
import re
import secrets
from storage import decode, directory, encode, read, require, synchronize, write

OWNER_PHASE = scope.OWNER_PHASE
LEGACY_OWNER_PHASE = scope.LEGACY_OWNER_PHASE

FIELDS = {'owner', 'family', 'network', 'platform', 'role', 'wallet', 'creation', 'host_binding', 'data_uuid'}


def contract(value):
    require(isinstance(value, dict) and set(value) == FIELDS, 'invalid BoLD ownership fields')
    require(value['family'] == scope.FAMILY and value['network'] == scope.NETWORK
            and value['role'] == scope.ROLE and value['platform'] == 'amd64',
            'only the sealed original validator profile is supported')
    for name, expression in [('owner', '[a-z0-9]{26}'), ('wallet', '0x[0-9a-f]{40}'),
                             ('creation', '[0-9a-f]{32}'), ('host_binding', '[0-9a-f]{64}')]:
        require(isinstance(value[name], str) and re.fullmatch(expression, value[name]), 'invalid original BoLD ownership')
    require(int(value['wallet'][2:], 16) != 0, 'original BoLD wallet is missing')
    require(isinstance(value['data_uuid'], str)
            and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['data_uuid'])
            and any(c not in '0-' for c in value['data_uuid']), 'invalid original validator data filesystem')
    return value


def token(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value), 'invalid validator operation identity')
    return value


class State:
    def __init__(self, root, cancellation=None):
        self.root, self.cancellation = root, cancellation

    def cancel_current(self, expected):
        if self.cancellation is None: return
        directory(self.cancellation.parent, create=True, mode=0o755)
        write(self.cancellation, encode({'contract': expected, 'generation': self.fence()['generation']}))

    def require_not_cancelled(self, expected, generation):
        if self.cancellation is None: return
        if self.cancellation.exists() or self.cancellation.is_symlink():
            value = decode(read(self.cancellation, mode=0o600))
            require(isinstance(value, dict) and set(value) == {'contract', 'generation'}
                    and value['contract'] == expected, 'same-boot cancellation belongs to another owner')
            token(value['generation'])
            require(value['generation'] != generation,
                    'this validator operation was cancelled; publish a durable new preparation')

    def get(self, name): return decode(read(self.root / name, mode=0o600))

    def put(self, name, value): write(self.root / name, encode(value))

    def owner(self, expected):
        contract(expected)
        saved = self.get('owner.json')
        require(isinstance(saved, dict) and set(saved) == {'phase', 'contract'} and
                isinstance(saved['phase'],str) and (saved['phase']==OWNER_PHASE or (isinstance(LEGACY_OWNER_PHASE,str) and saved['phase']==LEGACY_OWNER_PHASE))
                and saved['contract'] == expected,
                'original validator inventory, host, wallet or role differs')
        return saved

    def current_owner(self, expected):
        require(self.owner(expected)['phase'] == OWNER_PHASE,
                'legacy validator requires explicit stopped volume authority upgrade')

    def reserve(self, expected, initial_layout=None):
        contract(expected); directory(self.root)
        path = self.root / 'owner.json'
        if path.exists() or path.is_symlink():
            self.current_owner(expected); synchronize(path)
        else:
            if initial_layout is None:
                require(not any(self.root.iterdir()), 'unowned Nitro state cannot be adopted')
            else: initial_layout()
            self.put('owner.json', {'phase': OWNER_PHASE, 'contract': expected})
        # A missing initial fence is recoverable ONLY before any deployment,
        # custody or account intent was published. Never infer an active phase.
        fence = self.root / 'fence.json'
        if not fence.exists():
            if initial_layout is None:
                require({p.name for p in self.root.iterdir()} == {'owner.json'},
                        'missing validator cancellation authority requires recovery')
            else: initial_layout()
            self.put('fence.json', {'generation': secrets.token_hex(16), 'intent': None, 'stopped': True, 'retired': False})
        self.fence(); synchronize(fence)
        return self.owner(expected)

    def fence(self):
        value = self.get('fence.json')
        require(isinstance(value, dict) and set(value) == {'generation', 'intent', 'stopped', 'retired'}
                and type(value['stopped']) is bool and type(value['retired']) is bool,
                'invalid validator cancellation authority')
        token(value['generation'])
        if value['intent'] is not None: token(value['intent'])
        return value

    def prepare(self, expected, intent, target, shutdown):
        self.current_owner(expected); token(intent)
        require(isinstance(target, dict) and target, 'missing exact validator deployment target')
        fence = {'generation': secrets.token_hex(16), 'intent': intent, 'stopped': True, 'retired': False}
        try:
            self.cancel_current(expected)
            self.put('fence.json', fence)
            self.put('pending.json', {'fence': fence, 'target': target})
        except Exception:
            try: shutdown()
            except Exception: raise ValueError('validator preparation persistence and owned shutdown both failed') from None
            raise
        shutdown()
        return fence

    def pending(self, expected, intent):
        self.current_owner(expected); fence = self.fence()
        self.require_not_cancelled(expected, fence['generation'])
        require(fence['intent'] == token(intent) and fence['stopped'] and not fence['retired'],
                'validator preparation was cancelled or superseded')
        saved = self.get('pending.json')
        require(set(saved) == {'fence', 'target'} and saved['fence'] == fence,
                'validator pending deployment differs from current authority')
        return saved

    def completed(self, expected, intent):
        self.owner(expected); token(intent)
        target = self.guard(expected)
        pending = self.get('pending.json')
        require(pending['fence']['intent'] == intent and pending['target'] == target
                and pending['fence']['generation'] == self.fence()['generation'],
                'completed deployment does not belong to this original caller')
        return target

    def activate(self, expected, intent, qualify):
        pending = self.pending(expected, intent)
        qualify(pending['target'])
        require(self.pending(expected, intent) == pending, 'validator authority changed during qualification')
        # The running receipt is durable before lifting the independently
        # authoritative stopped fence. A failed later write cannot authorize A.
        self.put('active.json', {'target': pending['target'], 'generation': pending['fence']['generation']})
        self.put('fence.json', dict(pending['fence'], intent=None, stopped=False))

    def guard(self, expected):
        self.current_owner(expected)
        fence = self.fence()
        self.require_not_cancelled(expected, fence['generation'])
        require(not fence['stopped'] and not fence['retired'] and fence['intent'] is None,
                'validator runtime is stopped, retired or under preparation')
        active = self.get('active.json')
        require(set(active) == {'target', 'generation'} and active['generation'] == fence['generation'],
                'validator runtime has no current durable approval')
        return active['target']

    def start(self, expected, qualify):
        self.current_owner(expected); fence = self.fence()
        self.require_not_cancelled(expected, fence['generation'])
        require(not fence['retired'] and fence['intent'] is None,
                'resume the pending deployment or explicitly redeploy a retired validator')
        active = self.get('active.json')
        require(set(active) == {'target', 'generation'}, 'validator has no original runtime to restart')
        qualify(active['target'])
        require(self.fence() == fence, 'validator authority changed during manual startup checks')
        if not fence['stopped']:
            return self.guard(expected)
        self.put('active.json', dict(active, generation=fence['generation']))
        self.put('fence.json', dict(fence, stopped=False))
        return self.guard(expected)

    def stop(self, expected, shutdown, retired=False):
        self.owner(expected)
        require(type(retired) is bool, 'invalid validator retirement request')
        value = {'generation': secrets.token_hex(16), 'intent': None, 'stopped': True, 'retired': retired}
        try:
            value['retired'] = retired or self.fence()['retired']
            self.cancel_current(expected)
            self.put('fence.json', value)
        except Exception:
            try: shutdown()
            except Exception: raise ValueError('validator cancellation persistence and owned shutdown both failed') from None
            raise
        shutdown()
        return value
