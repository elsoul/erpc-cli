# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Arbitrum validator controller; private requests are stdin-only."""
import http.client
import json
import os
import resource
from pathlib import Path
import sys
import time
import scope
import accounts
import admission
import authority
import container
import credentials
import custody
import wallet_stage
import provider_stage
import history
import host
import locking
import observer
import processes
import protocol
import publication
import parent_tls
import registration
import runtime
import services
import storage
import upstreams
import volumes
from state import State
from storage import decode, directory, encode, read, require

SOURCE = Path(__file__).absolute().parent


def local_rpc(port, method, params):
    require(port in (8547, 18545) and method in (upstreams.METHODS | {'arb_latestValidated', 'web3_clientVersion', 'eth_syncing'}),
            'unsupported read-only original runtime observation')
    request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    if port == 18545:
        ca = read(host.CONFIG/'public/parent-ca.pem', 16384).decode('ascii')
        connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=15, context=parent_tls.client_context(ca))
    else: connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        connection.request('POST', '/', body=encode(request), headers={'Content-Type': 'application/json'})
        response = connection.getresponse(); raw = response.read(4*1024*1024+1)
        require(response.status == 200 and len(raw) <= 4*1024*1024, 'original runtime RPC observation failed')
        result = upstreams.rpc_response(request, decode(raw))
        require('result' in result, 'original runtime RPC result is unavailable')
        return result['result']
    finally: connection.close()


class Control:
    def __init__(self, expected, run=host.command):
        self.expected = protocol.contract(expected); self.state = State(host.ROOT, host.RUNTIME/'cancelled-state.json'); self.run = run

    def owner(self): return self.state.owner(self.expected)

    def retained(self): return accounts.retained(self.state, self.expected)

    def quiet(self): processes.quiescent(self.retained())

    def shutdown(self, retain_history=True):
        self.owner(); records = self.retained(); failures = []
        directory(host.RUNTIME, create=True, mode=0o755)
        # Cancellation becomes visible before waiting for a racing startup. The
        # startup lock then guarantees drain includes every admitted new PID.
        try: authority.revoke(records['transport']['gid'])
        except Exception: failures.append('send authority')
        with locking.locked(host.RUNTIME/'startup.lock'):
            try: services.shutdown(self.state, self.expected, records, self.run)
            except Exception: failures.append('owned shutdown')
        require(not failures, 'validator cancellation or original shutdown was not completely verified')
        custody.clear_runtime(records)
        if retain_history and (self.state.root/'signer-activated.json').exists():
            history.retain(self.state, self.expected, records['node'], self.quiet)
        return {'stopped': True, 'data_retained': True, 'identity_retained': True}

    def stop(self, retired=False):
        value = self.state.stop(self.expected, self.shutdown, retired)
        return {'stopped': True, 'retired': value['retired'], 'data_retained': True, 'identity_retained': True}

    def upgrade_volume_authority(self, original_root):
        self.owner()
        records=self.retained()
        # Stop original writers before reading or promoting historical volume
        # authority. Old device-number history cannot itself be the drain gate.
        self.state.stop(self.expected,lambda:self.shutdown(retain_history=False))
        records=accounts.verify(self.state,self.expected)
        self.quiet()
        return volumes.upgrade(self.state,self.expected,records,original_root,self.quiet,self.run)

    def parent_observation(self):
        self.owner()
        config = credentials.inspect(self.state, self.expected)
        return self.provider_observation(config)

    def provider_observation(self,config):
        self.owner()
        transport = credentials.client(config)
        def rpc(method, params):
            require(method in upstreams.METHODS, 'admission observation cannot submit a transaction')
            request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
            result = upstreams.rpc_response(request, transport.execution.request('POST', body=encode(request)))
            require('result' in result, 'finalized admission observation unavailable')
            return result['result']
        return admission.observe(rpc, self.expected['wallet'])

    def observe(self):
        self.owner(); target = self.state.guard(self.expected)
        records = accounts.verify(self.state, self.expected)
        volumes.verify(self.state,self.expected,self.run)
        tls,_ = parent_tls.sealed(self.state, self.expected)
        publication.verify(self.state, self.expected, target); runtime.common(self.state, self.expected, 'guard')
        services.transport(self.state, self.expected, records, self.run)
        services.running(self.state, self.expected, 'node', self.run)
        native = self.state.get('container.json')
        require(native['contract'] == self.expected and native['generation'] == self.state.fence()['generation']
                and native['target'] == target and native['account'] == records['node'], 'native runtime receipt differs')
        protocol_observation = admission.observe(lambda method, params: local_rpc(18545, method, params), self.expected['wallet'])
        value = observer.inspect(lambda method, params: local_rpc(8547, method, params),
                                 lambda: container.prove(native, self.run), target['phase'], protocol_observation)
        return dict(value, protocol=protocol_observation, parent_tls_expires_at=tls['not_after'],
                    parent_tls_renewal_due=tls['not_after']-time.time()<=parent_tls.RENEW_BEFORE)

    def status(self):
        self.owner(); fence = self.state.fence()
        value = {'contract': self.expected, 'stopped': fence['stopped'], 'retired': fence['retired'],
                 'pending_intent': fence['intent'], 'ready': False, 'validator_ready': False,
                 'local_validation_ready': False, 'problems': []}
        try:
            tls,_=parent_tls.sealed(self.state,self.expected,allow_expired=True)
            value.update(parent_tls_expires_at=tls['not_after'],parent_tls_renewal_due=tls['not_after']-time.time()<=parent_tls.RENEW_BEFORE)
        except Exception: value['parent_tls_identity_verified']=False
        try:
            value.update(self.observe()); value['ready'] = value['validator_ready']
            if value['phase'] == 'observing': value['problems'].append('Watchtower is observing; active validator operation has not been accepted')
            elif not value['ready']: value['problems'].append('active staking, funding reserve or native assertion progress is not established')
        except Exception:
            value['problems'].append('original services, account, process/listener, firewall or fresh native validation could not be established')
        return value

    def prepare(self, intent, target):
        self.owner(); host.namespaces(); accounts.verify(self.state, self.expected)
        digest, _ = publication.profile(SOURCE); protocol.target(target, digest)
        previous = self.state.get('active.json')['target'] if (self.state.root/'active.json').exists() else None
        activated = (self.state.root/'signer-activated.json').exists()
        protocol.transition(previous, target, activated)
        host.capacity(self.state, self.expected, self.run)
        container.image(target, self.run)
        observation = None
        if target['phase'] == 'active':
            admission_state = self.parent_observation()
            require(admission_state['funding_checks_passed'] is True, 'external wallet funding and allowances are not yet sufficient')
            custody.inspect(self.state, self.expected)
            if not activated:
                require(admission_state.get('is_staked') is False,
                        'an already-staked wallet requires explicit original-history migration; fresh activation cannot adopt it')
                observation = self.observe()
                require(observation['phase'] == 'observing' and observation['local_validation_ready'] is True,
                        'first active transition requires the original healthy native observer')
        fence = self.state.prepare(self.expected, intent, target, self.shutdown)
        if observation is not None:
            records = self.retained()
            history.activate(self.state, self.expected, records['node'], custody.origin(self.state, self.expected),
                             self.quiet, observation)
        return {'prepared': True, 'intent': intent, 'generation': fence['generation'], 'phase': target['phase']}

    def qualify(self, target):
        protocol.target(target); self.owner(); self.quiet(); host.namespaces()
        records = accounts.verify(self.state, self.expected); host.capacity(self.state, self.expected, self.run)
        publication.verify(self.state, self.expected, target)
        from installer import verify_config
        verify_config(self.state, self.expected, target)
        for role in ('node', 'transport'):
            require(services.loaded(self.state, self.expected, role, self.run) is not None, 'original runtime unit is missing')
        credentials.inspect(self.state, self.expected)
        if target['phase'] == 'active':
            custody.inspect(self.state, self.expected)
            history.verify(self.state, self.expected, records['node'], self.quiet)
            require(self.parent_observation()['funding_checks_passed'] is True,
                    'active external wallet funding and allowance reserve is not established')
        container.image(target, self.run)
        runtime.common(self.state, self.expected, 'guard')
        return records

    def start_units(self):
        for role in ('transport', 'node'):
            self.run(['/usr/bin/systemctl', 'enable', services.NAMES[role]])
            self.run(['/usr/bin/systemctl', 'start', services.NAMES[role]], timeout=180)
            deadline = time.monotonic()+60
            while True:
                try:
                    services.running(self.state, self.expected, role, self.run)
                    if role == 'transport': services.transport(self.state, self.expected, self.retained(), self.run)
                    else: container.prove(self.state.get('container.json'), self.run, listeners=False)
                    break
                except Exception:
                    require(time.monotonic() < deadline, 'credential condition or original runtime startup did not complete')
                    time.sleep(0.2)
        return dict(self.status(), applied=True)

    def start(self, restart=False):
        self.owner()
        # A manual start is an explicit durable new cancellation generation;
        # it cannot lift a failed stop's same-boot revocation using an old token.
        require(self.state.fence()['intent'] is None, 'pending deployment must be explicitly resumed')
        require(not self.state.fence()['retired'], 'retired validator requires explicit deployment')
        if not restart and not self.state.fence()['stopped']:
            try:
                self.state.guard(self.expected); records = accounts.verify(self.state, self.expected)
                services.transport(self.state, self.expected, records, self.run)
                services.running(self.state, self.expected, 'node', self.run)
                container.prove(self.state.get('container.json'), self.run, listeners=False)
            except Exception: pass
            else: return dict(self.status(), applied=True, already_running=True)
        self.state.stop(self.expected, self.shutdown)
        self.state.start(self.expected, self.qualify)
        try: return self.start_units()
        except Exception:
            self.state.stop(self.expected, self.shutdown)
            raise

    def identity(self):
        self.owner(); original, _ = custody.sealed(self.state, self.expected)
        return {'wallet': original['wallet'], 'original_identity': True, 'host_encrypted': True,
                'signer_ever_activated': (self.state.root/'signer-activated.json').exists()}

    def registration(self):
        value = self.parent_observation()
        return {'contract': self.expected, 'protocol': value, 'external_preparation': registration.prepare(value), 'financial_action_performed': False,
                'automatic_deposit': False, 'automatic_allowance_increase': False,
                'external_actions': ('Fund this original dedicated wallet and set exact WETH allowance to the observed rollup using an external signing tool; no owner key is imported.' if scope.STRATEGY=='Defensive' else 'Fund this original dedicated wallet and set exact WETH allowances to the observed rollup and challenge manager using an external signing tool; no owner key is imported.'),
                'activation_authorized': False, 'ready_for_activation_checks': value['funding_checks_passed']}


def dispatch(request):
    protocol.request(request); action = request['action']
    if action == 'preflight':
        host.namespaces()
        if 'contract' in request:
            expected = request['contract']; state = State(host.ROOT, host.RUNTIME/'cancelled-state.json'); state.owner(expected)
            return dict(host.platform_facts(), data_uuid=expected['data_uuid'], **host.capacity(state, expected))
        # Fresh storage qualification owns the closed ROOT/DATA/lost+found
        # layout policy; an outer emptiness test would reject prepared volumes.
        accounts.plan()  # Read-only unknown-account and numeric namespace check.
        host.fresh()
        return host.preflight()
    expected = request['contract']
    if action == 'init': return host.initialize(expected, processes.quiescent)
    control = Control(expected); control.owner()
    if action == 'prepare': return control.prepare(request['intent'], request['target'])
    if action == 'provider-stage-authorize': return provider_stage.authorize(control,request['intent'])
    if action == 'provider-stage-import':
        return provider_stage.install(control,request['intent'],request['secret'].encode('utf-8'))
    if action == 'wallet-stage-authorize': return wallet_stage.authorize(control,request['intent'],request['restore'])
    if action == 'wallet-stage-import':
        return wallet_stage.install(control,request['intent'],request['restore'],request['secret'].encode('ascii'))
    if action == 'import-wallet':
        return custody.import_original(control.state, expected, request['intent'], request['secret'].encode('ascii'),
                                       control.quiet, request['restore'])
    if action == 'import-upstreams':
        return credentials.install(control.state, expected, request['intent'], request['secret'].encode('utf-8'), control.quiet)
    if action == 'upgrade-volume-authority': return control.upgrade_volume_authority(request['original_root'])
    if action == 'metadata':
        return {'contract': expected, 'fence': control.state.fence(),
                'target': control.state.get('active.json')['target'] if (host.ROOT/'active.json').exists() else None}
    if action == 'status': return control.status()
    if action in ('start', 'restart'): return control.start(restart=action == 'restart')
    if action == 'stop': return control.stop()
    if action == 'destroy':
        value = control.stop(retired=True)
        if (host.ROOT/'common-firewall.json').exists(): runtime.common(control.state, expected, 'teardown')
        return value
    if action == 'identity': return control.identity()
    if action.startswith('registration-'): return control.registration()
    if action == 'firewall-confirm':
        control.state.pending(expected, request['intent'])
        runtime.common(control.state, expected, 'confirm', request['operation'], request['bundle'])
        control.state.pending(expected, request['intent'])
        return {'firewall_confirmed': True, 'operation': request['operation'], 'bundle': request['bundle']}
    raise ValueError('unknown original validator operation')


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(os.geteuid() == storage.ROOT_UID, 'validator control requires root authority')
    args = sys.argv[1:]
    if args and args[0] in ('runtime-condition', 'runtime-prepare', 'runtime-run', 'runtime-stop', 'runtime-ready'):
        require(len(args) == 2 and args[1] in ('node', 'transport'), 'invalid runtime entrypoint')
        action, role = args
        if action == 'runtime-condition': runtime.condition(role); return
        if action == 'runtime-prepare': runtime.prepare(role); return
        if action == 'runtime-stop': runtime.stop_component(role); return
        if action == 'runtime-ready': runtime.ready(role); return
        raise SystemExit(runtime.node() if role == 'node' else runtime.parent())
    if args == ['firewall-load']:
        state, expected = runtime.original()
        directory(host.RUNTIME, create=True, mode=0o755)
        # No outer /opt/erpc lock: the common loader owns its one boot lock.
        runtime.common(state, expected, 'load'); return
    raw = sys.stdin.buffer.read(262145)
    require(0 < len(raw) <= 262144, 'validator request exceeds its bound')
    request = decode(raw); protocol.request(request)
    if args:
        import installer
        with locking.locked(locking.CONTROL): result = installer.play(args, request, SOURCE)
    elif request['action'] in ('preflight', 'status', 'metadata', 'identity', 'registration-prepare',
                               'registration-validate', 'registration-status', 'firewall-confirm'):
        result = dispatch(request)
    else:
        with locking.locked(locking.CONTROL): result = dispatch(request)
    print(encode(result).decode())


if __name__ == '__main__':
    try: main()
    except Exception:
        # Never print raw request, provider/CLI exception or concealed stdout.
        print('Original qualified validator operation refused; inspect public ownership and runtime status.', file=sys.stderr)
        raise SystemExit(255 if sys.argv[1:2] == ['runtime-condition'] else 1) from None
