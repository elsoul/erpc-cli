#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execution-only private L1 transport using the reviewed shared transport policy."""
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time

# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS
if __name__=='__main__':
    trusted_imports(Path(__file__).absolute().parent)

# Heimdall helper/call.go, contract binding reads and ethclient.BlockByNumber.
# RPC nodes do not run the bridge broadcaster; its signing/gas/nonce APIs are
# deliberately absent, as are rollup-specific proof and blob methods.
METHODS=frozenset({'eth_chainId','eth_blockNumber','eth_getBlockByNumber',
    'eth_getTransactionReceipt','eth_getTransactionByHash','eth_getLogs',
    'eth_call','eth_getCode','eth_getBalance','eth_getUncleByBlockHashAndIndex'})


def transport(path):
    spec = importlib.util.spec_from_file_location('erpc_polygon_parent_transport', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Parent:
    def __init__(self, shared, config, network, bridge=None, authorize=None, require_public_tls=False, admit=None, financial_guard=None):
        if (network not in shared.L1 or not isinstance(config, dict) or set(config) != {'execution'}
                or type(require_public_tls) is not bool):
            shared.fail()
        self.bridge=None
        if bridge is not None:
            import checkpoint
            if (not isinstance(bridge,dict) or set(bridge)!={'network','signer'}
                    or bridge['network'] not in ('mainnet','amoy')
                    or network!=('mainnet' if bridge['network']=='mainnet' else 'sepolia')):
                shared.fail()
            self.bridge=dict(bridge,signer=checkpoint.address(bridge['signer']))
        self.shared, self.network = shared, network
        self.authorize,self.admit,self.financial_guard=authorize,admit,financial_guard
        self.execution = shared.Endpoint(config['execution'])
        if (self.bridge or require_public_tls) and (not self.execution.tls or self.execution.loopback):
            shared.fail()  # Financial upstreams require public TLS identity.
        if self.execution.loopback and self.execution.port==9545:
            shared.fail()  # Refuse recursive requests back into this local proxy.
        self.checked = None
        self.lock = threading.Lock()

    def verify(self):
        with self.lock:
            now = time.monotonic()
            if self.checked is not None and now - self.checked < self.shared.IDENTITY_TTL:
                return
            expected = self.shared.L1[self.network]
            def rpc(method, params):
                query = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
                answer = self.shared.rpc_response(query, self.execution.request('POST', body=json.dumps(query).encode()))
                if 'result' not in answer:
                    self.shared.fail()
                return answer['result']
            if rpc('eth_chainId', []) != expected['chain']:
                self.shared.fail()
            genesis = rpc('eth_getBlockByNumber', ['0x0', False])
            if not isinstance(genesis, dict) or genesis.get('hash') != expected['block']:
                self.shared.fail()
            self.checked = now

    def execution_request(self, body):
        extra=frozenset({'eth_maxPriorityFeePerGas','eth_getTransactionCount','eth_estimateGas','eth_sendRawTransaction'}) if self.bridge else frozenset()
        request = self.shared.rpc_request(body, METHODS|extra)
        if isinstance(request,list) and any(call['method'] in ('eth_estimateGas','eth_sendRawTransaction') for call in request):
            self.shared.fail()  # Never partially execute a financial batch.
        for call in request if isinstance(request,list) else [request]:
            if call['method'] in extra:
                import checkpoint
                try:checkpoint.allow(call,self.bridge['network'],self.bridge['signer'])
                except (ValueError,TypeError,KeyError):self.shared.fail()
            elif call['method'] not in METHODS:self.shared.fail()
        financial=any(call['method'] in ('eth_estimateGas','eth_sendRawTransaction') for call in (request if isinstance(request,list) else [request]))
        def forward():
            if self.bridge:
                if not callable(self.authorize):self.shared.fail()
                self.authorize()
            self.verify()
            if financial:
                if not callable(self.admit):self.shared.fail()
                self.admit()
            if self.bridge:self.authorize()  # Identity probing cannot outlive revocation unnoticed.
            return self.shared.rpc_response(request, self.execution.request('POST', body=body))
        if financial:
            if not callable(self.financial_guard):self.shared.fail()
            with self.financial_guard():return forward()
        return forward()


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) != 2 or sys.argv[1] not in ('mainnet', 'sepolia'):
        raise ValueError('unsupported parent network')
    transport(Path(__file__).absolute().with_name('accounts.py')).runtime('parent',sys.argv[1],parent=True)
    shared = transport(Path(__file__).absolute().with_name('upstreams.py'))
    with Path('/run/credentials/polygon-l1-proxy.service/execution.json').open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        shared.fail()
    owner=shared.strict_json(Path('/etc/polygon/contract.json').read_bytes())
    bridge=None
    if owner.get('role')=='validator':
        import gateway
        import local_tls
        import native_authority
        from state import State,contract
        scope={key:value for key,value in owner.items() if key!='runtime_protocol'}
        expected=contract(**scope)
        host=State()
        published=host.read('/etc/polygon/validator-runtime.json')
        if (set(published)!={'contract','helpers','profile','phase'} or published['contract']!=expected
                or published['helpers']!=Path(__file__).absolute().parent.name
                or published['phase'] not in ('observing','active')):shared.fail()
        import re
        if re.fullmatch('[a-f0-9]{64}',published['profile']) is None:shared.fail()
        native_authority.fenced(host)
        def secret(name):
            with (Path('/run/credentials/polygon-l1-proxy.service')/name).open('rb') as stream:
                value=stream.read(65537)
            if len(value)>65536:shared.fail()
            return shared.strict_json(value)
        auth=secret('polygon-bor-auth');tls=secret('polygon-gateway-tls')
        if set(tls)!={'ca','certificate','key'}:shared.fail()
        context=local_tls.server_context({'ca':tls['ca'],'leaves':{'gateway':{'certificate':tls['certificate'],'key':tls['key']}}},'gateway')
        if published['phase']=='active':bridge={'network':expected['network'],'signer':expected['signer']}
        def authorize():
            native_authority.fenced(host)
            if host.read('/etc/polygon/validator-runtime.json')!=published:shared.fail()
            original=host.accounts.record(expected)
            if original is None or original['state']!='established':shared.fail()
            if any(None in pair for pair in host.accounts.observed(original).values()):shared.fail()
        authorize()
        def admitted():
            import admission
            import validator_activation
            authorize()
            query=validator_activation.parent_query(shared,shared.strict_json(raw),expected['network'])
            snapshot=admission.snapshot({'network':expected['network'],'parent':sys.argv[1]},expected['signer'],query,parent_only=True)
            admission.admitted(snapshot,expected)
            authorize()
        upstream=Parent(shared,shared.strict_json(raw),sys.argv[1],bridge,authorize,require_public_tls=True,admit=admitted,financial_guard=lambda:native_authority.financial_lock(host))
        upstream.verify()
        def prove(component):return lambda:native_authority.read(host,expected,component,published['helpers'],published['profile'])
        gateway.serve(shared,upstream,gateway.Bor(shared,prove('bor'),auth,expected),gateway.Heimdall(prove('heimdall')),context)
        return
    elif owner.get('role')!='fullnode':shared.fail()
    upstream = Parent(shared, shared.strict_json(raw), sys.argv[1],bridge)
    upstream.verify()
    server = shared.Server(('127.0.0.1', 9545), shared.Handler, upstream, 'execution')
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Polygon parent transport unavailable or rejected', file=sys.stderr)
        raise SystemExit(1)
