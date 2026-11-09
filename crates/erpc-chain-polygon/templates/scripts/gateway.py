# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Validator-only private TLS adapters with authenticated native Bor callers."""
import base64
import hashlib
import hmac
import json
import re
import threading
import native_peer

# Pinned Heimdall helper/call.go and its Bor ethclient dependency. In particular
# bor_getVoteOnHash updates native milestone locking state: it is NOT a public
# read-only API. Every Bor adapter request requires the original Heimdall secret.
BOR_METHODS=frozenset({'eth_chainId','eth_blockNumber','eth_syncing',
    'eth_getBlockByNumber','eth_getHeaderByNumber','eth_getTdByNumber','eth_getTdByHash',
    'eth_getTransactionReceipt','eth_getBorBlockReceipt','bor_getAuthor','bor_getRootHash','bor_getVoteOnHash'})
BOR_BATCH=frozenset({'eth_getHeaderByNumber','eth_getTdByNumber','bor_getAuthor'})
AUTH='/etc/credstore.encrypted/polygon/bor-auth'
AUTH_NAME='polygon-bor-auth'
USERNAME='heimdall'
ADDRESSES={'parent':('127.0.0.10',9545),'bor':('127.0.0.11',8545),'heimdall':('127.0.0.12',1317)}


def require(value,message):
    if not value:raise ValueError(message)


def credential(value,expected):
    require(isinstance(value,dict) and set(value)=={'format','contract','password'}
            and type(value['format']) is int and value['format']==1 and value['contract']==expected
            and expected['role']=='validator' and isinstance(value['password'],str)
            and re.fullmatch('[a-f0-9]{64}',value['password']) is not None,
            'native adapter credential belongs to another validator')
    return value['password']


def create_credential(expected):
    import secrets
    return {'format':1,'contract':expected,'password':secrets.token_hex(32)}


def prepare_auth(state,expected,intent,profile,helpers,create=create_credential,convert=None):
    """A fenced host creates/reuses one encrypted local protocol credential."""
    import local_tls
    import host
    from state import canonical,unique
    state.phase(expected,intent,profile,helpers);state.stopped();state.accounts.verify(expected)
    convert=convert or (lambda action,name,raw:local_tls.transform(state,action,name,raw))
    path=state.protected(AUTH,missing=True);pending=state.protected(AUTH+'.pending',missing=True)
    recorded='/etc/polygon/bor-auth.json'
    require(path.exists() or pending.exists() or not state.path(recorded).exists(),
            'original native adapter ciphertext is missing; explicit recovery required')
    require(not(path.exists() and pending.exists()),'conflicting native adapter staging requires recovery')
    if not path.exists():
        if not pending.exists():
            raw=create(expected);credential(raw,expected)
            local_tls.write_bytes(state,AUTH+'.pending',convert('encrypt',AUTH_NAME,canonical(raw)))
        candidate=pending.read_bytes()
        require(0<len(candidate)<=65536,'native adapter credential exceeds its bound')
        credential(json.loads(convert('decrypt',AUTH_NAME,candidate),object_pairs_hook=unique),expected)
        state.phase(expected,intent,profile,helpers);state.stopped()
        host.publish(pending,path,stop=state.root)
    cipher=path.read_bytes()
    require(0<len(cipher)<=65536,'native adapter credential exceeds its bound')
    value=json.loads(convert('decrypt',AUTH_NAME,cipher),object_pairs_hook=unique)
    credential(value,expected)
    receipt={'contract':expected,'cipher_sha256':hashlib.sha256(cipher).hexdigest()}
    if state.path(recorded).exists():require(state.read(recorded)==receipt,'original native adapter credential changed')
    state.phase(expected,intent,profile,helpers);state.stopped();state.write(recorded,receipt)
    return value


def bor_url(value,expected):
    # Only serialized inside the encrypted native --app override. Never an
    # argument, environment variable, public profile or diagnostic payload.
    password=credential(value,expected)
    return 'https://'+USERNAME+':'+password+'@127.0.0.11:8545'


class Bor:
    def __init__(self,shared,prove,auth,expected):
        password=credential(auth,expected)
        self.authorization='Basic '+base64.b64encode((USERNAME+':'+password).encode()).decode()
        self.shared,self.prove=shared,prove

    def authenticate(self,headers):
        values=headers.get_all('Authorization',[])
        require(len(values)==1 and isinstance(values[0],str) and len(values[0])<=256
                and hmac.compare_digest(values[0],self.authorization),'native caller authentication failed')

    def execution_request(self,body):
        request=self.shared.strict_json(body)
        if isinstance(request,list):
            # Native helper/call.go constructs at most three entries for each
            # of x/bor/grpc/client.go's 256 blocks. Keep the ordinary shared
            # transport's 100-entry policy unchanged; validate closed chunks
            # here and also reject IDs repeated across chunk boundaries.
            require(1<=len(request)<=3*256,'native Bor batch exceeds its protocol bound')
            seen=set()
            for offset in range(0,len(request),100):
                chunk=self.shared.rpc_request(json.dumps(request[offset:offset+100],separators=(',',':')).encode(),BOR_BATCH)
                for item in chunk:
                    identity=(type(item['id']),item['id'])
                    require(identity not in seen,'native Bor batch repeats an identifier');seen.add(identity)
        else:request=self.shared.rpc_request(body,BOR_METHODS)
        return native_peer.rpc('bor',self.prove,body,lambda raw:self.shared.rpc_response(request,self.shared.strict_json(raw)))


class Heimdall:
    def __init__(self,prove):self.prove=prove
    def request(self,path):return native_peer.rest(path,self.prove)


def types(shared):
    class Handler(shared.Handler):
        def do_POST(self):
            if self.server.endpoint=='bor':
                try:self.server.upstreams.authenticate(self.headers)
                except Exception:
                    self.send_error(403);return
            super().do_POST()

        def do_GET(self):
            try:
                if (self.server.endpoint!='heimdall' or self.headers.get('Transfer-Encoding') is not None
                        or self.headers.get_all('Content-Length',[]) not in ([],['0'])):
                    shared.fail()
                status,body=self.server.upstreams.request(self.path)
                self.reply(status,shared.strict_json(body))
            except Exception:self.send_error(502)

    class Server(shared.Server):
        def __init__(self,endpoint,upstream,context):
            require(endpoint in ADDRESSES,'unsupported validator TLS endpoint')
            self.endpoint,self.context=endpoint,context
            super().__init__(ADDRESSES[endpoint],Handler,upstream,'execution' if endpoint!='heimdall' else 'heimdall')

        def work(self,request,client_address):
            stream=request
            try:
                # TLS handshakes run inside the existing eight-worker bound,
                # with an absolute socket timeout, never in the accept loop.
                request.settimeout(shared.TIMEOUT)
                stream=self.context.wrap_socket(request,server_side=True)
                stream.settimeout(shared.TIMEOUT)
                self.finish_request(stream,client_address)
            except Exception:pass  # No credential-bearing URI or native error.
            finally:
                self.shutdown_request(stream);self.slots.release()
    return Server,Handler


def serve(shared,parent,bor,heimdall,context):
    Server,_=types(shared);servers=[];threads=[]
    try:
        for endpoint,upstream in [('parent',parent),('bor',bor),('heimdall',heimdall)]:
            servers.append(Server(endpoint,upstream,context))
        for server in servers[:-1]:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
        servers[-1].serve_forever()
    finally:
        # shutdown waits on serve_forever, so never call it for a server whose
        # thread was not started (including a failed second/third bind).
        for server in servers[:len(threads)]:server.shutdown()
        for server in servers:server.server_close()
        for thread in threads:thread.join()
