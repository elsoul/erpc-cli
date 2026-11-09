# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Distinct private TLS server authorities for the funded validator dependencies.

Generation is called only by fenced deployment on an owned host. Qualification
uses inert builders and existing public test certificates, never new operational
keys/certificates. The CA private key is never retained or delivered to a client.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import time

SERVERS = {'gateway': ('127.0.0.10','127.0.0.11','127.0.0.12'),
           'comet': ('127.0.0.13',), 'broker': ('127.0.0.14',)}
RENEW_BEFORE = 30*24*3600


def require(value, message):
    if not value: raise ValueError(message)


def generate(expected):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ERPC Polygon '+expected['owner'])])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=366))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
          .sign(ca_key,hashes.SHA256()))
    leaves = {}
    for role, addresses in SERVERS.items():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ERPC Polygon '+role)])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
            .not_valid_after(now+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip)) for ip in addresses]),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
            .sign(ca_key,hashes.SHA256()))
        leaves[role] = {'certificate': certificate.public_bytes(serialization.Encoding.PEM).decode(),
                        'key': key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()).decode()}
    return {'contract':expected,'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),'leaves':leaves}


def dates(cert):
    if hasattr(cert,'not_valid_after_utc'): return cert.not_valid_before_utc.timestamp(),cert.not_valid_after_utc.timestamp()
    return cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp(),cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp()


def verify_signature(certificate, issuer):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    public = issuer.public_key()
    require(isinstance(certificate.signature_hash_algorithm,hashes.SHA256)
            and isinstance(public,ec.EllipticCurvePublicKey) and isinstance(public.curve,ec.SECP256R1),
            'local TLS authority uses an unqualified signature')
    public.verify(certificate.signature,certificate.tbs_certificate_bytes,ec.ECDSA(certificate.signature_hash_algorithm))


def validate(value, expected, allow_expired=False, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    require(isinstance(value,dict) and set(value)=={'contract','ca','leaves'} and value['contract']==expected
            and expected.get('role')=='validator' and isinstance(value['ca'],str) and 0<len(value['ca'])<16384
            and isinstance(value['leaves'],dict) and set(value['leaves'])==set(SERVERS),
            'local TLS bundle belongs to another validator authority')
    ca=x509.load_pem_x509_certificate(value['ca'].encode())
    issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ERPC Polygon '+expected['owner'])])
    require(ca.subject==issuer and ca.issuer==issuer
            and ca.extensions.get_extension_for_class(x509.BasicConstraints).value==x509.BasicConstraints(ca=True,path_length=0)
            and ca.extensions.get_extension_for_class(x509.BasicConstraints).critical
            and ca.extensions.get_extension_for_class(x509.KeyUsage).critical
            and ca.extensions.get_extension_for_class(x509.KeyUsage).value==x509.KeyUsage(False,False,False,False,False,True,True,False,False),
            'local TLS issuer does not match its original ownership')
    verify_signature(ca,ca)
    issuer_key_id=x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
    require(ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest==issuer_key_id
            and ca.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier==issuer_key_id,
            'local TLS issuer key identifiers differ')
    now=time.time() if now is None else now
    ca_before,ca_after=dates(ca)
    require(ca_before<=now and (allow_expired or now<ca_after), 'local TLS issuer is not currently valid')
    result={'public_ca':value['ca'],'ca_sha256':hashlib.sha256(value['ca'].encode()).hexdigest(),'certificates':{}}
    public_keys=set();end=[]
    for role, addresses in SERVERS.items():
        leaf=value['leaves'][role]
        require(isinstance(leaf,dict) and set(leaf)=={'certificate','key'}
                and all(isinstance(v,str) and 0<len(v)<16384 for v in leaf.values()), 'invalid local TLS leaf encoding')
        cert=x509.load_pem_x509_certificate(leaf['certificate'].encode())
        key=serialization.load_pem_private_key(leaf['key'].encode(),password=None)
        require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1)
                and isinstance(cert.public_key(),ec.EllipticCurvePublicKey)
                and key.public_key().public_numbers()==cert.public_key().public_numbers(), 'local TLS private key differs')
        public=cert.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        require(public not in public_keys, 'independent native TLS authorities cannot reuse a private key')
        public_keys.add(public)
        require(cert.issuer==ca.subject and cert.subject==x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ERPC Polygon '+role)])
                and cert.extensions.get_extension_for_class(x509.BasicConstraints).value==x509.BasicConstraints(ca=False,path_length=None)
                and cert.extensions.get_extension_for_class(x509.BasicConstraints).critical
                and cert.extensions.get_extension_for_class(x509.KeyUsage).critical
                and list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
                    ==[x509.IPAddress(ipaddress.ip_address(ip)) for ip in addresses]
                and list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[ExtendedKeyUsageOID.SERVER_AUTH]
                and cert.extensions.get_extension_for_class(x509.KeyUsage).value==x509.KeyUsage(True,False,False,False,False,False,False,False,False),
                'native TLS leaf can impersonate another authority')
        require(cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                    ==x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
                and cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier==issuer_key_id,
                'native TLS leaf key identifiers differ from its original issuer')
        verify_signature(cert,ca)
        before,after=dates(cert)
        require(before<=now and ca_before<=before and after<=ca_after and (allow_expired or now<after),
                'native TLS leaf is not currently valid; prepare a same-owner renewal')
        result['certificates'][role]={'certificate':leaf['certificate'],
            'sha256':hashlib.sha256(leaf['certificate'].encode()).hexdigest()}
        end.append(int(after))
    result['not_after']=min(end)
    return result


DIRECTORY='/etc/credstore.encrypted/polygon/local-tls'
RECORD='/etc/polygon/local-tls.json'
PENDING='/etc/polygon/local-tls-pending.json'
BUNDLE_NAME='polygon-local-tls'


def transform(state, action, name, raw):
    import subprocess
    require(action in ('encrypt','decrypt') and name in (BUNDLE_NAME,'polygon-gateway-tls','comet-certificate','comet-private-key','polygon-broker-tls','polygon-bor-auth','polygon-broker-original','native-app.toml','heimdall-observer-key.json','heimdall-validator-key.json','bor-signer.json','execution.json')
            and isinstance(raw,bytes) and 0<len(raw)<=131072,
            'invalid local TLS credential operation')
    arguments=['/usr/bin/systemd-creds',action,'--name='+name]
    if action=='encrypt':arguments.append('--with-key=host')
    result=state.run([*arguments,'-','-'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=30,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and 0<len(result.stdout)<=131072,'local TLS credential operation failed')
    return result.stdout


def write_bytes(state, name, raw, mode=0o600):
    import os
    import host
    destination=state.protected(name,missing=True)
    pending=state.protected(name+'.pending',missing=True)
    if pending.exists():host.unlink(pending,state.root)
    descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        with os.fdopen(descriptor,'wb') as output:
            output.write(raw);output.flush();os.fchmod(output.fileno(),mode);os.fsync(output.fileno())
        host.publish(pending,destination,stop=state.root)
    finally:
        if pending.exists():host.unlink(pending,state.root)


def load(state, expected, allow_expired=False, convert=None, validator=validate):
    import json
    import re
    from state import unique
    state.ownership(expected)
    saved=state.read(RECORD)
    fields={'contract','source_intent','cipher_sha256','ca_sha256','public_ca','certificates','not_after'}
    require(isinstance(saved,dict) and set(saved)==fields and saved['contract']==expected
            and isinstance(saved['source_intent'],str) and re.fullmatch('[a-f0-9]{32}',saved['source_intent']),
            'local TLS identity belongs to another original validator')
    cipher=state.protected(DIRECTORY+'/'+saved['source_intent']+'/bundle').read_bytes()
    require(0<len(cipher)<=131072 and hashlib.sha256(cipher).hexdigest()==saved['cipher_sha256'],
            'original local TLS ciphertext differs')
    convert=convert or (lambda action,name,raw:transform(state,action,name,raw))
    value=json.loads(convert('decrypt',BUNDLE_NAME,cipher),object_pairs_hook=unique)
    public=validator(value,expected,allow_expired=allow_expired)
    require(all(saved.get(name)==item for name,item in public.items()),'original local TLS public binding differs')
    return value,saved


def ensure(state, expected, intent, profile, helpers, create=generate, convert=None, validator=validate):
    import json
    import re
    import host
    from state import canonical,unique
    require(expected.get('role')=='validator','RPC ownership cannot issue validator TLS authority')
    state.phase(expected,intent,profile,helpers);state.namespaces();state.accounts.verify(expected);state.stopped()
    require(state.path('/etc/polygon/preparing').exists(),'local TLS renewal requires a stopped preparation')
    convert=convert or (lambda action,name,raw:transform(state,action,name,raw))
    saved=state.read(RECORD) if state.path(RECORD).exists() else None
    if saved is not None:
        _value,saved=load(state,expected,allow_expired=True,convert=convert,validator=validator)
        if saved['not_after']>time.time()+RENEW_BEFORE:return saved
    pending=state.read(PENDING) if state.path(PENDING).exists() else None
    if saved is None and pending is None:
        existing=state.protected(DIRECTORY,missing=True)
        require(not existing.exists() or not any(existing.iterdir()),'orphan TLS material requires original recovery')
    # A completed prior renewal is not an unfinished creation. A later renewal
    # gets a new durable source intent; interrupted creations keep their original.
    if pending is not None and saved is not None and pending.get('source_intent')==saved['source_intent']:
        pending=None
    if pending is None:
        pending={'contract':expected,'source_intent':intent}
        state.write(PENDING,pending)
    require(set(pending)=={'contract','source_intent'} and pending['contract']==expected
            and isinstance(pending['source_intent'],str) and re.fullmatch('[a-f0-9]{32}',pending['source_intent']),
            'pending local TLS authority differs')
    directory=state.protected(DIRECTORY,missing=True)
    directory.mkdir(mode=0o700,exist_ok=True);host.sync_parents(directory,state.root)
    stage=state.protected(DIRECTORY+'/'+pending['source_intent'],missing=True)
    stage.mkdir(mode=0o700,exist_ok=True);host.sync_parents(stage,state.root)
    require({path.name for path in stage.iterdir()}<={'bundle','bundle.pending'},'unknown TLS staging material cannot be adopted')
    path=DIRECTORY+'/'+pending['source_intent']+'/bundle'
    if not state.path(path).exists():
        value=create(expected);validator(value,expected)
        cipher=convert('encrypt',BUNDLE_NAME,canonical(value))
        write_bytes(state,path,cipher)
    cipher=state.protected(path).read_bytes()
    require(0<len(cipher)<=131072,'local TLS ciphertext exceeds its bound')
    value=json.loads(convert('decrypt',BUNDLE_NAME,cipher),object_pairs_hook=unique)
    public=validator(value,expected)
    state.phase(expected,intent,profile,helpers);state.stopped()
    saved=dict(public,contract=expected,source_intent=pending['source_intent'],cipher_sha256=hashlib.sha256(cipher).hexdigest())
    state.write(RECORD,saved)
    load(state,expected,convert=convert,validator=validator)
    return saved


def publish_credentials(state, expected, intent, profile, helpers, convert=None, validator=validate):
    """Emit only each native server's own leaf, after complete original binding."""
    from state import canonical
    state.phase(expected,intent,profile,helpers);state.namespaces();state.accounts.verify(expected);state.stopped()
    convert=convert or (lambda action,name,raw:transform(state,action,name,raw))
    value,saved=load(state,expected,convert=convert,validator=validator)
    credentials={
        'polygon-gateway-tls':canonical(dict(value['leaves']['gateway'],ca=value['ca'])),
        'comet-certificate':value['leaves']['comet']['certificate'].encode(),
        'comet-private-key':value['leaves']['comet']['key'].encode(),
        'polygon-broker-tls':canonical(dict(value['leaves']['broker'],ca=value['ca'])),
    }
    # These are projections of an already durable original bundle. Retrying
    # encryption may change ciphertext bytes, never the private/public identity.
    published={}
    for name,raw in credentials.items():
        path=DIRECTORY+'/'+name
        write_bytes(state,path,convert('encrypt',name,raw))
        published[name]=hashlib.sha256(state.protected(path).read_bytes()).hexdigest()
    write_bytes(state,'/etc/polygon/local-ca.pem',value['ca'].encode(),0o644)
    state.phase(expected,intent,profile,helpers);state.stopped()
    state.write('/etc/polygon/local-tls-projection.json',{'contract':expected,'source_intent':saved['source_intent'],
        'ca_sha256':saved['ca_sha256'],'ciphertexts':published})
    return {'source_intent':saved['source_intent'],'ca_sha256':saved['ca_sha256']}


def verify_projection(state, expected, convert=None, validator=validate):
    _value,saved=load(state,expected,convert=convert,validator=validator)
    projected=state.read('/etc/polygon/local-tls-projection.json')
    names={'polygon-gateway-tls','comet-certificate','comet-private-key','polygon-broker-tls'}
    require(set(projected)=={'contract','source_intent','ca_sha256','ciphertexts'}
            and projected['contract']==expected and projected['source_intent']==saved['source_intent']
            and projected['ca_sha256']==saved['ca_sha256'] and set(projected['ciphertexts'])==names,
            'local TLS credential projections belong to another generation')
    for name in names:
        cipher=state.protected(DIRECTORY+'/'+name).read_bytes()
        require(0<len(cipher)<=131072 and hashlib.sha256(cipher).hexdigest()==projected['ciphertexts'][name],
                'native TLS credential projection is incomplete or changed')
    require(hashlib.sha256(state.protected('/etc/polygon/local-ca.pem').read_bytes()).hexdigest()==saved['ca_sha256'],
            'native TLS trust root differs from original custody')
    return projected


def server_context(value, role):
    import fcntl
    import os
    import ssl
    require(role in SERVERS, 'unknown native TLS server role')
    leaf=value['leaves'][role]
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    descriptor=os.memfd_create('polygon-local-tls',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        raw=(leaf['certificate']+value['ca']+leaf['key']).encode();offset=0
        while offset<len(raw):
            written=os.write(descriptor,raw[offset:]);require(written>0,'anonymous TLS credential write failed');offset+=written
        fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        context.load_cert_chain('/proc/self/fd/'+str(descriptor))
    finally:os.close(descriptor)
    return context


def client_context(ca):
    import ssl
    # Providing cadata loads only this issuer while retaining the platform's
    # default validation flags, including strict X.509 checks on newer Python.
    context=ssl.create_default_context(cadata=ca);context.minimum_version=ssl.TLSVersion.TLSv1_2
    require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED,'native TLS peer verification is mandatory')
    return context
