# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Host-encrypted private-CA authentication for the native parent's loopback TLS.

TLS identities may renew only during a fenced original-owner preparation. They
are separate from the immutable financial wallet. No generation function runs
in offline tests; optional handshake tests use published CPython test material.
"""
from datetime import datetime, timedelta, timezone
import scope
import fcntl
import hashlib
import ipaddress
import os
import re
import ssl
import subprocess
import time
import host
import upstreams
from state import token
from storage import decode, directory, encode, read, require, sync_directory, synchronize, write

NAME=scope.CREDENTIAL_PREFIX+'-parent-tls'
RENEW_BEFORE=30*24*3600


def transform(action, raw):
    require(action in ('encrypt','decrypt') and isinstance(raw,bytes) and len(raw)<=131072,'invalid parent TLS credential operation')
    args=['/usr/bin/systemd-creds',action,'--name='+NAME]
    if action=='encrypt':args.append('--with-key=host')
    value=subprocess.run([*args,'-','-'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                         timeout=30,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(value.returncode==0 and 0<len(value.stdout)<=131072,'parent TLS credential operation failed')
    return value.stdout


def generate(expected):
    """Executed only on an owned stopped host during an actual deployment."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    now=datetime.now(timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1());server_key=ec.generate_private_key(ec.SECP256R1())
    issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ERPC parent '+expected['creation'])])
    ca=(x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(days=366))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    certificate=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'127.0.0.1')]))
        .issuer_name(issuer).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    # The issuing private key is deliberately not retained or delivered to the
    # transport. Renewal creates a new CA while the original runtime is drained.
    return {'contract':expected,'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),
            'certificate':certificate.public_bytes(serialization.Encoding.PEM).decode(),
            'key':server_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()).decode()}


def dates(cert):
    if hasattr(cert,'not_valid_after_utc'):return cert.not_valid_before_utc.timestamp(),cert.not_valid_after_utc.timestamp()
    return cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp(),cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp()


def verify_signature(certificate, issuer):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec,padding,rsa
    require(isinstance(certificate.signature_hash_algorithm,hashes.SHA256),'parent TLS certificate uses an unqualified signature')
    public=issuer.public_key()
    if isinstance(public,ec.EllipticCurvePublicKey):
        require(isinstance(public.curve,ec.SECP256R1),'parent TLS issuer curve differs')
        public.verify(certificate.signature,certificate.tbs_certificate_bytes,ec.ECDSA(certificate.signature_hash_algorithm))
    elif isinstance(public,rsa.RSAPublicKey):
        require(public.key_size>=2048,'parent TLS issuer key is too small')
        public.verify(certificate.signature,certificate.tbs_certificate_bytes,padding.PKCS1v15(),certificate.signature_hash_algorithm)
    else:raise ValueError('parent TLS issuer type differs')


def validate(value, expected, allow_expired=False, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    require(isinstance(value,dict) and set(value)=={'contract','ca','certificate','key'} and value['contract']==expected
            and all(isinstance(value[key],str) and 0<len(value[key])<16384 for key in ('ca','certificate','key')),
            'parent TLS material belongs to another original owner')
    ca=x509.load_pem_x509_certificate(value['ca'].encode());cert=x509.load_pem_x509_certificate(value['certificate'].encode())
    key=serialization.load_pem_private_key(value['key'].encode(),password=None)
    require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1)
            and key.public_key().public_numbers()==cert.public_key().public_numbers(), 'parent TLS private key differs from its certificate')
    require(ca.subject==ca.issuer and cert.issuer==ca.subject
            and ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value=='ERPC parent '+expected['creation'],
            'parent TLS issuing authority differs from original creation')
    require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value==x509.BasicConstraints(ca=True,path_length=0)
            and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
            'parent TLS certificate cannot act as an issuing authority')
    san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    require(list(san)==[x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
            and list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[ExtendedKeyUsageOID.SERVER_AUTH],
            'parent TLS certificate does not identify the fixed loopback server')
    verify_signature(ca,ca);verify_signature(cert,ca)
    now=time.time() if now is None else now
    before,after=dates(cert);ca_before,ca_after=dates(ca)
    require(before<=now and ca_before<=now and ca_after>=after and (allow_expired or now<after),
            'parent TLS certificate is not currently valid; prepare a same-owner renewal')
    return {'ca_sha256':hashlib.sha256(value['ca'].encode()).hexdigest(),
            'certificate_sha256':hashlib.sha256(value['certificate'].encode()).hexdigest(),'not_after':int(after),
            'public_ca':value['ca'],'public_certificate':value['certificate']}


def sealed(state, expected, allow_expired=False):
    state.owner(expected);saved=state.get('parent-tls.json')
    require(set(saved)=={'contract','intent','cipher_sha256','ca_sha256','certificate_sha256','not_after','public_ca','public_certificate'}
            and saved['contract']==expected and type(saved['not_after']) is int
            and (allow_expired or time.time()<saved['not_after']), 'original parent TLS receipt is missing or expired')
    token(saved['intent'])
    require(all(isinstance(saved[key],str) and re.fullmatch('[0-9a-f]{64}',saved[key])
                for key in ('cipher_sha256','ca_sha256','certificate_sha256'))
            and all(isinstance(saved[key],str) and 0<len(saved[key])<16384 for key in ('public_ca','public_certificate')),
            'parent TLS receipt encoding differs')
    cipher=read(host.TLS_CUSTODY/'parent-tls.cred',131072,mode=0o600)
    require(hashlib.sha256(cipher).hexdigest()==saved['cipher_sha256'],'parent TLS ciphertext differs')
    require(hashlib.sha256(saved['public_ca'].encode()).hexdigest()==saved['ca_sha256']
            and hashlib.sha256(saved['public_certificate'].encode()).hexdigest()==saved['certificate_sha256'],
            'parent TLS public identity differs')
    return saved,cipher


def load(state, expected, raw=None, allow_expired=False, convert=transform):
    saved,cipher=sealed(state,expected,allow_expired)
    value=decode(convert('decrypt',cipher) if raw is None else raw)
    checked=validate(value,expected,allow_expired)
    require(all(saved[key]==result for key,result in checked.items()),'loaded TLS credential differs from its original public identity')
    return value


def ensure(state, expected, intent, quiet, create=generate, convert=transform):
    state.pending(expected,intent);host.namespaces();quiet()
    pending_path=state.root/'parent-tls-pending.json'
    previous=state.get('parent-tls-pending.json') if pending_path.exists() else None
    if previous is not None:
        require(set(previous)=={'contract','intent'} and previous['contract']==expected,'TLS publication intent belongs to another owner')
        token(previous['intent'])
    existing=(state.root/'parent-tls.json').exists()
    saved=state.get('parent-tls.json') if existing else None
    if existing:
        token(saved['intent']);require(saved['contract']==expected,'original TLS recovery belongs to another owner')
    inflight=previous is not None and (not existing or previous['intent']!=saved['intent'])
    staged_pending=host.TLS_CUSTODY/('prepare-'+previous['intent'])/'parent-tls.cred' if inflight else None
    if existing and not (inflight and staged_pending.exists()):
        if not (host.TLS_CUSTODY/'parent-tls.cred').exists():
            original=host.TLS_CUSTODY/('prepare-'+saved['intent'])/'parent-tls.cred'
            cipher=read(original,131072,mode=0o600)
            require(hashlib.sha256(cipher).hexdigest()==saved['cipher_sha256'], 'original TLS recovery generation differs')
            write(host.TLS_CUSTODY/'parent-tls.cred',cipher)
        load(state,expected,allow_expired=True,convert=convert)
        if not inflight and saved['not_after']-time.time()>RENEW_BEFORE:return sealed(state,expected)[0]
    if previous is None or (existing and previous['intent']==saved['intent']):
        if not existing:
            require(not host.TLS_CUSTODY.exists() or not any(host.TLS_CUSTODY.iterdir()),
                    'orphan TLS material cannot be adopted')
        previous={'contract':expected,'intent':intent};state.put('parent-tls-pending.json',previous)
    synchronize(pending_path)
    tls_intent=previous['intent']
    directory(host.TLS_CUSTODY,create=True,mode=0o700)
    stage=host.TLS_CUSTODY/('prepare-'+tls_intent);staged=stage/'parent-tls.cred'
    directory(stage,create=True,mode=0o700)
    require({path.name for path in stage.iterdir()}<={'parent-tls.cred'},'unknown TLS staging content cannot be adopted')
    if staged.exists():cipher=read(staged,131072,mode=0o600);value=decode(convert('decrypt',cipher))
    else:
        value=create(expected);validate(value,expected)
        cipher=convert('encrypt',encode(value));write(staged,cipher)
        require(decode(convert('decrypt',cipher))==value,'parent TLS encryption readback differs')
    metadata=validate(value,expected);synchronize(staged);sync_directory(stage);state.pending(expected,intent);quiet()
    saved=dict(metadata,contract=expected,intent=tls_intent,cipher_sha256=hashlib.sha256(cipher).hexdigest())
    write(host.TLS_CUSTODY/'parent-tls.cred',cipher);state.put('parent-tls.json',saved)
    load(state,expected,convert=convert)
    return saved


def server_context(value):
    """Load plaintext only from a sealed anonymous Linux descriptor, then close."""
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    descriptor=os.memfd_create('erpc-parent-tls',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        raw=(value['certificate']+value['ca']+value['key']).encode();offset=0
        while offset<len(raw):
            written=os.write(descriptor,raw[offset:]);require(written>0,'parent TLS anonymous publication failed');offset+=written
        fcntl.fcntl(descriptor,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        context.load_cert_chain('/proc/self/fd/'+str(descriptor))
    finally:os.close(descriptor)
    return context


def client_context(ca):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca)
    require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED,'parent TLS verification must remain mandatory')
    return context


class Server(upstreams.Server):
    def __init__(self,address,handler,proxy,role,context):
        self.context=context;super().__init__(address,handler,proxy,role)
    def get_request(self):
        request,address=self.socket.accept()
        try:return self.context.wrap_socket(request,server_side=True,do_handshake_on_connect=False),address
        except Exception:request.close();raise
    def work(self,request,address):
        try:
            request.settimeout(upstreams.TIMEOUT);request.do_handshake()
            self.finish_request(request,address)
        except Exception:pass
        finally:self.shutdown_request(request);self.slots.release()
