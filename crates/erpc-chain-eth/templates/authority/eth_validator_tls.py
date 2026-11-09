# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Purpose-separated private TLS custody for the dedicated validator host.

TLS keys are transport identities, never the consensus signer. Issuer private
keys are discarded with the volatile issuance scratch after the encrypted leaf
capsule and its original receipt are durable. Renewal is a stopped deployment.
"""
import calendar
import datetime
import os
from pathlib import Path
import secrets
import re
import ssl
import time
from eth_files import atomic,digest,encoded,read,require,root_directory,run,synchronize,unique
import eth_validator_custody as custody
import eth_validator_native as native

IPS={'engine':'127.0.0.2','beacon':'127.0.0.3'}
RENEW_WINDOW=30*24*3600
START_MARGIN=24*3600
MAX_CAPSULE=65536
MEMBERS=('ca.key','ca.pem','leaf.key','leaf.csr','leaf.pem','extensions.cnf')


def crypt(purpose,action,raw):
    require(purpose in IPS and action in ('encrypt','decrypt'),'unknown validator transport credential')
    argv=['/usr/bin/systemd-creds',action,'--name=erpc-ethereum-'+purpose+'-tls']
    if action=='encrypt':argv.append('--with-key=host')
    result=run(argv+['-','-'],input_data=raw)
    require(0<len(result)<=MAX_CAPSULE*2,'transport credential exceeds its bound')
    return result


def dates(raw):
    values={}
    for line in raw.decode('ascii').splitlines():
        name,separator,value=line.partition('=')
        require(separator and name in ('notBefore','notAfter') and name not in values,'invalid native certificate dates')
        values[name]=calendar.timegm(datetime.datetime.strptime(value,'%b %d %H:%M:%S %Y GMT').timetuple())
    require(set(values)=={'notBefore','notAfter'} and values['notAfter']>values['notBefore'],'invalid certificate lifetime')
    return {'not_before':values['notBefore'],'not_after':values['notAfter']}


def inspect(purpose,stage):
    require(purpose in IPS,'unknown validator TLS audience')
    for name in ('ca.pem','leaf.pem','leaf.key'):read(stage/name,MAX_CAPSULE,mode=0o600)
    native.worker(['/usr/bin/openssl','verify','-x509_strict','-purpose','sslserver','-verify_ip',IPS[purpose],
                   '-CAfile',str(stage/'ca.pem'),str(stage/'leaf.pem')])
    expected=native.worker(['/usr/bin/openssl','pkey','-in',str(stage/'leaf.key'),'-pubout'])
    observed=native.worker(['/usr/bin/openssl','x509','-in',str(stage/'leaf.pem'),'-pubkey','-noout'])
    require(expected==observed,'transport private key does not match its certificate')
    lifetime=dates(native.worker(['/usr/bin/openssl','x509','-in',str(stage/'leaf.pem'),'-noout','-dates']))
    return dict(lifetime,ca_sha256=digest(read(stage/'ca.pem')),certificate_sha256=digest(read(stage/'leaf.pem')))


def issue(purpose,stage):
    require(purpose in IPS,'unknown original TLS purpose')
    # Scratch uses a fresh random pathname on every attempt. A killed native
    # child can never write into a later attempt's named files.
    native.worker(['/usr/bin/openssl','req','-config','/dev/null','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
        '-keyout',str(stage/'ca.key'),'-out',str(stage/'ca.pem'),'-days','366','-subj','/CN=ERPC Ethereum '+purpose+' issuer',
        '-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-addext','subjectKeyIdentifier=hash','-addext','authorityKeyIdentifier=keyid:always'])
    native.worker(['/usr/bin/openssl','req','-config','/dev/null','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
        '-keyout',str(stage/'leaf.key'),'-out',str(stage/'leaf.csr'),'-subj','/CN=ERPC Ethereum '+purpose])
    atomic(stage/'extensions.cnf',('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
        'extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=IP:'+IPS[purpose]+'\n').encode())
    native.worker(['/usr/bin/openssl','x509','-req','-in',str(stage/'leaf.csr'),'-CA',str(stage/'ca.pem'),'-CAkey',str(stage/'ca.key'),
        '-set_serial','0x'+secrets.token_hex(16),'-out',str(stage/'leaf.pem'),'-days','365','-extfile',str(stage/'extensions.cnf')])
    observed=inspect(purpose,stage)
    capsule={'purpose':purpose,'ip':IPS[purpose],'ca':read(stage/'ca.pem',MAX_CAPSULE,mode=0o600).decode('ascii'),
             'certificate':read(stage/'leaf.pem',MAX_CAPSULE,mode=0o600).decode('ascii'),
             'private_key':read(stage/'leaf.key',MAX_CAPSULE,mode=0o600).decode('ascii')}
    raw=encoded(capsule);require(len(raw)<=MAX_CAPSULE,'transport capsule exceeds its bound')
    return raw,observed


def material(purpose,cipher):
    raw=crypt(purpose,'decrypt',cipher);value=unique(raw)
    require(isinstance(value,dict) and set(value)=={'purpose','ip','ca','certificate','private_key'}
            and value['purpose']==purpose and value['ip']==IPS[purpose]
            and all(isinstance(value[key],str) and 0<len(value[key])<MAX_CAPSULE for key in ('ca','certificate','private_key')),
            'original transport credential audience differs')
    return value


def receipt(state,expected,purpose):
    require(purpose in IPS,'unknown original TLS purpose');binding=custody.authority(state,expected)
    record=state.get('tls-'+purpose+'.json')
    require(isinstance(record,dict) and set(record)=={'authority','purpose','intent','cipher_sha256','not_before','not_after','ca_sha256','certificate_sha256'}
            and record['authority']==binding and record['purpose']==purpose
            and isinstance(record['intent'],str) and re.fullmatch('[a-f0-9]{32}',record['intent'])
            and all(isinstance(record[key],str) and re.fullmatch('[a-f0-9]{64}',record[key])
                    for key in ('cipher_sha256','ca_sha256','certificate_sha256'))
            and type(record['not_before'])is int and type(record['not_after'])is int and record['not_after']>record['not_before'],
            'original transport receipt differs')
    synchronize(state.path('tls-'+purpose+'.json'))
    return record


def read_original(state,expected,purpose):
    record=receipt(state,expected,purpose)
    path=state.path('tls-'+purpose+'-'+record['intent']+'.cred');cipher=read(path,MAX_CAPSULE*2,mode=0o600)
    require(digest(cipher)==record['cipher_sha256'],'original transport ciphertext differs');synchronize(path)
    value=material(purpose,cipher)
    require(digest(value['ca'].encode())==record['ca_sha256'] and digest(value['certificate'].encode())==record['certificate_sha256'],
            'original transport certificate changed')
    return record,value



def publish_ca(state,purpose,record,value):
    path=state.path('tls-'+purpose+'-'+record['intent']+'.ca')
    raw=value['ca'].encode();require(digest(raw)==record['ca_sha256'],'original public transport CA differs')
    if state.exists(path.name):require(read(path,MAX_CAPSULE,mode=0o444)==raw,'existing original transport CA changed')
    else:atomic(path,raw,0o444)
    synchronize(path)


def certificate_authority(state,expected,purpose,now=None):
    record=receipt(state,expected,purpose);clock=time.time() if now is None else now
    require(record['not_before']<=clock<record['not_after']-START_MARGIN,'original transport certificate is expired or needs renewal')
    raw=read(state.path('tls-'+purpose+'-'+record['intent']+'.ca'),MAX_CAPSULE,mode=0o444)
    require(digest(raw)==record['ca_sha256'],'original public TLS authority changed')
    return raw.decode('ascii')


def ready(state,expected,purpose,now=None):
    record,value=read_original(state,expected,purpose);clock=time.time() if now is None else now
    require(type(record['not_before'])is int and type(record['not_after'])is int
            and record['not_before']<=clock<record['not_after']-START_MARGIN,
            'validator transport certificate is not currently usable; renew with stopped deployment')
    return record,value



def cleanup(state,purpose,operation):
    name='tls-'+purpose+'-'+operation+'.json';journal=state.get(name)
    require(isinstance(journal.get('scratch'),list) and len(journal['scratch'])<=64,'invalid original TLS scratch journal')
    for value in journal['scratch']:
        path=Path(value)
        require(path.parent==native.RUN/'tls-issuance' and re.fullmatch('attempt-[a-f0-9]{32}',path.name),
                'TLS cleanup path differs from its original volatile namespace')
        if path.exists() or path.is_symlink():native.remove_scratch(path,MEMBERS)
    journal['scratch']=[];state.put(name,journal);synchronize(state.path(name))


def renew(state,expected,purpose,operation,force=False):
    import eth_state
    eth_state.intent(operation);require(purpose in IPS,'unknown TLS purpose')
    current=state.current(expected,operation)
    require(state.get('cutover.json')==current,'TLS issuance requires the current stopped original deployment')
    require(type(force)is bool and (not force or current['target'].get('renew_transport') is True),'transport recovery must be explicitly bound to this original deployment')
    binding=custody.authority(state,expected)
    if state.exists('tls-'+purpose+'.json'):
        previous=receipt(state,expected,purpose)
        if previous['intent']==operation:
            previous,value=ready(state,expected,purpose)
            publish_ca(state,purpose,previous,value)
            cleanup(state,purpose,operation);return previous
        if not force:
            previous,value=read_original(state,expected,purpose)
            if previous['not_before']<=time.time()<previous['not_after']-RENEW_WINDOW:
                publish_ca(state,purpose,previous,value);cleanup(state,purpose,previous['intent']);return previous
        require(previous['intent']!=operation,'transport renewal needs a fresh original deployment intent')
    name='tls-'+purpose+'-'+operation;path=state.path(name+'.cred');journal=name+'.json'
    if state.exists(journal):
        candidate=state.get(journal)
        require(candidate['authority']==binding and candidate['intent']==operation and candidate['purpose']==purpose,
                'interrupted transport issuance belongs to another owner')
        synchronize(state.path(journal))
    else:
        require(not state.exists(path.name),'unowned transport ciphertext cannot be adopted')
        candidate={'authority':binding,'purpose':purpose,'intent':operation,'scratch':[]}
        state.put(journal,candidate);synchronize(state.path(journal))
    if not state.exists(path.name):
        parent=native.RUN/'tls-issuance';descriptor=root_directory(parent,True);os.close(descriptor)
        scratch=native.scratch(parent)
        require(isinstance(candidate.get('scratch'),list) and len(candidate['scratch'])<64,'too many interrupted TLS issuance attempts')
        candidate['scratch'].append(str(scratch));state.put(journal,candidate);synchronize(state.path(journal))
        raw,observed=issue(purpose,scratch)
        candidate=dict(candidate,**observed)
        state.put(journal,candidate);synchronize(state.path(journal))
        atomic(path,crypt(purpose,'encrypt',raw))
    cipher=read(path,MAX_CAPSULE*2,mode=0o600);synchronize(path);value=material(purpose,cipher)
    require(set(candidate)=={'authority','purpose','intent','not_before','not_after','ca_sha256','certificate_sha256','scratch'}
            and digest(value['ca'].encode())==candidate['ca_sha256'] and digest(value['certificate'].encode())==candidate['certificate_sha256'],
            'interrupted original TLS generation differs')
    state.current(expected,operation)
    record={key:value for key,value in candidate.items() if key!='scratch'}
    record['cipher_sha256']=digest(cipher);publish_ca(state,purpose,record,value)
    state.put('tls-'+purpose+'.json',record)
    synchronize(state.path('tls-'+purpose+'.json'))
    cleanup(state,purpose,operation)
    return record
