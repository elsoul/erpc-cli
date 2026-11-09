# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Monotonic native database-opening authorization, independent of stale inventory.

Acquisition does not advance a floor. Authorization immediately before native
bootstrap/runtime does, conservatively even when later service startup fails.
"""
import fcntl
import os
import re
from eth_files import checked_file,require,root_directory,synchronize
import eth_layout as layout

CLIENTS=('reth','lighthouse')


def version(value):
    require(isinstance(value,str) and re.fullmatch(r'v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})',value),
            'database source floor requires a canonical stable native version')
    return tuple(int(part) for part in value[1:].split('.'))


def pins(source,artifacts=None):
    require(isinstance(source,dict) and isinstance(source.get('pair'),str),'original native source required')
    match=re.fullmatch(r'reth-(v[^-]+)--lighthouse-(v[^-]+)',source['pair'])
    require(match is not None,'canonical stable client pair required for database opening')
    result={}
    for client,tag in zip(CLIENTS,match.groups()):
        version(tag);commit=source.get(client+'_commit');archive=source.get(client+'_archive')
        require(isinstance(commit,str) and re.fullmatch('[a-f0-9]{40}',commit)
                and isinstance(archive,str) and re.fullmatch('[a-f0-9]{64}',archive),'original source/archive pin required')
        binary=None if artifacts is None else artifacts[client]['sha256']
        require(binary is None or (isinstance(binary,str) and re.fullmatch('[a-f0-9]{64}',binary)),'original image digest required')
        result[client]={'version':tag,'commit':commit,'archive':archive,'binary':binary}
    return result


def historical(value):
    require(isinstance(value,dict) and set(value)==set(CLIENTS),'highest previously opened client records required')
    for pin in value.values():
        require(isinstance(pin,dict) and set(pin)=={'version','commit'},'historical highest-version/source record required')
        version(pin['version']);require(isinstance(pin['commit'],str) and re.fullmatch('[a-f0-9]{40}',pin['commit']),
                                       'historical original source commit required')
    return value


def compare(candidate,previous):
    require(version(candidate['version'])>=version(previous['version']),
            'native target is below the original highest database-opening version')
    if candidate['version']==previous['version']:
        require(all(previous[key] is None or candidate[key] is None or candidate[key]==previous[key]
                    for key in ('commit','archive','binary')),'same opened native version cannot substitute source or image')


def bound(state,expected,client,pin):
    record=state.get('layout.json')
    require(record['contract']==expected,'original database layout differs')
    return {'contract':expected,'data':record,'client':client,'pin':pin}


def records(state,expected,client):
    result=[]
    for name in ('source-'+client+'.json','source-'+client+'-pending.json'):
        if not state.exists(name):continue
        row=state.get(name)
        require(isinstance(row,dict) and set(row)=={'contract','data','client','pin'} and row==bound(state,expected,client,row['pin']),
                'original database-opening authority differs')
        pin=row['pin']
        require(isinstance(pin,dict) and set(pin)=={'version','commit','archive','binary'},'invalid original source floor')
        version(pin['version'])
        for key,length in [('commit',40),('archive',64),('binary',64)]:
            require((key!='commit' and pin[key] is None) or (isinstance(pin[key],str) and re.fullmatch('[a-f0-9]{'+str(length)+'}',pin[key])),
                    'invalid original opened source identity')
        synchronize(state.path(name));result.append(row)
    return result


def empty_data(state,expected,plan,client):
    names=('beacon','vc') if expected['role']=='validator' and client=='lighthouse' else (client,)
    for name in names:
        fd=layout.open_native(state,expected,plan,name)
        try:
            if os.listdir(fd):return False
        finally:os.close(fd)
    return True


def check(state,expected,source,artifacts=None):
    state.check(expected);candidate=pins(source,artifacts)
    for client in CLIENTS:
        for row in records(state,expected,client):compare(candidate[client],row['pin'])
    return candidate


def authorize(state,expected,plan,source,artifacts,clients=CLIENTS):
    state.check(expected);candidate=pins(source,artifacts)
    require(set(clients)<=set(CLIENTS),'unknown database-opening client')
    for client in clients:
        directory=root_directory(state.directory)
        try:fd=os.open('source-'+client+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        finally:os.close(directory)
        with os.fdopen(fd,'rb') as lock:
            checked_file(os.fstat(lock.fileno()),mode=0o600);fcntl.flock(lock,fcntl.LOCK_EX)
            previous=records(state,expected,client)
            for row in previous:compare(candidate[client],row['pin'])
            if not previous:
                require(not state.exists('active.json') and empty_data(state,expected,plan,client),
                        'original opened-source receipts are missing; restore original authority or explicitly migrate historical evidence')
            wanted=bound(state,expected,client,candidate[client])
            # Pending is itself a conservative floor. A visible rename followed
            # by failed fsync cannot authorize the old source on a later retry.
            state.put('source-'+client+'-pending.json',wanted);synchronize(state.path('source-'+client+'-pending.json'))
            state.put('source-'+client+'.json',wanted);synchronize(state.path('source-'+client+'.json'))
    return candidate


def migrate(state,expected,value):
    historical(value)
    for client in CLIENTS:
        pin=dict(value[client],archive=None,binary=None);wanted=bound(state,expected,client,pin)
        for row in records(state,expected,client):
            # Repeated migration cannot reset a later managed opening floor.
            require(row==wanted,'historical migration cannot replace established native opening authority')
        state.put('source-'+client+'-pending.json',wanted);synchronize(state.path('source-'+client+'-pending.json'))
        state.put('source-'+client+'.json',wanted);synchronize(state.path('source-'+client+'.json'))
