# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Immutable original public host binding, separate from native mutable data."""
import os
from pathlib import Path
import re
import secrets
from eth_files import atomic,encoded,read,require,root_directory,synchronize,unique

ROOT=Path('/var/lib/erpc-ethereum-authority')


def intent(value):
    require(isinstance(value,str) and re.fullmatch('[a-f0-9]{32}',value),'original operation intent required')
    return value


def contract(value):
    require(isinstance(value,dict) and set(value)=={'schema','role','owner','network','kind','host_binding'}
            and type(value['schema'])is int and value['schema']==1 and value['role'] in ('rpc','validator')
            and isinstance(value['owner'],str) and re.fullmatch('[A-Za-z0-9]{1,80}',value['owner'])
            and isinstance(value['host_binding'],str) and re.fullmatch('[a-f0-9]{64}',value['host_binding']),
            'complete original Ethereum host contract required')
    require((value['role']=='rpc' and value['network']=='mainnet' and value['kind'] in ('full','archive'))
            or (value['role']=='validator' and value['network'] in ('mainnet','hoodi') and value['kind']=='validator'),
            'unsupported original Ethereum role/network/type')
    return value


class State:
    def __init__(self,role,directory=None):
        require(role in ('rpc','validator'),'unsupported original Ethereum role')
        self.role=role;self.directory=ROOT/role if directory is None else directory

    def path(self,name):
        require(isinstance(name,str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,100}',name)
                and '..' not in name,'invalid private receipt name')
        return self.directory/name

    def exists(self,name):
        path=self.path(name);return path.exists() or path.is_symlink()

    def get(self,name):return unique(read(self.path(name),mode=0o600))
    def put(self,name,value):atomic(self.path(name),encoded(value))

    def remove(self,name):
        descriptor=root_directory(self.directory)
        try:
            # Authenticate an existing private entry before unlinking it. Never
            # follow a replacement symlink or discard foreign staged material.
            if self.exists(name):self.get(name);os.unlink(self.path(name).name,dir_fd=descriptor)
            os.fsync(descriptor)
        finally:os.close(descriptor)

    def check(self,expected):
        expected=contract(expected);require(expected['role']==self.role,'wrong original role')
        value=self.get('owner.json')
        require(isinstance(value,dict) and set(value)=={'contract','machine'} and value['contract']==expected
                and isinstance(value['machine'],str) and re.fullmatch('[a-f0-9]{64}',value['machine']),
                'immutable Ethereum host authority differs')
        return value

    def reserve(self,expected,machine):
        expected=contract(expected)
        descriptor=root_directory(self.directory,create=True)
        os.close(descriptor)
        require(expected['role']==self.role and re.fullmatch('[a-f0-9]{64}',machine),'invalid original host identity')
        if not self.exists('owner.json'):
            require(not any(self.directory.iterdir()),'unowned original-authority staging cannot be adopted')
            self.put('owner.json',{'contract':expected,'machine':machine})
        require(self.check(expected)['machine']==machine,'original authority belongs to another machine')
        synchronize(self.path('owner.json'))
        return self

    def halted(self):
        if not self.exists('halt.json'):return {'generation':None,'retired':False}
        value=self.get('halt.json')
        require(set(value)=={'generation','retired'} and type(value['retired'])is bool,'invalid cancellation authority')
        intent(value['generation']);return value

    def current(self,expected,operation):
        self.check(expected);intent(operation)
        require(not self.exists('recovery.json'),'original deployment recovery must complete first')
        value=self.get('pending.json');fence=self.get('operation.json');halt=self.halted()
        require(set(value)=={'intent','generation','target','action'} and value['intent']==operation
                and value['generation']==halt['generation']
                and fence=={'intent':operation,'generation':halt['generation']},
                'Ethereum deployment was stopped or superseded')
        for name in ('owner.json','halt.json','operation.json','pending.json'):synchronize(self.path(name))
        return value

    def authorize(self,expected,operation,target,action):
        self.check(expected);intent(operation)
        require(action in ('deploy','update','update-config') and isinstance(target,dict),'invalid deployment request')
        require(not self.exists('recovery.json'),'original deployment recovery must complete first')
        require(not self.exists('canceled-'+operation+'.json'),'canceled intent cannot be reused')
        if self.exists('pending.json'):
            existing=self.current(expected,operation)
            require(existing['target']==target and existing['action']==action,'pending original target differs')
            return existing
        halt=self.halted()
        require(not halt['retired'] or action=='deploy','retired Ethereum host requires explicit deploy')
        require(not self.exists('cutover.json'),'original cutover requires explicit recovery')
        # Reserve a cancellation generation before publishing any continuation.
        # Changing only operation.json never authorizes an older target.
        if halt['generation'] is None:
            halt={'generation':secrets.token_hex(16),'retired':False};self.put('halt.json',halt)
        synchronize(self.path('halt.json'))
        self.put('operation.json',{'intent':operation,'generation':halt['generation']})
        value={'intent':operation,'generation':halt['generation'],'target':target,'action':action}
        self.put('pending.json',value)
        return self.current(expected,operation)

    def begin(self,expected,operation,shutdown):
        value=self.current(expected,operation)
        if self.exists('cutover.json'):
            require(self.get('cutover.json')==value,'another native cutover is incomplete')
        else:self.put('cutover.json',value)
        synchronize(self.path('cutover.json'))
        shutdown()
        return self.current(expected,operation)

    def publish(self,expected,operation,receipt):
        value=self.current(expected,operation)
        require(self.get('cutover.json')==value,'original native cutover required before publication')
        active={'intent':operation,'generation':value['generation'],'target':value['target'],'receipt':receipt}
        self.put('active.json',active);synchronize(self.path('active.json'))
        # The new target has completed its original cutover. A retired host is
        # unretired only by this explicit deploy, never by inspection/start.
        self.put('halt.json',{'generation':value['generation'],'retired':False})
        self.remove('cutover.json')
        return self.guard(expected)

    def guard(self,expected):
        self.check(expected)
        require(not self.exists('cutover.json') and not self.exists('recovery.json'),'native cutover/recovery is incomplete')
        halt=self.halted();active=self.get('active.json')
        require(not halt['retired'] and active['generation']==halt['generation'],'Ethereum runtime is stopped or retired')
        for name in ('owner.json','active.json','halt.json'):synchronize(self.path(name))
        return active

    def consume(self,expected,operation):
        value=self.current(expected,operation)
        require(self.guard(expected)['intent']==operation,'running receipt belongs to another deployment')
        self.put('operation.json',{'intent':None,'generation':value['generation']})
        self.remove('pending.json')

    def stop(self,expected,shutdown,retire=False):
        self.check(expected)
        halt={'generation':secrets.token_hex(16),'retired':bool(retire)}
        failures=[]
        try:self.put('halt.json',halt);synchronize(self.path('halt.json'))
        except Exception:failures.append('cancellation persistence')
        try:self.put('operation.json',{'intent':None,'generation':halt['generation']})
        except Exception:failures.append('continuation persistence')
        try:shutdown()
        except Exception:failures.append('owned shutdown')
        if failures:
            # Retry only the original revocation after attempting drain. An
            # earlier failure is still an error even if this retry succeeds.
            try:
                self.put('halt.json',halt);synchronize(self.path('halt.json'))
                self.put('operation.json',{'intent':None,'generation':halt['generation']})
            except Exception:failures.append('durable cancellation unavailable')
        require(not failures,'Ethereum stop incomplete: '+', '.join(failures)+'; original data retained')
        return halt

    def start(self,expected,qualify):
        self.check(expected)
        require(not self.exists('pending.json') and not self.exists('cutover.json')
                and not self.exists('recovery.json'),'complete or recover original deployment before manual start')
        halt=self.halted();require(not halt['retired'],'retired Ethereum host requires explicit deploy')
        require(self.get('operation.json')=={'intent':None,'generation':halt['generation']},'incomplete cancellation cannot be cleared')
        active=self.get('active.json');qualify(active)
        self.put('active.json',dict(active,generation=halt['generation']))
        return self.guard(expected)

    def recover(self,expected,operation,shutdown):
        self.check(expected);intent(operation)
        archive='canceled-'+operation+'.json'
        if self.exists(archive) and not self.exists('recovery.json'):
            original=self.get(archive)
            require(original.get('contract')==expected and original.get('intent')==operation,'retained recovery archive belongs to another original host')
            if self.exists('pending.json'):require(self.get('pending.json')['intent']!=operation,'incomplete original recovery')
            if self.exists('cutover.json'):require(self.get('cutover.json')['intent']!=operation,'incomplete original recovery')
            synchronize(self.path(archive));return {'recovered':True,'already':True,'started':False}
        if self.exists('recovery.json'):
            journal=self.get('recovery.json')
            require(journal['intent']==operation and journal['contract']==expected,'different original recovery is incomplete')
        else:
            value=self.get('pending.json');require(value['intent']==operation,'recovery names another operation')
            cutover=self.get('cutover.json') if self.exists('cutover.json') else None
            require(cutover is None or cutover==value,'original cutover differs from pending target')
            journal={'intent':operation,'contract':expected,'pending':value,'cutover':cutover}
        for name,key in [('pending.json','pending'),('cutover.json','cutover')]:
            if self.exists(name):require(self.get(name)==journal[key],'recovery cannot cancel a newer deployment')
        self.stop(expected,shutdown,retire=self.halted()['retired'])
        self.put('recovery.json',journal);synchronize(self.path('recovery.json'))
        if self.exists(archive):require(self.get(archive)==journal,'retained recovery archive differs')
        else:self.put(archive,journal)
        synchronize(self.path(archive))
        self.remove('pending.json');self.remove('cutover.json');self.remove('recovery.json')
        return {'recovered':True,'already':False,'started':False}
