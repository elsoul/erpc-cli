# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original provider readback becomes native ownership only after durable ack.

A complete receipt is written before the final marker. A retry after that point
repairs only marker durability, never recopies data or replays original custody.
"""
import hashlib
import re
from native_files import encoded,require,sync_directory,sync_file
import native_migration_custody as custody
import native_migration_guard as guard

PREPARED='migration-cutover.json'
COMPLETE='migration-complete.json'


def receipt(value,contract,scope):
    fields={'schema','intent','inventory_id','reserved_version','source_sha256','contract_sha256','config_sha256','custody_sha256'}
    require(isinstance(value,dict) and set(value)==fields and type(value['schema'])is int and value['schema']==1
            and value['intent']==scope['intent'] and value['source_sha256']==scope['source_sha256']
            and value['inventory_id']==contract['inventory_id'] and type(value['reserved_version'])is int
            and 0<value['reserved_version']<2**64 and value['contract_sha256']==hashlib.sha256(encoded(contract)).hexdigest(),
            'original provider cutover binding differs')
    require(all(isinstance(value[name],str) and re.fullmatch('[a-f0-9]{64}',value[name])
                for name in ('source_sha256','contract_sha256','config_sha256','custody_sha256')),
            'original provider cutover digests differ')
    return value


def complete_record(state,contract,scope):
    value=state.get(COMPLETE)
    require(isinstance(value,dict) and set(value)=={'contract','scope','receipt','provider_version'}
            and value['contract']==contract and value['scope']==scope,'native completion belongs to another original owner')
    receipt(value['receipt'],contract,scope)
    require(type(value['provider_version'])is int and value['receipt']['reserved_version']<value['provider_version']<2**64,
            'native completion lacks the promoted provider version')
    return value


def committed(state,contract):
    """Data-opening paths require durable completion; stop stays independent."""
    owner=state.get('owner.json');scope=owner.get('migration')
    if scope is None:return
    require(state.migration is None,'ordinary data opening cannot use a migration override')
    require(state.get('migration.json')=={'contract':contract,'scope':scope,'phase':'complete'},'native migration is not complete')
    complete_record(state,contract,scope)
    for name in (COMPLETE,'migration.json'):sync_file(state.directory/name)
    sync_directory(state.directory)


class Cutover:
    def __init__(self,operation):
        self.operation=operation;self.capture=custody.Capture(operation)
        self.state=self.capture.state;self.contract=self.capture.contract
        self.scope=self.capture.promotion.owner
    def entry(self,value):
        return {'contract':self.contract,'scope':self.scope,'receipt':receipt(value,self.contract,self.scope)}
    def owner(self):
        # Explicit completion repair may restore a lost final marker, but only
        # with the unchanged original owner and an already durable complete ack.
        value=self.state.get('owner.json')
        require(set(value)=={'contract','initial_halt','initialized','migration'} and value['contract']==self.contract
                and value['migration']==self.scope and value['initialized'] is True,'original native owner cannot be reconstructed')
        return value
    def completed(self,value):
        self.owner();saved=complete_record(self.state,self.contract,self.scope)
        require(saved['receipt']==receipt(value,self.contract,self.scope),'a different cutover cannot replace completed ownership')
        prepared=self.state.get(PREPARED);require(prepared==self.entry(value),'completed original provider intent differs')
        return saved
    def gate(self,value):
        self.capture.gate();guard.verify(self.operation)
        key=custody.custody.complete(self.state,self.contract,self.capture.role)
        require(key['public']==self.capture.identity['public'] and key['plaintext_sha256']==value['custody_sha256'],
                'provider readback is not the original encrypted identity')
        plain=custody.custody.key_material(custody.custody.crypt('decrypt',custody.custody.private(
            custody.custody.CUSTODY/(self.capture.role+'.cred'))),key['public'])
        require(hashlib.sha256(plain).hexdigest()==value['custody_sha256'],'host original custody readback differs')
    def prepare(self,value):
        expected=self.entry(value)
        if (self.state.directory/COMPLETE).exists():
            self.completed(value);path=self.state.directory/'migration.json'
            return {'cutover_prepared':True,'migration_complete':path.exists() and self.state.get(path.name)['phase']=='complete'}
        self.gate(value)
        helper={'revision':guard.verify(self.operation)['revision']}
        require(isinstance(helper['revision'],str) and re.fullmatch('[a-f0-9]{64}',helper['revision']),
                'original native helper publication differs')
        helper_path=self.state.directory/'helper-revision.json'
        if helper_path.exists():require(self.state.get(helper_path.name)==helper,'another native helper already owns migration data')
        else:self.state.put(helper_path.name,helper)
        sync_file(helper_path);sync_directory(self.state.directory)
        path=self.state.directory/PREPARED
        if path.exists():require(self.state.get(PREPARED)==expected,'another original provider cutover is already reserved')
        else:self.state.put(PREPARED,expected)
        sync_file(path);sync_directory(self.state.directory)
        self.gate(value)
        return {'cutover_prepared':True,'migration_complete':False}
    def finalize(self,value,provider_version):
        receipt(value,self.contract,self.scope)
        require(type(provider_version)is int and value['reserved_version']<provider_version<2**64,'promoted original provider version required')
        if (self.state.directory/COMPLETE).exists():
            saved=self.completed(value)
            require(provider_version>=saved['provider_version'],'a stale provider version cannot acknowledge completion')
        else:
            self.prepare(value);self.gate(value)
            saved={'contract':self.contract,'scope':self.scope,'receipt':value,'provider_version':provider_version}
            self.state.put(COMPLETE,saved)
        # This durable receipt is authoritative even if the final marker's
        # rename/fsync reply is lost. It is never recomputed from later history.
        sync_file(self.state.directory/COMPLETE);sync_directory(self.state.directory)
        self.owner()
        expected={'contract':self.contract,'scope':self.scope,'phase':'complete'}
        path=self.state.directory/'migration.json'
        if path.exists():
            marker=self.state.get(path.name)
            require(marker in (expected,dict(expected,phase='preparing')),'original migration marker changed')
        if not path.exists() or self.state.get(path.name)!=expected:self.state.put(path.name,expected)
        sync_file(path);sync_directory(self.state.directory)
        return {'migration_complete':True,'runtime_started':False,'provider_version':saved['provider_version'],
                'receipt':saved['receipt'],'original_source_retained':True}


def status(state,contract,scope):
    if (state.directory/COMPLETE).exists():
        saved=complete_record(state,contract,scope)
        return {'phase':'complete','receipt':saved['receipt'],'provider_version':saved['provider_version']}
    if (state.directory/PREPARED).exists():
        saved=state.get(PREPARED)
        require(set(saved)=={'contract','scope','receipt'} and saved['contract']==contract and saved['scope']==scope,
                'original cutover preparation belongs to another owner')
        return {'phase':'prepared','receipt':receipt(saved['receipt'],contract,scope),'provider_version':None}
    return None
