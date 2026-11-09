# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Retain the already-qualified original host key while native startup is fenced."""
from native_files import encoded, require
import native_accounts as accounts
import native_custody as custody
import native_migration_key as keys
import native_migration_promote as promote
import native_process as process
import native_source_floor as floor


class Capture:
    def __init__(self, operation):
        self.operation=operation;self.promotion=promote.Promotion(operation)
        self.state=self.promotion.state;self.contract=self.promotion.contract
        self.original=operation.binding['legacy'];self.identity=self.original['host_identity']
        self.intent=operation.binding['intent'];self.role=self.identity['role']
        require(self.role in ('sync','rpc') and self.identity['public'] != self.contract.get('authority_account'),
                'only original host-only identities may be retained')
    def gate(self):
        completed=self.state.directory/'migration-complete.json'
        require(not completed.exists() and not completed.is_symlink(),'completed native ownership cannot recapture or export its original source')
        self.promotion.copy.gate();self.state.owner(self.contract)
        marker=self.state.get('migration.json')
        require(marker['phase']=='preparing','completed migration cannot recapture an original key')
        identities=accounts.verify(self.state,self.contract);node=identities['node']
        require(self.state.get('data.json')=={'contract':self.contract,'uid':node['uid'],'gid':node['gid']},
                'original copied data ownership is incomplete')
        historical=self.original['artifact_evidence']['source']
        require(floor.highest(floor.records(self.state,self.contract))==floor.source(historical),
                'original copied source floor differs')
        for value in identities.values():process.assert_quiescent(value['uid'])
        keys.source(self.original)
    def selected(self):
        self.gate();identity,material=keys.qualified_material(self.original)
        try:
            require(identity==self.identity and identity['public'] != self.contract.get('authority_account'),
                    'original private source differs from its approved descriptor')
            registered=None if self.role=='rpc' else {'identity':self.contract['identity_account'],'vote_account':self.contract['vote_account'],'withdrawer':self.contract['authority_account']}
            observation=keys.classify(self.original['network'],identity['public'],identity['bls_public'],registered=registered)
            require(observation.get('bls_authority_checked') is True,
                    'original BLS voting authority must be excluded before custody transfer')
            require(observation.get('commission')==self.original['commission'],'original public commission changed during migration')
            self.gate()
            return material,observation
        except Exception:
            material[:]=bytes(len(material));raise
    def capture(self):
        material,observation=self.selected()
        try:
            receipt=custody.retain_original(self.state,self.contract,self.intent,self.role,
                encoded(list(material)),self.identity['public'],self.gate,self.gate)
            self.gate()
            return {'role':self.role,'public':receipt['public'],'custody_verified':True,
                    'authority_observation':observation,'private_exported':False,'runtime_started':False}
        finally:material[:]=bytes(len(material))
    def export(self):
        """Dedicated private transport only; the normal JSON controller rejects it."""
        material,_=self.selected()
        try:
            receipt=custody.complete(self.state,self.contract,self.role)
            require(receipt['public']==self.identity['public'],'retained identity differs')
            raw=custody.key_material(custody.crypt('decrypt',custody.private(custody.CUSTODY/(self.role+'.cred'))),receipt['public'])
            require(raw==encoded(list(material)),'retained ciphertext is not the original host key')
            self.gate();return raw
        finally:material[:]=bytes(len(material))
