# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Lighthouse history identity and conservative observed high-water marks.

Lighthouse's native import/prune preserves maximum slot/source/target bounds,
including synthetic unknown-root records. ERPC does not recreate a lost live DB
from an initial import backup or claim to journal each native signature.
"""
import os
import stat
from eth_files import checked_file,digest,encoded,require,synchronize
import eth_layout as layout
import eth_validator_custody as custody

DATABASE='slashing_protection.sqlite'


def summary(value,network,pubkey):
    custody.history(value,network,pubkey)
    entry=value['data'][0]
    def maximum(rows,field):return max((int(row[field]) for row in rows),default=None)
    return {'pubkey':pubkey,'genesis_validators_root':custody.ROOTS[network],
            'block_slot':maximum(entry['signed_blocks'],'slot'),
            'source_epoch':maximum(entry['signed_attestations'],'source_epoch'),
            'target_epoch':maximum(entry['signed_attestations'],'target_epoch')}


def dominates(current,previous):
    require(current['pubkey']==previous['pubkey'] and current['genesis_validators_root']==previous['genesis_validators_root'],
            'original native history key or network differs')
    for name in ('block_slot','source_epoch','target_epoch'):
        require(previous[name] is None or (current[name] is not None and current[name]>=previous[name]),
                'native history regressed below its last recorded signing bound')


def identity(state,expected,plan,durable=False):
    directory=layout.descendant(state,expected,plan,'vc','validators')
    try:
        descriptor=os.open(DATABASE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            info=os.fstat(descriptor);account=plan['users']['ev-validator']
            checked_file(info,owner=account['uid'],mode=0o600)
            require(info.st_gid==account['gid'] and info.st_dev==os.fstat(directory).st_dev and info.st_size>=4096,
                    'original native slashing DB ownership, size or filesystem differs')
            require(os.read(descriptor,16)==b'SQLite format 3\x00','native slashing DB has no SQLite header')
            if durable:
                os.fsync(descriptor);os.fsync(directory)
            return {'inode':info.st_ino,'directory_inode':os.fstat(directory).st_ino}
        finally:os.close(descriptor)
    finally:os.close(directory)


def verify_identity(state,expected,plan,pubkey):
    state.check(expected);record=state.get('signer-history.json')
    require(record['contract']==expected and record['pubkey']==pubkey and record['identity']==identity(state,expected,plan),
            'original native slashing history identity changed; never recreate it from an initial backup')
    synchronize(state.path('signer-history.json'));return record


def observe(state,expected,plan,pubkey,value,initial=False):
    """Caller exports from the quiescent original native DB using qualified LH."""
    state.check(expected);current=summary(value,expected['network'],pubkey);observed=identity(state,expected,plan,durable=True)
    if state.exists('signer-history.json'):
        previous=verify_identity(state,expected,plan,pubkey);dominates(current,previous['summary'])
    else:
        require(initial and state.exists('signer-import.json'),'original native history receipt is missing')
        pending=state.get('signer-import.json')
        require(pending['contract']==expected and pending['pubkey']==pubkey and pending['ever_authorized'] is False,
                'a previously authorized signer cannot reconstruct its original history receipt')
    record={'contract':expected,'pubkey':pubkey,'identity':observed,'summary':current,'export_sha256':digest(encoded(value))}
    state.put('signer-history.json',record);synchronize(state.path('signer-history.json'))
    return record


def authorize(state,expected,plan,pubkey):
    """Persist before native VC execution; failed startup remains conservative."""
    verify_identity(state,expected,plan,pubkey)
    imported=state.get('signer-import.json')
    require(imported['contract']==expected and imported['pubkey']==pubkey and imported['phase']=='complete',
            'original signer import is incomplete')
    imported['ever_authorized']=True;state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))


def adopt_legacy(state,expected,plan,pubkey,value):
    """One explicit stopped conversion of the retained native DB, never its initial backup."""
    state.check(expected);imported=state.get('signer-import.json');legacy=state.get('legacy-signer.json')
    complete=state.get('legacy-migration-complete.json');observed=identity(state,expected,plan,durable=True)
    require(imported['contract']==expected and imported['pubkey']==pubkey and imported['phase']=='legacy'
            and imported['ever_authorized'] is True and legacy['contract']==expected and legacy['pubkey']==pubkey
            and complete['contract']==expected and complete['records']==legacy['records'] and legacy['database']==observed,
            'original legacy signing history cannot be reconstructed from another database')
    current=summary(value,expected['network'],pubkey)
    # The retained import is only a known lower bound, never a replacement DB.
    initial=state.get('legacy-history-input.json')['history']
    dominates(current,summary(initial,expected['network'],pubkey))
    if state.exists('signer-history.json'):
        previous=verify_identity(state,expected,plan,pubkey);dominates(current,previous['summary'])
    record={'contract':expected,'pubkey':pubkey,'identity':observed,'summary':current,'export_sha256':digest(encoded(value))}
    state.put('signer-history.json',record);synchronize(state.path('signer-history.json'));return record
