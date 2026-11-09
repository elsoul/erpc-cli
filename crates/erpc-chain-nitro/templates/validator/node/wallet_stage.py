# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original root-encrypted custody before an explicit active deployment.

An observer never receives plaintext or a systemd wallet credential. Public
qualification precedes private delivery; the private stage repeats all original
host/NSS/generation checks. Active restoration first fences and drains the
original writer and preserves its signing history.
"""
import accounts
import container
import publication
import services
import custody
import history
import host
import protocol
import volumes
from storage import require, synchronize

RECORD='wallet-stage.json'
FIELDS={'contract','intent','generation','restore','mode','origin'}


def original_host(control):
    control.state.current_owner(control.expected)
    host.namespaces()
    records=accounts.verify(control.state,control.expected)
    require((control.state.root/'data.json').exists(), 'original data authority is incomplete')
    volumes.verify(control.state,control.expected,control.run)
    return records


def observer_running(control,records):
    try:
        target=control.state.guard(control.expected)
        require(target['phase']=='observing','the original runtime is not an observer')
        publication.verify(control.state,control.expected,target)
        services.transport(control.state,control.expected,records,control.run)
        services.running(control.state,control.expected,'node',control.run)
        native=control.state.get('container.json')
        require(native['contract']==control.expected and native['generation']==control.state.fence()['generation']
                and native['target']==target and native['account']==records['node'],'original observer receipt differs')
        container.prove(native,control.run,listeners=False)
        return True
    except Exception:return False


def observing(control):
    require(not (control.state.root/'signer-activated.json').exists(),
            'an activated signer cannot use observing custody staging')
    value=control.observe()
    require(value.get('phase')=='observing' and value.get('local_validation_ready') is True,
            'first custody staging requires the original healthy observer')
    require(control.parent_observation().get('funding_checks_passed') is True,
            'original active admission and external funding are not established')


def stopped_original(control,records):
    fence=control.state.fence()
    require(fence['stopped'] and fence['intent'] is None,
            'original active recovery requires a completed explicit stop')
    control.state.require_not_cancelled(control.expected,fence['generation'])
    control.quiet()
    saved=history.verify(control.state,control.expected,records['node'],control.quiet)
    require(saved.get('origin')==custody.origin(control.state,control.expected),
            'original signing history and custody origin differ')


def authorize(control,intent,restore):
    protocol.token(intent)
    require(type(restore) is bool,'invalid original custody recovery choice')
    control.state.current_owner(control.expected)
    activated_path=control.state.root/'signer-activated.json'
    activated=activated_path.exists() or activated_path.is_symlink()
    if restore and activated:
        # Drain by retained original process authority, before current NSS or
        # damaged ciphertext can prevent emergency shutdown.
        control.stop()
    records=original_host(control)
    if restore and activated:stopped_original(control,records)
    origin_path=control.state.root/'key-origin.json'
    original=custody.origin(control.state,control.expected) if origin_path.exists() or origin_path.is_symlink() else None
    if restore:require(original is not None,'original key origin is required for explicit restoration')
    if not activated and not observer_running(control,records):
        return {'contract':control.expected,'wallet':control.expected['wallet'],'requires_import':False,
                'observer_required':True,'intent':intent,'restore':restore}
    if not restore and ((control.state.root/'key-current.json').exists() or (control.state.root/'key-current.json').is_symlink()):
        custody.inspect(control.state,control.expected)
        return {'contract':control.expected,'wallet':control.expected['wallet'],'requires_import':False,'observer_required':False,'intent':intent,'restore':False}
    require(restore or not activated,'missing active custody requires explicit original restoration')
    if original is None:
        require(not (control.state.root/'key-current.json').exists()
                and (not host.CUSTODY.exists() or not any(host.CUSTODY.iterdir())),
                'orphan original wallet material cannot be adopted')
    mode='stopped-active' if activated else 'observing'
    if mode=='observing':observing(control)
    fence=control.state.fence()
    control.state.require_not_cancelled(control.expected,fence['generation'])
    value={'contract':control.expected,'intent':intent,'generation':fence['generation'],
           'restore':restore,'mode':mode,'origin':original}
    control.state.put(RECORD,value)
    synchronize(control.state.root/RECORD)
    check(control,intent,restore)
    return {'contract':control.expected,'wallet':control.expected['wallet'],'requires_import':True,'observer_required':False,'intent':intent,'restore':restore}


def check(control,intent,restore):
    records=original_host(control)
    value=control.state.get(RECORD)
    require(isinstance(value,dict) and set(value)==FIELDS and value['contract']==control.expected
            and value['intent']==protocol.token(intent) and type(restore) is bool and value['restore']==restore
            and value['mode'] in ('observing','stopped-active'), 'original custody staging permission differs')
    fence=control.state.fence()
    require(value['generation']==fence['generation'],'original custody staging was cancelled or superseded')
    control.state.require_not_cancelled(control.expected,fence['generation'])
    if value['origin'] is not None:
        require(custody.origin(control.state,control.expected)==value['origin'],'original custody origin changed')
    if value['mode']=='observing':observing(control)
    else:
        require(restore,'active original staging requires explicit recovery')
        stopped_original(control,records)
    return value


def install(control,intent,restore,raw):
    guard=lambda:check(control,intent,restore)
    guard()
    # Only root-only encrypted files are written. No stage_runtime, authority
    # grant, native startup or mode transition is available in this path.
    return custody.import_authorized(control.state,control.expected,intent,raw,guard,guard,restore)
