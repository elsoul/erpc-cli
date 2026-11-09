# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stopped original provider recovery without trusting the unavailable old secret."""
import credentials
import history
import protocol
import wallet_stage
from storage import require, synchronize

RECORD='provider-stage.json'


def stopped(control):
    records=wallet_stage.original_host(control)
    fence=control.state.fence()
    require(fence['stopped'] and fence['intent'] is None,
            'provider recovery requires completed original shutdown')
    control.state.require_not_cancelled(control.expected,fence['generation'])
    control.quiet()
    path=control.state.root/'signer-activated.json'
    if path.exists() or path.is_symlink():
        history.verify(control.state,control.expected,records['node'],control.quiet)
    return fence


def authorize(control,intent):
    protocol.token(intent);control.state.current_owner(control.expected)
    # Retained numeric authority drains before current NSS or a broken provider
    # can block shutdown. No provider plaintext is needed to retain history.
    control.stop()
    fence=stopped(control)
    control.state.put(RECORD,{'contract':control.expected,'intent':intent,'generation':fence['generation']})
    synchronize(control.state.root/RECORD)
    check(control,intent)
    return {'contract':control.expected,'intent':intent,'requires_import':True}


def check(control,intent):
    fence=stopped(control);value=control.state.get(RECORD)
    require(value=={'contract':control.expected,'intent':protocol.token(intent),'generation':fence['generation']},
            'provider recovery was cancelled or superseded')
    return value


def install(control,intent,raw):
    guard=lambda:check(control,intent)
    guard()
    result=credentials.install_authorized(control.state,control.expected,intent,raw,guard,
                                           validate=control.provider_observation)
    # This is the existing bounded, read-only fixed-chain/protocol observer.
    # Funding may still need external preparation; automatic sends stay fenced.
    control.parent_observation()
    guard()
    return result
