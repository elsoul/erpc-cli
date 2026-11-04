#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Cleanly stop only a container bearing this host's exact immutable owner labels."""
import json
import os
import re
import sys

import rollup_control as c


def prepare(family, role):
    c.require(os.geteuid() == 0 and family in {'optimism', 'soneium'} and role in {'execution', 'consensus'}, 'invalid container ownership request')
    state = c.read_state()
    c.require(state['contract']['family'] == family, 'container family differs from owner')
    c.guard(state, role)
    stop_owned(state, role)


def stop_owned(state, role):
    family = state['contract']['family']
    c.require(family in {'optimism', 'soneium'} and role in {'execution', 'consensus'}, 'invalid container role')
    conf, _, _ = c.paths(state['contract'])
    docker = ['docker', '--config', str(conf / 'docker')]
    name = 'erpc-' + family + '-' + role
    raw = c.run(docker + ['container', 'inspect', name], allowed=(0, 1))
    c.require(raw.strip(), 'container daemon did not return an inspection result')
    values = json.loads(raw)
    if not values:
        return
    c.require(isinstance(values, list) and len(values) == 1, 'ambiguous owned container')
    value = values[0]
    c.require(value.get('Name') == '/' + name, 'wrong container selected')
    labels = value.get('Config', {}).get('Labels', {})
    for field in ('owner', 'family', 'network', 'history'):
        c.require(labels.get('erpc.' + field) == state['contract'][field], 'unowned or cross-network container exists')
    identity = value.get('Id')
    c.require(isinstance(identity, str) and re.fullmatch('[a-f0-9]{64}', identity), 'invalid owned container identifier')
    # A lost Docker CLI must not leave an orphan operating the database while a
    # replacement is started. Shutdown remains graceful and bounded.
    if value.get('State', {}).get('Running'):
        c.run(docker + ['container', 'stop', '--time', '600', identity], timeout=660)
    after = c.run(docker + ['container', 'inspect', identity], allowed=(0, 1))
    c.require(after.strip(), 'container shutdown could not be verified')
    remaining = json.loads(after)
    if remaining:
        c.require(len(remaining) == 1 and remaining[0].get('Id') == identity and remaining[0].get('State', {}).get('Running') is False, 'owned container is still running')
        c.run(docker + ['container', 'rm', identity])
    final = c.run(docker + ['container', 'inspect', name], allowed=(0, 1))
    c.require(final.strip() and json.loads(final) == [], 'a replacement container appeared during shutdown')


if __name__ == '__main__':
    try:
        c.require(len(sys.argv) == 3, 'invalid container invocation')
        prepare(*sys.argv[1:])
    except Exception:
        print('Owned container preparation refused', file=sys.stderr)
        sys.exit(1)
