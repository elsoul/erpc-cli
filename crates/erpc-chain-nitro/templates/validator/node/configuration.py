# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed Nitro v3.12.2 validator configuration without secret values.

The strategy and wallet switches are defined in staker/legacy/staker.go;
BoLD monetary defaults in staker/bold/bold_staker.go; queue persistence in
arbnode/dataposter/config/config.go; same-process block verification in
cmd/nitro/nitro.go. All were qualified at source 5f02f3f03076343061f167e81b8e82ec5518064b.
"""
import re
import scope

MODES = ('observing', 'active')


def public(wallet, phase):
    if (not isinstance(wallet, str) or not re.fullmatch('0x[0-9a-f]{40}', wallet)
            or int(wallet[2:], 16) == 0 or phase not in MODES):
        raise ValueError('invalid original BoLD wallet or runtime phase')
    active = phase == 'active'
    staker = {
        'enable': True, 'strategy': scope.STRATEGY if active else 'Watchtower',
        'disable-challenge': False, 'use-smart-contract-wallet': False,
        'only-create-wallet-contract': False, 'contract-wallet-address': '',
        'gas-refunder-address': '', 'redis-url': '', 'enable-fast-confirmation': False,
        'dangerous': {'without-block-validator': False},
        'data-poster': {
            'use-db-storage': True, 'use-noop-storage': False,
            'wait-for-l1-finality': True, 'max-mempool-transactions': 1,
            'max-mempool-weight': 1, 'allocate-mempool-balance': True,
            # ERPC policy; the transport independently enforces the same ceiling.
            'max-fee-cap-formula': '100',
            'dangerous': {'clear-dbstorage': False},
            'external-signer': {'url': ''},
        },
    }
    if active:
        # Private key is loaded ONLY from an additional protected ephemeral
        # config. It never appears in this public configuration or argv.
        staker['parent-chain-wallet'] = {
            'pathname': '', 'account': wallet, 'only-create-key': False,
        }
    result = {
        'chain': {'id': scope.CHILD_ID, 'name': scope.CHAIN_NAME, 'info-files': ['/config/chain-info.json']},
        'parent-chain': {'connection': {'url': 'https://127.0.0.1:18545'},
                         'blob-client': {'beacon-url': 'https://127.0.0.1:15052'}},
        'persistent': {'global-config': '/data', 'chain': '/data/chain'},
        'node': {
            'sequencer': False, 'batch-poster': {'enable': False},
            'parent-chain-reader': {'poll-only': True}, 'staker': staker,
            'block-validator': {
                'enable': True, 'validation-server': {'url': 'self-auth'},
                'failure-is-fatal': True, 'current-module-root': 'current',
                'pending-upgrade-module-root': 'latest',
                'block-inputs-file-path': '/data/validation-inputs',
                'dangerous': {'reset-block-validation': False},
            },
            'bold': {
                'auto-deposit': False, 'auto-increase-allowance': False,
                'rpc-block-number': 'finalized', 'enable-fast-confirmation': False,
                'delegated-staking': {'enable': False, 'custom-withdrawal-address': ''},
                'state-provider-config': {'machine-leaves-cache-path': '/data/machine-hashes-cache'},
                'api': False,
            },
        },
        # NodeConfig.Validate at the pinned source rejects PathDB whenever
        # ValidatorRequired is true, including this block-validating observer.
        'execution': {
            'sequencer': {'enable': False}, 'caching': {'state-scheme': 'hash', 'archive': False},
            'recording-database': {'mode': 'chain-tip'},
            'tx-indexer': {'tx-lookup-limit': 0},
        },
        'validation': {
            'api-public': False, 'api-auth': True, 'use-jit': True,
            'wasm': {'enable-wasmroots-check': True,
                     'allowed-wasm-module-roots': ['/home/user/nitro-legacy/machines', '/home/user/target/machines']},
        },
        'http': {'addr': '127.0.0.1', 'port': 8547, 'api': ['eth', 'net', 'web3', 'arb'], 'vhosts': ['localhost']},
        'ws': {'addr': '127.0.0.1', 'port': 8548, 'api': ['eth', 'net', 'web3', 'arb'], 'origins': ['localhost']},
        'metrics': True, 'metrics-server': {'addr': '127.0.0.1', 'port': 6070},
        'init': {'latest': '' if active or scope.SNAPSHOT_BASE is None else 'pruned', 'latest-base': scope.SNAPSHOT_BASE or '',
                 'validate-checksum': True, 'force': False,
                 'validate-genesis-assertion': True, 'download-path': '/data/downloads'},
        'conf': {'dump': False},
    }
    if scope.GENESIS_DOCUMENT is not None:
        result['init']['genesis-json-file']='/config/genesis.json'
    return result
