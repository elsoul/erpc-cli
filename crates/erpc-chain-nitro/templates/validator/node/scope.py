# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed Arbitrum One scope; alternate profiles are sealed at bundle assembly.

Neither request fields nor environment variables select namespaces, strategy or
parent chains. This entire module is included in the immutable helper digest.
"""
FAMILY = 'arbitrum'
NETWORK = 'mainnet'
ROLE = 'assertion-validator'
NAMESPACE = 'arbitrum-validator'
ROOT = '/var/lib/erpc-nitro'
PARENT = 'mainnet'
PARENT_ID = 1
CHILD_ID = 42161
CHAIN_NAME = 'arb1'
STRATEGY = 'MakeNodes'
PUBLIC_RESULT = 'erpc-arbitrum-public-result-v1'
ACCOUNTS = {'node': ('erpc-nitro-validator', '/var/lib/erpc-nitro-validator'),
            'transport': ('erpc-nitro-validator-l1', '/var/lib/erpc-nitro-validator-l1')}
SERVICES = {'node': 'erpc-arbitrum-nitro.service', 'transport': 'erpc-arbitrum-upstreams.service',
            'firewall': 'erpc-arbitrum-firewall.service'}
CREDENTIAL_PREFIX = 'arbitrum'
OWNER_PHASE = 'assertion-validator-v2'
LEGACY_OWNER_PHASE = 'assertion-validator-v1'
VERSION = '3.12.2'
COMMIT = '5f02f3f03076343061f167e81b8e82ec5518064b'
IMAGE = 'docker.io/offchainlabs/nitro-node@sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9'
IMAGE_ID = 'sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a'
CHAIN_DOCUMENT = ('raw.githubusercontent.com', '/OffchainLabs/nitro/5f02f3f03076343061f167e81b8e82ec5518064b/cmd/chaininfo/arbitrum_chain_info.json',
                  'd7e8b87f078b10178a0ef03e809d3dad93a2583f6e181cc50f12368b57e58cdc')
GENESIS_DOCUMENT = None
SNAPSHOT_BASE = 'https://snapshot.arbitrum.foundation/'
ADMISSION_KEY = 'permissionless'
REQUIRES_EXISTING_STAKE = True
FOREIGN_ROOTS = ()
