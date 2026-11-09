# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed Robinhood mainnet Defensive scope; sealed at bundle assembly.

Neither request fields nor environment variables select namespaces, strategy or
parent chains. This entire module is included in the immutable helper digest.
"""
FAMILY = 'robinhood'
NETWORK = 'mainnet'
ROLE = 'defensive-validator'
NAMESPACE = 'robinhood-mainnet-validator'
ROOT = '/var/lib/erpc-robinhood-mainnet-validator'
PARENT = 'mainnet'
PARENT_ID = 1
CHILD_ID = 4663
CHAIN_NAME = 'Robinhood Chain'
STRATEGY = 'Defensive'
PUBLIC_RESULT = 'erpc-robinhood-defensive-result-v1'
ACCOUNTS = {'node': ('erpc-rh-mainnet-node', '/var/lib/erpc-rh-mainnet-node'), 'transport': ('erpc-rh-mainnet-l1', '/var/lib/erpc-rh-mainnet-l1')}
SERVICES = {'node': 'erpc-robinhood-nitro.service', 'transport': 'erpc-robinhood-upstreams.service', 'firewall': 'erpc-robinhood-firewall.service'}
CREDENTIAL_PREFIX = 'robinhood-mainnet-defensive'
OWNER_PHASE = 'robinhood-defensive-v1'
LEGACY_OWNER_PHASE = None
VERSION = '3.12.2'
COMMIT = '5f02f3f03076343061f167e81b8e82ec5518064b'
IMAGE = 'docker.io/offchainlabs/nitro-node@sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9'
IMAGE_ID = 'sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a'
CHAIN_DOCUMENT = ('cdn.robinhood.com', '/assets/generated_assets/hoodchain_docsite/chain-node-configs/robinhood-chain-info.json', 'cf6c0aa2bc520a28fe8983f783676bc43de94cc25a57a1cdc9b1f0afc5208f0a')
GENESIS_DOCUMENT = ('cdn.robinhood.com', '/assets/generated_assets/hoodchain_docsite/chain-node-configs/robinhood-genesis.json', '353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba')
SNAPSHOT_BASE = None
ADMISSION_KEY = 'admitted'
REQUIRES_EXISTING_STAKE = False
FOREIGN_ROOTS = ('/var/lib/erpc-nitro', '/var/lib/erpc-robinhood-testnet-validator')
BRIDGE = '0xdf8755334ce7a73ccf6b581c02ea649ae3e864b3'
ROLLUP = '0x23a19d23e89166adedbdcb432518ab01e4272d94'
WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
PARENT_GENESIS = '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'
ASSERTION_BOND_LIMIT_WEI = 10**18
