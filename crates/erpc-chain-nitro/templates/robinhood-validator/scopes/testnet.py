# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed Robinhood testnet Defensive scope; sealed at bundle assembly.

Neither request fields nor environment variables select namespaces, strategy or
parent chains. This entire module is included in the immutable helper digest.
"""
FAMILY = 'robinhood'
NETWORK = 'testnet'
ROLE = 'defensive-validator'
NAMESPACE = 'robinhood-testnet-validator'
ROOT = '/var/lib/erpc-robinhood-testnet-validator'
PARENT = 'sepolia'
PARENT_ID = 11155111
CHILD_ID = 46630
CHAIN_NAME = 'Robinhood Chain Sepolia'
STRATEGY = 'Defensive'
PUBLIC_RESULT = 'erpc-robinhood-defensive-result-v1'
ACCOUNTS = {'node': ('erpc-rh-testnet-node', '/var/lib/erpc-rh-testnet-node'), 'transport': ('erpc-rh-testnet-l1', '/var/lib/erpc-rh-testnet-l1')}
SERVICES = {'node': 'erpc-robinhood-nitro.service', 'transport': 'erpc-robinhood-upstreams.service', 'firewall': 'erpc-robinhood-firewall.service'}
CREDENTIAL_PREFIX = 'robinhood-testnet-defensive'
OWNER_PHASE = 'robinhood-defensive-v1'
LEGACY_OWNER_PHASE = None
VERSION = '3.12.2'
COMMIT = '5f02f3f03076343061f167e81b8e82ec5518064b'
IMAGE = 'docker.io/offchainlabs/nitro-node@sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9'
IMAGE_ID = 'sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a'
CHAIN_DOCUMENT = ('cdn.robinhood.com', '/assets/generated_assets/hoodchain_docsite/chain-node-configs/robinhood-chain-testnet-info.json', '0ad167c746c2aa9169c84a252f8c863140cdbd4fc23b571fa1041f94cabaf745')
GENESIS_DOCUMENT = None
SNAPSHOT_BASE = None
ADMISSION_KEY = 'admitted'
REQUIRES_EXISTING_STAKE = False
FOREIGN_ROOTS = ('/var/lib/erpc-nitro', '/var/lib/erpc-robinhood-mainnet-validator')
BRIDGE = '0x96295bdad104ead97cc08797b3dc68eff59ccf30'
ROLLUP = '0xdc5f8e399dbd8a9f5f87aec4c23beb12431b386d'
WETH = '0x7b79995e5f793a07bc00c21412e50ecae098e7f9'
PARENT_GENESIS = '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'
ASSERTION_BOND_LIMIT_WEI = 10**18
