<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Solana public registration checks

`erpc v --chain solana registration` reads the named validator's public
identity, vote-account address and withdrawal authority from its network
inventory. It requests only the selected item's five public fields, without
retrieving Host items, signer references or whole item documents. Metadata
listings before and after the projection bind the exact scope, name and item
version; ambiguous fields or changed metadata are refused. It observes the selected official public RPC and either reports
account state, validates it, or emits public intent for an external signing
tool. It does not load keypair fields, construct a signed transaction, submit
one, or activate a node.

Supply an explicit network, inventory name, expected native BLS public key and
commission percentage. Derive the public BLS key using the qualified native
`solana-keygen bls_pubkey` command with your authorized-voter keypair in your
external signing environment. The public key argument is an assertion to
compare with the account, not proof that ERPC possesses the signer.

```sh
erpc v --chain solana -n mainnet --name validator registration \
  --action status --bls <public-bls-key> --commission 5
erpc v --chain solana -n mainnet --name validator registration \
  --action validate --bls <public-bls-key> --commission 5
```

`status` reports a missing account or authority mismatch without treating it as
an RPC failure. `validate` succeeds only when the account exists and the node
identity, current voter, future voter schedule, withdrawal authority,
commission and BLS key match. The recommended profile uses the node identity
as authorized voter and a distinct external withdrawal authority. Fractional
basis-point commission profiles are refused, since this interface deliberately
requires an integer percentage.

Both actions check the genesis hash, finalized block freshness, account owner
and parsed vote-account type. Epoch observations surround the account read;
a changed epoch or backwards context requires a retry. This is a bounded
public RPC observation, not an atomic historical snapshot or cryptographic
proof. Public endpoint throttling, missing block timestamps and unsupported
parsed-account formats fail without substituting another endpoint.

## Prepare external actions

`--action prepare --step <step>` uses the same public observation and emits
JSON intent. All lamport amounts are exact decimal strings in the output.
The output records the expected genesis hash, qualified native CLI version and
source commit. It is not a serialized transaction or an admission guarantee.

| Step | Additional inputs | Required account state |
| --- | --- | --- |
| `create-vote` | None | Explicitly absent at the reserved address; the external native CLI quotes rent and selects the currently supported instruction |
| `register-bls` | None | Existing account with the reserved authorities and commission; an already registered different BLS key is refused |
| `fund-identity` | `--amount-lamports` | Any existing vote account must match its reserved authorities |
| `fund-vote` | `--amount-lamports` | Existing matching vote account; destination is its reserved address |
| `withdraw-vote` | `--amount-lamports`, `--recipient`, `--admission-reserve-lamports` | Existing matching account; remaining balance covers observed rent, pending delegator rewards and the explicit reserve |

For example, to prepare the native BLS registration after external vote-account
creation:

```sh
erpc --json v --chain solana -n mainnet --name validator registration \
  --action prepare --step register-bls --bls <public-bls-key> --commission 5
```

Inspect the public intent, then construct, quote, sign and submit using official
external tooling. Recheck genesis, current authorities, native instruction
feature availability, BLS proof, rent and transaction fees immediately before
signing. Run `validate` again after confirmation. The `vote-account` command
remains a separate testnet transaction workflow for validators recorded on the
Solv backend and is refused for a native validator; this registration interface
does not enable mainnet submission through it.

For withdrawals, the admission reserve is an explicit operator-selected amount,
not an ERPC protocol-fee quote. The external signer must verify the current
network's admission fee and epoch requirements before signing, and increase
the reserve if necessary. The CLI adds current rent and native pending
delegator rewards to that reserve and rejects overflow or an insufficient
remaining balance. Future rewards are not assumed. Identity funding and
vote-account funding are distinct operations with fixed recipients.

## Primary sources

The source this command records in its intent is Agave `v4.3.2`, commit
`a203300045b405f86c9c84308b2eae76af69ac3b`, for Mainnet and `v4.4.0-beta.1`, commit
`3ad9da2c390eb7ad2630ed15afcd463e72e007a8`, for Testnet. Both pinned sources expose
the same public vote-account decoder layout used here. These pins identify the
decoder profile, not the release a native node runs, which is the one in the
[native guide](solana-native.md); ERPC does not execute a native CLI during these
observations.

- [Agave public vote-account decoder, Mainnet source](https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/account-decoder/src/parse_vote.rs)
- [Agave public vote-account decoder, Testnet source](https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/account-decoder/src/parse_vote.rs)
- [Official vote-account and BLS management](https://docs.anza.xyz/operations/guides/vote-accounts/)
- [Official account context and encoding](https://solana.com/docs/rpc/http/getaccountinfo)
- [Official finalized epoch context](https://solana.com/docs/rpc/http/getepochinfo)

The source-build and native-history requirements for node deployment are
recorded in the [Solana chain reference](chains/solana.md).
