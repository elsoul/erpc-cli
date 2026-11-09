<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Robinhood validator admission

`erpc v --chain robinhood registration` observes the public validator allowlist
and prepares an unsigned administrator call for external review. Select an
existing Robinhood RPC inventory host with `--name` and its network explicitly.
The host must have a settled ERPC RPC installation and original encrypted L1
provider configuration. Both parent execution and beacon endpoints must use
public HTTPS; this command refuses plaintext and loopback providers.

Use the prospective validator's public EOA address. No signing key is required.
Replace the example name, address and SSH public-key path with your public inputs:

```sh
erpc --json v --chain robinhood registration --network testnet --name rh-rpc --validator-address <public-address> --ssh-key <key.pub> --action status
erpc --json v --chain robinhood registration --network testnet --name rh-rpc --validator-address <public-address> --ssh-key <key.pub> --action prepare > admission.json
erpc --json v --chain robinhood registration --network testnet --name rh-rpc --validator-address <public-address> --ssh-key <key.pub> --action validate --file admission.json
```

Use `--network mainnet` for mainnet and `--vault` to select the inventory vault.
Keep the same network, RPC inventory host and validator address for preparation
and validation. `prepare` prints the public intent directly; pass that JSON file
to `validate`. Validate again shortly before external review. A saved observation
expires after 30 minutes, and its block number, hash and timestamp must still
match the authenticated parent chain. Validation also makes a fresh observation.

## Interpreting results

The command checks the original RPC owner, installed client pin and provider
configuration before and after observation. Its sealed helper makes read-only
parent-chain requests at one finalized block. It checks the parent chain ID and
genesis, the official Bridge-to-Rollup relationship, child chain ID, bridge,
staking token, allowlist status and paused state. The validator address must
have no deployed code at that block. A changed finalized header is refused.
Provider credentials remain in the host-side observation process; public output
is bound to the exact run, compiled helper bundle and request.

`status` returns a nonzero problem result when the address is not admitted or the
rollup is paused. `admitted` means allowlisted or permissionless at the observed
block. It does not establish a running validator or authorize activation.
`base_stake_wei` is an observed protocol parameter, not a verified total bond
budget, funding balance or gas limit.

`prepare` constructs the single-address `setValidator(address[],bool[])` call
with the flag set to `true`, zero ETH value and the pinned Rollup target. The
intent identifies the parent and child chains and the public validator address.
It is intended for the chain administrator's review. The administrator must
verify the deployed implementation and current administrator/executor route and
authority before signing externally. The prospective validator cannot
self-register merely by having this JSON or funding its address.

`validate` reports `intent_matches_current_observation` only after the intent's
closed fields, canonical calldata and saved parent snapshot pass verification.
The returned `administrator_authority_verified`,
`deployed_implementation_verified`, `activation_authorized` and
`financial_action_performed` fields remain false. Validation is not permission
to sign, pay, stake or activate. ERPC does not send the prepared transaction.

## Source qualification

Network identities come from the chain-info files linked by the
[official Robinhood node guide](https://docs.robinhood.com/chain/run-a-full-node/),
read on 2026-10-29. The mainnet and testnet bytes are independently pinned in the
[admission catalog](../crates/erpc-chain-nitro/templates/robinhood-admission/node/catalog.json)
and checked against the RPC network catalog. Mainnet is chain 4663 on Ethereum;
testnet is chain 46630 on Sepolia. The administrator calldata follows
[the pinned Nitro Rollup administrator interface](https://github.com/OffchainLabs/nitro-contracts/blob/4341b132cfbdcc980ead03765ca5224ff6cb5d97/src/rollup/RollupAdminLogic.sol).
A source ABI is not evidence of the current deployed implementation or its
administrator. See the [chain source map](chains/robinhood.md) and
[RPC operator guide](nitro-rpc.md) for client selection and node operation.

Offline tests exercise both networks through the compiled request, Ansible
stdin, carried entry point, public result and intent roundtrip. They also cover
foreign ownership, credential failures, restricted providers, changed original
configuration, stale/forked parent observations and modified intent fields.
These checks do not substitute for later real-host and live-provider acceptance.
