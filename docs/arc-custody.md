<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arc inventory and original node keys

Arc uses an Ed25519 consensus identity for its node. The RPC lifecycle does not
grant permissioned validator admission or financial authority. Keep its original
key item and public inventory binding throughout the node's lifetime.

## Public operations

`list` and the inventory portion of `status` request only the declared public
RPC fields. They do not fetch the consensus-key reference, a private key, or
whole Host/key items. Reads verify the exact network tag, item/vault identifiers,
category, title, field types and version, with a metadata recheck afterward.
Duplicate fields, concealed values in a public field, ambiguous identities and
changed versions are refused. A provider read error is never treated as a missing
field or missing key.

Use the vault's identifier rather than its mutable name. Secret references must
contain exact identifiers in the original vault and the expected field name.

## Initial reservation and interrupted creation

After the host preflight and normal confirmation, `init` first stores the public
host and the new consensus public key. Only a verified public reservation permits
that same in-memory key to be stored in its concealed item. The key item's metadata
binds it to the original inventory item. The private value is delivered on stdin,
then read back through exactly one concealed field and checked against its public
identity before the reference is bound to the inventory.

An ambiguous creation or binding error remains an error. Repeating `init` looks
for the one original key matching the existing public reservation. It does not
generate another key. If the original item cannot be confirmed, reconcile the
original provider operation before proceeding; the reservation stays intact.
A separately named new node is a new identity, not a repair or rotation of that
reservation. Retrying a completed reservation preserves its key and host binding.

Legacy key items without the newer original-inventory tag can be verified only
through their already stored exact reference, title, network scope and public
key. An incomplete new reservation cannot adopt an unbound legacy key by name.
This inventory check is not proof of original Linux account ownership or permission
to adopt a legacy host; host migration is a separate operation.

## Explicit updates and private reads

Public updates preserve the original consensus identity, host address, pinned
host key, history type and completed key reference. Only an unbound reservation
can acquire its first exact key reference. `destroy --forget` is refused before
opening the vault or host because deleting that item would unlink the original
key authority. Mutable release/access/run fields
remain updateable for full, archive and provider nodes.

Explicit writes have a narrow full-item exception: after public qualification,
ERPC reads that exact RPC inventory item into a typed snapshot whose field values
are `SecretString`. This preserves its original key reference, notes, tags and
field IDs while constructing the replacement template, then verifies the result
on readback. Unknown fields, concealed RPC inventory fields, sections, attachments
and URLs are refused before editing. The consensus key item itself is never read
as a whole item. Its public field is verified before the selected concealed seed
is requested, and metadata is checked again after the private read.

Key and template buffers use zeroizing types. The Arc adapters immediately wrap
returned provider stdout/stderr in `SecretString`; the existing generic process
transport returns ordinary output buffers before that boundary.
Provider diagnostics are not copied into errors. Private values are never command
arguments, run inventory or ordinary JSON result fields. This does not claim erasure of generic transport allocations or the provider
subprocess's internal memory.

Local serialization and before/after version checks narrow concurrent-writer
races; they are not a provider-side compare-and-swap or a global uniqueness lock.
Ambiguous writes never trigger rollback, item deletion or key regeneration.
The [official 1Password item reference](https://www.1password.dev/cli/reference/management-commands/item)
documents selected field reads and stdin JSON templates. ERPC does not assume
that a partial template retains omitted fields or that a failed selector proves
absence. No live vault item is required by the offline regression tests.
