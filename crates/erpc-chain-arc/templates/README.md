# Arc node plays

The plays and templates an Arc RPC node runs to set itself up, carried in the
erpc binary. erpc wrote them; nothing here is vendored. A run's bundle holds
this tree plus an `inventory.yml` and the `vars/` erpc makes for the run.

The separate `ansible/arc-validator/` plays carry the dedicated preparation
profile from `validator/`. Native observer units never enable production
signing. Original account/volume/custody receipts, per-operation cancellation,
closed helper namespaces and exact confirmed ingress precede mutations.
Compiled bundle/entrypoint and pinned Ansible/controller tests exercise this
separate path; see `docs/arc-validator.md` for the held signing scope.

Validator startup additionally proves selected PID1 D-Bus policy before the first
credential-writing phase. Unknown loaded stop hooks never run; only original PID
identities may be drained. Append-only lifecycle events retain partial cancellation
and supersession evidence, and new explicit recovery binds a fresh durable grant.
These events do not implement consensus signing-history protection.
