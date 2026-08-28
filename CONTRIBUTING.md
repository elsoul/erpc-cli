# Contributing

Thank you for contributing to the ERPC CLI.

## Development

Requirements:

- Node.js 20 or newer
- Corepack
- pnpm 11

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm check
corepack pnpm test
corepack pnpm build
corepack pnpm pack:check
```

Keep changes focused and cover observable behavior with tests. Public APIs must
use explicit exports and strict TypeScript types. Generated templates and the
checked-in examples must stay synchronized.

Never log, persist in project files, or include OAuth credentials in errors,
fixtures, snapshots, examples, or `erpc.toml`. Refresh credentials belong only
in the operating-system keychain. Do not add Cloud write commands until their
documented scopes, confirmation, idempotency, and recovery behavior are ready.

## Pull requests

- Explain user-visible behavior and compatibility impact.
- Update the README and roadmap when commands or runtimes change.
- Verify both Node.js and Deno examples when templates change.
- Ensure every check passes from a clean install.

All releases require explicit human approval.
