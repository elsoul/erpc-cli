# Contributing

Thank you for contributing to the ERPC CLI.

## Development

The root CLI requires Deno 2.9.6. Node.js 20 and pnpm 11 are needed only when
changing or verifying the generated Node application template.

```bash
deno task fmt:check
deno task lint
deno task check
deno task test
deno task build
sh -n install
```

PowerShell changes must also parse without errors on Windows. CI runs native
binary smoke checks on Linux, macOS, and Windows.

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
- Ensure every check passes with the frozen Deno lockfile.

All releases require explicit human approval.
