# Changelog

## Unreleased

## 0.2.1 — 2026-08-28

- Rebuild the command interface with a typed declarative parser and generated,
  command-specific help.
- Print the colored ERPC welcome artwork after installation and with
  `erpc --print`.

## 0.2.0 — 2026-08-28

- Move the CLI runtime and development workflow from Node.js to Deno 2.9.
- Distribute standalone Linux, macOS, and Windows executables for x86-64 and
  ARM64 from R2 with checksum-verifying, non-root installers.
- Use the Linux Secret Service for refresh credential storage without a native
  npm dependency.
- Download and verify a pinned application-local Node.js runtime when a target
  node needs one.
- Add private `~/.erpc/config.toml` application and SSH node configuration.
- Create named applications under `~/.erpc/apps` and add `erpc app list`.
- Add `erpc deploy` with manifest discovery, Linux build gating, SSH upload,
  systemd activation, application-local Node runtime fallback, and rollback.

## 0.1.0 — 2026-08-28

- Add OAuth Device Authorization login with operating-system keychain storage.
- Add masked usage, capability catalog, credit snapshot, and credential-free
  resource inventory commands.
- Add interactive `erpc app init` scaffolding for Node.js with pnpm and Deno.
- Add runnable Node.js and Deno Hono examples.
- Publish the initial npm package.
