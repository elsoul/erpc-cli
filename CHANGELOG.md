# Changelog

## Unreleased

- Add private `~/.erpc/config.toml` application and SSH node configuration.
- Create named applications under `~/.erpc/apps` and add `erpc app list`.
- Add `erpc deploy` with manifest discovery, Linux build gating, SSH upload,
  systemd activation, application-local Node runtime fallback, and rollback.

## 0.1.0 — Unreleased

- Add OAuth Device Authorization login with operating-system keychain storage.
- Add masked usage, capability catalog, credit snapshot, and credential-free
  resource inventory commands.
- Add interactive `erpc app init` scaffolding for Node.js with pnpm and Deno.
- Add runnable Node.js and Deno Hono examples.
- Add human-approved npm Trusted Publishing workflow.
