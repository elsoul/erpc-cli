# Roadmap

The CLI exposes only capabilities whose authorization and server contracts are
ready for public use.

## Available in 0.1

- OAuth Device Authorization login and server-side logout
- refresh credentials stored in the operating-system keychain
- monthly API-key usage
- read-only Cloud catalog, credit snapshot, and resource inventory
- `erpc app init` templates for Node.js with pnpm and Deno
- private `~/.erpc` configuration and application discovery
- local Linux build-gated SSH deployment with systemd activation and rollback

## Planned

- inspect and validate `erpc.toml` without deploying
- resolve owned Cloud compute resources into deployment targets without
  exposing infrastructure credentials
- managed artifact upload and deployment through the ERPC control plane
- resource provisioning and hourly billing controls
- deployment logs, status, rollback, and health checks
- Rust application templates
- additional application runtimes based on demand

Write, billing, and deployment commands will be added only after their scoped
authorization, confirmation, idempotency, and recovery contracts are available.
