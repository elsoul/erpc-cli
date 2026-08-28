# Security policy

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository. Do not
open a public issue for suspected vulnerabilities, leaked credentials, or
customer data.

Include affected versions, impact, reproduction steps, and any suggested
mitigation. Remove API keys, access tokens, refresh credentials, customer
identifiers, and private service details unless the secure reporting channel
explicitly requires them.

## Supported versions

Before the first stable release, security fixes are applied to the latest
published preview only. A supported-version table will be added with the first
stable release.

## Deployment security boundary

`erpc deploy` connects only to a node explicitly listed in the user's private
`~/.erpc/config.toml`. The CLI uses OpenSSH host-key verification and
non-interactive authentication; it never stores SSH private keys, passwords, or
Cloud credentials in an application manifest.

The local build and artifact validation complete before the first SSH command.
Remote activation requires Linux, systemd, and either root or passwordless
`sudo`. Applications run as the unprivileged `erpc-app` service account with
systemd hardening. A failed activation restores the previous service unit and
release when one exists.

Operators remain responsible for securing the target host, reviewing its SSH
host key, limiting the deployment user's sudo permissions, and protecting any
application secrets supplied outside this CLI.
