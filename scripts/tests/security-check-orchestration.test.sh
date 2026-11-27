#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(dirname "$0")/../.."

test_name=node::server_security::tests::production_security_check_gates_ssh_and_metered_submission
output=$(cargo test --locked -p erpc --bin erpc --features security-check-pilot "$test_name" -- --exact)
printf '%s\n' "$output"
if [[ "$output" != *"1 passed; 0 failed"* ]]; then
  echo "Security Check orchestration test did not run" >&2
  exit 1
fi
