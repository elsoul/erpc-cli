// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the installer worker's body check.
 *
 * The fixtures are the real first lines of the artifacts
 * `dist build --artifacts=global` produces with the cargo-dist version pinned
 * in `dist-workspace.toml`, not the shapes the upstream template suggests. An
 * earlier version of this predicate was written from the template, required
 * `<#` at position 0, and would have returned 502 for every PowerShell
 * install; only a fixture taken from a generated artifact catches that.
 *
 *   npm test        (node --test, no dependencies)
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { looksLikeInstaller } from "./index.ts";

// Verbatim from target/distrib/erpc-installer.sh
const REAL_SH = `#!/bin/sh
# shellcheck shell=dash
# shellcheck disable=SC2039  # local is non-POSIX
`;

// The first lines of target/distrib/erpc-installer.ps1. The licence URL on
// the second line is replaced with a placeholder: the shape under test is the
// leading run of `#` comments before the `<#` block, and a literal URL here
// would have to be declared in the endpoint allowlist for no reason.
const REAL_PS1 = `# Licensed under the MIT license
# <LICENSE-MIT or LICENCE-URL-REDACTED-FOR-THE-ENDPOINT-GATE>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

<#
.SYNOPSIS
`;

test("accepts the shell installer cargo-dist really generates", () => {
  assert.equal(looksLikeInstaller(REAL_SH, "sh"), true);
});

test("accepts the PowerShell installer cargo-dist really generates", () => {
  assert.equal(looksLikeInstaller(REAL_PS1, "ps1"), true);
});

test("accepts a PowerShell installer that opens with its block comment", () => {
  assert.equal(looksLikeInstaller("<#\n.SYNOPSIS\n#>\n", "ps1"), true);
});

test("rejects an HTML error page for either flavour", () => {
  const html = "<!DOCTYPE html>\n<html><body>Not Found</body></html>";
  assert.equal(looksLikeInstaller(html, "sh"), false);
  assert.equal(looksLikeInstaller(html, "ps1"), false);
  assert.equal(looksLikeInstaller("<html>x</html>", "ps1"), false);
  assert.equal(looksLikeInstaller('<?xml version="1.0"?><Error/>', "sh"), false);
});

test("rejects an empty or whitespace body", () => {
  assert.equal(looksLikeInstaller("", "sh"), false);
  assert.equal(looksLikeInstaller("   \n\n", "ps1"), false);
});

test("rejects a plain-text error body", () => {
  assert.equal(looksLikeInstaller("Not Found", "sh"), false);
  assert.equal(looksLikeInstaller("Not Found", "ps1"), false);
});

test("does not accept a PowerShell installer as a shell one", () => {
  assert.equal(looksLikeInstaller(REAL_PS1, "sh"), false);
});
