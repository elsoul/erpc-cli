// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Assert that the worker's body check accepts the installers cargo-dist
 * really produces, and that the test fixtures still match their first bytes.
 *
 * The unit tests use hand-copied fixtures. That is what made the round-4
 * defect possible: the predicate was written from the upstream template, the
 * real PowerShell installer opens differently, and nothing compared the two.
 * This script closes that loop and must run whenever the cargo-dist version
 * or the installer sources change.
 *
 *   dist build --artifacts=global
 *   node installer/scripts/verify-against-real-installers.mjs
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const distrib = resolve(repoRoot, "target", "distrib");

const { looksLikeInstaller } = await import(resolve(here, "..", "src", "index.ts"));

const cases = [
  { file: "erpc-installer.sh", flavor: "sh" },
  { file: "erpc-installer.ps1", flavor: "ps1" },
];

let failed = 0;
const fail = (msg) => {
  console.error(`FAIL ${msg}`);
  failed += 1;
};

for (const { file, flavor } of cases) {
  const path = resolve(distrib, file);
  if (!existsSync(path)) {
    fail(`${file} is missing from ${distrib}. Run: dist build --artifacts=global`);
    continue;
  }
  const body = readFileSync(path, "utf8");
  const head = JSON.stringify(body.slice(0, 40));

  if (looksLikeInstaller(body, flavor)) {
    console.log(`ok   ${file} is accepted as ${flavor} (starts ${head})`);
  } else {
    fail(
      `${file} is REJECTED as ${flavor}. The worker would return 502 for every ` +
        `install on this path. It starts ${head}`,
    );
  }

  // The other flavour's filename is never requested, but a shell installer
  // accepted as PowerShell would hide a mix-up, so record the asymmetry.
  const other = flavor === "sh" ? "ps1" : "sh";
  console.log(`     (as ${other}: ${looksLikeInstaller(body, other)})`);
}

// The unit-test fixtures must still look like the real thing.
const testSrc = readFileSync(resolve(here, "..", "src", "index.test.ts"), "utf8");
for (const { file } of cases) {
  const path = resolve(distrib, file);
  if (!existsSync(path)) continue;
  const firstLine = readFileSync(path, "utf8").split("\n")[0];
  if (testSrc.includes(firstLine)) {
    console.log(`ok   the fixture for ${file} still matches its first line`);
  } else {
    fail(
      `the fixture for ${file} no longer matches the generated artifact. ` +
        `Its first line is now ${JSON.stringify(firstLine)}; update index.test.ts.`,
    );
  }
}

if (failed > 0) {
  console.error(`\n${failed} check(s) failed against the generated installers.`);
  process.exit(1);
}
console.log("\nall checks passed against the generated installers");
