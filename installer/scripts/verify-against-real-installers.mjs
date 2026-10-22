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

  // Assert the asymmetry rather than printing it. A PowerShell installer must
  // never pass as a shell one, because the shell check is the stricter of the
  // two (`#!`), and a predicate that accepted it would mean the shebang check
  // had been lost. The reverse direction is expected to be true: a `#!` line
  // also starts with `#`, which is all the PowerShell check requires, and the
  // flavour comes from the request path, so it is recorded, not asserted.
  const other = flavor === "sh" ? "ps1" : "sh";
  const cross = looksLikeInstaller(body, other);
  if (flavor === "ps1" && cross) {
    fail(`${file} is accepted as a SHELL installer; the shebang check is gone`);
  } else {
    console.log(`     (as ${other}: ${cross}${flavor === "sh" ? ", expected" : ", correctly rejected"})`);
  }
}

// The unit-test fixtures must still look like the real thing.
//
// Compared POSITIONALLY against the fixture constants, not with
// `testSrc.includes(line)`. A substring search over the whole test file lets
// a line match anywhere, in any order, including inside the OTHER flavour's
// fixture or a comment, so it would report a match the fixture does not
// actually make.
const fixtures = {
  "erpc-installer.sh": "REAL_SH",
  "erpc-installer.ps1": "REAL_PS1",
};
const testSrc = readFileSync(resolve(here, "..", "src", "index.test.ts"), "utf8");

/** Pull the template-literal body of `const <name> = \`...\`;` out of the test file. */
function fixtureLines(name) {
  const m = new RegExp("const " + name + " = `([^`]*)`").exec(testSrc);
  if (!m) return null;
  // Drop the redacted line too. The real file has a URL there and the URL
  // filter removes it; the placeholder carries no "://" and would survive,
  // putting the two lists one line out of step. The loose substring check
  // this replaced could not see that.
  return m[1]
    .split("\n")
    .filter((l) => l.trim().length > 0 && !l.includes("://") && !l.includes("REDACTED"));
}

for (const { file } of cases) {
  const path = resolve(distrib, file);
  if (!existsSync(path)) continue;
  // Compare several lines, not one: the shell installer's first line is
  // `#!/bin/sh`, which would match forever and prove nothing. Lines carrying
  // a URL are skipped, because the fixture redacts them to keep the endpoint
  // allowlist out of it.
  const real = readFileSync(path, "utf8")
    .split("\n")
    .slice(0, 6)
    .filter((l) => l.trim().length > 0 && !l.includes("://"));
  if (real.length < 2) {
    fail(`${file} has too few comparable lines to check the fixture against`);
    continue;
  }
  const fixture = fixtureLines(fixtures[file]);
  if (fixture === null) {
    fail(`${fixtures[file]} is not a plain template literal in index.test.ts any more`);
    continue;
  }
  const n = Math.min(real.length, fixture.length);
  if (n < 2) {
    fail(`${fixtures[file]} has fewer than 2 comparable lines, so it pins nothing`);
    continue;
  }
  const diff = [];
  for (let i = 0; i < n; i += 1) {
    if (real[i] !== fixture[i]) diff.push({ line: i + 1, real: real[i], fixture: fixture[i] });
  }
  if (diff.length === 0) {
    console.log(`ok   ${fixtures[file]} matches ${file} line for line (${n} lines)`);
  } else {
    fail(
      `${fixtures[file]} no longer matches ${file}. In order, the first ${n} ` +
        `comparable lines differ at: ${JSON.stringify(diff)}`,
    );
  }
}

if (failed > 0) {
  console.error(`\n${failed} check(s) failed against the generated installers.`);
  process.exit(1);
}
console.log("\nall checks passed against the generated installers");
