// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";
import { resolveLatest } from "../src/releases.ts";

if (!process.env.GH_TOKEN || !process.env.GITHUB_OUTPUT) {
  throw new Error("release selection requires the workflow token and output file");
}
const selected = await resolveLatest("elsoul/erpc-cli", (url, init) => fetch(url, {
  ...init,
  redirect: "error",
  headers: { ...init.headers, authorization: `Bearer ${process.env.GH_TOKEN}` },
}));
if (!selected) throw new Error("could not select a published GitHub release; deployment stopped");
appendFileSync(process.env.GITHUB_OUTPUT, `tag=${selected.tag}\nsource=${selected.source}\n`);
console.log(`Selected ${selected.tag} (${selected.source})`);
