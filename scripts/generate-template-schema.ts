#!/usr/bin/env -S deno run --allow-read --allow-write=schemas
// Generates schemas/erpc-template.v1.schema.json from the Zod schema in
// src/app/template-manifest.ts, which remains the source of truth.
// `--check` verifies the committed file matches without writing to it;
// `deno task schema:check` runs that mode so drift fails release:check.

import { z } from '@zod/zod'
import { templateManifestSchema } from '../src/app/template-manifest.ts'

const OUTPUT_URL = new URL(
  '../schemas/erpc-template.v1.schema.json',
  import.meta.url,
)

const buildSchemaDocument = (): Record<string, unknown> => {
  const jsonSchema = z.toJSONSchema(templateManifestSchema) as Record<
    string,
    unknown
  >
  return {
    ...jsonSchema,
    $id: 'https://storage.erpc.global/schemas/erpc-template/v1.json',
    title: 'erpc-template.json v1',
  }
}

const serialize = (document: unknown): string =>
  `${JSON.stringify(document, null, 2)}\n`

const main = async (): Promise<void> => {
  const check = Deno.args.includes('--check')
  const generated = serialize(buildSchemaDocument())

  if (!check) {
    await Deno.writeTextFile(OUTPUT_URL, generated)
    console.log(`Wrote ${OUTPUT_URL}`)
    return
  }

  let existing: string
  try {
    existing = await Deno.readTextFile(OUTPUT_URL)
  } catch {
    console.error(`Missing generated schema file: ${OUTPUT_URL}`)
    Deno.exit(1)
  }
  if (existing !== generated) {
    console.error(
      'schemas/erpc-template.v1.schema.json is out of date. Run: ' +
        'deno run --allow-read --allow-write=schemas scripts/generate-template-schema.ts',
    )
    Deno.exit(1)
  }
  console.log('schemas/erpc-template.v1.schema.json is up to date.')
}

if (import.meta.main) await main()
