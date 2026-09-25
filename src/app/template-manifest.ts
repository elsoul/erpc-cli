// `erpc-template.json` v1: Zod schema (source of truth) + semantic lint L1-L12.
// See design doc §2.1-§2.3 and Task Brief Decision 5.
//
// Validation happens in two stages, both of which run before any prompt is
// shown to the user (Acceptance A7/A8):
//   1. `parseTemplateManifest` - Zod structural validation, then the lint
//      rules that only need the manifest object (L1, L2, L3, L6, L8's naming
//      half, L9, L10, L11).
//   2. `lintTemplateFiles` - the lint rules that need the archive's raw
//      (pre-render) file bytes (L4, L5, L8's wrangler-subset half, L12).

import { parse as parseToml } from '@std/toml'
import { z } from '@zod/zod'
import { CLI_VERSION } from '../version.ts'

const KEY_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/
const RESERVED_KEYS = new Set(['app', 'broker', 'erpc'])
const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/
const APP_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
const KV_BINDING_PATTERN = /^[A-Z][A-Z0-9_]*$/
export const PLACEHOLDER_PATTERN = /\{\{([^{}]+)\}\}/g
// deno-lint-ignore no-control-regex
const CONTROL_CHARACTER_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/

export class TemplateManifestError extends Error {
  readonly issues: readonly string[]

  constructor(issues: readonly string[]) {
    super(
      `Invalid erpc-template.json:\n${
        issues.map((issue) => `  - ${issue}`).join('\n')
      }`,
    )
    this.name = 'TemplateManifestError'
    this.issues = issues
  }
}

const keySchema = z.string().regex(KEY_PATTERN)
const humanString = z.string().min(1).max(512)
const validateSchema = z.strictObject({ pattern: z.string().min(1).max(512) })

const varPromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('var'),
  question: humanString,
  default: z.string().max(512).optional(),
  validate: validateSchema.optional(),
  flag: z.enum(['domain', 'email']).optional(),
})

const derivedPromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('derived'),
  expr: humanString,
})

const brokerRegisterPromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('broker-register'),
  redirectUris: z.array(humanString).min(1),
  clientName: humanString,
  validate: validateSchema.optional(),
})

const secretGeneratePromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('secret-generate'),
  bytes: z.number().int().min(32).max(128),
  encoding: z.enum(['base64url', 'base64', 'hex']),
  required: z.boolean().optional(),
})

const secretPipePromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('secret-pipe'),
  command: z.array(z.string().min(1)).min(1),
  validate: validateSchema.optional(),
  backup: z.strictObject({
    message: z.string().min(1).max(2000),
    confirm: z.string().min(1).max(200),
  }).optional(),
  required: z.boolean().optional(),
})

const secretInputPromptSchema = z.strictObject({
  key: keySchema,
  target: z.literal('secret-input'),
  question: humanString.optional(),
  env: z.string().min(1).max(128).optional(),
  validate: validateSchema.optional(),
  required: z.boolean().optional(),
})

const promptSchema = z.discriminatedUnion('target', [
  varPromptSchema,
  derivedPromptSchema,
  brokerRegisterPromptSchema,
  secretGeneratePromptSchema,
  secretPipePromptSchema,
  secretInputPromptSchema,
])

export type VarPrompt = z.infer<typeof varPromptSchema>
export type DerivedPrompt = z.infer<typeof derivedPromptSchema>
export type BrokerRegisterPrompt = z.infer<typeof brokerRegisterPromptSchema>
export type SecretGeneratePrompt = z.infer<typeof secretGeneratePromptSchema>
export type SecretPipePrompt = z.infer<typeof secretPipePromptSchema>
export type SecretInputPrompt = z.infer<typeof secretInputPromptSchema>
export type TemplatePrompt = z.infer<typeof promptSchema>

const kvBindingSchema = z.strictObject({
  binding: z.string().regex(KV_BINDING_PATTERN),
  title: humanString,
})

const cloudflareSchema = z.strictObject({
  config: z.string().min(1),
  wrangler: z.array(z.string().min(1)).min(1),
  minWranglerVersion: z.string().min(1).optional(),
  kv: z.array(kvBindingSchema).optional(),
  preflight: z.array(z.array(z.string().min(1)).min(1)).optional(),
})

const buildSchema = z.strictObject({
  command: z.array(z.string().min(1)).min(1),
})
const brokerSchema = z.strictObject({ issuer: z.string().min(1) })
const renderEntrySchema = z.strictObject({
  path: z.string().min(1),
  format: z.enum(['toml', 'text']),
})

const postDeployHttpSchema = z.strictObject({
  kind: z.literal('http'),
  baseUrlFromVar: z.string().min(1),
  path: z.string().min(1),
  expectStatus: z.number().int(),
  expectJson: z.record(z.string(), z.unknown()).optional(),
})

const postDeployOauthSchema = z.strictObject({
  kind: z.literal('oauth-authorize-redirect'),
  baseUrlFromVar: z.string().min(1),
  issuerFromVar: z.string().min(1),
  followIssuer: z.boolean().optional(),
})

const postDeploySchema = z.discriminatedUnion('kind', [
  postDeployHttpSchema,
  postDeployOauthSchema,
])

export const templateManifestSchema = z.strictObject({
  $schema: z.string().optional(),
  schemaVersion: z.literal(1),
  name: z.string().regex(APP_NAME_PATTERN),
  runtime: z.literal('cloudflare-worker'),
  minCliVersion: z.string().min(1),
  cloudflare: cloudflareSchema,
  build: buildSchema.optional(),
  broker: brokerSchema.optional(),
  render: z.array(renderEntrySchema),
  prompts: z.array(promptSchema),
  postDeploy: z.array(postDeploySchema).optional(),
})

export type TemplateManifest = z.infer<typeof templateManifestSchema>

export const SECRET_PROMPT_TARGETS = [
  'secret-generate',
  'secret-pipe',
  'secret-input',
] as const
export type SecretPromptTarget = (typeof SECRET_PROMPT_TARGETS)[number]

export const isSecretPromptTarget = (
  target: string,
): target is SecretPromptTarget =>
  (SECRET_PROMPT_TARGETS as readonly string[]).includes(target)

/** Whether a prompt must have a value before deploy (Decision 5b / design §2.2). */
export const isPromptRequired = (prompt: TemplatePrompt): boolean => {
  if (prompt.target === 'secret-input') return prompt.required ?? false
  if (prompt.target === 'secret-generate' || prompt.target === 'secret-pipe') {
    return prompt.required ?? true
  }
  return true
}

export const requiredSecretKeys = (
  manifest: TemplateManifest,
): readonly string[] =>
  manifest.prompts
    .filter((prompt) =>
      isSecretPromptTarget(prompt.target) && isPromptRequired(prompt)
    )
    .map((prompt) => prompt.key)

export const extractPlaceholderNames = (text: string): readonly string[] =>
  [...text.matchAll(PLACEHOLDER_PATTERN)].map((match) => match[1]!.trim())

const truncate = (value: string, max = 80): string =>
  value.length > max ? `${value.slice(0, max)}...` : value

const isHttpsOrLocalhostOrigin = (value: string): boolean => {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  const isLocalHttp = url.protocol === 'http:' &&
    ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(url.hostname)
  return (url.protocol === 'https:' || isLocalHttp) &&
    url.pathname === '/' && url.search === '' && url.hash === ''
}

const parseSemverCore = (
  value: string,
): readonly [number, number, number] | null => {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(value)
  if (!match) return null
  return [Number(match[1]), Number(match[2]), Number(match[3])]
}

const satisfiesMinCliVersion = (current: string, minimum: string): boolean => {
  const currentParts = parseSemverCore(current)
  const minimumParts = parseSemverCore(minimum)
  if (!currentParts || !minimumParts) return false
  for (let index = 0; index < 3; index++) {
    if (currentParts[index]! > minimumParts[index]!) return true
    if (currentParts[index]! < minimumParts[index]!) return false
  }
  return true
}

const referencedPlaceholders = (prompt: TemplatePrompt): readonly string[] => {
  if (prompt.target === 'derived') return extractPlaceholderNames(prompt.expr)
  if (prompt.target === 'broker-register') {
    return [
      ...prompt.redirectUris.flatMap(extractPlaceholderNames),
      ...extractPlaceholderNames(prompt.clientName),
    ]
  }
  return []
}

const humanStringsOf = (manifest: TemplateManifest): readonly string[] => {
  const values: string[] = []
  if (manifest.broker) values.push(manifest.broker.issuer)
  for (const kv of manifest.cloudflare.kv ?? []) values.push(kv.title)
  for (const prompt of manifest.prompts) {
    if (prompt.target === 'var') {
      values.push(prompt.question)
      if (prompt.default !== undefined) values.push(prompt.default)
    } else if (prompt.target === 'derived') {
      values.push(prompt.expr)
    } else if (prompt.target === 'broker-register') {
      values.push(prompt.clientName, ...prompt.redirectUris)
    } else if (
      prompt.target === 'secret-input' && prompt.question !== undefined
    ) {
      values.push(prompt.question)
    } else if (prompt.target === 'secret-pipe' && prompt.backup) {
      values.push(prompt.backup.message, prompt.backup.confirm)
    }
  }
  return values
}

/** L1, L2, L3, L6, L8 (naming half), L9, L10, L11 - the manifest-only lint rules. */
const lintTemplateManifest = (manifest: TemplateManifest): void => {
  const violations: string[] = []
  const seenKeys = new Set<string>()
  const nonSecretKeysSoFar = new Set<string>()
  const secretKeys = new Set<string>()

  for (const prompt of manifest.prompts) {
    if (RESERVED_KEYS.has(prompt.key)) {
      violations.push(
        `L1: prompt key "${prompt.key}" is reserved (app, broker, erpc)`,
      )
    }
    if (seenKeys.has(prompt.key)) {
      violations.push(`L1: duplicate prompt key: ${prompt.key}`)
    }
    seenKeys.add(prompt.key)
    if (isSecretPromptTarget(prompt.target)) secretKeys.add(prompt.key)
  }

  // `{{broker.issuer}}` only resolves when a `broker` section exists
  // (steiner r1 N6); referencing it otherwise is an undefined-key reference.
  const isBuiltIn = (name: string): boolean =>
    name === 'app.name' ||
    (name === 'broker.issuer' && manifest.broker !== undefined)
  for (const prompt of manifest.prompts) {
    for (const name of referencedPlaceholders(prompt)) {
      if (isBuiltIn(name)) continue
      if (secretKeys.has(name)) {
        violations.push(
          `L3: "${prompt.key}" references secret key "${name}" in a placeholder`,
        )
        continue
      }
      if (!nonSecretKeysSoFar.has(name)) {
        violations.push(
          `L2: "${prompt.key}" references an undefined or not-yet-declared key "${name}"`,
        )
      }
    }
    if (!isSecretPromptTarget(prompt.target)) nonSecretKeysSoFar.add(prompt.key)
  }
  for (const kv of manifest.cloudflare.kv ?? []) {
    for (const name of extractPlaceholderNames(kv.title)) {
      if (isBuiltIn(name)) continue
      if (secretKeys.has(name)) {
        violations.push(
          `L3: cloudflare.kv title references secret key "${name}"`,
        )
        continue
      }
      if (!nonSecretKeysSoFar.has(name)) {
        violations.push(
          `L2: cloudflare.kv title references an undefined key "${name}"`,
        )
      }
    }
  }

  const brokerRegisterPrompts = manifest.prompts.filter((prompt) =>
    prompt.target === 'broker-register'
  )
  if (brokerRegisterPrompts.length > 1) {
    violations.push('L6: at most one broker-register prompt is allowed')
  }
  if (brokerRegisterPrompts.length > 0) {
    if (!manifest.broker) {
      violations.push(
        'L6: a broker-register prompt requires a top-level "broker" section',
      )
    } else if (!isHttpsOrLocalhostOrigin(manifest.broker.issuer)) {
      violations.push(
        `L6: broker.issuer must be an https origin: ${manifest.broker.issuer}`,
      )
    }
  }

  // At most one `var` may claim flag "domain": the --domain shorthand and the
  // L12 route-origin check both assume that flag uniquely identifies one
  // prompt (steiner r2 N-9).
  const domainFlaggedVarCount =
    manifest.prompts.filter((prompt) =>
      prompt.target === 'var' && prompt.flag === 'domain'
    ).length
  if (domainFlaggedVarCount > 1) {
    violations.push('L12: at most one var prompt may declare flag "domain"')
  }

  // `cloudflare.config` must itself be a render[] target, or any `{{...}}` it
  // contains is written to the generated app unresolved (steiner r2 N-4).
  if (
    !manifest.render.some((entry) => entry.path === manifest.cloudflare.config)
  ) {
    violations.push(
      `L12: cloudflare.config (${manifest.cloudflare.config}) must be listed in render[]`,
    )
  }

  for (const prompt of manifest.prompts) {
    if (
      isSecretPromptTarget(prompt.target) &&
      !SECRET_NAME_PATTERN.test(prompt.key)
    ) {
      violations.push(
        `L8: secret key "${prompt.key}" must match ${SECRET_NAME_PATTERN}`,
      )
    }
  }

  const commands: readonly (readonly string[])[] = [
    ...(manifest.build ? [manifest.build.command] : []),
    ...(manifest.cloudflare.preflight ?? []),
    ...manifest.prompts
      .filter((prompt): prompt is SecretPipePrompt =>
        prompt.target === 'secret-pipe'
      )
      .map((prompt) => prompt.command),
  ]
  for (const command of commands) {
    if (
      command.length === 0 ||
      command.some((argument) => argument.includes('\0'))
    ) {
      violations.push(
        'L9: a command must be a non-empty argv array with no NUL bytes',
      )
    }
  }

  for (const value of humanStringsOf(manifest)) {
    if (value.length > 512) {
      violations.push(
        `L10: a manifest string exceeds 512 characters: ${truncate(value)}`,
      )
    }
    if (CONTROL_CHARACTER_PATTERN.test(value)) {
      violations.push(
        `L10: a manifest string contains a control character: ${
          truncate(value)
        }`,
      )
    }
  }

  // Compile every `validate.pattern` at lint time so a malformed regex fails
  // here, not with a confusing runtime error during answer collection or
  // rendering (cyan r1 N5).
  for (const prompt of manifest.prompts) {
    if (prompt.target === 'derived' || prompt.target === 'secret-generate') {
      continue // these targets have no `validate` field
    }
    if (prompt.validate === undefined) continue
    try {
      new RegExp(`^(?:${prompt.validate.pattern})$`)
    } catch (error) {
      violations.push(
        `L10: "${prompt.key}" has an invalid validate.pattern: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
    }
  }

  if (!satisfiesMinCliVersion(CLI_VERSION, manifest.minCliVersion)) {
    violations.push(
      `L11: this template requires erpc-cli ${manifest.minCliVersion} or newer (running ${CLI_VERSION})`,
    )
  }

  if (violations.length > 0) throw new TemplateManifestError(violations)
}

/** Validates `erpc-template.json` structurally, then runs the manifest-only lint rules. */
export const parseTemplateManifest = (json: unknown): TemplateManifest => {
  const result = templateManifestSchema.safeParse(json)
  if (!result.success) {
    const issues = result.error.issues.map((issue) =>
      `${
        issue.path.length > 0 ? issue.path.join('.') : '(root)'
      }: ${issue.message}`
    )
    throw new TemplateManifestError(issues)
  }
  lintTemplateManifest(result.data)
  return result.data
}

/**
 * Whether `index` sits inside a double-quoted ("basic") TOML string on
 * `line`, tracking single-quoted ("literal") regions so a `'` inside one
 * doesn't get mistaken for the start of a double-quoted string (steiner r1 N5).
 * This is a line-local heuristic, not a full TOML parser.
 */
const isWithinDoubleQuotedString = (line: string, index: number): boolean => {
  let inDouble = false
  let inSingle = false
  for (let position = 0; position < index; position++) {
    const character = line[position]
    if (!inSingle && character === '"' && line[position - 1] !== '\\') {
      inDouble = !inDouble
    } else if (!inDouble && character === "'") {
      inSingle = !inSingle
    }
  }
  return inDouble
}

export const isKnownTemplateSentinel = (
  name: string,
  kvBindings: readonly string[],
): boolean => {
  if (name === 'erpc:cloudflare-account-id') return true
  const kvMatch = /^erpc:kv-id:(.+)$/.exec(name)
  return kvMatch !== null && kvBindings.includes(kvMatch[1]!)
}

const DOMAIN_MARKER = 'ERPC_DOMAIN_PLACEHOLDER'
const GENERIC_MARKER = 'ERPC_GENERIC_PLACEHOLDER'

const lintCloudflareWorkerConfig = (
  manifest: TemplateManifest,
  files: ReadonlyMap<string, Uint8Array>,
  violations: string[],
): void => {
  const configPath = manifest.cloudflare.config
  const bytes = files.get(configPath)
  if (!bytes) {
    violations.push(
      `L12: cloudflare.config file not found in the archive: ${configPath}`,
    )
    return
  }
  const raw = new TextDecoder().decode(bytes)
  const marked = raw
    .replaceAll('{{domain}}', DOMAIN_MARKER)
    .replace(PLACEHOLDER_PATTERN, GENERIC_MARKER)
  let doc: Record<string, unknown>
  try {
    doc = parseToml(marked) as Record<string, unknown>
  } catch (error) {
    violations.push(
      `L12: ${configPath} could not be parsed as TOML after placeholder substitution: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
    return
  }

  if ('route' in doc) {
    violations.push(
      `L12: ${configPath} declares a top-level "route" (use [[routes]] with {{domain}} instead)`,
    )
  }
  if ('env' in doc) {
    violations.push(
      `L12: ${configPath} declares [env.*] tables, which are not permitted`,
    )
  }
  if ('routes' in doc) {
    const routes = doc.routes
    if (!Array.isArray(routes)) {
      violations.push(
        `L12: ${configPath} declares "routes" with an unsupported shape`,
      )
    } else {
      for (const route of routes) {
        if (typeof route === 'string') {
          violations.push(
            `L12: ${configPath} declares a string route (use [[routes]] with {{domain}} instead)`,
          )
          continue
        }
        if (route === null || typeof route !== 'object') {
          violations.push(
            `L12: ${configPath} declares an invalid [[routes]] entry`,
          )
          continue
        }
        const entry = route as Record<string, unknown>
        if ('zone_id' in entry || 'zone_name' in entry) {
          violations.push(
            `L12: ${configPath} [[routes]] entry declares zone_id/zone_name, which is not permitted`,
          )
          continue
        }
        const keys = Object.keys(entry).sort()
        const isExactDomainRoute = keys.length === 2 &&
          keys[0] === 'custom_domain' && keys[1] === 'pattern' &&
          entry.pattern === DOMAIN_MARKER && entry.custom_domain === true
        if (!isExactDomainRoute) {
          violations.push(
            `L12: ${configPath} [[routes]] entry must be exactly { pattern = "{{domain}}", custom_domain = true }`,
          )
        } else {
          // The placeholder is named "domain", but that alone does not prove
          // its value came from the user: the "domain" *key* itself must be
          // the flagged var - a decoy where some other key (e.g. "host")
          // carries flag "domain" while a `derived` (or flag-less `var`)
          // "domain" key supplies a fixed/attacker-chosen value would
          // otherwise pass, since `{{domain}}` still resolves and *some*
          // prompt still has flag "domain" (steiner r2 B-1, closing the gap
          // left by steiner r1 B2 / cyan r1 B2).
          const domainPrompt = manifest.prompts.find((prompt) =>
            prompt.key === 'domain'
          )
          const isDomainKeyItselfFlagged = domainPrompt !== undefined &&
            domainPrompt.target === 'var' && domainPrompt.flag === 'domain'
          if (!isDomainKeyItselfFlagged) {
            violations.push(
              `L12: ${configPath} [[routes]] binds to {{domain}}, but the "domain" prompt itself is not { target: "var", flag: "domain" }`,
            )
          } else if (
            domainPrompt.target === 'var' && domainPrompt.default !== undefined
          ) {
            // A `default` would let `--yes` route to that zone with no value
            // the user actually typed (el ruling, cyan r2 B2-P2): the
            // "domain" prompt must require a real answer.
            violations.push(
              `L12: ${configPath} [[routes]] binds to {{domain}}, but the "domain" prompt declares a default (it must require a typed answer)`,
            )
          }
        }
      }
    }
  }

  const secretsTable = doc.secrets
  if (secretsTable !== undefined) {
    if (
      typeof secretsTable !== 'object' || secretsTable === null ||
      Array.isArray(secretsTable)
    ) {
      violations.push(`L8: ${configPath} declares an invalid [secrets] table`)
    } else {
      const required = (secretsTable as Record<string, unknown>).required
      if (required !== undefined) {
        if (
          !Array.isArray(required) ||
          !required.every((value) => typeof value === 'string')
        ) {
          violations.push(
            `L8: ${configPath} [secrets] required must be an array of strings`,
          )
        } else {
          const allowed = new Set(requiredSecretKeys(manifest))
          for (const name of required as readonly string[]) {
            if (!allowed.has(name)) {
              violations.push(
                `L8: ${configPath} [secrets] required lists "${name}", which is not a required secret target in erpc-template.json`,
              )
            }
          }
        }
      }
    }
  }
}

/**
 * L4, L5, L8 (wrangler-subset half), and L12 - the lint rules that need the
 * archive's raw file bytes. `files` maps archive-relative path -> raw bytes,
 * exactly as extracted (before any answer substitution).
 */
export const lintTemplateFiles = (
  manifest: TemplateManifest,
  files: ReadonlyMap<string, Uint8Array>,
): void => {
  const violations: string[] = []
  const decoder = new TextDecoder()
  const nonSecretKeys = new Set(
    manifest.prompts
      .filter((prompt) => !isSecretPromptTarget(prompt.target))
      .map((prompt) => prompt.key),
  )
  const secretKeys = new Set(
    manifest.prompts
      .filter((prompt) => isSecretPromptTarget(prompt.target))
      .map((prompt) => prompt.key),
  )
  const isBuiltIn = (name: string): boolean =>
    name === 'app.name' ||
    (name === 'broker.issuer' && manifest.broker !== undefined)
  const kvBindings = (manifest.cloudflare.kv ?? []).map((kv) => kv.binding)

  for (const render of manifest.render) {
    const bytes = files.get(render.path)
    if (!bytes) {
      violations.push(`render path not found in the archive: ${render.path}`)
      continue
    }
    const text = decoder.decode(bytes)
    const lines = text.split(/\r?\n/)
    lines.forEach((line, lineIndex) => {
      for (const match of line.matchAll(PLACEHOLDER_PATTERN)) {
        const name = match[1]!.trim()
        if (secretKeys.has(name)) {
          violations.push(
            `L3: ${render.path}:${
              lineIndex + 1
            } references secret key "${name}" in a placeholder`,
          )
          continue
        }
        const resolved = isBuiltIn(name) || nonSecretKeys.has(name) ||
          isKnownTemplateSentinel(name, kvBindings)
        if (!resolved) {
          violations.push(
            `L4: ${render.path}:${
              lineIndex + 1
            } has an unresolved placeholder: {{${name}}}`,
          )
          continue
        }
        if (
          render.format === 'toml' &&
          !isWithinDoubleQuotedString(line, match.index)
        ) {
          violations.push(
            `L5: ${render.path}:${
              lineIndex + 1
            } places {{${name}}} outside a quoted TOML string`,
          )
        }
      }
    })
  }

  lintCloudflareWorkerConfig(manifest, files, violations)

  if (violations.length > 0) throw new TemplateManifestError(violations)
}
