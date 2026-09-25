import { z } from '@zod/zod'
import { describe, expect, it } from './testing.ts'
import {
  type BrokerRegisterPrompt,
  lintTemplateFiles,
  parseTemplateManifest,
  templateManifestSchema,
  type TemplatePrompt,
  type VarPrompt,
} from '../src/app/template-manifest.ts'

const textEncoder = new TextEncoder()
const files = (entries: Record<string, string>): Map<string, Uint8Array> =>
  new Map(
    Object.entries(entries).map((
      [path, content],
    ) => [path, textEncoder.encode(content)]),
  )

const baseManifest = () => ({
  $schema: 'https://storage.erpc.global/schemas/erpc-template/v1.json',
  schemaVersion: 1,
  name: 'stablecoin-manager',
  runtime: 'cloudflare-worker',
  minCliVersion: '0.1.0',
  cloudflare: {
    config: 'wrangler.toml',
    wrangler: ['pnpm', 'exec', 'wrangler'],
    kv: [{ binding: 'MCP_KV', title: '{{app.name}}-mcp-kv' }],
  },
  build: { command: ['pnpm', 'install', '--frozen-lockfile'] },
  broker: { issuer: 'https://app-oidc-api.example.workers.dev' },
  render: [{ path: 'wrangler.toml', format: 'toml' as const }],
  prompts: [
    {
      key: 'domain',
      target: 'var',
      flag: 'domain',
      question: 'Custom domain',
      validate: { pattern: '[a-z.]+' },
    },
    {
      key: 'MCP_SERVER_BASE_URL',
      target: 'derived',
      expr: 'https://{{domain}}',
    },
    {
      key: 'APP_OIDC_CLIENT_ID',
      target: 'broker-register',
      redirectUris: ['https://{{domain}}/oauth/callback'],
      clientName: '{{app.name}}',
    },
    {
      key: 'JWT_SECRET',
      target: 'secret-generate',
      bytes: 32,
      encoding: 'base64url',
    },
  ] as TemplatePrompt[],
})

const wranglerToml = `name = "{{app.name}}"
id = "{{erpc:kv-id:MCP_KV}}"

[[routes]]
pattern = "{{domain}}"
custom_domain = true

[secrets]
required = ["JWT_SECRET"]
`

describe('parseTemplateManifest', () => {
  it('accepts a well-formed manifest', () => {
    const manifest = parseTemplateManifest(baseManifest())
    expect(manifest.name).toBe('stablecoin-manager')
  })

  it('rejects a manifest missing a required field (schema)', () => {
    const invalid = { ...baseManifest(), name: undefined }
    expect(() => parseTemplateManifest(invalid)).toThrow()
  })

  it('L1: rejects a reserved prompt key', () => {
    const manifest = baseManifest()
    manifest.prompts = [{ ...(manifest.prompts[0]! as VarPrompt), key: 'app' }]
    expect(() => parseTemplateManifest(manifest)).toThrow('L1')
  })

  it('L1: rejects a duplicate prompt key', () => {
    const manifest = baseManifest()
    manifest.prompts = [manifest.prompts[0]!, manifest.prompts[0]!]
    expect(() => parseTemplateManifest(manifest)).toThrow('L1')
  })

  it('L2: rejects a derived expr referencing an undeclared key', () => {
    const manifest = baseManifest()
    manifest.prompts = [
      { key: 'derivedOnly', target: 'derived', expr: 'https://{{missing}}' },
    ]
    expect(() => parseTemplateManifest(manifest)).toThrow('L2')
  })

  it('L3: rejects a placeholder referencing a secret key', () => {
    const manifest = baseManifest()
    manifest.prompts = [
      {
        key: 'JWT_SECRET',
        target: 'secret-generate',
        bytes: 32,
        encoding: 'base64url',
      },
      { key: 'leak', target: 'derived', expr: '{{JWT_SECRET}}' },
    ]
    expect(() => parseTemplateManifest(manifest)).toThrow('L3')
  })

  it('L6: rejects more than one broker-register prompt', () => {
    const manifest = baseManifest()
    const brokerPrompt = manifest.prompts[2]! as BrokerRegisterPrompt
    manifest.prompts = [...manifest.prompts, {
      ...brokerPrompt,
      key: 'SECOND_CLIENT_ID',
    }]
    expect(() => parseTemplateManifest(manifest)).toThrow('L6')
  })

  it('L6: rejects a non-https broker issuer', () => {
    const manifest = baseManifest()
    manifest.broker = { issuer: 'http://not-secure.example.com' }
    expect(() => parseTemplateManifest(manifest)).toThrow('L6')
  })

  it('L8: rejects a secret key that is not UPPER_SNAKE_CASE', () => {
    const manifest = baseManifest()
    manifest.prompts = [
      {
        key: 'jwtSecret',
        target: 'secret-generate',
        bytes: 32,
        encoding: 'base64url',
      },
    ]
    expect(() => parseTemplateManifest(manifest)).toThrow('L8')
  })

  it('L9: rejects an empty preflight command', () => {
    const manifest = baseManifest()
    ;(manifest.cloudflare as { preflight?: string[][] }).preflight = [[]]
    expect(() => parseTemplateManifest(manifest)).toThrow()
  })

  it('L10: rejects a control character in a question', () => {
    const manifest = baseManifest()
    manifest.prompts = [
      {
        ...(manifest.prompts[0]! as VarPrompt),
        question: 'Bad question\u0007',
      },
      ...manifest.prompts.slice(1),
    ]
    expect(() => parseTemplateManifest(manifest)).toThrow('L10')
  })

  it('L11: rejects a template that requires a newer CLI than is running', () => {
    const manifest = baseManifest()
    manifest.minCliVersion = '99.0.0'
    expect(() => parseTemplateManifest(manifest)).toThrow('L11')
  })

  it('L7: rejects an unknown flag value', () => {
    // Constructed as untyped JSON (not the TemplatePrompt-typed fixture) so
    // TypeScript itself doesn't block the very input this test exists to
    // reject at runtime.
    const manifest = JSON.parse(JSON.stringify(baseManifest())) as Record<
      string,
      unknown
    >
    const prompts = manifest.prompts as Array<Record<string, unknown>>
    prompts[0]!.flag = 'unknown'
    expect(() => parseTemplateManifest(manifest)).toThrow()
  })

  it('L9: rejects a build command argument containing a NUL byte (passes schema, only L9 catches it)', () => {
    const manifest = baseManifest()
    manifest.build = { command: ['node', 'x\0evil'] }
    expect(() => parseTemplateManifest(manifest)).toThrow('L9')
  })

  it('N6: rejects a reference to {{broker.issuer}} when no broker section exists', () => {
    const manifest = { ...baseManifest(), broker: undefined }
    manifest.prompts = [
      {
        key: 'domain',
        target: 'var',
        flag: 'domain',
        question: 'Custom domain',
        validate: { pattern: '[a-z.]+' },
      },
      { key: 'ISSUER_REF', target: 'derived', expr: '{{broker.issuer}}' },
    ] as TemplatePrompt[]
    expect(() => parseTemplateManifest(manifest)).toThrow('L2')
  })

  it('rejects an invalid validate.pattern regex at lint time (cyan r1 N5)', () => {
    const manifest = baseManifest()
    manifest.prompts = manifest.prompts.map((prompt) =>
      prompt.key === 'domain'
        ? { ...(prompt as VarPrompt), validate: { pattern: '(' } }
        : prompt
    )
    expect(() => parseTemplateManifest(manifest)).toThrow(
      'invalid validate.pattern',
    )
  })
})

describe('lintTemplateFiles', () => {
  it('accepts a well-formed render set', () => {
    const manifest = parseTemplateManifest(baseManifest())
    // No assertion beyond "does not throw": this test harness's `.not.toThrow()`
    // does not invert (see test/testing.ts), so an uncaught throw here is what
    // fails the test.
    lintTemplateFiles(manifest, files({ 'wrangler.toml': wranglerToml }))
  })

  it('L4: rejects an unresolved placeholder in a render file', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = wranglerToml.replace(
      '{{app.name}}',
      '{{totally_unknown_key}}',
    )
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L4')
  })

  it('L5: rejects a toml placeholder outside a quoted string', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = wranglerToml.replace(
      'id = "{{erpc:kv-id:MCP_KV}}"',
      'id = {{erpc:kv-id:MCP_KV}}',
    )
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L5')
  })

  it('L8: rejects a wrangler required-secret name absent from the manifest', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = wranglerToml.replace(
      'required = ["JWT_SECRET"]',
      'required = ["JWT_SECRET", "NOT_A_REAL_SECRET"]',
    )
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L8')
  })

  it('L12: rejects a top-level route', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = `route = "evil.example.com/*"\n${wranglerToml}`
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L12')
  })

  it('L12: rejects a string routes entry', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = `routes = ["evil.example.com/*"]\n${wranglerToml}`
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L12')
  })

  it('L12: rejects a [[routes]] entry with zone_name', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = wranglerToml.replace(
      'custom_domain = true',
      'custom_domain = true\nzone_name = "example.com"',
    )
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L12')
  })

  it('L12: rejects a [[routes]] entry not bound to {{domain}}', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = wranglerToml.replace(
      'pattern = "{{domain}}"',
      'pattern = "other.example.com/*"',
    )
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L12')
  })

  it('L12: rejects an [env.*] table', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const broken = `${wranglerToml}\n[env.production]\nname = "other"\n`
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': broken }))
    ).toThrow('L12')
  })

  // steiner r1 B2 / cyan r1 B2: {{domain}} in a [[routes]] entry must trace
  // back to a `var` prompt flagged "domain" - not a `derived` key or a
  // flag-less `var`, either of which could route to a domain the user never
  // actually supplied.
  it('L12: rejects binding to {{domain}} when "domain" is a derived key, not a flagged var', () => {
    const source = baseManifest()
    source.prompts = source.prompts.map((prompt) =>
      prompt.key === 'domain'
        ? { key: 'domain', target: 'derived', expr: 'evil.example.com' }
        : prompt
    ) as TemplatePrompt[]
    const manifest = parseTemplateManifest(source)
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': wranglerToml }))
    ).toThrow('L12')
  })

  it('L12: rejects binding to {{domain}} when "domain" is a var without flag "domain"', () => {
    const source = baseManifest()
    source.prompts = source.prompts.map((prompt) =>
      prompt.key === 'domain'
        ? {
          key: 'domain',
          target: 'var',
          question: 'Domain',
          default: 'evil.example.com',
        }
        : prompt
    ) as TemplatePrompt[]
    const manifest = parseTemplateManifest(source)
    expect(() =>
      lintTemplateFiles(manifest, files({ 'wrangler.toml': wranglerToml }))
    ).toThrow('L12')
  })

  it('does not misread a double quote embedded in a single-quoted literal on the same line (steiner r1 N5)', () => {
    const manifest = parseTemplateManifest(baseManifest())
    const trickyLine =
      `weird = { note = 'contains a bare " character', real = "{{app.name}}" }`
    const content = `${trickyLine}\n${wranglerToml}`
    // No assertion beyond "does not throw" (see the note on this harness's
    // `.not.toThrow()` earlier in this file).
    lintTemplateFiles(manifest, files({ 'wrangler.toml': content }))
  })
})

describe('schema drift', () => {
  it('matches the committed schemas/erpc-template.v1.schema.json', async () => {
    const generated = {
      ...z.toJSONSchema(templateManifestSchema) as Record<string, unknown>,
      $id: 'https://storage.erpc.global/schemas/erpc-template/v1.json',
      title: 'erpc-template.json v1',
    }
    const committed = JSON.parse(
      await Deno.readTextFile(
        new URL('../schemas/erpc-template.v1.schema.json', import.meta.url),
      ),
    )
    expect(generated).toEqual(committed)
  })
})
