import { describe, expect, it } from './testing.ts'
import { renderTemplateFiles } from '../src/app/template-render.ts'
import { parseTemplateManifest } from '../src/app/template-manifest.ts'
import type { ExtractedTemplateFile } from '../src/app/template-archive.ts'

const encoder = new TextEncoder()

const fileInput = (path: string, content: string): ExtractedTemplateFile => ({
  content: encoder.encode(content),
  executable: false,
  path,
})

// `cloudflare.config` must itself be a render[] target (L12), so each fixture
// below points it at the one file being rendered rather than introducing a
// second, unused render entry.
const manifestWith = (renderPath: string, format: 'text' | 'toml') =>
  parseTemplateManifest({
    schemaVersion: 1,
    name: 'fixture-template',
    runtime: 'cloudflare-worker',
    minCliVersion: '0.1.0',
    cloudflare: {
      config: renderPath,
      wrangler: ['pnpm', 'exec', 'wrangler'],
    },
    render: [{ path: renderPath, format }],
    prompts: [{ key: 'LABEL', target: 'var', question: 'A label' }],
  })

describe('renderTemplateFiles: format "text" newline guard', () => {
  it('rejects a value containing a carriage return with no line feed', () => {
    const manifest = manifestWith('notes.txt', 'text')
    const files = [fileInput('notes.txt', 'note: {{LABEL}}\n')]
    const answers = new Map([['LABEL', 'a\rb']])

    // A mutant that narrows the guard from `/[\n\r]/` to `/\n/` would let a
    // bare `\r` (no `\n`) through unrejected - this fixture carries no `\n`
    // at all, so only the `\r` branch of the guard can catch it.
    expect(() =>
      renderTemplateFiles(manifest, files, answers, { appName: 'demo-app' })
    ).toThrow('contains a newline')
  })

  it('rejects a value containing a line feed', () => {
    const manifest = manifestWith('notes.txt', 'text')
    const files = [fileInput('notes.txt', 'note: {{LABEL}}\n')]
    const answers = new Map([['LABEL', 'a\nb']])

    expect(() =>
      renderTemplateFiles(manifest, files, answers, { appName: 'demo-app' })
    ).toThrow('contains a newline')
  })

  it('accepts a value with neither a carriage return nor a line feed', () => {
    const manifest = manifestWith('notes.txt', 'text')
    const files = [fileInput('notes.txt', 'note: {{LABEL}}\n')]
    const answers = new Map([['LABEL', 'a-b']])

    const rendered = renderTemplateFiles(manifest, files, answers, {
      appName: 'demo-app',
    })
    expect(new TextDecoder().decode(rendered[0]!.content)).toBe('note: a-b\n')
  })
})

describe('renderTemplateFiles: format "toml" escapes control characters', () => {
  it('escapes a carriage return and a line feed in a toml basic string instead of rejecting them', () => {
    const manifest = manifestWith('config.toml', 'toml')
    const files = [fileInput('config.toml', 'label = "{{LABEL}}"\n')]
    const answers = new Map([['LABEL', 'a\r\nb']])

    const rendered = renderTemplateFiles(manifest, files, answers, {
      appName: 'demo-app',
    })
    const text = new TextDecoder().decode(rendered[0]!.content)
    expect(text).toBe('label = "a\\r\\nb"\n')
  })
})
