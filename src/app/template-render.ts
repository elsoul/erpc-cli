// Renders the `render[]` files declared by an `erpc-template.json` manifest.
// See design doc §1.4/§2.3 (L4/L5) and Task Brief Decision 9.

import type { ExtractedTemplateFile } from './template-archive.ts'
import {
  isKnownTemplateSentinel,
  PLACEHOLDER_PATTERN,
  type TemplateManifest,
} from './template-manifest.ts'

export interface RenderedTemplateFile {
  readonly content: Uint8Array
  readonly executable: boolean
  readonly path: string
}

export interface TemplateRenderBuiltIns {
  readonly appName: string
  readonly brokerIssuer?: string
}

/** Escapes `value` for embedding inside a TOML basic ("...") string. */
export const tomlBasicString = (value: string): string => {
  let out = ''
  for (const character of value) {
    const codePoint = character.codePointAt(0)!
    if (character === '\\') out += '\\\\'
    else if (character === '"') out += '\\"'
    else if (character === '\b') out += '\\b'
    else if (character === '\t') out += '\\t'
    else if (character === '\n') out += '\\n'
    else if (character === '\f') out += '\\f'
    else if (character === '\r') out += '\\r'
    else if (codePoint <= 0x1f || codePoint === 0x7f) {
      out += `\\u${codePoint.toString(16).padStart(4, '0')}`
    } else out += character
  }
  return out
}

const assertNoUnresolvedPlaceholders = (
  path: string,
  rendered: string,
  kvBindings: readonly string[],
): void => {
  for (const match of rendered.matchAll(PLACEHOLDER_PATTERN)) {
    const name = match[1]!.trim()
    if (!isKnownTemplateSentinel(name, kvBindings)) {
      throw new Error(
        `${path} still has an unresolved placeholder after rendering: {{${name}}}`,
      )
    }
  }
}

/**
 * Renders every file declared in `manifest.render[]` by substituting
 * `{{key}}` placeholders with `answers` and the built-in `app.name` /
 * `broker.issuer` values. Known deploy-time sentinels
 * (`{{erpc:kv-id:<BINDING>}}`, `{{erpc:cloudflare-account-id}}`) are left
 * untouched. Files not declared in `render[]` pass through byte-for-byte.
 * `lintTemplateFiles` must already have accepted `files` (L3/L4/L5) before
 * this runs; the checks here are a defensive re-assertion, not the primary
 * gate.
 */
export const renderTemplateFiles = (
  manifest: TemplateManifest,
  files: readonly ExtractedTemplateFile[],
  answers: ReadonlyMap<string, string>,
  builtIns: TemplateRenderBuiltIns,
): readonly RenderedTemplateFile[] => {
  const renderFormats = new Map(
    manifest.render.map((entry) => [entry.path, entry.format]),
  )
  const kvBindings = (manifest.cloudflare.kv ?? []).map((kv) => kv.binding)
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()

  const resolve = (name: string): string | undefined => {
    if (name === 'app.name') return builtIns.appName
    if (name === 'broker.issuer') return builtIns.brokerIssuer
    return answers.get(name)
  }

  return files.map((file) => {
    const format = renderFormats.get(file.path)
    if (!format) return file

    const text = decoder.decode(file.content)
    const rendered = text.replace(
      PLACEHOLDER_PATTERN,
      (whole, rawName: string) => {
        const name = rawName.trim()
        if (isKnownTemplateSentinel(name, kvBindings)) return whole
        const value = resolve(name)
        if (value === undefined) {
          throw new Error(`Unresolved template placeholder: {{${name}}}`)
        }
        if (format === 'text' && /[\n\r]/.test(value)) {
          throw new Error(
            `The value for "${name}" contains a newline and cannot be rendered into a text file`,
          )
        }
        return format === 'toml' ? tomlBasicString(value) : value
      },
    )
    assertNoUnresolvedPlaceholders(file.path, rendered, kvBindings)

    return {
      content: encoder.encode(rendered),
      executable: file.executable,
      path: file.path,
    }
  })
}
