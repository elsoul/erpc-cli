// Release-asset fetch, checksum verification, and the on-disk template cache.
// See design doc §1.2 and Task Brief Decision 3.

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { TemplateSource } from './template-registry.ts'

export const TEMPLATE_ARCHIVE_MAX_BYTES = 8 * 1024 * 1024 // 8 MiB, compressed
const DEFAULT_TIMEOUT_MS = 30_000

const hexadecimal = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')

export const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
  // crypto.subtle.digest can detach/transfer some inputs; copy defensively
  // (matches the existing precedent in deploy/node-runtime.ts).
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return hexadecimal(await crypto.subtle.digest('SHA-256', copy))
}

/** Builds the release-asset download URL. Only `tag` and `asset` are percent-encoded (Decision 3). */
export const templateAssetUrl = (source: TemplateSource, tag: string): URL =>
  new URL(
    `https://github.com/${source.owner}/${source.repo}/releases/download/${
      encodeURIComponent(tag)
    }/${encodeURIComponent(source.asset)}`,
  )

export interface TemplateFetchOptions {
  readonly fetch?: typeof globalThis.fetch
  readonly timeoutMs?: number
}

const downloadTemplateArchive = async (
  url: URL,
  options: TemplateFetchOptions,
): Promise<Uint8Array> => {
  if (url.protocol !== 'https:') {
    throw new Error('Template archives may only be downloaded over HTTPS')
  }
  const fetcher = options.fetch ?? globalThis.fetch
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  let response: Response
  try {
    response = await fetcher(url, { signal: controller.signal })
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error('Timed out downloading the template archive')
    }
    throw new Error(
      `Unable to download the template archive: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  try {
    if (!response.ok) {
      throw new Error(
        `Unable to download the template archive: HTTP ${response.status}`,
      )
    }
    if (!response.body) {
      // Fall back for injected fetch stubs that only implement arrayBuffer().
      const buffer = new Uint8Array(await response.arrayBuffer())
      if (buffer.byteLength > TEMPLATE_ARCHIVE_MAX_BYTES) {
        throw new Error(
          `The template archive exceeds the ${TEMPLATE_ARCHIVE_MAX_BYTES} byte download limit`,
        )
      }
      return buffer
    }
    const reader = response.body.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > TEMPLATE_ARCHIVE_MAX_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw new Error(
          `The template archive exceeds the ${TEMPLATE_ARCHIVE_MAX_BYTES} byte download limit`,
        )
      }
      chunks.push(value)
    }
    const bytes = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    return bytes
  } finally {
    clearTimeout(timeout)
  }
}

const cachedTemplatePath = (erpcHome: string, sha256: string): string =>
  join(erpcHome, 'cache', 'templates', `sha256-${sha256}.tar.gz`)

const regularFileBytes = async (
  path: string,
): Promise<Uint8Array | undefined> => {
  try {
    // `readFile` returns a Node `Buffer`. Copy into a plain `Uint8Array` so
    // every return path of this Web-standard-facing module (DecompressionStream,
    // UntarStream, fetch) hands callers the same, non-Node-specific type.
    return new Uint8Array(await readFile(path))
  } catch {
    return undefined
  }
}

/**
 * Fetches (or reuses a verified cache entry for) the release asset at `url`
 * and verifies it against `expectedSha256` *before* returning. On a checksum
 * mismatch, nothing is written to the cache and the caller has not yet
 * touched the target directory (Decision 3 / Acceptance A4).
 */
export const obtainVerifiedTemplateArchive = async (
  url: URL,
  erpcHome: string,
  expectedSha256: string,
  options: TemplateFetchOptions = {},
): Promise<Uint8Array> => {
  const cachePath = cachedTemplatePath(erpcHome, expectedSha256)
  const cached = await regularFileBytes(cachePath)
  if (cached && (await sha256Hex(cached)) === expectedSha256) {
    return cached
  }

  const bytes = await downloadTemplateArchive(url, options)
  const actual = await sha256Hex(bytes)
  if (actual !== expectedSha256) {
    throw new Error(
      `Template archive failed checksum verification (expected ${expectedSha256}, got ${actual})`,
    )
  }

  const cacheDirectory = join(erpcHome, 'cache', 'templates')
  await mkdir(cacheDirectory, { mode: 0o700, recursive: true })
  try {
    await writeFile(cachePath, bytes, {
      encoding: undefined,
      flag: 'wx',
      mode: 0o600,
    })
  } catch (error) {
    if (
      !(error instanceof Error && 'code' in error && error.code === 'EEXIST')
    ) {
      throw error
    }
  }
  return bytes
}
