// Archive expansion policy for `erpc app init --template`.
//
// `@std/tar`'s UntarStream does not apply pax `path` overrides, passes `..`
// and absolute paths straight through, and represents symlinks with their
// literal typeflag. This module is therefore the only place
// that decides whether an archive entry is safe to write, and it validates
// every entry into an in-memory map before a single file is written.

import { UntarStream } from '@std/tar'

export const TEMPLATE_ARCHIVE_MAX_EXTRACTED_BYTES = 32 * 1024 * 1024 // 32 MiB
export const TEMPLATE_ARCHIVE_MAX_ENTRIES = 2000
const MAX_PAX_RECORD_BYTES = 64 * 1024

const ALLOWED_PAX_KEYS = new Set([
  'comment',
  'mtime',
  'atime',
  'ctime',
  'uid',
  'gid',
  'uname',
  'gname',
])

const WINDOWS_RESERVED_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
])

export interface ExtractedTemplateFile {
  readonly content: Uint8Array
  readonly executable: boolean
  readonly path: string
}

export interface ExtractedTemplateArchive {
  readonly files: readonly ExtractedTemplateFile[]
}

export interface ExtractTemplateArchiveOptions {
  readonly maxEntries?: number
  readonly maxExtractedBytes?: number
}

class TemplateArchivePolicyError extends Error {
  constructor(message: string) {
    super(`Template archive rejected: ${message}`)
    this.name = 'TemplateArchivePolicyError'
  }
}

const readAllBounded = async (
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  onOverLimit: string,
): Promise<Uint8Array> => {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined)
        throw new TemplateArchivePolicyError(onOverLimit)
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

const decodePaxKeys = (bytes: Uint8Array): readonly string[] => {
  const text = new TextDecoder().decode(bytes)
  const keys: string[] = []
  let offset = 0
  while (offset < text.length) {
    let spaceIndex = offset
    while (spaceIndex < text.length && text[spaceIndex] !== ' ') spaceIndex++
    if (spaceIndex >= text.length) {
      throw new TemplateArchivePolicyError(
        'a pax extended header record is malformed',
      )
    }
    const length = Number.parseInt(text.slice(offset, spaceIndex), 10)
    if (
      !Number.isInteger(length) || length <= 0 || offset + length > text.length
    ) {
      throw new TemplateArchivePolicyError(
        'a pax extended header record has an invalid length',
      )
    }
    const record = text.slice(offset, offset + length)
    const equalsIndex = record.indexOf('=')
    if (equalsIndex === -1 || equalsIndex <= spaceIndex - offset) {
      throw new TemplateArchivePolicyError(
        'a pax extended header record is missing its key',
      )
    }
    keys.push(record.slice(spaceIndex - offset + 1, equalsIndex))
    offset += length
  }
  return keys
}

/** Validates the raw ustar path for filesystem-escape and portability hazards. */
const splitAndValidateRawPath = (
  rawPath: string,
  isDirectory: boolean,
): readonly string[] => {
  if (rawPath.includes('\\')) {
    throw new TemplateArchivePolicyError(
      `path contains a backslash: ${rawPath}`,
    )
  }
  if (rawPath.includes(':')) {
    throw new TemplateArchivePolicyError(`path contains a colon: ${rawPath}`)
  }
  if (rawPath.includes('\0')) {
    throw new TemplateArchivePolicyError(`path contains a NUL byte: ${rawPath}`)
  }
  if (rawPath.startsWith('/')) {
    throw new TemplateArchivePolicyError(`path is absolute: ${rawPath}`)
  }
  const trimmed = isDirectory ? rawPath.replace(/\/+$/, '') : rawPath
  if (trimmed.length === 0) {
    throw new TemplateArchivePolicyError('an entry has an empty path')
  }
  const segments = trimmed.split('/')
  for (const segment of segments) {
    if (segment.length === 0) {
      throw new TemplateArchivePolicyError(
        `path contains an empty segment: ${rawPath}`,
      )
    }
    if (segment === '.' || segment === '..') {
      throw new TemplateArchivePolicyError(
        `path escapes the extraction root: ${rawPath}`,
      )
    }
    // deno-lint-ignore no-control-regex
    if (/[\x00-\x1f\x7f]/.test(segment)) {
      throw new TemplateArchivePolicyError(
        `path contains a control character: ${rawPath}`,
      )
    }
    const stem = (segment.split('.')[0] ?? '').toUpperCase()
    if (WINDOWS_RESERVED_NAMES.has(stem)) {
      throw new TemplateArchivePolicyError(
        `path uses a reserved Windows device name: ${rawPath}`,
      )
    }
  }
  return segments
}

/** Case-insensitive: `.GIT`, `ERPC.toml`, `Node_Modules/`, `.ENV` must be
 * rejected exactly like their lowercase forms. */
const rejectDisallowedFinalPath = (
  segments: readonly string[],
  displayPath: string,
): void => {
  const lowerSegments = segments.map((segment) => segment.toLowerCase())
  if (lowerSegments.includes('node_modules')) {
    throw new TemplateArchivePolicyError(
      `contains a disallowed node_modules entry: ${displayPath}`,
    )
  }
  if (lowerSegments.includes('.git')) {
    throw new TemplateArchivePolicyError(
      `contains a disallowed .git entry: ${displayPath}`,
    )
  }
  const basename = lowerSegments[lowerSegments.length - 1] ?? ''
  if (basename === 'erpc.toml') {
    throw new TemplateArchivePolicyError(
      `contains a disallowed erpc.toml entry: ${displayPath}`,
    )
  }
  if (basename === '.dev.vars') {
    throw new TemplateArchivePolicyError(
      `contains a disallowed .dev.vars entry: ${displayPath}`,
    )
  }
  if (basename.startsWith('.env') && basename !== '.env.example') {
    throw new TemplateArchivePolicyError(
      `contains a disallowed env file: ${displayPath}`,
    )
  }
}

interface RawEntry {
  readonly content?: Uint8Array
  readonly executable: boolean
  readonly kind: 'dir' | 'file'
  readonly rawPath: string
  readonly segments: readonly string[]
}

/**
 * Decompresses and extracts a `.tar.gz` template archive under a strict
 * allowlist policy. Every entry is validated (and file content fully read)
 * before this function returns; nothing is written to disk here, and nothing
 * about the caller's filesystem is touched on rejection.
 */
export const extractTemplateArchive = async (
  bytes: Uint8Array,
  options: ExtractTemplateArchiveOptions = {},
): Promise<ExtractedTemplateArchive> => {
  const maxEntries = options.maxEntries ?? TEMPLATE_ARCHIVE_MAX_ENTRIES
  const maxExtractedBytes = options.maxExtractedBytes ??
    TEMPLATE_ARCHIVE_MAX_EXTRACTED_BYTES

  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
  const entries = source
    .pipeThrough(
      new DecompressionStream('gzip') as unknown as ReadableWritablePair<
        Uint8Array,
        Uint8Array
      >,
    )
    .pipeThrough(new UntarStream())

  const rawEntries: RawEntry[] = []
  let entryCount = 0
  let extractedBytes = 0

  for await (const entry of entries) {
    entryCount++
    if (entryCount > maxEntries) {
      await entry.readable?.cancel().catch(() => undefined)
      throw new TemplateArchivePolicyError(
        `contains more than ${maxEntries} entries`,
      )
    }
    const typeflag = entry.header.typeflag

    if (typeflag === 'g' || typeflag === 'x') {
      const content = entry.readable
        ? await readAllBounded(
          entry.readable,
          MAX_PAX_RECORD_BYTES,
          'a pax extended header exceeds the size this CLI will process',
        )
        : new Uint8Array(0)
      const keys = decodePaxKeys(content)
      for (const key of keys) {
        if (!ALLOWED_PAX_KEYS.has(key)) {
          throw new TemplateArchivePolicyError(
            `contains an unsupported pax header field: ${key}`,
          )
        }
      }
      continue
    }

    if (typeflag !== '0' && typeflag !== '5') {
      await entry.readable?.cancel().catch(() => undefined)
      const kind = typeflag === '1'
        ? 'a hard link'
        : typeflag === '2'
        ? 'a symbolic link'
        : typeflag === '3' || typeflag === '4'
        ? 'a device file'
        : typeflag === '6'
        ? 'a FIFO'
        : `an unsupported entry type (${JSON.stringify(typeflag)})`
      throw new TemplateArchivePolicyError(`contains ${kind}: ${entry.path}`)
    }

    const isDirectory = typeflag === '5'
    const segments = splitAndValidateRawPath(entry.path, isDirectory)

    if (isDirectory) {
      rawEntries.push({
        executable: false,
        kind: 'dir',
        rawPath: segments.join('/'),
        segments,
      })
      continue
    }

    const remainingBudget = maxExtractedBytes - extractedBytes
    const content = entry.readable
      ? await readAllBounded(
        entry.readable,
        Math.max(remainingBudget, 0),
        `extracts to more than ${maxExtractedBytes} bytes`,
      )
      : new Uint8Array(0)
    extractedBytes += content.byteLength
    if (extractedBytes > maxExtractedBytes) {
      throw new TemplateArchivePolicyError(
        `extracts to more than ${maxExtractedBytes} bytes`,
      )
    }
    const mode = 'mode' in entry.header ? entry.header.mode : 0o644
    rawEntries.push({
      content,
      executable: (mode & 0o111) !== 0,
      kind: 'file',
      rawPath: segments.join('/'),
      segments,
    })
  }

  const rootManifest = rawEntries.find(
    (candidate) =>
      candidate.kind === 'file' && candidate.rawPath === 'erpc-template.json',
  )

  let stripPrefix: string | null = null
  if (!rootManifest) {
    const firstSegments = new Set(rawEntries.map((entry) => entry.segments[0]))
    if (firstSegments.size === 1) {
      const [candidate] = [...firstSegments]
      const nested = rawEntries.find(
        (entry) =>
          entry.kind === 'file' &&
          entry.segments.length > 1 &&
          entry.segments[0] === candidate &&
          entry.segments.slice(1).join('/') === 'erpc-template.json',
      )
      if (nested && candidate !== undefined) stripPrefix = candidate
    }
    if (stripPrefix === null) {
      throw new TemplateArchivePolicyError(
        'is missing erpc-template.json at its root or under a single top-level directory',
      )
    }
  }

  const seen = new Set<string>()
  const files: ExtractedTemplateFile[] = []
  for (const entry of rawEntries) {
    let finalSegments = entry.segments
    if (stripPrefix !== null) {
      if (entry.segments[0] !== stripPrefix) {
        throw new TemplateArchivePolicyError(
          `contains an entry outside the single top-level directory: ${entry.rawPath}`,
        )
      }
      finalSegments = entry.segments.slice(1)
      if (finalSegments.length === 0) continue // the stripped container directory itself
    }
    const finalPath = finalSegments.join('/')
    rejectDisallowedFinalPath(finalSegments, finalPath)
    const dedupeKey = finalPath.toLowerCase()
    if (seen.has(dedupeKey)) {
      throw new TemplateArchivePolicyError(
        `contains case-insensitively duplicate paths: ${finalPath}`,
      )
    }
    seen.add(dedupeKey)
    if (entry.kind === 'file') {
      files.push({
        content: entry.content ?? new Uint8Array(0),
        executable: entry.executable,
        path: finalPath,
      })
    }
  }

  // A path used as a file must not also be needed as a directory prefix of
  // another path (e.g. both "a" and "a/b"): writing "a" first, then trying to
  // mkdir "a" for "a/b", would partially write the archive.
  const neededDirectories = new Set<string>()
  for (const path of seen) {
    const pathSegments = path.split('/')
    for (let index = 1; index < pathSegments.length; index++) {
      neededDirectories.add(pathSegments.slice(0, index).join('/'))
    }
  }
  for (const file of files) {
    if (neededDirectories.has(file.path.toLowerCase())) {
      throw new TemplateArchivePolicyError(
        `contains a path used as both a file and a directory: ${file.path}`,
      )
    }
  }

  if (!files.some((file) => file.path === 'erpc-template.json')) {
    throw new TemplateArchivePolicyError(
      'is missing erpc-template.json after applying the root directory rule',
    )
  }

  return { files }
}
