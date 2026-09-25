import { TarStream, type TarStreamInput } from '@std/tar'
import { describe, expect, it } from './testing.ts'
import {
  extractTemplateArchive,
  TEMPLATE_ARCHIVE_MAX_ENTRIES,
  TEMPLATE_ARCHIVE_MAX_EXTRACTED_BYTES,
} from '../src/app/template-archive.ts'

const textEncoder = new TextEncoder()

const concatBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

const gzip = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
  const stream = source.pipeThrough(
    new CompressionStream('gzip') as unknown as ReadableWritablePair<
      Uint8Array,
      Uint8Array
    >,
  )
  const chunks: Uint8Array[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return concatBytes(chunks)
}

const tarGzFromInputs = async (
  inputs: readonly TarStreamInput[],
): Promise<Uint8Array> => {
  const chunks: Uint8Array[] = []
  const tarStream = ReadableStream.from([...inputs]).pipeThrough(
    new TarStream(),
  )
  for await (const chunk of tarStream) chunks.push(chunk)
  return await gzip(concatBytes(chunks))
}

const fileInput = (path: string, content: string): TarStreamInput => ({
  type: 'file',
  path,
  size: textEncoder.encode(content).byteLength,
  readable: ReadableStream.from([textEncoder.encode(content)]),
})

const MANIFEST_CONTENT = JSON.stringify({
  schemaVersion: 1,
  name: 'fixture',
  runtime: 'cloudflare-worker',
  minCliVersion: '0.1.0',
  cloudflare: {
    config: 'wrangler.toml',
    wrangler: ['pnpm', 'exec', 'wrangler'],
  },
  render: [],
  prompts: [],
})

// -- raw ustar header builder, for entry types TarStreamInput cannot express --

const parseOctalInto = (value: number, buffer: Uint8Array): void => {
  for (let index = buffer.length - 1; index >= 0; index--) {
    buffer[index] = (value % 8) + 48
    value = Math.floor(value / 8)
  }
}

const buildRawHeader = (options: {
  readonly linkname?: string
  readonly name: string
  readonly size?: number
  readonly typeflag: string
}): Uint8Array => {
  const buffer = new Uint8Array(512)
  const nameBytes = textEncoder.encode(options.name)
  buffer.set(nameBytes.subarray(0, Math.min(100, nameBytes.length)), 0)
  parseOctalInto(0o644, buffer.subarray(100, 106))
  buffer[106] = 32
  buffer[107] = 0
  parseOctalInto(0, buffer.subarray(108, 114))
  buffer[114] = 32
  buffer[115] = 0
  parseOctalInto(0, buffer.subarray(116, 122))
  buffer[122] = 32
  buffer[123] = 0
  buffer[135] = 32
  parseOctalInto(options.size ?? 0, buffer.subarray(124, 135))
  parseOctalInto(0, buffer.subarray(136, 147))
  buffer[147] = 32
  buffer.fill(32, 148, 156)
  buffer[156] = options.typeflag.charCodeAt(0)
  buffer.fill(0, 157, 257)
  if (options.linkname) {
    const linkBytes = textEncoder.encode(options.linkname)
    buffer.set(linkBytes.subarray(0, Math.min(100, linkBytes.length)), 157)
  }
  buffer.set(textEncoder.encode('ustar'), 257)
  buffer[262] = 0
  buffer.set(textEncoder.encode('00'), 263)
  buffer.fill(0, 500, 512)
  let sum = 0
  for (const byte of buffer) sum += byte
  parseOctalInto(sum, buffer.subarray(148, 154))
  buffer[154] = 0
  return buffer
}

const padTo512 = (bytes: Uint8Array): Uint8Array => {
  const remainder = bytes.byteLength % 512
  if (remainder === 0) return bytes
  const padded = new Uint8Array(bytes.byteLength + (512 - remainder))
  padded.set(bytes)
  return padded
}

const rawTarGz = async (
  entries: readonly {
    readonly content?: Uint8Array
    readonly header: Uint8Array
  }[],
): Promise<Uint8Array> => {
  const parts: Uint8Array[] = []
  for (const entry of entries) {
    parts.push(entry.header)
    if (entry.content && entry.content.byteLength > 0) {
      parts.push(padTo512(entry.content))
    }
  }
  parts.push(new Uint8Array(1024))
  return await gzip(concatBytes(parts))
}

/** A pax extended-header record: `<len> <key>=<value>\n`, length self-referential. */
const paxRecord = (key: string, value: string): Uint8Array => {
  const suffix = `${key}=${value}\n`
  let length = suffix.length + 2 // " " + suffix, plus an initial guess for len's own digits
  while (true) {
    const total = String(length).length + 1 + suffix.length
    if (total === length) return textEncoder.encode(`${length} ${suffix}`)
    length = total
  }
}

describe('extractTemplateArchive', () => {
  it('extracts a well-formed archive rooted at the archive root', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('wrangler.toml', 'name = "fixture"\n'),
    ])
    const { files } = await extractTemplateArchive(archive)
    expect(files.map((file) => file.path).sort()).toEqual([
      'erpc-template.json',
      'wrangler.toml',
    ])
  })

  it('strips a single top-level directory to find the manifest', async () => {
    const archive = await tarGzFromInputs([
      fileInput(
        'stablecoin-manager-v0.1.0/erpc-template.json',
        MANIFEST_CONTENT,
      ),
      fileInput('stablecoin-manager-v0.1.0/src/index.ts', 'export {}\n'),
    ])
    const { files } = await extractTemplateArchive(archive)
    expect(files.map((file) => file.path).sort()).toEqual([
      'erpc-template.json',
      'src/index.ts',
    ])
  })

  it('preserves the executable bit and normalizes other mode bits', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      {
        type: 'file',
        path: 'scripts/run.sh',
        size: textEncoder.encode('#!/bin/sh\n').byteLength,
        readable: ReadableStream.from([textEncoder.encode('#!/bin/sh\n')]),
        options: { mode: 0o755 },
      },
    ])
    const { files } = await extractTemplateArchive(archive)
    const script = files.find((file) => file.path === 'scripts/run.sh')
    expect(script?.executable).toBe(true)
    const manifest = files.find((file) => file.path === 'erpc-template.json')
    expect(manifest?.executable).toBe(false)
  })

  it('rejects a symlink', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      { type: 'symlink', path: 'link', linkname: 'erpc-template.json' },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'symbolic link',
    )
  })

  it('rejects a hard link', async () => {
    const archive = await rawTarGz([
      {
        header: buildRawHeader({
          name: 'erpc-template.json',
          typeflag: '0',
          size: MANIFEST_CONTENT.length,
        }),
        content: textEncoder.encode(MANIFEST_CONTENT),
      },
      {
        header: buildRawHeader({
          name: 'hard',
          typeflag: '1',
          linkname: 'erpc-template.json',
        }),
      },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('hard link')
  })

  it('rejects a device file', async () => {
    const archive = await rawTarGz([
      {
        header: buildRawHeader({
          name: 'erpc-template.json',
          typeflag: '0',
          size: MANIFEST_CONTENT.length,
        }),
        content: textEncoder.encode(MANIFEST_CONTENT),
      },
      { header: buildRawHeader({ name: 'dev', typeflag: '3' }) },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('device file')
  })

  it('rejects a FIFO', async () => {
    const archive = await rawTarGz([
      {
        header: buildRawHeader({
          name: 'erpc-template.json',
          typeflag: '0',
          size: MANIFEST_CONTENT.length,
        }),
        content: textEncoder.encode(MANIFEST_CONTENT),
      },
      { header: buildRawHeader({ name: 'fifo', typeflag: '6' }) },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('FIFO')
  })

  it('rejects a path that escapes the extraction root with ..', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('../evil.txt', 'evil'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'escapes the extraction root',
    )
  })

  it('rejects an absolute path', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('/etc/evil.txt', 'evil'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('is absolute')
  })

  it('rejects a pax extended header that overrides path', async () => {
    const paxContent = paxRecord('path', 'evil.txt')
    const archive = await rawTarGz([
      {
        header: buildRawHeader({
          name: 'erpc-template.json',
          typeflag: '0',
          size: MANIFEST_CONTENT.length,
        }),
        content: textEncoder.encode(MANIFEST_CONTENT),
      },
      {
        header: buildRawHeader({
          name: 'PaxHeaders/x',
          typeflag: 'x',
          size: paxContent.byteLength,
        }),
        content: paxContent,
      },
      {
        header: buildRawHeader({
          name: 'original-name.txt',
          typeflag: '0',
          size: 4,
        }),
        content: textEncoder.encode('data'),
      },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'pax header field: path',
    )
  })

  it('accepts a pax global header with only allowed keys', async () => {
    const paxContent = paxRecord('comment', 'git archive')
    const archive = await rawTarGz([
      {
        header: buildRawHeader({
          name: 'pax_global_header',
          typeflag: 'g',
          size: paxContent.byteLength,
        }),
        content: paxContent,
      },
      {
        header: buildRawHeader({
          name: 'erpc-template.json',
          typeflag: '0',
          size: MANIFEST_CONTENT.length,
        }),
        content: textEncoder.encode(MANIFEST_CONTENT),
      },
    ])
    const { files } = await extractTemplateArchive(archive)
    expect(files.map((file) => file.path)).toEqual(['erpc-template.json'])
  })

  it('rejects an archive with more than the maximum entry count', async () => {
    const inputs: TarStreamInput[] = [
      fileInput('erpc-template.json', MANIFEST_CONTENT),
    ]
    for (let index = 0; index < TEMPLATE_ARCHIVE_MAX_ENTRIES + 1; index++) {
      inputs.push(fileInput(`file-${index}.txt`, 'x'))
    }
    const archive = await tarGzFromInputs(inputs)
    await expect(extractTemplateArchive(archive)).rejects.toThrow('more than')
  })

  it('rejects an archive that extracts to more than the maximum size', async () => {
    const oversized = new Uint8Array(TEMPLATE_ARCHIVE_MAX_EXTRACTED_BYTES + 1)
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      {
        type: 'file',
        path: 'big.bin',
        size: oversized.byteLength,
        readable: ReadableStream.from([oversized]),
      },
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('bytes')
  })

  it('rejects an archive that bundles erpc.toml', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('erpc.toml', 'schema_version = 1\n'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('erpc.toml')
  })

  it('rejects an archive that bundles node_modules', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('node_modules/pkg/index.js', 'module.exports = {}\n'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'node_modules',
    )
  })

  it('rejects an archive with case-insensitively duplicate paths', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('README.md', 'a'),
      fileInput('readme.md', 'b'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow('duplicate')
  })

  it('rejects an archive missing erpc-template.json', async () => {
    const archive = await tarGzFromInputs([
      fileInput('index.ts', 'export {}\n'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'erpc-template.json',
    )
  })

  // steiner r1 B3: the disallowed-name checks must be case-insensitive.
  it.each(
    [
      ['.GIT/config', '.git'],
      ['ERPC.toml', 'erpc.toml'],
      ['Node_Modules/pkg/index.js', 'node_modules'],
      ['.ENV', 'env file'],
      ['.Dev.vars', '.dev.vars'],
    ] as const,
  )(
    'rejects %s case-insensitively',
    async (path, expectedFragment) => {
      const archive = await tarGzFromInputs([
        fileInput('erpc-template.json', MANIFEST_CONTENT),
        fileInput(path, 'x'),
      ])
      await expect(extractTemplateArchive(archive)).rejects.toThrow(
        expectedFragment,
      )
    },
  )

  it('rejects a file path that collides with a needed directory (cyan r1 N1)', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', MANIFEST_CONTENT),
      fileInput('a', 'file content'),
      fileInput('a/b', 'nested content'),
    ])
    await expect(extractTemplateArchive(archive)).rejects.toThrow(
      'both a file and a directory',
    )
  })
})
