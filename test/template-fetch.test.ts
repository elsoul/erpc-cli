import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  obtainVerifiedTemplateArchive,
  sha256Hex,
  TEMPLATE_ARCHIVE_MAX_BYTES,
  templateAssetUrl,
} from '../src/app/template-fetch.ts'

const directories: string[] = []

const temporaryErpcHome = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), 'erpc-template-fetch-'))
  directories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

const cacheEntries = async (erpcHome: string): Promise<readonly string[]> => {
  try {
    return await readdir(join(erpcHome, 'cache', 'templates'))
  } catch {
    return []
  }
}

const jsonResponse = (bytes: Uint8Array, status = 200): Response =>
  new Response(bytes as unknown as BodyInit, { status })

describe('templateAssetUrl', () => {
  it('encodes the tag and asset but not the owner or repo', () => {
    const url = templateAssetUrl(
      {
        owner: 'elsoul',
        repo: 'stablecoin-manager-template',
        asset: 'erpc-template.tar.gz',
      },
      'v0.1.0',
    )
    expect(url.toString()).toBe(
      'https://github.com/elsoul/stablecoin-manager-template/releases/download/v0.1.0/erpc-template.tar.gz',
    )
  })

  it('percent-encodes unusual tag and asset characters', () => {
    const url = templateAssetUrl(
      { owner: 'elsoul', repo: 'repo', asset: 'a b.tar.gz' },
      'v0.1.0-rc+1',
    )
    expect(url.pathname).toContain('a%20b.tar.gz')
  })
})

describe('obtainVerifiedTemplateArchive', () => {
  it('fetches, verifies, and caches the archive under sha256-<hex>.tar.gz', async () => {
    const erpcHome = await temporaryErpcHome()
    const body = new TextEncoder().encode('fixture archive bytes')
    const expected = await sha256Hex(body)
    let calls = 0
    const fetchStub = (async () => {
      calls++
      return jsonResponse(body)
    }) as typeof fetch

    const first = await obtainVerifiedTemplateArchive(
      new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
      erpcHome,
      expected,
      { fetch: fetchStub },
    )
    expect(first).toEqual(body)
    expect(calls).toBe(1)
    expect(await cacheEntries(erpcHome)).toEqual([`sha256-${expected}.tar.gz`])

    const second = await obtainVerifiedTemplateArchive(
      new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
      erpcHome,
      expected,
      { fetch: fetchStub },
    )
    expect(second).toEqual(body)
    expect(calls).toBe(1) // served from the verified cache, not refetched
  })

  it('rejects a checksum mismatch without writing to the cache', async () => {
    const erpcHome = await temporaryErpcHome()
    const body = new TextEncoder().encode('fixture archive bytes')
    const wrongExpected = '0'.repeat(64)
    const fetchStub = (async () => jsonResponse(body)) as typeof fetch

    await expect(
      obtainVerifiedTemplateArchive(
        new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
        erpcHome,
        wrongExpected,
        { fetch: fetchStub },
      ),
    ).rejects.toThrow('checksum')
    expect(await cacheEntries(erpcHome)).toEqual([])
  })

  it('rejects a download over the compressed size limit', async () => {
    const erpcHome = await temporaryErpcHome()
    const oversized = new Uint8Array(TEMPLATE_ARCHIVE_MAX_BYTES + 1)
    const expected = await sha256Hex(oversized)
    const fetchStub = (async () => jsonResponse(oversized)) as typeof fetch

    await expect(
      obtainVerifiedTemplateArchive(
        new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
        erpcHome,
        expected,
        { fetch: fetchStub },
      ),
    ).rejects.toThrow('exceeds')
    expect(await cacheEntries(erpcHome)).toEqual([])
  })

  it('rejects an HTTP (non-HTTPS) download URL', async () => {
    const erpcHome = await temporaryErpcHome()
    await expect(
      obtainVerifiedTemplateArchive(
        new URL('http://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
        erpcHome,
        '0'.repeat(64),
      ),
    ).rejects.toThrow('HTTPS')
  })

  it('rejects a non-2xx response', async () => {
    const erpcHome = await temporaryErpcHome()
    const fetchStub =
      (async () => jsonResponse(new Uint8Array(), 404)) as typeof fetch
    await expect(
      obtainVerifiedTemplateArchive(
        new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
        erpcHome,
        '0'.repeat(64),
        { fetch: fetchStub },
      ),
    ).rejects.toThrow('404')
  })

  it('re-verifies a cache entry on every read and heals a corrupted one', async () => {
    const erpcHome = await temporaryErpcHome()
    const goodBody = new TextEncoder().encode('correct archive bytes')
    const expected = await sha256Hex(goodBody)
    const cachePath = join(
      erpcHome,
      'cache',
      'templates',
      `sha256-${expected}.tar.gz`,
    )
    await mkdir(join(erpcHome, 'cache', 'templates'), { recursive: true })
    // Plant a file at the expected cache path whose content does NOT hash to
    // `expected` (as if it were corrupted on disk), bypassing
    // obtainVerifiedTemplateArchive entirely.
    await writeFile(cachePath, new TextEncoder().encode('corrupted bytes'))

    let calls = 0
    const fetchStub = (async () => {
      calls++
      return jsonResponse(goodBody)
    }) as typeof fetch

    const result = await obtainVerifiedTemplateArchive(
      new URL('https://github.com/o/r/releases/download/v0.1.0/a.tar.gz'),
      erpcHome,
      expected,
      { fetch: fetchStub },
    )

    // The corrupted cache entry must not have been trusted: a real fetch had
    // to happen, and the returned bytes are the freshly verified ones.
    expect(calls).toBe(1)
    expect(result).toEqual(goodBody)
    // The cache entry is healed in place rather than left corrupted forever.
    expect(new Uint8Array(await readFile(cachePath))).toEqual(goodBody)
  })
})
