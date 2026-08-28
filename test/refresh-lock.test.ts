import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { withRefreshLock } from '../src'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

describe('refresh lock', () => {
  it('serializes refresh operations from concurrent CLI processes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'erpc-cli-lock-'))
    directories.push(directory)
    const lockPath = join(directory, 'refresh.lock')
    let active = 0
    let maximumActive = 0

    const operation = () => withRefreshLock(async () => {
      active++
      maximumActive = Math.max(maximumActive, active)
      await new Promise((resolve) => setTimeout(resolve, 20))
      active--
    }, lockPath)

    await Promise.all([operation(), operation()])

    expect(maximumActive).toBe(1)
  })
})
