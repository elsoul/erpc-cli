import { mkdir, open, stat, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

const LOCK_STALE_MS = 60_000
const LOCK_WAIT_MS = 15_000

const delay = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds))

export const defaultRefreshLockPath = () =>
  join(homedir(), '.config', 'erpc', 'refresh.lock')

export const withRefreshLock = async <T>(
  operation: () => Promise<T>,
  lockPath = defaultRefreshLockPath(),
): Promise<T> => {
  await mkdir(dirname(lockPath), { mode: 0o700, recursive: true })
  const deadline = Date.now() + LOCK_WAIT_MS

  while (true) {
    try {
      const handle = await open(lockPath, 'wx', 0o600)
      try {
        return await operation()
      } finally {
        await handle.close()
        await unlink(lockPath).catch(() => undefined)
      }
    } catch (error) {
      if (!(error instanceof Error) || !('code' in error) || error.code !== 'EEXIST') {
        throw error
      }

      const lockStat = await stat(lockPath).catch(() => null)
      if (lockStat && Date.now() - lockStat.mtimeMs > LOCK_STALE_MS) {
        await unlink(lockPath).catch(() => undefined)
        continue
      }
      if (Date.now() >= deadline) {
        throw new Error('Another ERPC CLI process is refreshing the login')
      }
      await delay(100)
    }
  }
}
