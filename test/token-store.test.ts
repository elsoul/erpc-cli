import { describe, expect, it } from './testing.ts'
import {
  KeyringRefreshTokenStore,
  type ProcessRequest,
  type ProcessResult,
  type ProcessRunner,
} from '../src/index.ts'

const result = (code = 0, stdout = ''): ProcessResult => ({
  code,
  stderr: '',
  stdout,
})

describe('Linux OS keychain adapter', () => {
  it('passes refresh credentials only through secret-tool stdin', async () => {
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      return result()
    }
    const store = new KeyringRefreshTokenStore('service', 'account', run)

    await store.set('refresh-secret')

    expect(calls).toHaveLength(1)
    expect(calls[0]?.command).toBe('secret-tool')
    expect(calls[0]?.args.join(' ')).not.toContain('refresh-secret')
    expect(calls[0]?.input).toBe('refresh-secret')
  })

  it('reads and clears the keychain entry without retaining line endings', async () => {
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      return request.args[0] === 'lookup'
        ? result(0, 'stored-refresh\n')
        : result()
    }
    const store = new KeyringRefreshTokenStore('service', 'account', run)

    await expect(store.get()).resolves.toBe('stored-refresh')
    await store.delete()

    expect(calls.map((call) => call.args[0])).toEqual(['lookup', 'clear'])
  })
})
