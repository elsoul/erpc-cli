import { type ProcessRunner, runProcess } from '../process.ts'

const KEYRING_SERVICE = 'erpc-cli'
const KEYRING_ACCOUNT = 'default-refresh-token'

export interface RefreshTokenStore {
  delete(): Promise<void>
  get(): Promise<string | null>
  set(refreshToken: string): Promise<void>
}

export class KeyringRefreshTokenStore implements RefreshTokenStore {
  readonly #account: string
  readonly #run: ProcessRunner
  readonly #service: string

  constructor(
    service = KEYRING_SERVICE,
    account = KEYRING_ACCOUNT,
    run: ProcessRunner = runProcess,
  ) {
    this.#service = service
    this.#account = account
    this.#run = run
  }

  async delete(): Promise<void> {
    this.#requireLinuxKeyring()
    try {
      const result = await this.#run({
        args: [
          'clear',
          'service',
          this.#service,
          'account',
          this.#account,
        ],
        command: 'secret-tool',
      })
      if (result.code === 0 || result.code === 1) return
    } catch {
      throw new Error('Unable to delete the ERPC login from the OS keychain')
    }
    throw new Error('Unable to delete the ERPC login from the OS keychain')
  }

  async get(): Promise<string | null> {
    this.#requireLinuxKeyring()
    try {
      const result = await this.#run({
        args: [
          'lookup',
          'service',
          this.#service,
          'account',
          this.#account,
        ],
        command: 'secret-tool',
      })
      if (result.code === 1) return null
      if (result.code !== 0) throw new Error('keychain lookup failed')
      return result.stdout.replace(/\r?\n$/, '') || null
    } catch {
      throw new Error('Unable to read the ERPC login from the OS keychain')
    }
  }

  async set(refreshToken: string): Promise<void> {
    if (!refreshToken) {
      throw new Error('Refusing to store an empty refresh token')
    }
    this.#requireLinuxKeyring()
    try {
      const result = await this.#run({
        args: [
          'store',
          '--label=ERPC CLI',
          'service',
          this.#service,
          'account',
          this.#account,
        ],
        command: 'secret-tool',
        input: refreshToken,
      })
      if (result.code !== 0) throw new Error('keychain storage failed')
    } catch {
      throw new Error('Unable to store the ERPC login in the OS keychain')
    }
  }

  #requireLinuxKeyring(): void {
    if (Deno.build.os !== 'linux') {
      throw new Error('OS keychain login is currently supported on Linux')
    }
  }
}
