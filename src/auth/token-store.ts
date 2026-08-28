const KEYRING_SERVICE = 'erpc-cli'
const KEYRING_ACCOUNT = 'default-refresh-token'

export interface RefreshTokenStore {
  delete(): Promise<void>
  get(): Promise<string | null>
  set(refreshToken: string): Promise<void>
}

export class KeyringRefreshTokenStore implements RefreshTokenStore {
  readonly #account: string
  readonly #service: string

  constructor(service = KEYRING_SERVICE, account = KEYRING_ACCOUNT) {
    this.#service = service
    this.#account = account
  }

  async #entry() {
    const { Entry } = await import('@napi-rs/keyring')
    return new Entry(this.#service, this.#account)
  }

  async delete(): Promise<void> {
    try {
      const entry = await this.#entry()
      entry.deletePassword()
    } catch (error) {
      if (error instanceof Error && /no entry|not found/i.test(error.message)) return
      throw new Error('Unable to delete the ERPC login from the OS keychain')
    }
  }

  async get(): Promise<string | null> {
    try {
      const entry = await this.#entry()
      return entry.getPassword()
    } catch {
      throw new Error('Unable to read the ERPC login from the OS keychain')
    }
  }

  async set(refreshToken: string): Promise<void> {
    if (!refreshToken) throw new Error('Refusing to store an empty refresh token')
    try {
      const entry = await this.#entry()
      entry.setPassword(refreshToken)
    } catch {
      throw new Error('Unable to store the ERPC login in the OS keychain')
    }
  }
}
