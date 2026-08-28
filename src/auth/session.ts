import {
  DeviceAuthClient,
  OAuthProtocolError,
  type OAuthTokenSet,
} from './device'
import { withRefreshLock } from './refresh-lock'
import type { RefreshTokenStore } from './token-store'

export class CliAuthSession {
  readonly #auth: DeviceAuthClient
  readonly #store: RefreshTokenStore

  constructor(auth: DeviceAuthClient, store: RefreshTokenStore) {
    this.#auth = auth
    this.#store = store
  }

  async getAccessToken(): Promise<string> {
    return withRefreshLock(async () => {
      const refreshToken = await this.#store.get()
      if (!refreshToken) {
        throw new Error('Not logged in. Run `erpc login` first.')
      }

      let tokens: OAuthTokenSet
      try {
        tokens = await this.#auth.refresh(refreshToken)
      } catch (error) {
        if (error instanceof OAuthProtocolError && error.oauthCode === 'invalid_grant') {
          await this.#store.delete()
          throw new Error('ERPC login expired. Run `erpc login` again.')
        }
        throw error
      }
      await this.#store.set(tokens.refreshToken)
      return tokens.accessToken
    })
  }

  async logout(): Promise<boolean> {
    return withRefreshLock(async () => {
      const refreshToken = await this.#store.get()
      if (!refreshToken) return false
      await this.#auth.revoke(refreshToken)
      await this.#store.delete()
      return true
    })
  }
}
