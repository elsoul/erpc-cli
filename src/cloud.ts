export const DEFAULT_USER_ENDPOINT = 'https://user-api.erpc.global'

export interface MonthlyUsageParams {
  readonly yearMonth?: string
}

export interface MonthlyApiKeyMethodUsage {
  readonly count: number
  readonly creditCost: number
  readonly credits: number
  readonly method: string
  readonly updatedAt: string | null
}

export interface MonthlyApiKeyChainUsage {
  readonly chain: string
  readonly count: number
  readonly credits: number
  readonly methods: readonly MonthlyApiKeyMethodUsage[]
  readonly updatedAt: string | null
}

export interface MonthlyApiKeyUsageEntry {
  readonly apiKeyLast4: string
  readonly apiKeyLength: number
  readonly chains: readonly MonthlyApiKeyChainUsage[]
  readonly count: number
  readonly credits: number
  readonly keyId: number | null
  readonly updatedAt: string | null
}

export interface MonthlyUsage {
  readonly apiKeys: readonly MonthlyApiKeyUsageEntry[]
  readonly chains: readonly MonthlyApiKeyChainUsage[]
  readonly hasStrandedUsage: boolean
  readonly keyCount: number
  readonly totalCount: number
  readonly totalCredits: number
  readonly updatedAt: string | null
  readonly yearMonth: string
}

export type CloudResourceKind =
  | 'bare-metal'
  | 'solana-grpc'
  | 'solana-shredstream'
  | 'vps'

export type CloudResourceMode = 'dedicated' | 'direct' | 'shared'

export interface CloudResource {
  readonly createdAt?: string
  readonly id: string
  readonly kind: CloudResourceKind
  readonly mode?: CloudResourceMode
  readonly name?: string
  readonly region?: string
  readonly status: string
}

export interface CloudResourceStatusBilling {
  readonly graceEndsAt?: string
  readonly hourlyCredits?: number
  readonly nextChargeAt?: string
  readonly status: 'active' | 'grace-period' | 'inactive' | 'suspended'
}

export interface CloudResourceStatus {
  readonly billing?: CloudResourceStatusBilling
  readonly id: string
  readonly status: string
}

export interface CloudOfferingBilling {
  readonly amountCents: number
  readonly unit: 'cents-per-hour'
}

export interface CloudOfferingCompute {
  readonly tenancy: 'bare-metal' | 'virtual-machine'
}

export interface CloudOfferingSolana {
  readonly transport: 'grpc' | 'shredstream'
}

export interface CloudOffering {
  readonly billing?: CloudOfferingBilling
  readonly capabilities: readonly string[]
  readonly compute?: CloudOfferingCompute
  readonly description: string
  readonly id: string
  readonly kind: CloudResourceKind
  readonly mode?: CloudResourceMode
  readonly name: string
  readonly regions: readonly string[]
  readonly solana?: CloudOfferingSolana
}

export type CloudCreditAlertLevel =
  | 'critical'
  | 'normal'
  | 'suspended'
  | 'warning'

export interface CloudCredit {
  readonly alertLevel: CloudCreditAlertLevel
  readonly balanceCents: number
  readonly burnRateCentsPerHour: number
  readonly quoteExpiresAt: string
  readonly quoteTimestamp: string
  readonly timeToZeroHours: number | null
}

export interface CloudApiClientConfig {
  readonly accessToken: string
  readonly endpoint?: string
  readonly fetch?: typeof globalThis.fetch
  readonly timeoutMs?: number
}

const YEAR_MONTH = /^\d{4}-(0[1-9]|1[0-2])$/

const objectValue = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null
    ? value as Record<string, unknown>
    : null

const isTimestamp = (value: unknown): value is string | null =>
  value === null || typeof value === 'string'

const parseMethod = (value: unknown): MonthlyApiKeyMethodUsage | null => {
  const method = objectValue(value)
  if (
    method === null ||
    typeof method.count !== 'number' ||
    typeof method.creditCost !== 'number' ||
    typeof method.credits !== 'number' ||
    typeof method.method !== 'string' ||
    !isTimestamp(method.updatedAt)
  ) return null
  return {
    count: method.count,
    creditCost: method.creditCost,
    credits: method.credits,
    method: method.method,
    updatedAt: method.updatedAt,
  }
}

const parseChain = (value: unknown): MonthlyApiKeyChainUsage | null => {
  const chain = objectValue(value)
  if (
    chain === null ||
    typeof chain.chain !== 'string' ||
    typeof chain.count !== 'number' ||
    typeof chain.credits !== 'number' ||
    !Array.isArray(chain.methods) ||
    !isTimestamp(chain.updatedAt)
  ) return null
  const methods = chain.methods.map(parseMethod)
  if (methods.some((method) => method === null)) return null
  return {
    chain: chain.chain,
    count: chain.count,
    credits: chain.credits,
    methods: methods as readonly MonthlyApiKeyMethodUsage[],
    updatedAt: chain.updatedAt,
  }
}

const parseApiKey = (value: unknown): MonthlyApiKeyUsageEntry | null => {
  const apiKey = objectValue(value)
  if (
    apiKey === null ||
    typeof apiKey.apiKeyLast4 !== 'string' ||
    typeof apiKey.apiKeyLength !== 'number' ||
    !Array.isArray(apiKey.chains) ||
    typeof apiKey.count !== 'number' ||
    typeof apiKey.credits !== 'number' ||
    (apiKey.keyId !== null && typeof apiKey.keyId !== 'number') ||
    !isTimestamp(apiKey.updatedAt)
  ) return null
  const chains = apiKey.chains.map(parseChain)
  if (chains.some((chain) => chain === null)) return null
  return {
    apiKeyLast4: apiKey.apiKeyLast4,
    apiKeyLength: apiKey.apiKeyLength,
    chains: chains as readonly MonthlyApiKeyChainUsage[],
    count: apiKey.count,
    credits: apiKey.credits,
    keyId: apiKey.keyId,
    updatedAt: apiKey.updatedAt,
  }
}

const parseMonthlyUsage = (value: unknown): MonthlyUsage | null => {
  const usage = objectValue(value)
  if (
    usage === null ||
    !Array.isArray(usage.apiKeys) ||
    !Array.isArray(usage.chains) ||
    typeof usage.hasStrandedUsage !== 'boolean' ||
    typeof usage.keyCount !== 'number' ||
    typeof usage.totalCount !== 'number' ||
    typeof usage.totalCredits !== 'number' ||
    !isTimestamp(usage.updatedAt) ||
    typeof usage.yearMonth !== 'string' ||
    !YEAR_MONTH.test(usage.yearMonth)
  ) return null
  const apiKeys = usage.apiKeys.map(parseApiKey)
  const chains = usage.chains.map(parseChain)
  if (
    apiKeys.some((apiKey) => apiKey === null) ||
    chains.some((chain) => chain === null)
  ) return null
  return {
    apiKeys: apiKeys as readonly MonthlyApiKeyUsageEntry[],
    chains: chains as readonly MonthlyApiKeyChainUsage[],
    hasStrandedUsage: usage.hasStrandedUsage,
    keyCount: usage.keyCount,
    totalCount: usage.totalCount,
    totalCredits: usage.totalCredits,
    updatedAt: usage.updatedAt,
    yearMonth: usage.yearMonth,
  }
}

const resourceKinds: readonly CloudResourceKind[] = [
  'bare-metal',
  'solana-grpc',
  'solana-shredstream',
  'vps',
]
const resourceModes: readonly CloudResourceMode[] = [
  'dedicated',
  'direct',
  'shared',
]
const billingStatuses: readonly CloudResourceStatusBilling['status'][] = [
  'active',
  'grace-period',
  'inactive',
  'suspended',
]
const alertLevels: readonly CloudCreditAlertLevel[] = [
  'critical',
  'normal',
  'suspended',
  'warning',
]

const isDateTime = (value: unknown): value is string =>
  typeof value === 'string' && Number.isFinite(Date.parse(value))

const stringArray = (value: unknown): readonly string[] | null =>
  Array.isArray(value) && value.every((item) => typeof item === 'string')
    ? value
    : null

const parseStatusBilling = (
  value: unknown,
): CloudResourceStatusBilling | null => {
  const billing = objectValue(value)
  if (
    billing === null ||
    typeof billing.status !== 'string' ||
    !billingStatuses.includes(
      billing.status as CloudResourceStatusBilling['status'],
    ) ||
    (billing.hourlyCredits !== undefined &&
      (typeof billing.hourlyCredits !== 'number' ||
        !Number.isFinite(billing.hourlyCredits) ||
        billing.hourlyCredits < 0)) ||
    (billing.nextChargeAt !== undefined &&
      !isDateTime(billing.nextChargeAt)) ||
    (billing.graceEndsAt !== undefined &&
      !isDateTime(billing.graceEndsAt))
  ) return null
  return {
    status: billing.status as CloudResourceStatusBilling['status'],
    ...(typeof billing.hourlyCredits === 'number'
      ? { hourlyCredits: billing.hourlyCredits }
      : {}),
    ...(typeof billing.nextChargeAt === 'string'
      ? { nextChargeAt: billing.nextChargeAt }
      : {}),
    ...(typeof billing.graceEndsAt === 'string'
      ? { graceEndsAt: billing.graceEndsAt }
      : {}),
  }
}

const parseResourceStatus = (value: unknown): CloudResourceStatus | null => {
  const status = objectValue(value)
  if (
    status === null ||
    typeof status.id !== 'string' ||
    typeof status.status !== 'string'
  ) return null
  const billing = status.billing === undefined
    ? undefined
    : parseStatusBilling(status.billing)
  if (status.billing !== undefined && billing === null) return null
  return {
    id: status.id,
    status: status.status,
    ...(billing ? { billing } : {}),
  }
}

const parseOffering = (value: unknown): CloudOffering | null => {
  const offering = objectValue(value)
  if (
    offering === null ||
    typeof offering.id !== 'string' ||
    typeof offering.kind !== 'string' ||
    !resourceKinds.includes(offering.kind as CloudResourceKind) ||
    typeof offering.name !== 'string' ||
    typeof offering.description !== 'string' ||
    (offering.mode !== undefined &&
      (typeof offering.mode !== 'string' ||
        !resourceModes.includes(offering.mode as CloudResourceMode)))
  ) return null
  const regions = stringArray(offering.regions)
  const capabilities = stringArray(offering.capabilities)
  if (regions === null || capabilities === null) return null

  const compute = offering.compute === undefined
    ? undefined
    : objectValue(offering.compute)
  if (
    compute !== undefined &&
    (compute === null ||
      (compute.tenancy !== 'virtual-machine' &&
        compute.tenancy !== 'bare-metal'))
  ) return null
  const solana = offering.solana === undefined
    ? undefined
    : objectValue(offering.solana)
  if (
    solana !== undefined &&
    (solana === null ||
      (solana.transport !== 'grpc' && solana.transport !== 'shredstream'))
  ) return null
  const billing = offering.billing === undefined
    ? undefined
    : objectValue(offering.billing)
  if (
    billing !== undefined &&
    (billing === null ||
      billing.unit !== 'cents-per-hour' ||
      typeof billing.amountCents !== 'number' ||
      !Number.isInteger(billing.amountCents) ||
      billing.amountCents < 0)
  ) return null

  return {
    id: offering.id,
    kind: offering.kind as CloudResourceKind,
    name: offering.name,
    description: offering.description,
    regions,
    capabilities,
    ...(typeof offering.mode === 'string'
      ? { mode: offering.mode as CloudResourceMode }
      : {}),
    ...(compute &&
        (compute.tenancy === 'virtual-machine' || compute.tenancy === 'bare-metal')
      ? { compute: { tenancy: compute.tenancy } }
      : {}),
    ...(solana &&
        (solana.transport === 'grpc' || solana.transport === 'shredstream')
      ? { solana: { transport: solana.transport } }
      : {}),
    ...(billing &&
        billing.unit === 'cents-per-hour' &&
        typeof billing.amountCents === 'number'
      ? {
        billing: {
          amountCents: billing.amountCents,
          unit: billing.unit,
        },
      }
      : {}),
  }
}

const parseCredit = (value: unknown): CloudCredit | null => {
  const credit = objectValue(value)
  if (
    credit === null ||
    typeof credit.balanceCents !== 'number' ||
    !Number.isInteger(credit.balanceCents) ||
    typeof credit.burnRateCentsPerHour !== 'number' ||
    !Number.isInteger(credit.burnRateCentsPerHour) ||
    credit.burnRateCentsPerHour < 0 ||
    (credit.timeToZeroHours !== null &&
      (typeof credit.timeToZeroHours !== 'number' ||
        !Number.isFinite(credit.timeToZeroHours) ||
        credit.timeToZeroHours < 0)) ||
    typeof credit.alertLevel !== 'string' ||
    !alertLevels.includes(credit.alertLevel as CloudCreditAlertLevel) ||
    !isDateTime(credit.quoteTimestamp) ||
    !isDateTime(credit.quoteExpiresAt)
  ) return null
  return {
    alertLevel: credit.alertLevel as CloudCreditAlertLevel,
    balanceCents: credit.balanceCents,
    burnRateCentsPerHour: credit.burnRateCentsPerHour,
    quoteExpiresAt: credit.quoteExpiresAt,
    quoteTimestamp: credit.quoteTimestamp,
    timeToZeroHours: credit.timeToZeroHours,
  }
}
const parseResource = (value: unknown): CloudResource | null => {
  const resource = objectValue(value)
  if (
    resource === null ||
    typeof resource.id !== 'string' ||
    typeof resource.kind !== 'string' ||
    !resourceKinds.includes(resource.kind as CloudResourceKind) ||
    typeof resource.status !== 'string' ||
    (resource.mode !== undefined &&
      (typeof resource.mode !== 'string' ||
        !resourceModes.includes(resource.mode as CloudResourceMode))) ||
    (resource.name !== undefined && typeof resource.name !== 'string') ||
    (resource.region !== undefined && typeof resource.region !== 'string') ||
    (resource.createdAt !== undefined && typeof resource.createdAt !== 'string')
  ) return null

  return {
    id: resource.id,
    kind: resource.kind as CloudResourceKind,
    status: resource.status,
    ...(typeof resource.mode === 'string'
      ? { mode: resource.mode as CloudResourceMode }
      : {}),
    ...(typeof resource.name === 'string' ? { name: resource.name } : {}),
    ...(typeof resource.region === 'string' ? { region: resource.region } : {}),
    ...(typeof resource.createdAt === 'string'
      ? { createdAt: resource.createdAt }
      : {}),
  }
}

const normalizedEndpoint = (value?: string): URL => {
  const endpoint = new URL(value ?? DEFAULT_USER_ENDPOINT)
  const isLocalHttp = endpoint.protocol === 'http:' &&
    ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(endpoint.hostname)
  if (endpoint.protocol !== 'https:' && !isLocalHttp) {
    throw new Error('Cloud endpoint must use HTTPS except on localhost')
  }
  endpoint.search = ''
  endpoint.hash = ''
  endpoint.pathname = endpoint.pathname.replace(/\/+$/, '') || '/'
  return endpoint
}

export class CloudApiClient {
  readonly #accessToken: string
  readonly #endpoint: URL
  readonly #fetch: typeof globalThis.fetch
  readonly #timeoutMs: number

  constructor(config: CloudApiClientConfig) {
    this.#accessToken = config.accessToken.trim()
    if (!this.#accessToken) throw new Error('accessToken must not be empty')
    this.#endpoint = normalizedEndpoint(config.endpoint)
    this.#fetch = config.fetch ?? globalThis.fetch
    this.#timeoutMs = config.timeoutMs ?? 30_000
    if (typeof this.#fetch !== 'function') {
      throw new Error('A Fetch API implementation is required')
    }
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new Error('timeoutMs must be a positive finite number')
    }
  }

  async getMonthlyApiKeyUsage(
    params: MonthlyUsageParams = {},
  ): Promise<MonthlyUsage> {
    if (
      params.yearMonth !== undefined &&
      !YEAR_MONTH.test(params.yearMonth)
    ) {
      throw new Error('yearMonth must use YYYY-MM format')
    }
    const usage = parseMonthlyUsage(
      await this.#get('/v3/user/api-keys/usage', params.yearMonth
        ? { yearMonth: params.yearMonth }
        : undefined),
    )
    if (usage === null) {
      throw new Error('ERPC Cloud returned invalid monthly usage')
    }
    return usage
  }

  async listResources(): Promise<readonly CloudResource[]> {
    const message = objectValue(await this.#get(
      '/v4/cloud/resources',
    ))
    if (!Array.isArray(message?.resources)) {
      throw new Error('ERPC Cloud returned an invalid resource list')
    }
    const resources = message.resources.map(parseResource)
    if (resources.some((resource) => resource === null)) {
      throw new Error('ERPC Cloud returned an invalid resource list')
    }
    return resources as readonly CloudResource[]
  }

  async listCatalog(): Promise<readonly CloudOffering[]> {
    const message = objectValue(await this.#get('/v4/cloud/catalog'))
    if (!Array.isArray(message?.offerings)) {
      throw new Error('ERPC Cloud returned an invalid catalog')
    }
    const offerings = message.offerings.map(parseOffering)
    if (offerings.some((offering) => offering === null)) {
      throw new Error('ERPC Cloud returned an invalid catalog')
    }
    return offerings as readonly CloudOffering[]
  }

  async getCredit(): Promise<CloudCredit> {
    const credit = parseCredit(await this.#get('/v4/cloud/credit'))
    if (credit === null) {
      throw new Error('ERPC Cloud returned an invalid credit snapshot')
    }
    return credit
  }

  async getResource(resourceId: string): Promise<CloudResource> {
    const normalizedId = resourceId.trim()
    if (!normalizedId) throw new Error('resourceId must not be empty')
    const message = objectValue(
      await this.#get(`/v4/cloud/resources/${encodeURIComponent(normalizedId)}`),
    )
    const resource = parseResource(message?.resource)
    if (resource === null) {
      throw new Error('ERPC Cloud returned an invalid resource')
    }
    return resource
  }

  async getResourceStatus(resourceId: string): Promise<CloudResourceStatus> {
    const normalizedId = resourceId.trim()
    if (!normalizedId) throw new Error('resourceId must not be empty')
    const status = parseResourceStatus(
      await this.#get(
        `/v4/cloud/resources/${encodeURIComponent(normalizedId)}/status`,
      ),
    )
    if (status === null) {
      throw new Error('ERPC Cloud returned an invalid resource status')
    }
    return status
  }

  async #get<T>(path: string, query?: Readonly<Record<string, string>>): Promise<T> {
    const url = new URL(this.#endpoint)
    const base = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '')
    url.pathname = `${base}/${path.replace(/^\/+/, '')}`.replace(/\/{2,}/g, '/')
    for (const [key, value] of Object.entries(query ?? {})) {
      url.searchParams.set(key, value)
    }
    let response: Response
    try {
      response = await this.#fetch(url, {
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${this.#accessToken}`,
        },
        signal: AbortSignal.timeout(this.#timeoutMs),
      })
    } catch {
      throw new Error('Unable to reach ERPC Cloud')
    }
    if (!response.ok) {
      throw new Error(`ERPC Cloud request failed with HTTP ${response.status}`)
    }
    let body: unknown
    try {
      body = await response.json()
    } catch {
      throw new Error('ERPC Cloud returned malformed JSON')
    }
    const envelope = objectValue(body)
    if (
      envelope?.success !== true ||
      envelope.message === null ||
      typeof envelope.message !== 'object'
    ) {
      throw new Error('ERPC Cloud returned an invalid response')
    }
    return envelope.message as T
  }
}
