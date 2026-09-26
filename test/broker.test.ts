import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { assert, assertEquals, assertRejects } from '@std/assert'
import { TarStream, type TarStreamInput } from '@std/tar'
import { parse as parseToml } from '@std/toml'
import { afterEach, describe, it } from './testing.ts'
import {
  assertIssuerDiscovery,
  BrokerRegistrationError,
  type BrokerRegistrationFailure,
} from '../src/broker/discovery.ts'
import {
  type BrokerRegistrarDeps,
  createBrokerRegistrar,
} from '../src/broker/register.ts'
import { runCli } from '../src/cli.ts'
import { defaultOidcClientRegistrar } from '../src/app/template-init.ts'
import { sha256Hex } from '../src/app/template-fetch.ts'
import type { TemplateRegistry } from '../src/app/template-registry.ts'

const ISSUER = 'https://broker.example.com'
const USER_CODE = 'BCDF-GHJK'
const VERIFICATION_URI_COMPLETE = `${ISSUER}/register?user_code=${USER_CODE}`
// A recognisable device_code: it must never show up in output or errors.
const DEVICE_SENTINEL = 'DEVICE-SENTINEL-abcdefghijklmnopqrstuvwxyz0'
const CLIENT_ID = 'app_AbCdEfGhIjKlMnOpQrStUv'
const APPROVER = 'owner@example.com'
const CLIENT_NAME = 'my-app'
const REDIRECT_URIS = [
  'https://app.example.org/oauth/callback',
  'https://staging.app.example.org/oauth/callback',
] as const
const REGISTRATION_PATH = '/clients/registration-requests'
const POLL_PATH = '/clients/registration-requests/poll'

// ---------------------------------------------------------------------------
// Fake broker
// ---------------------------------------------------------------------------

interface RecordedRequest {
  readonly body: string | undefined
  readonly headers: Headers
  readonly method: string
  readonly path: string
  readonly redirect: RequestRedirect | undefined
  readonly url: string
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })

const oauthError = (error: string, description?: string): Response =>
  json(
    400,
    description === undefined
      ? { error }
      : { error, error_description: description },
  )

const discoveryDocument = (issuer = ISSUER): Record<string, unknown> => ({
  issuer,
  authorization_endpoint: `${issuer}/oauth/authorize`,
  token_endpoint: `${issuer}/oauth/token`,
  jwks_uri: `${issuer}/.well-known/jwks.json`,
  response_types_supported: ['code'],
  response_modes_supported: ['query'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['ES256'],
  scopes_supported: ['openid', 'email'],
  claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'email'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
  authorization_response_iss_parameter_supported: true,
})

const registrationCreated = (
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
  device_code: DEVICE_SENTINEL,
  user_code: USER_CODE,
  verification_uri: `${ISSUER}/register`,
  verification_uri_complete: VERIFICATION_URI_COMPLETE,
  expires_in: 600,
  interval: 5,
  ...overrides,
})

interface SubmittedRegistration {
  readonly client_name: string
  readonly redirect_uris: readonly string[]
}

/** The approved-registration body the broker returns from a poll. */
const approvedRegistration = (
  submitted: SubmittedRegistration,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
  client_id: CLIENT_ID,
  client_name: submitted.client_name,
  redirect_uris: [...submitted.redirect_uris],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code'],
  response_types: ['code'],
  client_id_issued_at: 1_790_000_000,
  approved_by_email: APPROVER,
  ...overrides,
})

type PollStep =
  | Response
  | Error
  | ((context: PollContext) => Response | Error)

interface PollContext {
  readonly now: number
  readonly submitted: SubmittedRegistration
}

const approve =
  (overrides: Record<string, unknown> = {}) => (context: PollContext) =>
    json(200, approvedRegistration(context.submitted, overrides))

const pending = () => oauthError('authorization_pending')

interface FakeBroker {
  readonly fetch: typeof fetch
  /** The fake clock's time at each poll, in order. */
  readonly pollTimes: readonly number[]
  readonly polls: () => number
  readonly posts: () => number
  readonly requests: readonly RecordedRequest[]
}

const fakeBroker = (options: {
  readonly clock: Clock
  readonly created?: () => Response
  readonly discovery?: () => Response
  /** The origin the fake broker serves. Defaults to `ISSUER`. */
  readonly issuer?: string
  /** Poll answers in order; once exhausted, every further poll is pending. */
  readonly polls?: readonly PollStep[]
}): FakeBroker => {
  const requests: RecordedRequest[] = []
  const pollTimes: number[] = []
  const steps = [...(options.polls ?? [])]
  let submitted: SubmittedRegistration = {
    client_name: '',
    redirect_uris: [],
  }
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = new URL(input instanceof Request ? input.url : input)
    const body = typeof init?.body === 'string' ? init.body : undefined
    const record: RecordedRequest = {
      body,
      headers: new Headers(init?.headers),
      method: init?.method ?? 'GET',
      path: url.pathname,
      redirect: init?.redirect,
      url: url.href,
    }
    requests.push(record)
    const issuer = options.issuer ?? ISSUER
    if (url.origin !== issuer) {
      throw new TypeError(`unexpected origin ${url.origin}`)
    }
    if (
      record.method === 'GET' &&
      url.pathname === '/.well-known/openid-configuration'
    ) {
      return options.discovery?.() ?? json(200, discoveryDocument(issuer))
    }
    if (record.method === 'POST' && url.pathname === REGISTRATION_PATH) {
      submitted = JSON.parse(body ?? '{}') as SubmittedRegistration
      return options.created?.() ?? json(201, registrationCreated())
    }
    if (record.method === 'POST' && url.pathname === POLL_PATH) {
      pollTimes.push(options.clock.now())
      const step = steps.shift() ?? pending()
      const result = typeof step === 'function'
        ? step({ now: options.clock.now(), submitted })
        : step
      if (result instanceof Error) throw result
      return result
    }
    return json(404, { error: 'not_found' })
  }) as typeof fetch
  return {
    fetch: fetchImpl,
    pollTimes,
    polls: () =>
      requests.filter((request) => request.path === POLL_PATH).length,
    posts: () => requests.filter((request) => request.method === 'POST').length,
    requests,
  }
}

interface Clock {
  readonly now: () => number
  readonly sleep: (milliseconds: number) => Promise<void>
  readonly sleeps: readonly number[]
}

const fakeClock = (start = 1_800_000_000_000): Clock => {
  let current = start
  const sleeps: number[] = []
  return {
    now: () => current,
    sleep: (milliseconds: number) => {
      sleeps.push(milliseconds)
      current += milliseconds
      return Promise.resolve()
    },
    sleeps,
  }
}

interface Run {
  readonly broker: FakeBroker
  readonly clock: Clock
  readonly opened: readonly string[]
  readonly output: readonly string[]
  readonly result: Promise<{ readonly clientId: string }>
}

const run = (options: {
  readonly clientName?: string
  readonly created?: () => Response
  readonly deps?: BrokerRegistrarDeps
  readonly discovery?: () => Response
  readonly issuer?: string
  readonly polls?: readonly PollStep[]
  readonly redirectUris?: readonly string[]
  readonly signal?: AbortSignal
} = {}): Run => {
  const clock = fakeClock()
  const broker = fakeBroker({
    clock,
    ...(options.created ? { created: options.created } : {}),
    ...(options.discovery ? { discovery: options.discovery } : {}),
    ...(options.issuer ? { issuer: options.issuer } : {}),
    ...(options.polls ? { polls: options.polls } : {}),
  })
  const output: string[] = []
  const opened: string[] = []
  const registrar = createBrokerRegistrar({
    fetch: broker.fetch,
    now: clock.now,
    sleep: clock.sleep,
    ...options.deps,
  })
  const result = registrar.register(
    {
      issuer: options.issuer ?? ISSUER,
      clientName: options.clientName ?? CLIENT_NAME,
      redirectUris: options.redirectUris ?? REDIRECT_URIS,
    },
    {
      output: (message) => output.push(message),
      openExternal: (url) => opened.push(url),
      ...(options.signal ? { signal: options.signal } : {}),
    },
  )
  return { broker, clock, opened, output, result }
}

/** Every failure must be a typed error that never carries the device_code. */
const expectFailure = async (
  subject: Run,
  reason: BrokerRegistrationFailure,
): Promise<BrokerRegistrationError> => {
  const error = await assertRejects(
    () => subject.result,
    BrokerRegistrationError,
  )
  assertEquals(error.reason, reason, error.message)
  assert(!error.message.includes(DEVICE_SENTINEL))
  assert(!String(error.stack).includes(DEVICE_SENTINEL))
  assertNoSecretInOutput(subject)
  assert(
    !subject.output.some((line) => line.startsWith('Approved by:')),
    'nothing may be reported as approved after a failure',
  )
  return error
}

const assertNoSecretInOutput = (subject: Run): void => {
  for (const line of subject.output) {
    assert(!line.includes(DEVICE_SENTINEL), `device_code leaked: ${line}`)
  }
  for (const url of subject.opened) assert(!url.includes(DEVICE_SENTINEL))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createBrokerRegistrar', () => {
  it('registers after two pending polls and reports the approver once', async () => {
    const subject = run({ polls: [pending(), pending(), approve()] })

    assertEquals(await subject.result, { clientId: CLIENT_ID })
    assert(subject.output.includes(`Open ${VERIFICATION_URI_COMPLETE}`))
    assert(subject.output.includes(`Code: ${USER_CODE}`))
    const confirmation = subject.output.find((line) =>
      line.startsWith('Before approving')
    )
    assert(confirmation !== undefined)
    for (const uri of REDIRECT_URIS) assert(confirmation.includes(uri))
    assertEquals(
      subject.output.filter((line) => line.startsWith('Approved by:')),
      [
        `Approved by: ${APPROVER} — if this is not the Google account you used, stop and do not deploy.`,
      ],
    )
    assertEquals(subject.opened, [VERIFICATION_URI_COMPLETE])
    assertNoSecretInOutput(subject)

    assertEquals(
      subject.broker.requests.map((request) =>
        `${request.method} ${request.path}`
      ),
      [
        'GET /.well-known/openid-configuration',
        `POST ${REGISTRATION_PATH}`,
        `POST ${POLL_PATH}`,
        `POST ${POLL_PATH}`,
        `POST ${POLL_PATH}`,
      ],
    )
    // The first poll only happens after one full interval.
    assertEquals(subject.clock.sleeps, [5000, 5000, 5000])
    assertEquals(JSON.parse(subject.broker.requests[1]!.body!), {
      client_name: CLIENT_NAME,
      redirect_uris: [...REDIRECT_URIS],
    })
    for (const poll of subject.broker.requests.slice(2)) {
      assertEquals(JSON.parse(poll.body!), { device_code: DEVICE_SENTINEL })
    }
  })

  it('sends every request without following redirects or credentials, and POSTs JSON', async () => {
    const subject = run({ polls: [pending(), approve()] })
    await subject.result

    assert(subject.broker.requests.length > 0)
    for (const request of subject.broker.requests) {
      assertEquals(request.redirect, 'manual', request.path)
      assertEquals(request.headers.get('authorization'), null, request.path)
      assertEquals(request.headers.get('accept'), 'application/json')
      if (request.method === 'POST') {
        assertEquals(request.headers.get('content-type'), 'application/json')
        JSON.parse(request.body!)
      } else {
        assertEquals(request.body, undefined)
      }
    }
  })

  describe('issuer discovery', () => {
    const cases: ReadonlyArray<readonly [string, () => Response]> = [
      [
        'names the issuer with a trailing slash',
        () => json(200, discoveryDocument(`${ISSUER}/`)),
      ],
      [
        'names another origin',
        () => json(200, discoveryDocument('https://other.example.com')),
      ],
      ['redirects', () =>
        new Response(null, {
          status: 302,
          headers: {
            location:
              'https://other.example.com/.well-known/openid-configuration',
          },
        })],
      [
        'is not JSON',
        () =>
          new Response('{"issuer": "https://broker.example.com"', {
            status: 200,
          }),
      ],
      ['has no issuer', () => json(200, { jwks_uri: `${ISSUER}/jwks` })],
      ['is not found', () => json(404, { error: 'not_found' })],
    ]
    for (const [label, discovery] of cases) {
      it(`fails without POSTing when the discovery document ${label}`, async () => {
        const subject = run({ discovery })
        await expectFailure(subject, 'discovery_failed')
        assertEquals(subject.broker.posts(), 0)
        assertEquals(subject.output, [])
      })
    }

    it('fails without POSTing when discovery cannot be reached', async () => {
      const subject = run({
        discovery: () => {
          throw new TypeError('connection refused')
        },
      })
      await expectFailure(subject, 'discovery_failed')
      assertEquals(subject.broker.posts(), 0)
    })

    it('times out a discovery request that never answers', async () => {
      const hanging =
        ((_input: string | URL | Request, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              'abort',
              () => reject(new DOMException('Aborted', 'AbortError')),
            )
          })) as typeof fetch
      const error = await assertRejects(
        () =>
          assertIssuerDiscovery(ISSUER, {
            fetch: hanging,
            requestTimeoutMs: 10,
          }),
        BrokerRegistrationError,
      )
      assertEquals(error.reason, 'discovery_failed')
    })

    it('refuses a discovery document over 64 KiB and accepts one of exactly 64 KiB', async () => {
      const paddedTo = (bytes: number): string => {
        const empty = JSON.stringify({ ...discoveryDocument(), pad: '' })
        return JSON.stringify({
          ...discoveryDocument(),
          pad: 'x'.repeat(bytes - empty.length),
        })
      }
      assertEquals(new TextEncoder().encode(paddedTo(65_536)).length, 65_536)

      const over = run({
        discovery: () => new Response(paddedTo(65_537), { status: 200 }),
      })
      await expectFailure(over, 'discovery_failed')
      assertEquals(over.broker.posts(), 0)

      const exact = run({
        discovery: () => new Response(paddedTo(65_536), { status: 200 }),
        polls: [approve()],
      })
      assertEquals(await exact.result, { clientId: CLIENT_ID })
    })

    it('times out a discovery response whose body stops arriving', async () => {
      // Headers arrive at once; the body sends one chunk and then stalls
      // until the request is aborted, as a real fetch body does.
      const stalledBody =
        ((_input: string | URL | Request, init?: RequestInit) =>
          Promise.resolve(
            new Response(
              new ReadableStream<Uint8Array>({
                start(controller) {
                  controller.enqueue(new TextEncoder().encode('{"issuer":'))
                  init?.signal?.addEventListener(
                    'abort',
                    () =>
                      controller.error(
                        new DOMException('Aborted', 'AbortError'),
                      ),
                    { once: true },
                  )
                },
              }),
              { status: 200 },
            ),
          )) as typeof fetch
      let guard: ReturnType<typeof setTimeout> | undefined
      const outcome = await Promise.race([
        assertIssuerDiscovery(ISSUER, {
          fetch: stalledBody,
          requestTimeoutMs: 20,
        }).then(() => 'resolved', (error: unknown) => error),
        new Promise<string>((resolve) => {
          guard = setTimeout(() => resolve('still waiting'), 2_000)
        }),
      ])
      clearTimeout(guard)
      assert(outcome instanceof BrokerRegistrationError, String(outcome))
      assertEquals(outcome.reason, 'discovery_failed')
      assert(outcome.message.includes('could not be reached'))
    })

    it('rejects an issuer that is not a bare origin before any request', async () => {
      for (
        const issuer of [
          `${ISSUER}/`,
          `${ISSUER}/path`,
          'http://broker.example.com',
        ]
      ) {
        const subject = run({ issuer })
        await expectFailure(subject, 'invalid_issuer')
        assertEquals(subject.broker.requests.length, 0)
      }
    })
  })

  describe('checks before sending', () => {
    it('lists every client_name and redirect_uri violation and sends nothing', async () => {
      const subject = run({
        clientName: 'n'.repeat(65),
        redirectUris: [
          'http://app.example.org/cb',
          'https://app.example.org/cb?next=1',
          'https://app.example.org/cb#top',
          'https://user:pw@app.example.org/cb',
          'https://localhost/cb',
          'https://203.0.113.7/cb',
          'https://broker.example.com/cb',
          'https://APP.example.org/cb',
        ],
      })
      const error = await expectFailure(subject, 'invalid_request')
      for (
        const expected of [
          'client_name must be 1 to 64 characters (got 65)',
          'redirect_uris must contain 1 to 5 entries (got 8)',
          'redirect_uris[0] "http://app.example.org/cb" must use https',
          'redirect_uris[1] "https://app.example.org/cb?next=1" must not contain a query',
          'redirect_uris[2] "https://app.example.org/cb#top" must not contain a fragment',
          'redirect_uris[3] "https://user:pw@app.example.org/cb" must not contain userinfo',
          'redirect_uris[4] "https://localhost/cb" host must not be localhost',
          'redirect_uris[5] "https://203.0.113.7/cb" host must not be an IP address',
          `redirect_uris[6] "https://broker.example.com/cb" host must not be the broker's own host`,
          'redirect_uris[7] "https://APP.example.org/cb" is not in canonical form',
        ]
      ) {
        assert(
          error.message.includes(expected),
          `missing: ${expected}\n${error.message}`,
        )
      }
      assertEquals(subject.broker.requests.length, 0)
    })

    it('rejects six redirect URIs', async () => {
      const subject = run({
        redirectUris: Array.from(
          { length: 6 },
          (_, index) => `https://app${index}.example.org/cb`,
        ),
      })
      const error = await expectFailure(subject, 'invalid_request')
      assert(error.message.includes('1 to 5 entries (got 6)'))
      assertEquals(subject.broker.requests.length, 0)
    })

    it('rejects an empty query or fragment and a URI over 2048 characters', async () => {
      const prefix = 'https://app.example.org/'
      const tooLong = `${prefix}${'a'.repeat(2049 - prefix.length)}`
      const subject = run({
        redirectUris: [
          'https://app.example.org/cb?',
          'https://app.example.org/cb#',
          tooLong,
        ],
      })
      const error = await expectFailure(subject, 'invalid_request')
      const lines = error.message.split('\n')
      assertEquals(
        lines.filter((line) => line.includes('redirect_uris[0]')),
        [
          '  - redirect_uris[0] "https://app.example.org/cb?" must not contain a query',
        ],
      )
      assertEquals(
        lines.filter((line) => line.includes('redirect_uris[1]')),
        [
          '  - redirect_uris[1] "https://app.example.org/cb#" must not contain a fragment',
        ],
      )
      const longIssues = lines.filter((line) =>
        line.includes('redirect_uris[2]')
      )
      assertEquals(longIssues.length, 1)
      assert(longIssues[0]!.endsWith('longer than 2048 characters'))
      assertEquals(subject.broker.requests.length, 0)
    })

    it('accepts a redirect URI of exactly 2048 characters', async () => {
      const prefix = 'https://app.example.org/'
      const longest = `${prefix}${'a'.repeat(2048 - prefix.length)}`
      const subject = run({ redirectUris: [longest], polls: [approve()] })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
    })

    it('rejects the other forms the broker refuses', async () => {
      const subject = run({
        clientName: 'bad\u202ename',
        redirectUris: [
          'https://[2001:db8::1]/cb',
          'https://*.example.org/cb',
          'https://app.example.org./cb',
          'https://dev.localhost/cb',
          'https://api.erpc.global/cb',
          'https://app.example.org/cb',
          'https://app.example.org/cb',
        ],
      })
      const error = await expectFailure(subject, 'invalid_request')
      for (
        const expected of [
          'client_name must not contain control or format characters',
          'redirect_uris[0] "https://[2001:db8::1]/cb" host must not be an IP address',
          'redirect_uris[1] "https://*.example.org/cb" must not contain a wildcard',
          'redirect_uris[2] "https://app.example.org./cb" host must not end with a dot',
          'redirect_uris[3] "https://dev.localhost/cb" host must not be localhost',
          'redirect_uris[4] "https://api.erpc.global/cb" host must not be erpc.global',
          'redirect_uris[6] "https://app.example.org/cb" is listed more than once',
        ]
      ) {
        assert(
          error.message.includes(expected),
          `missing: ${expected}\n${error.message}`,
        )
      }
      assertEquals(subject.broker.requests.length, 0)
    })
  })

  describe('the registration request', () => {
    it('stops without polling when the verification page is on another origin', async () => {
      const evil = 'https://phish.example.net/register?user_code=BCDF-GHJK'
      for (
        const overrides of [
          { verification_uri_complete: evil },
          { verification_uri: 'https://phish.example.net/register' },
        ]
      ) {
        const subject = run({
          created: () => json(201, registrationCreated(overrides)),
        })
        const error = await expectFailure(subject, 'untrusted_verification_uri')
        assert(!error.message.includes('phish.example.net'))
        assert(
          !subject.output.some((line) => line.includes('phish.example.net')),
        )
        assertEquals(subject.opened, [])
        assertEquals(subject.broker.polls(), 0)
      }
    })

    it('opens the verification page only in its fixed form', async () => {
      const unexpected: ReadonlyArray<readonly [string, readonly string[]]> = [
        [`${VERIFICATION_URI_COMPLETE}&calc`, ['calc']],
        [`${VERIFICATION_URI_COMPLETE}&t=%CLOUDFLARE_API_TOKEN%`, [
          'CLOUDFLARE_API_TOKEN',
        ]],
        [`${ISSUER}/register?u=%USERNAME%|x^y`, ['USERNAME', '|', '^']],
      ]
      for (const [complete, fragments] of unexpected) {
        const subject = run({
          created: () =>
            json(
              201,
              registrationCreated({ verification_uri_complete: complete }),
            ),
          polls: [approve()],
        })
        assertEquals(await subject.result, { clientId: CLIENT_ID }, complete)
        assertEquals(subject.opened, [], complete)
        assertEquals(subject.output.slice(0, 2), [
          `Open ${ISSUER}/register`,
          `Code: ${USER_CODE}`,
        ])
        for (const line of subject.output) {
          assert(!line.includes('?'), line)
          for (const fragment of fragments) {
            assert(!line.includes(fragment), `${fragment} in ${line}`)
          }
        }
      }
    })

    it('does not open the fixed form when the issuer host has a shell metacharacter', async () => {
      for (
        const issuer of [
          'https://x&calc.example.com',
          'https://x!username!.example.com',
        ]
      ) {
        const subject = run({
          issuer,
          created: () =>
            json(
              201,
              registrationCreated({
                verification_uri: `${issuer}/register`,
                verification_uri_complete:
                  `${issuer}/register?user_code=${USER_CODE}`,
              }),
            ),
          polls: [approve()],
        })
        assertEquals(await subject.result, { clientId: CLIENT_ID }, issuer)
        assertEquals(subject.opened, [], issuer)
        assertEquals(subject.output.slice(0, 2), [
          `Open ${issuer}/register`,
          `Code: ${USER_CODE}`,
        ], issuer)
      }
    })

    it('prints the verification_uri fallback without its query', async () => {
      const subject = run({
        created: () =>
          json(
            201,
            registrationCreated({
              verification_uri: `${ISSUER}/register?x=%CLOUDFLARE_API_TOKEN%`,
              verification_uri_complete:
                `${ISSUER}/register?x=1&user_code=${USER_CODE}`,
            }),
          ),
        polls: [approve()],
      })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.opened, [])
      assertEquals(subject.output.slice(0, 2), [
        `Open ${ISSUER}/register`,
        `Code: ${USER_CODE}`,
      ])
    })

    it('neither prints nor opens a verification_uri_complete that carries the device_code', async () => {
      const subject = run({
        created: () =>
          json(
            201,
            registrationCreated({
              verification_uri_complete:
                `${VERIFICATION_URI_COMPLETE}&device_code=${DEVICE_SENTINEL}`,
            }),
          ),
        polls: [approve()],
      })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.opened, [])
      assert(subject.output.includes(`Open ${ISSUER}/register`))
      assertNoSecretInOutput(subject)
    })

    it('refuses a registration response whose user_code is the device_code', async () => {
      const subject = run({
        created: () =>
          json(201, registrationCreated({ device_code: USER_CODE })),
      })
      const error = await expectFailure(subject, 'invalid_response')
      assert(error.message.includes('(user_code)'))
      assert(!error.message.includes(USER_CODE))
      assertEquals(subject.output, [])
      assertEquals(subject.opened, [])
      assertEquals(subject.broker.polls(), 0)
    })

    it('refuses a registration response whose user_code contains the device_code', async () => {
      const deviceCode = USER_CODE.slice(1, 6)
      const subject = run({
        created: () =>
          json(201, registrationCreated({ device_code: deviceCode })),
      })
      const error = await expectFailure(subject, 'invalid_response')
      assert(error.message.includes('(user_code)'), error.message)
      assert(!error.message.includes(deviceCode))
      assertEquals(subject.output, [])
      assertEquals(subject.opened, [])
      assertEquals(subject.broker.polls(), 0)
    })

    it('refuses a registration response whose printed verification page carries the device_code', async () => {
      const page = `${ISSUER}/register/${DEVICE_SENTINEL}`
      const subject = run({
        created: () =>
          json(
            201,
            registrationCreated({
              verification_uri: page,
              verification_uri_complete: `${page}?user_code=${USER_CODE}`,
            }),
          ),
      })
      const error = await expectFailure(subject, 'invalid_response')
      assert(error.message.includes('(verification_uri)'))
      assertEquals(subject.output, [])
      assertEquals(subject.opened, [])
      assertEquals(subject.broker.polls(), 0)
    })

    // Each case would print the device code in a changed form (percent-encoded
    // in the page path, or with its control character removed from the
    // approver email) if the device code were accepted.
    const deviceCodesChangedByPrinting: ReadonlyArray<
      readonly [string, string, string, Record<string, unknown>, PollStep]
    > = [
      [
        'a space',
        'dev code',
        'dev%20code',
        {
          verification_uri: `${ISSUER}/r/dev code`,
          verification_uri_complete:
            `${ISSUER}/r/dev code?user_code=${USER_CODE}`,
        },
        approve(),
      ],
      [
        'a control character',
        'dev\u0007code',
        'devcode',
        {},
        approve({ approved_by_email: 'devcode@example.com' }),
      ],
    ]
    for (
      const [label, deviceCode, printed, overrides, poll]
        of deviceCodesChangedByPrinting
    ) {
      it(`refuses a device_code with ${label} before printing anything`, async () => {
        const subject = run({
          created: () =>
            json(
              201,
              registrationCreated({ device_code: deviceCode, ...overrides }),
            ),
          polls: [poll],
        })
        const error = await expectFailure(subject, 'invalid_response')
        assert(error.message.includes('(device_code)'), error.message)
        assert(!error.message.includes(printed), error.message)
        assertEquals(subject.output, [])
        assertEquals(subject.opened, [])
        assertEquals(subject.broker.polls(), 0)
      })
    }

    it('shows the broker error code and a cleaned, bounded description on 400', async () => {
      const subject = run({
        created: () =>
          oauthError(
            'invalid_redirect_uri',
            `redirect_uris\u001b is\u202e invalid ${'x'.repeat(400)}`,
          ),
      })
      const error = await expectFailure(subject, 'rejected')
      assert(
        error.message.includes(
          '(invalid_redirect_uri): redirect_uris is invalid',
        ),
      )
      assert(!error.message.includes('\u001b'))
      assert(!error.message.includes('\u202e'))
      assert(!error.message.includes('x'.repeat(200)))
      assertEquals(subject.broker.polls(), 0)
    })

    it('asks the user to wait when the broker answers 429', async () => {
      const subject = run({
        created: () =>
          json(429, {
            error: 'temporarily_unavailable',
            error_description: 'rate_limited',
          }),
      })
      const error = await expectFailure(subject, 'rate_limited')
      assert(error.message.includes('Wait a while'))
      assertEquals(subject.broker.polls(), 0)
    })

    const invalidCreated: ReadonlyArray<
      readonly [string, Record<string, unknown>]
    > = [
      ['device_code', { device_code: '' }],
      ['user_code', { user_code: 'bcdf-ghjk' }],
      ['expires_in', { expires_in: 1801 }],
      ['expires_in', { expires_in: 1.5 }],
      ['interval', { interval: 0 }],
      ['interval', { interval: 61 }],
      ['verification_uri_complete', { verification_uri_complete: 'not a url' }],
    ]
    for (const [field, overrides] of invalidCreated) {
      it(`rejects a registration response with an invalid ${field} (${JSON.stringify(overrides)})`, async () => {
        const subject = run({
          created: () => json(201, registrationCreated(overrides)),
        })
        const error = await expectFailure(subject, 'invalid_response')
        assert(error.message.includes(field))
        assertEquals(subject.broker.polls(), 0)
        assertEquals(subject.output, [])
      })
    }

    it('requires exactly 201', async () => {
      const subject = run({ created: () => json(200, registrationCreated()) })
      await expectFailure(subject, 'invalid_response')
      assertEquals(subject.broker.polls(), 0)
    })
  })

  describe('polling', () => {
    it('adds five seconds to the interval after slow_down', async () => {
      const subject = run({
        polls: [pending(), oauthError('slow_down'), pending(), approve()],
      })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.clock.sleeps, [5000, 5000, 10000, 10000])
    })

    it('stops with distinct messages for quota, denial, and an expired request', async () => {
      const quota = run({
        polls: [oauthError('access_denied', 'quota_exceeded')],
      })
      const denied = run({ polls: [oauthError('access_denied')] })
      const expired = run({ polls: [oauthError('expired_token')] })
      const messages = [
        (await expectFailure(quota, 'quota_exceeded')).message,
        (await expectFailure(denied, 'access_denied')).message,
        (await expectFailure(expired, 'expired_token')).message,
      ]
      assertEquals(new Set(messages).size, 3)
      assert(messages[0]!.includes('registration limit'))
      assert(messages[1]!.includes('denied in the browser'))
      assert(messages[2]!.includes('expired or was already used'))
    })

    it('gives up 60 s after the last poll before expires_in, after at most 22 polls', async () => {
      const subject = run({
        created: () =>
          json(201, registrationCreated({ expires_in: 60, interval: 5 })),
        // Pending for every poll the window allows. A poll past the window is
        // denied, so polling too long fails the assertions below instead of
        // running without end.
        polls: [
          ...Array.from({ length: 22 }, pending),
          oauthError('access_denied'),
        ],
      })
      const start = subject.clock.now()
      const error = await expectFailure(subject, 'expired')
      assert(error.message.includes('expired before it was approved'))
      assertEquals(subject.broker.polls(), 22)
      // Polls at 5 s, 10 s, ... 55 s before expiry. The 55 s poll could have
      // been answered with a lost approval, so polling goes on until 60 s
      // after it: 60 s, 65 s, ... 110 s. The 115 s mark is the end itself.
      assertEquals(
        subject.broker.pollTimes.map((time) => (time - start) / 1000),
        Array.from({ length: 22 }, (_, index) => 5 * (index + 1)),
      )
    })

    it('never sleeps past the expiry when the interval is longer than the lifetime', async () => {
      const subject = run({
        created: () =>
          json(201, registrationCreated({ expires_in: 1, interval: 60 })),
      })
      await expectFailure(subject, 'expired')
      assert(subject.clock.sleeps.length > 0)
      for (const milliseconds of subject.clock.sleeps) {
        assert(milliseconds <= 1000, `slept ${milliseconds} ms`)
      }
      assert(
        subject.clock.sleeps.reduce((sum, value) => sum + value, 0) <= 1000,
      )
      assertEquals(subject.broker.polls(), 0)
    })

    it('keeps polling through network errors and server errors', async () => {
      const subject = run({
        polls: [
          new TypeError('connection reset'),
          json(503, { error: 'server_error' }),
          new Response('<html>bad gateway</html>', { status: 502 }),
          json(429, { error: 'temporarily_unavailable' }),
          approve(),
        ],
      })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.broker.polls(), 5)
    })

    it('stops without showing a poll error code that carries the device_code', async () => {
      const codes = [
        `bad_${DEVICE_SENTINEL}`,
        // Only the shown form, after control characters are removed, has it.
        `${DEVICE_SENTINEL.slice(0, 16)}\u0007${DEVICE_SENTINEL.slice(16)}`,
        // Only the full value has it; the shown form is cut at 64 characters.
        `${'x'.repeat(30)}${DEVICE_SENTINEL}`,
      ]
      for (const code of codes) {
        const subject = run({ polls: [oauthError(code)] })
        const error = await expectFailure(subject, 'invalid_response')
        assert(error.message.includes('(error)'), error.message)
        assert(!error.message.includes('SENTINEL'), error.message)
        assertEquals(subject.broker.polls(), 1)
      }
    })

    it('stops on an unexpected poll status', async () => {
      const subject = run({
        polls: [
          new Response(null, {
            status: 302,
            headers: { location: 'https://x.example' },
          }),
        ],
      })
      await expectFailure(subject, 'invalid_response')
      assertEquals(subject.broker.polls(), 1)
    })

    it('stops at once when the signal aborts while waiting', async () => {
      const controller = new AbortController()
      const clock = fakeClock()
      const broker = fakeBroker({ clock })
      let sleeps = 0
      const registrar = createBrokerRegistrar({
        fetch: broker.fetch,
        now: clock.now,
        sleep: async (milliseconds) => {
          sleeps++
          await clock.sleep(milliseconds)
          if (sleeps === 2) controller.abort()
        },
      })
      const error = await assertRejects(() =>
        registrar.register(
          {
            issuer: ISSUER,
            clientName: CLIENT_NAME,
            redirectUris: REDIRECT_URIS,
          },
          { output: () => {}, signal: controller.signal },
        )
      )
      assert(error instanceof DOMException && error.name === 'AbortError')
      assertEquals(broker.polls(), 1)
    })

    it('sends nothing when the signal is already aborted', async () => {
      const controller = new AbortController()
      controller.abort()
      const subject = run({ signal: controller.signal })
      await assertRejects(() => subject.result, DOMException)
      assertEquals(subject.broker.requests.length, 0)
    })
  })

  describe('the approved registration', () => {
    it('accepts redirect URIs returned in a different order', async () => {
      const subject = run({
        polls: [approve({ redirect_uris: [...REDIRECT_URIS].reverse() })],
      })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
    })

    const mismatches: ReadonlyArray<
      readonly [string, Record<string, unknown>]
    > = [
      ['one extra redirect URI', {
        redirect_uris: [...REDIRECT_URIS, 'https://extra.example.org/cb'],
      }],
      ['one missing redirect URI', { redirect_uris: [REDIRECT_URIS[0]] }],
      ['a different redirect URI', {
        redirect_uris: [
          REDIRECT_URIS[0],
          'https://other.example.org/oauth/callback',
        ],
      }],
      ['a duplicated redirect URI', {
        redirect_uris: [REDIRECT_URIS[0], REDIRECT_URIS[0]],
      }],
      ['a different client_name', { client_name: 'someone-else' }],
    ]
    for (const [label, overrides] of mismatches) {
      it(`refuses a registration with ${label}`, async () => {
        const subject = run({ polls: [approve(overrides)] })
        const error = await expectFailure(subject, 'registration_mismatch')
        assert(error.message.includes('does not match the request'))
        assert(error.message.includes('was not used'))
      })
    }

    it('refuses without showing a client_id that carries the device_code', async () => {
      const subject = run({
        polls: [
          approve({
            client_id: `app_${DEVICE_SENTINEL}`,
            client_name: 'someone-else',
          }),
        ],
      })
      const error = await expectFailure(subject, 'invalid_response')
      assert(error.message.includes('(client_id)'), error.message)
    })

    it('refuses without showing an approver email that carries the device_code', async () => {
      const subject = run({
        polls: [
          approve({ approved_by_email: `${DEVICE_SENTINEL}@example.com` }),
        ],
      })
      const error = await expectFailure(subject, 'invalid_response')
      assert(error.message.includes('(approved_by_email)'), error.message)
    })

    it('refuses a malformed client_id', async () => {
      const subject = run({
        polls: [approve({ client_id: 'app id with spaces' })],
      })
      await expectFailure(subject, 'invalid_response')
    })

    const badApprovers: ReadonlyArray<
      readonly [string, Record<string, unknown>]
    > = [
      ['missing', { approved_by_email: undefined }],
      ['empty', { approved_by_email: '' }],
      ['without @', { approved_by_email: 'owner.example.com' }],
      ['with a control character', {
        approved_by_email: 'owner@example.com\u0007',
      }],
      ['with a newline', {
        approved_by_email: 'owner@example.com\nApproved by: x',
      }],
      ['with a bidi override', {
        approved_by_email: 'owner@\u202eexample.com',
      }],
      ['too long', { approved_by_email: `${'a'.repeat(310)}@example.com` }],
      ['not a string', { approved_by_email: ['owner@example.com'] }],
    ]
    for (const [label, overrides] of badApprovers) {
      it(`refuses a registration whose approved_by_email is ${label}`, async () => {
        const subject = run({ polls: [approve(overrides)] })
        await expectFailure(subject, 'invalid_approver')
      })
    }
  })

  describe('redelivery after a lost response', () => {
    // The broker marks the registration delivered, then keeps answering the
    // same device_code with the same 200 for 60 seconds.
    const deliverOnce = (options: { readonly loseBody?: boolean } = {}) => {
      let deliveredAt: number | undefined
      const step = (context: PollContext): Response | Error => {
        if (deliveredAt === undefined) {
          deliveredAt = context.now
          if (options.loseBody) {
            let sent = false
            return new Response(
              new ReadableStream<Uint8Array>({
                pull(controller) {
                  if (sent) {
                    controller.error(new TypeError('connection reset'))
                    return
                  }
                  sent = true
                  controller.enqueue(
                    new TextEncoder().encode('{"client_id":"app_'),
                  )
                },
              }),
              { status: 200 },
            )
          }
          return new TypeError('connection reset')
        }
        if (context.now < deliveredAt + 60_000) {
          return json(200, approvedRegistration(context.submitted))
        }
        return oauthError('expired_token')
      }
      return step
    }

    it('accepts the same approval on the next poll inside the grace period', async () => {
      const step = deliverOnce()
      const subject = run({ polls: [pending(), step, step] })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.broker.polls(), 3)
      assertEquals(
        subject.output.filter((line) => line.startsWith('Approved by:')).length,
        1,
      )
    })

    it('treats a 200 whose body is cut off as lost and retries', async () => {
      const step = deliverOnce({ loseBody: true })
      const subject = run({ polls: [step, step] })
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      assertEquals(subject.broker.polls(), 2)
    })

    it('receives an approval lost at the last poll before expiry', async () => {
      const step = deliverOnce()
      const subject = run({
        created: () =>
          json(201, registrationCreated({ expires_in: 60, interval: 5 })),
        polls: [...Array.from({ length: 10 }, pending), step, step],
      })
      const start = subject.clock.now()
      assertEquals(await subject.result, { clientId: CLIENT_ID })
      // The approval went out, and was lost, at 55 s; it arrives again from
      // the poll at 60 s, which is already past expires_in.
      assertEquals(
        subject.broker.pollTimes.slice(-2).map((time) => (time - start) / 1000),
        [55, 60],
      )
      assertEquals(
        subject.output.filter((line) => line.startsWith('Approved by:')).length,
        1,
      )
    })

    it('stops with the expired-request message once the grace period is over', async () => {
      const step = deliverOnce()
      const subject = run({
        created: () => json(201, registrationCreated({ interval: 60 })),
        polls: [step, step],
      })
      const error = await expectFailure(subject, 'expired_token')
      assert(error.message.includes('expired or was already used'))
    })
  })

  it('is what app init uses when no registrar is injected', async () => {
    // A trailing-slash issuer is refused before any request, so this reaches
    // no network: it only shows that the default is this registrar.
    const error = await assertRejects(
      () =>
        defaultOidcClientRegistrar.register(
          {
            issuer: `${ISSUER}/`,
            clientName: CLIENT_NAME,
            redirectUris: REDIRECT_URIS,
          },
          { output: () => {} },
        ),
      BrokerRegistrationError,
    )
    assertEquals(error.reason, 'invalid_issuer')
  })

  it('rejects a non-positive request timeout', () => {
    let thrown: unknown
    try {
      createBrokerRegistrar({ requestTimeoutMs: 0 })
    } catch (error) {
      thrown = error
    }
    assert(thrown instanceof Error)
  })
})

// ---------------------------------------------------------------------------
// End to end through `erpc app init --template`
// ---------------------------------------------------------------------------

const directories: string[] = []
afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

const tarGz = async (
  files: Readonly<Record<string, string>>,
): Promise<Uint8Array> => {
  const encoder = new TextEncoder()
  const inputs: TarStreamInput[] = Object.entries(files).map((
    [path, content],
  ) => ({
    type: 'file',
    path,
    size: encoder.encode(content).byteLength,
    readable: ReadableStream.from([encoder.encode(content)]),
  }))
  const chunks: Uint8Array[] = []
  const stream = ReadableStream.from(inputs)
    .pipeThrough(new TarStream())
    .pipeThrough(
      new CompressionStream('gzip') as unknown as ReadableWritablePair<
        Uint8Array,
        Uint8Array
      >,
    )
  for await (const chunk of stream) chunks.push(chunk)
  const out = new Uint8Array(
    chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0),
  )
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

const brokerTemplateArchive = (): Promise<Uint8Array> =>
  tarGz({
    'erpc-template.json': JSON.stringify({
      schemaVersion: 1,
      name: 'broker-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: { config: 'wrangler.toml', wrangler: ['wrangler'] },
      broker: { issuer: ISSUER },
      render: [{ path: 'wrangler.toml', format: 'toml' }],
      prompts: [
        {
          key: 'domain',
          target: 'var',
          flag: 'domain',
          question: 'Custom domain',
          validate: { pattern: '[a-z0-9.-]+' },
        },
        {
          key: 'APP_OIDC_CLIENT_ID',
          target: 'broker-register',
          redirectUris: ['https://{{domain}}/oauth/callback'],
          clientName: '{{app.name}}',
          validate: { pattern: 'app_[A-Za-z0-9_-]{22}' },
        },
      ],
    }),
    'wrangler.toml': `name = "{{app.name}}"
main = "src/index.ts"
compatibility_date = "2026-01-01"

[vars]
AUTH_PROVIDER = "app-oidc"
APP_OIDC_ISSUER = "{{broker.issuer}}"
APP_OIDC_CLIENT_ID = "{{APP_OIDC_CLIENT_ID}}"
`,
    'src/index.ts': 'export default { fetch: () => new Response("ok") }\n',
  })

describe('erpc app init --template with a broker-register prompt', () => {
  it('writes the client_id the broker approved into wrangler.toml and erpc.toml', async () => {
    const archive = await brokerTemplateArchive()
    const sha256 = await sha256Hex(archive)
    const registry: TemplateRegistry = {
      'broker-template': {
        source: {
          owner: 'elsoul',
          repo: 'broker-template',
          asset: 'erpc-template.tar.gz',
        },
        pins: { 'v0.1.0': sha256 },
      },
    }
    const parent = await mkdtemp(join(tmpdir(), 'erpc-broker-init-'))
    directories.push(parent)
    const directory = join(parent, 'my-app')
    const clock = fakeClock()
    const broker = fakeBroker({ clock, polls: [pending(), approve()] })
    const output: string[] = []
    const opened: string[] = []

    const code = await runCli(
      [
        'app',
        'init',
        directory,
        '--template',
        'broker-template@v0.1.0',
        '--set',
        'domain=my-app.example.org',
        '--yes',
      ],
      {
        erpcHome: join(parent, '.erpc'),
        templateRegistry: registry,
        fetch: (() =>
          Promise.resolve(
            new Response(archive as unknown as BodyInit),
          )) as typeof fetch,
        oidcRegistrar: createBrokerRegistrar({
          fetch: broker.fetch,
          now: clock.now,
          sleep: clock.sleep,
        }),
        openExternal: (url) => opened.push(url),
        output: (message) => output.push(message),
      },
    )

    assertEquals(code, 0)
    assertEquals(JSON.parse(broker.requests[1]!.body!), {
      client_name: 'my-app',
      redirect_uris: ['https://my-app.example.org/oauth/callback'],
    })
    const wrangler = parseToml(
      await readFile(join(directory, 'wrangler.toml'), 'utf8'),
    ) as { vars: Record<string, string> }
    assertEquals(wrangler.vars.APP_OIDC_CLIENT_ID, CLIENT_ID)
    assertEquals(wrangler.vars.APP_OIDC_ISSUER, ISSUER)
    const erpcToml = parseToml(
      await readFile(join(directory, 'erpc.toml'), 'utf8'),
    ) as {
      oidc: { client_id: string; issuer: string; redirect_uris: string[] }
    }
    assertEquals(erpcToml.oidc, {
      issuer: ISSUER,
      client_id: CLIENT_ID,
      redirect_uris: ['https://my-app.example.org/oauth/callback'],
    })
    assert(output.includes(`Open ${VERIFICATION_URI_COMPLETE}`))
    assertEquals(
      output.filter((line) => line.startsWith('Approved by:')).length,
      1,
    )
    assertEquals(opened, [VERIFICATION_URI_COMPLETE])
    for (const line of output) assert(!line.includes(DEVICE_SENTINEL))
  })
})
