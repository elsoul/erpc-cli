// Collects answers for `var`, `derived`, and `broker-register` prompts.
// See design doc §2.5/§2.6 and Task Brief Decision 6.
//
// `secret-generate` / `secret-pipe` / `secret-input` prompts are resolved at
// deploy time (PR-B), not here (design §2.2: their "confirmed" column is
// "deploy"). Callers must reject `--set` for those keys before this module
// runs (Decision 6: "`--set` で secret target のキーを渡したらエラー").
//
// Broker registration is resolved once, after every `var`/`derived` prompt in
// the manifest has been processed (not inline, mid-loop): a var declared
// *after* the broker-register prompt must still block the registrar call,
// and issuer trust must be checked (and reported) independently of whether
// other answers are missing (packet Decision 6).

import type { PromptIO } from './prompt-io.ts'
import type {
  BrokerRegisterPrompt,
  TemplateManifest,
  VarPrompt,
} from './template-manifest.ts'

const MAX_ANSWER_LENGTH = 512
// Every control character, including tab/newline/carriage-return: Decision 6
// requires "no control characters" unconditionally.
// deno-lint-ignore no-control-regex
const CONTROL_CHARACTER_PATTERN = /[\x00-\x1f\x7f]/
const PLACEHOLDER_PATTERN = /\{\{([^{}]+)\}\}/g

export class TemplateAnswersError extends Error {
  readonly issues: readonly string[]

  constructor(issues: readonly string[]) {
    super(
      `Unable to collect template answers:\n${
        issues.map((issue) => `  - ${issue}`).join('\n')
      }`,
    )
    this.name = 'TemplateAnswersError'
    this.issues = issues
  }
}

const howToProvide = (prompt: VarPrompt): string =>
  prompt.flag !== undefined
    ? `pass --${prompt.flag} <value> or --set ${prompt.key}=<value>`
    : `pass --set ${prompt.key}=<value>`

const anchoredPattern = (pattern: string): RegExp =>
  new RegExp(`^(?:${pattern})$`)

const answerShapeIssue = (key: string, value: string): string | undefined => {
  if (value.length > MAX_ANSWER_LENGTH) {
    return `${key}: answer exceeds ${MAX_ANSWER_LENGTH} characters`
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    return `${key}: answer contains a control character`
  }
  if (value.includes('{{')) {
    // Prevents an answer from smuggling a fake `{{erpc:...}}` sentinel into a
    // rendered file, where a later deploy step would treat it as genuine.
    return `${key}: answer must not contain "{{" (reserved for template placeholders)`
  }
  return undefined
}

const interpolate = (
  text: string,
  values: ReadonlyMap<string, string>,
  builtIns: TemplateAnswerBuiltIns,
): string =>
  text.replace(PLACEHOLDER_PATTERN, (_whole, rawName: string) => {
    const name = rawName.trim()
    if (name === 'app.name') return builtIns.appName
    if (name === 'broker.issuer') {
      if (builtIns.brokerIssuer === undefined) {
        throw new Error(
          'Cannot resolve {{broker.issuer}}: this template has no broker.issuer',
        )
      }
      return builtIns.brokerIssuer
    }
    const value = values.get(name)
    if (value === undefined) {
      throw new Error(
        `Cannot resolve {{${name}}}: no value has been collected yet`,
      )
    }
    return value
  })

export interface TemplateAnswerBuiltIns {
  readonly appName: string
  readonly brokerIssuer?: string
}

export interface TemplateAnswerInputs {
  readonly builtIns: TemplateAnswerBuiltIns
  /** Resolves whether the (unpinned) broker issuer should be trusted for this run (Decision 7). */
  readonly confirmIssuerTrust: (issuer: string) => Promise<boolean>
  readonly domainValue?: string
  readonly emailValue?: string
  readonly interactive: boolean
  /**
   * Called once, with every `var`/`derived` answer resolved, before broker
   * registration is attempted - the hook the interactive summary uses so it
   * always prints before the registrar runs (design §2.5).
   */
  readonly onAnswersReady?: (values: ReadonlyMap<string, string>) => void
  readonly promptIO: PromptIO
  readonly resolveBrokerRegister: (
    prompt: BrokerRegisterPrompt,
    redirectUris: readonly string[],
    clientName: string,
  ) => Promise<string>
  readonly setValues: ReadonlyMap<string, string>
}

export interface CollectedBrokerRegistration {
  readonly clientId: string
  readonly key: string
  readonly redirectUris: readonly string[]
  /** False when `clientId` came from `--set` rather than an actual registrar call. */
  readonly registered: boolean
}

export interface CollectedTemplateAnswers {
  readonly brokerRegistration?: CollectedBrokerRegistration
  readonly values: ReadonlyMap<string, string>
}

/**
 * Resolves every `var` and `derived` prompt in manifest order (non-
 * interactively, every `var` is checked independently so all missing keys
 * and validation failures are reported together - Acceptance A8; `PromptIO`
 * is never called in that path), then - once, after the full manifest has
 * been walked - resolves at most one `broker-register` prompt (L6 caps the
 * manifest at one). Issuer trust is always checked and always contributes to
 * the same aggregated error; the registrar itself is only actually called
 * once every other answer in the manifest (declared before *or* after the
 * broker-register prompt) is known to be valid, unless `--set` already
 * supplied the value, in which case only that value's own shape/pattern is
 * checked and the registrar is never called.
 */
export const collectTemplateAnswers = async (
  manifest: TemplateManifest,
  inputs: TemplateAnswerInputs,
): Promise<CollectedTemplateAnswers> => {
  const values = new Map<string, string>()
  const issues: string[] = []
  let brokerPrompt: BrokerRegisterPrompt | undefined

  for (const prompt of manifest.prompts) {
    if (prompt.target === 'var') {
      const sugar = prompt.flag === 'domain'
        ? inputs.domainValue
        : prompt.flag === 'email'
        ? inputs.emailValue
        : undefined
      const provided = sugar ?? inputs.setValues.get(prompt.key)

      let resolved: string | undefined
      if (provided !== undefined) {
        resolved = provided
      } else if (inputs.interactive) {
        resolved = await inputs.promptIO.text(prompt.question, {
          ...(prompt.default === undefined ? {} : { default: prompt.default }),
          ...(prompt.validate === undefined ? {} : {
            validate: (value: string): boolean | string => {
              const shapeIssue = answerShapeIssue(prompt.key, value)
              if (shapeIssue) return shapeIssue
              return anchoredPattern(prompt.validate!.pattern).test(value) ||
                `Must match ${prompt.validate!.pattern}`
            },
          }),
        })
      } else if (prompt.default !== undefined) {
        resolved = prompt.default
      }

      if (resolved === undefined) {
        issues.push(`${prompt.key}: missing value (${howToProvide(prompt)})`)
        continue
      }
      const shapeIssue = answerShapeIssue(prompt.key, resolved)
      if (shapeIssue) {
        issues.push(`${shapeIssue} (${howToProvide(prompt)})`)
        continue
      }
      if (
        prompt.validate &&
        !anchoredPattern(prompt.validate.pattern).test(resolved)
      ) {
        issues.push(
          `${prompt.key}: value does not match the required pattern (${
            howToProvide(prompt)
          })`,
        )
        continue
      }
      values.set(prompt.key, resolved)
      continue
    }

    if (prompt.target === 'derived') {
      try {
        values.set(
          prompt.key,
          interpolate(prompt.expr, values, inputs.builtIns),
        )
      } catch (error) {
        // The reference this expression depends on failed earlier in this
        // same loop (that failure already has its own issue above) - still
        // enumerate this derived key's own failure explicitly rather than
        // resolving it silently, so the aggregated error names every key
        // that came out unresolved, not just the root cause (packet
        // Decision 6).
        issues.push(
          `${prompt.key}: could not be derived (${
            error instanceof Error ? error.message : String(error)
          })`,
        )
      }
      continue
    }

    if (
      prompt.target === 'secret-generate' ||
      prompt.target === 'secret-pipe' ||
      prompt.target === 'secret-input'
    ) {
      continue // resolved at deploy time (PR-B), not during init
    }

    // prompt.target === 'broker-register': defer to a single pass below, so
    // registration only happens after the entire manifest is known-good.
    brokerPrompt = prompt
  }

  inputs.onAnswersReady?.(values)

  let brokerRegistration: CollectedBrokerRegistration | undefined
  if (brokerPrompt) {
    const prompt = brokerPrompt
    const setValue = inputs.setValues.get(prompt.key)

    // `--set`'s own shape/pattern is a local, side-effect-free check with no
    // dependency on issuer trust, so it is validated - and, if bad, reported
    // - regardless of whether the issuer turns out to be trusted: an
    // untrusted issuer must not swallow a genuinely malformed `--set` value
    // out of the same aggregated error (packet Decision 6).
    let setValueValid = false
    if (setValue !== undefined) {
      const shapeIssue = answerShapeIssue(prompt.key, setValue)
      if (shapeIssue) {
        issues.push(shapeIssue)
      } else if (
        prompt.validate &&
        !anchoredPattern(prompt.validate.pattern).test(setValue)
      ) {
        issues.push(
          `${prompt.key}: --set value does not match the required pattern (pass --set ${prompt.key}=<value> matching ${prompt.validate.pattern})`,
        )
      } else {
        setValueValid = true
      }
    }

    const trusted = await inputs.confirmIssuerTrust(
      inputs.builtIns.brokerIssuer ?? '',
    )
    if (!trusted) {
      issues.push(
        `${prompt.key}: the broker issuer is not trusted (pass --trust-issuer <origin>, or confirm interactively)`,
      )
    } else if (setValue !== undefined) {
      // The format issue (if any) was already pushed above; only record the
      // answer when it actually passed.
      if (setValueValid) {
        let redirectUris: readonly string[] = []
        try {
          redirectUris = prompt.redirectUris.map((uri) =>
            interpolate(uri, values, inputs.builtIns)
          )
        } catch {
          // `--set` never calls the registrar, so it has no use for
          // redirectUris; keep the recorded list empty rather than failing
          // an otherwise-valid --set value over an unrelated missing key.
        }
        values.set(prompt.key, setValue)
        brokerRegistration = {
          clientId: setValue,
          key: prompt.key,
          redirectUris,
          registered: false,
        }
      }
    } else {
      // No `--set`: attempt the real registrar call, but only once every
      // other answer in the manifest (declared before *or* after
      // broker-register) is known to be valid.
      let redirectUris: readonly string[] = []
      let clientName = ''
      let interpolationFailed = false
      try {
        redirectUris = prompt.redirectUris.map((uri) =>
          interpolate(uri, values, inputs.builtIns)
        )
        clientName = interpolate(prompt.clientName, values, inputs.builtIns)
      } catch {
        interpolationFailed = true
      }
      if (!interpolationFailed && issues.length === 0) {
        const clientId = await inputs.resolveBrokerRegister(
          prompt,
          redirectUris,
          clientName,
        )
        const shapeIssue = answerShapeIssue(prompt.key, clientId)
        const patternOk = prompt.validate === undefined ||
          anchoredPattern(prompt.validate.pattern).test(clientId)
        if (shapeIssue !== undefined || !patternOk) {
          // The registrar *was* called and returned this value - show it
          // (redacted if it carries a control character) rather than only
          // saying "invalid", so the user can tell the bad value came back
          // from the network rather than from their own --set (packet
          // Decision 6).
          const shown = CONTROL_CHARACTER_PATTERN.test(clientId)
            ? `<redacted, ${clientId.length} characters>`
            : clientId
          issues.push(
            `${prompt.key}: the registrar's response does not match the required pattern (got ${shown}; pass --set ${prompt.key}=<value> to override)`,
          )
        } else {
          values.set(prompt.key, clientId)
          brokerRegistration = {
            clientId,
            key: prompt.key,
            redirectUris,
            registered: true,
          }
        }
      }
    }
  }

  if (issues.length > 0) throw new TemplateAnswersError(issues)
  return { values, ...(brokerRegistration ? { brokerRegistration } : {}) }
}
