// Collects answers for `var`, `derived`, and `broker-register` prompts.
// See design doc §2.5/§2.6 and Task Brief Decision 6.
//
// `secret-generate` / `secret-pipe` / `secret-input` prompts are resolved at
// deploy time (PR-B), not here (design §2.2: their "confirmed" column is
// "deploy"). Callers must reject `--set` for those keys before this module
// runs (Decision 6: "`--set` で secret target のキーを渡したらエラー").

import type { PromptIO } from './prompt-io.ts'
import type {
  BrokerRegisterPrompt,
  TemplateManifest,
  VarPrompt,
} from './template-manifest.ts'

const MAX_ANSWER_LENGTH = 512
// Every control character, including tab/newline/carriage-return: Decision 6
// requires "no control characters" unconditionally (steiner r1 N2 / cyan r1 B4).
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
    // rendered file, where a later deploy step would treat it as genuine
    // (cyan r1 N12).
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
}

export interface CollectedTemplateAnswers {
  readonly brokerRegistration?: CollectedBrokerRegistration
  readonly values: ReadonlyMap<string, string>
}

/**
 * Resolves every `var`, `derived`, and `broker-register` prompt in manifest
 * order. Non-interactively, every `var` is checked independently so all
 * missing keys and validation failures are reported together in a single
 * thrown error (Acceptance A8); `PromptIO` is never called in that path. A
 * `broker-register` failure (for example, this release's registrar stub)
 * propagates as its own error rather than joining that list, since it is not
 * a missing-answer problem.
 */
export const collectTemplateAnswers = async (
  manifest: TemplateManifest,
  inputs: TemplateAnswerInputs,
): Promise<CollectedTemplateAnswers> => {
  const values = new Map<string, string>()
  const issues: string[] = []
  let brokerRegistration: CollectedBrokerRegistration | undefined

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
      } catch {
        // An upstream dependency already failed to resolve and was reported
        // above; nothing further to add for this derived key.
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

    // prompt.target === 'broker-register'
    let redirectUris: readonly string[]
    let clientName: string
    try {
      redirectUris = prompt.redirectUris.map((uri) =>
        interpolate(uri, values, inputs.builtIns)
      )
      clientName = interpolate(prompt.clientName, values, inputs.builtIns)
    } catch {
      continue // an upstream dependency already failed and was reported above
    }
    // Trust is checked unconditionally (even if other answers are still
    // missing) so an untrusted issuer always joins the same aggregated error
    // list (Acceptance A8 / Decision 6; steiner r1 B4, cyan r1 B3). Only the
    // actual registration call is skipped while other answers are missing.
    const trusted = await inputs.confirmIssuerTrust(
      inputs.builtIns.brokerIssuer ?? '',
    )
    if (!trusted) {
      issues.push(
        `${prompt.key}: the broker issuer is not trusted (pass --trust-issuer <origin>, or confirm interactively)`,
      )
      continue
    }
    if (issues.length > 0) continue // do not register while other answers are missing
    const clientId = await inputs.resolveBrokerRegister(
      prompt,
      redirectUris,
      clientName,
    )
    const shapeIssue = answerShapeIssue(prompt.key, clientId)
    if (shapeIssue) {
      issues.push(shapeIssue)
      continue
    }
    if (
      prompt.validate &&
      !anchoredPattern(prompt.validate.pattern).test(clientId)
    ) {
      issues.push(
        `${prompt.key}: the registrar returned a value that does not match the required pattern`,
      )
      continue
    }
    values.set(prompt.key, clientId)
    brokerRegistration = { clientId, key: prompt.key, redirectUris }
  }

  if (issues.length > 0) throw new TemplateAnswersError(issues)
  return { values, ...(brokerRegistration ? { brokerRegistration } : {}) }
}
