// D4b: resolving `secret-generate`/`secret-pipe`/`secret-input` prompt
// values and handing them to `wrangler secret put`.
//
// Common rule: a secret value lives only in memory, travels
// only through stdin, and is zeroed (for the generated-bytes case) right
// after use. Nothing here ever writes a secret value to `output`, to an
// error message, or to a file.

import type { PromptIO } from '../app/prompt-io.ts'
import {
  isSecretPromptTarget,
  type SecretGeneratePrompt,
  type SecretInputPrompt,
  type SecretPipePrompt,
  type TemplatePrompt,
} from '../app/template-manifest.ts'
import type { ProcessRunner } from '../process.ts'
import { encodeBase64 } from '@std/encoding/base64'

export type SecretPrompt =
  | SecretGeneratePrompt
  | SecretPipePrompt
  | SecretInputPrompt

export const secretPromptsOf = (
  prompts: readonly TemplatePrompt[],
): readonly SecretPrompt[] =>
  prompts.filter((prompt): prompt is SecretPrompt =>
    isSecretPromptTarget(prompt.target)
  )

const toBase64Url = (bytes: Uint8Array): string =>
  encodeBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(
    /=+$/,
    '',
  )

const toHex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')

export const encodeGeneratedSecret = (
  bytes: Uint8Array,
  encoding: SecretGeneratePrompt['encoding'],
): string => {
  if (encoding === 'hex') return toHex(bytes)
  if (encoding === 'base64') return encodeBase64(bytes)
  return toBase64Url(bytes)
}

const matchesValidate = (
  validate: { readonly pattern: string } | undefined,
  value: string,
): boolean =>
  validate === undefined ||
  new RegExp(`^(?:${validate.pattern})$`).test(value)

/**
 * `origin` says where the value came from ("generated", "entered",
 * "provided in ERPC_API_KEY") so the message describes what actually
 * happened. The value itself is never part of the message.
 */
const validateOrThrow = (
  validate: { readonly pattern: string } | undefined,
  value: string,
  key: string,
  origin: string,
): void => {
  if (!matchesValidate(validate, value)) {
    throw new Error(
      `The value ${origin} for secret ${key} does not match its validate.pattern`,
    )
  }
}

/**
 * A `secret-input` prompt's environment value, or `undefined` when no
 * variable is configured, the variable is unset, or it is empty. An empty
 * value means "not provided", never "store an empty secret": CI systems
 * commonly expand an unregistered secret to an empty string.
 */
const secretInputEnvValue = (prompt: SecretInputPrompt): string | undefined => {
  if (prompt.env === undefined) return undefined
  const value = Deno.env.get(prompt.env)
  return value === undefined || value.length === 0 ? undefined : value
}

export type SecretResolution =
  | { readonly kind: 'skip' }
  | { readonly kind: 'value'; readonly value: string }

export interface SecretResolutionDeps {
  readonly ackBackup: ReadonlySet<string>
  readonly isInteractive: boolean
  readonly output: (message: string) => void
  readonly promptIO: PromptIO
  readonly random: (bytes: Uint8Array<ArrayBuffer>) => void
  readonly root: string
  readonly run: ProcessRunner
}

/**
 * Every reason a prompt in `toProcess` cannot be resolved non-interactively,
 * collected up front and reported together (the same pattern
 * `collectTemplateAnswers` uses for `erpc app init`) so nothing - no pipe
 * command, no `secret put` - runs until every one of them is either
 * resolvable or explicitly optional.
 */
export const blockingSecretIssues = (
  toProcess: readonly SecretPrompt[],
  deps: Pick<SecretResolutionDeps, 'ackBackup' | 'isInteractive'>,
): readonly string[] => {
  if (deps.isInteractive) return []
  const issues: string[] = []
  for (const prompt of toProcess) {
    if (
      prompt.target === 'secret-pipe' && prompt.backup &&
      !deps.ackBackup.has(prompt.key)
    ) {
      issues.push(
        `${prompt.key} generates a value you must back up; pass --ack-backup ${prompt.key} to run non-interactively`,
      )
      continue
    }
    if (prompt.target === 'secret-input') {
      const envValue = secretInputEnvValue(prompt)
      if (envValue !== undefined) {
        if (!matchesValidate(prompt.validate, envValue)) {
          issues.push(
            `${prompt.key}: the value provided in ${prompt.env} does not match its validate.pattern`,
          )
        }
        continue
      }
      if (prompt.required ?? false) {
        issues.push(
          prompt.env === undefined
            ? `${prompt.key} is required and has no non-interactive input configured`
            : `${prompt.key} is required; set the ${prompt.env} environment variable to a non-empty value`,
        )
      }
    }
  }
  return issues
}

/** Resolves one secret prompt's value. Assumes `blockingSecretIssues` already passed for the whole batch. */
export const resolveSecretValue = async (
  prompt: SecretPrompt,
  deps: SecretResolutionDeps,
): Promise<SecretResolution> => {
  if (prompt.target === 'secret-generate') {
    const bytes = new Uint8Array(prompt.bytes)
    try {
      deps.random(bytes)
      return {
        kind: 'value',
        value: encodeGeneratedSecret(bytes, prompt.encoding),
      }
    } finally {
      bytes.fill(0)
    }
  }

  if (prompt.target === 'secret-pipe') {
    if (prompt.backup) {
      if (deps.isInteractive) {
        const typed = await deps.promptIO.text(
          `${prompt.backup.message}\nType "${prompt.backup.confirm}" to continue:`,
        )
        if (typed !== prompt.backup.confirm) {
          throw new Error(`Backup was not acknowledged for ${prompt.key}`)
        }
      } else if (!deps.ackBackup.has(prompt.key)) {
        // blockingSecretIssues() must have already caught this - defensive.
        throw new Error(
          `${prompt.key} requires --ack-backup ${prompt.key} in non-interactive mode`,
        )
      }
    }
    const [command, ...rest] = prompt.command
    const result = await deps.run({
      args: rest,
      command: command!,
      cwd: deps.root,
      display: false,
    })
    const value = result.stdout.endsWith('\n')
      ? result.stdout.slice(0, -1)
      : result.stdout
    // The pipe command's stderr may echo the value it just generated (a
    // diagnostic, a warning) - redact every occurrence before it ever
    // reaches `output`.
    if (result.stderr) {
      const redacted = value.length > 0
        ? result.stderr.split(value).join('[REDACTED]')
        : result.stderr
      deps.output(`${prompt.key} generator stderr: ${redacted}`)
    }
    if (result.code !== 0) {
      throw new Error(`The command that generates ${prompt.key} failed`)
    }
    validateOrThrow(prompt.validate, value, prompt.key, 'generated')
    return { kind: 'value', value }
  }

  // secret-input: an empty answer and an empty environment variable both
  // mean "no value was provided", so an optional prompt is skipped rather
  // than stored as an empty secret or treated as an error.
  let value: string | undefined
  let origin: string
  if (deps.isInteractive) {
    const answer = await deps.promptIO.secret(
      prompt.question ?? `Enter a value for ${prompt.key}`,
    )
    value = answer.length === 0 ? undefined : answer
    origin = 'entered'
  } else {
    value = secretInputEnvValue(prompt)
    origin = prompt.env === undefined ? 'provided' : `provided in ${prompt.env}`
  }
  if (value !== undefined) {
    validateOrThrow(prompt.validate, value, prompt.key, origin)
    return { kind: 'value', value }
  }
  if (prompt.required ?? false) {
    // Non-interactive: blockingSecretIssues() must have already caught this.
    throw new Error(
      deps.isInteractive
        ? `${prompt.key} is required; an empty value was entered`
        : `${prompt.key} is required and no value is available`,
    )
  }
  deps.output(
    `${prompt.key} was left unset (not required, and no value was provided).`,
  )
  return { kind: 'skip' }
}
