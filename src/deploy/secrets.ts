// D4b: resolving `secret-generate`/`secret-pipe`/`secret-input` prompt
// values and handing them to `wrangler secret put`. See design doc §4 and
// Task Brief Decision 6/10.
//
// Common rule (Decision 10): a secret value lives only in memory, travels
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

const validateOrThrow = (
  validate: { readonly pattern: string } | undefined,
  value: string,
  key: string,
): void => {
  if (!validate) return
  if (!new RegExp(`^(?:${validate.pattern})$`).test(value)) {
    throw new Error(
      `The value generated for secret ${key} does not match its validate.pattern`,
    )
  }
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
 * collected up front (Decision 6's "非対話で不足は1回のエラーで全件列挙"
 * pattern from PR-A's `collectTemplateAnswers`) so nothing - no pipe
 * command, no `secret put` - runs until every one of them is either
 * resolvable or explicitly optional (Acceptance A12).
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
    if (prompt.target === 'secret-input' && (prompt.required ?? false)) {
      const hasEnv = prompt.env !== undefined &&
        Deno.env.get(prompt.env) !== undefined
      if (!hasEnv) {
        issues.push(
          prompt.env === undefined
            ? `${prompt.key} is required and has no non-interactive input configured`
            : `${prompt.key} is required; set the ${prompt.env} environment variable`,
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
    // Decision 6: the pipe command's stderr may echo the value it just
    // generated (a diagnostic, a warning) - redact every occurrence before
    // it ever reaches `output` (Acceptance A11).
    if (result.stderr) {
      const redacted = value.length > 0
        ? result.stderr.split(value).join('[REDACTED]')
        : result.stderr
      deps.output(`${prompt.key} generator stderr: ${redacted}`)
    }
    if (result.code !== 0) {
      throw new Error(`The command that generates ${prompt.key} failed`)
    }
    validateOrThrow(prompt.validate, value, prompt.key)
    return { kind: 'value', value }
  }

  // secret-input
  if (deps.isInteractive) {
    const value = await deps.promptIO.secret(
      prompt.question ?? `Enter a value for ${prompt.key}`,
    )
    return { kind: 'value', value }
  }
  const envValue = prompt.env === undefined
    ? undefined
    : Deno.env.get(prompt.env)
  if (envValue !== undefined) return { kind: 'value', value: envValue }
  if (prompt.required ?? false) {
    // blockingSecretIssues() must have already caught this - defensive.
    throw new Error(`${prompt.key} is required and no value is available`)
  }
  deps.output(
    `${prompt.key} was left unset (not required, and no value was provided).`,
  )
  return { kind: 'skip' }
}
