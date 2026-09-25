// The prompt surface used by template init/answers (Decision 13) and, in a
// later PR, by deploy-time secret-input and backup-acknowledgement prompts.
// Kept narrow and injectable so non-interactive and test code never touches
// a real terminal.

import { Confirm, Input, Secret, Select } from '@cliffy/prompt'

export interface PromptTextOptions {
  readonly default?: string
  readonly validate?: (value: string) => boolean | string
}

export interface PromptConfirmOptions {
  readonly default?: boolean
}

export interface PromptSelectChoice {
  readonly name: string
  readonly value: string
}

export interface PromptIO {
  readonly confirm: (
    question: string,
    options?: PromptConfirmOptions,
  ) => Promise<boolean>
  readonly isInteractive: () => boolean
  readonly secret: (question: string) => Promise<string>
  readonly select: (
    question: string,
    choices: readonly PromptSelectChoice[],
  ) => Promise<string>
  readonly text: (
    question: string,
    options?: PromptTextOptions,
  ) => Promise<string>
}

export const defaultPromptIO: PromptIO = {
  confirm: async (question, options) =>
    await Confirm.prompt({
      message: question,
      default: options?.default ?? false,
    }),
  isInteractive: () => Deno.stdin.isTerminal() && Deno.stdout.isTerminal(),
  secret: async (question) => await Secret.prompt({ message: question }),
  select: async (question, choices) =>
    await Select.prompt({
      message: question,
      options: choices.map((choice) => ({
        name: choice.name,
        value: choice.value,
      })),
    }),
  text: async (question, options) =>
    await Input.prompt({
      message: question,
      ...(options?.default === undefined ? {} : { default: options.default }),
      ...(options?.validate === undefined
        ? {}
        : { validate: options.validate }),
    }),
}
