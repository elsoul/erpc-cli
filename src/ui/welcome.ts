import * as colors from '@std/fmt/colors'
import { CLI_VERSION } from '../version.ts'

export type WelcomeOutput = (message: string) => void

const rgb = (color: number) => (value: string): string =>
  colors.rgb24(value, color)
const boldRgb = (color: number) => (value: string): string =>
  colors.bold(colors.rgb24(value, color))

const sky1 = rgb(0xc44e52)
const sky2 = rgb(0xd4756a)
const sky3 = rgb(0xe8a87c)
const sky4 = rgb(0xf0c88e)
const snow = boldRgb(0xffffff)
const mountain = rgb(0x3d5a80)
const mountainDark = rgb(0x2c3e6b)
const moon = boldRgb(0xffeebb)
const pine = rgb(0x2d5a27)
const trunk = rgb(0x8b5e3c)
const cloud = rgb(0xe0d6c8)
const green = rgb(0x4a7c59)
const greenDark = rgb(0x355e3b)
const sea = rgb(0x4a90a8)
const seaLight = rgb(0x6bb5c9)
const seaDark = rgb(0x2e6e82)
const sand = rgb(0xc2956b)
const cat = rgb(0xf0d870)
const star = boldRgb(0xffd700)
const shell = boldRgb(0xff69b4)

const terminalWidth = (): number => {
  try {
    return Math.max(Deno.consoleSize().columns, 1)
  } catch {
    return 80
  }
}

export const stripAnsi = (value: string): string =>
  // deno-lint-ignore no-control-regex
  value.replace(/\x1b\[[0-9;]*m/g, '')

const trimToWidth = (line: string, maximumWidth: number): string => {
  if (stripAnsi(line).length <= maximumWidth) return line

  let visible = 0
  let index = 0
  while (index < line.length && visible < maximumWidth) {
    if (line[index] === '\x1b') {
      const end = line.indexOf('m', index)
      if (end !== -1) {
        index = end + 1
        continue
      }
    }
    visible++
    index++
  }
  return `${line.slice(0, index)}\x1b[0m`
}

const fillWidth = (pattern: string, width: number): string =>
  pattern.repeat(Math.ceil(width / pattern.length)).slice(0, width)

export const renderErpcWelcomeArt = (width = terminalWidth()): string => {
  const safeWidth = Math.max(width, 1)
  const separator = rgb(0x555555)(fillWidth('…', safeWidth))
  const header = `${
    boldRgb(0x14f195)(`Welcome to ERPC v${CLI_VERSION}`)
  }\n${separator}`
  const lines = [
    `${sky1('     ')}${star('*')}${sky1('                    ')}${snow('▄▄')}${
      sky1('              ')
    }${moon('▄████▄')}${sky1('        ')}`,
    `${sky1('                        ')}${snow('▄████▄')}${
      sky1('            ')
    }${moon('██████')}${sky1('        ')}`,
    `${sky2('            ')}${star('*')}${sky2('         ')}${
      snow('▄██████▄')
    }${sky2('            ')}${moon('▀████▀')}${sky2('        ')}`,
    `${sky2('    ')}${pine('▄██▄')}${sky2('           ')}${snow('▄████')}${
      mountain('████')
    }${snow('██▄')}${sky2('                    ')}${star('*')}${sky2('   ')}`,
    `${sky3('     ')}${trunk('█')}${pine('▄███▄')}${sky3('      ')}${
      mountain('▄██')
    }${mountainDark('████████████')}${mountain('▄')}${
      sky3('                       ')
    }`,
    `${sky3(' ')}${pine('▄███▄')}${trunk('█')}${sky3('    ')}${cloud('▄▄▄')}${
      sky3(' ')
    }${mountain('▄██')}${mountainDark('████████████████')}${mountain('██▄')}${
      sky3('    ')
    }${cloud('▄▄▄')}${sky3('      ')}`,
    `${sky4('     ')}${trunk('█')}${pine('▄██▄')}${cloud('▀▀▀▀▀')}${
      mountainDark('▄████████████████████████')
    }${mountainDark('▄')}${cloud('▀▀▀▀▀▀')}${sky4('   ')}`,
    `${green('▄▄▄▄')}${trunk('█')}${greenDark('▄▄▄▄')}${
      mountainDark('▄████████████████████████████')
    }${greenDark('▄▄▄▄▄')}${green('▄▄▄▄▄▄')}`,
    `${green('████')}${trunk('█')}${green('███')}${
      greenDark('██████████████████████████████████████')
    }${green('██████████')}`,
    `${sea('~~')}${seaLight('~~~')}${sea('~~')}${seaLight('~~~')}${sea('~~')}${
      seaLight('~~~')
    }${sea('~~')}${seaLight('~~~')}${sea('~~')}${seaLight('~~~')}${sea('~~')}${
      seaLight('~~~')
    }${sea('~~')}${seaLight('~~~')}${sea('~~')}${seaLight('~~~')}${sea('~~')}${
      seaLight('~~')
    }${seaLight('~~')}${seaLight('~~')}${seaLight('~~')}${seaLight('~~')}${
      seaLight('~~')
    }${seaLight('~~')}`,
    `${seaDark('~~')}${sea('~~~')}${seaDark('~~')}${sea('~~~')}${
      seaDark('~~')
    }${sea('~~~')}${seaDark('~~')}${sea('~~~')}${seaDark('~~')}${sea('~~~')}${
      seaDark('~~')
    }${sea('~~~')}${seaDark('~~')}${sea('~~~')}${seaDark('~~')}${sea('~~~')}${
      seaDark('~~')
    }${sea('~~')}${seaLight('~~')}${seaLight('~~')}${seaLight('~~')}${
      seaLight('~~')
    }${seaLight('~~')}${seaLight('~~')}`,
    `${sand('·:·.·:·')}${cat('▄█')}${sand('·····')}${cat('█▄')}${
      sand('·:·.·:·.·:·.·:·.·:·.·:·.·:·.·:·.·:·.·:·')
    }`,
    `${sand('·:·.·:·')}${cat('█████████')}${
      sand(':·.·:·.·:·.·:·.·:·.·:·.·:·.·:·.·:·.·:·.·')
    }`,
    `${sand('·:·.·:·')}${cat('██▄███▄██')}${sand(':·.·:·.·:·.·:·.·:·.·:·')}${
      shell('☆')
    }${sand('·')}${shell('@')}${sand('·:·.·:·.·:·')}`,
  ]

  return `\n${header}\n${
    lines.map((line) => trimToWidth(line, safeWidth)).join('\n')
  }\n${separator}`
}

export const erpcAA = (
  output: WelcomeOutput = console.log,
  width?: number,
): void => output(renderErpcWelcomeArt(width))

export const erpcWelcomeMessage = (
  output: WelcomeOutput = console.log,
): void => {
  output(`ERPC - Global Edge RPC CLI

Build, deploy, and operate ERPC applications.

$ erpc login       - Sign in to ERPC
$ erpc app init    - Create an application
$ erpc deploy      - Build and deploy an application
$ erpc --help      - Show every command`)
}
