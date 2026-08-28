import { randomUUID } from 'node:crypto'
import { encodeBase64 } from '@std/encoding/base64'
import type { ErpcManifest } from '../app/manifest.ts'
import type { ErpcNodeConfig } from '../config.ts'
import type { BuildArtifact, LinuxArchitecture } from './build.ts'
import {
  type ProcessRequest,
  type ProcessRunner,
  runProcess,
} from '../process.ts'

export interface SshDeployOptions {
  readonly resolveNodeRuntime?: (
    architecture: LinuxArchitecture,
  ) => Promise<string>
  readonly run?: ProcessRunner
}

export interface DeploymentResult {
  readonly node: string
  readonly release: string
  readonly service: string
}

const remoteArchitecture = (value: string): LinuxArchitecture | null => {
  const normalized = value.trim().split(/\s+/).at(-1)
  if (normalized === 'x86_64' || normalized === 'amd64') return 'x64'
  if (normalized === 'aarch64' || normalized === 'arm64') return 'arm64'
  return null
}

const sshTarget = (node: ErpcNodeConfig): string => `${node.user}@${node.host}`

const sshArguments = (node: ErpcNodeConfig): string[] => [
  '-o',
  'BatchMode=yes',
  '-o',
  'ConnectTimeout=10',
  '-p',
  String(node.port),
  ...(node.identityFile === undefined ? [] : ['-i', node.identityFile]),
]

const scpArguments = (node: ErpcNodeConfig): string[] => [
  '-q',
  '-o',
  'BatchMode=yes',
  '-o',
  'ConnectTimeout=10',
  '-P',
  String(node.port),
  ...(node.identityFile === undefined ? [] : ['-i', node.identityFile]),
]

const checked = async (
  run: ProcessRunner,
  request: ProcessRequest,
  message: string,
) => {
  const result = await run(request)
  if (result.code !== 0) throw new Error(message)
  return result
}

const serviceUnit = (
  manifest: ErpcManifest,
  executable: string,
  artifact: string,
): string => {
  const execStart = manifest.app.runtime === 'node'
    ? `${executable} ${artifact}`
    : artifact
  return `[Unit]
Description=ERPC application ${manifest.name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=erpc-app
Group=erpc-app
WorkingDirectory=/opt/erpc/apps/${manifest.name}/current
ExecStart=${execStart}
Environment=HOST=${manifest.run.host}
Environment=PORT=${manifest.run.port}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
`
}

const activationScript = (input: {
  artifactTemporary: string
  manifest: ErpcManifest
  nodeTemporary?: string
  release: string
  service: string
  unit: string
}) => {
  const base = `/opt/erpc/apps/${input.manifest.name}`
  const release = `${base}/releases/${input.release}`
  const artifactName = input.manifest.app.runtime === 'node' ? 'app.js' : 'app'
  const nodeInstall = input.nodeTemporary === undefined
    ? ''
    : `$sudo_cmd install -m 0755 ${input.nodeTemporary} ${release}/node\n`
  const unitPath = `/etc/systemd/system/${input.service}.service`
  const unitBackup = `${release}/previous.service`
  const encodedUnit = encodeBase64(input.unit)
  return `set -eu
if [ "$(id -u)" -eq 0 ]; then sudo_cmd=""; else sudo_cmd="sudo -n"; fi
cleanup() { rm -f -- ${input.artifactTemporary}${
    input.nodeTemporary ? ` ${input.nodeTemporary}` : ''
  }; }
trap cleanup EXIT
$sudo_cmd install -d -m 0755 /opt/erpc/apps/${input.manifest.name}/releases
$sudo_cmd install -d -m 0755 ${release}
$sudo_cmd install -m ${
    input.manifest.app.runtime === 'node' ? '0644' : '0755'
  } ${input.artifactTemporary} ${release}/${artifactName}
${nodeInstall}if ! id -u erpc-app >/dev/null 2>&1; then $sudo_cmd useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin erpc-app; fi
previous=$($sudo_cmd readlink ${base}/current 2>/dev/null || true)
had_unit=false
if $sudo_cmd test -f ${unitPath}; then
  $sudo_cmd cp ${unitPath} ${unitBackup}
  had_unit=true
fi
activate() {
  printf '%s' '${encodedUnit}' | base64 -d | $sudo_cmd tee ${unitPath} >/dev/null &&
  $sudo_cmd chmod 0644 ${unitPath} &&
  $sudo_cmd ln -sfn ${release} ${base}/current &&
  $sudo_cmd systemctl daemon-reload &&
  $sudo_cmd systemctl enable ${input.service}.service >/dev/null &&
  $sudo_cmd systemctl restart ${input.service}.service &&
  $sudo_cmd systemctl is-active --quiet ${input.service}.service
}
if ! activate; then
  if [ "$had_unit" = true ]; then
    $sudo_cmd cp ${unitBackup} ${unitPath}
  else
    $sudo_cmd rm -f ${unitPath}
    $sudo_cmd systemctl disable ${input.service}.service >/dev/null 2>&1 || true
  fi
  if [ -n "$previous" ]; then
    $sudo_cmd ln -sfn "$previous" ${base}/current
  else
    $sudo_cmd rm -f ${base}/current
  fi
  $sudo_cmd systemctl daemon-reload || true
  if [ -n "$previous" ]; then $sudo_cmd systemctl restart ${input.service}.service || true; fi
  echo 'ERPC service failed to become active' >&2
  exit 1
fi
`
}

export const deployOverSsh = async (
  manifest: ErpcManifest,
  artifact: BuildArtifact,
  nodeName: string,
  node: ErpcNodeConfig,
  options: SshDeployOptions = {},
): Promise<DeploymentResult> => {
  const run = options.run ?? runProcess
  const target = sshTarget(node)
  const ssh = sshArguments(node)
  const preflight = await checked(run, {
    args: [
      ...ssh,
      target,
      'set -eu; test "$(uname -s)" = Linux; command -v systemctl >/dev/null; command -v base64 >/dev/null; command -v install >/dev/null; command -v useradd >/dev/null; if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null; sudo -n true; fi; uname -m',
    ],
    command: 'ssh',
  }, 'Remote Linux/systemd/sudo preflight failed; nothing was uploaded')
  const remoteArch = remoteArchitecture(preflight.stdout)
  if (!remoteArch) {
    throw new Error('The target node architecture is unsupported')
  }
  if (artifact.architecture && artifact.architecture !== remoteArch) {
    throw new Error(
      'The local Linux binary architecture does not match the target node',
    )
  }

  let nodeExecutable = ''
  let localNode: string | undefined
  if (manifest.app.runtime === 'node') {
    const detection = await checked(run, {
      args: [
        ...ssh,
        target,
        'node_path=$(command -v node || true); if [ -n "$node_path" ]; then printf \'%s\\n\' "$node_path"; node -p \'process.versions.node.split(".")[0]\'; fi',
      ],
      command: 'ssh',
    }, 'Unable to inspect the Node.js runtime on the target')
    const lines = detection.stdout.trim().split(/\r?\n/).filter(Boolean)
    const major = Number.parseInt(lines[1] ?? '', 10)
    if (lines[0] && /^\/[A-Za-z0-9_./-]+$/.test(lines[0]) && major >= 20) {
      nodeExecutable = lines[0]
    } else {
      if (!options.resolveNodeRuntime) {
        throw new Error(
          'Target Node.js 20+ is missing and no verified application-local runtime is available',
        )
      }
      localNode = await options.resolveNodeRuntime(remoteArch)
      nodeExecutable = `/opt/erpc/apps/${manifest.name}/current/node`
    }
  }

  const release = `${Date.now()}-${randomUUID().slice(0, 8)}`
  const artifactTemporary = `/tmp/erpc-${manifest.name}-${release}.artifact`
  const nodeTemporary = localNode === undefined
    ? undefined
    : `/tmp/erpc-${manifest.name}-${release}.node`
  await checked(run, {
    args: [
      ...scpArguments(node),
      artifact.path,
      `${target}:${artifactTemporary}`,
    ],
    command: 'scp',
    display: true,
  }, 'Artifact upload failed; the active service was not changed')
  if (localNode && nodeTemporary) {
    await checked(run, {
      args: [
        ...scpArguments(node),
        localNode,
        `${target}:${nodeTemporary}`,
      ],
      command: 'scp',
      display: true,
    }, 'Node.js runtime upload failed; the active service was not changed')
  }

  const service = `erpc-${manifest.name}`
  const artifactPath = `/opt/erpc/apps/${manifest.name}/current/${
    manifest.app.runtime === 'node' ? 'app.js' : 'app'
  }`
  const unit = serviceUnit(manifest, nodeExecutable, artifactPath)
  const activation = activationScript({
    artifactTemporary,
    manifest,
    ...(nodeTemporary === undefined ? {} : { nodeTemporary }),
    release,
    service,
    unit,
  })
  await checked(
    run,
    {
      args: [...ssh, target, 'bash -se'],
      command: 'ssh',
      input: activation,
      display: true,
    },
    'Remote activation failed; the previous release was restored when available',
  )

  return { node: nodeName, release, service }
}
