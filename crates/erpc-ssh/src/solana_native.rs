// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated native Solana operations. Requests and custody use stdin only.

/// Content identity of a protected helper release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(String);
impl Revision {
    /// Parse a fixed helper content digest, never an arbitrary remote path.
    /// # Errors
    /// Refuses anything other than 64 lowercase hexadecimal characters.
    pub fn new(value: &str) -> Result<Self, String> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid native Solana helper revision".into());
        }
        Ok(Self(value.into()))
    }
}

/// Fixed remote inspection and installed-controller entrypoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Read hardware and actual SSH connection facts before changing a host.
    Facts,
    /// Inspect public lifecycle scope and its last prepared helper revision.
    Probe,
    /// Read legacy public ownership/configuration without executing its scripts.
    LegacyInspect,
    /// Classify only the original host-only RPC/sync key; returns public facts.
    LegacyKeyInspect,
    /// Read original progress even if installed helpers have not been published.
    MigrationStatus,
    /// Send a closed controller request over stdin to one authenticated release.
    Control(Revision),
    /// Receive only the original migration key with `Session::run_private`.
    MigrationExport(Revision),
}
impl Command {
    pub(crate) fn shell(&self) -> String {
        match self {
            Self::Facts => {
                crate::eth::NODE_FACTS.replace("/var/lib/ethereum", "/var/lib/erpc-solana")
            }
            Self::Probe => format!(
                "sudo -n /usr/bin/python3 -I -c '{}'",
                include_str!("solana_native_probe.py").replace('\'', "'\\''")
            ),
            Self::LegacyInspect => compressed_inspection(),
            Self::MigrationStatus => {
                compressed_source(include_bytes!("solana_migration_status.py"))
            }
            Self::LegacyKeyInspect => key_inspection_command(),
            Self::MigrationExport(revision) => crate::python::command(&format!(
                "/usr/local/lib/erpc/solana-native/releases/{}/native_runtime_control.py",
                revision.0
            ))
            .map_or_else(
                |_| "false".into(),
                |command| format!("{command} migration-export"),
            ),
            Self::Control(revision) => crate::python::command(&format!(
                "/usr/local/lib/erpc/solana-native/releases/{}/native_runtime_control.py",
                revision.0
            ))
            .map_or_else(|_| "false".into(), |command| format!("{command} control")),
        }
    }
}

fn compressed_inspection() -> String {
    compressed_source(include_bytes!("solana_legacy_inspect.py"))
}
/// Frame the immutable public inspector ahead of its bounded public request.
/// Its compressed bytes are hash-pinned in the fixed remote command, so the
/// stdin channel cannot substitute another privileged program.
/// # Errors
/// Refuses oversized public input or an unavailable compression result.
pub fn key_inspection_input(request: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    if request.len() > 65_536 {
        return Err("original key inspection request exceeds its bound".into());
    }
    let source = key_inspection_payload()?;
    let mut input = base64::engine::general_purpose::STANDARD
        .encode(source)
        .into_bytes();
    input.push(b'\n');
    input.extend_from_slice(request);
    Ok(input)
}
fn key_inspection_payload() -> Result<Vec<u8>, String> {
    use std::io::Write as _;
    let mut compressor = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    compressor
        .write_all(key_inspection_source().as_bytes())
        .map_err(|_| "public inspector compression failed")?;
    compressor
        .finish()
        .map_err(|_| "public inspector compression failed".into())
}
fn key_inspection_command() -> String {
    use sha2::{Digest as _, Sha256};
    let Ok(payload) = key_inspection_payload() else {
        return "false".into();
    };
    let digest = format!("{:x}", Sha256::digest(payload));
    let source = format!(
        r"import base64,hashlib,sys,zlib
try:
 line=sys.stdin.buffer.readline(65537)
 if len(line)>65536 or not line.endswith(b'\n'): raise ValueError('invalid public frame')
 source=base64.b64decode(line[:-1],validate=True)
 if hashlib.sha256(source).hexdigest()!='{digest}': raise ValueError('public inspector content differs')
 exec(compile(zlib.decompress(source),'original-key-inspector','exec'))
except Exception:
 print('Original key inspector framing failed',file=sys.stderr)
 sys.exit(1)
"
    );
    format!(
        "sudo -n /usr/bin/python3 -I -c '{}'",
        source.replace('\'', "'\\''")
    )
}

fn key_inspection_source() -> String {
    // Rust's debug string literal is valid Python for these compile-time ASCII
    // sources (newline/backslash/quote escapes). Compression sees source text,
    // not base64 noise, keeping the Windows process argument bounded.
    let valid = |source: &str| {
        source.is_ascii()
            && source
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    };
    if !valid(include_str!("solana_legacy_inspect.py"))
        || !valid(include_str!("solana_migration_key.py"))
        || !valid(include_str!("solana_migration_bls.py"))
        || !valid(include_str!("solana_migration_sources.json"))
        || !valid(include_str!("solana_native_platform.py"))
        || !valid(include_str!("solana_migration_runs.py"))
    {
        return "raise ValueError('invalid compiled source encoding')".into();
    }
    let legacy = format!("{:?}", include_str!("solana_legacy_inspect.py"));
    let key = format!("{:?}", include_str!("solana_migration_key.py"));
    let platform = format!("{:?}", include_str!("solana_native_platform.py"));
    let runs = format!("{:?}", include_str!("solana_migration_runs.py"));
    let bls = format!("{:?}", include_str!("solana_migration_bls.py"));
    let origins = format!("{:?}", include_str!("solana_migration_sources.json"));
    let source = format!(
        r"import types,sys,base64,json,os,resource
try:
 os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 if os.geteuid()!=0: raise ValueError('root observation required')
 for name,content in [('native_migration_inspect',{legacy}),('native_platform',{platform}),('native_migration_bls',{bls}),('native_migration_runs',{runs}),('native_migration_key',{key})]:
  module=types.ModuleType(name);sys.modules[name]=module
  if name=='native_migration_bls':module.ORIGINAL_SOURCES=json.loads({origins})
  exec(compile(content,name,'exec'),module.__dict__)
 raw=sys.stdin.buffer.read(65537)
 if len(raw)>65536: raise ValueError('request too large')
 legacy=sys.modules['native_migration_inspect'];request=legacy.unique(raw)
 if not isinstance(request,dict) or set(request)!=set(['legacy','withdrawer']): raise ValueError('invalid public request')
 result=sys.modules['native_migration_key'].inspect(request['legacy'],request['withdrawer'])
 print(json.dumps(result,separators=(',',':')))
except Exception:
 print('Original host-only identity classification failed; preserve Solv operation',file=sys.stderr)
 sys.exit(1)
"
    );
    source
}
fn compressed_source(source: &[u8]) -> String {
    use base64::Engine as _;
    use std::io::Write as _;
    let mut compressor = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    if compressor.write_all(source).is_err() {
        return "false".into();
    }
    let Ok(compressed) = compressor.finish() else {
        return "false".into();
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(compressed);
    // Keep the public source below Windows OpenSSH/CreateProcess argument limits.
    // Secret request bytes still use the separate stdin channel unchanged.
    format!(
        r#"sudo -n /usr/bin/python3 -I -c 'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("{encoded}",validate=True)),"solana-legacy-inspect","exec"))'"#
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn carried_migration_observer_is_exactly_the_readonly_ssh_source() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-solana-native/templates/node/native_migration_inspect.py");
        assert_eq!(
            std::fs::read(path).unwrap(),
            include_bytes!("solana_legacy_inspect.py")
        );
    }

    #[test]
    fn compressed_inspection_is_exact_public_source_with_portable_command_budget() {
        use base64::Engine as _;
        use std::io::Read as _;
        let command = super::Command::LegacyInspect.shell();
        assert!(
            command.len() < 24_000,
            "leave room for Windows SSH arguments"
        );
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I -c 'import base64,zlib;"));
        let encoded = command
            .split("base64.b64decode(\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(bytes.as_slice());
        let mut source = Vec::new();
        decoder.read_to_end(&mut source).unwrap();
        assert_eq!(source, include_bytes!("solana_legacy_inspect.py"));
    }

    #[test]
    fn original_key_inspector_is_exact_compiled_source_and_within_command_budget() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-solana-native/templates/node/native_migration_key.py");
        assert_eq!(
            std::fs::read(path).unwrap(),
            include_bytes!("solana_migration_key.py")
        );
        let command = super::Command::LegacyKeyInspect.shell();
        assert!(
            command.len() < 24_000,
            "compiled key observer exceeds Windows transport budget: {}",
            command.len()
        );
        assert!(command.starts_with("sudo -n /usr/bin/python3 -I"));
    }

    #[cfg(unix)]
    #[test]
    fn actual_public_key_loader_refuses_substituted_source_and_private_fields() {
        use base64::Engine as _;
        use std::io::Write as _;
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-solana-native/tests/migration_key_entry.py");
        let command = super::Command::LegacyKeyInspect.shell();
        let packet =
            super::key_inspection_input(br#"{"legacy":{"network":"testnet"},"withdrawer":null}"#)
                .unwrap();
        let encoder = base64::engine::general_purpose::STANDARD;
        let data = format!("{}\n{}\n", encoder.encode(command), encoder.encode(packet));
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn actual_legacy_inspector_refuses_changed_ownership_without_executing_legacy_code() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-solana-native/tests/legacy_inspection.py");
        let output = std::process::Command::new("python3")
            .args([
                "-B",
                script.to_str().unwrap(),
                include_str!("solana_legacy_inspect.py"),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    #[test]
    fn actual_probe_refuses_unknown_scope_and_unsafe_state_without_reading_keys() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-solana-native/tests/probe.py");
        let result = std::process::Command::new("python3")
            .arg("-B")
            .arg(script)
            .arg(include_str!("solana_native_probe.py"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    #[test]
    fn revision_cannot_change_the_remote_path_or_command() {
        for invalid in ["", "../escape", "$(id)", &"a".repeat(63), &"A".repeat(64)] {
            assert!(super::Revision::new(invalid).is_err());
        }
        let command =
            super::Command::Control(super::Revision::new(&"a".repeat(64)).unwrap()).shell();
        assert!(command.contains("trusted_imports"));
        assert!(command.ends_with(" control"));
        for secret in ["key_file", "OP_SERVICE_ACCOUNT_TOKEN", "PRIVATE_KEY"] {
            assert!(!command.contains(secret));
        }
        #[cfg(unix)]
        for command in [
            command,
            super::Command::Facts.shell(),
            super::Command::Probe.shell(),
            super::Command::LegacyInspect.shell(),
            super::Command::LegacyKeyInspect.shell(),
        ] {
            assert!(
                std::process::Command::new("bash")
                    .args(["-n", "-c", &command])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}
