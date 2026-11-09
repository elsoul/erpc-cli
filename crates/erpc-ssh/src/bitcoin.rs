// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Fixed Bitcoin source travels on stdin, never in the OS command line.

const SOURCE_SHA256: &str = "b1a33f7b30f52600e19dd5b1ab8ab0b652ee31f102e172b872c98d10c2181c4c";

fn qualified(source: &'static str) -> bool {
    use sha2::Digest as _;
    source.len() <= 524_288
        && format!("{:x}", sha2::Sha256::digest(source.as_bytes())) == SOURCE_SHA256
}

/// Frame the exact public controller followed by its bounded public JSON request.
/// Source authentication on both ends prevents this from becoming a general
/// Python transport; stdin framing also avoids Windows' argv-size limit.
///
/// # Errors
/// Refuses changed controller bytes or an excessive request before SSH.
pub fn input(source: &'static str, request: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !qualified(source) || request.len() > 1_048_576 {
        return Err("Bitcoin carried source or request is not qualified");
    }
    let mut value = Vec::with_capacity(source.len() + request.len());
    value.extend_from_slice(source.as_bytes());
    value.extend_from_slice(request);
    Ok(value)
}

pub(crate) fn control(source: &'static str) -> String {
    if !qualified(source) {
        return "printf '%s\\n' 'Bitcoin carried controller source is not qualified' >&2; exit 1"
            .into();
    }
    loader(source.len(), SOURCE_SHA256)
}

fn loader(length: usize, digest: &str) -> String {
    format!(
        "sudo -n /usr/bin/python3 -I -c 'import sys,hashlib;source=sys.stdin.buffer.read({length});exec(source if hashlib.sha256(source).hexdigest()==\"{digest}\" else sys.exit(1),{{\"__name__\":\"__main__\"}})'"
    )
}

/// Bounded journal read, after the caller has verified the host contract.
pub(crate) fn logs(lines: u32, follow: bool) -> String {
    format!(
        "sudo -n journalctl --no-pager -o short-iso -u erpc-bitcoin -n {lines}{}",
        if follow { " -f" } else { "" }
    )
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn framed_public_source_preserves_request_and_refuses_changed_bytes() {
        use sha2::Digest as _;
        use std::io::Write as _;
        const SOURCE: &str = "import json,sys\nprint(json.dumps({'input':sys.stdin.read(),'literal':\"$HOME `id`\"}))\n";
        assert!(super::input(SOURCE, b"request").is_err());
        assert!(!super::control(SOURCE).contains("/usr/bin/python3"));
        let digest = format!("{:x}", sha2::Sha256::digest(SOURCE.as_bytes()));
        let command = super::loader(SOURCE.len(), &digest);
        assert!(command.encode_utf16().count() < 1024);
        for changed in [false, true] {
            let mut child = std::process::Command::new("sh")
                .args(["-c", command.strip_prefix("sudo -n ").unwrap()])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut bytes = SOURCE.as_bytes().to_vec();
            if changed {
                bytes[0] = b'#';
            }
            bytes.extend_from_slice(b"public request");
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let result = child.wait_with_output().unwrap();
            assert_eq!(result.status.success(), !changed);
            if changed {
                assert!(result.stdout.is_empty());
            } else {
                let text = String::from_utf8(result.stdout).unwrap();
                assert!(text.contains("public request"));
                assert!(text.contains("$HOME `id`"));
            }
        }
    }
}
