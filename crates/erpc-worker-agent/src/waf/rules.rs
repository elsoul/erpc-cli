// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What a request's method and target are judged by, before any of it
//! reaches the app. No socket and no clock: a method and a target go in,
//! and a verdict comes out.
//!
//! The target is never rewritten. It is read into a normal form to be
//! judged, and a target that has none is refused; the one forwarded is the
//! one that was sent.

use erpc_worker::waf::WafConfig;

/// Why a request, or a connection, was not let through. The names are the
/// stats file's counters and the log's `reason=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reason {
    /// The head is not one unambiguous request, is too large or too slow.
    Malformed,
    /// A method not in `methods`.
    Method,
    /// A path that is not in normal form.
    Path,
    /// A path in `deny_paths`.
    Denied,
    /// A path not in `allow_paths`.
    NotAllowed,
    /// A scanner's probe.
    Probe,
    /// A request to change protocol.
    Upgrade,
    /// Over the address's rate.
    Rate,
    /// A body over `max_body_bytes`.
    Body,
    /// A body still coming once its time, `body_timeout_secs`, is used up.
    BodyTimeout,
    /// The address is banned.
    Banned,
    /// Too many connections.
    Connections,
}

impl Reason {
    /// Every reason, in the order the stats file lists them.
    pub(super) const ALL: [Self; 12] = [
        Self::Method,
        Self::Path,
        Self::Denied,
        Self::NotAllowed,
        Self::Probe,
        Self::Rate,
        Self::Body,
        Self::Malformed,
        Self::Banned,
        Self::Connections,
        Self::Upgrade,
        Self::BodyTimeout,
    ];

    /// Its name in the stats file and the log.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Method => "method",
            Self::Path => "path",
            Self::Denied => "denied",
            Self::NotAllowed => "not_allowed",
            Self::Probe => "probe",
            Self::Upgrade => "upgrade",
            Self::Rate => "rate",
            Self::Body => "body",
            Self::BodyTimeout => "body_timeout",
            Self::Banned => "banned",
            Self::Connections => "connections",
        }
    }

    /// Whether it counts against the address towards a ban. Every blocked
    /// request does; a refused connection is not a request.
    pub(super) const fn is_violation(self) -> bool {
        !matches!(self, Self::Banned | Self::Connections)
    }
}

/// A refusal: the rule, the status answered, and what tripped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Block {
    /// The rule.
    pub(super) reason: Reason,
    /// The status answered.
    pub(super) status: u16,
    /// What about the request tripped the rule, for the log.
    pub(super) detail: &'static str,
    /// Seconds until a request would pass again, when the rule is the rate.
    pub(super) retry_after: Option<u64>,
}

impl Block {
    pub(super) const fn new(reason: Reason, status: u16, detail: &'static str) -> Self {
        Self {
            reason,
            status,
            detail,
            retry_after: None,
        }
    }
}

/// A request target in normal form: its path percent-decoded once, and its
/// query as it was sent.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Target<'a> {
    /// The path, decoded.
    pub(super) path: Vec<u8>,
    /// What follows the first `?`.
    pub(super) query: Option<&'a str>,
}

/// Reads a request target into normal form, or says why it has none.
///
/// Refused: a target that is not a path (`*`, a full URL, an authority), a
/// byte that had to be percent-encoded and was not, a `%` not followed by
/// two hex digits, an encoded slash or backslash and a plain backslash
/// (a server that reads either as a separator sees other segments than
/// were judged), a control byte once decoded, bytes that are not UTF-8
/// once decoded (an overlong encoding of a slash or a dot among them), a
/// `.` or `..` segment once decoded, and an empty segment (servers
/// disagree on whether `//` is `/`). A fragment never gets here: the head
/// is refused with one.
pub(super) fn normalise(target: &str) -> Result<Target<'_>, &'static str> {
    let (raw, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !raw.starts_with('/') {
        return Err("the target is not a path");
    }
    let bytes = raw.as_bytes();
    let mut path = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let decoded = match byte {
            b'%' => {
                let Some(decoded) = hex_pair(bytes.get(at + 1..at + 3)) else {
                    return Err("invalid percent-encoding");
                };
                match decoded {
                    b'/' => return Err("an encoded slash"),
                    b'\\' => return Err("an encoded backslash"),
                    _ => {}
                }
                at += 3;
                decoded
            }
            b'\\' => return Err("a backslash"),
            0x21..=0x7e => {
                at += 1;
                byte
            }
            _ => return Err("a byte that must be percent-encoded"),
        };
        if decoded < 0x20 || decoded == 0x7f {
            return Err("a control byte");
        }
        path.push(decoded);
    }
    if std::str::from_utf8(&path).is_err() {
        return Err("not UTF-8 once decoded");
    }
    let mut segments = path.split(|b| *b == b'/').skip(1).peekable();
    while let Some(segment) = segments.next() {
        if segment == b"." || segment == b".." {
            return Err("a dot segment");
        }
        if segment.is_empty() && segments.peek().is_some() {
            return Err("an empty segment");
        }
    }
    Ok(Target { path, query })
}

/// The byte two hex digits spell.
fn hex_pair(pair: Option<&[u8]>) -> Option<u8> {
    let [high, low] = pair? else { return None };
    let digit = |d: u8| char::from(d).to_digit(16);
    u8::try_from(digit(*high)? * 16 + digit(*low)?).ok()
}

/// One pattern of `allow_paths` or `deny_paths`
/// ([`erpc_worker::waf::path_pattern`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    /// One path.
    Exact(Vec<u8>),
    /// Every path that starts with this.
    Prefix(Vec<u8>),
}

/// A path without its trailing slash, the root aside.
fn without_slash(path: &[u8]) -> &[u8] {
    match path.strip_suffix(b"/") {
        Some(rest) if !rest.is_empty() => rest,
        _ => path,
    }
}

impl Pattern {
    fn new(text: &str) -> Self {
        match text.strip_suffix('*') {
            Some(start) => Self::Prefix(start.as_bytes().to_vec()),
            None => Self::Exact(text.as_bytes().to_vec()),
        }
    }

    /// Whether a decoded path is this pattern's. A trailing slash makes no
    /// difference: an app that serves `/admin/` as `/admin` must not be
    /// reached past a rule that names one of them.
    fn matches(&self, path: &[u8]) -> bool {
        match self {
            Self::Exact(want) => without_slash(path) == without_slash(want),
            Self::Prefix(start) => {
                path.starts_with(start) || (start.ends_with(b"/") && path == without_slash(start))
            }
        }
    }
}

/// Where in a target a probe is looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    /// One whole path segment.
    Segment,
    /// The start of a path segment.
    SegmentStart,
    /// The end of a path segment.
    SegmentEnd,
    /// Anywhere in the path or the query.
    Anywhere,
}

/// Something a scanner asks for.
struct Probe {
    /// What is looked for, in lower case.
    needle: &'static str,
    /// Where.
    at: At,
    /// Why it is refused.
    why: &'static str,
}

/// What scanners ask every address on the internet for, and an app made
/// with `erpc worker` does not serve. Compared in lower case with the
/// decoded path, and with the query decoded once (`+` as a space). Kept
/// short on purpose: it takes the noise off the app and out of its logs,
/// and is no substitute for the app checking its own input.
const PROBES: &[Probe] = &[
    Probe {
        needle: ".env",
        at: At::SegmentStart,
        why: "an environment file, where credentials are kept",
    },
    Probe {
        needle: ".git",
        at: At::Segment,
        why: "a Git directory, which holds the source and its history",
    },
    Probe {
        needle: ".aws",
        at: At::Segment,
        why: "a cloud credentials directory",
    },
    Probe {
        needle: "wp-admin",
        at: At::Segment,
        why: "the WordPress admin",
    },
    Probe {
        needle: "wp-login.php",
        at: At::Segment,
        why: "the WordPress login",
    },
    Probe {
        needle: "phpmyadmin",
        at: At::Segment,
        why: "a database admin tool",
    },
    Probe {
        needle: "cgi-bin",
        at: At::Segment,
        why: "CGI scripts",
    },
    Probe {
        needle: ".php",
        at: At::SegmentEnd,
        why: "a PHP script",
    },
    Probe {
        needle: ".asp",
        at: At::SegmentEnd,
        why: "an ASP script",
    },
    Probe {
        needle: ".aspx",
        at: At::SegmentEnd,
        why: "an ASP.NET page",
    },
    Probe {
        needle: ".jsp",
        at: At::SegmentEnd,
        why: "a JSP page",
    },
    Probe {
        needle: "etc/passwd",
        at: At::Anywhere,
        why: "a read of the password file",
    },
    Probe {
        needle: "${jndi:",
        at: At::Anywhere,
        why: "a Log4Shell lookup",
    },
    Probe {
        needle: "<script",
        at: At::Anywhere,
        why: "script injection",
    },
    Probe {
        needle: "union select",
        at: At::Anywhere,
        why: "SQL injection",
    },
];

/// A query decoded once: `+` as a space, `%XX` as its byte, and a `%` that
/// is not followed by two hex digits left as it is.
fn decode_query(query: &str) -> Vec<u8> {
    let bytes = query.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        at += 1;
        match byte {
            b'+' => out.push(b' '),
            b'%' => match hex_pair(bytes.get(at..at + 2)) {
                Some(decoded) => {
                    out.push(decoded);
                    at += 2;
                }
                None => out.push(byte),
            },
            _ => out.push(byte),
        }
    }
    out
}

/// The probe a target is, when it is one.
fn probe(target: &Target<'_>) -> Option<&'static Probe> {
    let path = target.path.to_ascii_lowercase();
    // The path and the query in one line of lower case, every run of
    // spaces and control bytes as one space.
    let mut line = path.clone();
    if let Some(query) = target.query {
        line.push(b'?');
        line.extend(decode_query(query).to_ascii_lowercase());
    }
    let mut spaced = Vec::with_capacity(line.len());
    for byte in line {
        let byte = if byte <= b' ' || byte == 0x7f {
            b' '
        } else {
            byte
        };
        if byte != b' ' || spaced.last() != Some(&b' ') {
            spaced.push(byte);
        }
    }
    PROBES.iter().find(|probe| {
        let needle = probe.needle.as_bytes();
        let mut segments = path.split(|b| *b == b'/');
        match probe.at {
            At::Segment => segments.any(|s| s == needle),
            At::SegmentStart => segments.any(|s| s.starts_with(needle)),
            At::SegmentEnd => segments.any(|s| s.ends_with(needle)),
            At::Anywhere => spaced.windows(needle.len()).any(|w| w == needle),
        }
    })
}

/// The rules of one config that need nothing but the request's method and
/// target.
#[derive(Debug)]
pub(super) struct Rules {
    methods: Vec<String>,
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
    probes: bool,
}

impl Rules {
    pub(super) fn new(config: &WafConfig) -> Self {
        let patterns = |list: &[String]| list.iter().map(|p| Pattern::new(p)).collect();
        Self {
            methods: config.methods.clone(),
            allow: patterns(&config.allow_paths),
            deny: patterns(&config.deny_paths),
            probes: config.block_probes,
        }
    }

    /// The methods forwarded, as an `Allow` header lists them.
    pub(super) fn allowed_methods(&self) -> String {
        self.methods.join(", ")
    }

    /// Judges a request by its method and its target, in this order, the
    /// first rule that fails being the answer: the method, the path's
    /// normal form, `deny_paths`, `allow_paths`, the probe list.
    pub(super) fn judge(&self, method: &str, target: &str) -> Result<(), Block> {
        if !self.methods.iter().any(|m| m == method) {
            return Err(Block::new(Reason::Method, 405, "the method is not listed"));
        }
        let target = normalise(target).map_err(|why| Block::new(Reason::Path, 400, why))?;
        if self.deny.iter().any(|p| p.matches(&target.path)) {
            return Err(Block::new(Reason::Denied, 403, "the path is denied"));
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|p| p.matches(&target.path)) {
            return Err(Block::new(
                Reason::NotAllowed,
                404,
                "the path is not allowed",
            ));
        }
        if self.probes
            && let Some(probe) = probe(&target)
        {
            return Err(Block::new(Reason::Probe, 403, probe.why));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use erpc_worker::waf::WafConfig;

    use super::{PROBES, Pattern, Reason, Rules, normalise};

    fn rules(allow: &[&str], deny: &[&str]) -> Rules {
        let mut config = WafConfig::default_for(
            "bot-prod",
            "127.0.0.1:8080".parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        );
        config.allow_paths = allow.iter().map(|p| (*p).to_owned()).collect();
        config.deny_paths = deny.iter().map(|p| (*p).to_owned()).collect();
        config.validate().expect("valid");
        Rules::new(&config)
    }

    #[test]
    fn a_path_in_normal_form_is_read_and_another_is_refused() {
        for (target, path, query) in [
            ("/", "/", None),
            (
                "/api/trades/123?limit=10&cursor=abc",
                "/api/trades/123",
                Some("limit=10&cursor=abc"),
            ),
            ("/api/", "/api/", None),
            ("/a%20b/%7Euser", "/a b/~user", None),
            ("/caf%C3%A9", "/caf\u{e9}", None),
            ("/a.b/..c/c../.d", "/a.b/..c/c../.d", None),
            ("/x?", "/x", Some("")),
            ("/x?a=%2f..%2f&b=/../", "/x", Some("a=%2f..%2f&b=/../")),
            ("/%41%61", "/Aa", None),
        ] {
            let read = normalise(target).unwrap_or_else(|why| panic!("{target}: {why}"));
            assert_eq!(read.path, path.as_bytes(), "{target}");
            assert_eq!(read.query, query, "{target}");
        }
        for (target, why) in [
            ("*", "not a path"),
            ("", "not a path"),
            ("api", "not a path"),
            ("http://127.0.0.1/api", "not a path"),
            ("127.0.0.1:443", "not a path"),
            ("/a/../b", "dot segment"),
            ("/a/./b", "dot segment"),
            ("/..", "dot segment"),
            ("/.", "dot segment"),
            ("/a/..", "dot segment"),
            ("/%2e%2e/etc", "dot segment"),
            ("/a/%2E%2e/b", "dot segment"),
            ("/a/.%2e/b", "dot segment"),
            ("/a/%2e/b", "dot segment"),
            ("/a%2fb", "encoded slash"),
            ("/a%2Fb", "encoded slash"),
            ("/a%5cb", "encoded backslash"),
            ("/a%5Cb", "encoded backslash"),
            ("/a\\b", "backslash"),
            ("/a%00b", "control byte"),
            ("/a%0ab", "control byte"),
            ("/a%0d%0ab", "control byte"),
            ("/a%7fb", "control byte"),
            // Latin-1, and overlong forms of a slash and of a dot.
            ("/caf%E9", "not UTF-8"),
            ("/a%c0%afb", "not UTF-8"),
            ("/%c0%ae%c0%ae/etc", "not UTF-8"),
            ("/a%ff", "not UTF-8"),
            ("/a%1", "percent-encoding"),
            ("/a%", "percent-encoding"),
            ("/a%zz", "percent-encoding"),
            ("/a%2", "percent-encoding"),
            ("/%+1", "percent-encoding"),
            ("//", "empty segment"),
            ("//a", "empty segment"),
            ("/a//b", "empty segment"),
            ("/a//", "empty segment"),
            ("/a b", "percent-encoded"),
            ("/a\tb", "percent-encoded"),
            ("/a\0b", "percent-encoded"),
            ("/caf\u{e9}", "percent-encoded"),
            ("/a\u{7f}", "percent-encoded"),
        ] {
            let refused = normalise(target).expect_err(target);
            assert!(refused.contains(why), "{target:?}: {refused}");
        }
        // Decoded once, never twice: this is the segment `%2e%2e`, which
        // is what is forwarded and what a deny pattern is compared with.
        assert_eq!(normalise("/%252e%252e/x").expect("once").path, b"/%2e%2e/x");
    }

    #[test]
    fn a_pattern_is_one_path_or_a_prefix_and_a_trailing_slash_does_not_matter() {
        for (pattern, path, is) in [
            ("/healthz", "/healthz", true),
            ("/healthz", "/healthz/", true),
            ("/healthz", "/healthz/x", false),
            ("/healthz", "/healthzz", false),
            ("/healthz", "/Healthz", false),
            ("/healthz", "/", false),
            ("/healthz/", "/healthz", true),
            ("/", "/", true),
            ("/", "/x", false),
            ("/api/*", "/api/", true),
            ("/api/*", "/api/trades/123", true),
            ("/api/*", "/api", true),
            ("/api/*", "/apix", false),
            ("/api/*", "/ap", false),
            ("/api/*", "/x/api/y", false),
            ("/api/*", "/API/x", false),
            ("/api*", "/api", true),
            ("/api*", "/apix/y", true),
            ("/api*", "/ap", false),
            ("/*", "/", true),
            ("/*", "/anything/at/all", true),
        ] {
            assert_eq!(
                Pattern::new(pattern).matches(path.as_bytes()),
                is,
                "{pattern} against {path}"
            );
        }
    }

    #[test]
    fn deny_is_judged_on_the_decoded_path_and_before_allow() {
        let listed = rules(&["/api/*", "/healthz"], &["/api/admin/*"]);
        for (target, verdict) in [
            ("/api/trades/123?limit=10&cursor=abc", None),
            ("/healthz", None),
            ("/healthz/", None),
            ("/api", None),
            ("/api/admin/users", Some((Reason::Denied, 403))),
            ("/api/admin", Some((Reason::Denied, 403))),
            ("/api/admin/", Some((Reason::Denied, 403))),
            // An encoded letter is the same path to the app, and to the rule.
            ("/api/%61dmin/users", Some((Reason::Denied, 403))),
            ("/api/admi%6E", Some((Reason::Denied, 403))),
            ("/api/administrators", None),
            ("/metrics", Some((Reason::NotAllowed, 404))),
            ("/", Some((Reason::NotAllowed, 404))),
            ("/healthz/deep", Some((Reason::NotAllowed, 404))),
            // Ways round a rule are refused as paths, before the rule.
            ("/api/x/../admin/users", Some((Reason::Path, 400))),
            ("/api//admin/users", Some((Reason::Path, 400))),
            ("/api/admin%2fusers", Some((Reason::Path, 400))),
            ("/api\\admin\\users", Some((Reason::Path, 400))),
            ("/healthz/..%2fapi/admin", Some((Reason::Path, 400))),
        ] {
            let judged = listed
                .judge("GET", target)
                .err()
                .map(|b| (b.reason, b.status));
            assert_eq!(judged, verdict, "{target}");
        }
        // With no allow list every path is forwarded but the denied ones.
        let open = rules(&[], &["/api/admin/*"]);
        assert!(open.judge("GET", "/metrics").is_ok());
        assert!(open.judge("GET", "/api/admin/x").is_err());
    }

    #[test]
    fn a_method_not_listed_is_refused_first() {
        let rules = rules(&["/api/*"], &[]);
        assert!(rules.judge("POST", "/api/orders").is_ok());
        assert_eq!(rules.allowed_methods(), "GET, POST, PUT, DELETE");
        for method in [
            "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "get", "GETX", "",
        ] {
            // The path would be refused too; the method is what is said.
            let block = rules.judge(method, "/a/../b").expect_err(method);
            assert_eq!(
                (block.reason, block.status),
                (Reason::Method, 405),
                "{method}"
            );
        }
    }

    /// One request each probe refuses. Every entry of the table has one.
    const EXAMPLES: &[(&str, &str)] = &[
        (".env", "/.env"),
        (".git", "/.git/config"),
        (".aws", "/.aws/credentials"),
        ("wp-admin", "/wp-admin/install.php"),
        ("wp-login.php", "/blog/wp-login.php"),
        ("phpmyadmin", "/phpMyAdmin/"),
        ("cgi-bin", "/cgi-bin/luci"),
        (".php", "/index.php?s=/Index/think/app/invokefunction"),
        (".asp", "/login.asp"),
        (".aspx", "/owa/auth/logon.aspx"),
        (".jsp", "/console/login/LoginForm.jsp"),
        ("etc/passwd", "/download?file=/etc/passwd"),
        ("${jndi:", "/api/search?q=${jndi:ldap://x/a}"),
        ("<script", "/api/search?q=<script>alert(1)</script>"),
        (
            "union select",
            "/api/items?id=1 union select password from users",
        ),
    ];

    #[test]
    fn each_probe_blocks_its_example_and_an_ordinary_path_passes() {
        let rules = rules(&[], &[]);
        assert_eq!(PROBES.len(), EXAMPLES.len(), "an example for every probe");
        for probe in PROBES {
            assert_eq!(probe.needle, probe.needle.to_ascii_lowercase());
            assert!(!probe.why.is_empty());
            let (_, example) = EXAMPLES
                .iter()
                .find(|(needle, _)| *needle == probe.needle)
                .unwrap_or_else(|| panic!("no example for {}", probe.needle));
            // The example is refused by this probe, not by one before it.
            let found = super::probe(&normalise(example).expect("normal form"))
                .unwrap_or_else(|| panic!("{example} is not a probe"));
            assert_eq!(found.needle, probe.needle, "{example}");
            let block = rules.judge("GET", example).expect_err(example);
            assert_eq!(
                (block.reason, block.status),
                (Reason::Probe, 403),
                "{example}"
            );
        }
        for encoded in [
            "/.ENV",
            "/%2eenv",
            "/.env.production",
            "/a/b/.git/HEAD",
            "/WP-Admin/",
            "/x.PHP",
            "/index.php/extra",
            "/api/items?id=1+UNION+SELECT+1",
            "/api/items?id=1%20union%20select%201",
            "/api/items?id=1%0aunion%0a%0aselect%201",
            "/api/items?id=1+union++select+1",
            "/api/search?q=%3CScRiPt%3E",
            "/api/search?q=$%7Bjndi:ldap",
            "/api/search?q=%24%7BJNDI%3Aldap",
            "/api/file?name=..%2F..%2Fetc%2Fpasswd",
            "/static/etc/passwd",
        ] {
            let block = rules.judge("GET", encoded).expect_err(encoded);
            assert_eq!(block.reason, Reason::Probe, "{encoded}");
        }
        for ordinary in [
            "/",
            "/healthz",
            "/api/trades/123?limit=10&cursor=abc",
            "/api/orders?symbol=SOL%2FUSDC&side=buy",
            "/api/environment",
            "/api/users/git",
            "/api/.gitignore-rules",
            "/api/scripts/42",
            "/api/reunion?select=all",
            "/api/select/union",
            "/docs/setup.php.md",
            "/api/aspect",
            "/api/etc",
            "/api/passwd",
            "/api/search?q=100%25+of+the+%24",
            "/api/search?q=a%3Cb",
        ] {
            assert!(rules.judge("GET", ordinary).is_ok(), "{ordinary}");
        }
        // Off, the same requests are the app's to answer.
        let mut config = WafConfig::default_for(
            "bot-prod",
            "127.0.0.1:8080".parse().expect("listen"),
            "127.0.0.1:3000".parse().expect("upstream"),
        );
        config.block_probes = false;
        let off = Rules::new(&config);
        for (_, example) in EXAMPLES {
            assert!(off.judge("GET", example).is_ok(), "{example}");
        }
    }

    #[test]
    fn every_reason_has_a_name_and_only_requests_count_towards_a_ban() {
        let names: Vec<&str> = Reason::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(
            names,
            [
                "method",
                "path",
                "denied",
                "not_allowed",
                "probe",
                "rate",
                "body",
                "malformed",
                "banned",
                "connections",
                "upgrade",
                "body_timeout"
            ]
        );
        for reason in Reason::ALL {
            let counts = !matches!(reason, Reason::Banned | Reason::Connections);
            assert_eq!(reason.is_violation(), counts, "{}", reason.name());
        }
    }
}
