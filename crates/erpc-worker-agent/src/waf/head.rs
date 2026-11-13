// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A request's head, read strictly before hyper reads it.
//!
//! hyper reads HTTP as the RFC lets a server read it, which is more
//! forgiving than a proxy in front of another server should be: it takes a
//! request with both `Transfer-Encoding` and `Content-Length` and drops the
//! length, and takes a bare line feed for a line end. Where two readers of
//! the same bytes can disagree about where a request ends, one request can
//! be smuggled inside another. So the head is first read here, with the
//! parser hyper itself uses (`httparse`), and refused unless it has
//! exactly one reading: then the same bytes are handed to hyper.

/// The most header lines in a head; hyper's own limit.
pub(super) const MAX_HEADERS: usize = 100;

/// How a request's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Framing {
    /// There is none.
    None,
    /// `Content-Length`: this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`: until its last chunk.
    Chunked,
}

/// What a head says, as far as the proxy's rules need it. The headers
/// themselves are hyper's to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Head {
    /// The method, as sent.
    pub(super) method: String,
    /// The request target, as sent.
    pub(super) target: String,
    /// How its body is delimited.
    pub(super) framing: Framing,
    /// Whether the connection ends with this request: the client says so,
    /// it speaks HTTP/1.0, or where the request ends is hyper's to find
    /// (a chunked body), so nothing after it on the connection is read.
    pub(super) close: bool,
    /// Whether it asks to change protocol.
    pub(super) upgrade: bool,
}

/// Why a head is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Fault {
    /// The status answered: 400, or 431 for too many headers.
    pub(super) status: u16,
    /// What is wrong with it.
    pub(super) why: &'static str,
    /// Its method and target, when its first line could be read.
    pub(super) line: Option<(String, String)>,
}

/// Where the head in `buf` ends: the index after its empty line. `from`
/// is how far a search has already looked.
pub(super) fn end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| from + at + 4)
}

/// Whether `buf` can still be the start of a request: one to sixteen
/// upper-case letters, then a space. Anything else (a TLS handshake sent to
/// a plain port, a scanner's bytes) is refused at its first read instead of
/// when the head's time is up.
pub(super) fn plausible(buf: &[u8]) -> bool {
    for (at, byte) in buf.iter().take(17).enumerate() {
        match byte {
            b'A'..=b'Z' => {}
            b' ' => return at > 0,
            _ => return false,
        }
    }
    buf.len() < 17
}

/// Without the spaces and tabs around it.
fn trim(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

/// A `Content-Length`: digits and nothing else, so that it has one reading.
fn length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// Whether a `Host` is a name or an address, with or without a port.
fn is_host(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:[]".contains(b))
}

/// Reads one head: `head` is everything up to and with its empty line.
///
/// Refused, because another server could read it differently or because
/// the proxy does not speak it:
///
/// - a line feed without a carriage return before it, or a carriage
///   return without a line feed after it;
/// - an empty line before the request line;
/// - anything `httparse` refuses in a request: more than one space between
///   the parts of its first line, a version other than HTTP/1.0 or 1.1, a
///   header name with a space before its colon, a header continued on the
///   next line (obs-fold), a control byte in a value;
/// - a target that is not ASCII, or has a fragment;
/// - more than one `Content-Length`, or one that is not all digits;
/// - more than one `Transfer-Encoding`, one that is not exactly
///   `chunked`, one on HTTP/1.0, and one beside a `Content-Length`;
/// - more than one `Host`, none on HTTP/1.1, or one that is not a name or
///   an address.
pub(super) fn parse(head: &[u8]) -> Result<Head, Fault> {
    let bad = |why, line| Fault {
        status: 400,
        why,
        line,
    };
    if matches!(head.first(), Some(b'\r' | b'\n')) {
        return Err(bad("an empty line before the request", None));
    }
    let mut before = 0_u8;
    for &byte in head {
        if byte == b'\n' && before != b'\r' {
            return Err(bad("a line feed without a carriage return", None));
        }
        if before == b'\r' && byte != b'\n' {
            return Err(bad("a carriage return without a line feed", None));
        }
        before = byte;
    }
    let mut lines = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut lines);
    let parsed = request.parse(head);
    let line = request
        .method
        .zip(request.path)
        .map(|(method, target)| (method.to_owned(), target.to_owned()));
    match parsed {
        Ok(httparse::Status::Complete(read)) if read == head.len() => {}
        Ok(_) => return Err(bad("not one whole head", line)),
        Err(httparse::Error::TooManyHeaders) => {
            return Err(Fault {
                status: 431,
                why: "more than 100 headers",
                line,
            });
        }
        Err(_) => return Err(bad("not an HTTP/1 request", line)),
    }
    let Some((method, target)) = line.clone() else {
        return Err(bad("not an HTTP/1 request", None));
    };
    let http11 = request.version == Some(1);
    if !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(bad("a target that is not ASCII", line));
    }
    if target.contains('#') {
        return Err(bad("a target with a fragment", line));
    }
    let (framing, close, upgrade) =
        headers(request.headers, http11).map_err(|why| bad(why, line))?;
    Ok(Head {
        method,
        target,
        framing,
        close,
        upgrade,
    })
}

/// What a head's headers say: how the body is delimited, whether the
/// connection ends with the request, and whether it asks to change
/// protocol. Or what makes them ambiguous.
fn headers(
    lines: &[httparse::Header<'_>],
    http11: bool,
) -> Result<(Framing, bool, bool), &'static str> {
    let mut length_said = None;
    let mut chunked = false;
    let mut hosts = 0_u32;
    let mut close = !http11;
    let mut upgrade = false;
    for header in lines {
        let value = trim(header.value);
        if header.name.eq_ignore_ascii_case("content-length") {
            if length_said.is_some() {
                return Err("more than one Content-Length");
            }
            let Some(said) = length(value) else {
                return Err("a Content-Length that is not a number");
            };
            length_said = Some(said);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked {
                return Err("more than one Transfer-Encoding");
            }
            if !value.eq_ignore_ascii_case(b"chunked") {
                return Err("a Transfer-Encoding other than chunked");
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if !is_host(value) {
                return Err("a Host that is not a name or an address");
            }
        } else if header.name.eq_ignore_ascii_case("connection") {
            close |= value
                .split(|b| *b == b',')
                .any(|token| trim(token).eq_ignore_ascii_case(b"close"));
        } else if header.name.eq_ignore_ascii_case("upgrade") {
            upgrade = true;
        }
    }
    if chunked && length_said.is_some() {
        return Err("both Transfer-Encoding and Content-Length");
    }
    if chunked && !http11 {
        return Err("Transfer-Encoding on HTTP/1.0");
    }
    if hosts > 1 {
        return Err("more than one Host");
    }
    if http11 && hosts == 0 {
        return Err("HTTP/1.1 without a Host");
    }
    let framing = match (chunked, length_said) {
        (true, _) => Framing::Chunked,
        (false, Some(said)) => Framing::Length(said),
        (false, None) => Framing::None,
    };
    Ok((framing, close || chunked || upgrade, upgrade))
}

#[cfg(test)]
mod tests {
    use super::{Framing, MAX_HEADERS, end, parse, plausible};

    /// A head from its lines.
    fn head(lines: &[&str]) -> Vec<u8> {
        let mut text = lines.join("\r\n");
        text.push_str("\r\n\r\n");
        text.into_bytes()
    }

    #[test]
    fn a_plain_request_is_read() {
        let get = parse(&head(&[
            "GET /api/trades/123?limit=10 HTTP/1.1",
            "Host: bot.example:8080",
            "Accept: */*",
            "Authorization: Bearer abc",
        ]))
        .expect("a GET");
        assert_eq!(get.method, "GET");
        assert_eq!(get.target, "/api/trades/123?limit=10");
        assert_eq!(get.framing, Framing::None);
        assert!(!get.close && !get.upgrade);
        let post = parse(&head(&[
            "POST /api/orders HTTP/1.1",
            "host: 127.0.0.1",
            "content-length:  42 ",
        ]))
        .expect("a POST");
        assert_eq!(post.framing, Framing::Length(42));
        assert!(!post.close);
        let chunked = parse(&head(&[
            "POST /api/orders HTTP/1.1",
            "Host: [::1]:8080",
            "Transfer-Encoding: Chunked",
        ]))
        .expect("chunked");
        assert_eq!(chunked.framing, Framing::Chunked);
        assert!(chunked.close, "what follows a chunked body is not read");
        let zero = parse(&head(&["PUT /x HTTP/1.1", "Host: a", "Content-Length: 0"]))
            .expect("an empty body");
        assert_eq!(zero.framing, Framing::Length(0));
    }

    #[test]
    fn the_connection_ends_when_the_client_says_so_or_speaks_http_1_0() {
        for (lines, close, upgrade) in [
            (vec!["GET / HTTP/1.1", "Host: a"], false, false),
            (
                vec!["GET / HTTP/1.1", "Host: a", "Connection: close"],
                true,
                false,
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "Connection: keep-alive, Close"],
                true,
                false,
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "Connection: keep-alive"],
                false,
                false,
            ),
            (vec!["GET / HTTP/1.0"], true, false),
            (
                vec!["GET / HTTP/1.0", "Connection: keep-alive"],
                true,
                false,
            ),
            (
                vec![
                    "GET /ws HTTP/1.1",
                    "Host: a",
                    "Connection: Upgrade",
                    "Upgrade: websocket",
                ],
                true,
                true,
            ),
        ] {
            let read = parse(&head(&lines)).unwrap_or_else(|f| panic!("{lines:?}: {f:?}"));
            assert_eq!((read.close, read.upgrade), (close, upgrade), "{lines:?}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of heads")]
    fn a_head_two_servers_could_read_differently_is_refused() {
        for (lines, why) in [
            // Which of the two ends the body?
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Transfer-Encoding: chunked",
                    "Content-Length: 4",
                ],
                "both Transfer-Encoding and Content-Length",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Content-Length: 4",
                    "Transfer-Encoding: chunked",
                ],
                "both Transfer-Encoding and Content-Length",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Content-Length: 4",
                    "Content-Length: 5",
                ],
                "more than one Content-Length",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Content-Length: 4",
                    "content-length: 4",
                ],
                "more than one Content-Length",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length: 4, 4"],
                "not a number",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length: +4"],
                "not a number",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length: 0x4"],
                "not a number",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length: 4 4"],
                "not a number",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length: -1"],
                "not a number",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Content-Length:"],
                "not a number",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Content-Length: 99999999999999999999",
                ],
                "not a number",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Transfer-Encoding: chunked",
                    "Transfer-Encoding: chunked",
                ],
                "more than one Transfer-Encoding",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Transfer-Encoding: gzip, chunked",
                ],
                "other than chunked",
            ),
            (
                vec![
                    "POST / HTTP/1.1",
                    "Host: a",
                    "Transfer-Encoding: chunked, chunked",
                ],
                "other than chunked",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Transfer-Encoding: identity"],
                "other than chunked",
            ),
            (
                vec!["POST / HTTP/1.1", "Host: a", "Transfer-Encoding: xchunked"],
                "other than chunked",
            ),
            (
                vec!["POST / HTTP/1.0", "Transfer-Encoding: chunked"],
                "HTTP/1.0",
            ),
            // Which host is asked for?
            (
                vec!["GET / HTTP/1.1", "Host: a", "Host: b"],
                "more than one Host",
            ),
            (
                vec!["GET / HTTP/1.0", "Host: a", "host: a"],
                "more than one Host",
            ),
            (vec!["GET / HTTP/1.1"], "without a Host"),
            (vec!["GET / HTTP/1.1", "Host:"], "not a name"),
            (vec!["GET / HTTP/1.1", "Host: a b"], "not a name"),
            (vec!["GET / HTTP/1.1", "Host: a/b"], "not a name"),
            (vec!["GET / HTTP/1.1", "Host: user@a"], "not a name"),
            (vec!["GET / HTTP/1.1", "Host: a, b"], "not a name"),
            // Where does the header end?
            (
                vec!["GET / HTTP/1.1", "Host: a", "X-Folded: one", " two"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "X-Folded: one", "\ttwo"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "Content-Length : 4"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", " Content-Length: 4"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "No colon here"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", ": empty name"],
                "not an HTTP/1 request",
            ),
            (
                vec!["GET / HTTP/1.1", "Host: a", "X: a\0b"],
                "not an HTTP/1 request",
            ),
            // What is the request?
            (vec!["GET  / HTTP/1.1", "Host: a"], "not an HTTP/1 request"),
            (vec!["GET / HTTP/1.1 ", "Host: a"], "not an HTTP/1 request"),
            (
                vec!["GET /a b HTTP/1.1", "Host: a"],
                "not an HTTP/1 request",
            ),
            (vec!["GET / HTTP/2.0", "Host: a"], "not an HTTP/1 request"),
            (vec!["GET / HTTP/0.9", "Host: a"], "not an HTTP/1 request"),
            (vec!["GET /", "Host: a"], "not an HTTP/1 request"),
            (vec!["GET / http/1.1", "Host: a"], "not an HTTP/1 request"),
            (vec!["G(T / HTTP/1.1", "Host: a"], "not an HTTP/1 request"),
            (vec!["PRI * HTTP/2.0"], "not an HTTP/1 request"),
            (vec!["GET /a#b HTTP/1.1", "Host: a"], "fragment"),
            (vec!["GET /caf\u{e9} HTTP/1.1", "Host: a"], "not ASCII"),
        ] {
            let fault = parse(&head(&lines)).expect_err(&lines.join(" | "));
            assert_eq!(fault.status, 400, "{lines:?}");
            assert!(fault.why.contains(why), "{lines:?}: {}", fault.why);
        }
    }

    #[test]
    fn a_line_ends_in_crlf_and_nothing_else() {
        for raw in [
            &b"GET / HTTP/1.1\nHost: a\n\n"[..],
            b"GET / HTTP/1.1\r\nHost: a\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\nContent-Length: 5\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\rContent-Length: 5\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\r\n\r\n",
            b"GET /\r HTTP/1.1\r\nHost: a\r\n\r\n",
        ] {
            let fault = parse(raw).expect_err("a bare line end");
            assert_eq!(fault.status, 400);
            assert!(
                fault.why.contains("without"),
                "{}: {}",
                String::from_utf8_lossy(raw).escape_debug(),
                fault.why
            );
        }
        // An empty line before the request, half a head, and bytes after
        // the head are not one head either.
        for raw in [
            &b"\r\n\r\n"[..],
            b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET",
            b"",
        ] {
            assert!(
                parse(raw).is_err(),
                "{}",
                String::from_utf8_lossy(raw).escape_debug()
            );
        }
    }

    #[test]
    fn the_first_line_is_kept_for_the_log_when_it_could_be_read() {
        let fault = parse(&head(&[
            "POST /api/orders HTTP/1.1",
            "Host: a",
            "Authorization: Bearer abc",
            "Content-Length: 4",
            "Transfer-Encoding: chunked",
        ]))
        .expect_err("both");
        assert_eq!(
            fault.line,
            Some(("POST".to_owned(), "/api/orders".to_owned()))
        );
        let fault = parse(b"\x16\x03\x01\x02\x00\r\n\r\n").expect_err("not HTTP");
        assert_eq!(fault.line, None);
    }

    #[test]
    fn a_head_has_at_most_a_hundred_headers() {
        let mut lines = vec!["GET / HTTP/1.1".to_owned(), "Host: a".to_owned()];
        lines.extend((1..MAX_HEADERS).map(|n| format!("X-{n}: {n}")));
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert!(parse(&head(&refs)).is_ok(), "a hundred");
        lines.push("X-More: 1".to_owned());
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let fault = parse(&head(&refs)).expect_err("a hundred and one");
        assert_eq!(fault.status, 431);
    }

    #[test]
    fn the_end_of_a_head_is_found_wherever_the_search_resumes() {
        let bytes = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody";
        assert_eq!(end(bytes, 0), Some(27));
        assert_eq!(end(bytes, 23), Some(27));
        assert_eq!(end(bytes, 24), None);
        assert_eq!(end(bytes, 400), None);
        assert_eq!(end(b"GET / HTTP/1.1\r\nHost: a\r\n", 0), None);
        assert_eq!(end(b"", 0), None);
    }

    #[test]
    fn what_cannot_be_a_request_is_known_from_its_first_bytes() {
        for start in [
            &b""[..],
            b"G",
            b"GET",
            b"GET ",
            b"DELETE /x",
            b"ABCDEFGHIJKLMNOP",
            b"ABCDEFGHIJKLMNOP /",
        ] {
            assert!(plausible(start), "{}", String::from_utf8_lossy(start));
        }
        for start in [
            &b"\x16\x03\x01\x02\x00\x01"[..],
            b" GET",
            b"get / HTTP/1.1",
            b"\r\nGET",
            b"G3T /",
            b"ABCDEFGHIJKLMNOPQ",
            b"ABCDEFGHIJKLMNOPQ /",
            b"SSH-2.0-OpenSSH_9.6\r\n",
        ] {
            assert!(
                !plausible(start),
                "{}",
                String::from_utf8_lossy(start).escape_debug()
            );
        }
    }
}
