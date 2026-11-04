// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reading what can carry the key -- an unlock on standard input, a
//! request on the agent's socket -- into one buffer, sized for the most it
//! may be before anything goes in, and wiped when it is dropped. A buffer
//! that grows leaves the copy it grew from behind, and a reader of its own
//! (a `BufReader`) keeps a copy nobody wipes, so neither is used.

use std::io::Read;

use zeroize::Zeroizing;

/// Reads from `from` until end of input, or until a newline when `line`,
/// keeping at most `max` bytes. `None` when there is more than that.
/// Each read goes straight into the buffer: a slice this large goes past
/// the standard input's own buffer rather than through it.
pub(crate) fn read(
    from: &mut impl Read,
    max: usize,
    line: bool,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut buf = Zeroizing::new(vec![0_u8; max + 1]);
    let mut n = 0;
    while let Some(free) = buf.get_mut(n..).filter(|f| !f.is_empty()) {
        let got = match from.read(free) {
            Ok(0) => break,
            Ok(got) => got,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let seen = n;
        n += got;
        if line && buf.get(seen..n).is_some_and(|b| b.contains(&b'\n')) {
            break;
        }
    }
    if n > max {
        return Ok(None);
    }
    // Shortened in place: the bytes past `n` are zeros, and the ones kept
    // stay in this buffer, which is wiped.
    buf.truncate(n);
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    #[test]
    fn what_is_read_fits_in_one_buffer_or_is_refused() {
        let got = super::read(&mut &b"{\"op\":\"status\"}\n"[..], 64, true)
            .expect("reads")
            .expect("fits");
        assert_eq!(got.as_slice(), b"{\"op\":\"status\"}\n");
        assert!(
            super::read(&mut &[b'x'; 65][..], 64, false)
                .expect("reads")
                .is_none()
        );
        let all = super::read(&mut &b"a\nb"[..], 64, false)
            .expect("reads")
            .expect("fits");
        assert_eq!(all.as_slice(), b"a\nb");
        // A line ends the read; nothing after it is waited for.
        let first = super::read(&mut &b"a\nb"[..], 64, true)
            .expect("reads")
            .expect("fits");
        assert!(first.starts_with(b"a\n"));
    }
}
