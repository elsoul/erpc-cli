// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What a binary is, read from its ELF header: enough to say, before it is
//! uploaded, whether a server can run it.
//!
//! `erpc worker` ships a binary it did not build itself in two cases: one
//! the operator built with another toolchain (`build.prebuilt`), and one
//! cargo built on this machine without the cross-build. Neither went
//! through `cargo zigbuild`, which pins the platform and the oldest glibc,
//! so both are read here: the machine it is for, whether it is a program,
//! whether it is linked against glibc, and the newest glibc version it
//! asks for.
//!
//! Only the header, the program headers, the dynamic section and the
//! version names are read. Every offset is checked against the file's
//! length: the bytes may be anything. What cannot be read is refused, not
//! guessed at: a file that ends before what its header names is cut short,
//! never a static binary.

/// The machine a binary runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    X86_64,
    Aarch64,
    /// Another one, by its ELF number.
    Other(u16),
}

impl Machine {
    /// The architecture as Rust target triples start: `x86_64`, `aarch64`.
    pub(crate) fn arch(self) -> String {
        match self {
            Self::X86_64 => "x86_64".to_owned(),
            Self::Aarch64 => "aarch64".to_owned(),
            Self::Other(number) => format!("ELF machine {number}"),
        }
    }

    /// Where glibc's loader and musl's are on a Linux of this machine: the
    /// paths a binary linked against either names, to the letter.
    const fn loaders(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::X86_64 => Some(("/lib64/ld-linux-x86-64.so.2", "/lib/ld-musl-x86_64.so.1")),
            Self::Aarch64 => Some(("/lib/ld-linux-aarch64.so.1", "/lib/ld-musl-aarch64.so.1")),
            Self::Other(_) => None,
        }
    }
}

/// How a binary finds its C library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Libc {
    /// It carries what it needs: no interpreter is named.
    Static,
    /// Linked against glibc, and the newest version it asks for
    /// (`(2, 39)` for `GLIBC_2.39`), when it names one.
    Glibc(Option<(u32, u32)>),
    /// Linked against musl's loader.
    Musl,
    /// Another loader, by its path as it can be printed: one that is
    /// neither glibc's nor musl's, or either of them somewhere a server
    /// does not have it.
    Other(String),
}

/// What an ELF file says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Elf {
    pub(crate) machine: Machine,
    pub(crate) libc: Libc,
}

impl Elf {
    /// The glibc version the binary needs, as `2.39`.
    pub(crate) fn glibc(&self) -> Option<String> {
        match self.libc {
            Libc::Glibc(Some((major, minor))) => Some(format!("{major}.{minor}")),
            _ => None,
        }
    }
}

/// Why a file is not a program the servers run. What it says is said by
/// the command that read the file, in the language of the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotAProgram {
    /// A Mach-O binary: built for macOS.
    MacOs,
    /// A PE binary: built for Windows.
    Windows,
    /// A script, by its `#!`.
    Script,
    /// Not an ELF file, nor any of the above.
    NotElf,
    /// A 32-bit ELF file.
    Bits32,
    /// A big-endian ELF file.
    BigEndian,
    /// It ends before what its header names.
    CutShort,
    /// An object file or a core.
    NotExecutable,
    /// It has no part the system would load.
    NothingToLoad,
    /// A shared library.
    SharedLibrary,
}

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
/// The size of a 64-bit program header, and of an entry of the dynamic
/// section.
const PROGRAM_HEADER: usize = 56;
const DYNAMIC_ENTRY: usize = 16;
const DT_NULL: u64 = 0;
const DT_SONAME: u64 = 14;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// In `DT_FLAGS_1`: the file is a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;

/// The `N` bytes at `at`, when the file has them: an offset read from the
/// file may be anything, past the end or too large to add to.
fn at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    at(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    at(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    at(bytes, offset).map(u64::from_le_bytes)
}

/// A 64-bit offset or length in the file, as an index into it.
fn index_at(bytes: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(u64_at(bytes, offset)?).ok()
}

/// A program header: its type, and the bytes of the file it names.
struct Segment<'a> {
    kind: u32,
    file: &'a [u8],
}

/// The program headers of `bytes`, each with the part of the file it
/// names. `None` when the table, or what an entry names, is not in the
/// file: the file is shorter than its header says.
fn segments(bytes: &[u8]) -> Option<Vec<Segment<'_>>> {
    let table = index_at(bytes, 32)?;
    let entry_size = usize::from(u16_at(bytes, 54)?);
    let entries = usize::from(u16_at(bytes, 56)?);
    if entries > 0 && entry_size < PROGRAM_HEADER {
        return None;
    }
    (0..entries)
        .map(|index| {
            let header = table.checked_add(index.checked_mul(entry_size)?)?;
            let kind = u32_at(bytes, header)?;
            let start = index_at(bytes, header.checked_add(8)?)?;
            let length = index_at(bytes, header.checked_add(32)?)?;
            // One that names no bytes of the file (what is only memory,
            // a stack) is at whatever offset the linker gave it.
            let file = match length {
                0 => &[],
                _ => bytes.get(start..start.checked_add(length)?)?,
            };
            Some(Segment { kind, file })
        })
        .collect()
}

/// The entries of a dynamic section, as `(tag, value)`, up to its end
/// mark.
fn dynamic(section: &[u8]) -> impl Iterator<Item = (u64, u64)> + '_ {
    section
        .as_chunks::<DYNAMIC_ENTRY>()
        .0
        .iter()
        .filter_map(|entry| Some((u64_at(entry, 0)?, u64_at(entry, 8)?)))
        .take_while(|(tag, _)| *tag != DT_NULL)
}

/// Reads `bytes` as a 64-bit little-endian ELF program, which is what
/// every server `erpc worker` deploys to runs.
///
/// A program is a file of type `ET_EXEC`, or one of type `ET_DYN` that
/// says it is run: it names an interpreter, or its dynamic section carries
/// the flag linkers give a position-independent executable (`DF_1_PIE`),
/// which is how a static one is told from a library. A file of type
/// `ET_DYN` with neither, or one that gives itself a library's name
/// (`DT_SONAME`), is a shared library. The header cannot say more: a
/// static position-independent executable from a linker that sets no such
/// flag is refused with the libraries.
///
/// # Errors
///
/// What it is instead ([`NotAProgram`]): not an ELF file at all (a script,
/// a Mach-O or PE binary built for this machine), a 32-bit or big-endian
/// one, an object file, a core or a shared library rather than a program,
/// or a file that ends before what its header names.
pub(crate) fn inspect(bytes: &[u8]) -> Result<Elf, NotAProgram> {
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(match bytes.get(..4) {
            Some([0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]) => NotAProgram::MacOs,
            Some([b'M', b'Z', ..]) => NotAProgram::Windows,
            Some([b'#', b'!', ..]) => NotAProgram::Script,
            _ => NotAProgram::NotElf,
        });
    }
    let cut = NotAProgram::CutShort;
    if *bytes.get(4).ok_or(cut)? != 2 {
        return Err(NotAProgram::Bits32);
    }
    if *bytes.get(5).ok_or(cut)? != 1 {
        return Err(NotAProgram::BigEndian);
    }
    let kind = u16_at(bytes, 16).ok_or(cut)?;
    if kind != ET_EXEC && kind != ET_DYN {
        return Err(NotAProgram::NotExecutable);
    }
    let machine = match u16_at(bytes, 18).ok_or(cut)? {
        62 => Machine::X86_64,
        183 => Machine::Aarch64,
        other => Machine::Other(other),
    };
    let segments = segments(bytes).ok_or(cut)?;
    // Nothing to load is nothing the system can start.
    if !segments.iter().any(|s| s.kind == PT_LOAD) {
        return Err(NotAProgram::NothingToLoad);
    }
    let interpreter = segments.iter().find(|s| s.kind == PT_INTERP).map(|s| {
        let path = s.file.split(|b| *b == 0).next().unwrap_or_default();
        String::from_utf8_lossy(path).into_owned()
    });
    let entries = || {
        let sections = segments.iter().filter(|s| s.kind == PT_DYNAMIC);
        sections.flat_map(|s| dynamic(s.file))
    };
    let library = entries().any(|(tag, _)| tag == DT_SONAME);
    let pie = entries().any(|(tag, value)| tag == DT_FLAGS_1 && value & DF_1_PIE != 0);
    if kind == ET_DYN && (library || (interpreter.is_none() && !pie)) {
        return Err(NotAProgram::SharedLibrary);
    }
    let libc = match (interpreter, machine.loaders()) {
        (None, _) => Libc::Static,
        (Some(path), Some((glibc, _))) if path == glibc => Libc::Glibc(newest_glibc(bytes)),
        (Some(path), Some((_, musl))) if path == musl => Libc::Musl,
        (Some(path), _) => Libc::Other(
            path.chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
        ),
    };
    Ok(Elf { machine, libc })
}

/// The newest `GLIBC_<major>.<minor>` a binary names. The names are in its
/// dynamic string table, one for each version of glibc a symbol it uses
/// came in; the newest is the oldest glibc it runs on.
fn newest_glibc(bytes: &[u8]) -> Option<(u32, u32)> {
    const NAME: &[u8] = b"GLIBC_";
    let number = |digits: &[u8]| -> Option<(u32, usize)> {
        let length = digits.iter().take_while(|b| b.is_ascii_digit()).count();
        // A version is a few digits: more is not one.
        if length == 0 || length > 4 {
            return None;
        }
        let text = std::str::from_utf8(&digits[..length]).ok()?;
        Some((text.parse().ok()?, length))
    };
    let mut newest = None;
    let mut rest = bytes;
    while let Some(at) = rest.windows(NAME.len()).position(|w| w == NAME) {
        rest = &rest[at + NAME.len()..];
        let Some((major, used)) = number(rest) else {
            continue;
        };
        if rest.get(used) != Some(&b'.') {
            continue;
        }
        let Some((minor, _)) = number(&rest[used + 1..]) else {
            continue;
        };
        if newest.is_none_or(|n| (major, minor) > n) {
            newest = Some((major, minor));
        }
    }
    newest
}

/// ELF files made for tests, here and where a binary is checked for the
/// servers: small, and the same on every machine the tests run on.
#[cfg(test)]
pub(crate) mod fixture {
    use super::{ET_DYN, PT_DYNAMIC, PT_INTERP, PT_LOAD};

    pub(crate) const X86_64: u16 = 62;
    pub(crate) const AARCH64: u16 = 183;
    pub(crate) const GLIBC_X86_64: &str = "/lib64/ld-linux-x86-64.so.2";

    /// A 64-bit little-endian ELF file as a linker lays one out: the
    /// header, a program header for what is loaded (the whole file), one
    /// for the loader `interpreter` names (none: static) and one for the
    /// dynamic section when it has `dynamic` entries, then those and
    /// `strings`.
    pub(crate) fn elf(
        kind: u16,
        machine: u16,
        interpreter: Option<&str>,
        dynamic: &[(u64, u64)],
        strings: &[u8],
    ) -> Vec<u8> {
        let interp = interpreter.map_or_else(Vec::new, |path| [path.as_bytes(), &[0]].concat());
        let dynamic: Vec<u8> = dynamic
            .iter()
            .chain(&[(0, 0)])
            .filter(|_| !dynamic.is_empty())
            .flat_map(|(tag, value)| [tag.to_le_bytes(), value.to_le_bytes()].concat())
            .collect();
        let parts = [(PT_INTERP, &interp), (PT_DYNAMIC, &dynamic)];
        let headers = 1 + parts.iter().filter(|(_, part)| !part.is_empty()).count();
        let mut at = 64 + 56 * headers;
        let total = at + interp.len() + dynamic.len() + strings.len();
        let header = |kind: u32, start: usize, length: usize| {
            let mut header = vec![0_u8; 56];
            header[..4].copy_from_slice(&kind.to_le_bytes());
            header[8..16].copy_from_slice(&(start as u64).to_le_bytes());
            header[32..40].copy_from_slice(&(length as u64).to_le_bytes());
            header
        };
        let mut file = vec![0_u8; 64];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2; // 64-bit
        file[5] = 1; // little-endian
        file[16..18].copy_from_slice(&kind.to_le_bytes());
        file[18..20].copy_from_slice(&machine.to_le_bytes());
        file[32..40].copy_from_slice(&64_u64.to_le_bytes()); // program headers
        file[54..56].copy_from_slice(&56_u16.to_le_bytes());
        file[56..58].copy_from_slice(&u16::try_from(headers).expect("few").to_le_bytes());
        file.extend(header(PT_LOAD, 0, total));
        for (kind, part) in parts {
            if !part.is_empty() {
                file.extend(header(kind, at, part.len()));
                at += part.len();
            }
        }
        file.extend(interp);
        file.extend(dynamic);
        file.extend(strings);
        assert_eq!(file.len(), total);
        file
    }

    /// A program linked against the loader at `interpreter`.
    pub(crate) fn linked(machine: u16, interpreter: &str, strings: &[u8]) -> Vec<u8> {
        elf(ET_DYN, machine, Some(interpreter), &[(1, 1)], strings)
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{AARCH64, GLIBC_X86_64, X86_64, elf, linked};
    use super::{
        DF_1_PIE, DT_FLAGS_1, DT_SONAME, ET_DYN, ET_EXEC, Elf, Libc, Machine, NotAProgram, inspect,
    };

    #[test]
    fn a_glibc_binary_says_its_machine_and_the_newest_glibc_it_asks_for() {
        let read = inspect(&linked(
            X86_64,
            GLIBC_X86_64,
            b"\0GLIBC_2.2.5\0GLIBC_2.39\0GLIBC_2.17\0GLIBCXX_3.4\0GLIBC_PRIVATE\0",
        ))
        .expect("an ELF");
        assert_eq!(
            read,
            Elf {
                machine: Machine::X86_64,
                libc: Libc::Glibc(Some((2, 39))),
            }
        );
        assert_eq!(read.glibc().as_deref(), Some("2.39"));
        let arm = inspect(&linked(AARCH64, "/lib/ld-linux-aarch64.so.1", b"")).expect("an ELF");
        assert_eq!(arm.machine, Machine::Aarch64);
        assert_eq!(arm.libc, Libc::Glibc(None), "no version named");
        assert_eq!(arm.glibc(), None);
        // Not position-independent: a program all the same.
        let fixed = elf(ET_EXEC, X86_64, Some(GLIBC_X86_64), &[], b"GLIBC_2.31");
        assert_eq!(
            inspect(&fixed).expect("an ELF").libc,
            Libc::Glibc(Some((2, 31)))
        );
    }

    #[test]
    fn a_static_or_musl_binary_asks_for_no_glibc() {
        // GLIBC_ in the strings of a static binary is text, not a need.
        let fixed = inspect(&elf(ET_EXEC, X86_64, None, &[], b"GLIBC_2.99")).expect("an ELF");
        assert_eq!(fixed.libc, Libc::Static);
        assert_eq!(fixed.glibc(), None);
        // Static and position-independent: its dynamic section says it
        // is an executable.
        let pie = elf(ET_DYN, AARCH64, None, &[(DT_FLAGS_1, DF_1_PIE | 1)], b"");
        assert_eq!(inspect(&pie).expect("an ELF").libc, Libc::Static);
        let musl = inspect(&linked(X86_64, "/lib/ld-musl-x86_64.so.1", b"")).expect("an ELF");
        assert_eq!(musl.libc, Libc::Musl);
        let musl = inspect(&linked(AARCH64, "/lib/ld-musl-aarch64.so.1", b"")).expect("an ELF");
        assert_eq!(musl.libc, Libc::Musl);
    }

    #[test]
    fn a_loader_is_glibcs_or_musls_only_at_its_own_path() {
        // A loader that only holds the name, one from another store, the
        // other machine's, and one of neither kind: a server has none.
        for (machine, path) in [
            (X86_64, "/opt/loader"),
            (X86_64, "/tmp/ld-linux-x86-64.so.2"),
            (X86_64, "/store/glibc-2.39/lib64/ld-linux-x86-64.so.2"),
            (X86_64, "/lib64/ld-linux-x86-64.so.2.bak"),
            (X86_64, "/lib/ld-musl-x86_64.so.1/../evil"),
            (X86_64, "/lib/ld-linux-aarch64.so.1"),
            (AARCH64, GLIBC_X86_64),
            (AARCH64, "/lib/ld-musl-x86_64.so.1"),
            (X86_64, "/lib64/ld64.so.2"),
            (X86_64, ""),
        ] {
            let read = inspect(&linked(machine, path, b"GLIBC_2.39")).expect("an ELF");
            assert_eq!(read.libc, Libc::Other(path.to_owned()), "{path}");
            assert_eq!(read.glibc(), None, "{path}");
        }
        // Its path is the file's own bytes: said without what a terminal
        // would act on.
        let odd = inspect(&linked(X86_64, "/lib/\u{1b}[2Jld", b"")).expect("an ELF");
        assert_eq!(odd.libc, Libc::Other("/lib/?[2Jld".to_owned()));
        // Another machine's binary is read, for the build to refuse.
        let other = inspect(&linked(8, GLIBC_X86_64, b"")).expect("an ELF");
        assert_eq!(other.machine, Machine::Other(8));
        assert_eq!(other.libc, Libc::Other(GLIBC_X86_64.to_owned()));
    }

    #[test]
    fn a_shared_library_is_not_a_program() {
        let library = |bytes: &[u8]| inspect(bytes) == Err(NotAProgram::SharedLibrary);
        // Position-independent with no loader and no word that it is an
        // executable: a library, as cargo builds a cdylib.
        assert!(library(&elf(ET_DYN, X86_64, None, &[(1, 1)], b"")));
        assert!(library(&elf(ET_DYN, X86_64, None, &[], b"")));
        let flagged = elf(ET_DYN, X86_64, None, &[(DT_FLAGS_1, 1)], b"");
        assert!(library(&flagged), "not the flag of an executable");
        // One that gives itself a library's name is one, loader or not.
        let named = [(DT_SONAME, 1), (DT_FLAGS_1, DF_1_PIE)];
        assert!(library(&elf(
            ET_DYN,
            X86_64,
            Some(GLIBC_X86_64),
            &named,
            b""
        )));
        assert!(library(&elf(ET_DYN, X86_64, None, &named, b"")));
        // What follows the end mark of the dynamic section is not read.
        let mut after = elf(ET_DYN, X86_64, Some(GLIBC_X86_64), &[(1, 1)], b"");
        after.extend([DT_SONAME.to_le_bytes(), 1_u64.to_le_bytes()].concat());
        assert!(inspect(&after).is_ok());
    }

    #[test]
    fn what_is_not_a_linux_program_is_said_for_what_it_is() {
        let said = |bytes: &[u8]| inspect(bytes).expect_err("refused");
        assert_eq!(said(b"#!/bin/sh\necho hi\n"), NotAProgram::Script);
        assert_eq!(
            said(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
            NotAProgram::MacOs
        );
        assert_eq!(said(b"MZ\x90\0"), NotAProgram::Windows);
        assert_eq!(said(b""), NotAProgram::NotElf);
        assert_eq!(said(b"just some text"), NotAProgram::NotElf);
        let mut narrow = elf(ET_EXEC, X86_64, None, &[], b"");
        narrow[4] = 1;
        assert_eq!(said(&narrow), NotAProgram::Bits32);
        let mut big = elf(ET_EXEC, X86_64, None, &[], b"");
        big[5] = 2;
        assert_eq!(said(&big), NotAProgram::BigEndian);
        let mut object = elf(ET_EXEC, X86_64, None, &[], b"");
        object[16] = 1; // ET_REL
        assert_eq!(said(&object), NotAProgram::NotExecutable);
        let mut nothing = elf(ET_EXEC, X86_64, None, &[], b"");
        nothing[56..58].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(said(&nothing), NotAProgram::NothingToLoad);
    }

    /// What the review found: a glibc binary cut short was read as one
    /// that names no loader, and so as static, and shipped.
    #[test]
    fn a_file_shorter_than_its_header_says_is_refused_not_called_static() {
        let cut = |bytes: &[u8]| assert_eq!(inspect(bytes), Err(NotAProgram::CutShort));
        let whole = linked(X86_64, GLIBC_X86_64, b"\0GLIBC_2.39\0");
        assert!(inspect(&whole).is_ok());
        // Cut anywhere: in the header, in the program headers, in the
        // loader's path, in what is loaded.
        let last = whole.len() - 1;
        for length in [4, 5, 20, 63, 64, 100, 64 + 56 * 3, last - 30, last] {
            cut(&whole[..length]);
        }
        // Offsets that point past the end, or cannot be added to.
        let mut far = whole.clone();
        far[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        cut(&far);
        let mut long = whole.clone();
        long[64 + 56 + 32..64 + 56 + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        cut(&long);
        let mut many = whole.clone();
        many[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        cut(&many);
        let mut thin = whole.clone();
        thin[54..56].copy_from_slice(&8_u16.to_le_bytes());
        cut(&thin);
    }

    /// The bytes may be anything: every byte of a file set to each of a
    /// few values is read to an answer, never to a panic.
    #[test]
    fn a_damaged_file_is_read_to_an_answer() {
        let whole = elf(
            ET_DYN,
            X86_64,
            Some(GLIBC_X86_64),
            &[(DT_FLAGS_1, DF_1_PIE), (1, 1)],
            b"\0GLIBC_2.39\0",
        );
        for at in 0..whole.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut damaged = whole.clone();
                damaged[at] = value;
                let _ = inspect(&damaged);
                let _ = inspect(&damaged[..at]);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_test_binary_itself_reads_as_this_machine() {
        let own = std::fs::read(std::env::current_exe().expect("exe")).expect("readable");
        let read = inspect(&own).expect("an ELF");
        assert_eq!(read.machine.arch(), std::env::consts::ARCH);
        assert_eq!(Machine::Other(8).arch(), "ELF machine 8");
        // Cut where the review cut one, and inside what is loaded:
        // refused, where it used to be shipped as static.
        for length in [600, 4096] {
            assert_eq!(inspect(&own[..length]), Err(NotAProgram::CutShort));
        }
    }
}
