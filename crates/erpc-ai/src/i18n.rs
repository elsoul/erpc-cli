// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What the assistant's console says to the person, in their language.
//!
//! The words live in `crates/erpc-ai/locales/<code>/<area>.toml`, read the
//! same way as erpc's (see `crates/erpc/locales/README.md`). They are what
//! the person is shown: confirmations, the labels of running tools and
//! errors. What the model is sent (the system prompt, the tools and their
//! results) stays English: the model answers in the person's language by
//! itself.

use std::sync::LazyLock;

use erpc_core::i18n::{Catalog, Lang};
use include_dir::{Dir, include_dir};

static LOCALES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/locales");

/// Every message of this crate, in every language.
pub(crate) static CATALOG: LazyLock<Catalog> =
    LazyLock::new(|| Catalog::parse(files(&LOCALES)).unwrap_or_default());

fn files(dir: &'static Dir<'static>) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    for entry in dir.entries() {
        if let Some(d) = entry.as_dir() {
            out.extend(files(d));
        } else if let Some((path, text)) = entry
            .as_file()
            .and_then(|f| Some((f.path().to_str()?, f.contents_utf8()?)))
        {
            out.push((path, text));
        }
    }
    out
}

/// The language a message is said in: the run's, or in a test English
/// unless [`speaking`] says otherwise, whatever the machine's locale.
pub(crate) fn lang() -> Lang {
    #[cfg(test)]
    {
        SPEAKING.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        erpc_core::i18n::current()
    }
}

#[cfg(test)]
thread_local! {
    static SPEAKING: std::cell::Cell<Lang> = const { std::cell::Cell::new(Lang::En) };
}

/// In a test: runs `f` with this thread's messages in `lang`.
#[cfg(test)]
pub(crate) fn speaking<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let before = SPEAKING.with(|s| s.replace(lang));
    let out = f();
    SPEAKING.with(|s| s.set(before));
    out
}

/// A message in the language of this run: `t!("confirm.start.title",
/// product)`, an argument by itself standing for `name = name`.
macro_rules! t {
    ($key:literal $(, $name:ident $(= $value:expr)?)* $(,)?) => {
        $crate::i18n::CATALOG.text(
            $crate::i18n::lang(),
            $key,
            &[$((stringify!($name), &$crate::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
        )
    };
}

/// A message whose words follow the count `n`, which it can show as `{n}`.
#[allow(unused_macros)]
macro_rules! tn {
    ($key:literal, $n:expr $(, $name:ident $(= $value:expr)?)* $(,)?) => {
        $crate::i18n::CATALOG.plural(
            $crate::i18n::lang(),
            $key,
            u64::try_from($n).unwrap_or(u64::MAX),
            &[$((stringify!($name), &$crate::i18n::arg!($name $(= $value)?) as &dyn ::std::fmt::Display)),*],
        )
    };
}

macro_rules! arg {
    ($name:ident) => {
        $name
    };
    ($name:ident = $value:expr) => {
        $value
    };
}

#[allow(unused_imports)]
pub(crate) use {arg, t, tn};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogs_read_and_every_language_says_everything() {
        let catalog = Catalog::parse(files(&LOCALES)).expect("the catalogs read");
        let problems = catalog.problems();
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// Every `t!`/`tn!` key in the source is in the English catalog, and
    /// every English key is said somewhere, so neither side drifts. A
    /// running tool's label is looked up by the tool's name, so every tool
    /// has one and every label is a tool's.
    #[test]
    fn the_source_and_the_catalogs_name_the_same_keys() {
        let mut used = std::collections::BTreeSet::new();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        collect_keys(&src, &mut used);
        used.extend(crate::tools::names().map(|n| format!("tools.{n}")));
        used.insert(crate::tools::UNKNOWN_LABEL.to_owned());
        let missing: Vec<&String> = used.iter().filter(|k| !CATALOG.has(k)).collect();
        assert!(missing.is_empty(), "used but not in en/: {missing:?}");
        let unused: Vec<&str> = CATALOG.keys().filter(|k| !used.contains(*k)).collect();
        assert!(unused.is_empty(), "in en/ but never used: {unused:?}");
    }

    fn collect_keys(dir: &std::path::Path, out: &mut std::collections::BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_keys(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                // rustfmt may put the key on the line after `t!(`.
                for marker in ["t!(", "tn!("] {
                    for (at, _) in text.match_indices(marker) {
                        let line = text[..at].rsplit('\n').next().unwrap_or_default();
                        if line.trim_start().starts_with("//") {
                            continue;
                        }
                        let before = text[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                            continue;
                        }
                        let Some(rest) = text[at + marker.len()..].trim_start().strip_prefix('"')
                        else {
                            continue;
                        };
                        let key = rest.split('"').next().unwrap_or_default();
                        if !key.is_empty()
                            && key
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || "._0123456789".contains(c))
                        {
                            out.insert(key.to_owned());
                        }
                    }
                }
            }
        }
    }
}
