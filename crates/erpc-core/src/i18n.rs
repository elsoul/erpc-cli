// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The language erpc speaks, and the words it says in each.
//!
//! A crate that has words to say keeps them in `locales/<code>/<area>.toml`,
//! one directory per language, and embeds the tree into a [`Catalog`]. A
//! key is the file's stem and the key inside it: `deploy.done` in
//! `worker.toml` is `worker.deploy.done`. A message is a string with
//! `{name}` placeholders (`{{` and `}}` for braces), or a table of plural
//! forms (`one`, `few`, `many`, `other`) chosen by the count `{n}`.
//!
//! English is the source: every language has every key English has, the
//! same placeholders, and the plural forms its rule asks for, which
//! [`Catalog::problems`] checks. A word that is still missing in a language
//! falls back to English, never to nothing.
//!
//! Adding a language is a directory of catalogs and a variant here, with
//! its code, its name and its plural rule.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Write as _};
use std::sync::OnceLock;

/// A language erpc can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Lang {
    /// English, the source every other language is translated from.
    #[default]
    En,
    /// Japanese.
    Ja,
    /// Simplified Chinese.
    Zh,
    /// Russian.
    Ru,
}

/// Which plural form a count takes, as CLDR names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plural {
    /// One (1 in English; 1, 21, 31 in Russian).
    One,
    /// A few (2-4, 22-24 in Russian).
    Few,
    /// Many (5-20, 25-30 in Russian).
    Many,
    /// Everything else, and the only form Japanese and Chinese have.
    Other,
}

impl Plural {
    const fn name(self) -> &'static str {
        match self {
            Self::One => "one",
            Self::Few => "few",
            Self::Many => "many",
            Self::Other => "other",
        }
    }
}

impl Lang {
    /// Every language, English first.
    pub const ALL: [Self; 4] = [Self::En, Self::Ja, Self::Zh, Self::Ru];

    /// The code its catalogs and settings use: `en`, `ja`, `zh`, `ru`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ja => "ja",
            Self::Zh => "zh",
            Self::Ru => "ru",
        }
    }

    /// Its name, in itself.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ja => "日本語",
            Self::Zh => "简体中文",
            Self::Ru => "Русский",
        }
    }

    /// The language a code or a locale names: `ja`, `ja_JP.UTF-8`,
    /// `zh-Hans-CN`, `ru-RU`. Chinese in any script is Simplified Chinese
    /// until Traditional has catalogs of its own.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        let primary = tag
            .split(['_', '-', '.', '@'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        Self::ALL.into_iter().find(|l| l.code() == primary)
    }

    /// The plural forms this language has, for whole counts.
    #[must_use]
    pub const fn plural_forms(self) -> &'static [Plural] {
        match self {
            Self::En => &[Plural::One, Plural::Other],
            Self::Ja | Self::Zh => &[Plural::Other],
            Self::Ru => &[Plural::One, Plural::Few, Plural::Many],
        }
    }

    /// The plural form `n` takes.
    #[must_use]
    pub const fn plural(self, n: u64) -> Plural {
        match self {
            Self::En => {
                if n == 1 {
                    Plural::One
                } else {
                    Plural::Other
                }
            }
            Self::Ja | Self::Zh => Plural::Other,
            Self::Ru => {
                let (ten, hundred) = (n % 10, n % 100);
                if ten == 1 && hundred != 11 {
                    Plural::One
                } else if ten >= 2 && ten <= 4 && !(hundred >= 12 && hundred <= 14) {
                    Plural::Few
                } else {
                    Plural::Many
                }
            }
        }
    }
}

static CURRENT: OnceLock<Lang> = OnceLock::new();

/// Sets the language for the rest of the run. The first call wins; later
/// ones, and a [`current`] that came first, keep the language as it was.
pub fn set_current(lang: Lang) {
    let _ = CURRENT.set(lang);
}

/// The language this run speaks: what [`set_current`] chose, else what the
/// environment says.
#[must_use]
pub fn current() -> Lang {
    *CURRENT.get_or_init(|| resolve(None, None, |name| std::env::var(name).ok()))
}

/// Where the language comes from, first match wins:
///
/// 1. `flag` (`--lang`), then `ERPC_LANG`, then `configured` (the
///    `locale` setting), each skipped when it names no language erpc has;
/// 2. the system's locale: the first of `LANGUAGE`'s list erpc has, then
///    the first of `LC_ALL`, `LC_MESSAGES`, `LANG` that is set, which is
///    English when it is `C`, `POSIX` or a language erpc does not have;
/// 3. on macOS, the first preferred language in System Settings, for a terminal that
///    sets none of those;
/// 4. English.
#[must_use]
pub fn resolve(
    flag: Option<&str>,
    configured: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Lang {
    let chosen = [
        flag.map(str::to_owned),
        env("ERPC_LANG"),
        configured.map(str::to_owned),
    ];
    if let Some(lang) = chosen.iter().flatten().find_map(|t| Lang::from_tag(t)) {
        return lang;
    }
    if let Some(lang) = env("LANGUAGE")
        .filter(|_| !system_is_c(&env))
        .and_then(|list| list.split(':').find_map(Lang::from_tag))
    {
        return lang;
    }
    if let Some(tag) = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|name| env(name).filter(|v| !v.is_empty()))
    {
        return Lang::from_tag(&tag).unwrap_or_default();
    }
    system_locale()
        .as_deref()
        .and_then(Lang::from_tag)
        .unwrap_or_default()
}

/// Whether the locale is `C` or `POSIX`, which turns `LANGUAGE` off as it
/// does for gettext.
fn system_is_c(env: &impl Fn(&str) -> Option<String>) -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|name| env(name).filter(|v| !v.is_empty()))
        .is_some_and(|v| v == "C" || v == "POSIX" || v.starts_with("C."))
}

/// The first language in macOS's preferred list, which a terminal started
/// outside Terminal.app may not pass on in `LANG`.
#[cfg(target_os = "macos")]
fn system_locale() -> Option<String> {
    let out = std::process::Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLanguages"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    first_apple_language(&String::from_utf8_lossy(&out.stdout))
}

/// The first entry of `defaults read -g AppleLanguages`, a list printed as
/// `( "en-NL", "ja-JP" )` or `( en, ja )`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn first_apple_language(list: &str) -> Option<String> {
    list.trim()
        .trim_start_matches('(')
        .split([',', ')'])
        .map(|item| item.trim().trim_matches('"'))
        .find(|item| !item.is_empty())
        .map(str::to_owned)
}

#[cfg(not(target_os = "macos"))]
const fn system_locale() -> Option<String> {
    None
}

/// One message in one language.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Message {
    Text(String),
    Plural(BTreeMap<&'static str, String>),
}

/// Every message of a crate, in every language.
#[derive(Debug, Default)]
pub struct Catalog {
    langs: BTreeMap<Lang, BTreeMap<String, Message>>,
}

/// An argument a message is filled in with.
pub type Arg<'a> = (&'a str, &'a dyn Display);

impl Catalog {
    /// Reads catalogs from `(path, contents)` pairs, `path` being
    /// `<code>/<area>.toml` under the crate's `locales` directory. Files of
    /// a language erpc does not have, and files that are not TOML, are
    /// left out.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with a file that does not read as a catalog.
    pub fn parse<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Self, String> {
        let mut catalog = Self::default();
        for (path, contents) in files {
            let path = path.replace('\\', "/");
            let Some((code, file)) = path.split_once('/') else {
                continue;
            };
            let Some(area) = file.strip_suffix(".toml") else {
                continue;
            };
            let Some(lang) = Lang::ALL.into_iter().find(|l| l.code() == code) else {
                continue;
            };
            let table: toml::Table =
                toml::from_str(contents).map_err(|e| format!("{path}: {e}"))?;
            let messages = catalog.langs.entry(lang).or_default();
            flatten(area, &table, messages).map_err(|e| format!("{path}: {e}"))?;
        }
        Ok(catalog)
    }

    /// `key` in `lang`, filled in with `args`; English when `lang` lacks
    /// it, and the key itself when English does too.
    #[must_use]
    pub fn text(&self, lang: Lang, key: &str, args: &[Arg<'_>]) -> String {
        match self.find(lang, key) {
            Some((_, Message::Text(text))) => fill(text, args),
            Some((found, Message::Plural(forms))) => {
                fill(pick(forms, found.plural(0)).unwrap_or(key), args)
            }
            None => key.to_owned(),
        }
    }

    /// `key` in `lang` in the plural form `n` takes, with `n` as `{n}`
    /// besides `args`.
    #[must_use]
    pub fn plural(&self, lang: Lang, key: &str, n: u64, args: &[Arg<'_>]) -> String {
        let mut all: Vec<Arg<'_>> = vec![("n", &n)];
        all.extend_from_slice(args);
        match self.find(lang, key) {
            Some((_, Message::Text(text))) => fill(text, &all),
            Some((found, Message::Plural(forms))) => {
                fill(pick(forms, found.plural(n)).unwrap_or(key), &all)
            }
            None => key.to_owned(),
        }
    }

    /// Whether `key` is a message in English.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.langs
            .get(&Lang::En)
            .is_some_and(|m| m.contains_key(key))
    }

    /// The English keys.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.langs
            .get(&Lang::En)
            .into_iter()
            .flat_map(|m| m.keys().map(String::as_str))
    }

    /// The message `key` names in `lang` without falling back, for a
    /// caller that has words of its own when a language has none.
    #[must_use]
    pub fn get(&self, lang: Lang, key: &str, args: &[Arg<'_>]) -> Option<String> {
        match self.langs.get(&lang)?.get(key)? {
            Message::Text(text) => Some(fill(text, args)),
            Message::Plural(_) => None,
        }
    }

    /// Everything that keeps the catalogs from being complete: a key a
    /// language lacks or English does not have, placeholders that differ
    /// from English, a plural form a language's rule needs and its message
    /// does not give. Empty when every language says everything.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let empty = BTreeMap::new();
        let english = self.langs.get(&Lang::En).unwrap_or(&empty);
        let mut problems = Vec::new();
        for lang in Lang::ALL {
            let messages = self.langs.get(&lang).unwrap_or(&empty);
            let code = lang.code();
            for (key, source) in english {
                let Some(message) = messages.get(key) else {
                    problems.push(format!("{code}: {key} is missing"));
                    continue;
                };
                let want = placeholders_of(source);
                let got = placeholders_of(message);
                if want != got {
                    problems.push(format!(
                        "{code}: {key} has placeholders {got:?}, English has {want:?}"
                    ));
                }
                match (source, message) {
                    (Message::Text(_), Message::Plural(_)) => {
                        problems.push(format!("{code}: {key} has plural forms, English has none"));
                    }
                    (Message::Plural(_), Message::Text(_)) => {
                        problems.push(format!("{code}: {key} has no plural forms, English has"));
                    }
                    (_, Message::Plural(forms)) => {
                        for form in lang.plural_forms() {
                            if !forms.contains_key(form.name()) && !forms.contains_key("other") {
                                problems.push(format!(
                                    "{code}: {key} lacks the plural form {}",
                                    form.name()
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for key in messages.keys().filter(|k| !english.contains_key(*k)) {
                problems.push(format!("{code}: {key} is not an English key"));
            }
        }
        problems
    }

    fn find(&self, lang: Lang, key: &str) -> Option<(Lang, &Message)> {
        [lang, Lang::En]
            .into_iter()
            .find_map(|l| self.langs.get(&l)?.get(key).map(|m| (l, m)))
    }
}

fn pick<'a>(forms: &'a BTreeMap<&'static str, String>, form: Plural) -> Option<&'a str> {
    forms
        .get(form.name())
        .or_else(|| forms.get("other"))
        .or_else(|| forms.values().next())
        .map(String::as_str)
}

const FORMS: [Plural; 4] = [Plural::One, Plural::Few, Plural::Many, Plural::Other];

fn flatten(
    prefix: &str,
    table: &toml::Table,
    out: &mut BTreeMap<String, Message>,
) -> Result<(), String> {
    for (name, value) in table {
        let key = format!("{prefix}.{name}");
        match value {
            toml::Value::String(text) => {
                out.insert(key, Message::Text(text.clone()));
            }
            toml::Value::Table(inner)
                if !inner.is_empty()
                    && inner.iter().all(|(k, v)| {
                        v.is_str() && FORMS.iter().any(|f| f.name() == k.as_str())
                    }) =>
            {
                let forms = FORMS
                    .iter()
                    .filter_map(|f| {
                        inner
                            .get(f.name())
                            .and_then(toml::Value::as_str)
                            .map(|s| (f.name(), s.to_owned()))
                    })
                    .collect();
                out.insert(key, Message::Plural(forms));
            }
            toml::Value::Table(inner) => flatten(&key, inner, out)?,
            other => return Err(format!("{key} is a {}, not a string", other.type_str())),
        }
    }
    Ok(())
}

/// The placeholders a message uses, across its plural forms.
fn placeholders_of(message: &Message) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    match message {
        Message::Text(text) => placeholders(text, &mut names),
        Message::Plural(forms) => {
            for text in forms.values() {
                placeholders(text, &mut names);
            }
            // A form may leave the count out ("one file" for 1).
            names.remove("n");
        }
    }
    names
}

fn placeholders(text: &str, names: &mut BTreeSet<String>) {
    let mut rest = text;
    while let Some(at) = rest.find('{') {
        rest = &rest[at + 1..];
        if let Some(after) = rest.strip_prefix('{') {
            rest = after;
            continue;
        }
        if let Some(end) = rest.find('}') {
            names.insert(rest[..end].to_owned());
            rest = &rest[end + 1..];
        }
    }
}

/// `text` with each `{name}` replaced by its argument; a placeholder with
/// no argument is left as it is, where a test sees it.
fn fill(text: &str, args: &[Arg<'_>]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '{' if chars.peek().is_some_and(|(_, n)| *n == '{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek().is_some_and(|(_, n)| *n == '}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let rest = &text[at + 1..];
                let Some(end) = rest.find('}') else {
                    out.push('{');
                    continue;
                };
                let name = &rest[..end];
                if let Some((_, value)) = args.iter().find(|(n, _)| *n == name) {
                    let _ = write!(out, "{value}");
                } else {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
                for _ in 0..=name.chars().count() {
                    chars.next();
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The placeholders `text` would leave unfilled with `args`, for tests.
#[must_use]
pub fn unfilled(text: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    placeholders(text, &mut names);
    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn a_locale_names_its_language() {
        assert_eq!(Lang::from_tag("ja_JP.UTF-8"), Some(Lang::Ja));
        assert_eq!(Lang::from_tag("zh-Hans-CN"), Some(Lang::Zh));
        assert_eq!(Lang::from_tag("zh_TW"), Some(Lang::Zh));
        assert_eq!(Lang::from_tag("RU"), Some(Lang::Ru));
        assert_eq!(Lang::from_tag("en_US"), Some(Lang::En));
        assert_eq!(Lang::from_tag("fr_FR"), None);
        assert_eq!(Lang::from_tag("C"), None);
    }

    #[test]
    fn the_flag_then_erpc_lang_then_the_setting_then_the_system() {
        let system = env(&[("LANG", "ru_RU.UTF-8"), ("ERPC_LANG", "zh")]);
        assert_eq!(resolve(Some("ja"), Some("en"), &system), Lang::Ja);
        assert_eq!(resolve(None, Some("en"), &system), Lang::Zh);
        assert_eq!(
            resolve(None, Some("en"), env(&[("LANG", "ru_RU")])),
            Lang::En
        );
        assert_eq!(resolve(None, None, env(&[("LANG", "ru_RU")])), Lang::Ru);
        // A choice erpc cannot honour does not hide the next one.
        assert_eq!(resolve(Some("fr"), Some("ja"), env(&[])), Lang::Ja);
    }

    #[test]
    fn the_system_locale_follows_gettext() {
        let both = env(&[("LANGUAGE", "fr:ja"), ("LANG", "ru_RU")]);
        assert_eq!(resolve(None, None, both), Lang::Ja);
        let c = env(&[("LANGUAGE", "ja"), ("LC_ALL", "C")]);
        assert_eq!(resolve(None, None, c), Lang::En);
        let all = env(&[("LC_ALL", "fr_FR.UTF-8"), ("LANG", "ja_JP.UTF-8")]);
        assert_eq!(resolve(None, None, all), Lang::En);
        let messages = env(&[("LC_MESSAGES", "zh_CN.UTF-8"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(resolve(None, None, messages), Lang::Zh);
    }

    #[test]
    fn the_first_preferred_macos_language_is_read() {
        let printed = "(\n    \"ja-JP\",\n    \"en-NL\"\n)\n";
        assert_eq!(first_apple_language(printed).as_deref(), Some("ja-JP"));
        assert_eq!(
            first_apple_language("(\n    en,\n    ja\n)").as_deref(),
            Some("en")
        );
        assert_eq!(first_apple_language("(\n)"), None);
    }

    #[test]
    fn russian_counts_take_three_forms() {
        use Plural::{Few, Many, One};
        let forms: Vec<Plural> = [1, 2, 5, 11, 12, 21, 22, 25, 101, 111, 0]
            .into_iter()
            .map(|n| Lang::Ru.plural(n))
            .collect();
        assert_eq!(
            forms,
            [One, Few, Many, Many, Many, One, Few, Many, One, Many, Many]
        );
        assert_eq!(Lang::En.plural(1), Plural::One);
        assert_eq!(Lang::En.plural(0), Plural::Other);
        assert_eq!(Lang::Ja.plural(1), Plural::Other);
    }

    fn sample() -> Catalog {
        Catalog::parse([
            (
                "en/worker.toml",
                "done = \"Deployed {name} to {host}\"\nbrace = \"{{literal}} {x}\"\n\
                 [servers]\none = \"one server\"\nother = \"{n} servers\"\n\
                 [deploy]\nonly_en = \"only in English\"",
            ),
            (
                "ru/worker.toml",
                "done = \"{name} развёрнут на {host}\"\nbrace = \"{{буквально}} {x}\"\n\
                 [servers]\none = \"{n} сервер\"\nfew = \"{n} сервера\"\nmany = \"{n} серверов\"",
            ),
            (
                "ja/worker.toml",
                "done = \"{name} を {host} にデプロイしました\"",
            ),
            ("README.md", "not a catalog"),
            ("fr/worker.toml", "done = \"ignoré\""),
        ])
        .unwrap()
    }

    #[test]
    fn messages_are_filled_in_and_fall_back_to_english() {
        let c = sample();
        let args: [Arg<'_>; 2] = [("name", &"api"), ("host", &"vps-1")];
        assert_eq!(
            c.text(Lang::Ja, "worker.done", &args),
            "api を vps-1 にデプロイしました"
        );
        assert_eq!(
            c.text(Lang::Zh, "worker.done", &args),
            "Deployed api to vps-1"
        );
        assert_eq!(
            c.text(Lang::Ru, "worker.brace", &[("x", &1)]),
            "{буквально} 1"
        );
        assert_eq!(c.text(Lang::En, "worker.nope", &[]), "worker.nope");
        assert_eq!(
            c.text(Lang::En, "worker.done", &[]),
            "Deployed {name} to {host}"
        );
    }

    #[test]
    fn counts_choose_their_form() {
        let c = sample();
        assert_eq!(c.plural(Lang::En, "worker.servers", 1, &[]), "one server");
        assert_eq!(c.plural(Lang::En, "worker.servers", 3, &[]), "3 servers");
        assert_eq!(c.plural(Lang::Ru, "worker.servers", 3, &[]), "3 сервера");
        assert_eq!(c.plural(Lang::Ru, "worker.servers", 25, &[]), "25 серверов");
        assert_eq!(c.plural(Lang::Ja, "worker.servers", 25, &[]), "25 servers");
    }

    #[test]
    fn what_is_missing_is_named() {
        let problems = sample().problems();
        assert!(
            problems.contains(&"ja: worker.brace is missing".to_owned()),
            "{problems:?}"
        );
        assert!(
            problems.contains(&"zh: worker.done is missing".to_owned()),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .all(|p| !p.starts_with("ru: worker.servers")),
            "{problems:?}"
        );
        let broken = Catalog::parse([
            (
                "en/a.toml",
                "x = \"{n} {who}\"\n[c]\none = \"a\"\nother = \"{n} b\"",
            ),
            ("ja/a.toml", "x = \"{n}\"\nc = \"b\"\nextra = \"z\""),
        ])
        .unwrap();
        let problems = broken.problems();
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("ja: a.x has placeholders")),
            "{problems:?}"
        );
        assert!(problems.contains(&"ja: a.c has no plural forms, English has".to_owned()));
        assert!(problems.contains(&"ja: a.extra is not an English key".to_owned()));
    }

    #[test]
    fn a_broken_file_is_an_error() {
        assert!(Catalog::parse([("en/a.toml", "x = ")]).is_err());
        assert!(Catalog::parse([("en/a.toml", "x = 1")]).is_err());
    }
}
