// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The app templates `erpc worker init` makes an app from.
//!
//! They are compiled into the binary, so `init` fetches nothing: what it
//! writes is what was reviewed when this erpc was released, with its
//! dependencies pinned by `Cargo.lock` and every git dependency by commit.
//! Each lives under `templates/<chain>/<template>/`. A file whose name ends
//! in `.tmpl` has `{{name}}` and `{{template}}` filled in and loses the
//! suffix; `Cargo.toml` is kept as `Cargo.toml.tmpl` so that Cargo does not
//! take the template for a package of this workspace, or leave it out of
//! this crate's package. Every other file is copied as it is.
//!
//! Where the files came from, and what was changed, is in
//! `templates/PROVENANCE.md`.

use std::path::{Path, PathBuf};

use include_dir::{Dir, include_dir};

use crate::manifest::{self, Chain};

static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// One template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    /// The chain it is for.
    pub chain: Chain,
    /// Its name within the chain.
    pub id: &'static str,
    /// Its version. An app records it, so a later erpc knows what it was
    /// made from.
    pub version: u32,
    /// One line on what it is, for the picker.
    pub about: &'static str,
    /// The app name `init` gives an app made from it by its id.
    pub default_name: &'static str,
    /// Whether an app made from it trades with a key: `init` then names
    /// `erpc worker key new` among the next steps and warns about funds.
    pub wallet: bool,
    /// The secret settings that are tokens of the app's own, which nobody
    /// has to choose: `init` names `secret put --generate` for each.
    pub generated: &'static [&'static str],
}

/// The setting that holds the account's own RPC API key, in every
/// template that reads ERPC's shared RPC: `init` names
/// `secret put --from-account` for it.
pub const ACCOUNT_RPC_KEY: &str = "ERPC_API_KEY";

impl Template {
    /// The flag `erpc worker secret put` takes for `setting`, with its
    /// leading space, when the value need not be typed: made here, or read
    /// from the account. Empty for a secret the operator has to give.
    #[must_use]
    pub fn secret_flag(&self, setting: &str) -> &'static str {
        if self.generated.contains(&setting) {
            " --generate"
        } else if setting == ACCOUNT_RPC_KEY {
            " --from-account"
        } else {
            ""
        }
    }
}

/// Every template. The first is the one `init` makes when nobody is there
/// to pick and none is named.
pub const ALL: [Template; 2] = [
    Template {
        chain: Chain::Solana,
        id: "hello",
        version: 1,
        about: "Hello, World!: a small HTTP API in Rust, with no key, secret or data line to set \
                up first",
        default_name: "hello-world",
        wallet: false,
        generated: &[],
    },
    Template {
        chain: Chain::Solana,
        id: "pumpfun",
        version: 1,
        about: "pump.fun / PumpSwap auto-trader: watches new pools over Geyser gRPC, buys and \
                sells with a key erpc hands over on a pipe",
        default_name: "pumpfun-bot",
        wallet: true,
        // The bearer token the bot's own API asks for.
        generated: &["API_TOKEN"],
    },
];

/// One thing `init` offers to make, as the picker lists it. Several can
/// be made from one template until each has its own; one with no template
/// yet is listed as coming soon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    /// The chain it is for.
    pub chain: Chain,
    /// What the picker shows, and what `--template` takes.
    pub label: &'static str,
    /// One line on what it is.
    pub about: &'static str,
    /// The id of the template it is made from; `None` while it is coming
    /// soon.
    pub template: Option<&'static str>,
    /// The app name `init` gives it.
    pub default_name: &'static str,
}

/// Everything `init` offers, in the order the picker shows it: the one to
/// start from first.
pub const KINDS: [Kind; 4] = [
    Kind {
        chain: Chain::Solana,
        label: "HelloWorld",
        about: "a small HTTP API in Rust: nothing to set up, the place to start",
        template: Some("hello"),
        default_name: "hello-world",
    },
    Kind {
        chain: Chain::Solana,
        label: "HFT",
        about: "high-frequency trading bot, made from the pumpfun template for now",
        template: Some("pumpfun"),
        default_name: "hft-bot",
    },
    Kind {
        chain: Chain::Solana,
        label: "Stablecoin",
        about: "coming soon...",
        template: None,
        default_name: "stablecoin-app",
    },
    Kind {
        chain: Chain::Solana,
        label: "pumpfun-bot",
        about: "pump.fun / PumpSwap auto-trader over Geyser gRPC",
        template: Some("pumpfun"),
        default_name: "pumpfun-bot",
    },
];

impl Kind {
    /// The template it is made from, or why there is none yet.
    ///
    /// # Errors
    ///
    /// A message saying it is coming soon.
    pub fn template(&self) -> Result<Template, String> {
        match self.template {
            Some(id) => find(self.chain, id),
            None => Err(format!("{} is coming soon...", self.label)),
        }
    }
}

/// What `init` offers for `chain`.
#[must_use]
pub fn kinds_for(chain: Chain) -> Vec<Kind> {
    KINDS.into_iter().filter(|k| k.chain == chain).collect()
}

/// The kind `label` names for `chain`, in any case: `hft`, `HFT`.
#[must_use]
pub fn find_kind(chain: Chain, label: &str) -> Option<Kind> {
    kinds_for(chain)
        .into_iter()
        .find(|k| k.label.eq_ignore_ascii_case(label))
}

impl Template {
    /// How an app's `erpc.toml` names it: `solana/pumpfun@1`.
    #[must_use]
    pub fn tag(&self) -> String {
        format!("{}/{}@{}", self.chain, self.id, self.version)
    }

    fn dir(&self) -> Option<&'static Dir<'static>> {
        TEMPLATES.get_dir(format!("{}/{}", self.chain, self.id))
    }

    /// Every file of the app it makes for `name`: its path inside the app,
    /// and its contents.
    ///
    /// # Errors
    ///
    /// A message when `name` cannot name an app, or the template is not
    /// in this build.
    pub fn render(&self, name: &str) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
        if !manifest::is_slug(name, 32) {
            return Err(format!(
                "`{name}` cannot name an app: 1 to 32 lowercase letters, digits and single \
                 hyphens, starting with a letter"
            ));
        }
        let root = self
            .dir()
            .ok_or_else(|| format!("the {} template is not in this build", self.tag()))?;
        let tag = self.tag();
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            stack.extend(dir.dirs());
            for file in dir.files() {
                let inside = file
                    .path()
                    .strip_prefix(root.path())
                    .map_err(|e| e.to_string())?;
                let (path, contents) = match inside.to_str().and_then(|p| p.strip_suffix(".tmpl")) {
                    Some(plain) => {
                        let text = file
                            .contents_utf8()
                            .ok_or_else(|| format!("{} is not text", inside.display()))?;
                        let mut filled =
                            text.replace("{{name}}", name).replace("{{template}}", &tag);
                        if Path::new(plain)
                            .file_name()
                            .is_some_and(|f| f == "Cargo.lock")
                        {
                            filled = place_app_package(&filled, name);
                        }
                        (PathBuf::from(plain), filled.into_bytes())
                    }
                    None => (inside.to_owned(), file.contents().to_vec()),
                };
                out.push((path, contents));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Makes the app for `name` at `dest`, which must not exist yet.
    ///
    /// The files are written to a directory beside `dest` and it is renamed
    /// into place at the end, so a failure part way leaves nothing behind
    /// and an existing directory is never written into.
    ///
    /// # Errors
    ///
    /// A message when `dest` exists, its parent does not, or a file cannot
    /// be written.
    pub fn write(&self, name: &str, dest: &Path) -> Result<Vec<PathBuf>, String> {
        if dest.exists() {
            return Err(format!(
                "{} exists already; nothing was written",
                dest.display()
            ));
        }
        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            return Err(format!("{} is not a directory", parent.display()));
        }
        let files = self.render(name)?;
        let mut staging_name = dest.file_name().unwrap_or_default().to_os_string();
        staging_name.push(format!(".erpc-init-{}", std::process::id()));
        let staging = parent.join(staging_name);
        let written = (|| {
            for (path, contents) in &files {
                let target = staging.join(path);
                if let Some(dir) = target.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| format!("could not make {}: {e}", dir.display()))?;
                }
                std::fs::write(&target, contents)
                    .map_err(|e| format!("could not write {}: {e}", target.display()))?;
            }
            std::fs::rename(&staging, dest)
                .map_err(|e| format!("could not move the app to {}: {e}", dest.display()))
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        Ok(files.into_iter().map(|(path, _)| path).collect())
    }
}

/// Moves the app's own entry in a `Cargo.lock` to where Cargo sorts it.
///
/// The lock is written for the template's placeholder name, so with the
/// app's name filled in its entry is out of order, and the first build
/// would rewrite the file -- the same packages, moved -- leaving a new
/// app's repository changed by nothing the operator did. Cargo orders
/// packages by name; the app's entry is the one without a `source`.
fn place_app_package(lock: &str, name: &str) -> String {
    // Blocks are separated by a blank line. Without the file's final
    // newline every block ends the same way, wherever it goes; the newline
    // is put back at the end.
    const SEP: &str = "\n\n[[package]]\n";
    let (body, tail) = lock
        .strip_suffix('\n')
        .map_or((lock, ""), |body| (body, "\n"));
    let mut parts = body.split(SEP);
    let head = parts.next().unwrap_or_default();
    let mut packages: Vec<&str> = parts.collect();
    let package_name = |block: &str| {
        block
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("name = \""))
            .and_then(|l| l.strip_suffix('"'))
            .unwrap_or_default()
            .to_owned()
    };
    let is_app = |block: &str| {
        package_name(block) == name && !block.lines().any(|l| l.starts_with("source = "))
    };
    let Some(at) = packages.iter().position(|b| is_app(b)) else {
        return lock.to_owned();
    };
    let app = packages.remove(at);
    let to = packages
        .iter()
        .position(|b| package_name(b).as_str() > name)
        .unwrap_or(packages.len());
    packages.insert(to, app);
    let mut out = head.to_owned();
    for block in packages {
        out.push_str(SEP);
        out.push_str(block);
    }
    out.push_str(tail);
    out
}

/// The templates for `chain`.
#[must_use]
pub fn for_chain(chain: Chain) -> Vec<Template> {
    ALL.into_iter().filter(|t| t.chain == chain).collect()
}

/// The template called `id` (`pumpfun`, or `solana/pumpfun`) for `chain`.
///
/// # Errors
///
/// A message naming the templates there are.
pub fn find(chain: Chain, id: &str) -> Result<Template, String> {
    let bare = id
        .strip_prefix(chain.as_str())
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(id);
    for_chain(chain)
        .into_iter()
        .find(|t| t.id == bare)
        .ok_or_else(|| {
            let known: Vec<&str> = for_chain(chain).iter().map(|t| t.id).collect();
            format!(
                "there is no {chain} template `{id}`; there is {}",
                known.join(", ")
            )
        })
}

/// The template an app's `erpc.toml` names (`solana/pumpfun@1`), when this
/// erpc has it; `None` for an app made by hand or from a template this
/// build does not carry.
#[must_use]
pub fn of_tag(tag: &str) -> Option<Template> {
    let (id, _version) = tag.rsplit_once('@').unwrap_or((tag, ""));
    ALL.into_iter()
        .find(|t| id == format!("{}/{}", t.chain, t.id))
}

#[cfg(test)]
mod tests {
    use super::{ALL, KINDS, find, find_kind, of_tag};
    use crate::manifest::{Chain, Manifest};

    #[test]
    fn every_kind_is_made_from_a_template_there_is_or_is_coming_soon() {
        for kind in KINDS {
            if kind.template.is_some() {
                assert!(kind.template().is_ok(), "{}", kind.label);
            } else {
                let soon = kind.template().expect_err("coming soon");
                assert!(soon.contains("coming soon"), "{soon}");
            }
            assert!(
                crate::manifest::is_slug(kind.default_name, 32),
                "{}",
                kind.default_name
            );
        }
        // HFT and pumpfun-bot are both the pumpfun template for now.
        let hft = find_kind(Chain::Solana, "hft").expect("hft");
        let pumpfun = find_kind(Chain::Solana, "pumpfun-bot").expect("pumpfun-bot");
        assert_eq!(hft.template(), pumpfun.template());
        assert_ne!(hft.default_name, pumpfun.default_name);
        assert!(find_kind(Chain::Solana, "Stablecoin").is_some());
        assert!(find_kind(Chain::Solana, "nothing").is_none());
        // The one to start from is first, under either spelling of its name.
        assert_eq!(KINDS[0].label, "HelloWorld");
        let hello = find_kind(Chain::Solana, "helloworld").expect("helloworld");
        assert_eq!(hello.template().expect("template").id, "hello");
        assert_eq!(hello.default_name, "hello-world");
    }

    #[test]
    fn only_a_template_that_trades_asks_for_a_key() {
        let hello = find(Chain::Solana, "hello").expect("hello");
        let pumpfun = find(Chain::Solana, "pumpfun").expect("pumpfun");
        assert!(!hello.wallet);
        assert!(pumpfun.wallet);
        // What nobody picked is the first, and it needs nothing set up.
        assert_eq!(ALL[0], hello);
        let files = hello.render("my-api").expect("renders");
        let (_, manifest) = files
            .iter()
            .find(|(p, _)| p.as_os_str() == "erpc.toml")
            .expect("an erpc.toml");
        let manifest =
            Manifest::parse(std::str::from_utf8(manifest).expect("utf8")).expect("valid");
        assert!(manifest.wallet.is_none());
        assert!(manifest.secrets.is_empty());
        assert!(
            manifest.missing().is_empty(),
            "the hello app starts with nothing set"
        );
    }

    #[test]
    fn a_secret_nobody_has_to_type_is_named_with_the_flag_that_gives_it() {
        let pumpfun = find(Chain::Solana, "pumpfun").expect("pumpfun");
        // The bot's own token is made; the account's RPC key is read from
        // the account; anything else is the operator's to give.
        assert_eq!(pumpfun.secret_flag("API_TOKEN"), " --generate");
        assert_eq!(pumpfun.secret_flag("ERPC_API_KEY"), " --from-account");
        assert_eq!(pumpfun.secret_flag("WEBHOOK_URL"), "");
        // What a template generates is a setting its erpc.toml asks for.
        let files = pumpfun.render("my-bot").expect("renders");
        let (_, manifest) = files
            .iter()
            .find(|(p, _)| p.as_os_str() == "erpc.toml")
            .expect("an erpc.toml");
        let manifest =
            Manifest::parse(std::str::from_utf8(manifest).expect("utf8")).expect("valid");
        let asked: Vec<String> = manifest
            .run
            .requires
            .iter()
            .flat_map(|r| {
                r.names()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .collect();
        for setting in pumpfun.generated {
            assert!(asked.iter().any(|a| a == setting), "{setting}: {asked:?}");
        }
        let hello = find(Chain::Solana, "hello").expect("hello");
        assert_eq!(hello.secret_flag("API_TOKEN"), "", "not its own to make");
    }

    #[test]
    fn an_apps_template_is_found_from_its_tag() {
        for template in ALL {
            assert_eq!(of_tag(&template.tag()), Some(template));
        }
        assert_eq!(
            of_tag("solana/pumpfun@7").map(|t| t.id),
            Some("pumpfun"),
            "whatever its version"
        );
        assert_eq!(of_tag("solana/nope@1"), None);
        assert_eq!(of_tag("pumpfun"), None);
    }

    #[test]
    fn every_template_renders_a_valid_manifest() {
        for template in ALL {
            let files = template.render("my-bot").expect("renders");
            let (_, manifest) = files
                .iter()
                .find(|(p, _)| p.as_os_str() == "erpc.toml")
                .expect("an erpc.toml");
            let manifest =
                Manifest::parse(std::str::from_utf8(manifest).expect("utf8")).expect("valid");
            assert_eq!(manifest.name, "my-bot");
            assert_eq!(manifest.template.as_deref(), Some(template.tag().as_str()));
            assert!(
                files
                    .iter()
                    .all(|(p, _)| p.extension().is_none_or(|e| e != "tmpl")),
                "a .tmpl file was not filled in"
            );
            let cargo = files
                .iter()
                .find(|(p, _)| p.as_os_str() == "Cargo.toml")
                .expect("a Cargo.toml");
            let cargo = std::str::from_utf8(&cargo.1).expect("utf8");
            assert!(cargo.contains("name = \"my-bot\""), "{cargo}");
            assert!(!cargo.contains("{{"), "{cargo}");
        }
    }

    #[test]
    fn the_hello_apps_waf_is_there_to_uncomment_and_valid_once_it_is() {
        let hello = find(Chain::Solana, "hello").expect("hello");
        let files = hello.render("my-api").expect("renders");
        let (_, manifest) = files
            .iter()
            .find(|(p, _)| p.as_os_str() == "erpc.toml")
            .expect("an erpc.toml");
        let text = std::str::from_utf8(manifest).expect("utf8");
        // As made, the app has no WAF.
        assert!(Manifest::parse(text).expect("valid").waf.is_none());
        // Its two lines, uncommented where they stand, put it behind one.
        let example = "# [waf]\n# port = 8080\n";
        assert_eq!(text.matches(example).count(), 1, "{text}");
        let with = text.replace(example, "[waf]\nport = 8080\n");
        let behind = Manifest::parse(&with).expect("valid with its WAF");
        let config = behind.waf_config("default").expect("a config");
        assert_eq!(config.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(config.upstream.to_string(), "127.0.0.1:3000");
        // The rest of the file is as it was: the tables after it are not
        // taken into `[waf]`.
        assert_eq!(behind.vars["API_PORT"], "3000");
        assert_eq!(behind.run.port, Some(3000));
    }

    #[test]
    fn no_template_carries_a_key_file_or_env_file() {
        for template in ALL {
            for (path, _) in template.render("my-bot").expect("renders") {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                assert!(
                    name != "wallet.json" && !name.starts_with(".env"),
                    "{} ships {}",
                    template.tag(),
                    path.display()
                );
            }
        }
    }

    #[test]
    fn every_template_file_is_the_one_provenance_md_lists() {
        use sha2::{Digest as _, Sha256};
        let table = include_str!("../templates/PROVENANCE.md");
        let mut listed: std::collections::BTreeMap<String, String> = table
            .lines()
            .filter_map(|line| {
                let mut cells = line.split('|').map(str::trim).skip(1);
                let file = cells.next()?.strip_prefix('`')?.strip_suffix('`')?;
                let digest = cells.next()?.strip_prefix('`')?.strip_suffix('`')?;
                Some((file.to_owned(), digest.to_owned()))
            })
            .collect();
        let mut stack = vec![&super::TEMPLATES];
        let mut seen = 0;
        while let Some(dir) = stack.pop() {
            stack.extend(dir.dirs());
            for file in dir.files() {
                let path = file.path().to_string_lossy().into_owned();
                if path == "PROVENANCE.md" {
                    continue;
                }
                let digest = Sha256::digest(file.contents()).iter().fold(
                    String::with_capacity(64),
                    |mut hex, b| {
                        use core::fmt::Write as _;
                        let _ = write!(hex, "{b:02x}");
                        hex
                    },
                );
                let expected = listed
                    .remove(&path)
                    .unwrap_or_else(|| panic!("{path} is not in templates/PROVENANCE.md"));
                assert_eq!(digest, expected, "{path} changed; update PROVENANCE.md");
                seen += 1;
            }
        }
        assert!(seen > 0);
        assert!(listed.is_empty(), "listed but not there: {listed:?}");
    }

    #[test]
    fn the_app_entry_of_a_lock_goes_where_cargo_sorts_it() {
        let lock = "# header\nversion = 4\n\n[[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\n\
                    source = \"registry+x\"\n\n[[package]]\nname = \"my-bot\"\nversion = \"0.1.0\"\n\
                    dependencies = [\n \"alpha\",\n]\n\n[[package]]\nname = \"zeta\"\n\
                    version = \"2.0.0\"\nsource = \"registry+x\"\n";
        let names = |text: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix("name = \""))
                .map(|l| l.trim_end_matches('"').to_owned())
                .collect()
        };
        let sorted_lines = |text: &str| {
            let mut v: Vec<&str> = text.lines().collect();
            v.sort_unstable();
            v.join("\n")
        };
        for (name, order) in [
            ("aaa", ["aaa", "alpha", "zeta"]),
            ("mmm", ["alpha", "mmm", "zeta"]),
            ("zzz", ["alpha", "zeta", "zzz"]),
        ] {
            let filled = lock.replace("my-bot", name);
            let placed = super::place_app_package(&filled, name);
            assert_eq!(names(&placed), order, "{placed}");
            assert_eq!(sorted_lines(&placed), sorted_lines(&filled));
            assert!(placed.ends_with('\n') && !placed.ends_with("\n\n"));
            assert!(!placed.contains("\n\n\n"), "{placed}");
        }
    }

    #[test]
    fn what_erpc_adds_to_a_new_apps_manifest_goes_after_what_is_there() {
        use crate::edit::{set_env, set_secret, set_wallet};
        use crate::manifest::{Env, Resource, ResourceKind, SecretRef};
        let files = find(Chain::Solana, "pumpfun")
            .expect("pumpfun")
            .render("my-bot")
            .expect("renders");
        let (_, text) = files
            .iter()
            .find(|(p, _)| p.as_os_str() == "erpc.toml")
            .expect("erpc.toml");
        let text = std::str::from_utf8(text).expect("utf8");
        let r = |a: &str| SecretRef::parse(&format!("keychain:erpc-worker/{a}")).expect("ref");
        // What `secret put`, `key new` and `deploy` write, in that order.
        let text = set_secret(text, "X_TOKEN", &r("my-bot.X_TOKEN")).expect("secret");
        let text = set_wallet(
            &text,
            &r("my-bot.wallet"),
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        )
        .expect("wallet");
        let env = Env {
            resource: Some(Resource {
                kind: ResourceKind::Vps,
                id: "1".to_owned(),
                region: None,
                hourly: true,
            }),
            host: Some("203.0.113.10".to_owned()),
            ..Env::default()
        };
        let text = set_env(&text, "default", &env).expect("env");
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("no {needle} in:\n{text}"))
        };
        let order = [
            "[run]",
            "[vars]",
            "# EXPLORER_URL",
            "RUST_LOG",
            "\n[secrets]",
            "\n[wallet]",
            "\n[env.default]",
            "\n[env.default.resource]",
        ];
        for pair in order.windows(2) {
            assert!(
                at(pair[0]) < at(pair[1]),
                "{} before {} in:\n{text}",
                pair[0],
                pair[1]
            );
        }
        // Deployed again: replaced in place, still last.
        let text = set_env(&text, "default", &env).expect("again");
        assert_eq!(text.matches("[env.default]").count(), 1, "{text}");
    }

    #[test]
    fn a_template_is_found_with_or_without_its_chain() {
        assert_eq!(find(Chain::Solana, "pumpfun").expect("found").id, "pumpfun");
        assert_eq!(
            find(Chain::Solana, "solana/pumpfun").expect("found").id,
            "pumpfun"
        );
        assert!(find(Chain::Solana, "nope").is_err());
    }

    #[test]
    fn a_bad_name_or_an_existing_directory_writes_nothing() {
        let root = std::env::temp_dir().join(format!("erpc-worker-tpl-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        let template = ALL[0];
        assert!(template.render("My_Bot").is_err());
        let dest = root.join("bot");
        let written = template.write("bot", &dest).expect("writes");
        assert!(written.iter().any(|p| p.as_os_str() == "erpc.toml"));
        assert!(dest.join("Cargo.toml").is_file());
        assert!(template.write("bot", &dest).is_err());
        let left: Vec<_> = std::fs::read_dir(&root)
            .expect("list")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".erpc-init-"))
            .collect();
        assert!(left.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
