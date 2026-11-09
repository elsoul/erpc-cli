// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Actual offline Cargo rebuilds using every template package's build script.
//! Only inert text fixtures are embedded; no node program or host helper runs.
#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            for attempt in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "erpc-template-build-{}-{stamp}-{attempt}",
                    std::process::id()
                ));
                let mut directory = fs::DirBuilder::new();
                directory.recursive(false);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    directory.mode(0o700);
                }
                match directory.create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create isolated build fixture: {error}"),
                }
            }
            panic!("cannot reserve an isolated build fixture");
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cargo(root: &Path, arguments: &[&str]) -> String {
        let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(root)
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env_remove("CARGO_MAKEFLAGS")
            .env_remove("MAKEFLAGS")
            .args(arguments)
            .output()
            .expect("Cargo must be available for incremental template verification");
        assert!(
            output.status.success(),
            "Cargo {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    struct Package {
        name: String,
        build: PathBuf,
    }

    fn template_packages(workspace: &Path) -> Vec<Package> {
        let raw = cargo(
            workspace,
            &[
                "metadata",
                "--offline",
                "--locked",
                "--no-deps",
                "--format-version=1",
            ],
        );
        let metadata: Value = serde_json::from_str(&raw).unwrap();
        let mut packages = Vec::new();
        for package in metadata["packages"].as_array().unwrap() {
            if !package["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dep| dep["name"] == "include_dir")
            {
                continue;
            }
            let name = package["name"].as_str().unwrap();
            let manifest = Path::new(package["manifest_path"].as_str().unwrap());
            let root = manifest.parent().unwrap();
            // The CLI also consumes include_dir's public types, but does not own an
            // embedded templates directory. Track packages that own these inputs.
            if !root.join("templates").is_dir() {
                continue;
            }
            let targets: Vec<_> = package["targets"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|target| {
                    target["kind"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|kind| kind == "custom-build")
                })
                .collect();
            assert_eq!(
                targets.len(),
                1,
                "{name}: Cargo must run its template-directory build script"
            );
            packages.push(Package {
                name: name.to_owned(),
                build: PathBuf::from(targets[0]["src_path"].as_str().unwrap()),
            });
        }
        assert!(
            !packages.is_empty(),
            "no embedded template packages were discovered"
        );
        packages.sort_by(|left, right| left.name.cmp(&right.name));
        packages
    }

    fn locked_include_dir(workspace: &Path) -> String {
        let lock = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
        let package = lock
            .split("[[package]]")
            .find(|part| part.lines().any(|line| line == "name = \"include_dir\""))
            .expect("include_dir must remain in the reviewed workspace lockfile");
        package
            .lines()
            .find_map(|line| {
                line.strip_prefix("version = \"")
                    .and_then(|text| text.strip_suffix('"'))
            })
            .unwrap()
            .to_owned()
    }

    fn fixture(root: &Path, packages: &[Package], version: &str) -> Vec<PathBuf> {
        let mut manifest = String::from(
            "[package]\nname=\"template-rebuild-probe\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\nresolver=\"3\"\nmembers=[\"packages/*\"]\n[dependencies]\n",
        );
        let mut main = String::from("fn main() {\n");
        let mut trees = Vec::new();
        // The extra package deliberately has no build script. It distinguishes a
        // new-file-only change from accidentally invalidating an old include_bytes.
        for index in 0..=packages.len() {
            let name = format!("probe_{index}");
            let package = root.join("packages").join(&name);
            fs::create_dir_all(package.join("src")).unwrap();
            fs::create_dir_all(package.join("templates/nested")).unwrap();
            fs::write(package.join("templates/stable.txt"), "stable").unwrap();
            fs::write(package.join("Cargo.toml"), format!(
                "[package]\nname=\"{name}\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[dependencies]\ninclude_dir={{version=\"={version}\",default-features=false}}\n"
            )).unwrap();
            fs::write(package.join("src/lib.rs"), r#"static FILES: include_dir::Dir<'static> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
    pub fn read(path: &str) -> &'static str { FILES.get_file(path).and_then(|file| file.contents_utf8()).unwrap_or("missing") }
    "#).unwrap();
            if let Some(original) = packages.get(index) {
                fs::copy(&original.build, package.join("build.rs")).unwrap();
            }
            writeln!(manifest, "{name}={{path=\"packages/{name}\"}}").unwrap();
            writeln!(main, "println!(\"{{}}:{{}}:{{}}\", {name}::read(\"stable.txt\"), {name}::read(\"nested/new.txt\"), {name}::read(\"nested/deeper/new.txt\"));").unwrap();
            trees.push(package.join("templates"));
        }
        main.push_str("}\n");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), main).unwrap();
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        trees
    }

    fn assert_embedded(
        root: &Path,
        packages: &[Package],
        value: &str,
        untracked: &str,
        initial: bool,
    ) {
        let arguments = if initial {
            vec!["run", "--offline", "--quiet", "--jobs=2"]
        } else {
            vec!["run", "--offline", "--locked", "--quiet", "--jobs=2"]
        };
        let output = cargo(root, &arguments);
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), packages.len() + 1);
        for (package, actual) in packages.iter().zip(&lines) {
            assert_eq!(
                *actual, value,
                "{} did not invalidate its embedded template directory",
                package.name
            );
        }
        assert_eq!(
            lines[packages.len()],
            untracked,
            "the control unexpectedly rebuilt; a non-template input may have changed"
        );
    }

    fn next_change() {
        // Keep edits separate from Cargo's recorded build time on filesystems with
        // coarse mtime precision; never touch Rust sources or clean build artifacts.
        std::thread::sleep(Duration::from_millis(1100));
    }

    #[test]
    fn each_template_package_tracks_nested_add_edit_delete_without_cleaning() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let packages = template_packages(workspace);
        let temporary = Temporary::new();
        let trees = fixture(&temporary.0, &packages, &locked_include_dir(workspace));
        // Preserve the reviewed dependency resolutions; Cargo removes unrelated
        // packages during the first fixture build. All later builds are --locked.
        fs::copy(workspace.join("Cargo.lock"), temporary.0.join("Cargo.lock")).unwrap();
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:missing:missing",
            "stable:missing:missing",
            true,
        );
        for (content, expected) in [
            ("added", "stable:added:missing"),
            ("edited", "stable:edited:missing"),
        ] {
            next_change();
            for tree in &trees {
                fs::write(tree.join("nested/new.txt"), content).unwrap();
            }
            assert_embedded(
                &temporary.0,
                &packages,
                expected,
                "stable:missing:missing",
                false,
            );
        }
        next_change();
        for tree in &trees {
            fs::remove_file(tree.join("nested/new.txt")).unwrap();
        }
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:missing:missing",
            "stable:missing:missing",
            false,
        );
        next_change();
        for tree in &trees {
            fs::create_dir(tree.join("nested/deeper")).unwrap();
            fs::write(tree.join("nested/deeper/new.txt"), "nested-added").unwrap();
        }
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:missing:nested-added",
            "stable:missing:missing",
            false,
        );
        next_change();
        for tree in &trees {
            fs::remove_dir_all(tree.join("nested/deeper")).unwrap();
        }
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:missing:missing",
            "stable:missing:missing",
            false,
        );
        next_change();
        for tree in &trees {
            fs::write(tree.join("nested/new.txt"), "added-again").unwrap();
        }
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:added-again:missing",
            "stable:missing:missing",
            false,
        );
        next_change();
        fs::write(trees.last().unwrap().join("stable.txt"), "existing-edited").unwrap();
        assert_embedded(
            &temporary.0,
            &packages,
            "stable:added-again:missing",
            "existing-edited:added-again:missing",
            false,
        );
        println!(
            "{} actual template package build scripts passed all incremental mutations",
            packages.len()
        );
    }
}
