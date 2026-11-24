// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The operating system, the installed packages the check knows, and
//! whether the collector runs as the superuser.

use std::path::Path;

use erpc_api::security_check::{Coverage, Os, OsFamily, Package, PackageName, Packages, Token};

fn read_file(path: &Path, limit: u64) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// Whether the process reading `proc` runs with the superuser's effective
/// id.
pub(super) fn privileged(proc: &Path) -> bool {
    read_file(&proc.join("self/status"), 64 * 1024).is_ok_and(|status| {
        status.lines().any(|line| {
            line.strip_prefix("Uid:")
                .and_then(|ids| ids.split_ascii_whitespace().nth(1))
                == Some("0")
        })
    })
}

/// The operating system under `root`.
pub(super) fn os(root: &Path) -> Os {
    let release = read_file(&root.join("etc/os-release"), 64 * 1024).ok();
    let field = |key: &str| {
        release.as_deref()?.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k == key).then(|| v.trim().trim_matches('"').to_owned())
        })
    };
    let family = match field("ID").as_deref() {
        Some("ubuntu") => OsFamily::Ubuntu,
        Some("debian") => OsFamily::Debian,
        Some("rhel") => OsFamily::Rhel,
        Some("rocky") => OsFamily::Rocky,
        Some("almalinux") => OsFamily::Alma,
        Some("fedora") => OsFamily::Fedora,
        Some("amzn") => OsFamily::Amazon,
        Some(_) => OsFamily::Other,
        None => OsFamily::Unknown,
    };
    let version = field("VERSION_ID").as_deref().and_then(Token::new);
    let kernel = read_file(&root.join("proc/sys/kernel/osrelease"), 256)
        .ok()
        .and_then(|k| Token::new(k.trim()));
    let coverage = match (release.is_some(), kernel.is_some()) {
        (true, true) => Coverage::Complete,
        (false, false) => Coverage::Unreadable,
        _ => Coverage::Partial,
    };
    Os {
        coverage,
        family,
        version,
        kernel,
    }
}

const DPKG_LIMIT: u64 = 64 * 1024 * 1024;

fn package_name(name: &str) -> Option<PackageName> {
    Some(match name {
        "openssh-server" => PackageName::OpensshServer,
        "openssl" => PackageName::Openssl,
        "libssl3" | "libssl3t64" | "libssl1.1" => PackageName::Libssl,
        "sudo" | "sudo-ldap" => PackageName::Sudo,
        "libc6" => PackageName::Libc6,
        "systemd" => PackageName::Systemd,
        "polkitd" | "policykit-1" => PackageName::Polkit,
        "xz-utils" => PackageName::XzUtils,
        "docker-ce" => PackageName::DockerCe,
        "docker.io" => PackageName::DockerIo,
        "containerd" | "containerd.io" => PackageName::Containerd,
        "runc" => PackageName::Runc,
        "nginx" | "nginx-core" => PackageName::Nginx,
        "apache2" => PackageName::Apache2,
        "haproxy" => PackageName::Haproxy,
        "redis-server" => PackageName::RedisServer,
        "mariadb-server" | "mariadb-server-core" => PackageName::MariadbServer,
        "mongodb-org-server" => PackageName::Mongodb,
        "nodejs" => PackageName::Nodejs,
        "python3" => PackageName::Python3,
        other
            if other
                .strip_prefix("postgresql-")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())) =>
        {
            PackageName::Postgresql
        }
        other if other.starts_with("mysql-server-") => PackageName::MysqlServer,
        _ => return None,
    })
}

/// The known packages installed under `root`, from the Debian package
/// database. A system without one reports it absent; one whose database
/// this cannot read, unreadable.
pub(super) fn packages(root: &Path) -> Packages {
    let status = match read_file(&root.join("var/lib/dpkg/status"), DPKG_LIMIT + 1) {
        Ok(status) => status,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if root.join("var/lib/rpm").exists() {
                Packages::unreadable()
            } else {
                Packages::new(Coverage::Absent, Vec::new())
            };
        }
        Err(_) => return Packages::unreadable(),
    };
    if status.len() as u64 > DPKG_LIMIT {
        return Packages::unreadable();
    }
    let mut partial = false;
    let mut found = Vec::new();
    for paragraph in status.split("\n\n") {
        let field = |key: &str| {
            paragraph
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix(':').map(str::trim))
        };
        let installed =
            field("Status").is_some_and(|s| s.ends_with("installed") && s.starts_with("install"));
        let Some(name) = field("Package").and_then(package_name) else {
            continue;
        };
        if !installed {
            continue;
        }
        match field("Version").and_then(Token::new) {
            Some(version) => found.push(Package { name, version }),
            None => partial = true,
        }
    }
    Packages::new(
        if partial {
            Coverage::Partial
        } else {
            Coverage::Complete
        },
        found,
    )
}

#[cfg(all(test, unix))]
mod tests {
    use erpc_api::security_check::{Coverage, OsFamily, PackageName};

    use super::{os, packages, privileged};

    #[test]
    fn os_release_kernel_and_effective_user() {
        let root = crate::node::security::fixture("os");
        std::fs::create_dir_all(root.join("etc")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(root.join("proc/sys/kernel")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(root.join("proc/self")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("etc/os-release"),
            "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(root.join("proc/sys/kernel/osrelease"), "6.8.0-49-generic\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let found = os(&root);
        assert_eq!(found.coverage, Coverage::Complete);
        assert_eq!(found.family, OsFamily::Ubuntu);
        assert_eq!(
            found
                .version
                .as_ref()
                .map(erpc_api::security_check::Token::as_str),
            Some("24.04")
        );
        assert_eq!(
            found
                .kernel
                .as_ref()
                .map(erpc_api::security_check::Token::as_str),
            Some("6.8.0-49-generic")
        );

        std::fs::write(
            root.join("proc/self/status"),
            "Name:\terpc\nUid:\t1000\t0\t0\t0\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(privileged(&root.join("proc")));
        std::fs::write(
            root.join("proc/self/status"),
            "Name:\terpc\nUid:\t0\t1000\t1000\t1000\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(!privileged(&root.join("proc")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_installed_known_packages_with_clean_versions_are_reported() {
        let root = crate::node::security::fixture("dpkg");
        assert_eq!(packages(&root).coverage(), Coverage::Absent);
        std::fs::create_dir_all(root.join("var/lib/dpkg")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            root.join("var/lib/dpkg/status"),
            "Package: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1-3ubuntu13.5\n\n\
             Package: postgresql-16\nStatus: install ok installed\nVersion: 16.4-0ubuntu0.24.04.2\n\n\
             Package: nginx\nStatus: deinstall ok config-files\nVersion: 1.24.0-2ubuntu7\n\n\
             Package: my-own-tool\nStatus: install ok installed\nVersion: 1.0\n\n\
             Package: sudo\nStatus: install ok installed\nVersion: 1.9.15p5 ignore this\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let found = packages(&root);
        assert_eq!(found.coverage(), Coverage::Partial);
        let names: Vec<_> = found
            .items()
            .iter()
            .map(|p| (p.name, p.version.as_str().to_owned()))
            .collect();
        assert_eq!(
            names,
            [
                (PackageName::OpensshServer, "1:9.6p1-3ubuntu13.5".to_owned()),
                (PackageName::Postgresql, "16.4-0ubuntu0.24.04.2".to_owned()),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
