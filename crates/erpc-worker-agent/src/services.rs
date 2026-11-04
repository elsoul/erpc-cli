// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `ctl services`: the local services an app's erpc.toml asks for
//! (`[services]`), installed from Ubuntu's own packages and running.
//!
//! - **Redis** listens on 127.0.0.1 only, as Ubuntu ships it, and the
//!   firewall drops every other inbound connection anyway.
//! - **PostgreSQL**: a role and a database named after the worker's unit,
//!   `erpc-worker-<id>`, which is the user systemd runs the app as. The
//!   app reaches it over the local socket with peer authentication: no
//!   password exists to leak.
//!
//! Each step is skipped when it is done already, so a deploy runs it every
//! time.

use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// Runs `program` with `args` as this (root) process, quietly, and says
/// why it failed.
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().last().unwrap_or_default();
        Err(format!("{program} {} failed: {last}", args.join(" ")))
    }
}

/// Whether Debian package `name` is installed.
fn installed(name: &str) -> bool {
    run("dpkg-query", &["-W", "-f=${Status}", name])
        .is_ok_and(|s| s.contains("install ok installed"))
}

/// Installs the packages not installed yet; which were.
fn install(packages: &[&str]) -> Result<Vec<String>, String> {
    let missing: Vec<&str> = packages.iter().copied().filter(|p| !installed(p)).collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    run("apt-get", &["update", "-qq"])?;
    let mut args = vec!["install", "-y", "-qq", "--no-install-recommends"];
    args.extend(&missing);
    run("apt-get", &args)?;
    Ok(missing.iter().map(|p| (*p).to_owned()).collect())
}

/// The SQL for an identifier: double-quoted. A worker id is lowercase
/// letters, digits and dashes, which needs nothing escaped.
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Runs one SQL statement as the `postgres` superuser.
fn psql(sql: &str) -> Result<String, String> {
    run(
        "runuser",
        &["-u", "postgres", "--", "psql", "-qtAX", "-c", sql],
    )
}

/// Makes the worker's role and database, when they are not there.
fn postgres_for(role: &str) -> Result<bool, String> {
    let literal = format!("'{}'", role.replace('\'', "''"));
    let has_role = psql(&format!("SELECT 1 FROM pg_roles WHERE rolname = {literal}"))? == "1";
    if !has_role {
        psql(&format!("CREATE ROLE {} LOGIN", quoted(role)))?;
    }
    let has_db = psql(&format!(
        "SELECT 1 FROM pg_database WHERE datname = {literal}"
    ))? == "1";
    if !has_db {
        psql(&format!(
            "CREATE DATABASE {} OWNER {}",
            quoted(role),
            quoted(role)
        ))?;
    }
    Ok(!has_role || !has_db)
}

/// `ctl services`: installs, enables and starts what was asked for.
pub(crate) fn ensure(id: &str, redis: bool, postgres: bool) -> Result<Value, String> {
    let mut answer = json!({ "ok": true });
    if redis {
        let added = install(&["redis-server"])?;
        run("systemctl", &["enable", "--now", "redis-server"])?;
        answer["redis"] = json!(if added.is_empty() {
            "present"
        } else {
            "installed"
        });
    }
    if postgres {
        let added = install(&["postgresql"])?;
        run("systemctl", &["enable", "--now", "postgresql"])?;
        let role = format!("erpc-worker-{id}");
        let made = postgres_for(&role)?;
        answer["postgres"] = json!(if added.is_empty() {
            "present"
        } else {
            "installed"
        });
        answer["postgres_role"] = json!(if made { "created" } else { "present" });
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifiers_are_quoted_whole() {
        assert_eq!(
            super::quoted("erpc-worker-bot-default"),
            "\"erpc-worker-bot-default\""
        );
        assert_eq!(super::quoted("a\"b"), "\"a\"\"b\"");
    }
}
