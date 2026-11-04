// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What erpc runs on an ERPC VPS it was just handed: the operator's key put
//! in place, password logins turned off for good, and, when asked, SSH
//! allowed only from the operator's addresses.
//!
//! The first two run once, the key over the password login ERPC set up and
//! the rest over the key, so password logins are turned off only once a key
//! is known to get in. The firewall table is applied under a rollback timer
//! and kept only when a fresh connection gets through it, the same way as
//! an Arc node's.

use std::fmt::Write as _;
use std::net::IpAddr;

/// Where the allow list's files are kept on the VPS, as a literal for the
/// scripts built with `concat!`.
macro_rules! allow_dir {
    () => {
        "/etc/erpc/ssh-allow"
    };
}
const ALLOW_DIR: &str = allow_dir!();
/// How long an applied allow list waits for erpc to get in again.
pub const ROLLBACK_SECONDS: u32 = 120;

/// Puts the public key on standard input in the login user's
/// `authorized_keys`, once, and prints `key=installed` and the address the
/// connection comes from.
pub(crate) const AUTHORIZE_KEY: &str = r#"set -eu
umask 077
IFS= read -r key
case "$key" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *|sk-*) ;;
  *) echo 'standard input is not one public key line' >&2; exit 3 ;;
esac
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
f="$HOME/.ssh/authorized_keys"
touch "$f"
chmod 600 "$f"
if ! grep -qxF -- "$key" "$f"; then
  # A last line with no newline would run into the key.
  [ ! -s "$f" ] || [ -z "$(tail -c 1 "$f")" ] || printf '\n' >> "$f"
  printf '%s\n' "$key" >> "$f"
fi
printf 'key=installed\n'
printf 'controller=%s\n' "${SSH_CLIENT%% *}""#;

/// Turns password logins off for good, run over the key. Run again, it
/// changes nothing more: a second run after one that stopped part way
/// finishes the work. Standard input's
/// first line is the login password, used only when `sudo` asks for one;
/// then the login user is given `sudo` without one, since the password
/// stops being a way in. The drop-in is `00-` so it is read before
/// cloud-init's `50-cloud-init.conf`, which turns passwords on, and sshd
/// keeps the first value it reads. Prints what sshd now enforces.
pub(crate) const HARDEN: &str = r#"set -eu
export LC_ALL=C
IFS= read -r pw || pw=''
if sudo -n true 2>/dev/null; then
  s() { sudo -n "$@"; }
  sudo_was=nopasswd
  # Given by an earlier run that stopped part way: it was erpc's doing.
  if sudo -n test -f /etc/sudoers.d/90-erpc-login; then sudo_was=password; fi
else
  [ -n "$pw" ] || { echo 'sudo asks for a password and none was given' >&2; exit 3; }
  s() { printf '%s\n' "$pw" | sudo -S -p '' "$@"; }
  sudo_was=password
fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if [ "$sudo_was" = password ]; then
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$(id -un)" > "$tmp"
  s visudo -cqf "$tmp"
  s install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/90-erpc-login
fi
cat > "$tmp" <<'EOF'
# Managed by erpc: log in with a key only.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
EOF
s install -o root -g root -m 0644 "$tmp" /etc/ssh/sshd_config.d/00-erpc.conf
# sudo without a password is the price of password logins going: if
# they stay, it goes too, with the drop-in.
# The sudoers file goes last: `s` may need it.
undo() {
  s rm -f /etc/ssh/sshd_config.d/00-erpc.conf
  for unit in ssh.service sshd.service; do
    if s systemctl is-active --quiet "$unit"; then s systemctl reload "$unit"; break; fi
  done
  if [ "$sudo_was" = password ]; then s rm -f /etc/sudoers.d/90-erpc-login; fi
}
if ! s /usr/sbin/sshd -t; then
  undo
  echo 'sshd rejects its configuration with the change; everything this run changed was taken back' >&2
  exit 4
fi
for unit in ssh.service sshd.service; do
  if s systemctl is-active --quiet "$unit"; then s systemctl reload "$unit"; break; fi
done
# Under `set -e` a failed read would end the script here, with nothing
# taken back.
if ! t=$(s /usr/sbin/sshd -T 2>/dev/null); then
  undo
  echo 'sshd could not report its settings after the change; everything this run changed was taken back' >&2
  exit 6
fi
pa=$(printf '%s\n' "$t" | awk '$1 == "passwordauthentication" {print $2}')
kia=$(printf '%s\n' "$t" | awk '$1 == "kbdinteractiveauthentication" {print $2}')
if [ "$pa" != no ] || [ "$kia" != no ]; then
  undo
  echo "sshd still allows passwords with the change (passwordauthentication $pa, kbdinteractiveauthentication $kia): another setting wins over it; everything this run changed was taken back" >&2
  exit 5
fi
printf 'password_authentication=%s\n' "$pa"
printf 'kbd_interactive_authentication=%s\n' "$kia"
printf 'sudo_was=%s\n' "$sudo_was""#;

/// The addresses SSH is allowed from: at least one, each a plain IPv4 or
/// IPv6 address, so each prints as nothing but digits, hex, `.` and `:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowList {
    addresses: Vec<IpAddr>,
    port: u16,
}

impl AllowList {
    /// The list for SSH on `port`.
    ///
    /// # Errors
    ///
    /// When there is no address, or more than 16.
    pub fn new(mut addresses: Vec<IpAddr>, port: u16) -> Result<Self, String> {
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.len() > 16 {
            return Err("allow SSH from 1 to 16 addresses".to_owned());
        }
        Ok(Self { addresses, port })
    }

    /// The addresses, in order.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// The table: SSH from the listed addresses and connections already
    /// open, nothing else on the SSH port. Other ports are left as they
    /// are. Loading it replaces the table erpc loaded before.
    #[must_use]
    pub fn table(&self) -> String {
        let port = self.port;
        let mut rules = String::new();
        for (family, v4) in [("ip", true), ("ip6", false)] {
            let set: Vec<String> = self
                .addresses
                .iter()
                .filter(|a| a.is_ipv4() == v4)
                .map(ToString::to_string)
                .collect();
            if !set.is_empty() {
                let _ = writeln!(
                    rules,
                    "    tcp dport {port} {family} saddr {{ {} }} accept",
                    set.join(", ")
                );
            }
        }
        format!(
            "table inet erpc_ssh\n\
             delete table inet erpc_ssh\n\
             table inet erpc_ssh {{\n  \
               chain input {{\n    \
                 type filter hook input priority filter - 10; policy accept;\n    \
                 iif \"lo\" accept\n    \
                 tcp dport {port} ct state established,related accept\n\
             {rules}    \
                 tcp dport {port} drop\n  \
               }}\n\
             }}\n"
        )
    }
}

/// Applies `list` under a rollback timer: the table now in force is kept to
/// go back to, and unless [`CONFIRM_ALLOW`] runs over a fresh connection
/// within [`ROLLBACK_SECONDS`] it is put back.
pub(crate) fn allow(list: &AllowList) -> String {
    let table = list.table();
    format!(
        r#"set -eu
export LC_ALL=C
d={ALLOW_DIR}
sudo -n install -d -o root -g root -m 0700 "$d"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<'EOF'
{table}EOF
sudo -n nft -c -f "$tmp"
sudo -n systemctl stop erpc-ssh-allow-rollback.timer 2>/dev/null || true
if sudo -n test -f "$d/allow.nft"; then
  sudo -n cp "$d/allow.nft" "$d/previous.nft"
else
  printf 'table inet erpc_ssh\ndelete table inet erpc_ssh\n' | sudo -n tee "$d/previous.nft" >/dev/null
fi
printf '%s\n' '#!/bin/bash' "nft -f $d/previous.nft" "rm -f $d/pending.nft" | sudo -n tee "$d/rollback.sh" >/dev/null
sudo -n install -o root -g root -m 0600 "$tmp" "$d/pending.nft"
sudo -n systemd-run --quiet --collect --unit=erpc-ssh-allow-rollback --on-active={ROLLBACK_SECONDS} /bin/bash "$d/rollback.sh"
sudo -n nft -f "$d/pending.nft"
printf 'firewall=applied\n'"#
    )
}

/// Run over a fresh connection after [`allow`]: getting here proves the new
/// table lets erpc in. Disarms the rollback and loads the table at boot.
pub(crate) const CONFIRM_ALLOW: &str = concat!(
    "set -eu\nd=",
    allow_dir!(),
    r#"
# No pending table: the rollback already ran and put the previous one back.
if ! sudo -n test -f "$d/pending.nft"; then printf 'firewall=rolled_back\n'; exit 0; fi
sudo -n systemctl stop erpc-ssh-allow-rollback.timer 2>/dev/null || true
sudo -n install -o root -g root -m 0600 "$d/pending.nft" "$d/allow.nft"
sudo -n rm -f "$d/pending.nft"
printf '%s\n' '[Unit]' 'Description=SSH allow list (managed by erpc)' 'DefaultDependencies=no' \
  'After=nftables.service' 'Wants=network-pre.target' 'Before=network-pre.target shutdown.target' \
  'Conflicts=shutdown.target' \
  '[Service]' 'Type=oneshot' 'RemainAfterExit=yes' "ExecStart=/usr/sbin/nft -f $d/allow.nft" \
  '[Install]' 'WantedBy=multi-user.target' | sudo -n tee /etc/systemd/system/erpc-ssh-allow.service >/dev/null
sudo -n systemctl daemon-reload
sudo -n systemctl enable --quiet erpc-ssh-allow.service
printf 'firewall=confirmed\n'"#
);

/// Takes the allow list away: SSH is open to every address again, as
/// before erpc restricted it.
pub(crate) const OPEN: &str = concat!(
    "set -eu
sudo -n systemctl stop erpc-ssh-allow-rollback.timer 2>/dev/null || true
sudo -n systemctl disable --quiet erpc-ssh-allow.service 2>/dev/null || true
sudo -n rm -f /etc/systemd/system/erpc-ssh-allow.service
sudo -n systemctl daemon-reload
sudo -n nft delete table inet erpc_ssh 2>/dev/null || true
sudo -n rm -rf ",
    allow_dir!(),
    "
printf 'firewall=open\\n'"
);

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{AUTHORIZE_KEY, AllowList, CONFIRM_ALLOW, HARDEN};
    #[cfg(unix)]
    use super::{OPEN, allow};

    #[cfg(unix)]
    fn valid_shell(line: &str) {
        let checked = std::process::Command::new("bash")
            .args(["-n", "-c", line])
            .status()
            .expect("bash");
        assert!(checked.success(), "{line}");
    }

    fn list() -> AllowList {
        let addresses: Vec<IpAddr> = ["203.0.113.7", "2001:db8::1", "203.0.113.7"]
            .iter()
            .map(|a| a.parse().expect("address"))
            .collect();
        AllowList::new(addresses, 22).expect("list")
    }

    #[cfg(unix)]
    #[test]
    fn every_script_is_valid_shell() {
        for script in [AUTHORIZE_KEY, HARDEN, CONFIRM_ALLOW, OPEN, &allow(&list())] {
            valid_shell(script);
        }
    }

    #[test]
    fn the_table_allows_ssh_from_the_list_only() {
        let table = list().table();
        assert!(table.contains("tcp dport 22 ip saddr { 203.0.113.7 } accept"));
        assert!(table.contains("tcp dport 22 ip6 saddr { 2001:db8::1 } accept"));
        assert!(table.contains("tcp dport 22 ct state established,related accept"));
        assert!(table.trim_end().ends_with("tcp dport 22 drop\n  }\n}"));
        assert_eq!(list().addresses().len(), 2, "duplicates go");
        assert!(AllowList::new(Vec::new(), 22).is_err());
    }

    #[test]
    fn a_key_goes_on_a_line_of_its_own_once() {
        use std::io::Write as _;
        let home = tempfile::tempdir().expect("home");
        let ssh = home.path().join(".ssh");
        std::fs::create_dir(&ssh).expect("dir");
        let file = ssh.join("authorized_keys");
        // Written by hand, with no newline at the end.
        std::fs::write(&file, "ssh-ed25519 AAAAold old@laptop").expect("write");
        let key = "ssh-ed25519 AAAAnew erpc";
        for _ in 0..2 {
            let mut child = std::process::Command::new("sh")
                .args(["-c", AUTHORIZE_KEY])
                .env("HOME", home.path())
                .env("SSH_CLIENT", "203.0.113.7 5000 22")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("sh");
            writeln!(child.stdin.take().expect("stdin"), "{key}").expect("key");
            assert!(child.wait().expect("wait").success());
        }
        assert_eq!(
            std::fs::read_to_string(&file).expect("read"),
            "ssh-ed25519 AAAAold old@laptop\nssh-ed25519 AAAAnew erpc\n"
        );
    }

    #[test]
    fn the_allow_list_loads_after_nftables_flushes() {
        assert!(CONFIRM_ALLOW.contains("'After=nftables.service'"));
    }

    #[test]
    fn password_logins_go_off_before_cloud_init_turns_them_on() {
        assert!(HARDEN.contains("/etc/ssh/sshd_config.d/00-erpc.conf"));
        assert!(HARDEN.contains("PasswordAuthentication no"));
        assert!(HARDEN.contains("sshd -t"));
    }
}
