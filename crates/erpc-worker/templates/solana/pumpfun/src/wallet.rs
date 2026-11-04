//! The trading key, handed over on a pipe and never written to a file.
//!
//! `erpc worker run` here and the erpc agent on a server start this app with
//! the key on a pipe, the descriptor named by `ERPC_WORKER_KEY_FD`: 0, the
//! app's standard input, which erpc uses, or one above stderr. The pipe
//! holds exactly 64 bytes, the secret key followed by the public key, as a
//! Solana keypair is laid out, then end of file. The bytes are read into a
//! buffer that is wiped when dropped, checked and turned into one
//! [`Keypair`]; a descriptor above stderr is then closed. The keypair is
//! shared from then on, never copied.
//!
//! Without the variable the app starts watch-only: it streams and serves its
//! API, and refuses to trade.

use std::io::Read;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signer::Signer;
use zeroize::Zeroizing;

/// Names the descriptor the key arrives on.
pub const KEY_FD_VAR: &str = "ERPC_WORKER_KEY_FD";
/// The public key the operator expects, from `erpc.toml`'s `[wallet]`.
pub const PUBKEY_VAR: &str = "ERPC_WORKER_PUBKEY";

/// Keeps this process out of core dumps and away from other processes of
/// the same user reading its memory, before the key is in it. Linux only;
/// elsewhere the app runs on the operator's own machine.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE takes no pointers.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            warn!("could not mark the process undumpable: {}", std::io::Error::last_os_error());
        }
    }
}

/// Reconstructs a keypair from its 64 bytes, checking that the public half
/// is the one the secret half derives.
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair> {
    if bytes.len() != 64 {
        bail!("a keypair is 64 bytes, got {}", bytes.len());
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes[..32]);
    let keypair = Keypair::new_from_array(*secret);
    let mut public = [0u8; 32];
    public.copy_from_slice(&bytes[32..]);
    let stored = Pubkey::new_from_array(public);
    if keypair.pubkey() != stored {
        bail!(
            "the key's public half {} is not what its secret half derives ({})",
            stored,
            keypair.pubkey()
        );
    }
    Ok(keypair)
}

/// The trading key from the descriptor erpc handed over, or none when the
/// app was started without one.
pub fn from_erpc() -> Result<Option<Arc<Keypair>>> {
    let Ok(fd) = std::env::var(KEY_FD_VAR) else {
        warn!("no trading key was handed over ({KEY_FD_VAR} is not set): watch-only, trading is refused");
        return Ok(None);
    };
    let fd: u32 = fd.parse().with_context(|| format!("{KEY_FD_VAR}={fd:?} is not a descriptor number"))?;
    if fd == 1 || fd == 2 {
        bail!("{KEY_FD_VAR} must be 0 (standard input) or a descriptor above stderr, not {fd}");
    }
    let mut bytes = Zeroizing::new([0u8; 64]);
    if fd == 0 {
        // Read through the process's own handle: what is left on the pipe
        // after the key is end of file, which is all the app ever reads there.
        read_key(&mut std::io::stdin().lock(), &mut bytes)?;
    } else {
        // Opening /dev/fd/N gives a file of our own over the inherited pipe;
        // the inherited descriptor is then closed so nothing can read it later.
        let path = format!("/dev/fd/{fd}");
        let mut pipe =
            std::fs::File::open(&path).with_context(|| format!("could not open {path}"))?;
        read_key(&mut pipe, &mut bytes)?;
        drop(pipe);
        close_inherited(fd);
    }

    let keypair = keypair_from_bytes(&bytes[..])?;
    if let Ok(expected) = std::env::var(PUBKEY_VAR) {
        if keypair.pubkey().to_string() != expected {
            bail!(
                "the key handed over is {}, and erpc.toml's wallet.pubkey is {}",
                keypair.pubkey(),
                expected
            );
        }
    }
    info!("trading key handed over: {}", keypair.pubkey());
    Ok(Some(Arc::new(keypair)))
}

/// Exactly 64 bytes, then end of file.
fn read_key(pipe: &mut impl Read, bytes: &mut [u8; 64]) -> Result<()> {
    pipe.read_exact(&mut bytes[..])
        .context("the key pipe closed before 64 bytes arrived")?;
    let mut extra = [0u8; 1];
    if pipe.read(&mut extra).context("could not read the key pipe")? != 0 {
        bail!("the key pipe holds more than 64 bytes");
    }
    Ok(())
}

fn close_inherited(fd: u32) {
    #[cfg(unix)]
    {
        // SAFETY: closing a descriptor number this process inherited and no
        // longer uses; nothing in the process holds it.
        unsafe {
            libc::close(fd as libc::c_int);
        }
    }
    #[cfg(not(unix))]
    let _ = fd;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_keypair_round_trips_through_its_bytes() {
        let kp = Keypair::new();
        let bytes = Zeroizing::new(kp.to_bytes());
        let restored = keypair_from_bytes(&bytes[..]).expect("round-trip");
        assert_eq!(restored.pubkey(), kp.pubkey());
    }

    #[test]
    fn a_public_half_that_does_not_match_is_refused() {
        let mut bytes = Keypair::new().to_bytes();
        bytes[40] ^= 1;
        assert!(keypair_from_bytes(&bytes).is_err());
        assert!(keypair_from_bytes(&bytes[..63]).is_err());
    }
}
