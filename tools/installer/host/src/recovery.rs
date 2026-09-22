//! Leaving Couch recovery, for someone with no terminal and no instructions.
//!
//! A runtime update that fails its health check rolls back correctly, but on
//! images whose bootstrap predates the rollback fix the reboot lands in
//! recovery with the bootloader control block's `boot-recovery` flag still
//! armed. Recovery keeps that flag on purpose, so every following boot comes
//! back to the COUCH RECOVERY screen until somebody clears it. The documented
//! way out is two commands typed into the root shell recovery offers on USB
//! serial; this action is those two commands, with the checks and the refusals
//! around them, behind a first-menu entry.
//!
//! What it may do to a remote is deliberately tiny: it writes the first 512
//! bytes of `mmcblk0p10` with zeros, reads them back, and restarts the remote.
//! It never touches another partition, never writes anything else, and never
//! retries a write. Everything else it sends is a read-only probe, and every
//! command it can send is a constant in [`shell`].

pub mod discover;
pub mod port;
pub mod shell;

/// One COM port record, read by the Windows registry reader that already
/// serves the installer's driver pre-flight and classified in [`discover`].
pub use discover::windows::Record as SerialPortRecord;

use crate::{
    frontend::{Choice, Ui},
    session::{Phase, SessionGuard},
};
use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;

/// What to do when nothing is found, phrased for someone whose remote is stuck.
const NOT_FOUND: &str = "No remote in Couch recovery is connected to this computer.\n\n\
     Check that the remote's screen shows COUCH RECOVERY, that the USB cable is plugged into \
     both the remote and this computer, and that the cable is a data cable rather than a \
     charge-only one. If the screen is off, hold the side Power button until it turns on.";

fn choice(label: &str, detail: &str) -> Choice {
    Choice {
        label: label.into(),
        detail: detail.into(),
    }
}

fn marker() -> Result<String> {
    let mut value = [0; 16];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
    Ok(format!(
        "COUCH-RECOVERY-{}",
        crate::public_inputs::hex(&value)
    ))
}

/// Offer to look again, or to stop. `false` means the user chose to stop.
fn look_again(ui: &mut Ui, title: &str, body: &str) -> Result<bool> {
    Ok(ui.choose(
        title,
        body,
        &[
            choice("Look again", "Nothing has been opened or written."),
            choice("Stop", "Leave the remote exactly as it is."),
        ],
    )? == 0)
}

/// Find the single remote sitting in recovery, or return `None` when the user
/// chose to stop. Nothing is opened until exactly one candidate is found.
fn find(ui: &mut Ui) -> Result<Option<discover::Remote>> {
    let mut first = true;
    loop {
        if first {
            let start = ui.choose(
                "Connect the remote by USB while it shows COUCH RECOVERY",
                "Plug the remote into this computer with its USB cable while its screen shows \
                 COUCH RECOVERY. This only looks at the remote; nothing is written to it until \
                 you say so on a later screen.",
                &[
                    choice("Find my remote", "Looks for one connected remote."),
                    choice("Go back", "Returns to the first menu."),
                ],
            )?;
            if start == 1 {
                return Ok(None);
            }
            first = false;
        }
        ui.progress(0, "Looking for a remote in Couch recovery", 0, 0)?;
        let found = match discover::candidates() {
            Ok(found) => found,
            Err(error) => {
                let body = format!(
                    "This computer could not be asked which remotes are connected: {error:#}"
                );
                if look_again(ui, "Could not look for your remote", &body)? {
                    continue;
                }
                return Ok(None);
            }
        };
        match found.len() {
            1 => return Ok(Some(found.into_iter().next().expect("one candidate"))),
            0 => {
                if look_again(ui, "No remote in recovery found", NOT_FOUND)? {
                    continue;
                }
                return Ok(None);
            }
            count => {
                let places: Vec<String> = found
                    .iter()
                    .map(|remote| format!("  {} ({})", remote.location, remote.label))
                    .collect();
                let body = format!(
                    "{count} remotes in Couch recovery are connected to this computer:\n\n{}\n\n\
                     Disconnect all but the one you want to fix and look again. This action \
                     never chooses a remote for you.",
                    places.join("\n")
                );
                if look_again(ui, "More than one remote is connected", &body)? {
                    continue;
                }
                return Ok(None);
            }
        }
    }
}

/// The whole action, from the first menu to the restarted remote.
pub fn run(ui: &mut Ui) -> Result<()> {
    ui.set_steps(
        ["Find the remote", "Check the remote", "Leave recovery"]
            .map(String::from)
            .to_vec(),
    )?;
    let Some(remote) = find(ui)? else {
        return Ok(());
    };
    // The same private state root and device-wide lock the installer uses, so
    // this cannot run beside an installation that owns the remote.
    let parent = crate::orchestrator::state_root()?;
    let mut session =
        SessionGuard::create(&parent.join(format!("recovery-{}", &marker()?[15..31])))?;
    let _lease = crate::adapter::UsbLease::acquire(&session)?;
    ui.set_log_path(session.path().to_str().context("invalid session path")?)?;
    session.checkpoint(
        &json!({"event":"recovery_candidate","location":remote.location,"port":remote.label}),
    )?;
    let result = leave(ui, &remote, &mut session);
    if result.is_err() && !matches!(session.phase(), Phase::Failed) {
        let _ = session.transition(Phase::Failed, &json!({"event":"recovery_stopped"}));
    }
    result
}

fn leave(ui: &mut Ui, remote: &discover::Remote, session: &mut SessionGuard) -> Result<()> {
    ui.progress(
        1,
        "Checking that this really is a Couch recovery shell",
        0,
        0,
    )?;
    let mut shell = shell::Shell::new(port::open(&remote.path)?, &marker()?)?;
    let found = shell.verify()?;
    session.checkpoint(
        &json!({"event":"recovery_verified","cid":found.cid,"slot":found.slot.recorded()}),
    )?;
    let chosen = ui.choose(
        "Found your remote",
        &format!(
            "Your remote is in Couch recovery at {}, and it will start {} once it is out.\n\n\
             Leaving recovery clears the flag that keeps sending it back there. It changes \
             nothing else: your settings, your devices and the Couch version on the remote all \
             stay as they are.",
            remote.location,
            found.slot.describe()
        ),
        &[
            choice(
                "Leave recovery and restart the remote",
                "Clears the flag, checks it is clear, then restarts.",
            ),
            choice("Stop", "Leave the remote in recovery, unchanged."),
        ],
    )?;
    if chosen == 1 {
        session.checkpoint(&json!({"event":"recovery_declined"}))?;
        ui.progress(
            2,
            "Nothing was written. The remote is still in recovery.",
            0,
            0,
        )?;
        return Ok(());
    }
    ui.progress(2, "Clearing the flag and checking it is clear", 0, 0)?;
    let readback = shell.leave()?;
    session.checkpoint(&json!({"event":"recovery_left","readback":readback}))?;
    ui.progress(
        2,
        "Done - watch the remote restart by itself, and when Couch is back open Settings \
         → Updates to finish updating it.",
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_session_gets_its_own_unguessable_marker() {
        let first = marker().unwrap();
        assert_eq!(first.len(), 15 + 32);
        assert!(first.starts_with("COUCH-RECOVERY-"));
        assert!(first[15..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, marker().unwrap());
        // The marker is also what names the session directory.
        assert_eq!(first[15..31].len(), 16);
    }
}
