//! Restarting a running Couch into download mode, only when its next start is
//! a normal one.
//!
//! Couch's init arms the bootloader's recovery flag at the start of every boot
//! and clears it once the GUI has proved healthy, 90 to 150 s later; COUCH
//! RECOVERY keeps it armed. A remote restarted while the flag is armed never
//! runs the installer stage written to boot, because the bootloader starts
//! recovery instead. So every Couch restart, in every mode and on every
//! attempt, first asks the remote over USB for its storage ID and the flag
//! (a read-only query), and restarts it only once the flag reads clear.
//!
//! Where the remote cannot be asked, the user restarts it by hand after
//! confirming what its screen shows. The only write is on request, for a
//! remote whose flag will not clear by itself: the recovery action's own
//! clear and readback, after which it restarts straight into download mode.
use crate::{
    adapter::Worker,
    frontend::{Choice, ProgressUnit, Ui},
    session::SessionGuard,
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

/// SHA-256 of the first 512 bytes of the boot control block when the next
/// start is a normal one (all zeros).
pub const FLAG_CLEAR_SHA256: &str =
    "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560";
/// SHA-256 of the same block when the next start is COUCH RECOVERY:
/// `boot-recovery` followed by 499 zero bytes. Every writer of the block
/// writes one of these two whole blocks.
pub const FLAG_ARMED_SHA256: &str =
    "9418492e5b413376d2927de020eecc19a0be271687c4edb6437b7ce7268a2171";
/// Seconds of uptime by which a healthy Couch has cleared the flag.
const COUCH_SETTLE: u64 = 180;
/// An armed flag at this uptime or later will not clear by itself: the remote
/// is in COUCH RECOVERY, or its GUI never became healthy.
const STUCK_UPTIME: u64 = 170;
/// Queries before a silent remote is restarted by hand.
const QUERY_ATTEMPTS: u32 = 3;
/// Queries while waiting for a remote that answered earlier in this check to
/// answer again, for example after it restarted itself into recovery.
const RETURN_QUERIES: u32 = 20;
const QUERY_SPACING: Duration = Duration::from_secs(2);
/// Between two openings of the remote's serial function. On macOS, releasing
/// it from libusb re-enumerates the device, and the remote's shell respawns
/// one second after its terminal closes.
const REOPEN_PAUSE: Duration = Duration::from_secs(2);
/// Identity checkpoints kept per installation. The journal is bounded, and
/// the bootstrap recovery tool reads at most 128 events.
const IDENTITY_RECORDS: usize = 16;

pub const STOPPED: &str = "Stopped before the remote was restarted. Nothing was written";
const OTHER_REMOTE: &str = "A different remote is now connected on the selected USB port. \
     Nothing was written. Connect only the remote you want to reinstall and run the installer \
     again";
/// A flag clear that did not finish cleanly. It is never retried.
const CLEAR_INTERRUPTED: &str = "Clearing the COUCH RECOVERY flag did not finish. The flag may \
     already be cleared; the remote was NOT restarted and nothing else was written. Hold the side \
     Power button until the remote turns off, start it again and run the installer again, or \
     choose My remote shows COUCH RECOVERY";
const OTHER_THAN_ENROLLED: &str = "Connected Couch CID differs from the retained enrollment; no \
     reboot attempted and nothing was written";

/// What the remote says its next start will be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootFlag {
    Clear,
    Armed,
    Unknown,
}
impl BootFlag {
    fn from_sha256(value: Option<&str>) -> Self {
        match value {
            Some(FLAG_CLEAR_SHA256) => BootFlag::Clear,
            Some(FLAG_ARMED_SHA256) => BootFlag::Armed,
            _ => BootFlag::Unknown,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            BootFlag::Clear => "clear",
            BootFlag::Armed => "armed",
            BootFlag::Unknown => "unknown",
        }
    }
}

/// Why the remote could not be asked. Nothing was written or restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Absent,
    NoSerialFunction,
    CannotOpen,
    NoAnswer,
}
impl Reason {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "absent" => Reason::Absent,
            "no_serial_function" => Reason::NoSerialFunction,
            "cannot_open" => Reason::CannotOpen,
            "no_answer" => Reason::NoAnswer,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Reason::Absent => "absent",
            Reason::NoSerialFunction => "no_serial_function",
            Reason::CannotOpen => "cannot_open",
            Reason::NoAnswer => "no_answer",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub cid: String,
    pub flag: BootFlag,
    pub uptime: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SerialIdentity {
    Observed(Observation),
    Unavailable(Reason),
}

fn keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

/// Parse one `couch_identity` worker result. Only the exact shapes the worker
/// sends are accepted.
pub fn serial_identity(result: &Value) -> Result<SerialIdentity> {
    ensure!(
        result["event"] == "couch_identity",
        "unexpected Couch identity result"
    );
    match result["result"].as_str() {
        Some("observed") => {
            ensure!(
                keys(result) == ["boot_flag_sha256", "cid", "event", "result", "uptime"],
                "invalid Couch identity result"
            );
            let cid = result["cid"].as_str().unwrap_or_default();
            ensure!(
                cid.len() == 32
                    && cid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && cid != "0".repeat(32)
                    && cid != "f".repeat(32),
                "The remote answered over USB with an invalid storage ID. Nothing was written"
            );
            let flag = match &result["boot_flag_sha256"] {
                Value::Null => None,
                Value::String(value)
                    if value.len() == 64
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
                {
                    Some(value.as_str())
                }
                _ => bail!("invalid Couch boot flag digest"),
            };
            let uptime = match &result["uptime"] {
                Value::Null => None,
                value => Some(
                    value
                        .as_u64()
                        .filter(|seconds| *seconds < 1_000_000_000)
                        .context("invalid Couch uptime")?,
                ),
            };
            Ok(SerialIdentity::Observed(Observation {
                cid: cid.into(),
                flag: BootFlag::from_sha256(flag),
                uptime,
            }))
        }
        Some("unavailable") => {
            ensure!(
                keys(result) == ["event", "reason", "result"],
                "invalid Couch identity result"
            );
            Ok(SerialIdentity::Unavailable(
                result["reason"]
                    .as_str()
                    .and_then(Reason::parse)
                    .context("invalid Couch identity reason")?,
            ))
        }
        _ => bail!("invalid Couch identity result"),
    }
}

/// What to do with one observation of the remote.
#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    /// The next start is a normal one: restart now.
    Restart,
    /// The flag is armed on a remote that started recently: wait this many
    /// seconds for Couch to clear it, then ask again.
    Wait(u64),
    /// The flag is armed on a remote that has been up long enough to have
    /// cleared it: it is in COUCH RECOVERY or never became healthy.
    Stuck,
    /// Still armed after a wait, on a remote that has restarted meanwhile or
    /// reports no uptime.
    NotReady,
    /// The remote answered, but not with a known flag value: its screen has
    /// to be confirmed before it is restarted.
    Confirm,
}
/// `waited` is set once this check has already waited for the remote to
/// finish starting; `retry` when the remote has only just come back by itself
/// after a missed download window.
pub fn readiness(observation: &Observation, waited: bool, retry: bool) -> Readiness {
    match (observation.flag, observation.uptime) {
        (BootFlag::Clear, _) => Readiness::Restart,
        // An unknown flag says nothing about readiness, so a remote that has
        // not been up three minutes gets them before the user is asked to
        // confirm; one that just came back with no uptime gets the full wait.
        (BootFlag::Unknown, Some(uptime)) if uptime < COUCH_SETTLE && !waited => {
            Readiness::Wait(COUCH_SETTLE - uptime)
        }
        (BootFlag::Unknown, None) if retry && !waited => Readiness::Wait(COUCH_SETTLE),
        (BootFlag::Unknown, _) => Readiness::Confirm,
        (BootFlag::Armed, Some(uptime)) if uptime >= STUCK_UPTIME => Readiness::Stuck,
        (BootFlag::Armed, _) if waited => Readiness::NotReady,
        (BootFlag::Armed, uptime) => Readiness::Wait(COUCH_SETTLE - uptime.unwrap_or(0)),
    }
}

/// The USB operations a Couch restart needs, so the sequence can be tested
/// without a device.
pub trait CouchPort {
    /// One read-only `couch_identity` result.
    fn identify(&mut self, bound: &Value, ui: &mut Ui) -> Result<Value>;
    /// The one-shot `couch_reboot`, which re-reads the CID before rebooting.
    fn reboot(&mut self, bound: &Value, cid: &str, ui: &mut Ui) -> Result<Value>;
    /// The one-shot `couch_clear_flag`, which re-reads the CID and the flag
    /// before clearing it.
    fn clear(&mut self, bound: &Value, cid: &str, ui: &mut Ui) -> Result<Value>;
    /// Whether the clear can be offered on this computer.
    fn can_clear(&self) -> bool;
    fn pause(&mut self, duration: Duration);
}
impl CouchPort for Worker {
    fn identify(&mut self, bound: &Value, ui: &mut Ui) -> Result<Value> {
        crate::orchestrator::simple(
            self,
            json!({"op":"couch_identify","candidate":bound}),
            "couch_identity",
            25,
            ui,
            1,
        )
    }
    fn reboot(&mut self, bound: &Value, cid: &str, ui: &mut Ui) -> Result<Value> {
        crate::orchestrator::simple(
            self,
            json!({"op":"couch_reboot","candidate":bound,"cid":cid}),
            "couch_reboot",
            20,
            ui,
            1,
        )
    }
    fn clear(&mut self, bound: &Value, cid: &str, ui: &mut Ui) -> Result<Value> {
        crate::orchestrator::simple(
            self,
            json!({"op":"couch_clear_flag","candidate":bound,"cid":cid}),
            "couch_flag_cleared",
            180,
            ui,
            1,
        )
    }
    /// The clear goes through libusb only. On Windows, which binds its own
    /// serial driver to Couch's USB connection, it is not offered until that
    /// route has been tested on hardware.
    fn can_clear(&self) -> bool {
        !cfg!(windows)
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// What the worker's flag clear did.
#[derive(Debug, PartialEq, Eq)]
pub enum FlagCleared {
    /// Written, read back as zeros and queried clear; carries the readback.
    Cleared(String),
    /// It was already clear, so nothing was written.
    AlreadyClear,
    /// The remote could not be asked before any write.
    Unavailable(Reason),
}
pub fn flag_cleared(result: &Value) -> Result<FlagCleared> {
    ensure!(
        result["event"] == "couch_flag_cleared",
        "unexpected Couch flag result"
    );
    Ok(match result["result"].as_str() {
        Some("cleared") => {
            ensure!(
                keys(result) == ["event", "readback", "result"],
                "invalid Couch flag result"
            );
            let readback = result["readback"].as_str().unwrap_or_default();
            ensure!(
                readback.len() <= 512 && !readback.chars().any(char::is_control),
                "invalid Couch flag readback"
            );
            FlagCleared::Cleared(readback.into())
        }
        Some("already_clear") => {
            ensure!(
                keys(result) == ["event", "result"],
                "invalid Couch flag result"
            );
            FlagCleared::AlreadyClear
        }
        Some("unavailable") => {
            ensure!(
                keys(result) == ["event", "reason", "result"],
                "invalid Couch flag result"
            );
            FlagCleared::Unavailable(
                result["reason"]
                    .as_str()
                    .and_then(Reason::parse)
                    .context("invalid Couch flag reason")?,
            )
        }
        _ => bail!("invalid Couch flag result"),
    })
}

/// The storage ID the restarted remote must keep, and what was journaled.
pub struct CouchBinding {
    expected: Option<String>,
    /// `expected` came from a saved enrollment (Reinstall, Restore), not from
    /// this remote's own answer.
    enrolled: bool,
    /// The remote was restarted (over USB or by hand) for an earlier attempt.
    restarted: bool,
    /// This installation cleared the remote's COUCH RECOVERY flag.
    flag_cleared: bool,
    recorded: usize,
    last: Option<(String, &'static str)>,
}
impl CouchBinding {
    /// Reinstall and Restore: the remote must report the enrolled CID.
    pub fn enrolled(cid: &str) -> Self {
        Self {
            expected: Some(cid.into()),
            enrolled: true,
            restarted: false,
            flag_cleared: false,
            recorded: 0,
            last: None,
        }
    }
    /// No saved enrollment: the first CID the remote reports binds it.
    pub fn unbound() -> Self {
        Self {
            expected: None,
            enrolled: false,
            restarted: false,
            flag_cleared: false,
            recorded: 0,
            last: None,
        }
    }
    /// The CID download mode must report, when one is known.
    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }
    /// What this installation has done to the remote so far, for a stop or a
    /// failure before its next restart.
    fn untouched(&self) -> &'static str {
        match (self.flag_cleared, self.restarted) {
            (false, false) => "Nothing was written and the remote was not restarted",
            (false, true) => {
                "Nothing was written to the remote; it was restarted once already, for an \
                 earlier attempt to reach download mode"
            }
            (true, false) => {
                "Nothing was written to the remote except clearing its COUCH RECOVERY flag, and \
                 it was not restarted"
            }
            (true, true) => {
                "Nothing was written to the remote except clearing its COUCH RECOVERY flag; it \
                 was restarted once already, for an earlier attempt to reach download mode"
            }
        }
    }
    /// The refusal when the user stops before the restart.
    fn stopped(&self) -> String {
        if self.restarted {
            format!(
                "Stopped before the remote was restarted again. {}",
                self.untouched()
            )
        } else {
            STOPPED.into()
        }
    }
    fn bind(&mut self, cid: &str) -> Result<()> {
        match &self.expected {
            None => self.expected = Some(cid.into()),
            Some(expected) => ensure!(
                expected == cid,
                "{}",
                if self.enrolled {
                    OTHER_THAN_ENROLLED
                } else {
                    OTHER_REMOTE
                }
            ),
        }
        Ok(())
    }
    /// Journal an answer that differs from the last one recorded, up to a cap.
    fn record(
        &mut self,
        session: &mut SessionGuard,
        bound: &Value,
        identity: &SerialIdentity,
    ) -> Result<()> {
        let (key, evidence) = match identity {
            SerialIdentity::Observed(seen) => (
                (seen.cid.clone(), seen.flag.name()),
                json!({"event":"couch_serial_identity","usb":bound,"result":"observed","cid":seen.cid,"boot_flag":seen.flag.name(),"uptime":seen.uptime}),
            ),
            SerialIdentity::Unavailable(reason) => (
                (String::new(), reason.name()),
                json!({"event":"couch_serial_identity","usb":bound,"result":"unavailable","reason":reason.name()}),
            ),
        };
        if self.last.as_ref() == Some(&key) || self.recorded >= IDENTITY_RECORDS {
            return Ok(());
        }
        session.checkpoint(&evidence)?;
        self.recorded += 1;
        self.last = Some(key);
        Ok(())
    }
}

fn choice(label: &str, detail: &str) -> Choice {
    Choice {
        label: label.into(),
        detail: detail.into(),
    }
}

/// Ask the remote, again a few times if it does not answer. After it has
/// answered once in this check, keep asking longer: it may be restarting.
fn ask(
    port: &mut impl CouchPort,
    bound: &Value,
    binding: &mut CouchBinding,
    answered: bool,
    session: &mut SessionGuard,
    ui: &mut Ui,
) -> Result<SerialIdentity> {
    let limit = if answered {
        RETURN_QUERIES
    } else {
        QUERY_ATTEMPTS
    };
    let mut attempt = 0;
    loop {
        let untouched = binding.untouched();
        let identity = serial_identity(
            &port
                .identify(bound, ui)
                .with_context(|| format!("Asking the remote over USB failed. {untouched}"))?,
        )?;
        binding.record(session, bound, &identity)?;
        attempt += 1;
        if matches!(identity, SerialIdentity::Observed(_)) || attempt >= limit {
            return Ok(identity);
        }
        ui.progress(
            1,
            if answered {
                "Waiting for the remote to answer over USB again"
            } else {
                "Asking the remote over USB again"
            },
            0,
            0,
        )?;
        port.pause(QUERY_SPACING);
    }
}

/// Count down to the end of Couch's start-up health check.
fn wait_for_start(port: &mut impl CouchPort, ui: &mut Ui, uptime: u64, seconds: u64) -> Result<()> {
    for second in 0..seconds {
        ui.progress_with_unit(
            1,
            "Waiting for Couch to finish starting",
            (uptime + second).min(COUCH_SETTLE),
            COUCH_SETTLE,
            ProgressUnit::Seconds,
        )?;
        port.pause(Duration::from_secs(1));
    }
    Ok(())
}

enum Confirmation {
    /// The remote answered but its flag is not a known value.
    Unknown,
    /// The remote could not be asked; the user restarts it.
    Manual(Reason),
}

/// The one screen that has the user confirm the remote's normal screen has
/// been up for three minutes. `false` means Stop.
fn confirm(ui: &mut Ui, confirmation: Confirmation) -> Result<bool> {
    const SCREEN: &str = "Check that the remote shows its normal Couch screen, not COUCH \
         RECOVERY, and has been on for at least three minutes.";
    let (body, proceed) = match confirmation {
        Confirmation::Unknown => (
            format!(
                "The remote answered over USB but did not say whether its next start is a \
                 normal one. {SCREEN} After Continue it is restarted over USB."
            ),
            choice("Continue", "Restart the remote over USB."),
        ),
        Confirmation::Manual(reason) => (
            format!(
                "{}This computer could not ask the remote over USB whether it is ready, so it \
                 must be restarted by hand. Keep USB connected. {SCREEN} After Continue, hold \
                 the side Power button until the remote turns off, then release it. If \
                 needed, hold Power until it starts again.\n\nA remote that keeps starting \
                 into COUCH RECOVERY cannot be reinstalled while this computer cannot ask it \
                 over USB.",
                if reason == Reason::NoSerialFunction {
                    "The selected USB device does not offer Couch's USB connection. If this \
                     remote is running Android, choose Stop and use Install with Android backup \
                     instead.\n\n"
                } else {
                    ""
                }
            ),
            choice(
                "Continue and watch USB",
                "Only the selected physical USB port can be captured.",
            ),
        ),
    };
    Ok(ui.choose(
        "Check the remote's screen",
        &body,
        &[
            proceed,
            choice(
                "Stop",
                "Leave the remote as it is. Nothing has been written.",
            ),
        ],
    )? == 0)
}

/// The remote would start COUCH RECOVERY next. `true` means check again.
/// `offer_clear` promises the clear only where it will be offered: the remote
/// reports its uptime, so the installer can tell when it is stuck.
fn not_ready(ui: &mut Ui, offer_clear: bool, untouched: &str) -> Result<bool> {
    let next = if offer_clear {
        "If it still reports COUCH RECOVERY then, the installer offers to clear that and \
         restart it straight into the installer."
    } else {
        "If it goes back to COUCH RECOVERY every time it starts, choose Stop, run the installer \
         again and choose My remote shows COUCH RECOVERY first."
    };
    Ok(ui.choose(
        "The remote is not ready yet",
        &format!(
            "The remote reports that it would start into COUCH RECOVERY next. That is normal for \
             about three minutes after Couch starts, and it is always the case while the screen \
             shows COUCH RECOVERY.\n\nWait until the remote has been on for three minutes, \
             whichever screen it shows, and check again. {next}\n\n{untouched}."
        ),
        &[
            choice("Check again", "Asks the remote again."),
            choice("Stop", "Leave the remote as it is."),
        ],
    )? == 0)
}

enum Stuck {
    Clear,
    CheckAgain,
    Stop,
}
/// The remote has been up for nearly three minutes or longer and still
/// starts COUCH RECOVERY next: it is in recovery, or its GUI never became
/// healthy, and Couch will not clear the flag itself.
fn stuck(ui: &mut Ui, untouched: &str) -> Result<Stuck> {
    Ok(
        match ui.choose(
            "The remote keeps starting into COUCH RECOVERY",
            &format!(
                "Your remote keeps starting into COUCH RECOVERY. The installer can clear that and \
                 restart it straight into the installer.\n\nIt has been on for nearly three \
                 minutes or longer and still reports that it would start COUCH RECOVERY next, so \
                 Couch is not going to clear that itself. Clearing writes only the flag that sends \
                 it there, exactly as My remote shows COUCH RECOVERY does, after the same checks, \
                 and checks that it reads back clear.\n\n{untouched}."
            ),
            &[
                choice(
                    "Clear it and restart into the installer",
                    "Clears the flag and checks it is clear; then the remote is restarted.",
                ),
                choice("Check again", "Asks the remote again."),
                choice("Stop", "Leave the remote as it is."),
            ],
        )? {
            0 => Stuck::Clear,
            1 => Stuck::CheckAgain,
            _ => Stuck::Stop,
        },
    )
}
/// The same remote on a computer where the clear is not offered. `true`
/// means check again.
fn stuck_without_clear(ui: &mut Ui, untouched: &str) -> Result<bool> {
    Ok(ui.choose(
        "The remote keeps starting into COUCH RECOVERY",
        &format!(
            "Your remote keeps starting into COUCH RECOVERY. On this computer the installer \
             cannot clear that for you yet.\n\nChoose Stop, run the installer again and choose \
             My remote shows COUCH RECOVERY, then reinstall once the remote has shown its normal \
             screen for three minutes. If it goes back to COUCH RECOVERY by itself every time, it \
             cannot be reinstalled from this computer yet; a Mac or Linux computer can clear the \
             flag during the reinstall.\n\n{untouched}."
        ),
        &[
            choice("Check again", "Asks the remote again."),
            choice("Stop", "Leave the remote as it is."),
        ],
    )? == 0)
}

/// Restart the remote over USB, re-checking its CID, or hand over to the user
/// where the restart itself cannot be sent.
fn request(
    port: &mut impl CouchPort,
    bound: &Value,
    binding: &mut CouchBinding,
    session: &mut SessionGuard,
    ui: &mut Ui,
) -> Result<()> {
    let cid = binding
        .expected()
        .context("no storage ID to restart the remote with")?
        .to_owned();
    port.pause(REOPEN_PAUSE);
    ui.progress(1, "Restarting the remote over USB", 0, 0)?;
    let restart = port.reboot(bound, &cid, ui).context(
        "Couch USB identity/restart failed or its delivery is ambiguous; no automatic retry was attempted",
    )?;
    session.checkpoint(&json!({"event":"couch_restart","usb":bound,"result":restart["result"]}))?;
    match restart["result"].as_str() {
        Some("requested") => {
            binding.restarted = true;
            Ok(())
        }
        Some("unavailable") => {
            ui.choose(
                "Restart the selected remote",
                "The remote is ready, but this computer cannot restart it over USB; no reboot \
                 command was sent. Keep USB connected. After Continue, hold the side Power \
                 button until the remote turns off, then release it. If needed, hold Power until \
                 it starts again.",
                &[choice(
                    "Continue and watch USB",
                    "Only the selected physical USB port can be captured.",
                )],
            )?;
            binding.restarted = true;
            Ok(())
        }
        _ => bail!("Invalid Couch restart result"),
    }
}

/// Restart the running Couch on the selected physical port into download
/// mode once its next start is a normal one. `retry` is set when the remote
/// has just come back by itself after a missed download window.
pub fn restart(
    port: &mut impl CouchPort,
    bound: &Value,
    binding: &mut CouchBinding,
    retry: bool,
    session: &mut SessionGuard,
    ui: &mut Ui,
) -> Result<()> {
    let mut waited = false;
    let mut answered = false;
    loop {
        ui.progress(1, "Checking the remote over USB", 0, 0)?;
        match ask(port, bound, binding, answered, session, ui)? {
            SerialIdentity::Unavailable(reason) => {
                if retry {
                    // It has only just started again; give its health check
                    // the same time before asking the user to look.
                    wait_for_start(port, ui, 0, COUCH_SETTLE)?;
                }
                ensure!(
                    confirm(ui, Confirmation::Manual(reason))?,
                    "{}",
                    binding.stopped()
                );
                session.checkpoint(&json!({"event":"couch_restart","usb":bound,"result":"manual","reason":reason.name()}))?;
                binding.restarted = true;
                return Ok(());
            }
            SerialIdentity::Observed(observation) => {
                binding.bind(&observation.cid)?;
                answered = true;
                match readiness(&observation, waited, retry) {
                    Readiness::Restart => return request(port, bound, binding, session, ui),
                    Readiness::Confirm => {
                        ensure!(confirm(ui, Confirmation::Unknown)?, "{}", binding.stopped());
                        return request(port, bound, binding, session, ui);
                    }
                    Readiness::Wait(seconds) => {
                        wait_for_start(port, ui, observation.uptime.unwrap_or(0), seconds)?;
                        waited = true;
                    }
                    Readiness::Stuck if !port.can_clear() => {
                        ensure!(
                            stuck_without_clear(ui, binding.untouched())?,
                            "{}",
                            binding.stopped()
                        );
                        waited = false;
                    }
                    Readiness::Stuck => match stuck(ui, binding.untouched())? {
                        Stuck::Stop => bail!("{}", binding.stopped()),
                        Stuck::CheckAgain => waited = false,
                        Stuck::Clear => {
                            let cid = observation.cid;
                            port.pause(REOPEN_PAUSE);
                            ui.progress(
                                1,
                                "Clearing the COUCH RECOVERY flag and checking it is clear",
                                0,
                                0,
                            )?;
                            // Journaled first, so a clear that is cut off is on record.
                            session.checkpoint(&json!({"event":"recovery_flag_clear_requested","usb":bound,"cid":cid}))?;
                            let cleared = port
                                .clear(bound, &cid, ui)
                                .and_then(|result| flag_cleared(&result))
                                .context(CLEAR_INTERRUPTED)?;
                            let evidence = match cleared {
                                // Nothing was written; ask the remote again.
                                FlagCleared::Unavailable(_) => {
                                    waited = false;
                                    continue;
                                }
                                FlagCleared::AlreadyClear => {
                                    json!({"event":"recovery_flag_cleared_for_reinstall","usb":bound,"cid":cid,"result":"already_clear"})
                                }
                                FlagCleared::Cleared(readback) => {
                                    binding.flag_cleared = true;
                                    json!({"event":"recovery_flag_cleared_for_reinstall","usb":bound,"cid":cid,"result":"cleared","readback":readback})
                                }
                            };
                            session.checkpoint(&evidence)?;
                            return request(port, bound, binding, session, ui);
                        }
                    },
                    Readiness::NotReady => {
                        ensure!(
                            not_ready(
                                ui,
                                observation.uptime.is_some() && port.can_clear(),
                                binding.untouched()
                            )?,
                            "{}",
                            binding.stopped()
                        );
                        waited = false;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::session::Phase;
    use sha2::{Digest, Sha256};
    use std::{cell::RefCell, collections::VecDeque, io::Cursor, rc::Rc};

    pub(crate) const CID: &str = "150100514d42333251aa11c0fe2b1d00";

    /// Everything the installer sends to the terminal, for reading back.
    #[derive(Clone, Default)]
    pub(crate) struct Screen(Rc<RefCell<Vec<u8>>>);
    impl std::io::Write for Screen {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Screen {
        fn events(&self) -> Vec<Value> {
            String::from_utf8(self.0.borrow().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        /// Every prompt as (title, kind, body, option labels).
        pub(crate) fn prompts(&self) -> Vec<(String, String, String, Vec<String>)> {
            let events = self.events();
            let mut body = String::new();
            let mut prompts = Vec::new();
            for event in events {
                if event["event"] == "state" {
                    body = event["detail"].as_str().unwrap_or_default().into();
                } else if event["event"] == "prompt" {
                    prompts.push((
                        event["title"].as_str().unwrap().into(),
                        event["kind"].as_str().unwrap().into(),
                        body.clone(),
                        event["options"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|o| o["label"].as_str().unwrap().to_string())
                            .collect(),
                    ));
                }
            }
            prompts
        }
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }
    }
    /// A terminal that answers each prompt in turn with `replies`.
    pub(crate) fn terminal(replies: &[&str]) -> (Ui, Screen) {
        let input: String = replies
            .iter()
            .enumerate()
            .map(|(index, value)| format!("{{\"id\":{},\"value\":\"{value}\"}}\n", index + 1))
            .collect();
        let screen = Screen::default();
        let mut ui = Ui::new(
            Box::new(Cursor::new(input.into_bytes())),
            Box::new(screen.clone()),
        );
        ui.set_steps(vec!["step".into(); 8]).unwrap();
        (ui, screen)
    }
    pub(crate) fn private_session() -> (tempfile::TempDir, SessionGuard) {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut session = SessionGuard::create(&root.path().join("session")).unwrap();
        session
            .transition(Phase::InputsVerified, &json!({"event":"inputs_verified"}))
            .unwrap();
        (root, session)
    }
    pub(crate) fn journal(session: &SessionGuard) -> Vec<Value> {
        let mut names: Vec<_> = std::fs::read_dir(session.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("event-"))
            .collect();
        names.sort();
        names
            .iter()
            .map(|name| {
                let event: Value =
                    serde_json::from_slice(&std::fs::read(session.path().join(name)).unwrap())
                        .unwrap();
                event["evidence"].clone()
            })
            .collect()
    }
    pub(crate) fn observed(cid: &str, flag: &str, uptime: Option<u64>) -> Value {
        json!({"event":"couch_identity","result":"observed","cid":cid,"boot_flag_sha256":flag,"uptime":uptime})
    }
    pub(crate) fn unavailable(reason: &str) -> Value {
        json!({"event":"couch_identity","result":"unavailable","reason":reason})
    }

    /// A remote that answers from a script and records what it was asked.
    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) answers: VecDeque<Value>,
        pub(crate) reboot: Option<Value>,
        pub(crate) cleared: VecDeque<Value>,
        pub(crate) no_clear: bool,
        pub(crate) log: Vec<String>,
        pub(crate) paused: Duration,
    }
    impl Script {
        pub(crate) fn with(answers: Vec<Value>) -> Self {
            Self {
                answers: answers.into(),
                ..Self::default()
            }
        }
    }
    impl CouchPort for Script {
        fn identify(&mut self, _: &Value, _: &mut Ui) -> Result<Value> {
            self.log.push("identify".into());
            // A scripted null is a worker that died mid-query.
            match self.answers.pop_front().expect("unscripted identity query") {
                Value::Null => anyhow::bail!("MTK worker stopped"),
                answer => Ok(answer),
            }
        }
        fn reboot(&mut self, _: &Value, cid: &str, _: &mut Ui) -> Result<Value> {
            self.log.push(format!("reboot {cid}"));
            Ok(self
                .reboot
                .clone()
                .unwrap_or(json!({"event":"couch_reboot","result":"requested"})))
        }
        fn clear(&mut self, _: &Value, cid: &str, _: &mut Ui) -> Result<Value> {
            self.log.push(format!("clear {cid}"));
            // A scripted null is a worker that stopped during the clear.
            match self.cleared.pop_front().unwrap_or(
                json!({"event":"couch_flag_cleared","result":"cleared","readback":"\\0  \\0"}),
            ) {
                Value::Null => anyhow::bail!("MTK worker stopped"),
                result => Ok(result),
            }
        }
        fn can_clear(&self) -> bool {
            !self.no_clear
        }
        fn pause(&mut self, duration: Duration) {
            self.paused += duration;
        }
    }
    fn port() -> Value {
        json!({"bus":1,"address":7,"ports":[4,2],"vid":0x0e8d,"pid":0x201c})
    }

    #[test]
    fn flag_constants_are_the_digests_of_the_only_two_blocks_couch_writes() {
        assert_eq!(
            format!("{:x}", Sha256::digest([0u8; 512])),
            FLAG_CLEAR_SHA256
        );
        let mut armed = b"boot-recovery".to_vec();
        armed.resize(512, 0);
        assert_eq!(format!("{:x}", Sha256::digest(&armed)), FLAG_ARMED_SHA256);
    }

    #[test]
    fn serial_identity_accepts_only_exact_worker_results() {
        assert_eq!(
            serial_identity(&observed(CID, FLAG_CLEAR_SHA256, Some(1900))).unwrap(),
            SerialIdentity::Observed(Observation {
                cid: CID.into(),
                flag: BootFlag::Clear,
                uptime: Some(1900)
            })
        );
        let flag = |value: Value| {
            let mut result = observed(CID, FLAG_CLEAR_SHA256, Some(5));
            result["boot_flag_sha256"] = value;
            match serial_identity(&result) {
                Ok(SerialIdentity::Observed(seen)) => Some(seen.flag),
                _ => None,
            }
        };
        assert_eq!(flag(json!(FLAG_ARMED_SHA256)), Some(BootFlag::Armed));
        // Missing tools, or any other block, leave the flag unknown.
        assert_eq!(flag(Value::Null), Some(BootFlag::Unknown));
        assert_eq!(
            flag(json!(format!("{:x}", Sha256::digest(b"")))),
            Some(BootFlag::Unknown)
        );
        assert_eq!(flag(json!(FLAG_CLEAR_SHA256.to_uppercase())), None);
        assert_eq!(flag(json!("clear")), None);
        let mut no_uptime = observed(CID, FLAG_CLEAR_SHA256, None);
        assert!(matches!(
            serial_identity(&no_uptime).unwrap(),
            SerialIdentity::Observed(Observation { uptime: None, .. })
        ));
        no_uptime["uptime"] = json!(-1);
        assert!(serial_identity(&no_uptime).is_err());
        for cid in [
            CID.to_uppercase(),
            "0".repeat(32),
            "f".repeat(32),
            CID[..30].to_string(),
        ] {
            let error = serial_identity(&observed(&cid, FLAG_CLEAR_SHA256, None)).unwrap_err();
            assert!(error.to_string().contains("invalid storage ID"), "{error}");
        }
        let mut extra = observed(CID, FLAG_CLEAR_SHA256, None);
        extra["reboot"] = json!(true);
        assert!(serial_identity(&extra).is_err());
        let mut missing = observed(CID, FLAG_CLEAR_SHA256, None);
        missing.as_object_mut().unwrap().remove("uptime");
        assert!(serial_identity(&missing).is_err());
        for reason in ["absent", "no_serial_function", "cannot_open", "no_answer"] {
            assert!(matches!(
                serial_identity(&unavailable(reason)).unwrap(),
                SerialIdentity::Unavailable(found) if found.name() == reason
            ));
        }
        assert!(serial_identity(&unavailable("busy")).is_err());
        let mut chatty = unavailable("absent");
        chatty["cid"] = json!(CID);
        assert!(serial_identity(&chatty).is_err());
        assert!(serial_identity(&json!({"event":"couch_reboot","result":"requested"})).is_err());
    }

    #[test]
    fn readiness_rules() {
        let seen = |flag, uptime| Observation {
            cid: CID.into(),
            flag,
            uptime,
        };
        use BootFlag::*;
        for waited in [false, true] {
            for retry in [false, true] {
                let ready = |flag, uptime| readiness(&seen(flag, uptime), waited, retry);
                assert_eq!(ready(Clear, Some(3)), Readiness::Restart);
                assert_eq!(ready(Clear, None), Readiness::Restart);
                assert_eq!(ready(Unknown, Some(180)), Readiness::Confirm);
                assert_eq!(ready(Unknown, Some(900)), Readiness::Confirm);
                assert_eq!(ready(Armed, Some(170)), Readiness::Stuck);
                assert_eq!(ready(Armed, Some(4000)), Readiness::Stuck);
            }
        }
        for retry in [false, true] {
            assert_eq!(
                readiness(&seen(Armed, Some(30)), false, retry),
                Readiness::Wait(150)
            );
            assert_eq!(
                readiness(&seen(Armed, Some(169)), false, retry),
                Readiness::Wait(11)
            );
            assert_eq!(
                readiness(&seen(Armed, None), false, retry),
                Readiness::Wait(180)
            );
            assert_eq!(
                readiness(&seen(Armed, Some(30)), true, retry),
                Readiness::NotReady
            );
            assert_eq!(
                readiness(&seen(Armed, None), true, retry),
                Readiness::NotReady
            );
            // An unknown flag waits out the start-up health check before the
            // user is asked to confirm, but only once.
            assert_eq!(
                readiness(&seen(Unknown, Some(40)), false, retry),
                Readiness::Wait(140)
            );
            assert_eq!(
                readiness(&seen(Unknown, Some(179)), false, retry),
                Readiness::Wait(1)
            );
            assert_eq!(
                readiness(&seen(Unknown, Some(40)), true, retry),
                Readiness::Confirm
            );
            assert_eq!(
                readiness(&seen(Unknown, None), true, retry),
                Readiness::Confirm
            );
        }
        // With no uptime, only a remote that has just come back gets the wait.
        assert_eq!(
            readiness(&seen(Unknown, None), false, false),
            Readiness::Confirm
        );
        assert_eq!(
            readiness(&seen(Unknown, None), false, true),
            Readiness::Wait(180)
        );
    }
    #[test]
    fn reinstall_and_restore_wait_for_a_clear_flag_before_the_first_restart_and_every_retry() {
        for retry in [false, true] {
            let (_root, mut session) = private_session();
            let (mut ui, screen) = terminal(&[]);
            // The remote has just started: armed, 30 s up. It clears 150 s later.
            let mut remote = Script::with(vec![
                observed(CID, FLAG_ARMED_SHA256, Some(30)),
                observed(CID, FLAG_CLEAR_SHA256, Some(182)),
            ]);
            let mut binding = CouchBinding::enrolled(CID);
            restart(
                &mut remote,
                &port(),
                &mut binding,
                retry,
                &mut session,
                &mut ui,
            )
            .unwrap();
            assert_eq!(
                remote.log,
                ["identify", "identify", &format!("reboot {CID}")],
                "restarted before the flag was clear"
            );
            // 150 s of waiting, then the pause before the serial port reopens.
            assert_eq!(remote.paused, Duration::from_secs(150) + REOPEN_PAUSE);
            assert!(screen.prompts().is_empty());
            assert!(screen
                .text()
                .contains("Waiting for Couch to finish starting"));
            let events = journal(&session);
            let flags: Vec<_> = events
                .iter()
                .filter(|e| e["event"] == "couch_serial_identity")
                .map(|e| e["boot_flag"].clone())
                .collect();
            assert_eq!(flags, [json!("armed"), json!("clear")]);
            assert_eq!(events.last().unwrap()["event"], "couch_restart");
            assert_eq!(events.last().unwrap()["result"], "requested");
        }
    }

    #[test]
    fn an_enrolled_remote_answering_with_another_cid_is_never_restarted() {
        let (_root, mut session) = private_session();
        let (mut ui, _) = terminal(&[]);
        let mut remote = Script::with(vec![observed(
            &"34".repeat(16),
            FLAG_CLEAR_SHA256,
            Some(900),
        )]);
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the retained enrollment"),
            "{error}"
        );
        assert_eq!(remote.log, ["identify"]);
    }

    #[test]
    fn an_unbound_remote_is_bound_by_its_first_answer_and_must_keep_it() {
        let (_root, mut session) = private_session();
        let (mut ui, _) = terminal(&[]);
        let mut binding = CouchBinding::unbound();
        let mut remote = Script::with(vec![observed(CID, FLAG_CLEAR_SHA256, Some(900))]);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(binding.expected(), Some(CID));
        assert_eq!(remote.log.last().unwrap(), &format!("reboot {CID}"));
        let mut other = Script::with(vec![observed(
            &"34".repeat(16),
            FLAG_CLEAR_SHA256,
            Some(40),
        )]);
        let error = restart(
            &mut other,
            &port(),
            &mut binding,
            true,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("A different remote"),
            "{error}"
        );
        assert_eq!(other.log, ["identify"]);
    }

    #[test]
    fn an_armed_flag_on_a_remote_up_three_minutes_is_not_restarted() {
        // Stop: nothing is restarted and the installation stops.
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["2"]);
        let mut remote = Script::with(vec![observed(CID, FLAG_ARMED_SHA256, Some(600))]);
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), STOPPED);
        assert_eq!(remote.log, ["identify"]);
        assert_eq!(remote.paused, Duration::ZERO);
        let prompts = screen.prompts();
        assert_eq!(
            prompts[0].0,
            "The remote keeps starting into COUCH RECOVERY"
        );
        assert_eq!(
            prompts[0].3,
            [
                "Clear it and restart into the installer",
                "Check again",
                "Stop"
            ]
        );
        // Check again: asked afresh, restarted once it reads clear.
        let (mut ui, _) = terminal(&["1"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(600)),
            observed(CID, FLAG_CLEAR_SHA256, Some(700)),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(remote.log.len(), 3);
    }

    #[test]
    fn a_remote_stuck_in_recovery_is_cleared_and_restarted_straight_into_the_installer() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["0"]);
        let mut remote = Script::with(vec![observed(CID, FLAG_ARMED_SHA256, Some(600))]);
        restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(
            remote.log,
            [
                "identify".to_string(),
                format!("clear {CID}"),
                format!("reboot {CID}")
            ]
        );
        // Re-opening the serial function waits before the clear and the reboot.
        assert_eq!(remote.paused, REOPEN_PAUSE * 2);
        assert_eq!(screen.prompts().len(), 1);
        let events = journal(&session);
        let tail: Vec<_> = events[events.len() - 2..]
            .iter()
            .map(|e| e["event"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            tail,
            ["recovery_flag_cleared_for_reinstall", "couch_restart"]
        );
        assert_eq!(events[events.len() - 2]["result"], "cleared");
        assert_eq!(
            events[events.len() - 3],
            json!({"event":"recovery_flag_clear_requested","usb":port(),"cid":CID})
        );
        assert_eq!(events[events.len() - 2]["cid"], CID);
    }

    #[test]
    fn a_clear_that_could_not_reach_the_remote_asks_again_and_one_already_clear_restarts() {
        let (_root, mut session) = private_session();
        let (mut ui, _) = terminal(&["0", "2"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(600)),
            observed(CID, FLAG_ARMED_SHA256, Some(610)),
        ]);
        remote.cleared.push_back(
            json!({"event":"couch_flag_cleared","result":"unavailable","reason":"no_answer"}),
        );
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), STOPPED);
        assert_eq!(
            remote.log,
            [
                "identify".to_string(),
                format!("clear {CID}"),
                "identify".into()
            ]
        );
        let (mut ui, _) = terminal(&["0"]);
        let mut remote = Script::with(vec![observed(CID, FLAG_ARMED_SHA256, Some(600))]);
        remote
            .cleared
            .push_back(json!({"event":"couch_flag_cleared","result":"already_clear"}));
        restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(remote.log.last().unwrap(), &format!("reboot {CID}"));
        assert_eq!(
            journal(&session)
                .iter()
                .rev()
                .find(|e| e["event"] == "recovery_flag_cleared_for_reinstall")
                .unwrap()["result"],
            "already_clear"
        );
    }

    #[test]
    fn a_clear_that_fails_is_never_followed_by_a_restart() {
        for failure in [
            Value::Null,
            json!({"event":"couch_flag_cleared","result":"written"}),
        ] {
            let (_root, mut session) = private_session();
            let (mut ui, _) = terminal(&["0"]);
            let mut remote = Script::with(vec![observed(CID, FLAG_ARMED_SHA256, Some(600))]);
            remote.cleared.push_back(failure);
            let error = restart(
                &mut remote,
                &port(),
                &mut CouchBinding::enrolled(CID),
                false,
                &mut session,
                &mut ui,
            )
            .unwrap_err();
            let text = format!("{error:#}");
            assert!(text.starts_with(CLEAR_INTERRUPTED), "{text}");
            assert!(text.contains("may already be cleared") && text.contains("NOT restarted"));
            assert!(!remote.log.iter().any(|entry| entry.starts_with("reboot")));
            // The request is on record even though the clear never answered.
            let events = journal(&session);
            assert_eq!(
                events.last().unwrap()["event"],
                "recovery_flag_clear_requested"
            );
        }
    }

    #[test]
    fn where_the_clear_is_not_offered_a_stuck_remote_gets_the_manual_advice() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["0", "1"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(600)),
            observed(CID, FLAG_ARMED_SHA256, Some(640)),
        ]);
        remote.no_clear = true;
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), STOPPED);
        assert!(remote.log.iter().all(|entry| entry == "identify"));
        let prompts = screen.prompts();
        assert_eq!(prompts[0].3, ["Check again", "Stop"]);
        assert!(prompts[0].2.contains("cannot clear that for you yet"));
        assert!(prompts[0].2.contains("My remote shows COUCH RECOVERY"));
        // Nor is a later clear promised on the not-ready screen.
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(30)),
            observed(CID, FLAG_ARMED_SHA256, Some(20)),
        ]);
        remote.no_clear = true;
        assert!(restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
        assert!(!screen.prompts()[0].2.contains("offers to clear"));
    }

    #[test]
    fn after_a_clear_a_later_stop_says_the_flag_was_cleared() {
        let (_root, mut session) = private_session();
        let mut binding = CouchBinding::enrolled(CID);
        let (mut ui, screen) = terminal(&["0", "2"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(600)),
            observed(CID, FLAG_ARMED_SHA256, Some(900)),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        let error = restart(
            &mut remote,
            &port(),
            &mut binding,
            true,
            &mut session,
            &mut ui,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("except clearing its COUCH RECOVERY flag"),
            "{error}"
        );
        let prompts = screen.prompts();
        assert!(prompts[0].2.contains("nearly three minutes or longer"));
        assert!(prompts[1]
            .2
            .contains("except clearing its COUCH RECOVERY flag"));
    }

    #[test]
    fn a_young_remote_still_armed_after_the_wait_is_not_offered_the_clear() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, Some(100)),
            observed(CID, FLAG_ARMED_SHA256, Some(30)),
        ]);
        assert!(restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
        let prompts = screen.prompts();
        assert_eq!(prompts[0].0, "The remote is not ready yet");
        assert_eq!(prompts[0].3, ["Check again", "Stop"]);
        assert!(!remote.log.iter().any(|entry| entry.starts_with("clear")));
    }

    #[test]
    fn flag_clear_results_are_parsed_exactly() {
        assert_eq!(
            flag_cleared(
                &json!({"event":"couch_flag_cleared","result":"cleared","readback":"\\0"})
            )
            .unwrap(),
            FlagCleared::Cleared("\\0".into())
        );
        assert_eq!(
            flag_cleared(&json!({"event":"couch_flag_cleared","result":"already_clear"})).unwrap(),
            FlagCleared::AlreadyClear
        );
        assert_eq!(
            flag_cleared(
                &json!({"event":"couch_flag_cleared","result":"unavailable","reason":"absent"})
            )
            .unwrap(),
            FlagCleared::Unavailable(Reason::Absent)
        );
        for bad in [
            json!({"event":"couch_flag_cleared","result":"cleared"}),
            json!({"event":"couch_flag_cleared","result":"cleared","readback":"x\ny"}),
            json!({"event":"couch_flag_cleared","result":"already_clear","readback":""}),
            json!({"event":"couch_flag_cleared","result":"unavailable","reason":"later"}),
            json!({"event":"couch_flag_cleared","result":"written"}),
            json!({"event":"couch_reboot","result":"requested"}),
        ] {
            assert!(flag_cleared(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_remote_that_restarts_during_the_wait_is_asked_again_and_not_restarted() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["1"]);
        // Its GUI stayed unhealthy: it restarted into recovery during the wait.
        let mut answers = vec![observed(CID, FLAG_ARMED_SHA256, Some(20))];
        answers.extend((0..6).map(|_| unavailable("absent")));
        answers.push(observed(CID, FLAG_ARMED_SHA256, Some(15)));
        let mut remote = Script::with(answers);
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), STOPPED);
        assert!(remote.log.iter().all(|entry| entry == "identify"));
        assert_eq!(remote.log.len(), 8);
        assert_eq!(screen.prompts()[0].0, "The remote is not ready yet");
    }

    #[test]
    fn a_silent_remote_is_asked_three_times_before_the_manual_screen() {
        for (retry, reason) in [(false, "no_answer"), (true, "cannot_open")] {
            let (_root, mut session) = private_session();
            let (mut ui, screen) = terminal(&["0"]);
            let mut remote = Script::with((0..3).map(|_| unavailable(reason)).collect());
            let mut binding = CouchBinding::unbound();
            restart(
                &mut remote,
                &port(),
                &mut binding,
                retry,
                &mut session,
                &mut ui,
            )
            .unwrap();
            assert_eq!(remote.log, ["identify"; 3]);
            let settle = if retry { COUCH_SETTLE } else { 0 };
            assert_eq!(
                remote.paused,
                QUERY_SPACING * 2 + Duration::from_secs(settle)
            );
            assert_eq!(binding.expected(), None);
            let prompts = screen.prompts();
            assert_eq!(prompts.len(), 1);
            assert_eq!(prompts[0].3, ["Continue and watch USB", "Stop"]);
            assert!(prompts[0].2.contains("three minutes"));
            assert!(!prompts[0]
                .2
                .contains("does not offer Couch's USB connection"));
            let events = journal(&session);
            assert_eq!(
                events.last().unwrap(),
                &json!({"event":"couch_restart","usb":port(),"result":"manual","reason":reason})
            );
            // Three identical answers are journaled once.
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e["event"] == "couch_serial_identity")
                    .count(),
                1
            );
        }
        // No Couch serial function: the Android hint, and Stop stops.
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with((0..3).map(|_| unavailable("no_serial_function")).collect());
        let error = restart(
            &mut remote,
            &port(),
            &mut CouchBinding::unbound(),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), STOPPED);
        assert!(screen.prompts()[0]
            .2
            .starts_with("The selected USB device does not offer Couch's USB connection"));
    }

    #[test]
    fn a_remote_that_answers_on_the_second_try_is_not_sent_to_the_manual_screen() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&[]);
        let mut remote = Script::with(vec![
            unavailable("no_answer"),
            observed(CID, FLAG_CLEAR_SHA256, Some(400)),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert!(screen.prompts().is_empty());
        assert_eq!(remote.log.last().unwrap(), &format!("reboot {CID}"));
    }

    #[test]
    fn an_unknown_flag_needs_the_screen_confirmed_before_a_usb_restart() {
        let unknown = "e".repeat(64);
        for (reply, restarted) in [("0", true), ("1", false)] {
            let (_root, mut session) = private_session();
            let (mut ui, screen) = terminal(&[reply]);
            // Up 40 s: it gets the rest of the three minutes before the user
            // is asked, and is asked once more afterwards.
            let mut remote = Script::with(vec![
                observed(CID, &unknown, Some(40)),
                observed(CID, &unknown, Some(181)),
            ]);
            let result = restart(
                &mut remote,
                &port(),
                &mut CouchBinding::enrolled(CID),
                false,
                &mut session,
                &mut ui,
            );
            assert_eq!(result.is_ok(), restarted);
            let waited = Duration::from_secs(140);
            if restarted {
                assert_eq!(remote.log.len(), 3);
                assert_eq!(remote.paused, waited + REOPEN_PAUSE);
            } else {
                assert_eq!(remote.log.len(), 2);
                assert_eq!(remote.paused, waited);
            }
            let prompts = screen.prompts();
            assert_eq!(prompts[0].0, "Check the remote's screen");
            assert!(prompts[0]
                .2
                .contains("did not say whether its next start is a normal one"));
            assert_eq!(prompts[0].3, ["Continue", "Stop"]);
        }
    }
    #[test]
    fn an_unknown_flag_waits_on_the_first_attempt_and_on_a_retry() {
        let unknown = "e".repeat(64);
        // First attempt, no uptime: it cannot be told, so the user is asked.
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["0"]);
        let mut remote = Script::with(vec![observed(CID, &unknown, None)]);
        let mut binding = CouchBinding::enrolled(CID);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(remote.paused, REOPEN_PAUSE);
        assert_eq!(screen.prompts()[0].0, "Check the remote's screen");
        // A retry right after it came back: the full three minutes first.
        let (mut ui, _) = terminal(&["0"]);
        let mut remote = Script::with(vec![
            observed(CID, &unknown, None),
            observed(CID, &unknown, None),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            true,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(
            remote.paused,
            Duration::from_secs(COUCH_SETTLE) + REOPEN_PAUSE
        );
        assert_eq!(remote.log.len(), 3);
        // A retry that reports 20 s of uptime waits the other 160 s.
        let (mut ui, _) = terminal(&["0"]);
        let mut remote = Script::with(vec![
            observed(CID, &unknown, Some(20)),
            observed(CID, &unknown, Some(181)),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            true,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(remote.paused, Duration::from_secs(160) + REOPEN_PAUSE);
    }

    #[test]
    fn the_clear_is_offered_only_for_an_armed_flag_with_a_known_uptime() {
        // Unknown at 900 s: the confirmation screen, never the clear.
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with(vec![observed(CID, &"e".repeat(64), Some(900))]);
        assert!(restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
        assert_eq!(screen.prompts()[0].0, "Check the remote's screen");
        assert_eq!(remote.log, ["identify"]);
        // Silent: the manual screen, never the clear.
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with((0..3).map(|_| unavailable("no_answer")).collect());
        assert!(restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
        assert_eq!(screen.prompts()[0].3, ["Continue and watch USB", "Stop"]);
        assert!(remote.log.iter().all(|entry| entry == "identify"));
        // Armed, still young after the wait, no uptime: not ready, and no
        // promise of a clear the installer cannot judge.
        let (mut ui, screen) = terminal(&["1"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_ARMED_SHA256, None),
            observed(CID, FLAG_ARMED_SHA256, None),
        ]);
        assert!(restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
        let prompts = screen.prompts();
        assert_eq!(prompts[0].0, "The remote is not ready yet");
        assert!(
            !prompts[0].2.contains("offers to clear"),
            "{}",
            prompts[0].2
        );
        assert!(prompts[0].2.contains("My remote shows COUCH RECOVERY"));
    }

    #[test]
    fn a_stop_or_failure_says_what_was_already_done_to_the_remote() {
        let (_root, mut session) = private_session();
        let mut binding = CouchBinding::enrolled(CID);
        // A worker that dies mid-query: nothing written, nothing restarted.
        let (mut ui, _) = terminal(&[]);
        let mut remote = Script::with(vec![Value::Null]);
        let error = restart(
            &mut remote,
            &port(),
            &mut binding,
            false,
            &mut session,
            &mut ui,
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "Asking the remote over USB failed. Nothing was written and the remote was not \
             restarted: MTK worker stopped"
        );
        // The first attempt restarts it; a stop on the retry must not claim
        // it was never restarted.
        let (mut ui, _) = terminal(&["2"]);
        let mut remote = Script::with(vec![
            observed(CID, FLAG_CLEAR_SHA256, Some(400)),
            observed(CID, FLAG_ARMED_SHA256, Some(600)),
        ]);
        restart(
            &mut remote,
            &port(),
            &mut binding,
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        let error = restart(
            &mut remote,
            &port(),
            &mut binding,
            true,
            &mut session,
            &mut ui,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.starts_with("Stopped before the remote was restarted again"),
            "{error}"
        );
        assert!(error.contains("restarted once already"), "{error}");
        assert_ne!(error, STOPPED);
    }

    #[test]
    fn a_reboot_that_cannot_be_sent_hands_over_to_the_power_button() {
        let (_root, mut session) = private_session();
        let (mut ui, screen) = terminal(&["0"]);
        let mut remote = Script::with(vec![observed(CID, FLAG_CLEAR_SHA256, Some(400))]);
        remote.reboot = Some(json!({"event":"couch_reboot","result":"unavailable"}));
        restart(
            &mut remote,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .unwrap();
        assert_eq!(screen.prompts()[0].0, "Restart the selected remote");
        assert_eq!(journal(&session).last().unwrap()["result"], "unavailable");
        let mut broken = Script::with(vec![observed(CID, FLAG_CLEAR_SHA256, Some(400))]);
        broken.reboot = Some(json!({"event":"couch_reboot","result":"maybe"}));
        assert!(restart(
            &mut broken,
            &port(),
            &mut CouchBinding::enrolled(CID),
            false,
            &mut session,
            &mut ui,
        )
        .is_err());
    }

    #[test]
    fn identity_checkpoints_are_deduplicated_and_capped() {
        let (_root, mut session) = private_session();
        let mut binding = CouchBinding::unbound();
        let armed = SerialIdentity::Observed(Observation {
            cid: CID.into(),
            flag: BootFlag::Armed,
            uptime: Some(1),
        });
        let silent = SerialIdentity::Unavailable(Reason::NoAnswer);
        for _ in 0..3 {
            binding.record(&mut session, &port(), &armed).unwrap();
        }
        for index in 0..40 {
            binding
                .record(
                    &mut session,
                    &port(),
                    if index % 2 == 0 { &silent } else { &armed },
                )
                .unwrap();
        }
        let recorded = journal(&session)
            .iter()
            .filter(|e| e["event"] == "couch_serial_identity")
            .count();
        assert_eq!(recorded, IDENTITY_RECORDS);
    }
}
