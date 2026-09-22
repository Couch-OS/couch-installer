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
//! confirming what its screen shows. Nothing here writes to the remote.
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
pub fn readiness(observation: &Observation, waited: bool) -> Readiness {
    match (observation.flag, observation.uptime) {
        (BootFlag::Clear, _) => Readiness::Restart,
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
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// The storage ID the restarted remote must keep, and what was journaled.
pub struct CouchBinding {
    expected: Option<String>,
    /// `expected` came from a saved enrollment (Reinstall, Restore), not from
    /// this remote's own answer.
    enrolled: bool,
    recorded: usize,
    last: Option<(String, &'static str)>,
}
impl CouchBinding {
    /// Reinstall and Restore: the remote must report the enrolled CID.
    pub fn enrolled(cid: &str) -> Self {
        Self {
            expected: Some(cid.into()),
            enrolled: true,
            recorded: 0,
            last: None,
        }
    }
    /// No saved enrollment: the first CID the remote reports binds it.
    pub fn unbound() -> Self {
        Self {
            expected: None,
            enrolled: false,
            recorded: 0,
            last: None,
        }
    }
    /// The CID download mode must report, when one is known.
    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
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
        let identity = serial_identity(&port.identify(bound, ui)?)?;
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
fn not_ready(ui: &mut Ui) -> Result<bool> {
    Ok(ui.choose(
        "The remote is not ready yet",
        "The remote reports that it would start into COUCH RECOVERY next. That is normal for \
         about three minutes after Couch starts, and it is always the case while the screen \
         shows COUCH RECOVERY.\n\nIf the screen shows COUCH RECOVERY, choose Stop, then run the \
         installer again and choose My remote shows COUCH RECOVERY first. Otherwise wait until \
         Couch has shown its normal screen for three minutes and check again. A remote that \
         goes back to COUCH RECOVERY every time it starts cannot be reinstalled yet.\n\nNothing \
         has been written and the remote has not been restarted.",
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
    binding: &CouchBinding,
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
        Some("requested") => Ok(()),
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
                ensure!(confirm(ui, Confirmation::Manual(reason))?, "{STOPPED}");
                session.checkpoint(&json!({"event":"couch_restart","usb":bound,"result":"manual","reason":reason.name()}))?;
                return Ok(());
            }
            SerialIdentity::Observed(observation) => {
                binding.bind(&observation.cid)?;
                answered = true;
                match readiness(&observation, waited) {
                    Readiness::Restart => return request(port, bound, binding, session, ui),
                    Readiness::Confirm => {
                        ensure!(confirm(ui, Confirmation::Unknown)?, "{STOPPED}");
                        return request(port, bound, binding, session, ui);
                    }
                    Readiness::Wait(seconds) => {
                        wait_for_start(port, ui, observation.uptime.unwrap_or(0), seconds)?;
                        waited = true;
                    }
                    Readiness::Stuck | Readiness::NotReady => {
                        ensure!(not_ready(ui)?, "{STOPPED}");
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
            Ok(self.answers.pop_front().expect("unscripted identity query"))
        }
        fn reboot(&mut self, _: &Value, cid: &str, _: &mut Ui) -> Result<Value> {
            self.log.push(format!("reboot {cid}"));
            Ok(self
                .reboot
                .clone()
                .unwrap_or(json!({"event":"couch_reboot","result":"requested"})))
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
            assert_eq!(readiness(&seen(Clear, Some(3)), waited), Readiness::Restart);
            assert_eq!(readiness(&seen(Clear, None), waited), Readiness::Restart);
            assert_eq!(
                readiness(&seen(Unknown, Some(900)), waited),
                Readiness::Confirm
            );
            assert_eq!(readiness(&seen(Armed, Some(170)), waited), Readiness::Stuck);
            assert_eq!(
                readiness(&seen(Armed, Some(4000)), waited),
                Readiness::Stuck
            );
        }
        assert_eq!(
            readiness(&seen(Armed, Some(30)), false),
            Readiness::Wait(150)
        );
        assert_eq!(
            readiness(&seen(Armed, Some(169)), false),
            Readiness::Wait(11)
        );
        assert_eq!(readiness(&seen(Armed, None), false), Readiness::Wait(180));
        assert_eq!(readiness(&seen(Armed, Some(30)), true), Readiness::NotReady);
        assert_eq!(readiness(&seen(Armed, None), true), Readiness::NotReady);
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
        let (mut ui, screen) = terminal(&["1"]);
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
        assert_eq!(prompts[0].0, "The remote is not ready yet");
        assert!(
            prompts[0].2.contains("cannot be reinstalled yet"),
            "{}",
            prompts[0].2
        );
        // Check again: asked afresh, restarted once it reads clear.
        let (mut ui, _) = terminal(&["0"]);
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
        for (reply, restarted) in [("0", true), ("1", false)] {
            let (_root, mut session) = private_session();
            let (mut ui, screen) = terminal(&[reply]);
            let mut remote = Script::with(vec![observed(CID, &"e".repeat(64), Some(40))]);
            let result = restart(
                &mut remote,
                &port(),
                &mut CouchBinding::enrolled(CID),
                false,
                &mut session,
                &mut ui,
            );
            assert_eq!(result.is_ok(), restarted);
            assert_eq!(remote.log.len(), if restarted { 2 } else { 1 });
            let prompts = screen.prompts();
            assert_eq!(prompts[0].0, "Check the remote's screen");
            assert!(prompts[0]
                .2
                .contains("did not say whether its next start is a normal one"));
            assert_eq!(prompts[0].3, ["Continue", "Stop"]);
        }
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
