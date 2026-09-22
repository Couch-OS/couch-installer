//! The Couch recovery shell protocol.
//!
//! Recovery starts `busybox sh` with its standard input and output on the USB
//! serial gadget (`0e8d:201c`). That shell is *not* interactive: it prints no
//! banner and no prompt, so a bare newline produces nothing to match on. What
//! proves a shell is executing is a command coming back answered, so every
//! exchange here is framed by a per-session random marker and the handshake is
//! the first framed probe rather than a prompt string.
//!
//! The marker reaches the remote inside a `printf` format argument only, never
//! adjacent to the literal the reply carries. The remote's tty echoes what it
//! is sent, and that echo is therefore never mistaken for an answer - the same
//! trick the reinstall path's CID query uses.
//!
//! Every shell command this action can ever send is a constant in this file.

use anyhow::{bail, ensure, Context, Result};
use std::time::{Duration, Instant};

/// Read-only probes, run in this order before anything is written.
///
/// The boot image command line of every HA100 Couch image. It does not
/// distinguish recovery from a normal boot - both images carry it - but it does
/// distinguish an HA100 running Couch from some other CDC serial device that
/// happens to answer.
const PROBE_CMDLINE: &str = "cat /proc/cmdline";
/// Recovery mounts the Couch filesystem (`mmcblk0p23`) at `/mnt/alpine` and
/// checks for exactly this file before using it, so an answer here says a
/// Couch installation is attached. It does NOT tell recovery from a normal
/// boot: normal Couch's init mounts the same filesystem at the same place,
/// and its serial shell runs beside that mount. Only the boot control block
/// itself says which system starts next.
const PROBE_COUCH: &str = "test -f /mnt/alpine/opt/couch/stage2.sh && echo ok";
/// The runtime slot the next normal boot will start. An absent symlink is the
/// built-in base runtime, which is a legitimate state after a full rollback.
const PROBE_SLOT: &str = "readlink /mnt/alpine/opt/couch/runtime/current";
/// The `para` partition holding the bootloader control block.
const PROBE_BCB: &str = "test -b /dev/mmcblk0p10 && echo ok";
/// The storage identity the installer reads wherever else it binds a remote.
const PROBE_CID: &str = "cat /sys/block/mmcblk0/device/cid";

/// The only write this action performs: the first 512 bytes of the bootloader
/// control block, exactly as the device's own bootstrap clears it after a
/// healthy boot. `conv=notrunc` and `count=1` keep the rest of the partition,
/// including the `ENV_v1` area at 128 KiB, byte for byte.
const CLEAR_BCB: &str = "dd if=/dev/zero of=/dev/mmcblk0p10 bs=512 count=1 conv=notrunc; sync";
/// Read that block back, before the remote is restarted.
const READ_BACK: &str = "dd if=/dev/mmcblk0p10 bs=512 count=1 2>/dev/null | od -An -c | head -1";
/// Issued only after the readback showed zeros, and never framed: the remote
/// leaves the USB bus while executing it, so there is no answer to wait for.
const REBOOT: &str = "reboot -f";

/// Command line every HA100 Couch boot image carries.
const HA100_CMDLINE: &str = "bootopt=64S3,32S1,32S1";
/// Upper bound on one answer. Every command above answers in well under a
/// kilobyte; the bound stops a talkative or hostile port from growing the
/// buffer without limit.
const MAX_ANSWER: usize = 65536;
/// How long one read-only probe or the readback may take to answer.
const PROBE_BUDGET: Duration = Duration::from_secs(20);
/// How long the single 512-byte write and its `sync` may take.
const WRITE_BUDGET: Duration = Duration::from_secs(60);

/// The byte stream of one opened serial port. Implemented by the real port and
/// by the test fixture, so the protocol is exercised without a device.
pub trait Link {
    /// Deliver every byte or fail. A short or failed write is never retried.
    fn send(&mut self, bytes: &[u8]) -> Result<()>;
    /// Append whatever has arrived, waiting at most `timeout`. `Ok(0)` means
    /// nothing arrived in that window, which is not an error by itself.
    fn receive(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize>;
}

/// What the next normal boot will start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// `runtime/current` points at `slots/<archive sha256>`.
    Runtime(String),
    /// No `runtime/current`: the version built into the OS image.
    Base,
}

impl Slot {
    /// One plain-English phrase for the "found your remote" screen.
    pub fn describe(&self) -> String {
        match self {
            Slot::Runtime(id) => format!("the Couch version in update slot {}", &id[..12]),
            Slot::Base => "the Couch version built into its OS image".into(),
        }
    }
    /// Journal form: the exact symlink value, or its absence.
    pub fn recorded(&self) -> String {
        match self {
            Slot::Runtime(id) => format!("slots/{id}"),
            Slot::Base => "base".into(),
        }
    }
}

/// What the read-only probes established about the connected remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub slot: Slot,
    /// The remote's storage CID, recorded in the session journal so the run can
    /// be matched to a device afterwards.
    pub cid: String,
}

/// A framed exchange with the recovery shell.
pub struct Shell<L: Link> {
    link: L,
    marker: String,
    buffer: Vec<u8>,
    probe_budget: Duration,
    write_budget: Duration,
}

/// Locate `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&at| &haystack[at..at + needle.len()] == needle)
}

impl<L: Link> Shell<L> {
    /// `marker` must be unguessable and fresh for every session: it is what
    /// separates this session's answers from echoed input and from anything an
    /// earlier one left in the port.
    pub fn new(link: L, marker: &str) -> Result<Self> {
        ensure!(
            marker.len() >= 16
                && marker
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid recovery session marker"
        );
        Ok(Self {
            link,
            marker: marker.into(),
            buffer: Vec::new(),
            probe_budget: PROBE_BUDGET,
            write_budget: WRITE_BUDGET,
        })
    }

    /// The exact bytes one framed command puts on the wire.
    ///
    /// The marker only ever reaches the remote as a `printf` *argument*, so the
    /// echo of this line can never contain `<marker>:BEGIN` or
    /// `<marker>:<status>:END`; only the expanded output can.
    fn framed(&self, command: &str) -> String {
        format!(
            "\nprintf \"\\n%s:BEGIN\\n\" {marker}; {command}; printf \"\\n%s:%s:END\\n\" {marker} \"$?\"\n",
            marker = self.marker,
        )
    }

    /// Run one command and return its exit status and its output.
    fn run(&mut self, command: &str, budget: Duration) -> Result<(u32, String)> {
        // A fresh command owns the port: anything still buffered belongs to an
        // earlier exchange and must not be searched for this marker.
        self.buffer.clear();
        self.link.send(self.framed(command).as_bytes())?;
        let begin = format!("\n{}:BEGIN\n", self.marker);
        let end = format!("\n{}:", self.marker);
        let deadline = Instant::now() + budget;
        let mut block = [0u8; 4096];
        loop {
            if let Some(at) = find(&self.buffer, begin.as_bytes()) {
                let rest = &self.buffer[at + begin.len()..];
                if let Some(stop) = find(rest, end.as_bytes()) {
                    let tail = &rest[stop + end.len()..];
                    if let Some(line) = find(tail, b"END\n") {
                        let status = std::str::from_utf8(&tail[..line])
                            .ok()
                            .and_then(|value| value.strip_suffix(':'))
                            .and_then(|value| value.parse::<u32>().ok())
                            .context("recovery shell returned an unreadable exit status")?;
                        let output = String::from_utf8(rest[..stop].to_vec())
                            .context("recovery shell returned output that is not text")?;
                        return Ok((status, output));
                    }
                }
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .context("the remote did not answer its recovery shell in time")?;
            let count = self
                .link
                .receive(&mut block, left.min(Duration::from_millis(250)))?;
            // The remote's tty translates its own newlines; dropping carriage
            // returns keeps one canonical form for matching and for display.
            self.buffer
                .extend(block[..count].iter().copied().filter(|byte| *byte != b'\r'));
            ensure!(
                self.buffer.len() <= MAX_ANSWER,
                "the remote answered with more than a recovery shell ever sends"
            );
        }
    }

    /// Run a probe that must succeed, and return its trimmed answer.
    fn probe(&mut self, command: &str) -> Result<String> {
        let (status, output) = self.run(command, self.probe_budget)?;
        ensure!(status == 0, "recovery probe `{command}` failed");
        Ok(output.trim().to_owned())
    }

    /// Establish that the port carries a Couch recovery shell on an HA100, and
    /// read what the next normal boot will start. Nothing is written.
    ///
    /// The bare newline is what an operator sends first; it ends any partial
    /// line left in the shell's input before the first framed command, which is
    /// also this protocol's handshake.
    pub fn verify(&mut self) -> Result<Recovery> {
        self.link.send(b"\n")?;
        let cmdline = self.probe(PROBE_CMDLINE).context(
            "The device on that USB port did not answer as a Couch recovery shell. Check that \
             the remote still shows COUCH RECOVERY and that no other program is using its \
             serial port",
        )?;
        ensure!(
            cmdline.contains(HA100_CMDLINE),
            "That device answered, but it is not running an HA100 Couch boot image. Nothing was \
             written"
        );
        // `test ... && echo ok` answers a plain no by exiting non-zero, which
        // is an ordinary outcome here rather than a broken shell, so these two
        // read the answer instead of requiring a successful command.
        ensure!(
            self.run(PROBE_COUCH, self.probe_budget)?.1.trim() == "ok",
            "That remote is not in Couch recovery with its Couch installation attached. Nothing \
             was written"
        );
        let (status, value) = self.run(PROBE_SLOT, self.probe_budget)?;
        let value = value.trim();
        let hex_id = |id: &str| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let slot = match (status, value.strip_prefix("slots/")) {
            (0, Some(id)) if hex_id(id) => Slot::Runtime(id.into()),
            (status, _) if status != 0 && value.is_empty() => Slot::Base,
            _ => bail!(
                "The remote's next Couch version could not be read from recovery. Nothing was \
                 written"
            ),
        };
        ensure!(
            self.run(PROBE_BCB, self.probe_budget)?.1.trim() == "ok",
            "The remote's boot flag partition is missing. Nothing was written"
        );
        let cid = self.probe(PROBE_CID)?;
        ensure!(
            cid.len() == 32 && cid.bytes().all(|b| b.is_ascii_hexdigit()),
            "The remote's storage identity could not be read from recovery. Nothing was written"
        );
        Ok(Recovery {
            slot,
            cid: cid.to_ascii_lowercase(),
        })
    }

    /// Clear the flag, prove it is clear, and only then restart the remote.
    ///
    /// Returns the readback line that was accepted, for the session journal. A
    /// failure after the write is reported as such: the flag may already be
    /// clear, and the next step is a manual restart, never a second automatic
    /// attempt.
    pub fn leave(&mut self) -> Result<String> {
        let (_, written) = self.run(CLEAR_BCB, self.write_budget)?;
        let (status, readback) = self.run(READ_BACK, self.probe_budget)?;
        ensure!(
            status == 0 && zeroed(&readback),
            "The remote's boot flag did not read back as cleared, so the remote was NOT \
             restarted. Leave it showing COUCH RECOVERY and report this. The write reported \
             {written:?} and the block now reads {readback:?}"
        );
        self.link.send(format!("\n{REBOOT}\n").as_bytes())?;
        Ok(readback.trim().to_owned())
    }
}

/// True when `od -An -c` printed one line of nothing but NUL bytes.
fn zeroed(line: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    !fields.is_empty() && fields.iter().all(|field| *field == "\\0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const MARKER: &str = "COUCH-RECOVERY-0123456789abcdef0123456789abcdef";
    const SLOT_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const SLOT_LINE: &str =
        "slots/0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const CID: &str = "150100514d42333251aa11c0fe2b1d00";
    const ZEROS: &str = "\\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0";

    /// A recovery shell that answers from a script, echoing its input the way
    /// the remote's tty does and using the remote's CRLF line endings.
    #[derive(Default)]
    struct Fake {
        answers: Vec<(String, u32, String)>,
        pending: Vec<u8>,
        sent: Rc<RefCell<Vec<String>>>,
        mute: bool,
    }

    impl Fake {
        fn with(answers: &[(&str, u32, &str)]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .map(|(c, s, o)| ((*c).to_owned(), *s, (*o).to_owned()))
                    .collect(),
                ..Self::default()
            }
        }
    }

    impl Link for Fake {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            self.sent.borrow_mut().push(text.clone());
            // The device echoes every byte it is sent, CRLF translated.
            self.pending.extend(text.replace('\n', "\r\n").as_bytes());
            if self.mute {
                return Ok(());
            }
            for (command, status, output) in &self.answers {
                if text.contains(command.as_str()) {
                    let body = if output.is_empty() {
                        String::new()
                    } else {
                        format!("{output}\r\n")
                    };
                    self.pending.extend(
                        format!("\r\n{MARKER}:BEGIN\r\n{body}\r\n{MARKER}:{status}:END\r\n")
                            .as_bytes(),
                    );
                    return Ok(());
                }
            }
            Ok(())
        }
        fn receive(&mut self, buffer: &mut [u8], _timeout: Duration) -> Result<usize> {
            let count = self.pending.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.pending[..count]);
            self.pending.drain(..count);
            Ok(count)
        }
    }

    fn healthy() -> Vec<(&'static str, u32, &'static str)> {
        vec![
            (
                PROBE_CMDLINE,
                0,
                "bootopt=64S3,32S1,32S1 buildvariant=userdebug",
            ),
            (PROBE_COUCH, 0, "ok"),
            (PROBE_SLOT, 0, SLOT_LINE),
            (PROBE_BCB, 0, "ok"),
            (PROBE_CID, 0, CID),
        ]
    }

    fn shell(answers: &[(&str, u32, &str)]) -> (Shell<Fake>, Rc<RefCell<Vec<String>>>) {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mut fake = Fake::with(answers);
        fake.sent = sent.clone();
        let mut shell = Shell::new(fake, MARKER).unwrap();
        // Keep a fixture that never answers from spinning for the real budget.
        shell.probe_budget = Duration::from_millis(50);
        shell.write_budget = Duration::from_millis(50);
        (shell, sent)
    }

    #[test]
    fn echoed_command_text_is_never_read_as_an_answer() {
        // Nothing in what the remote is sent may match the patterns used to
        // find the reply, because the remote's tty echoes all of it back.
        let shell = Shell::new(Fake::default(), MARKER).unwrap();
        let request = shell.framed(PROBE_CMDLINE);
        assert!(request.contains(PROBE_CMDLINE));
        assert!(!request.contains(&format!("{MARKER}:BEGIN")));
        assert!(!request.contains(&format!("{MARKER}:0:END")));
        assert!(Shell::new(Fake::default(), "short").is_err());
        assert!(Shell::new(Fake::default(), "has spaces and is long enough").is_err());
    }

    #[test]
    fn verification_reads_the_slot_and_identity_without_writing() {
        let (mut shell, sent) = shell(&healthy());
        let found = shell.verify().unwrap();
        assert_eq!(found.slot, Slot::Runtime(SLOT_ID.into()));
        assert_eq!(found.cid, CID);
        assert_eq!(found.slot.recorded(), SLOT_LINE);
        assert!(found.slot.describe().contains("0f1e2d3c4b5a"));
        let text = sent.borrow().concat();
        for forbidden in ["dd ", "reboot", "of=/dev/"] {
            assert!(!text.contains(forbidden), "verification sent {forbidden}");
        }
    }

    #[test]
    fn an_absent_runtime_symlink_is_the_base_version() {
        let mut answers = healthy();
        answers[2] = (PROBE_SLOT, 1, "");
        let (mut shell, _) = shell(&answers);
        let found = shell.verify().unwrap();
        assert_eq!(found.slot, Slot::Base);
        assert_eq!(found.slot.recorded(), "base");
        assert!(Slot::Base.describe().contains("built into"));
    }

    #[test]
    fn every_probe_that_does_not_match_refuses() {
        let cases: Vec<(usize, (&str, u32, &str), &str)> = vec![
            (
                0,
                (PROBE_CMDLINE, 0, "console=ttyS0 root=/dev/sda1"),
                "not running an HA100 Couch boot image",
            ),
            (0, (PROBE_CMDLINE, 1, ""), "failed"),
            (1, (PROBE_COUCH, 1, ""), "not in Couch recovery"),
            (2, (PROBE_SLOT, 0, "slots/nonsense"), "next Couch version"),
            (2, (PROBE_SLOT, 0, ""), "next Couch version"),
            (2, (PROBE_SLOT, 0, "/opt/couch/runtime/base"), "next Couch"),
            (3, (PROBE_BCB, 1, ""), "boot flag partition is missing"),
            (4, (PROBE_CID, 0, "not-a-cid"), "storage identity"),
        ];
        for (index, replacement, expected) in cases {
            let mut answers = healthy();
            answers[index] = replacement;
            let (mut shell, sent) = shell(&answers);
            let error = format!("{:#}", shell.verify().unwrap_err());
            assert!(error.contains(expected), "{error} lacks {expected}");
            assert!(!sent.borrow().concat().contains("dd "));
        }
    }

    #[test]
    fn a_port_that_never_answers_refuses_instead_of_hanging() {
        let (mut shell, _) = shell(&healthy());
        shell.link.mute = true;
        let error = format!("{:#}", shell.verify().unwrap_err());
        assert!(
            error.contains("did not answer as a Couch recovery shell"),
            "{error}"
        );
    }

    #[test]
    fn leaving_recovery_clears_reads_back_and_only_then_restarts() {
        let mut answers = healthy();
        answers.push((CLEAR_BCB, 0, "1+0 records out"));
        answers.push((READ_BACK, 0, ZEROS));
        let (mut shell, sent) = shell(&answers);
        shell.verify().unwrap();
        assert_eq!(shell.leave().unwrap(), ZEROS);
        let text = sent.borrow().concat();
        let write = text.find("if=/dev/zero").unwrap();
        let read = text.find("dd if=/dev/mmcblk0p10").unwrap();
        let restart = text.find("reboot -f").unwrap();
        assert!(write < read && read < restart, "wrong command order");
        // Exactly one partition is ever named, and only its first block.
        // The check, the single write and its readback; nothing else.
        assert_eq!(text.matches("/dev/mmcblk0p10").count(), 3);
        assert_eq!(text.matches("of=/dev/").count(), 1);
        assert_eq!(text.matches("bs=512 count=1").count(), 2);
        assert!(!text.contains("mmcblk0p8") && !text.contains("mmcblk0p23"));
        assert_eq!(text.matches("reboot").count(), 1);
    }

    #[test]
    fn a_block_that_does_not_read_back_as_zero_is_not_restarted() {
        for line in ["\\0  \\0   b  \\0", "", "1+0 records in", "0000000"] {
            let mut answers = healthy();
            answers.push((CLEAR_BCB, 0, ""));
            answers.push((READ_BACK, 0, line));
            let (mut shell, sent) = shell(&answers);
            shell.verify().unwrap();
            let error = format!("{:#}", shell.leave().unwrap_err());
            assert!(error.contains("was NOT"), "{error}");
            assert!(!sent.borrow().concat().contains("reboot"));
        }
    }

    #[test]
    fn a_reinstall_clears_the_flag_with_exactly_these_commands() {
        // The worker that clears a stuck flag before a reinstall sends these
        // same two commands and applies the same zero check.
        // Compared line by line: a Windows checkout may end its lines in CRLF.
        let worker = include_str!("../../../couch_serial.py");
        for line in [
            format!("CLEAR_BCB = b'{CLEAR_BCB}'"),
            format!("READ_BACK = b'{READ_BACK}'"),
        ] {
            assert!(worker.lines().any(|found| found == line), "{line}");
        }
    }

    #[test]
    fn a_failed_readback_command_is_not_restarted() {
        let mut answers = healthy();
        answers.push((CLEAR_BCB, 0, ""));
        answers.push((READ_BACK, 127, "od: applet not found"));
        let (mut shell, sent) = shell(&answers);
        shell.verify().unwrap();
        assert!(shell.leave().is_err());
        assert!(!sent.borrow().concat().contains("reboot"));
    }
}
