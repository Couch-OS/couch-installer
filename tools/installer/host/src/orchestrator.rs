//! Native fresh-Android installer. Every mutation follows durable enrollment;
//! the Python worker is restricted to MTK and bounded USB setup transport.
use crate::{
    adapter::{self, UsbLease, Worker},
    android, assembly, couch_restart, dependencies, enrollment, enrollment_sources,
    frontend::{Choice, Ui},
    network,
    public_inputs::{self, create, decode, digest, hex},
    saved_enrollment,
    session::{self, Phase, SessionGuard},
    stage::Channel,
    stage_tls,
    transaction::{self, OriginalOs},
    vendor_transfer,
};
use anyhow::{ensure, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
fn random() -> Result<[u8; 32]> {
    let mut value = [0; 32];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
    Ok(value)
}
/// Raised when the selected USB port never showed a download-mode identity.
/// No write has happened at that point.
const DOWNLOAD_MODE_TIMEOUT: &str = "Remote did not enter download mode within 120 s. No boot \
     write occurred; check the cable, the USB port and power";
/// Download-mode entries attempted before giving up. The first time a preloader
/// appears on a Windows machine, Windows usually spends the whole download
/// window installing its serial-port driver; the second appearance is instant.
/// Startup is read-only, so restarting the remote again risks nothing.
const DOWNLOAD_ATTEMPTS: u32 = 3;
/// How long a remote may take to boot back to Android or Couch after a missed
/// download window before the installer stops waiting for it.
const RETURN_WAIT: u64 = 90;
/// Read-only Windows driver check before any device is opened. The worker
/// opens the preloader through the serial port Windows creates for it, or
/// through WinUSB when that was bound on purpose; this only warns when a
/// recorded instance carries some third driver. Returns `false` when the user
/// chose to stop; the installer then exits cleanly like Cancel.
#[cfg(windows)]
fn windows_driver_preflight(ui: &mut Ui) -> Result<bool> {
    use crate::windows_drivers::{assess, describe_couch, inventory, Assessment, COUCH, PRELOADER};
    let assessment = match inventory(PRELOADER) {
        Ok(preloader) => assess(&preloader),
        Err(error) => Assessment {
            ready: true,
            summary: format!("The preloader driver record could not be read: {error:#}"),
        },
    };
    if assessment.ready {
        return Ok(true);
    }
    let couch = match inventory(COUCH) {
        Ok(record) => describe_couch(&record),
        Err(error) => format!("could not be read: {error:#}"),
    };
    let body = format!(
        "{}\n\nThe installer opens the preloader either as the serial port Windows creates for it \
         (usbser) or through WinUSB, and never installs or replaces drivers. An instance bound to \
         another driver can be removed in Device Manager (View > Show hidden devices, then \
         Uninstall device, ticking the option to delete its driver software if offered) so that \
         Windows binds its serial-port driver the next time the preloader appears.\n\n\
         Android/Couch device (USB 0e8d:201c): {couch}",
        assessment.summary
    );
    let selected = ui.choose(
        "Windows USB driver check",
        &body,
        &[
            choice(
                "Continue anyway",
                "Windows may still create a serial port when the preloader appears on another port.",
            ),
            choice(
                "Stop",
                "Nothing is opened or written; run the installer again afterwards.",
            ),
        ],
    )?;
    Ok(selected == 0)
}
fn choice(label: &str, detail: &str) -> Choice {
    Choice {
        label: label.into(),
        detail: detail.into(),
    }
}
pub(crate) fn state_root() -> Result<PathBuf> {
    #[cfg(windows)]
    let path = PathBuf::from(
        std::env::var_os("LOCALAPPDATA").context("missing local application data directory")?,
    )
    .join("CouchInstaller");
    #[cfg(not(windows))]
    let path = PathBuf::from(std::env::var_os("HOME").context("missing home directory")?)
        .join(".couch-installer");
    if !path.exists() {
        session::create_private_parent(&path)?;
    }
    Ok(path)
}
pub(crate) fn simple(
    worker: &mut Worker,
    command: Value,
    event: &str,
    budget: u64,
    ui: &mut Ui,
    phase: usize,
) -> Result<Value> {
    worker.operation(Duration::from_secs(budget), |w| {
        w.send(&command)?;
        let result = enrollment::event(w, ui, phase)?;
        ensure!(result["event"] == event, "unexpected USB operation result");
        Ok(result)
    })
}
/// Spawn the MediaTek worker and have it prepare the verified loader. A worker
/// stops for good at its first failure, so every attempt starts a fresh one.
fn prepared_worker(
    dependencies: &dependencies::PreparedDependencies,
    script: &Path,
    prepared: &Path,
    session_dir: &Path,
    ui: &mut Ui,
) -> Result<Worker> {
    let mut command = adapter::mtk_worker(&dependencies.python);
    command
        .arg("-I")
        .arg("-B")
        .arg(dependencies::python_path(script)?)
        .arg("--events-stdio")
        .current_dir(session_dir);
    let mut worker = Worker::spawn(&mut command)?;
    simple(
        &mut worker,
        json!({"op":"prepare","checkout":dependencies::python_path(&dependencies.mtk_root)?,"loader":dependencies::python_path(&dependencies.owner_da)?,"loader_sha256":dependencies.owner_da_sha256,"preloader":dependencies::python_path(&prepared.join("bootstrap/preloader.img"))?,"preloader_sha256":"0ad0d14b7203d98a6567af7a022cfe5df5b6fcbba60cb4e9b4bc2ee569cf1069","libusb":dependencies::python_path(&dependencies.libusb)?}),
        "prepared",
        60,
        ui,
        1,
    )?;
    Ok(worker)
}
/// USB product IDs of the MediaTek preloader and download agent.
const DOWNLOAD_MODE_PIDS: [u64; 6] = [0x0003, 0x6000, 0x2000, 0x2001, 0x20ff, 0x3000];
/// What to tell someone asked to connect a running Couch when none is found.
/// A remote still in download mode shows up with a download-mode identity
/// instead: an earlier attempt stopped after its read-only capture (every
/// refusal there leaves the download agent running) and it needs a power
/// cycle before it can start Couch again.
fn connect_couch_prompt(devices: &[Value]) -> &'static str {
    if devices.iter().any(|device| {
        device["pid"]
            .as_u64()
            .is_some_and(|pid| DOWNLOAD_MODE_PIDS.contains(&pid))
    }) {
        "A remote connected to this computer is still in download mode from an earlier attempt. \
         If it is yours, hold its side Power button until it turns off, then start it again."
    } else {
        "Keep Couch powered on and connected through USB so its physical port can be selected."
    }
}
/// Wait for the selected physical port to show a download-mode identity, then
/// start the read-only download-agent session on it. Nothing is written here.
fn download_mode(worker: &mut Worker, bound: &Value, ui: &mut Ui) -> Result<Value> {
    let start = Instant::now();
    let candidate = loop {
        ensure!(
            start.elapsed() < Duration::from_secs(120),
            "{DOWNLOAD_MODE_TIMEOUT}"
        );
        let result = simple(worker, json!({"op":"enumerate"}), "candidates", 20, ui, 3)?;
        let found = result["devices"]
            .as_array()
            .context("invalid USB inventory")?
            .iter()
            .filter(|d| {
                d["bus"] == bound["bus"]
                    && d["ports"] == bound["ports"]
                    && d["pid"]
                        .as_u64()
                        .is_some_and(|pid| DOWNLOAD_MODE_PIDS.contains(&pid))
            })
            .collect::<Vec<_>>();
        ensure!(found.len() <= 1, "ambiguous selected USB port");
        if let Some(device) = found.first() {
            break (*device).clone();
        }
        ui.progress_with_unit(
            3,
            "Waiting for the selected remote on USB",
            start.elapsed().as_secs(),
            120,
            crate::frontend::ProgressUnit::Seconds,
        )?;
        thread::sleep(Duration::from_millis(20));
    };
    let connected = simple(
        worker,
        json!({"op":"start","candidate":candidate}),
        "connected",
        120,
        ui,
        3,
    )
    .map_err(|error| anyhow::anyhow!("USB download startup failed: {error:#}"))?;
    Ok(connected)
}
/// Whether the selected Android remote is back on ADB after a missed download
/// window. A restart is only issued again to a remote that came back by itself.
fn android_returned(adb: &Path, serial: &str, ui: &mut Ui) -> Result<bool> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(RETURN_WAIT) {
        if let Ok(devices) = android::discover(adb) {
            if devices
                .iter()
                .any(|d| d.serial == serial && d.state == "device")
            {
                return Ok(true);
            }
        }
        ui.progress_with_unit(
            3,
            "Waiting for the remote to return to Android",
            start.elapsed().as_secs(),
            RETURN_WAIT,
            crate::frontend::ProgressUnit::Seconds,
        )?;
        thread::sleep(Duration::from_secs(2));
    }
    Ok(false)
}
/// Whether a running Couch is back on its bound physical port after a missed
/// download window.
fn couch_returned(worker: &mut Worker, bound: &Value, ui: &mut Ui) -> Result<bool> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(RETURN_WAIT) {
        let result = simple(worker, json!({"op":"enumerate"}), "candidates", 20, ui, 3)?;
        let back = result["devices"]
            .as_array()
            .context("invalid USB inventory")?
            .iter()
            .any(|d| {
                d["bus"] == bound["bus"] && d["ports"] == bound["ports"] && d["pid"] == 0x201c
            });
        if back {
            return Ok(true);
        }
        ui.progress_with_unit(
            3,
            "Waiting for the remote to return to Couch",
            start.elapsed().as_secs(),
            RETURN_WAIT,
            crate::frontend::ProgressUnit::Seconds,
        )?;
        thread::sleep(Duration::from_millis(500));
    }
    Ok(false)
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    ensure!(
        digest(path)? == format!("{:x}", Sha256::digest(bytes)),
        "private artifact readback differs"
    );
    Ok(())
}
fn input_path(ui: &mut Ui, title: &str, body: &str) -> Result<PathBuf> {
    let value = ui.input(title, body, false)?;
    if let Some(rest) = value.strip_prefix("~/") {
        Ok(PathBuf::from(std::env::var_os("HOME").context("missing home directory")?).join(rest))
    } else {
        Ok(PathBuf::from(value.as_str()))
    }
}
/// Where the reinstall takes its Android enrollment from.
#[derive(Debug, PartialEq, Eq)]
enum EnrollmentChoice {
    Folder(PathBuf),
    /// Reinstall from what is on the remote now. Restore stock Android is not
    /// available for the remote afterwards.
    WithoutEnrollment,
}
/// Pick the saved Android enrollment. With `offer_fresh` (Reinstall, never
/// Restore) the operator may also continue without one, after confirming what
/// that gives up; without it this is the unchanged folder picker.
fn enrollment_source(
    ui: &mut Ui,
    state_root: &Path,
    offer_fresh: bool,
    skip_userdata: bool,
) -> Result<EnrollmentChoice> {
    const TITLE: &str = "Saved Android enrollment directory";
    const BODY: &str =
        "Choose the retained native enrollment or older verified Python backup folder.";
    let candidates =
        enrollment_sources::discover(state_root, enrollment_sources::remembered(state_root));
    loop {
        if candidates.is_empty() {
            if !offer_fresh {
                return Ok(EnrollmentChoice::Folder(input_path(ui, TITLE, BODY)?));
            }
            let picked = ui.choose(
                "Saved Android enrollment",
                "No saved Android enrollment was found on this computer. It is the folder the \
                 first Couch installation on this remote created while the remote still ran \
                 Android, and it usually lives on the computer that did that installation.",
                &[
                    choice(
                        "Continue without a saved enrollment",
                        "Reinstall Couch from what is on the remote now. Restore stock Android \
                         will not be available afterwards.",
                    ),
                    choice(
                        "Enter a folder path",
                        "Type the location of a copied enrollment folder yourself.",
                    ),
                ],
            )?;
            if picked == 1 {
                return Ok(EnrollmentChoice::Folder(input_path(ui, TITLE, BODY)?));
            }
        } else {
            let mut options: Vec<Choice> = candidates
                .iter()
                .map(|found| choice(&found.label(), &found.detail()))
                .collect();
            options.push(choice("Enter a folder path", "Type the location yourself."));
            if offer_fresh {
                options.push(choice(
                    "I don't have a saved enrollment",
                    "Reinstall Couch without one. Restore stock Android will not be available \
                     afterwards.",
                ));
            }
            // The manual option always follows the candidates, so a single
            // candidate is still an explicit selection rather than something
            // applied on the operator's behalf.
            let picked = ui.choose(
                TITLE,
                "Confirm which retained enrollment to import, or enter another folder. Whichever you pick is verified in full before use.",
                &options,
            )?;
            if !(offer_fresh && picked == candidates.len() + 1) {
                return Ok(EnrollmentChoice::Folder(match enrollment_sources::resolve(
                    &candidates,
                    picked,
                ) {
                    Some(path) => path,
                    None => input_path(ui, TITLE, BODY)?,
                }));
            }
        }
        if confirm_without_enrollment(ui, skip_userdata)? {
            return Ok(EnrollmentChoice::WithoutEnrollment);
        }
    }
}
/// What a reinstall without a saved enrollment keeps and gives up. `false`
/// means go back to the enrollment picker.
fn confirm_without_enrollment(ui: &mut Ui, skip_userdata: bool) -> Result<bool> {
    let data = if skip_userdata {
        "Your current Couch data will not be backed up, as you chose; its current settings and \
         paired devices will be lost."
    } else {
        "Your current Couch data is also backed up, as you chose."
    };
    let body = format!(
        "Couch will be reinstalled using only what is on the remote now.\n\nKept: before \
         anything is written (except the COUCH RECOVERY flag, and only if you choose to clear \
         it), the remote's factory calibration (its Wi-Fi and Bluetooth \
         settings made at the factory) and its current boot, recovery and logo images are saved \
         to this computer and checked against the remote. The installer never writes \
         calibration. {data}\n\nGiven up: the saved enrollment is the only copy of the remote's \
         original Android system. Without it, Restore stock Android will not be available for \
         this remote.\n\nThis is only for a remote that is running Couch now. If it runs \
         Android, choose Install with Android backup instead; the installer checks, and stops \
         before writing anything if it finds Android."
    );
    Ok(ui.choose(
        "Reinstall without a saved enrollment",
        &body,
        &[
            choice(
                "Reinstall without a saved enrollment",
                "Continue. Restore stock Android will not be available afterwards.",
            ),
            choice(
                "Go back",
                "Choose or enter a saved enrollment folder instead.",
            ),
        ],
    )? == 0)
}
/// A reinstall without a saved enrollment, after the read-only capture:
/// the evidence to journal, or the journal reason and message to refuse
/// with. Every refusal comes with the remote still in download mode, so each
/// says how to get it out.
fn couch_images_admission(
    images: &std::result::Result<
        crate::android_images::CouchImages,
        crate::android_images::Refusal,
    >,
    skip_userdata: bool,
) -> std::result::Result<&'static str, (&'static str, &'static str)> {
    use crate::android_images::Refusal;
    match images {
        // An Android remote whose install stopped after the recovery write
        // looks exactly like this and still holds Android's userdata. Only a
        // reinstall that backs userdata up first may continue.
        Ok(images) if images.stage_in_boot && skip_userdata => Err((
            "stage_without_data_backup",
            "Your remote's last installation stopped halfway. Nothing was written. Hold the \
             side Power button until the remote turns off, then run the installer again and \
             choose Back up current Couch data",
        )),
        Ok(images) => Ok(images.evidence),
        Err(refused @ Refusal::AndroidBoot) => Err((
            refused.reason(),
            "This remote is running Android, not Couch, so it cannot be reinstalled without a \
             saved enrollment. Nothing was written. Hold the side Power button until the remote \
             turns off, start Android again, then run the installer and choose Install with \
             Android backup: that keeps the Android enrollment this option cannot",
        )),
        Err(refused @ Refusal::AndroidRecovery) => Err((
            refused.reason(),
            "This remote still has Android's recovery, so it was last running Android, not \
             Couch, and it cannot be reinstalled without a saved enrollment. Nothing was \
             written. Hold the side Power button until the remote turns off, then start it \
             again. If it starts Android, run the installer and choose Install with Android \
             backup. If it does not, an earlier installation attempt stopped after writing its \
             installer to the remote; keep that attempt's folder, which holds the original boot \
             image, and ask for help",
        )),
        Err(refused @ Refusal::Unrecognised(_)) => Err((
            refused.reason(),
            "The remote's current boot or recovery image is neither Couch nor Android, so it \
             cannot be reinstalled without a saved enrollment. Nothing was written. Hold the \
             side Power button until the remote turns off and ask for help, including the \
             folder named below",
        )),
    }
}
/// Which CID the download agent must report, and what the binding then rests
/// on. `expected` is the enrolled CID, or the one the running Couch reported
/// over USB before its restart.
fn download_agent_cid(expected: Option<&str>, observed: &str, fresh: bool) -> Result<&'static str> {
    match expected {
        Some(expected) => {
            ensure!(
                observed == expected,
                "{}",
                if fresh {
                    OTHER_DOWNLOAD_REMOTE
                } else {
                    "Canonical download-agent CID differs from enrollment"
                }
            );
            Ok("serial_and_download_agent")
        }
        None => {
            ensure!(fresh, "missing enrolled CID");
            Ok("download_agent")
        }
    }
}
/// After a calibration-only mismatch, the other saved enrollments on this
/// computer for the same remote, and whether each matches it as it is now.
/// Read without verification and shown as hints only: whichever the operator
/// picks next time is imported and checked in full.
fn same_remote_hints(
    others: &[(String, saved_enrollment::Peek)],
    observed: &saved_enrollment::ObservedHardware,
    restore: bool,
) -> String {
    let same: Vec<_> = others
        .iter()
        .filter(|(_, peek)| peek.cid == observed.cid)
        .map(|(label, peek)| {
            format!(
                "{label} ({})",
                if peek.matches(observed, restore) {
                    "matches this remote now"
                } else {
                    "does not match"
                }
            )
        })
        .collect();
    // No trailing full stop: the caller's error gets one appended.
    if same.is_empty() {
        "No other saved enrollment on this computer is for this remote. A folder with a \
         different storage ID belongs to another remote"
            .into()
    } else {
        format!(
            "Other saved enrollments for this remote on this computer: {}. Run the installer \
             again and pick one that matches this remote now; it is checked again in full. A \
             folder with a different storage ID belongs to another remote",
            same.join("; ")
        )
    }
}
/// The remote in download mode is not the one the serial query bound.
const OTHER_DOWNLOAD_REMOTE: &str = "The remote in download mode is not the one that was checked \
     over USB before the restart (its storage ID differs). Nothing was written. Hold the side \
     Power button until the remote turns off, connect only the remote you want to reinstall and \
     run the installer again";
fn identity_input(
    ui: &mut Ui,
    label: &str,
    available: Option<String>,
    mac: bool,
) -> Result<String> {
    if let Some(value) = available {
        return Ok(value);
    }
    loop {
        let value = ui
            .input(
                label,
                "ADB could not read this value. Read it from Android device information before the remote restarts.",
                false,
            )?
            .to_string();
        let valid = if mac {
            let bytes = decode(&value.to_ascii_lowercase().replace(':', ""));
            !value.eq_ignore_ascii_case("02:00:00:00:00:00")
                && value.len() == 17
                && value.as_bytes().iter().enumerate().all(|(i, c)| {
                    if i % 3 == 2 {
                        *c == b':'
                    } else {
                        c.is_ascii_hexdigit()
                    }
                })
                && bytes.is_ok_and(|b| {
                    b.len() == 6
                        && b[0] & 1 == 0
                        && b.iter().any(|c| *c != 0)
                        && b.iter().any(|c| *c != 255)
                })
        } else {
            (8..=64).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_alphanumeric())
        };
        if valid {
            return Ok(if mac {
                value.to_ascii_lowercase()
            } else {
                value
            });
        }
        ui.progress(
            1,
            "That device-information value is not valid. Check Android and try again.",
            0,
            0,
        )?;
    }
}
fn plan_images(paths: &BTreeMap<String, PathBuf>, device: &Value, ui: &mut Ui) -> Result<Value> {
    let mut images = serde_json::Map::new();
    for (name, path) in paths {
        let size = fs::metadata(path)?.len();
        ensure!(
            size > 0
                && size.is_multiple_of(512)
                && size
                    <= device["partitions"][name]["size"]
                        .as_u64()
                        .context("missing target partition")?,
            "assembled image does not fit"
        );
        let mut file = fs::File::open(path)?;
        let mut chunks = Vec::new();
        let mut full = Sha256::new();
        let mut buffer = vec![0; crate::stage::CHUNK];
        let mut done = 0;
        while done < size {
            let n = (size - done).min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..n])?;
            full.update(&buffer[..n]);
            chunks.push(format!("{:x}", Sha256::digest(&buffer[..n])));
            done += n as u64;
            ui.progress(4, &format!("Verifying {name} image"), done, size)?;
        }
        ensure!(
            file.read(&mut [0u8; 1])? == 0 && file.metadata()?.len() == size,
            "image changed during hashing"
        );
        images.insert(
            name.clone(),
            json!({"size":size,"sha256":format!("{:x}",full.finalize()),"chunks":chunks}),
        );
    }
    Ok(Value::Object(images))
}

pub fn run(ui: &mut Ui, config: Option<&Path>, local_payload: Option<&Path>) -> Result<()> {
    ui.set_steps(
        [
            "Prepare",
            "Device",
            "Originals",
            "Start installer",
            "Wi-Fi",
            "Backups",
            "Install",
            "Finish",
        ]
        .map(String::from)
        .to_vec(),
    )?;
    // Read the release configuration first so its version is on every screen,
    // including the first menu and any error; a missing configuration is still
    // reported after the menu, where it always was.
    let release = config.map(public_inputs::release).transpose()?;
    if let Some(release) = &release {
        ui.set_version(&format!("{} · OS {}", release.version, release.os.version))?;
    }
    let mode = ui.choose(
        "Install Couch",
        "For a fresh installation, start Android, enable USB debugging and connect USB. To reinstall Couch, keep Couch running and connect USB; your saved Android enrollment is used if you have one.",
        &[
            choice(
                "Install with Android backup",
                "Preserve Android data and device calibration before installing.",
            ),
            choice(
                "YOLO — skip Android data backup",
                "Device calibration and recovery originals are still preserved.",
            ),
            choice(
                "Reinstall existing Couch",
                "Keep Couch running. Uses your saved Android enrollment, or starts fresh without one.",
            ),
            choice(
                "Restore stock Android",
                "Write your saved Android originals and a fresh stock filesystem. Couch is replaced.",
            ),
            choice(
                "My remote shows COUCH RECOVERY",
                "Get a remote that keeps starting into recovery back to normal. Nothing is reinstalled.",
            ),
            choice("Cancel", "Leave the device unchanged."),
        ],
    )?;
    if mode == 5 {
        return Ok(());
    }
    // Leaving recovery needs no release configuration, no downloads and no
    // installation session: it clears one flag on a remote that is already
    // installed. Keep it ahead of everything the installation flow requires.
    if mode == 4 {
        return crate::recovery::run(ui);
    }
    // Restore shares the reinstall bootstrap path: the device currently runs Couch
    // and a saved Android enrollment is imported and re-bound before any write.
    let reinstall = mode == 2 || mode == 3;
    let restore = mode == 3;
    let release = release.context("This installer requires its verified release configuration")?;
    #[cfg(windows)]
    if !windows_driver_preflight(ui)? {
        return Ok(());
    }
    let parent = state_root()?;
    let mut session =
        SessionGuard::create(&parent.join(format!("install-{}", &hex(&random()?)[..16])))?;
    ui.set_log_path(
        session
            .path()
            .to_str()
            .context("invalid private session path")?,
    )?;
    let skip_userdata = if reinstall {
        ui.choose(
            "Current Couch data backup",
            "Calibration and the current boot, recovery and logo images are always saved first. Also save the current Couch data (settings and paired devices) before it is replaced?",
            &[
                choice(
                    "Back up current Couch data",
                    "Preserve current data before replacing the OS.",
                ),
                choice(
                    "YOLO — skip current Couch data",
                    "Calibration and boot/recovery originals are still saved.",
                ),
            ],
        )? == 1
    } else {
        mode == 1
    };
    let result = install(
        ui,
        &release,
        skip_userdata,
        reinstall,
        restore,
        &mut session,
        local_payload,
    );
    if let Err(error) = &result {
        if !matches!(session.phase(), Phase::Failed | Phase::Complete) {
            let _ = session.transition(
                Phase::Failed,
                &json!({"event":"installation_stopped","preserve_originals":true}),
            );
        }
        // The alternate form prints the cause chain, so a structural refusal
        // says which check failed rather than only that the pair was refused.
        let _ = ui.error(&format!(
            "{error:#}. Keep saved originals at {}. No automatic retry or restore was attempted.",
            session.path().display()
        ));
    }
    result
}
#[allow(clippy::too_many_arguments)]
fn install(
    ui: &mut Ui,
    release: &public_inputs::Release,
    skip_userdata: bool,
    reinstall: bool,
    restore: bool,
    session: &mut SessionGuard,
    local_payload: Option<&Path>,
) -> Result<()> {
    let _usb_lease = UsbLease::acquire(session)?;
    // macOS: Apple's serial driver owns the preloader and only root can hand it
    // to libusb. Hold that right now, before the long downloads, and refresh it
    // until the worker has started. Everything else stays unprivileged.
    let _privilege = adapter::Privilege::acquire()?;
    let dependencies = dependencies::prepare(
        session,
        dependencies::host_platform()?,
        |label, done, total, unit| ui.progress_with_unit(0, label, done, total, unit),
    )?;
    let ota = session.path().join("official-ota.zip");
    public_inputs::official(&ota, |done, total| {
        ui.progress(0, "Downloading verified official owner inputs", done, total)
    })?;
    let prepared = session.path().join("owner-inputs");
    ui.progress(0, "Reconstructing verified owner inputs", 0, 0)?;
    crate::prepare(&ota, &prepared)?;
    let public = public_inputs::payload(release, session.path(), local_payload, |done, total| {
        ui.progress(
            0,
            if local_payload.is_some() {
                "Verifying local Couch OS package"
            } else {
                "Downloading Couch OS"
            },
            done,
            total,
        )
    })?;
    // The installer stage is always assembled from the Couch payload to bootstrap
    // the RAM Wi-Fi installer. A restore writes no Couch OS images, so it builds
    // only the stage; a normal install also builds Couch boot/recovery/userdata.
    let mut images = BTreeMap::new();
    let ramdisks: &[(&str, &str)] = if restore {
        &[("installer", "installer.cpio.gz")]
    } else {
        &[
            ("boot", "boot.cpio.gz"),
            ("recovery", "recovery.cpio.gz"),
            ("installer", "installer.cpio.gz"),
        ]
    };
    for (name, ramdisk) in ramdisks {
        let ram = assembly::owner_ramdisk(&fs::read(&public[*ramdisk])?, &prepared)?;
        let kernel = fs::read(&public["zImage"])?;
        let bytes = assembly::boot_image(
            &prepared,
            if *name == "recovery" {
                None
            } else {
                Some(&kernel)
            },
            &ram,
        )?;
        let path = session.path().join(format!("{name}.img"));
        write(&path, &bytes)?;
        images.insert(name.to_string(), path);
    }
    let stage = images.remove("installer").unwrap();
    let stage_hash = digest(&stage)?;
    if !restore {
        images.insert("userdata".into(), public["userdata.ext4"].clone());
    }
    // Owner vendor runtime is a Couch-install concept; a stock restore carries none.
    let vendor = if restore {
        None
    } else {
        Some(vendor_transfer::prepare(&prepared)?)
    };
    session.transition(Phase::InputsVerified,&json!({"event":"inputs_verified","release":release.os.version,"installer_version":release.version,"installer_source_commit":release.source_commit,"os_source_commit":release.os.source_commit,"installation_protocol":release.os.installation_protocol,"payload_sha256":release.payload.sha256,"stage_sha256":stage_hash}))?;
    let state_root = session
        .path()
        .parent()
        .context("session needs a parent")?
        .to_path_buf();
    // Restore writes the saved Android originals back, so it never offers to
    // continue without them.
    let enrollment = if reinstall {
        Some(enrollment_source(ui, &state_root, !restore, skip_userdata)?)
    } else {
        None
    };
    let fresh = enrollment == Some(EnrollmentChoice::WithoutEnrollment);
    let chosen_folder = match &enrollment {
        Some(EnrollmentChoice::Folder(source)) => Some(source.clone()),
        _ => None,
    };
    let (saved, serial, expected_cid, identity) = if let Some(EnrollmentChoice::Folder(source)) =
        enrollment
    {
        let imported = if source.join("enrollment.json").is_file() {
            saved_enrollment::import(&source, session)?
        } else {
            let profile = input_path(
                ui,
                "Trusted stock manifest",
                "Select the independently retained stock manifest used with these originals.",
            )?;
            let hash=ui.input("Trusted stock manifest SHA-256","Enter its independently recorded SHA-256. Do not take a new trust pin from the backup being imported.",false)?;
            saved_enrollment::import_legacy(
                &source,
                &profile,
                &hash,
                session,
                |name, done, total| {
                    ui.progress(1, &format!("Verifying retained {name}"), done, total)
                },
            )?
        };
        let cid = imported.record().cid.clone();
        let identity = serde_json::to_value(&imported.record().android_identity)?;
        (Some(imported), None, Some(cid), identity)
    } else if fresh {
        // Nothing is imported: every value comes from this remote in this
        // session, and the running Couch's own answer binds its CID.
        session.checkpoint(&json!({"event":"reinstall_without_android_enrollment","android_enrollment":"none","restore_available_after":false,"skip_userdata_backup":skip_userdata}))?;
        (None, None, None, Value::Null)
    } else {
        ui.progress(
        1,
        "Enable USB debugging, connect the remote, and accept Android's USB authorization prompt.",
        0,
        0,
    )?;
        dependencies.verify()?;
        let devices = android::discover(&dependencies.adb)?;
        ensure!(
            !devices.is_empty(),
            "No Android remote found. Enable USB debugging and connect USB"
        );
        let selected = ui.choose(
            "Choose your Android remote",
            "Only USB-connected Android devices are listed.",
            &devices
                .iter()
                .map(|d| {
                    choice(
                        &d.serial,
                        &format!("{} · {}", d.model.as_deref().unwrap_or("Android"), d.state),
                    )
                })
                .collect::<Vec<_>>(),
        )?;
        let android = android::capture(&dependencies.adb, &devices[selected].serial)?;
        let cid = android
            .cid
            .as_deref()
            .context("Android did not expose a usable eMMC identity; no write is permitted")?;
        let identity = json!({"device_id":identity_input(ui,"Android Device ID",android.device_id,false)?,"wifi_mac":identity_input(ui,"Android Wi-Fi MAC",android.wifi_mac,true)?,"bt_mac":identity_input(ui,"Android Bluetooth MAC",android.bt_mac,true)?});
        (None, Some(android.serial), Some(cid.to_string()), identity)
    };
    ensure!(
        !(fresh && restore),
        "Restore needs the saved Android enrollment"
    );
    dependencies.verify()?;
    let script = adapter::materialize(session)?;
    let session_dir = session.path().to_path_buf();
    let mut worker = prepared_worker(&dependencies, &script, &prepared, &session_dir, ui)?;
    // Every Couch restart, first attempt and retry, waits until the remote
    // reports the expected CID and a normal next start. Without a saved
    // enrollment the remote's first answer is the expected CID.
    let mut binding = match &expected_cid {
        Some(cid) => couch_restart::CouchBinding::enrolled(cid),
        None => couch_restart::CouchBinding::unbound(),
    };
    let bound = if let Some(serial) = &serial {
        // The ADB server must not hold the remote while the worker reads its
        // USB serial descriptor (issue #89, Windows). Reboot restarts it.
        android::stop_server(&dependencies.adb)?;
        let bound = simple(
            &mut worker,
            json!({"op":"android_bind","serial":serial}),
            "android_bound",
            30,
            ui,
            1,
        )?;
        ensure!(
            bound["serial_sha256"] == format!("{:x}", Sha256::digest(serial.as_bytes())),
            "Android USB serial binding differs"
        );
        session.transition(Phase::AndroidBound,&json!({"event":"android_bound","cid":expected_cid,"usb":bound,"android_identity":identity}))?;
        ui.progress(1, "Restarting the selected remote through USB", 0, 0)?;
        dependencies.verify()?;
        android::reboot(&dependencies.adb, serial)?;
        bound
    } else {
        let bound = loop {
            let result = simple(
                &mut worker,
                json!({"op":"enumerate"}),
                "candidates",
                20,
                ui,
                1,
            )?;
            let devices = result["devices"]
                .as_array()
                .context("invalid USB inventory")?;
            let candidates = devices
                .iter()
                .filter(|d| d["pid"] == 0x201c)
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                ui.choose(
                    "Connect the Couch remote",
                    connect_couch_prompt(devices),
                    &[choice(
                        "Check USB again",
                        "No write or reboot has been requested.",
                    )],
                )?;
                continue;
            }
            let options = candidates
                .iter()
                .map(|d| {
                    choice(
                        &format!("USB bus {} · ports {}", d["bus"], d["ports"]),
                        "Select the connected Couch remote.",
                    )
                })
                .collect::<Vec<_>>();
            let selected = ui.choose(
                "Select the connected Couch remote",
                if fresh {
                    "Choose the remote that is running Couch now. It is checked over USB before it is restarted, and nothing is written until its storage and calibration have been saved and checked, except the COUCH RECOVERY flag, and only if you choose to clear it."
                } else {
                    "Its stored CID and calibration must match the imported enrollment before any write."
                },
                &options,
            )?;
            break candidates[selected].clone();
        };
        couch_restart::restart(&mut worker, &bound, &mut binding, false, session, ui)?;
        bound
    };
    let mut attempt = 1u32;
    let connected = loop {
        let error = match download_mode(&mut worker, &bound, ui) {
            Ok(result) => break result,
            Err(error) => error,
        };
        if attempt >= DOWNLOAD_ATTEMPTS {
            return Err(error.context(format!(
                "Download mode was not reached in {DOWNLOAD_ATTEMPTS} attempts; no boot write occurred"
            )));
        }
        // Startup is read-only, so a missed or failed entry has written nothing.
        // A worker stops for good at its first failure; a fresh one prepares the
        // same verified loader before the remote is restarted again.
        drop(worker);
        worker = prepared_worker(&dependencies, &script, &prepared, &session_dir, ui)?;
        let returned = if let Some(serial) = &serial {
            android_returned(&dependencies.adb, serial, ui)?
        } else {
            couch_returned(&mut worker, &bound, ui)?
        };
        ensure!(
            returned,
            "{error:#}. The remote did not come back on USB within {RETURN_WAIT} s, so it was not \
             restarted again. Hold the side Power button until it turns off, start it again and \
             run the installer again; no boot write occurred"
        );
        attempt += 1;
        session
            .checkpoint(&json!({"event":"download_mode_retry","attempt":attempt,"usb":bound}))?;
        ui.progress(
            1,
            &format!("Restarting the remote again (attempt {attempt} of {DOWNLOAD_ATTEMPTS})"),
            0,
            0,
        )?;
        if let Some(serial) = &serial {
            dependencies.verify()?;
            android::reboot(&dependencies.adb, serial)?;
        } else {
            couch_restart::restart(&mut worker, &bound, &mut binding, true, session, ui)?;
        }
    };
    let cid = connected["cid"]
        .as_str()
        .context("missing observed canonical CID")?;
    // Without a saved enrollment the CID read over the serial shell before the
    // restart binds the remote; where that was unavailable, this download-mode
    // read on the same physical port is the first observation.
    let cid_source = download_agent_cid(binding.expected(), cid, fresh)?;
    let device = &connected["device"];
    enrollment::admit_layout(device, cid, &prepared)?;
    let mut required = 256 * 1024 * 1024u64;
    for name in enrollment::IDENTITY
        .into_iter()
        .chain(enrollment::ORIGINALS)
    {
        let size = device["partitions"][name]["size"]
            .as_u64()
            .context("missing original size")?;
        required = required
            .checked_add(size.checked_mul(2).context("backup size overflow")?)
            .context("backup size overflow")?;
    }
    if !skip_userdata {
        required = required
            .checked_add(
                device["partitions"]["userdata"]["size"]
                    .as_u64()
                    .context("missing userdata size")?,
            )
            .context("backup size overflow")?;
    }
    ensure!(crate::space::available(session.path())? >= required, "Not enough free space for selected original backups and safety margin; no boot write occurred");

    let originals = enrollment::capture(&mut worker, device, session, ui)?;
    let imported_proof = if let Some(saved) = saved {
        let observation = saved_enrollment::ObservedHardware {
            cid: cid.to_string(),
            capacity: device["capacity"].as_u64().context("missing capacity")?,
            hwcode: device["hwcode"]
                .as_u64()
                .context("missing hardware code")?
                .try_into()?,
            cid_encoding: device["cid_encoding"]
                .as_str()
                .context("missing CID encoding")?
                .into(),
            partitions: serde_json::from_value(device["partitions"].clone())?,
            identity_sha256: enrollment::IDENTITY
                .into_iter()
                .map(|name| (name.to_string(), originals[name].clone()))
                .collect(),
            retained_sha256: originals.clone(),
        };
        let changed = saved.calibration_only_mismatch(&observation);
        let rejected = saved.sha256().to_owned();
        let proof = match saved.rebind_mode(&observation, session, restore) {
            Ok(proof) => proof,
            Err(error) => {
                // The remote is left in download mode. When only calibration
                // changed (Android started again after the folder was saved),
                // say so plainly and point at any other folder for this
                // remote that matches it now.
                const OFF: &str = "Nothing was written. Hold the side Power button until the \
                     remote turns off, then start it again";
                let Some(changed) = &changed else {
                    anyhow::bail!("{error:#}. {OFF}");
                };
                // A journal that cannot record the rejection must not hide it.
                let journal = session.checkpoint(&json!({"event":"imported_enrollment_rejected","enrollment_sha256":rejected,"calibration_changed":changed}));
                let others: Vec<_> = enrollment_sources::discover(&state_root, None)
                    .into_iter()
                    .filter(|candidate| {
                        chosen_folder
                            .as_deref()
                            .is_none_or(|picked| !enrollment_sources::same(&candidate.path, picked))
                    })
                    .filter_map(|candidate| {
                        Some((candidate.label(), saved_enrollment::peek(&candidate.path)?))
                    })
                    .collect();
                let mut message = format!(
                    "The saved enrollment you picked no longer matches this remote: its \
                     calibration has changed since it was saved ({}), which happens when Android \
                     was started again after it was saved. {OFF}. {}",
                    saved_enrollment::describe_calibration_change(changed),
                    same_remote_hints(&others, &observation, restore)
                );
                if let Err(journal) = journal {
                    message.push_str(&format!(
                        ". The installation journal could not record this: {journal:#}"
                    ));
                }
                anyhow::bail!("{message}");
            }
        };
        // Only now, imported in full and bound to this remote, is the folder
        // worth offering first next time. A folder that fails the rebind is
        // not remembered, so it cannot keep coming back at the top.
        if let Some(source) = &chosen_folder {
            enrollment_sources::remember(&state_root, source);
        }
        session.transition(Phase::AndroidBound,&json!({"event":"retained_enrollment_bound","cid":cid,"original_os":"Couch","enrollment_sha256":proof.enrollment().sha256(),"usb":bound,"restore":restore}))?;
        Some(proof)
    } else if fresh {
        // Nothing has been written. The remote must positively be running
        // Couch: Couch's boot and recovery and a MediaTek overlay, exactly as
        // just captured. Android here would lose its data with no backup.
        let images = enrollment::couch_originals(session.path(), &originals)?;
        match couch_images_admission(&images, skip_userdata) {
            Ok(evidence) => {
                session.checkpoint(&json!({"event":"couch_boot_verified","evidence":evidence,"boot_sha256":originals["boot"]}))?;
            }
            Err((reason, message)) => {
                let mut evidence = json!({"event":"couch_boot_refused","reason":reason});
                if let Err(crate::android_images::Refusal::Unrecognised(detail)) = &images {
                    evidence["detail"] = json!(detail);
                }
                session.checkpoint(&evidence)?;
                anyhow::bail!("{message}");
            }
        }
        session.transition(Phase::AndroidBound,&json!({"event":"couch_device_bound","original_os":"Couch","android_enrollment":"none","cid":cid,"cid_source":cid_source,"usb":bound,"restore_available":false}))?;
        None
    } else {
        let profile = enrollment::android_originals(session.path())?;
        session.checkpoint(&json!({"event":"android_stock_profile_verified","profile":profile}))?;
        None
    };
    ensure!(
        imported_proof.is_some() == (reinstall && !fresh),
        "missing retained enrollment admission"
    );
    if restore {
        // Assemble the restore set from the re-bound Android enrollment (recovery,
        // logo, odmdtbo, boot) plus a fresh stock F2FS userdata the owner prepared
        // offline with the firmware's make_f2fs. assemble re-hashes every original
        // against the imported record and refuses a non-Android enrollment.
        let proof = imported_proof
            .as_ref()
            .context("restore requires a re-bound Android enrollment")?;
        let enrollment = proof.enrollment();
        let userdata = input_path(
            ui,
            "Stock Android userdata image",
            "Select the full F2FS userdata image made offline by the firmware's make_f2fs. See docs/installer-android-restore.md.",
        )?;
        let receipt = input_path(
            ui,
            "Stock userdata receipt",
            "Select the couch-stock-userdata receipt recorded beside that image.",
        )?;
        ui.progress(
            2,
            "Verifying saved Android originals and stock userdata",
            0,
            0,
        )?;
        images = crate::android_restore::assemble(
            enrollment.directory(),
            enrollment.record(),
            &userdata,
            &receipt,
        )?;
    } else {
        let logo = assembly::logo_image(
            &fs::read(session.path().join("bootstrap-logo.img"))?,
            &fs::read(
                public
                    .get("logo.bgra")
                    .context("public Couch logo frame missing")?,
            )?,
        )?;
        let logo_path = session.path().join("logo.img");
        write(&logo_path, &logo)?;
        images.insert("logo".into(), logo_path);
    }
    let identity_hashes: BTreeMap<_, _> = enrollment::IDENTITY
        .into_iter()
        .map(|n| (n, originals[n].clone()))
        .collect();
    let original_hashes: BTreeMap<_, _> = enrollment::ORIGINALS
        .into_iter()
        .map(|n| (n, originals[n].clone()))
        .collect();
    let entries:BTreeMap<_,_>=originals.iter().map(|(name,sha)|(name,json!({"file":format!("bootstrap-{name}.img"),"size":device["partitions"][name]["size"],"sha256":sha}))).collect();
    let enrollment_path = session.path().join(if reinstall {
        "current-couch-snapshot.json"
    } else {
        "enrollment.json"
    });
    let mut snapshot = json!({"schema":1,"kind":"couch-device-enrollment","model":"sanytron-ha100","cid":cid,"capacity":device["capacity"],"partitions":device["partitions"],"identity_sha256":identity_hashes,"android_identity":identity,"original_os":if reinstall {"Couch"} else {"Android"},"originals":entries});
    if fresh {
        // A live Couch snapshot with no Android enrollment behind it. Import
        // refuses it on file name, original OS, this unknown field, its journal
        // and its boot image, so it can never become an Android baseline.
        snapshot["android_enrollment"] = json!("none");
    }
    write(&enrollment_path, &serde_json::to_vec(&snapshot)?)?;
    session.transition(
        Phase::OriginalsSaved,
        &json!({"event":"enrollment_complete","enrollment_sha256":digest(&enrollment_path)?}),
    )?;
    simple(
        &mut worker,
        json!({"op":"authorize_boot","cid_sha256":device["runtime_cid_sha256"],"partitions":device["partitions"],"identity_sha256":identity_hashes,"original_sha256":original_hashes,"stage":dependencies::python_path(&stage)?,"stage_sha256":stage_hash}),
        "boot_authorized",
        1800,
        ui,
        2,
    )?;
    session.transition(
        Phase::StageBootPending,
        &json!({"event":"bootstrap_write_admitted","stage_sha256":stage_hash}),
    )?;
    simple(
        &mut worker,
        json!({"op":"write_boot"}),
        "boot_verified",
        1800,
        ui,
        3,
    )?;
    session
        .checkpoint(&json!({"event":"bootstrap_readback_verified","stage_sha256":stage_hash}))?;
    simple(
        &mut worker,
        json!({"op":"boot"}),
        "boot_requested",
        30,
        ui,
        3,
    )?;
    let start = Instant::now();
    loop {
        ensure!(
            start.elapsed() < Duration::from_secs(120),
            "Installer stage did not appear. Keep the saved originals"
        );
        if simple(
            &mut worker,
            json!({"op":"stage_present"}),
            "stage_present",
            20,
            ui,
            3,
        )?["present"]
            == true
        {
            break;
        }
        ui.progress_with_unit(
            3,
            "Waiting for the installer USB stage",
            start.elapsed().as_secs(),
            120,
            crate::frontend::ProgressUnit::Seconds,
        )?;
        thread::sleep(Duration::from_millis(250));
    }
    simple(
        &mut worker,
        json!({"op":"stage_open"}),
        "stage_open",
        60,
        ui,
        3,
    )?;
    network::ready(&mut worker, ui)?;
    let network = network::select(&mut worker, ui)?;
    // Wi-Fi is always provisioned over USB for the TLS transfer. A restore writes
    // raw full-partition images, so the plan carries no stage-side network/vendor
    // personalization; a normal install personalizes its compact userdata.
    let mut plan = json!({"schema":1,"nonce":hex(&random()?),"manifest_sha256":release.payload.sha256,"stage_sha256":stage_hash,"original_boot_sha256":originals["boot"],"cid":cid,"capacity":device["capacity"],"partitions":device["partitions"],"identity_sha256":identity_hashes,"images":plan_images(&images,device,ui)?,"skip_userdata_backup":skip_userdata});
    // Stage probes parse the plan with deny_unknown_fields, and images built
    // before the restore mode existed do not know this key. Send it only for a
    // restore, which needs a stage that understands it; a normal install keeps
    // the exact plan shape every shipped stage accepts.
    if restore {
        plan["restore"] = json!(true);
    } else {
        plan["network"] = network.clone();
        plan["vendor_source_sha256"] = json!(vendor
            .as_ref()
            .context("owner vendor runtime missing for install")?
            .source_sha256());
    }
    let plan_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&plan)?);
    network::rpc(
        &mut worker,
        "stage_bind",
        json!({"plan_sha256":format!("{:x}",Sha256::digest(plan_bytes.as_slice())),"nonce":plan["nonce"]}),
    )?;
    let cert = rcgen::generate_simple_self_signed(vec!["couch-probe".into()])?;
    let der = cert.cert.der().to_vec();
    let key = zeroize::Zeroizing::new(cert.signing_key.serialize_der());
    let token = zeroize::Zeroizing::new(random()?);
    let mut provision = network.clone();
    let object = provision.as_object_mut().unwrap();
    object.insert("certificate_hex".into(), json!(hex(&der)));
    object.insert("private_key_hex".into(), json!(hex(&key)));
    object.insert("token_hex".into(), json!(hex(token.as_ref())));
    network::rpc(&mut worker, "stage_provision", provision)?;
    let start = Instant::now();
    let address = loop {
        ensure!(
            start.elapsed() < Duration::from_secs(120),
            "Remote Wi-Fi connection timed out"
        );
        let status = network::rpc(&mut worker, "stage_status", Value::Null)?;
        ensure!(
            status["status"] != "failed",
            "Remote Wi-Fi connection failed; preserve originals"
        );
        if status["status"] == "connected" {
            break status["ip"]
                .as_str()
                .context("missing Wi-Fi address")?
                .parse::<std::net::Ipv4Addr>()?;
        }
        ui.progress_with_unit(
            4,
            "Connecting the remote to Wi-Fi",
            start.elapsed().as_secs(),
            120,
            crate::frontend::ProgressUnit::Seconds,
        )?;
        thread::sleep(Duration::from_millis(500));
    };
    simple(
        &mut worker,
        json!({"op":"stage_close"}),
        "stage_closed",
        30,
        ui,
        4,
    )?;
    drop(worker);
    let mut connection = stage_tls::connect((address, 8443).into(), &der, &token)?;
    connection
        .sock
        .set_phase_timeout(Duration::from_secs(1800))?;
    session.transition(Phase::StageConnected,&json!({"event":"stage_authenticated","plan_sha256":format!("{:x}",Sha256::digest(plan_bytes.as_slice()))}))?;
    let mut channel = Channel::authenticated(connection);
    transaction::run_with_vendor(
        &mut channel,
        &plan,
        &images,
        &enrollment::original_boot(session),
        if reinstall {
            OriginalOs::Couch
        } else {
            OriginalOs::Android
        },
        session,
        vendor,
        |phase, target, done, total| {
            ui.progress(
                if phase.contains("Backup") { 5 } else { 6 },
                &format!("{phase} {target}"),
                done,
                total,
            )
        },
    )?;
    let reboot = ui.choose(
        if restore {
            "Stock Android restore verified"
        } else {
            "Couch installation verified"
        },
        "Backups and the journal are saved on this computer.",
        &[
            choice(
                if restore {
                    "Restart into stock Android"
                } else {
                    "Restart into Couch"
                },
                "Start the newly written OS.",
            ),
            choice(
                "Leave the installer running",
                "Keep the current verified stage available.",
            ),
        ],
    )?;
    channel.send_json(&json!({"action":if reboot==0{"reboot"}else{"leave"}}))?;
    if reboot == 0 {
        channel.expect(&json!({"event":"rebooting"}))?;
    }
    ui.progress(
        7,
        if restore {
            "Stock Android restored. Check first boot on the remote, then re-enroll from Android before any future Couch install."
        } else if fresh {
            "Couch reinstalled and verified. Check that the remote starts normally. This remote has no saved Android enrollment, so Restore stock Android is not available for it. Keep the folder shown on screen: it holds the remote's calibration and its previous Couch copies."
        } else {
            "Installation verified. First normal boot still needs to be checked on the remote."
        },
        0,
        0,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn cancel_never_requires_release_config_or_creates_session() {
        let mut ui = Ui::new(
            Box::new(Cursor::new(b"{\"id\":1,\"value\":\"5\"}\n".to_vec())),
            Box::new(Vec::new()),
        );
        run(&mut ui, None, None).unwrap();
    }
    #[test]
    fn leaving_recovery_is_offered_before_the_release_configuration_is_required() {
        // Selecting it with no remote connected reaches its own first screen
        // and stops there when the terminal answers nothing further.
        let mut ui = Ui::new(
            Box::new(Cursor::new(b"{\"id\":1,\"value\":\"4\"}\n".to_vec())),
            Box::new(Vec::new()),
        );
        let error = format!("{:#}", run(&mut ui, None, None).unwrap_err());
        assert!(!error.contains("release configuration"), "{error}");
    }
    #[test]
    fn images_use_fixed_wire_chunks_and_full_digest() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("image");
        let data = vec![42; crate::stage::CHUNK + 512];
        fs::write(&path, &data).unwrap();
        let paths = BTreeMap::from([("userdata".into(), path)]);
        let device = json!({"partitions":{"userdata":{"size":data.len()}}});
        let mut ui = Ui::new(Box::new(Cursor::new(Vec::new())), Box::new(Vec::new()));
        ui.set_steps(vec!["step".into(); 8]).unwrap();
        let result = plan_images(&paths, &device, &mut ui).unwrap();
        assert_eq!(
            result["userdata"]["chunks"],
            json!([
                format!("{:x}", Sha256::digest(&data[..crate::stage::CHUNK])),
                format!("{:x}", Sha256::digest(&data[crate::stage::CHUNK..]))
            ])
        );
        assert_eq!(
            result["userdata"]["sha256"],
            format!("{:x}", Sha256::digest(&data))
        );
    }
    use crate::couch_restart::tests::terminal;

    fn state_with(sessions: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for name in sessions {
            fs::create_dir(root.path().join(name)).unwrap();
            fs::write(root.path().join(name).join("enrollment.json"), b"{}").unwrap();
        }
        root
    }

    #[test]
    fn reinstall_without_candidates_offers_fresh_and_confirms_the_trade_off() {
        let root = state_with(&[]);
        // Continue, Go back, Continue, Reinstall without a saved enrollment.
        let (mut ui, screen) = terminal(&["0", "1", "0", "0"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::WithoutEnrollment
        );
        let prompts = screen.prompts();
        assert_eq!(prompts.len(), 4);
        assert_eq!(prompts[0].0, "Saved Android enrollment");
        assert_eq!(prompts[0].1, "choice");
        assert_eq!(
            prompts[0].3,
            ["Continue without a saved enrollment", "Enter a folder path"]
        );
        assert!(prompts[0]
            .2
            .contains("No saved Android enrollment was found"));
        assert_eq!(prompts[1].0, "Reinstall without a saved enrollment");
        assert_eq!(
            prompts[1].3,
            ["Reinstall without a saved enrollment", "Go back"]
        );
        assert_eq!(prompts[2], prompts[0]);
        assert_eq!(prompts[3], prompts[1]);
        // Or type a copied folder's location instead.
        let (mut ui, screen) = terminal(&["1", "/copied/install-a2baa68b63cc958a"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::Folder("/copied/install-a2baa68b63cc958a".into())
        );
        assert_eq!(screen.prompts()[1].1, "text");
    }

    #[test]
    fn reinstall_picker_with_candidates_appends_fresh_last() {
        let root = state_with(&["install-aaaa"]);
        let folder = root.path().join("install-aaaa");
        let (mut ui, screen) = terminal(&["0"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::Folder(folder.clone())
        );
        let options = &screen.prompts()[0].3;
        assert_eq!(
            options[1..],
            ["Enter a folder path", "I don't have a saved enrollment"]
        );
        assert!(options[0].ends_with(" · install-aaaa"), "{}", options[0]);
        let (mut ui, _) = terminal(&["2", "0"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::WithoutEnrollment
        );
        // Go back returns to the same picker, where the folder can be chosen.
        let (mut ui, screen) = terminal(&["2", "1", "0"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::Folder(folder)
        );
        let prompts = screen.prompts();
        assert_eq!(prompts[2], prompts[0]);
        let (mut ui, _) = terminal(&["1", "/elsewhere"]);
        assert_eq!(
            enrollment_source(&mut ui, root.path(), true, false).unwrap(),
            EnrollmentChoice::Folder("/elsewhere".into())
        );
    }

    #[test]
    fn restore_picker_is_unchanged_and_never_offers_fresh() {
        let empty = state_with(&[]);
        let (mut ui, screen) = terminal(&["/saved"]);
        assert_eq!(
            enrollment_source(&mut ui, empty.path(), false, false).unwrap(),
            EnrollmentChoice::Folder("/saved".into())
        );
        let prompts = screen.prompts();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].0, "Saved Android enrollment directory");
        assert_eq!(prompts[0].1, "text");
        let one = state_with(&["install-aaaa"]);
        let (mut ui, screen) = terminal(&["1", "/saved"]);
        assert_eq!(
            enrollment_source(&mut ui, one.path(), false, false).unwrap(),
            EnrollmentChoice::Folder("/saved".into())
        );
        let options = &screen.prompts()[0].3;
        assert_eq!(options.len(), 2);
        assert!(options
            .iter()
            .all(|label| !label.contains("without") && !label.contains("don't have")));
    }

    #[test]
    fn trade_off_body_follows_the_data_backup_choice() {
        for (skip, expected) in [
            (false, "Your current Couch data is also backed up, as you chose."),
            (
                true,
                "Your current Couch data will not be backed up, as you chose; its current settings and paired devices will be lost.",
            ),
        ] {
            let (mut ui, screen) = terminal(&["1"]);
            assert!(!confirm_without_enrollment(&mut ui, skip).unwrap());
            let body = &screen.prompts()[0].2;
            assert!(body.contains(expected), "{body}");
            assert!(body.contains("Restore stock Android will not be available"));
            assert!(body.contains("The installer never writes calibration."));
            assert!(body.contains("choose Install with Android backup instead"));
        }
    }

    #[test]
    fn a_stale_enrollment_points_at_the_saved_one_that_matches_this_remote_now() {
        let cid = "12".repeat(16);
        let calibration = |value: &str| -> BTreeMap<String, String> {
            enrollment::IDENTITY
                .into_iter()
                .map(|name| (name.to_string(), value.repeat(64)))
                .collect()
        };
        let layout = |size: u64| {
            BTreeMap::from([(
                "boot".to_string(),
                saved_enrollment::Region { offset: 0, size },
            )])
        };
        let observed = saved_enrollment::ObservedHardware {
            cid: cid.clone(),
            capacity: 4096,
            hwcode: 0x6580,
            cid_encoding: "mt6580-legacy-le32-registers".into(),
            partitions: layout(512),
            identity_sha256: calibration("b"),
            retained_sha256: BTreeMap::from([("odmdtbo".to_string(), "d".repeat(64))]),
        };
        let peek = |cid: &str, value: &str, size: u64, overlay: &str| saved_enrollment::Peek {
            cid: cid.into(),
            capacity: 4096,
            identity_sha256: calibration(value),
            partitions: layout(size),
            odmdtbo_sha256: overlay.repeat(64),
        };
        let others = vec![
            (
                "Saved 2026-09-13 06:50 UTC · install-a2ba".to_string(),
                peek(&cid, "b", 512, "d"),
            ),
            (
                "Saved 2026-09-12 22:10 UTC · install-05f5".to_string(),
                peek(&cid, "a", 512, "d"),
            ),
            (
                "Saved 2026-09-11 09:00 UTC · install-0b0b".to_string(),
                peek(&cid, "b", 1024, "d"),
            ),
            (
                "Saved 2026-09-10 09:00 UTC · install-0d0d".to_string(),
                peek(&cid, "b", 512, "e"),
            ),
            (
                "Saved 2026-09-01 10:00 UTC · install-9999".to_string(),
                peek(&"34".repeat(16), "b", 512, "d"),
            ),
        ];
        let hints = same_remote_hints(&others, &observed, false);
        assert!(
            hints.contains("install-a2ba (matches this remote now)"),
            "{hints}"
        );
        assert!(hints.contains("install-05f5 (does not match)"), "{hints}");
        // Layout and overlay count, as they do for the rebind itself ...
        assert!(hints.contains("install-0b0b (does not match)"), "{hints}");
        assert!(hints.contains("install-0d0d (does not match)"), "{hints}");
        // ... except for a restore, which does not compare them.
        let restoring = same_remote_hints(&others, &observed, true);
        assert!(
            restoring.contains("install-0b0b (matches this remote now)"),
            "{restoring}"
        );
        assert!(
            restoring.contains("install-0d0d (matches this remote now)"),
            "{restoring}"
        );
        assert!(!hints.contains("install-9999"), "{hints}");
        assert!(hints.contains("belongs to another remote"));
        assert!(!hints.ends_with('.'));
        let none = same_remote_hints(&others[4..], &observed, false);
        assert!(none.starts_with("No other saved enrollment on this computer is for this remote"));
        assert!(!none.ends_with('.'));
    }
    #[test]
    fn a_remote_left_in_download_mode_is_told_to_power_off() {
        let couch = json!({"bus":1,"address":5,"ports":[4],"vid":0x0e8d,"pid":0x201c});
        let other = json!({"bus":1,"address":6,"ports":[3],"vid":0x05ac,"pid":0x0250});
        assert!(connect_couch_prompt(&[]).starts_with("Keep Couch powered on"));
        assert!(
            connect_couch_prompt(std::slice::from_ref(&other)).starts_with("Keep Couch powered on")
        );
        for pid in DOWNLOAD_MODE_PIDS {
            let mut stuck = couch.clone();
            stuck["pid"] = json!(pid);
            let prompt = connect_couch_prompt(&[other.clone(), stuck]);
            assert!(prompt.contains("still in download mode"), "{pid:#x}");
            assert!(prompt.starts_with("A remote connected to this computer"));
            assert!(prompt.contains("hold its side Power button until it turns off"));
        }
    }

    #[test]
    fn every_refusal_after_download_mode_says_how_to_turn_the_remote_off() {
        use crate::android_images::{CouchImages, Refusal};
        let couch = |stage_in_boot| {
            Ok(CouchImages {
                evidence: if stage_in_boot { "stage" } else { "couch" },
                stage_in_boot,
            })
        };
        assert_eq!(couch_images_admission(&couch(false), true), Ok("couch"));
        assert_eq!(couch_images_admission(&couch(false), false), Ok("couch"));
        // A half-finished install is admitted only with a data backup.
        assert_eq!(couch_images_admission(&couch(true), false), Ok("stage"));
        let (reason, halfway) = couch_images_admission(&couch(true), true).unwrap_err();
        assert_eq!(reason, "stage_without_data_backup");
        assert!(halfway.starts_with("Your remote's last installation stopped halfway"));
        assert!(halfway.ends_with("choose Back up current Couch data"));
        let refused = |refusal| couch_images_admission(&Err(refusal), false).unwrap_err();
        let (reason, android) = refused(Refusal::AndroidBoot);
        assert_eq!(reason, "android_boot");
        assert!(android.starts_with("This remote is running Android"));
        let (reason, recovery) = refused(Refusal::AndroidRecovery);
        assert_eq!(reason, "android_recovery");
        assert!(recovery.contains("Android's recovery"));
        let (reason, neither) = refused(Refusal::Unrecognised("boot: zeros".into()));
        assert_eq!(reason, "unrecognised");
        assert!(neither.contains("neither Couch nor Android"));
        for message in [halfway, android, recovery, neither, OTHER_DOWNLOAD_REMOTE] {
            assert!(message.contains("Nothing was written"), "{message}");
            assert!(
                message.contains("Hold the side Power button until the remote turns off"),
                "{message}"
            );
            // run() appends ". Keep saved originals…".
            assert!(!message.ends_with('.'), "{message}");
        }
    }

    #[test]
    fn the_download_agent_must_report_the_cid_the_remote_was_bound_by() {
        let cid = "12".repeat(16);
        let other = "34".repeat(16);
        assert_eq!(
            download_agent_cid(Some(&cid), &cid, true).unwrap(),
            "serial_and_download_agent"
        );
        assert_eq!(
            download_agent_cid(None, &cid, true).unwrap(),
            "download_agent"
        );
        assert_eq!(
            download_agent_cid(Some(&cid), &other, true)
                .unwrap_err()
                .to_string(),
            OTHER_DOWNLOAD_REMOTE
        );
        assert_eq!(
            download_agent_cid(Some(&cid), &other, false)
                .unwrap_err()
                .to_string(),
            "Canonical download-agent CID differs from enrollment"
        );
        assert!(download_agent_cid(Some(&cid), &cid, false).is_ok());
        assert_eq!(
            download_agent_cid(None, &cid, false)
                .unwrap_err()
                .to_string(),
            "missing enrolled CID"
        );
    }

    #[test]
    fn nothing_is_written_before_the_remote_is_bound() {
        // A reinstall without a saved enrollment reaches OriginalsSaved, and
        // with it the boot write, only through the couch_device_bound
        // transition: the session refuses any shortcut from InputsVerified.
        let (_root, mut session) = crate::couch_restart::tests::private_session();
        for phase in [
            Phase::OriginalsSaved,
            Phase::StageBootPending,
            Phase::Writing,
        ] {
            assert!(session.transition(phase, &json!({})).is_err());
        }
        session
            .transition(Phase::AndroidBound, &json!({"event":"couch_device_bound"}))
            .unwrap();
        session
            .transition(Phase::OriginalsSaved, &json!({}))
            .unwrap();
    }
}
