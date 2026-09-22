//! Fresh-device admission: Android CID, fixed official layout and independently
//! saved partition reads must all agree before the native host admits bootstrap.
use crate::{
    adapter::Worker,
    frontend::Ui,
    public_inputs::{create, decode, digest},
    session::SessionGuard,
    stage::CHUNK,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
pub const IDENTITY: [&str; 5] = ["nvdata", "nvram", "proinfo", "protect1", "protect2"];
pub const ORIGINALS: [&str; 4] = ["boot", "recovery", "odmdtbo", "logo"];
pub fn admit_layout(observed: &Value, cid: &str, prepared: &Path) -> Result<()> {
    ensure!(
        observed["hwcode"] == 0x6580
            && observed["cid_encoding"] == "mt6580-legacy-le32-registers"
            && decode(cid)?.len() == 16
            && observed["runtime_cid_sha256"] == format!("{:x}", Sha256::digest(decode(cid)?)),
        "Android and download-agent storage identity differ"
    );
    let (_, scatter_size, scatter_sha) = crate::BOOTSTRAP
        .iter()
        .find(|v| v.0 == "scatter.txt")
        .unwrap();
    let scatter = prepared.join("bootstrap/scatter.txt");
    ensure!(
        fs::metadata(&scatter)?.len() == *scatter_size && digest(&scatter)? == *scatter_sha,
        "official layout changed"
    );
    let mut offsets = BTreeMap::new();
    for line in fs::read_to_string(scatter)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 2, "invalid official scatter");
        if !["preloader", "pgpt", "sgpt", "flashinfo"].contains(&fields[0]) {
            offsets.insert(
                fields[0].to_string(),
                u64::from_str_radix(fields[1].trim_start_matches("0x"), 16)?,
            );
        }
    }
    let partitions = observed["partitions"]
        .as_object()
        .context("missing observed layout")?;
    ensure!(
        partitions.len() == offsets.len() + 1
            && partitions.contains_key("flashinfo")
            && offsets.keys().all(|n| partitions.contains_key(n)),
        "unexpected stock partition inventory"
    );
    let capacity = observed["capacity"]
        .as_u64()
        .context("missing storage capacity")?;
    let mut ordered: Vec<_> = offsets.iter().collect();
    ordered.sort_by_key(|(_, offset)| *offset);
    ensure!(
        ordered
            .last()
            .is_some_and(|(name, _)| name.as_str() == "userdata"),
        "invalid fixed partition profile"
    );
    for (name, offset) in &ordered {
        ensure!(
            partitions[*name]["offset"] == **offset,
            "partition offset differs from official profile"
        );
    }
    for pair in ordered.windows(2) {
        let (name, start) = pair[0];
        let (_, end) = pair[1];
        ensure!(
            partitions[name]["size"] == end - start,
            "fixed partition length differs from official profile"
        );
    }
    let mut ranges = Vec::new();
    for region in partitions.values() {
        let offset = region["offset"].as_u64().context("invalid offset")?;
        let size = region["size"].as_u64().context("invalid size")?;
        ensure!(
            size > 0
                && offset.is_multiple_of(512)
                && size.is_multiple_of(512)
                && offset.checked_add(size).is_some_and(|end| end <= capacity),
            "partition exceeds capacity"
        );
        ranges.push((offset, offset + size));
    }
    ranges.sort();
    ensure!(
        ranges.windows(2).all(|v| v[0].1 <= v[1].0),
        "overlapping partition layout"
    );
    ensure!(
        partitions["userdata"]["offset"].as_u64().unwrap()
            + partitions["userdata"]["size"].as_u64().unwrap()
            == partitions["flashinfo"]["offset"],
        "userdata boundary differs"
    );
    Ok(())
}
// Progress activities. The first is host-driven; the rest are the phase names
// the USB worker reports with each of its own progress events.
const SAVE_ORIGINAL: &str = "save original";
const VERIFY_ORIGINAL: &str = "Verify original";
const WRITE_STAGE: &str = "Write";
const HASH_READBACK: &str = "Hash readback";
/// Fixed host wording for one progress tick.
///
/// Four different device operations drive this progress line and previously
/// shared the single label `Verifying NAME`: streaming an original into a local
/// backup, independently re-reading that partition from the device to check the
/// backup, writing the installer stage, and reading partitions back after that
/// write. The reported activity only selects wording here and is never shown
/// to the user, so no read, admission gate or ordering depends on it. Only boot
/// is written during bootstrap, because `authorize_boot` requires the stage
/// image to fill exactly that partition, so a readback of any other partition
/// is the recheck of the partitions the write had to leave untouched. An
/// unreported activity keeps the previous neutral wording.
fn progress_label(activity: &str, name: &str) -> String {
    match (activity, name) {
        (SAVE_ORIGINAL, _) => format!("Saving original {name} to this computer"),
        (VERIFY_ORIGINAL, _) => format!("Independently verifying saved {name} against the device"),
        (WRITE_STAGE, _) => format!("Writing the installer stage to {name}"),
        (HASH_READBACK, "boot") => format!("Verifying the installer stage written to {name}"),
        (HASH_READBACK, _) => format!("Rechecking retained {name} after the write"),
        _ => format!("Verifying {name}"),
    }
}
pub fn event(worker: &mut Worker, ui: &mut Ui, phase: usize) -> Result<Value> {
    loop {
        let value = worker.event()?;
        if value["event"] != "progress" {
            return Ok(value);
        }
        let done = value["done"].as_u64().context("invalid USB progress")?;
        let total = value["total"].as_u64().context("invalid USB progress")?;
        ensure!(
            done <= total && total <= 16 * 1024 * 1024 * 1024,
            "invalid USB progress bounds"
        );
        let name = value["target"]
            .as_str()
            .context("invalid USB progress target")?;
        ensure!(
            IDENTITY.contains(&name) || ORIGINALS.contains(&name),
            "invalid USB progress target"
        );
        let activity = value["phase"].as_str().unwrap_or_default();
        ui.progress(phase, &progress_label(activity, name), done, total)?;
    }
}

pub fn capture(
    worker: &mut Worker,
    device: &Value,
    session: &mut SessionGuard,
    ui: &mut Ui,
) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for name in IDENTITY.into_iter().chain(ORIGINALS) {
        let size = device["partitions"][name]["size"]
            .as_u64()
            .context("missing original partition")?;
        ensure!(
            size > 0 && size <= 256 * 1024 * 1024,
            "unexpected bootstrap backup size"
        );
        let path = session.path().join(format!("bootstrap-{name}.img"));
        let mut output = create(&path)?;
        let expected = worker.operation(Duration::from_secs(1800), |w| {
            w.send(&json!({"op":"read","target":name}))?;
            ensure!(
                w.event()? == json!({"event":"partition","target":name,"size":size}),
                "original partition header differs"
            );
            let mut done = 0;
            let mut full = Sha256::new();
            while done < size {
                let count = (size - done).min(CHUNK as u64) as usize;
                ui.progress(2, &progress_label(SAVE_ORIGINAL, name), done, size)?;
                let data = w.chunk(count)?;
                output.write_all(&data)?;
                full.update(&data);
                done += count as u64;
            }
            output.sync_all()?;
            let hash = format!("{:x}", full.finalize());
            ensure!(
                w.event()? == json!({"event":"read_complete","target":name,"sha256":hash}),
                "original transfer digest differs"
            );
            Ok(hash)
        })?;
        ensure!(
            digest(&path)? == expected,
            "saved original readback differs"
        );
        worker.operation(Duration::from_secs(1800), |w| {
            ui.progress(2, &progress_label(VERIFY_ORIGINAL, name), 0, size)?;
            w.send(&json!({"op":"hash","target":name}))?;
            ensure!(
                event(w, ui, 2)? == json!({"event":"hash","target":name,"sha256":expected}),
                "independent original device read differs"
            );
            Ok(())
        })?;
        session.checkpoint(&json!({"event":"bootstrap_original_verified","target":name,"size":size,"sha256":expected,"file":path.file_name().unwrap().to_str().unwrap()}))?;
        hashes.insert(name.into(), expected);
    }
    Ok(hashes)
}
/// Admit the saved boot/overlay originals as Android firmware for this HA100,
/// independent of the vendor firmware version. The caller already required the
/// selected Android CID, the exact HA100 layout, MT6580 hardware code,
/// independently captured originals and calibration. This only establishes
/// that the originals are Android images and not a previous Couch install.
pub fn android_originals(directory: &Path) -> Result<&'static str> {
    let boot = read_original(directory, "boot")?;
    let overlay = read_original(directory, "odmdtbo")?;
    crate::android_images::android_originals(&boot, &overlay)
        .context("original boot/overlay pair is not HA100 Android firmware")
}

/// One saved 16 MiB original, read from this session's own capture file.
fn read_original(directory: &Path, name: &str) -> Result<Vec<u8>> {
    let original = crate::regular(&directory.join(format!("bootstrap-{name}.img")))?;
    ensure!(
        original.metadata()?.is_file()
            && original.metadata()?.len() == crate::android_images::PARTITION_SIZE as u64,
        "original stock partition size differs"
    );
    let mut bytes = Vec::with_capacity(crate::android_images::PARTITION_SIZE);
    original
        .take(crate::android_images::PARTITION_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Classify the boot, recovery and overlay this session just captured, for a
/// reinstall without a saved enrollment. Each file is hashed again and must
/// still equal the digest its capture checkpoint recorded, so what is
/// classified is exactly what was read from the remote.
pub fn couch_originals(
    directory: &Path,
    captured: &BTreeMap<String, String>,
) -> Result<crate::android_images::CouchImages> {
    let mut images = BTreeMap::new();
    for name in ["boot", "recovery", "odmdtbo"] {
        let bytes = read_original(directory, name)?;
        ensure!(
            Some(&format!("{:x}", Sha256::digest(&bytes))) == captured.get(name),
            "saved original {name} changed after it was captured"
        );
        images.insert(name, bytes);
    }
    Ok(crate::android_images::couch_images(
        &images["boot"],
        &images["recovery"],
        &images["odmdtbo"],
    ))
}

pub fn original_boot(session: &SessionGuard) -> PathBuf {
    session.path().join("bootstrap-boot.img")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_progress_labels_distinguish_every_device_operation() {
        let ticks = [
            (SAVE_ORIGINAL, "boot"),
            (VERIFY_ORIGINAL, "boot"),
            (WRITE_STAGE, "boot"),
            (HASH_READBACK, "boot"),
            (HASH_READBACK, "nvdata"),
        ];
        let labels: Vec<_> = ticks
            .into_iter()
            .map(|(activity, name)| progress_label(activity, name))
            .collect();
        assert_eq!(
            labels
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            labels.len(),
            "each bootstrap device operation needs its own progress wording"
        );
        for ((_, name), label) in ticks.into_iter().zip(&labels) {
            assert!(label.contains(name), "progress label must name its target");
        }
        assert!(
            !progress_label(WRITE_STAGE, "boot")
                .to_lowercase()
                .contains("verif"),
            "the stage write must not be reported as a verification"
        );
        assert!(progress_label("unreported", "logo").contains("logo"));
    }
    #[test]
    fn android_originals_admit_any_android_firmware_but_never_a_couch_install() {
        use crate::android_images::fixtures;
        let root = tempfile::tempdir().unwrap();
        let write = |boot: &[u8], overlay: &[u8]| {
            fs::write(root.path().join("bootstrap-boot.img"), boot).unwrap();
            fs::write(root.path().join("bootstrap-odmdtbo.img"), overlay).unwrap();
        };
        write(&fixtures::android_boot(), &fixtures::mediatek_overlay());
        assert_eq!(
            android_originals(root.path()).unwrap(),
            "android-boot-image+mediatek-overlay"
        );
        // A different Android build is still Android: only the ramdisk contents change.
        write(
            &fixtures::boot_with(&[("init.rc", b"other version\n"), ("init", b"\x7fELF")]),
            &fixtures::mediatek_overlay(),
        );
        assert!(android_originals(root.path()).is_ok());
        write(&fixtures::couch_boot(), &fixtures::mediatek_overlay());
        let error = android_originals(root.path()).unwrap_err();
        assert!(format!("{error:#}").contains("no init.rc"), "{error:#}");
        write(
            &fixtures::android_boot(),
            &fixtures::overlay_with(b"qcom,sdm845\0"),
        );
        assert!(android_originals(root.path()).is_err());
        write(
            &fixtures::android_boot()[..1024],
            &fixtures::mediatek_overlay(),
        );
        assert!(android_originals(root.path()).is_err());
    }
    #[test]
    fn couch_originals_refuse_android_boot_and_foreign_overlay() {
        use crate::android_images::{fixtures, CouchImages};
        let root = tempfile::tempdir().unwrap();
        let write = |boot: &[u8], recovery: &[u8], overlay: &[u8]| {
            let mut captured = BTreeMap::new();
            for (name, bytes) in [("boot", boot), ("recovery", recovery), ("odmdtbo", overlay)] {
                fs::write(root.path().join(format!("bootstrap-{name}.img")), bytes).unwrap();
                captured.insert(name.to_string(), format!("{:x}", Sha256::digest(bytes)));
            }
            captured
        };
        let overlay = fixtures::mediatek_overlay();
        let captured = write(
            &fixtures::couch_boot(),
            &fixtures::couch_recovery(),
            &overlay,
        );
        assert_eq!(
            couch_originals(root.path(), &captured).unwrap(),
            CouchImages::Couch("couch-boot-image+couch-recovery-image+mediatek-overlay")
        );
        let captured = write(
            &fixtures::android_boot(),
            &fixtures::android_recovery(),
            &overlay,
        );
        assert_eq!(
            couch_originals(root.path(), &captured).unwrap(),
            CouchImages::AndroidBoot
        );
        let captured = write(&fixtures::stage(), &fixtures::android_recovery(), &overlay);
        assert_eq!(
            couch_originals(root.path(), &captured).unwrap(),
            CouchImages::AndroidRecovery
        );
        let captured = write(
            &fixtures::couch_boot(),
            &fixtures::couch_recovery(),
            &fixtures::overlay_with(b"qcom,sdm845\0"),
        );
        assert!(matches!(
            couch_originals(root.path(), &captured).unwrap(),
            CouchImages::Unrecognised(_)
        ));
        // The file is classified only while it is still what was captured.
        let mut captured = write(
            &fixtures::couch_boot(),
            &fixtures::couch_recovery(),
            &overlay,
        );
        fs::write(
            root.path().join("bootstrap-boot.img"),
            fixtures::android_boot(),
        )
        .unwrap();
        let error = couch_originals(root.path(), &captured).unwrap_err();
        assert!(format!("{error:#}").contains("changed after"), "{error:#}");
        captured.remove("recovery");
        assert!(couch_originals(root.path(), &captured).is_err());
        fs::write(root.path().join("bootstrap-boot.img"), b"short").unwrap();
        assert!(couch_originals(root.path(), &captured).is_err());
    }
    #[test]
    fn identity_encoding_and_complete_fixed_regions_are_required_before_bootstrap() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bootstrap")).unwrap();
        let scatter = include_str!("../tests/fixtures/ha100-scatter.txt");
        fs::write(root.path().join("bootstrap/scatter.txt"), scatter).unwrap();
        let mut ordered: Vec<_> = scatter
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let name = fields.next().unwrap();
                let offset =
                    u64::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16)
                        .unwrap();
                (!["preloader", "pgpt", "sgpt", "flashinfo"].contains(&name))
                    .then_some((name, offset))
            })
            .collect();
        ordered.sort_by_key(|v| v.1);
        let capacity = 4 * 1024 * 1024 * 1024u64;
        ordered.push(("flashinfo", capacity - 2 * 1024 * 1024));
        let mut parts = serde_json::Map::new();
        for pair in ordered.windows(2) {
            parts.insert(
                pair[0].0.into(),
                json!({"offset":pair[0].1,"size":pair[1].1-pair[0].1}),
            );
        }
        parts.insert(
            "flashinfo".into(),
            json!({"offset":capacity-2*1024*1024,"size":2*1024*1024}),
        );
        let cid = "12".repeat(16);
        let device = json!({"hwcode":0x6580,"cid_encoding":"mt6580-legacy-le32-registers","runtime_cid_sha256":format!("{:x}",Sha256::digest(decode(&cid).unwrap())),"capacity":capacity,"partitions":parts});
        admit_layout(&device, &cid, root.path()).unwrap();
        let mut shortened = device.clone();
        shortened["partitions"]["nvram"]["size"] = json!(512);
        assert!(admit_layout(&shortened, &cid, root.path()).is_err());
        let mut wrong = device.clone();
        wrong["cid_encoding"] = json!("guessed-permutation");
        assert!(admit_layout(&wrong, &cid, root.path()).is_err());
        assert!(admit_layout(&device, &"34".repeat(16), root.path()).is_err());
    }
}
