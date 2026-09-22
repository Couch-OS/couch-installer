//! Structural admission of a remote's boot, recovery and overlay images.
//!
//! The installer writes its own boot, recovery, logo, overlay and userdata, so
//! the Android version on the remote does not affect Couch. The saved boot and
//! overlay matter for one reason: they are the originals that a stock restore
//! writes back and that a reinstall on another computer imports. This module
//! checks that they are what an HA100 running Android carries, independent of
//! the firmware version:
//!
//! - `boot` is an Android boot image whose ramdisk is a gzip cpio archive with
//!   Android's `init.rc` at its root. Every Couch boot and installer image
//!   reuses the vendor header but carries a busybox ramdisk without `init.rc`,
//!   so a previous Couch install is never admitted as an Android original.
//! - `odmdtbo` is a MediaTek dtbo container whose flattened device tree names
//!   `mediatek,` compatibles.
//!
//! A reinstall without a saved enrollment needs the opposite, positive answer
//! before it writes anything: that the remote runs Couch. [`couch_boot`]
//! accepts only Couch's own ramdisk shape, and [`couch_images`] requires it of
//! both boot and recovery, so an Android remote whose boot still holds a
//! half-written installer stage (same busybox shape as Couch) is refused by
//! its Android recovery.
//!
//! HA100 identity itself is established elsewhere: the exact partition layout,
//! the eMMC CID, the MT6580 hardware code and the ADB model.
use anyhow::{ensure, Context, Result};
use flate2::read::GzDecoder;
use std::{io::Read, ops::Range};

pub const PARTITION_SIZE: usize = 16 * 1024 * 1024;
const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const MTK_DTBO_MAGIC: u32 = 0x8816_8858;
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_OFFSET: usize = 0x400;
const RAMDISK_LIMIT: u64 = 64 * 1024 * 1024;
/// How every Couch boot, recovery and installer-stage `init` starts.
const COUCH_INIT: &[u8] = b"#!/bin/busybox sh";
const REGULAR_FILE: u32 = 0o100000;
const FILE_TYPE: u32 = 0o170000;

fn le32(bytes: &[u8], offset: usize) -> Result<usize> {
    let raw = bytes
        .get(offset..offset + 4)
        .context("truncated image header")?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()) as usize)
}
fn be32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .context("truncated image header")?;
    Ok(u32::from_be_bytes(raw.try_into().unwrap()))
}
fn aligned(value: usize, page: usize) -> Result<usize> {
    value
        .checked_add(page - 1)
        .map(|n| n / page * page)
        .context("image offset overflow")
}

/// One entry of a newc cpio archive: its name, mode and where its data lies.
struct CpioEntry {
    name: String,
    mode: u32,
    data: Range<usize>,
}
impl CpioEntry {
    fn regular(&self) -> bool {
        self.mode & FILE_TYPE == REGULAR_FILE
    }
}

/// The entries of a newc cpio archive. Lenient on purpose: it only walks
/// headers and never trusts metadata beyond the bounds it needs.
fn cpio_entries(archive: &[u8]) -> Result<Vec<CpioEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(header) = archive.get(offset..offset + 110) {
        ensure!(
            &header[..6] == b"070701" || &header[..6] == b"070702",
            "ramdisk is not a newc cpio archive"
        );
        let field = |index: usize| -> Result<usize> {
            let text = std::str::from_utf8(&header[6 + index * 8..14 + index * 8])?;
            Ok(usize::from_str_radix(text, 16)?)
        };
        let (mode, size, name_size) = (field(1)?, field(6)?, field(11)?);
        ensure!(name_size > 0 && name_size <= 4096, "invalid cpio name size");
        let name_end = offset + 110 + name_size;
        let name = archive
            .get(offset + 110..name_end)
            .context("truncated cpio name")?;
        let name = std::str::from_utf8(&name[..name.len() - 1])?.to_owned();
        let data_start = aligned(name_end, 4)?;
        let data_end = data_start.checked_add(size).context("cpio overflow")?;
        offset = aligned(data_end, 4)?;
        ensure!(offset <= archive.len(), "truncated cpio file");
        if name == "TRAILER!!!" {
            return Ok(entries);
        }
        entries.push(CpioEntry {
            name,
            mode: mode as u32,
            data: data_start..data_end,
        });
        ensure!(entries.len() <= 65536, "cpio archive exceeds bound");
    }
    anyhow::bail!("cpio archive has no trailer")
}

/// The decompressed ramdisk of one full boot-partition image in the Android
/// boot image format (header version 0, as MT6580 firmware uses). `what`
/// names the image in errors.
fn ramdisk(image: &[u8], what: &str) -> Result<Vec<u8>> {
    ensure!(
        image.len() == PARTITION_SIZE,
        "{what} is not a complete partition"
    );
    ensure!(
        &image[..8] == BOOT_MAGIC,
        "{what} is not an Android boot image"
    );
    let kernel_size = le32(image, 8)?;
    let ramdisk_size = le32(image, 16)?;
    let page = le32(image, 36)?;
    ensure!(
        [2048, 4096, 8192, 16384].contains(&page) && kernel_size > 0 && ramdisk_size > 0,
        "{what} has an unsupported header geometry"
    );
    let ramdisk_start = aligned(page + kernel_size, page)?;
    let ramdisk = image
        .get(
            ramdisk_start
                ..ramdisk_start
                    .checked_add(ramdisk_size)
                    .context("boot overflow")?,
        )
        .with_context(|| format!("{what} ramdisk exceeds the partition"))?;
    let mut archive = Vec::new();
    GzDecoder::new(ramdisk)
        .take(RAMDISK_LIMIT + 1)
        .read_to_end(&mut archive)
        .with_context(|| format!("{what} ramdisk is not gzip"))?;
    ensure!(
        archive.len() as u64 <= RAMDISK_LIMIT,
        "{what} ramdisk exceeds bound"
    );
    Ok(archive)
}

/// An Android boot image (header version 0, as MT6580 firmware uses) whose
/// gzip cpio ramdisk carries Android's `init.rc` at the archive root.
pub fn android_boot(image: &[u8]) -> Result<()> {
    let archive = ramdisk(image, "boot original")?;
    let entries = cpio_entries(&archive)?;
    ensure!(
        entries.iter().any(|entry| entry.name == "init.rc"),
        "boot original ramdisk is not Android (no init.rc); a Couch image is not an Android original"
    );
    Ok(())
}

/// A Couch boot, recovery or installer-stage image: the vendor header over a
/// busybox ramdisk whose root holds exactly one `init`, a regular file
/// starting `#!/bin/busybox sh`, and exactly one regular `bin/busybox`, and
/// no Android `init.rc`. Stock Android boot and recovery images carry a root
/// `init.rc` and an ELF `init`, so neither shape can pass for the other.
pub fn couch_boot(image: &[u8]) -> Result<()> {
    let archive = ramdisk(image, "image")?;
    let entries = cpio_entries(&archive)?;
    let named = |name: &str| {
        entries
            .iter()
            .filter(|entry| entry.name == name)
            .collect::<Vec<_>>()
    };
    ensure!(
        named("init.rc").is_empty(),
        "image is Android (its ramdisk has init.rc)"
    );
    let init = named("init");
    ensure!(
        init.len() == 1
            && init[0].regular()
            && archive[init[0].data.clone()].starts_with(COUCH_INIT),
        "image ramdisk has no Couch init (a root #!/bin/busybox sh script)"
    );
    let busybox = named("bin/busybox");
    ensure!(
        busybox.len() == 1 && busybox[0].regular(),
        "image ramdisk has no bin/busybox"
    );
    Ok(())
}

/// What one boot-format image is, as far as a reinstall is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootKind {
    /// Stock Android: a root `init.rc`.
    Android,
    /// Couch's boot, recovery or installer stage.
    Couch,
    /// Neither: empty, truncated, foreign or damaged.
    Unrecognised,
}
impl BootKind {
    pub fn name(self) -> &'static str {
        match self {
            BootKind::Android => "android",
            BootKind::Couch => "couch",
            BootKind::Unrecognised => "unrecognised",
        }
    }
}
pub fn boot_kind(image: &[u8]) -> BootKind {
    if android_boot(image).is_ok() {
        BootKind::Android
    } else if couch_boot(image).is_ok() {
        BootKind::Couch
    } else {
        BootKind::Unrecognised
    }
}

/// What a reinstall without a saved enrollment makes of the remote's current
/// boot, recovery and overlay, before anything is written.
#[derive(Debug, PartialEq, Eq)]
pub enum CouchImages {
    /// Boot and recovery are Couch's and the overlay is MediaTek's. Carries
    /// the evidence string recorded in the journal.
    Couch(&'static str),
    /// Boot is stock Android: the remote runs Android.
    AndroidBoot,
    /// Recovery is stock Android: the remote was last running Android, even
    /// if its boot now holds a half-written installer stage.
    AndroidRecovery,
    /// Neither Couch nor Android, or a foreign overlay; names the failed check.
    Unrecognised(String),
}
impl CouchImages {
    /// Journal reason for a refusal.
    pub fn reason(&self) -> &'static str {
        match self {
            CouchImages::Couch(_) => "couch",
            CouchImages::AndroidBoot => "android_boot",
            CouchImages::AndroidRecovery => "android_recovery",
            CouchImages::Unrecognised(_) => "unrecognised",
        }
    }
}
pub fn couch_images(boot: &[u8], recovery: &[u8], overlay: &[u8]) -> CouchImages {
    if android_boot(boot).is_ok() {
        return CouchImages::AndroidBoot;
    }
    if android_boot(recovery).is_ok() {
        return CouchImages::AndroidRecovery;
    }
    for (name, check) in [
        ("boot", couch_boot(boot)),
        ("recovery", couch_boot(recovery)),
        ("odmdtbo", mediatek_overlay(overlay)),
    ] {
        if let Err(error) = check {
            return CouchImages::Unrecognised(format!("{name}: {error:#}"));
        }
    }
    CouchImages::Couch("couch-boot-image+couch-recovery-image+mediatek-overlay")
}

/// A MediaTek dtbo container with a flattened device tree at 0x400 that names
/// `mediatek,` compatibles.
pub fn mediatek_overlay(image: &[u8]) -> Result<()> {
    ensure!(
        image.len() == PARTITION_SIZE,
        "overlay original is not a complete partition"
    );
    ensure!(
        be32(image, 0)? == MTK_DTBO_MAGIC && &image[8..12] == b"dtbo",
        "overlay original is not a MediaTek dtbo container"
    );
    ensure!(
        be32(image, FDT_OFFSET)? == FDT_MAGIC,
        "overlay original carries no device tree"
    );
    let total = be32(image, FDT_OFFSET + 4)? as usize;
    let tree = image
        .get(FDT_OFFSET..FDT_OFFSET.checked_add(total).context("overlay overflow")?)
        .filter(|tree| tree.len() >= 40)
        .context("overlay original device tree exceeds the partition")?;
    ensure!(
        tree.windows(9).any(|window| window == b"mediatek,"),
        "overlay original device tree is not a MediaTek overlay"
    );
    Ok(())
}

/// Both originals together; the evidence string is recorded in the journal.
pub fn android_originals(boot: &[u8], overlay: &[u8]) -> Result<&'static str> {
    android_boot(boot)?;
    mediatek_overlay(overlay)?;
    Ok("android-boot-image+mediatek-overlay")
}

#[cfg(test)]
pub(crate) mod fixtures {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn cpio(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut push = |name: &str, mode: u32, data: &[u8]| {
            let header = format!(
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                out.len() + 1, mode, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name.len() + 1, 0
            );
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        };
        for (name, mode, data) in entries {
            push(name, *mode, data);
        }
        push("TRAILER!!!", 0, b"");
        out
    }
    pub(crate) fn boot_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let regular: Vec<_> = entries
            .iter()
            .map(|(name, data)| (*name, 0o100644, *data))
            .collect();
        boot_with_modes(&regular)
    }
    pub(crate) fn boot_with_modes(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&cpio(entries)).unwrap();
        let ramdisk = gzip.finish().unwrap();
        let kernel = vec![0xe1; 4000];
        let mut image = vec![0u8; super::PARTITION_SIZE];
        image[..8].copy_from_slice(b"ANDROID!");
        image[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        image[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        image[36..40].copy_from_slice(&2048u32.to_le_bytes());
        image[2048..2048 + kernel.len()].copy_from_slice(&kernel);
        let ramdisk_start = 2048 + kernel.len().div_ceil(2048) * 2048;
        image[ramdisk_start..ramdisk_start + ramdisk.len()].copy_from_slice(&ramdisk);
        image
    }
    /// A vendor Android boot image: Android ramdisk with init.rc.
    pub(crate) fn android_boot() -> Vec<u8> {
        boot_with(&[
            ("init.rc", b"on init\n"),
            ("default.prop", b"ro.debuggable=1\n"),
        ])
    }
    /// A stock recovery: the same shape as the stock boot, with an ELF init.
    pub(crate) fn android_recovery() -> Vec<u8> {
        boot_with(&[
            ("init", b"\x7fELF\x01\x01\x01"),
            ("init.rc", b"on init\n"),
            ("init.recovery.mt6580.rc", b"on init\n"),
        ])
    }
    /// A Couch-style image: same header, busybox ramdisk, no init.rc.
    pub(crate) fn couch_boot() -> Vec<u8> {
        boot_with(&[
            ("bin/busybox", b"\x7fELF"),
            ("init", b"#!/bin/busybox sh\n"),
        ])
    }
    /// Couch recovery: its own busybox init script beside the same busybox.
    pub(crate) fn couch_recovery() -> Vec<u8> {
        boot_with(&[
            ("bin", b""),
            ("bin/busybox", b"\x7fELF"),
            ("extra/fbcon", b"\x7fELF"),
            ("init", b"#!/bin/busybox sh\n# Couch recovery\n"),
        ])
    }
    /// The installer's RAM stage, which an interrupted run leaves in boot.
    pub(crate) fn stage() -> Vec<u8> {
        boot_with(&[
            ("init", b"#!/bin/busybox sh\n# Private benchmark only.\n"),
            ("bin/busybox", b"\x7fELF"),
            ("bin/couch-installer-probe", b"\x7fELF"),
        ])
    }
    pub(crate) fn overlay_with(compatible: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; super::PARTITION_SIZE];
        image[..4].copy_from_slice(&super::MTK_DTBO_MAGIC.to_be_bytes());
        image[8..12].copy_from_slice(b"dtbo");
        let mut tree = Vec::new();
        tree.extend_from_slice(&super::FDT_MAGIC.to_be_bytes());
        let total = 40 + 8 + compatible.len().div_ceil(4) * 4 + 8;
        tree.extend_from_slice(&(total as u32).to_be_bytes());
        tree.extend_from_slice(&[0u8; 32]);
        tree.extend_from_slice(compatible);
        tree.resize(total, 0);
        image[super::FDT_OFFSET..super::FDT_OFFSET + total].copy_from_slice(&tree);
        image
    }
    pub(crate) fn mediatek_overlay() -> Vec<u8> {
        overlay_with(b"mediatek,mt6580\0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_boot_with_init_rc_is_admitted_and_couch_ramdisk_is_not() {
        android_boot(&fixtures::android_boot()).unwrap();
        let couch = android_boot(&fixtures::couch_boot()).unwrap_err();
        assert!(couch.to_string().contains("no init.rc"), "{couch}");
        // init.rc must sit at the archive root, not inside a nested directory.
        assert!(android_boot(&fixtures::boot_with(&[("system/init.rc", b"x")])).is_err());
    }

    #[test]
    fn boot_geometry_and_container_faults_are_rejected() {
        let good = fixtures::android_boot();
        let mut short = good.clone();
        short.truncate(PARTITION_SIZE - 1);
        assert!(android_boot(&short).is_err());
        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(android_boot(&magic).is_err());
        let mut page = good.clone();
        page[36..40].copy_from_slice(&1000u32.to_le_bytes());
        assert!(android_boot(&page).is_err());
        let mut oversized = good.clone();
        oversized[16..20].copy_from_slice(&(PARTITION_SIZE as u32).to_le_bytes());
        assert!(android_boot(&oversized).is_err());
        // The ramdisk starts one page after the 4000-byte kernel: 2048 + 4096.
        let mut plain = good.clone();
        plain[6144..6144 + 4].copy_from_slice(b"0707");
        assert!(android_boot(&plain).is_err());
        assert!(android_boot(&vec![0; PARTITION_SIZE]).is_err());
    }

    #[test]
    fn overlay_requires_mediatek_dtbo_container_with_device_tree() {
        mediatek_overlay(&fixtures::mediatek_overlay()).unwrap();
        assert!(mediatek_overlay(&fixtures::overlay_with(b"qcom,sdm845\0")).is_err());
        let mut no_tree = fixtures::mediatek_overlay();
        no_tree[FDT_OFFSET] = 0;
        assert!(mediatek_overlay(&no_tree).is_err());
        let mut huge = fixtures::mediatek_overlay();
        huge[FDT_OFFSET + 4..FDT_OFFSET + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(mediatek_overlay(&huge).is_err());
        let mut tag = fixtures::mediatek_overlay();
        tag[8..12].copy_from_slice(b"dtbX");
        assert!(mediatek_overlay(&tag).is_err());
        assert!(mediatek_overlay(&vec![0; PARTITION_SIZE]).is_err());
        assert!(mediatek_overlay(&fixtures::mediatek_overlay()[..PARTITION_SIZE - 1]).is_err());
    }

    #[test]
    fn pair_evidence_names_both_structures() {
        assert_eq!(
            android_originals(&fixtures::android_boot(), &fixtures::mediatek_overlay()).unwrap(),
            "android-boot-image+mediatek-overlay"
        );
        assert!(android_originals(&fixtures::couch_boot(), &fixtures::mediatek_overlay()).is_err());
        assert!(android_originals(&fixtures::android_boot(), &fixtures::couch_boot()).is_err());
    }

    #[test]
    fn couch_boot_admits_couch_and_stage_ramdisks_but_never_android() {
        for couch in [
            fixtures::couch_boot(),
            fixtures::couch_recovery(),
            fixtures::stage(),
        ] {
            couch_boot(&couch).unwrap();
            assert_eq!(boot_kind(&couch), BootKind::Couch);
        }
        for android in [fixtures::android_boot(), fixtures::android_recovery()] {
            let error = couch_boot(&android).unwrap_err().to_string();
            assert!(error.contains("init.rc"), "{error}");
            assert_eq!(boot_kind(&android), BootKind::Android);
        }
        // A busybox init beside Android's init.rc is still Android.
        let mixed = fixtures::boot_with(&[
            ("init", b"#!/bin/busybox sh\n"),
            ("bin/busybox", b"\x7fELF"),
            ("init.rc", b"on init\n"),
        ]);
        assert!(couch_boot(&mixed).is_err());
        assert_eq!(boot_kind(&mixed), BootKind::Android);
        let mut truncated = fixtures::couch_boot();
        truncated.truncate(PARTITION_SIZE - 512);
        for (label, image) in [
            ("zeros", vec![0; PARTITION_SIZE]),
            ("truncated", truncated),
            (
                "elf init without init.rc",
                fixtures::boot_with(&[("init", b"\x7fELF"), ("bin/busybox", b"\x7fELF")]),
            ),
            (
                "another shell",
                fixtures::boot_with(&[("init", b"#!/bin/sh\n"), ("bin/busybox", b"\x7fELF")]),
            ),
            (
                "no busybox",
                fixtures::boot_with(&[("init", b"#!/bin/busybox sh\n")]),
            ),
            (
                "nested init",
                fixtures::boot_with(&[
                    ("sbin/init", b"#!/bin/busybox sh\n"),
                    ("bin/busybox", b"\x7fELF"),
                ]),
            ),
            (
                "two inits",
                fixtures::boot_with(&[
                    ("init", b"#!/bin/busybox sh\n"),
                    ("init", b"\x7fELF"),
                    ("bin/busybox", b"\x7fELF"),
                ]),
            ),
            (
                "symlinked init",
                fixtures::boot_with_modes(&[
                    ("init", 0o120777, b"#!/bin/busybox sh"),
                    ("bin/busybox", 0o100755, b"\x7fELF"),
                ]),
            ),
        ] {
            assert!(couch_boot(&image).is_err(), "{label} was admitted as Couch");
            assert_eq!(boot_kind(&image), BootKind::Unrecognised, "{label}");
        }
    }

    #[test]
    fn a_reinstall_needs_couch_boot_and_couch_recovery_and_a_mediatek_overlay() {
        let overlay = fixtures::mediatek_overlay();
        let couch = |boot: &[u8], recovery: &[u8]| couch_images(boot, recovery, &overlay);
        assert_eq!(
            couch(&fixtures::couch_boot(), &fixtures::couch_recovery()),
            CouchImages::Couch("couch-boot-image+couch-recovery-image+mediatek-overlay")
        );
        // A Couch remote stuck mid-install still has Couch recovery: repairable.
        assert!(matches!(
            couch(&fixtures::stage(), &fixtures::couch_recovery()),
            CouchImages::Couch(_)
        ));
        // The same stage beside Android's recovery is an Android remote whose
        // install stopped after the boot write: refused, or Android would lose
        // its data with no backup.
        assert_eq!(
            couch(&fixtures::stage(), &fixtures::android_recovery()),
            CouchImages::AndroidRecovery
        );
        assert_eq!(
            couch(&fixtures::android_boot(), &fixtures::android_recovery()),
            CouchImages::AndroidBoot
        );
        assert_eq!(
            couch(&fixtures::android_boot(), &fixtures::couch_recovery()),
            CouchImages::AndroidBoot
        );
        assert_eq!(
            couch(&fixtures::couch_boot(), &fixtures::android_recovery()),
            CouchImages::AndroidRecovery
        );
        for (boot, recovery, check) in [
            (vec![0; PARTITION_SIZE], fixtures::couch_recovery(), "boot:"),
            (fixtures::couch_boot(), vec![0; PARTITION_SIZE], "recovery:"),
            (
                fixtures::couch_boot()[..4096].to_vec(),
                fixtures::couch_recovery(),
                "boot:",
            ),
        ] {
            match couch(&boot, &recovery) {
                CouchImages::Unrecognised(detail) => {
                    assert!(detail.starts_with(check), "{detail}")
                }
                other => panic!("{other:?}"),
            }
        }
        let foreign = couch_images(
            &fixtures::couch_boot(),
            &fixtures::couch_recovery(),
            &fixtures::overlay_with(b"qcom,sdm845\0"),
        );
        assert!(matches!(&foreign, CouchImages::Unrecognised(d) if d.starts_with("odmdtbo:")));
        assert_eq!(foreign.reason(), "unrecognised");
        assert_eq!(CouchImages::AndroidRecovery.reason(), "android_recovery");
    }
}
