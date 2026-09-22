//! Offline acceptance for the reinstall-without-enrollment image check.
//!
//! `classify_saved_images DIRECTORY` classifies the `bootstrap-boot.img` and
//! `bootstrap-recovery.img` of every session folder directly under DIRECTORY
//! (for example `~/.couch-installer`) with the installer's own checks, and
//! prints what a reinstall without a saved enrollment would decide for that
//! capture. It opens no USB device, only reads the images, writes nothing,
//! and prints classes, never image bytes.
use anyhow::{ensure, Context, Result};
use couch_installer_host::android_images::{self, PARTITION_SIZE};
use std::{fs, io::Read, path::Path};

fn image(folder: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let path = folder.join(format!("bootstrap-{name}.img"));
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(None);
    };
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    fs::File::open(&path)?
        .take(PARTITION_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 1, "usage: classify_saved_images DIRECTORY");
    let root = Path::new(&args[0]);
    let mut folders: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("cannot list {}", root.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    folders.sort();
    println!("session\tboot\trecovery\treinstall without enrollment");
    for folder in folders {
        let (Some(boot), Some(recovery)) = (image(&folder, "boot")?, image(&folder, "recovery")?)
        else {
            continue;
        };
        let decision = match image(&folder, "odmdtbo")? {
            None => "no saved overlay".to_string(),
            Some(overlay) => match android_images::couch_images(&boot, &recovery, &overlay) {
                Ok(images) if images.stage_in_boot => {
                    format!("admit only with a data backup ({})", images.evidence)
                }
                Ok(images) => format!("admit ({})", images.evidence),
                Err(refused) => format!("refuse ({})", refused.reason()),
            },
        };
        println!(
            "{}\t{}\t{}\t{}",
            folder.file_name().unwrap_or_default().to_string_lossy(),
            android_images::boot_kind(&boot).name(),
            android_images::boot_kind(&recovery).name(),
            decision
        );
    }
    Ok(())
}
