# Native installer host

The `frontend` module communicates directly with the Ratatui terminal over its
private inherited socket (Unix) or pipes (Windows). Prompts use increasing IDs;
invalid, stale, cancelled, truncated or oversized replies stop the channel.
Input buffers are zeroized and secret replies are never echoed as display state.
The `--ui-smoke` command is an explicit device-free interface fixture. The native installation orchestrator uses the same channel for the complete
fresh-Android and retained-enrollment reinstall flows described below.

The independent `prepare-official` command performs complete
owner-side official input preparation. It verifies the pinned ZIP, bounded
full-OTA transfer lists and Brotli streams, then reads the approved files through
a [read-only Rust ext4 parser](https://docs.rs/ext4-view/0.9.3/ext4_view/).
That input-preparation command executes no subprocess, requires no Python or debugfs, mounts no filesystem
and opens no USB/device handles. It uses ordinary private scratch files.

```sh
cargo build --release --locked
./target/release/couch-installer-host prepare-official \
  /path/to/official.zip /path/outside-git/new-private-inputs
```

The output matches the owner-input and private-vendor receipts consumed by the
existing installer prerequisites. Exactly four bootstrap members and 33 runtime
files are accepted using compile-time pins. Preloader is an EMI input only;
there is no preloader writer. Output is published only after all hashes verify,
and remains private/noninstallable with no redistribution authorization.
Distribution firmware is not an original-device backup.

The Windows binary is `couch-installer-host.exe`; input preparation uses the
same native Rust pipeline. CI runs portable fixtures on Linux, macOS and Windows.
The manual workflow option additionally downloads the pinned official OTA and
executes the real pipeline on all three hosts without uploading vendor outputs.
The original vendor URL uses HTTP; the reviewed repository SHA-256 pin checks
its bytes before parsing, but does not create an independent vendor signature.

The native orchestrator now connects these inputs to supervised USB startup,
Wi-Fi setup, backups and the Linux-stage writer. Filesystem expansion and
personalization run on the remote, so host e2fsprogs are unnecessary. Public
release readiness still requires a verified release payload and separate physical
acceptance; native builds and preparation tests alone do not certify installation.

## Session journals

`SessionGuard::create(new_directory)` starts a single attempt under an existing
private state directory outside Git. Unix parents must be owned by the effective
user and mode0700; macOS parents with extended ACLs are rejected. Windows requires
a filesystem with persistent ACLs, validates owner/access grants, creates a
protected user/System DACL and holds directory handles against replacement.
The caller should use its private per-user application state directory.

`transition(Phase, evidence)` enforces the reviewed forward sequence;
`checkpoint(evidence)` records per-partition hashes without advancing that phase.
Persist a checkpoint before sending a corresponding device acknowledgement.
Evidence is bounded to64KiB per event and must contain hashes/receipt references,
not credentials. Events are immutable, atomically published and flushed; Windows
uses write-through rename because it has no Unix directory-fsync contract.
Actual power-loss durability on host storage remains a physical validation.

A persistence failure disables that guard. Existing directories, including
interrupted writes, cannot be opened as new sessions. Drop only releases the
process lock and preserves originals/journals. Explicit recovery is separate.
The session lock excludes another owner of that run; the USB adapter must also
enforce device-wide exclusion across different run directories. These primitives
do not open USB or authorize writes.

The native library also contains Linux-stage transport primitives. `stage_tls`
connects only to an explicit selected address using TLS 1.3 and the certificate
provisioned over USB, checks the exact peer certificate before sending the
session token, and applies absolute deadlines to socket I/O. It uses
[Rustls's explicit provider and trust-store configuration](https://docs.rs/rustls/0.23.44/rustls/client/struct.ClientConfig.html),
without system roots, fallback trust or automatic reconnect.

`stage` bounds JSON and raw/zlib frames and validates monotonic verification
progress. `stage_files` independently reads back saved host backups, compares the
device's readback hash and identity pin, and rechecks each image chunk immediately
before sending. Saving a backup returns its hash without acknowledging it: the
orchestrator must persist a journal checkpoint before permitting the next device
phase. These APIs have loopback/file fixtures on Linux and macOS; the host CI
matrix also runs them on Windows.

`transaction` drives a previously admitted USB-bound plan through original boot
copy/readback, complete selected backups, recovery/userdata/optional image writes
and final boot. Every acknowledgement follows a durable `SessionGuard` checkpoint;
original files live directly beside the journal so its directory synchronization
also commits their entries. Image contents are reverified after backups and again
per chunk. Explicit YOLO omits only userdata backup. Failed expansion or journal
publication prevents the final boot acknowledgement. Completion leaves the restart
decision to the caller; there is no automatic reconnect, restore or retry.

The integrated orchestrator below connects these components. Direct library
callers must still verify the release, enrollment evidence, selected device and
USB plan binding before using the transaction API; it deliberately does not
infer admission from a caller-supplied plan alone.

## Native installation orchestration

`couch-installer-tui --native-backend /path/to/couch-installer-host --config
/path/to/installer.json` now enters the native installation flow. Use the
release-specific launcher to verify these files together; an arbitrary local
configuration is not a trusted release. Selecting Cancel happens before
configuration loading, downloads, private-session creation or USB access.

Rust owns dependency preparation, owner-side OTA extraction, fixed public payload
admission, session/USB locks, Android enrollment, progress, Wi-Fi selection and
TLS installation. The embedded Python worker retains only the reviewed MTK
handshake and a fixed USB setup protocol. It uses the independently verified
owner-local Python/MTK/libusb bundle, never a system-library fallback. Pipe reads,
writes and nested USB operations have finite deadlines; cancellation kills the
worker. Windows uses a kill-on-close job, Linux a parent-death signal, and macOS
inherits the TUI's process group.

Fresh enrollment requires authorized Android ADB, canonical storage CID, exact
physical USB selection, the pinned HA100 partition boundaries and matching stock
boot/device-tree prefixes or the reviewed retained-stock full-image pair. Original calibration, boot, recovery, device tree and
logo are read, saved, independently read back and journaled before the sole USB
boot write. Device ID and unavailable MAC addresses are entered from Android;
Android ID or serial is never substituted for the vendor Device ID. Free space
for the selected backups is checked before bootstrap. No preloader or LK write
operation exists in the worker.

Reinstallation imports a [saved enrollment](https://github.com/dangerouslaser/couch/blob/dev/docs/installer-saved-enrollment.md)
into a new private session. Every Couch restart (Reinstall, Restore and a
reinstall without a saved enrollment, on the first attempt and on every
download-mode retry) goes through one readiness check in `couch_restart`. A
read-only, nonce-framed query over the selected port's Couch serial function
returns the storage CID, the SHA-256 of the first 512 bytes of the boot control
block (`mmcblk0p10`) and the uptime. Only two block values are legitimate: all
zeros (the next start is normal) and `boot-recovery` followed by zeros (the next
start is COUCH RECOVERY); any other value, or a missing tool, reads as unknown.
The CID must match, and the remote is restarted only once the flag reads clear:
an armed flag on a remote up for less than 170 s waits until 180 s of uptime
and asks again, and one still armed after that wait stops at a not-ready screen.
A flag still armed after 170 s will not clear by itself (the remote is in COUCH
RECOVERY, or its GUI never became healthy), so the installer offers to clear it.
The request is journaled first. The worker then re-reads the CID and requires
exactly the armed block, runs the recovery action's own pre-write probes (the
HA100 boot command line and the `mmcblk0p10` block device), sends its `dd`
clear and `od` readback (a host test keeps all these command strings
identical), and requires a zero readback and a clear digest, at most once per
worker. Any failure after the write stops without a restart, saying the flag
may already be clear. The one-shot reboot then restarts the remote straight
into download mode. An unknown flag first waits until 180 s of uptime (the full
180 s on a retry without an uptime); an unknown flag after that, or a remote
that does not answer three queries two seconds apart, needs the user to confirm
the normal screen has been up for three minutes, and a silent remote is then
restarted by hand. The unchanged one-shot reboot, which re-reads the CID,
follows two seconds after the query, since macOS re-enumerates the device when
libusb releases it. On Windows the query uses the COM port Windows created for
Couch's serial function, and only one whose reported location matches the
selected physical port chain exactly (never a port of unknown location);
anything else falls back to the manual restart. The reboot and the flag clear
go through libusb only, so on Windows the restart is a manual Power-button
restart and the clear is not offered until it has been tested on hardware.
A CID mismatch or ambiguous reboot stops without retry.
Download-mode CID, full layout, calibration and retained device-tree identity
are checked again before writing. Current Couch originals are saved separately
and marked Couch; imported Android originals are preserved for Android recovery
and never replaced by Couch backups.

Without a saved enrollment, Reinstall can continue from what is on the remote
now, after a screen that says Restore stock Android will then be unavailable for
it; Restore never offers this. Nothing is imported. The running Couch's answer
to the identity query binds its CID, and the download-agent CID on the same
physical port must match it; when the serial function could not be asked, the
download-agent CID is the first observation (journaled as `cid_source:
download_agent`). After the read-only capture and before any write, the captured
boot and recovery must both be structurally Couch (a gzip cpio ramdisk with
exactly one root `init` starting `#!/bin/busybox sh`, a root `bin/busybox` and no
`init.rc`) and the overlay a MediaTek dtbo. A stock Android boot or recovery
refuses, which also refuses an Android remote whose boot still holds a
half-written installer stage. The installer's own RAM stage in boot beside Couch's
recovery (an earlier installation stopped halfway, possibly over Android's data)
is admitted only when current data is backed up first. The session records `original_os: Couch` and
`android_enrollment: none` in `current-couch-snapshot.json`; it is never offered
or imported as an Android enrollment, and the bootstrap recovery tool admits its
`couch_device_bound` binding. To check that decision offline against saved
captures, read-only and printing classes only:

```sh
cargo run --locked --example classify_saved_images -- ~/.couch-installer
```

The public payload contains only `manifest.json`, `userdata.ext4`,
`installer.cpio.gz`, `boot.cpio.gz`, `recovery.cpio.gz`, `zImage` and `logo.bgra`.
The manifest uses schema 1, kind `couch-public-os-inputs`, release `version`,
`source_commit`, and a `files` map of exact size/SHA-256 pairs. Owner vendor data,
stock kernel/header material and retained logo frames are assembled locally.
Non-files, unknown paths, duplicate entries, changed hashes and trailing payload
data are rejected. No private device baseline is a public input.

After USB-bound Wi-Fi credentials and TLS identity are provisioned, Rust performs
all requested backups, transfers the 33 pinned owner vendor files, and writes the
compact filesystem. The stage expands it, installs and reads back vendor/Wi-Fi
files, checks calibration, and commits normal boot last. The final restart is an
explicit choice after verification. YOLO omits only the userdata backup.

These source paths and fixtures do not certify a physical installation on every
host. Windows additionally requires a usable driver binding for the selected
MTK download interface and installer vendor interface. The installer reports a
bounded claim failure; it does not replace drivers for other USB devices. See
[libusb's Windows driver documentation](https://github.com/libusb/libusb/wiki/Windows#driver-installation).
Fresh Android enrollment, OS startup, restoration and reinstall from another
computer need separate physical acceptance records before a public-ready claim.

### Leaving Couch recovery

**My remote shows COUCH RECOVERY** is a first-menu action for a remote that
starts into recovery on every boot. It needs no release configuration, no
downloads, no Python worker and no administrator rights: `recovery` runs
entirely in this crate, and the orchestrator dispatches it before anything the
installation flow requires. A runtime candidate that failed its health check on
an image with an older bootstrap is rolled back correctly but leaves
`boot-recovery` armed in the bootloader control block, and recovery keeps that
flag on purpose, so every following boot returns there.

`recovery::discover` resolves the recovery USB identity `0e8d:201c` to the
serial port the operating system created for its CDC ACM function, through that
system's own record and never by guessing from a port name:

- **macOS** reads `ioreg -a -l -r -c IOUSBHostDevice` and walks the device whose
  `idVendor`/`idProduct` match, taking the single `IOCalloutDevice` in its
  subtree; `locationID` gives the bus and hub port chain, decoded exactly as the
  Python callout transport does. Empty output means no USB device, not an error.
- **Linux** reads `/sys/bus/usb/devices`, matching `idVendor`/`idProduct` and
  taking the single `tty/` entry across that device's interfaces, with `busnum`
  and `devpath` as the location.
- **Windows** reads the device instances under
  `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_0E8D&PID_201C[&MI_xx]` with the
  same registry reader as the driver pre-flight, takes the instance's
  `Device Parameters\PortName`, and prefers instances Windows currently reports
  as started (a volatile `Control` key). Nothing binds or replaces a driver.

More than one candidate, or a device the host has not given exactly one serial
port, refuses and asks for the others to be disconnected. The action never
chooses a remote, and discovery happens once.

`recovery::shell` then proves the port really is a Couch recovery shell before
anything is written. That shell is `busybox sh` run non-interactively on the USB
gadget, so it prints no prompt; every command is framed by a per-session random
marker that only ever reaches the remote inside a `printf` format argument, so
the tty's echo can never be read as an answer. The read-only probes are
`cat /proc/cmdline` (must carry the HA100 boot image command line),
`test -f /mnt/alpine/opt/couch/stage2.sh` (recovery's own test that the Couch
filesystem is attached; normal Couch mounts it at the same place, so this alone
does not tell recovery from a normal boot),
`readlink /mnt/alpine/opt/couch/runtime/current` (`slots/<sha256>`, or absent
for the base runtime), `test -b /dev/mmcblk0p10` and
`cat /sys/block/mmcblk0/device/cid`. Any answer that does not match refuses with
a plain message and nothing is written.

On explicit confirmation it sends, in this order and nothing else:

```sh
dd if=/dev/zero of=/dev/mmcblk0p10 bs=512 count=1 conv=notrunc; sync
dd if=/dev/mmcblk0p10 bs=512 count=1 2>/dev/null | od -An -c | head -1
reboot -f
```

`reboot -f` is issued only after that readback printed a line of nothing but
NUL bytes. A readback that does not, or a readback command that fails, stops
with the remote left in recovery and says so; there is no second attempt. Only
the first 512 bytes of `para` are written, so the `ENV_v1` area at 128 KiB is
preserved, and no other partition is named by any command in the module.

The run takes the same private state root and device-wide USB lock as an
installation, and journals the bound location, the storage CID, the slot the
next boot will select and the accepted readback. Detection, probe parsing,
every refusal and the command order are unit-tested on all three platforms with
fixtures and a fake serial endpoint, and the entrypoint test drives the real
per-platform search with no device attached. None of that is a hardware run:
clearing the flag on an actual remote in recovery remains a separate physical
acceptance.

### Offline owner-image assembly acceptance

Before a release reaches USB testing, exercise the actual public archive with
verified owner inputs through all three native RAM and boot-image assembly paths:

```sh
cargo run --locked --example verify_owner_images -- \
  /private/installer.json /private/public-inputs.tar.gz \
  /private/prepared-owner-inputs /private/new-assembly-check
```

The example verifies the public archive against its descriptor, checks the
compiled owner-file pins, and assembles normal boot, recovery, and installer
images using the same APIs as the installer. It writes private image readbacks
and an `assembly.json` receipt. It performs no network requests, USB operations,
or device writes. Keep its owner-derived images private. Successful public tar
hash admission alone does not establish boot-image assembly compatibility.
