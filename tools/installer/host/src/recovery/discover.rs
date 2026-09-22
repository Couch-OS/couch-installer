//! Finding a remote that is sitting in Couch recovery.
//!
//! Recovery brings up one CDC ACM function with the vendor/product identity
//! `0e8d:201c` and runs its shell on it, so the remote appears as an ordinary
//! serial port: `/dev/cu.usbmodem*` on macOS, `/dev/ttyACM*` on Linux and a
//! `usbser` COM port on Windows - the same driver binding the installer already
//! relies on for the preloader and the RAM stage.
//!
//! Each platform resolves that identity to its serial port through the record
//! the operating system itself keeps, never by guessing from a device name, and
//! the caller requires exactly one candidate before opening anything. Discovery
//! happens once; nothing rediscovers a device later in the run.
//!
//! The parsing and selection below is platform independent so it is unit-tested
//! everywhere; only the three system queries are conditionally compiled.

use anyhow::Result;

/// USB identity Couch recovery presents. `VENDOR` is shared with the preloader
/// and with a normally running remote, which is why the shell is verified
/// before anything is written.
pub const VENDOR: u16 = crate::windows_drivers::VENDOR;
pub const RECOVERY: u16 = crate::windows_drivers::COUCH;

/// One remote found in recovery, bound to the physical place it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// Where the operating system says this candidate is attached: the USB bus
    /// and hub port chain on macOS and Linux, the device instance Windows
    /// recorded. Reported on screen and in the session journal so the run names
    /// the exact physical connection it used.
    pub location: String,
    /// The serial port as the host names it, for people.
    pub label: String,
    /// The path the serial port is opened by.
    pub path: String,
}

/// Every remote in Couch recovery this host can currently see.
pub fn candidates() -> Result<Vec<Remote>> {
    #[cfg(target_os = "macos")]
    {
        macos::candidates()
    }
    #[cfg(target_os = "linux")]
    {
        linux::remotes_in(std::path::Path::new("/sys/bus/usb/devices"))
    }
    #[cfg(windows)]
    {
        windows::candidates()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        anyhow::bail!("this computer is not a supported installer host")
    }
}

/// Apple encodes the bus in the top byte of a location and the hub port chain
/// in the nibbles below it, exactly as the installer's macOS transport reads it.
fn topology(location: u32) -> (u32, Vec<u32>) {
    let mut ports = Vec::new();
    for shift in [20, 16, 12, 8, 4, 0] {
        let nibble = (location >> shift) & 0xf;
        if nibble == 0 {
            break;
        }
        ports.push(nibble);
    }
    (location >> 24, ports)
}

fn describe(bus: u32, ports: &[u32]) -> String {
    let chain: Vec<String> = ports.iter().map(u32::to_string).collect();
    match chain.is_empty() {
        true => format!("USB bus {bus}"),
        false => format!("USB bus {bus} port {}", chain.join(".")),
    }
}

/// A callout/tty name the host may hand us, kept to the shape a USB serial port
/// actually has so a malformed record can never become an arbitrary path.
fn valid_node(path: &str, prefix: &str) -> bool {
    let Some(name) = path.strip_prefix(prefix) else {
        return false;
    };
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// ---------------------------------------------------------------- macOS ----

/// Just enough of the XML property list format to read `ioreg -a` output.
///
/// `ioreg` is the only interface macOS offers for resolving a USB device to the
/// serial port its CDC data interface was given, and `-a` is its machine
/// readable form. Values this reader does not need - data, dates, reals and
/// booleans - are accepted and discarded rather than parsed.
mod plist {
    use anyhow::{bail, ensure, Context, Result};
    use std::collections::BTreeMap;

    const MAX_DEPTH: usize = 64;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Dict(BTreeMap<String, Value>),
        Array(Vec<Value>),
        Text(String),
        Number(i64),
        Other,
    }

    impl Value {
        pub fn text(&self, key: &str) -> Option<&str> {
            match self.get(key) {
                Some(Value::Text(value)) => Some(value),
                _ => None,
            }
        }
        pub fn number(&self, key: &str) -> Option<i64> {
            match self.get(key) {
                Some(Value::Number(value)) => Some(*value),
                _ => None,
            }
        }
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Dict(map) => map.get(key),
                _ => None,
            }
        }
        pub fn items(&self) -> &[Value] {
            match self {
                Value::Array(values) => values,
                _ => &[],
            }
        }
    }

    enum Tag<'a> {
        Open(&'a str),
        Close(&'a str),
        Empty,
    }

    struct Reader<'a> {
        text: &'a str,
        at: usize,
    }

    impl<'a> Reader<'a> {
        /// Read the next element, skipping the declaration and doctype.
        fn tag(&mut self) -> Result<Tag<'a>> {
            loop {
                let start = self.text[self.at..]
                    .find('<')
                    .context("expected a property list element")?
                    + self.at;
                let end = self.text[start..]
                    .find('>')
                    .context("unterminated property list element")?
                    + start;
                let inner = &self.text[start + 1..end];
                self.at = end + 1;
                if inner.starts_with('?') || inner.starts_with('!') {
                    continue;
                }
                let name = |value: &'a str| value.split([' ', '\t', '\n']).next().unwrap_or("");
                return Ok(match (inner.strip_prefix('/'), inner.strip_suffix('/')) {
                    (Some(closing), _) => Tag::Close(name(closing)),
                    (None, Some(_)) => Tag::Empty,
                    (None, None) => Tag::Open(name(inner)),
                });
            }
        }

        /// Raw character data up to the next element.
        fn body(&mut self) -> Result<String> {
            let stop = self.text[self.at..]
                .find('<')
                .context("unterminated property list text")?
                + self.at;
            let raw = &self.text[self.at..stop];
            self.at = stop;
            Ok(raw
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&"))
        }

        fn close(&mut self, expected: &str) -> Result<()> {
            match self.tag()? {
                Tag::Close(name) if name == expected => Ok(()),
                _ => bail!("expected </{expected}> in the property list"),
            }
        }

        fn value(&mut self, tag: Tag<'a>, depth: usize) -> Result<Value> {
            ensure!(depth < MAX_DEPTH, "property list nests too deeply");
            let name = match tag {
                // <true/>, <false/> and any other empty element.
                Tag::Empty => return Ok(Value::Other),
                Tag::Close(name) => bail!("unexpected </{name}> in the property list"),
                Tag::Open(name) => name,
            };
            match name {
                "dict" => {
                    let mut map = BTreeMap::new();
                    loop {
                        match self.tag()? {
                            Tag::Close("dict") => return Ok(Value::Dict(map)),
                            Tag::Open("key") => {
                                let key = self.body()?;
                                self.close("key")?;
                                let tag = self.tag()?;
                                map.insert(key, self.value(tag, depth + 1)?);
                            }
                            _ => bail!("expected a key in the property list dictionary"),
                        }
                    }
                }
                "array" => {
                    let mut values = Vec::new();
                    loop {
                        match self.tag()? {
                            Tag::Close("array") => return Ok(Value::Array(values)),
                            tag => values.push(self.value(tag, depth + 1)?),
                        }
                    }
                }
                "string" => {
                    let value = self.body()?;
                    self.close("string")?;
                    Ok(Value::Text(value))
                }
                "integer" => {
                    let value = self.body()?;
                    self.close("integer")?;
                    Ok(Value::Number(value.trim().parse().unwrap_or(-1)))
                }
                // data, date, real: read past them without interpreting them.
                other => {
                    self.body()?;
                    self.close(other)?;
                    Ok(Value::Other)
                }
            }
        }
    }

    /// Parse one `ioreg -a` document. An empty document means "no devices",
    /// which is what `ioreg` prints when nothing matches its class filter.
    pub fn parse(document: &str) -> Result<Value> {
        if document.trim().is_empty() {
            return Ok(Value::Array(Vec::new()));
        }
        let mut reader = Reader {
            text: document,
            at: 0,
        };
        let tag = reader.tag()?;
        let root = match tag {
            Tag::Open("plist") => {
                let tag = reader.tag()?;
                reader.value(tag, 0)?
            }
            tag => reader.value(tag, 0)?,
        };
        Ok(root)
    }
}

pub mod macos {
    use super::{describe, plist, topology, valid_node, Remote, RECOVERY, VENDOR};
    use anyhow::{ensure, Context, Result};

    /// The I/O Registry query. `-r -c IOUSBHostDevice -l` prints every USB
    /// device with its properties and its children, which is where the serial
    /// port created for a CDC interface hangs.
    const IOREG: [&str; 5] = ["-a", "-l", "-r", "-c", "IOUSBHostDevice"];
    const MAX_REGISTRY: usize = 64 * 1024 * 1024;

    /// Every `IOCalloutDevice` in one device's subtree.
    fn callouts(node: &plist::Value, found: &mut Vec<String>) {
        if let Some(path) = node.text("IOCalloutDevice") {
            found.push(path.to_owned());
        }
        for child in node
            .get("IORegistryEntryChildren")
            .map(plist::Value::items)
            .unwrap_or_default()
        {
            callouts(child, found);
        }
    }

    fn collect(node: &plist::Value, found: &mut Vec<Remote>) -> Result<()> {
        let recovery = node.text("IOObjectClass") == Some("IOUSBHostDevice")
            && node.number("idVendor") == Some(VENDOR as i64)
            && node.number("idProduct") == Some(RECOVERY as i64);
        if recovery {
            let location = node
                .number("locationID")
                .filter(|value| (0..=0xffff_ffff).contains(value))
                .context("macOS reported a remote without a USB location")?;
            let (bus, ports) = topology(location as u32);
            let mut ports_found = Vec::new();
            callouts(node, &mut ports_found);
            ensure!(
                ports_found.len() == 1,
                "macOS has not given the remote at {} exactly one serial port; wait a moment \
                 and look again, or reconnect it",
                describe(bus, &ports)
            );
            let path = ports_found.remove(0);
            ensure!(
                valid_node(&path, "/dev/cu."),
                "macOS reported an unexpected serial port for the remote"
            );
            found.push(Remote {
                location: describe(bus, &ports),
                label: path.clone(),
                path,
            });
            // A remote is one candidate; nothing below it is another one.
            return Ok(());
        }
        for child in node
            .get("IORegistryEntryChildren")
            .map(plist::Value::items)
            .unwrap_or_default()
        {
            collect(child, found)?;
        }
        Ok(())
    }

    /// Select every recovery remote from one `ioreg -a` document.
    pub fn remotes_in_registry(document: &str) -> Result<Vec<Remote>> {
        let listing = plist::parse(document).context("macOS I/O Registry listing is unreadable")?;
        let mut found = Vec::new();
        for node in listing.items() {
            collect(node, &mut found)?;
        }
        Ok(found)
    }

    pub fn candidates() -> Result<Vec<Remote>> {
        let result = std::process::Command::new("/usr/sbin/ioreg")
            .args(IOREG)
            .stdin(std::process::Stdio::null())
            .output()
            .context("could not ask macOS which USB devices are connected")?;
        ensure!(
            result.status.success() && result.stdout.len() <= MAX_REGISTRY,
            "macOS I/O Registry query failed"
        );
        let document =
            String::from_utf8(result.stdout).context("macOS I/O Registry listing is not text")?;
        remotes_in_registry(&document)
    }
}

// ---------------------------------------------------------------- Linux ----

pub mod linux {
    use super::{describe, valid_node, Remote, RECOVERY, VENDOR};
    use anyhow::{ensure, Context, Result};
    use std::path::Path;

    fn attribute(directory: &Path, name: &str) -> Option<String> {
        std::fs::read_to_string(directory.join(name))
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
    }

    /// Every tty the kernel created for the interfaces of one USB device.
    fn ttys(devices: &Path, device: &str) -> Result<Vec<String>> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(devices)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Interfaces of a device are named "<device>:<configuration>.<n>".
            if !name.starts_with(&format!("{device}:")) {
                continue;
            }
            let tty = entry.path().join("tty");
            if !tty.is_dir() {
                continue;
            }
            for node in std::fs::read_dir(&tty)? {
                found.push(node?.file_name().to_string_lossy().into_owned());
            }
        }
        found.sort();
        Ok(found)
    }

    /// Select every recovery remote from a sysfs USB device directory.
    pub fn remotes_in(devices: &Path) -> Result<Vec<Remote>> {
        let mut found = Vec::new();
        let Ok(listing) = std::fs::read_dir(devices) else {
            // No USB bus at all is "nothing connected", not a failure.
            return Ok(found);
        };
        let mut names: Vec<String> = listing
            .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
            .filter(|name| !name.contains(':'))
            .collect();
        names.sort();
        for name in names {
            let directory = devices.join(&name);
            if attribute(&directory, "idVendor").as_deref() != Some(&format!("{VENDOR:04x}"))
                || attribute(&directory, "idProduct").as_deref() != Some(&format!("{RECOVERY:04x}"))
            {
                continue;
            }
            let bus = attribute(&directory, "busnum")
                .and_then(|value| value.parse::<u32>().ok())
                .context("Linux reported a remote without a USB bus number")?;
            let ports: Vec<u32> = attribute(&directory, "devpath")
                .unwrap_or_default()
                .split('.')
                .filter_map(|part| part.parse::<u32>().ok())
                .collect();
            let location = describe(bus, &ports);
            let mut nodes = ttys(devices, &name)?;
            ensure!(
                nodes.len() == 1,
                "Linux has not given the remote at {location} exactly one serial port; wait a \
                 moment and look again, or reconnect it"
            );
            let path = format!("/dev/{}", nodes.remove(0));
            ensure!(
                valid_node(&path, "/dev/tty"),
                "Linux reported an unexpected serial port for the remote"
            );
            found.push(Remote {
                location,
                label: path.clone(),
                path,
            });
        }
        Ok(found)
    }
}

// -------------------------------------------------------------- Windows ----

pub mod windows {
    use super::{Remote, RECOVERY};
    use anyhow::Result;

    /// One device instance Windows recorded for the recovery identity, with the
    /// COM port its serial-port driver created for it. `started` marks an
    /// instance Windows currently has running, which is the only presence
    /// signal the device enumeration keeps in the registry.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Record {
        pub instance: String,
        pub port: String,
        pub started: bool,
    }

    /// Select the recovery remotes from the recorded serial ports.
    ///
    /// Windows keeps a record of every device instance it has ever enumerated,
    /// so a machine that has had a remote attached before still lists it after
    /// it is unplugged. When Windows reports any instance as started, only
    /// those are candidates; otherwise every record is offered and the caller's
    /// "exactly one" rule still decides, with the recovery shell verification
    /// behind it.
    pub fn remotes_in_records(records: &[Record]) -> Vec<Remote> {
        let started = records.iter().any(|record| record.started);
        let mut found: Vec<Remote> = Vec::new();
        for record in records {
            if started && !record.started {
                continue;
            }
            if !valid_port(&record.port) || found.iter().any(|other| other.label == record.port) {
                continue;
            }
            found.push(Remote {
                location: format!("device instance {}", record.instance),
                label: record.port.clone(),
                // The device namespace form, which is the only one that works
                // for two-digit and higher COM numbers.
                path: format!(r"\\.\{}", record.port),
            });
        }
        found
    }

    fn valid_port(port: &str) -> bool {
        port.strip_prefix("COM").is_some_and(|number| {
            (1..=3).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit())
        })
    }

    #[cfg(windows)]
    pub fn candidates() -> Result<Vec<Remote>> {
        Ok(remotes_in_records(&crate::windows_drivers::serial_ports(
            RECOVERY,
        )?))
    }

    #[cfg(not(windows))]
    pub fn candidates() -> Result<Vec<Remote>> {
        let _ = RECOVERY;
        anyhow::bail!("this query exists only on Windows")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// One serial port hanging off a CDC data interface, as macOS records it.
    fn serial(callout: &str) -> String {
        format!(
            "<dict><key>IOObjectClass</key><string>IOSerialBSDClient</string>\
             <key>IOCalloutDevice</key><string>{callout}</string></dict>"
        )
    }

    /// An `ioreg -a` listing with one unrelated device and one remote whose
    /// CDC data interface carries `children`.
    fn registry(vendor: u16, product: u16, children: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>IOObjectClass</key>
		<string>IOUSBHostDevice</string>
		<key>USB Product Name</key>
		<string>Keyboard &amp; Trackpad</string>
		<key>idVendor</key>
		<integer>1452</integer>
		<key>idProduct</key>
		<integer>613</integer>
		<key>locationID</key>
		<integer>337641472</integer>
		<key>AAPL,phandle</key>
		<data>
		PQEAAA==
		</data>
		<key>IOPowerManagement</key>
		<dict>
			<key>CurrentPowerState</key>
			<integer>2</integer>
		</dict>
	</dict>
	<dict>
		<key>IOObjectClass</key>
		<string>IOUSBHostDevice</string>
		<key>idVendor</key>
		<integer>{vendor}</integer>
		<key>idProduct</key>
		<integer>{product}</integer>
		<key>locationID</key>
		<integer>339738624</integer>
		<key>IOMatchedAtBoot</key>
		<true/>
		<key>IORegistryEntryChildren</key>
		<array>
			<dict>
				<key>IOObjectClass</key>
				<string>IOUSBHostInterface</string>
				<key>bInterfaceNumber</key>
				<integer>0</integer>
			</dict>
			<dict>
				<key>IOObjectClass</key>
				<string>IOUSBHostInterface</string>
				<key>bInterfaceNumber</key>
				<integer>1</integer>
				<key>IORegistryEntryChildren</key>
				<array>{children}</array>
			</dict>
		</array>
	</dict>
</array>
</plist>
"#
        )
    }

    /// The everyday case: a remote in recovery with its one serial port.
    fn recovery_registry() -> String {
        registry(VENDOR, RECOVERY, &serial("/dev/cu.usbmodem14201"))
    }

    #[test]
    fn an_empty_registry_listing_is_no_remote_rather_than_a_failure() {
        // ioreg prints nothing at all when its class filter matches no device.
        assert!(macos::remotes_in_registry("").unwrap().is_empty());
        assert!(macos::remotes_in_registry("   \n").unwrap().is_empty());
    }

    #[test]
    fn the_recovery_identity_resolves_to_its_own_callout_device() {
        assert_eq!(
            macos::remotes_in_registry(&recovery_registry()).unwrap(),
            vec![Remote {
                location: "USB bus 20 port 4".into(),
                label: "/dev/cu.usbmodem14201".into(),
                path: "/dev/cu.usbmodem14201".into(),
            }]
        );
    }

    #[test]
    fn another_usb_device_with_a_serial_port_is_not_a_candidate() {
        // The same tree, with a product and then a vendor recovery never uses.
        for (vendor, product) in [(VENDOR, RECOVERY + 1), (0x05ac, RECOVERY)] {
            let listing = registry(vendor, product, &serial("/dev/cu.usbmodem14201"));
            assert!(macos::remotes_in_registry(&listing).unwrap().is_empty());
        }
    }

    #[test]
    fn a_remote_without_exactly_one_serial_port_refuses() {
        let two = serial("/dev/cu.usbmodem14201") + &serial("/dev/cu.usbmodem14202");
        for children in ["", two.as_str()] {
            let listing = registry(VENDOR, RECOVERY, children);
            let error = macos::remotes_in_registry(&listing)
                .unwrap_err()
                .to_string();
            assert!(error.contains("exactly one serial port"), "{error}");
            assert!(error.contains("USB bus 20 port 4"), "{error}");
        }
    }

    #[test]
    fn a_callout_path_outside_the_serial_namespace_refuses() {
        for callout in ["/dev/../etc/passwd", "/dev/ttyACM0", "", "/dev/cu."] {
            let listing = registry(VENDOR, RECOVERY, &serial(callout));
            let error = macos::remotes_in_registry(&listing)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("unexpected serial port"),
                "{callout}: {error}"
            );
        }
    }

    #[test]
    fn a_malformed_registry_listing_refuses_rather_than_inventing_a_device() {
        for broken in [
            "<plist><array><dict><key>a</key>",
            "<plist><array><dict><string>no key</string></dict></array></plist>",
            "<plist><array><dict><key>k</key><string>unterminated",
            "<plist><array><dict><key>k</key></dict></array></plist>",
        ] {
            assert!(macos::remotes_in_registry(broken).is_err(), "{broken}");
        }
    }

    #[test]
    fn apple_location_identifiers_split_into_bus_and_hub_ports() {
        assert_eq!(topology(0x14200000), (20, vec![2]));
        assert_eq!(topology(0x14210000), (20, vec![2, 1]));
        assert_eq!(topology(0x01000000), (1, vec![]));
        assert_eq!(topology(0x14123456), (20, vec![1, 2, 3, 4, 5, 6]));
        assert_eq!(describe(20, &[4, 2]), "USB bus 20 port 4.2");
        assert_eq!(describe(1, &[]), "USB bus 1");
    }

    // A sysfs interface directory is named "<device>:<configuration>.<n>", and
    // Windows cannot create a file whose name contains a colon, so the fixture
    // tree for the Linux reader exists only where sysfs itself could.
    #[cfg(unix)]
    fn sysfs(devices: &Path, name: &str, vendor: &str, product: &str, ttys: &[(&str, &str)]) {
        let directory = devices.join(name);
        std::fs::create_dir_all(&directory).unwrap();
        for (attribute, value) in [
            ("idVendor", vendor),
            ("idProduct", product),
            ("busnum", "1"),
            ("devpath", "4.2"),
        ] {
            std::fs::write(directory.join(attribute), format!("{value}\n")).unwrap();
        }
        for (interface, tty) in ttys {
            let path = devices.join(format!("{name}:{interface}")).join("tty");
            std::fs::create_dir_all(path.join(tty)).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn linux_resolves_the_recovery_identity_to_its_own_tty() {
        let root = tempfile::tempdir().unwrap();
        let devices = root.path();
        sysfs(devices, "usb1", "1d6b", "0002", &[]);
        sysfs(devices, "1-3", "05ac", "0250", &[("1.0", "ttyACM9")]);
        sysfs(devices, "1-4", "0e8d", "201c", &[("1.0", "ttyACM0")]);
        assert_eq!(
            linux::remotes_in(devices).unwrap(),
            vec![Remote {
                location: "USB bus 1 port 4.2".into(),
                label: "/dev/ttyACM0".into(),
                path: "/dev/ttyACM0".into(),
            }]
        );
    }

    #[test]
    #[cfg(unix)]
    fn linux_reports_two_connected_remotes_separately() {
        let root = tempfile::tempdir().unwrap();
        let devices = root.path();
        sysfs(devices, "1-4", "0e8d", "201c", &[("1.0", "ttyACM0")]);
        sysfs(devices, "1-5", "0e8d", "201c", &[("1.0", "ttyACM1")]);
        assert_eq!(linux::remotes_in(devices).unwrap().len(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn linux_refuses_a_remote_without_exactly_one_tty() {
        for interfaces in [
            [].as_slice(),
            [("1.0", "ttyACM0"), ("1.2", "ttyACM1")].as_slice(),
        ] {
            let root = tempfile::tempdir().unwrap();
            sysfs(root.path(), "1-4", "0e8d", "201c", interfaces);
            let error = linux::remotes_in(root.path()).unwrap_err().to_string();
            assert!(error.contains("exactly one serial port"), "{error}");
        }
    }

    #[test]
    fn an_absent_usb_directory_is_no_remote_rather_than_a_failure() {
        assert!(linux::remotes_in(Path::new("/nonexistent-usb-devices"))
            .unwrap()
            .is_empty());
    }

    fn record(instance: &str, port: &str, started: bool) -> windows::Record {
        windows::Record {
            instance: instance.into(),
            port: port.into(),
            started,
        }
    }

    #[test]
    fn windows_prefers_the_instance_it_reports_as_started() {
        let records = [
            record("5&1a2b3c&0&4", "COM3", false),
            record("5&1a2b3c&0&7", "COM12", true),
        ];
        assert_eq!(
            windows::remotes_in_records(&records),
            vec![Remote {
                location: "device instance 5&1a2b3c&0&7".into(),
                label: "COM12".into(),
                path: r"\\.\COM12".into(),
            }]
        );
    }

    #[test]
    fn windows_offers_every_stale_record_when_none_is_started() {
        let records = [
            record("a", "COM3", false),
            record("b", "COM4", false),
            // The same port recorded twice is one candidate, not two.
            record("c", "COM4", false),
        ];
        let found = windows::remotes_in_records(&records);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].path, r"\\.\COM3");
    }

    #[test]
    fn windows_discards_a_record_without_a_usable_port_name() {
        let records = [
            record("a", "", false),
            record("b", "LPT1", false),
            record("c", "COM1234", false),
            record("d", r"COM3\..\x", false),
        ];
        assert!(windows::remotes_in_records(&records).is_empty());
    }
}
