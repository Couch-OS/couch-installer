//! One opened serial port, with the deadlines the recovery protocol needs.
//!
//! The recovery shell speaks plain bytes over a CDC ACM function, so the host
//! side only has to be raw: no line editing, no newline translation and no
//! flow control, or the framing this action relies on would be rewritten in
//! transit. Line speed is meaningless over USB and is set only because the
//! interfaces expect a value.
//!
//! The port is opened for this one candidate and never reopened. Both
//! platforms fail a read or a write that makes no progress inside its deadline
//! rather than blocking, so a remote that stops answering ends the run instead
//! of hanging the terminal.

use super::shell::Link;
use anyhow::{Context, Result};

/// Line speed handed to the driver. A CDC ACM function ignores it.
const SPEED: u32 = 115_200;

#[cfg(unix)]
pub use unix::SerialPort;
#[cfg(windows)]
pub use windows::SerialPort;

#[cfg(unix)]
mod unix {
    use super::{Link, Result, SPEED};
    use anyhow::{bail, Context};
    use std::ffi::CString;
    use std::time::Duration;

    pub struct SerialPort {
        fd: libc::c_int,
    }

    impl SerialPort {
        pub fn open(path: &str) -> Result<Self> {
            let name = CString::new(path).context("invalid serial port name")?;
            // O_NONBLOCK so opening never waits for carrier, and no controlling
            // terminal so a hang-up cannot reach this process.
            let fd = unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("could not open the remote's serial port {path}"));
            }
            let port = Self { fd };
            port.exclusive()?;
            port.raw()?;
            Ok(port)
        }

        /// Refuse to share the port with another program on this computer.
        fn exclusive(&self) -> Result<()> {
            // The request type differs between the C libraries this builds on.
            if unsafe { libc::ioctl(self.fd, libc::TIOCEXCL as _) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("another program is using the remote's serial port");
            }
            Ok(())
        }

        fn raw(&self) -> Result<()> {
            let mut settings: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(self.fd, &mut settings) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not read the serial port settings");
            }
            unsafe {
                libc::cfmakeraw(&mut settings);
                libc::cfsetispeed(&mut settings, SPEED as libc::speed_t);
                libc::cfsetospeed(&mut settings, SPEED as libc::speed_t);
            }
            // Read what has arrived and return; the deadline lives in poll().
            settings.c_cc[libc::VMIN] = 0;
            settings.c_cc[libc::VTIME] = 0;
            settings.c_cflag |= libc::CREAD | libc::CLOCAL;
            settings.c_cflag &= !libc::CRTSCTS;
            if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &settings) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not put the serial port into raw mode");
            }
            Ok(())
        }

        /// Wait for the port to become readable or writable, or time out.
        fn ready(&self, events: libc::c_short, timeout: Duration) -> Result<bool> {
            let mut watch = libc::pollfd {
                fd: self.fd,
                events,
                revents: 0,
            };
            let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
            let count = unsafe { libc::poll(&mut watch, 1, millis) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(false);
                }
                return Err(error).context("the remote's serial port failed while waiting");
            }
            if watch.revents & (libc::POLLERR | libc::POLLNVAL) != 0
                || (watch.revents & libc::POLLHUP != 0 && watch.revents & libc::POLLIN == 0)
            {
                bail!("the remote disconnected from USB");
            }
            Ok(count > 0 && watch.revents & events != 0)
        }
    }

    impl Link for SerialPort {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            let mut sent = 0;
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while sent < bytes.len() {
                let left = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .context("the remote stopped accepting commands")?;
                if !self.ready(libc::POLLOUT, left)? {
                    continue;
                }
                let count = unsafe {
                    libc::write(self.fd, bytes[sent..].as_ptr().cast(), bytes.len() - sent)
                };
                if count < 0 {
                    let error = std::io::Error::last_os_error();
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    return Err(error).context("could not send to the remote");
                }
                sent += count as usize;
            }
            Ok(())
        }

        fn receive(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize> {
            if !self.ready(libc::POLLIN, timeout)? {
                return Ok(0);
            }
            let count = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    return Ok(0);
                }
                return Err(error).context("could not read from the remote");
            }
            if count == 0 {
                bail!("the remote disconnected from USB");
            }
            Ok(count as usize)
        }
    }

    impl Drop for SerialPort {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Link, Result, SPEED};
    use anyhow::{bail, Context};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Devices::Communication::{
            GetCommState, SetCommState, SetCommTimeouts, COMMTIMEOUTS, DCB, NOPARITY, ONESTOPBIT,
        },
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING},
    };

    /// Windows' "no timeout" sentinel for a communications timeout field.
    const MAXDWORD: u32 = 0xffff_ffff;
    /// `fBinary`, `fDtrControl = DTR_CONTROL_ENABLE` and
    /// `fRtsControl = RTS_CONTROL_ENABLE` in the DCB's packed flags, with every
    /// other flag - parity checking, XON/XOFF and hardware flow control - clear.
    const DCB_FLAGS: u32 = 1 | (1 << 4) | (1 << 12);

    pub struct SerialPort {
        handle: HANDLE,
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    impl SerialPort {
        pub fn open(path: &str) -> Result<Self> {
            // No sharing: a COM port opened elsewhere must fail here rather
            // than interleave with another program's traffic.
            let handle = unsafe {
                CreateFileW(
                    wide(path).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("could not open the remote's serial port {path}"));
            }
            let port = Self { handle };
            port.raw()?;
            Ok(port)
        }

        fn raw(&self) -> Result<()> {
            let mut settings: DCB = unsafe { std::mem::zeroed() };
            settings.DCBlength = std::mem::size_of::<DCB>() as u32;
            if unsafe { GetCommState(self.handle, &mut settings) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not read the serial port settings");
            }
            settings.BaudRate = SPEED;
            settings.ByteSize = 8;
            settings.Parity = NOPARITY;
            settings.StopBits = ONESTOPBIT;
            settings._bitfield = DCB_FLAGS;
            if unsafe { SetCommState(self.handle, &settings) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not put the serial port into raw mode");
            }
            Ok(())
        }

        /// Return as soon as anything has arrived, waiting at most `millis` for
        /// the first byte - the documented meaning of this exact combination.
        fn timeouts(&self, millis: u32) -> Result<()> {
            let settings = COMMTIMEOUTS {
                ReadIntervalTimeout: MAXDWORD,
                ReadTotalTimeoutMultiplier: MAXDWORD,
                ReadTotalTimeoutConstant: millis,
                WriteTotalTimeoutMultiplier: 0,
                WriteTotalTimeoutConstant: 10_000,
            };
            if unsafe { SetCommTimeouts(self.handle, &settings) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not set the serial port deadlines");
            }
            Ok(())
        }
    }

    impl Link for SerialPort {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            self.timeouts(1000)?;
            let mut sent = 0;
            while sent < bytes.len() {
                let mut count = 0u32;
                let piece = (bytes.len() - sent).min(u32::MAX as usize) as u32;
                let written = unsafe {
                    WriteFile(
                        self.handle,
                        bytes[sent..].as_ptr(),
                        piece,
                        &mut count,
                        null_mut(),
                    )
                };
                if written == 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("could not send to the remote");
                }
                if count == 0 {
                    bail!("the remote stopped accepting commands");
                }
                sent += count as usize;
            }
            Ok(())
        }

        fn receive(&mut self, buffer: &mut [u8], timeout: std::time::Duration) -> Result<usize> {
            self.timeouts(timeout.as_millis().min(u32::MAX as u128) as u32)?;
            let mut count = 0u32;
            let read = unsafe {
                ReadFile(
                    self.handle,
                    buffer.as_mut_ptr(),
                    buffer.len().min(u32::MAX as usize) as u32,
                    &mut count,
                    null_mut(),
                )
            };
            if read == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not read from the remote");
            }
            Ok(count as usize)
        }
    }

    impl Drop for SerialPort {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Open one discovered candidate.
pub fn open(path: &str) -> Result<SerialPort> {
    SerialPort::open(path).with_context(|| {
        format!(
            "The remote's serial port could not be opened. Close any other program using it, \
             then try again ({path})"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_a_port_that_does_not_exist_is_reported_plainly() {
        #[cfg(unix)]
        let path = "/dev/cu.couch-installer-no-such-port";
        #[cfg(windows)]
        let path = r"\\.\COM255";
        let error = format!("{:#}", open(path).err().expect("no such port"));
        assert!(error.contains("could not be opened"), "{error}");
        assert!(error.contains(path), "{error}");
    }
}
