"""Fixed queries and at most one reboot on an explicitly selected Couch CDC port.

The identity query is read-only: it reads the storage CID, the SHA-256 of the
first 512 bytes of the bootloader control block and the uptime, and never
writes or restarts anything. The restart re-reads the CID and sends one fixed
reboot only when it equals the expected value.
"""
import re
import secrets
import time
from couch_install import require
from mtk_com import open_serial_port
from mtk_session import Candidate

# Every writer of the bootloader control block (mmcblk0p10) writes a whole
# 512-byte block, so only two values are legitimate. All zeros means the next
# start is a normal one; "boot-recovery" followed by 499 zero bytes means the
# bootloader starts COUCH RECOVERY next. Anything else is reported as unknown.
FLAG_CLEAR_SHA256 = '076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560'
FLAG_ARMED_SHA256 = '9418492e5b413376d2927de020eecc19a0be271687c4edb6437b7ce7268a2171'
REASONS = frozenset(('absent', 'no_serial_function', 'cannot_open', 'no_answer'))
# A running Couch has had its COM port for a long time; this only covers
# Windows starting its serial driver right after the remote reconnected.
COUCH_PORT_WAIT = 6.0


class Unavailable(Exception):
    """Nothing was written or restarted; a manual restart is still possible.

    `reason` says why, so the host can word its manual-restart screen:
    `absent` (no Couch USB device on the selected port), `no_serial_function`
    (the device there offers no CDC serial function, as stock Android does),
    `cannot_open` (the function exists but could not be opened) and
    `no_answer` (it opened but no framed answer came back).
    """

    def __init__(self, reason, message=None):
        require(reason in REASONS, 'Invalid Couch serial reason')
        super().__init__(message or f'Couch serial {reason}')
        self.reason = reason


def open_couch_port(selected, usb):
    """Couch's CDC ACM function as the COM port Windows created for it.

    Windows binds its own serial-port driver to the function and libusb
    cannot claim it, so the port is found the way the RAM stage's is: by
    vendor, product and the selected physical port chain.
    """
    couch = Candidate(selected.bus, 0, selected.ports, 0x0e8d, 0x201c)
    return open_serial_port(couch, 0, usb, services=lambda vid, pid: [], wait=COUCH_PORT_WAIT)


class CouchSerial:
    def __init__(self, usb, backend, selected, *, serial_port=None):
        """Open the selected port's Couch serial function.

        With `serial_port` (Windows) the function is reached through that
        opener's COM port; otherwise its interfaces are claimed through libusb.
        """
        self.usb, self.device, self.port = usb, None, None
        self.claimed, self.detached = [], []
        self.attempted = False
        try:
            devices = [d for d in usb.core.find(find_all=True, idVendor=0x0e8d,
                       idProduct=0x201c, backend=backend)
                       if d.bus == selected.bus and tuple(d.port_numbers or ()) == selected.ports]
            if len(devices) != 1:
                raise Unavailable('absent', 'Couch serial device unavailable on selected port')
            self.device = devices[0]
            try:
                interfaces = list(self.device.get_active_configuration())
            except Exception:
                # Windows may refuse the descriptor read for a function its
                # serial driver owns; the COM port lookup below still requires
                # exactly one port on this physical port chain.
                if serial_port is None:
                    raise
                interfaces = None
            if interfaces is not None:
                data = [i for i in interfaces if i.bInterfaceClass == 10 and i.bNumEndpoints == 2]
                control = [i for i in interfaces if i.bInterfaceClass == 2 and i.bInterfaceSubClass == 2]
                if len(data) != 1 or len(control) != 1:
                    raise Unavailable('no_serial_function', 'Couch serial interface unavailable')
                endpoints = list(data[0])
                incoming = [e for e in endpoints if e.bmAttributes & 3 == 2 and e.bEndpointAddress & 0x80]
                outgoing = [e for e in endpoints if e.bmAttributes & 3 == 2 and not e.bEndpointAddress & 0x80]
                if len(incoming) != 1 or len(outgoing) != 1:
                    raise Unavailable('no_serial_function', 'Couch serial endpoints unavailable')
            if serial_port is not None:
                self.port = serial_port(selected, usb)
                self.incoming = self.outgoing = self.port
            else:
                for interface in (control[0], data[0]):
                    number = interface.bInterfaceNumber
                    try:
                        if self.device.is_kernel_driver_active(number):
                            self.device.detach_kernel_driver(number)
                            self.detached.append(number)
                    except NotImplementedError:
                        pass
                    usb.util.claim_interface(self.device, number)
                    self.claimed.append(number)
                self.incoming, self.outgoing = incoming[0], outgoing[0]
                self.device.ctrl_transfer(0x21, 0x22, 3, control[0].bInterfaceNumber, None, timeout=1000)
        except Unavailable:
            self.close()
            raise
        except Exception as error:
            self.close()
            raise Unavailable('cannot_open', 'Couch serial interface cannot be opened') from error

    def _exchange(self, command, pattern):
        """Send one fixed command and return every answer framed by its marker.

        Bounded to 5 s and 16 KiB of output. Any transport fault, a short
        write or no answer at all is `no_answer`: nothing has been changed.
        """
        try:
            if self.outgoing.write(command, timeout=1000) != len(command):
                raise Unavailable('no_answer', 'Couch query write incomplete')
            output = bytearray()
            deadline = time.monotonic() + 5
            matches = []
            while time.monotonic() < deadline and len(output) <= 16384:
                try:
                    part = bytes(self.incoming.read(512, timeout=250))
                except self.usb.core.USBTimeoutError:
                    continue
                output.extend(part)
                if len(output) > 16384:
                    raise Unavailable('no_answer', 'Couch response exceeds bound')
                matches = re.findall(pattern, output)
                if matches:
                    break
        except Unavailable:
            raise
        except Exception as error:
            raise Unavailable('no_answer', 'Couch query unavailable') from error
        if not matches:
            raise Unavailable('no_answer', 'Couch query did not answer')
        return matches

    def identify(self):
        """Read-only: (CID, control-block SHA-256 or None, uptime seconds or None).

        The CID is mandatory. A missing tool or an unreadable block leaves its
        field empty, which is reported as None rather than as no answer, so the
        host treats the flag as unknown instead of the remote as silent. The
        shell variables are reset first so nothing from an earlier command can
        stand in for a value that was not read.
        """
        require(not self.attempted, 'Couch reboot already attempted')
        marker = ('COUCH_' + secrets.token_hex(16)).encode()
        command = (b'\nc=; h=; u=; x=; read -r c < /sys/block/mmcblk0/device/cid; '
                   b'h=$(dd if=/dev/mmcblk0p10 bs=512 count=1 2>/dev/null | sha256sum); '
                   b'read -r u x < /proc/uptime; '
                   b'printf "\\n' + marker + b':%s:%s:%s:END\\n" "$c" "${h%% *}" "${u%%.*}"\n')
        # The echoed command cannot match: its marker follows a literal
        # backslash-n rather than a newline, and "%s" is not a hex CID.
        matches = self._exchange(command, rb'(?:^|\n)' + marker
                                 + rb':([0-9a-fA-F]{32}):([^:\r\n]{0,128}):([^:\r\n]{0,32}):END\r?(?:\n|$)')
        require(len(matches) == 1, 'Couch identity query answered more than once')
        cid, flag, uptime = (value.decode('ascii', 'replace') for value in matches[0])
        return (cid.lower(),
                flag if re.fullmatch('[0-9a-f]{64}', flag) else None,
                int(uptime) if re.fullmatch('[0-9]{1,9}', uptime) else None)

    def restart(self, expected_cid):
        require(re.fullmatch('[0-9a-f]{32}', expected_cid) is not None, 'Invalid retained CID')
        require(not self.attempted, 'Couch reboot already attempted')
        marker = ('COUCH_' + secrets.token_hex(16)).encode()
        command = b'\nread -r c < /sys/block/mmcblk0/device/cid; printf "\\n' + marker + b':%s:END\\n" "$c"\n'
        matches = self._exchange(command, rb'(?:^|\n)' + marker + rb':([0-9a-fA-F]{32}):END\r?(?:\n|$)')
        require(len(matches) == 1 and matches[0].decode().lower() == expected_cid,
                'Connected Couch CID differs from retained enrollment; no reboot attempted')
        # Consume before the one write. An exception or short write is ambiguous:
        # propagate it as a hard failure, never offer an automatic second attempt.
        self.attempted = True
        reboot = b'\n/bin/busybox sync; /bin/busybox reboot -f\n'
        require(self.outgoing.write(reboot, timeout=1000) == len(reboot),
                'Couch reboot delivery ambiguous; do not retry automatically')

    def close(self):
        if self.port is not None:
            port, self.port = self.port, None
            try:
                port.close()
            except Exception:
                pass
        if self.device is None:
            return
        for number in reversed(self.claimed):
            try:
                self.usb.util.release_interface(self.device, number)
            except Exception:
                pass
        if not self.attempted:
            for number in self.detached:
                try:
                    self.device.attach_kernel_driver(number)
                except Exception:
                    pass
        try:
            self.usb.util.dispose_resources(self.device)
        except Exception:
            pass
        self.device = None
