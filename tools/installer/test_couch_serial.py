import hashlib
import re
from types import SimpleNamespace as NS
import unittest
from couch_install import InstallError
from couch_serial import (CouchSerial, FLAG_ARMED_SHA256, FLAG_CLEAR_SHA256, Unavailable,
                          open_couch_port)


class SerialTests(unittest.TestCase):
    def fixture(self, cid='1'*32, *, reboot_short=False, query_echo=False,
                flag=FLAG_CLEAR_SHA256, uptime='1900', answers=1, noise=b'', echo=True):
        serial = CouchSerial.__new__(CouchSerial)
        serial.attempted = False
        writes, pending = [], bytearray()
        def write(data, **kwargs):
            writes.append(data)
            if data == b'\n/bin/busybox sync; /bin/busybox reboot -f\n':
                return 1 if reboot_short else len(data)
            marker = re.search(rb'COUCH_[0-9a-f]{32}', data).group()
            if query_echo:
                pending.extend(data)
            elif b'sha256sum' in data:
                # The remote's tty echoes the command, then prints the answer
                # with CRLF line endings.
                pending.extend((data.replace(b'\n', b'\r\n') if echo else b'') + noise)
                for _ in range(answers):
                    pending.extend(b'\r\n' + marker + b':' + cid.encode() + b':' + flag.encode()
                                   + b':' + uptime.encode() + b':END\r\n')
            else:
                pending.extend(b'\n' + marker + b':' + cid.encode() + b':END\r\n')
            return len(data)
        def read(size, **kwargs):
            if not pending:
                raise RuntimeError('fixture has no more output')
            value = bytes(pending[:size]); del pending[:size]; return value
        serial.outgoing = NS(write=write)
        serial.incoming = NS(read=read)
        serial.usb = NS(core=NS(USBTimeoutError=TimeoutError))
        return serial, writes

    def test_matching_nonce_cid_allows_one_fixed_reboot(self):
        serial, writes = self.fixture()
        serial.restart('1'*32)
        self.assertEqual(writes[-1], b'\n/bin/busybox sync; /bin/busybox reboot -f\n')
        with self.assertRaises(InstallError): serial.restart('1'*32)
        self.assertEqual(len(writes), 2)

    def test_wrong_identity_never_reboots_or_falls_back(self):
        serial, writes = self.fixture(cid='2'*32)
        with self.assertRaises(InstallError): serial.restart('1'*32)
        self.assertEqual(len(writes), 1)
        self.assertFalse(serial.attempted)

    def test_echoed_query_is_not_identity_evidence(self):
        serial, writes = self.fixture(query_echo=True)
        with self.assertRaises(Unavailable): serial.restart('1'*32)
        self.assertEqual(len(writes), 1)

    def test_ambiguous_reboot_consumes_attempt(self):
        serial, writes = self.fixture(reboot_short=True)
        with self.assertRaises(InstallError): serial.restart('1'*32)
        self.assertTrue(serial.attempted)
        with self.assertRaises(InstallError): serial.restart('1'*32)
        self.assertEqual(len(writes), 2)

    def test_wrong_physical_port_is_never_claimed(self):
        claims = []
        usb = NS(core=NS(find=lambda **kw:[NS(bus=2,port_numbers=(3,))]),
                 util=NS(claim_interface=lambda *args:claims.append(args)))
        with self.assertRaises(Unavailable) as raised:
            CouchSerial(usb, object(), NS(bus=2, ports=(4,)))
        self.assertEqual(raised.exception.reason, 'absent')
        self.assertEqual(claims, [])

    def test_flag_constants_are_the_only_two_blocks_couch_writes(self):
        self.assertEqual(hashlib.sha256(bytes(512)).hexdigest(), FLAG_CLEAR_SHA256)
        self.assertEqual(hashlib.sha256(b'boot-recovery' + bytes(499)).hexdigest(), FLAG_ARMED_SHA256)

    def test_identify_reads_cid_and_boot_flag_without_rebooting(self):
        serial, writes = self.fixture(cid='AB'*16, noise=b'1+0 records in\r\n')
        self.assertEqual(serial.identify(), ('ab'*16, FLAG_CLEAR_SHA256, 1900))
        self.assertEqual(len(writes), 1)
        for forbidden in (b'reboot', b'of=', b'conv='):
            self.assertNotIn(forbidden, writes[0])
        # Reads the whole first block of the control block, and nothing else.
        self.assertIn(b'dd if=/dev/mmcblk0p10 bs=512 count=1 ', writes[0])
        self.assertEqual(writes[0].count(b'/dev/mmcblk0'), 1)
        self.assertFalse(serial.attempted)
        # Read-only, so it may be repeated before the one reboot.
        self.assertEqual(serial.identify()[0], 'ab'*16)
        serial.restart('ab'*16)
        with self.assertRaises(InstallError): serial.identify()

    def test_identify_resets_every_variable_before_reading(self):
        serial, writes = self.fixture()
        serial.identify()
        self.assertTrue(writes[0].startswith(b'\nc=; h=; u=; x=; read -r c '))

    def test_identify_reports_armed_flag(self):
        serial, _ = self.fixture(flag=FLAG_ARMED_SHA256, uptime='37')
        self.assertEqual(serial.identify(), ('1'*32, FLAG_ARMED_SHA256, 37))

    def test_identify_missing_tools_leave_the_flag_unknown_not_unanswered(self):
        # No sha256sum or /proc/uptime on an old image: empty fields.
        serial, _ = self.fixture(flag='', uptime='')
        self.assertEqual(serial.identify(), ('1'*32, None, None))
        # Anything that is not a digest or whole seconds is also unknown.
        serial, _ = self.fixture(flag='sh sha256sum not found', uptime='12.5')
        self.assertEqual(serial.identify(), ('1'*32, None, None))

    def test_identify_requires_a_cid(self):
        serial, _ = self.fixture(cid='')
        with self.assertRaises(Unavailable) as raised: serial.identify()
        self.assertEqual(raised.exception.reason, 'no_answer')

    def test_identify_echo_is_not_evidence(self):
        serial, _ = self.fixture(query_echo=True)
        with self.assertRaises(Unavailable) as raised: serial.identify()
        self.assertEqual(raised.exception.reason, 'no_answer')

    def test_identify_two_answers_refuse(self):
        # Two framed answers arriving together are ambiguous, never a choice.
        serial, _ = self.fixture(answers=2, echo=False)
        with self.assertRaises(InstallError): serial.identify()

    def test_identify_output_bound(self):
        serial, _ = self.fixture(noise=b'x' * 20000)
        with self.assertRaises(Unavailable) as raised: serial.identify()
        self.assertEqual(raised.exception.reason, 'no_answer')

    def usb_fixture(self, interfaces, *, claim=None, configuration=None):
        claims = []
        def claim_interface(device, number):
            if claim is not None:
                raise claim
            claims.append(number)
        device = NS(bus=2, port_numbers=(4,),
                    get_active_configuration=configuration or (lambda: interfaces),
                    is_kernel_driver_active=lambda number: False,
                    ctrl_transfer=lambda *args, **kwargs: None)
        usb = NS(core=NS(find=lambda **kw: [device]),
                 util=NS(claim_interface=claim_interface, release_interface=lambda *a: None,
                         dispose_resources=lambda *a: None))
        return usb, claims

    def acm(self):
        endpoints = [NS(bmAttributes=2, bEndpointAddress=0x81), NS(bmAttributes=2, bEndpointAddress=0x01)]
        control = NS(bInterfaceClass=2, bInterfaceSubClass=2, bNumEndpoints=1, bInterfaceNumber=0)
        data = type('Data', (), {'bInterfaceClass': 10, 'bInterfaceSubClass': 0, 'bNumEndpoints': 2,
                                 'bInterfaceNumber': 1, '__iter__': lambda self: iter(endpoints)})()
        return [control, data]

    def test_unavailable_reasons_are_preserved(self):
        adb = [NS(bInterfaceClass=0xff, bInterfaceSubClass=0x42, bNumEndpoints=2, bInterfaceNumber=0)]
        usb, claims = self.usb_fixture(adb)
        with self.assertRaises(Unavailable) as raised:
            CouchSerial(usb, object(), NS(bus=2, ports=(4,)))
        self.assertEqual(raised.exception.reason, 'no_serial_function')
        self.assertEqual(claims, [])
        usb, _ = self.usb_fixture(self.acm(), claim=OSError(16, 'busy'))
        with self.assertRaises(Unavailable) as raised:
            CouchSerial(usb, object(), NS(bus=2, ports=(4,)))
        self.assertEqual(raised.exception.reason, 'cannot_open')
        usb, claims = self.usb_fixture(self.acm())
        serial = CouchSerial(usb, object(), NS(bus=2, ports=(4,)))
        self.assertEqual(claims, [0, 1])
        serial.close()
        with self.assertRaises(InstallError):
            Unavailable('something else')

    def test_windows_queries_through_the_com_port_of_the_selected_port_without_claiming(self):
        opened = []
        port = NS(write=lambda data, timeout=None: len(data), read=lambda size, timeout=None: b'',
                  close=lambda: opened.append('closed'))
        def serial_port(selected, usb):
            opened.append((selected.bus, selected.ports))
            return port
        usb, claims = self.usb_fixture(self.acm())
        serial = CouchSerial(usb, object(), NS(bus=2, ports=(4,)), serial_port=serial_port)
        self.assertIs(serial.incoming, port)
        self.assertIs(serial.outgoing, port)
        self.assertEqual(claims, [])
        serial.close()
        self.assertEqual(opened, [(2, (4,)), 'closed'])
        # A descriptor read Windows refuses does not stop the COM route ...
        def refused():
            raise NotImplementedError('usbser owns it')
        usb, _ = self.usb_fixture([], configuration=refused)
        CouchSerial(usb, object(), NS(bus=2, ports=(4,)), serial_port=serial_port).close()
        # ... but it does stop the libusb route, and a missing port is cannot_open.
        with self.assertRaises(Unavailable) as raised:
            CouchSerial(usb, object(), NS(bus=2, ports=(4,)))
        self.assertEqual(raised.exception.reason, 'cannot_open')
        def no_port(selected, usb):
            raise InstallError('Windows created no serial port for the selected USB device in time')
        usb, _ = self.usb_fixture(self.acm())
        with self.assertRaises(Unavailable) as raised:
            CouchSerial(usb, object(), NS(bus=2, ports=(4,)), serial_port=no_port)
        self.assertEqual(raised.exception.reason, 'cannot_open')

    def test_the_com_port_is_found_by_couch_identity_and_physical_port(self):
        seen = []
        class Transport:
            def __init__(self, name, usb, **kwargs):
                seen.append(name)
        import mtk_com
        ports = [NS(device='COM7', vid=0x0e8d, pid=0x201c, location='1-4.2:x.1'),
                 NS(device='COM8', vid=0x0e8d, pid=0x201c, location='1-3:x.1'),
                 NS(device='COM9', vid=0x0e8d, pid=0x2000, location='1-4.2')]
        original = mtk_com.open_serial_port
        def opener(candidate, number, usb, **kwargs):
            self.assertEqual((candidate.vid, candidate.pid, candidate.ports), (0x0e8d, 0x201c, (4, 2)))
            return original(candidate, number, usb, comports=lambda: ports, transport=Transport, **kwargs)
        import couch_serial
        couch_serial.open_serial_port, saved = opener, couch_serial.open_serial_port
        try:
            open_couch_port(NS(bus=1, ports=(4, 2)), object())
        finally:
            couch_serial.open_serial_port = saved
        self.assertEqual(seen, ['COM7'])


if __name__ == '__main__': unittest.main()
