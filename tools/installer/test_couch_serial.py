import hashlib
import re
from types import SimpleNamespace as NS
import unittest
from couch_install import InstallError
import itertools
from unittest.mock import patch
from couch_serial import (CLEAR_BCB, CouchSerial, FLAG_ARMED_SHA256, FLAG_CLEAR_SHA256, HA100_CMDLINE,
                          PROBE_BCB, PROBE_CMDLINE, READ_BACK, Unavailable, open_couch_port)

ZEROS = '\\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0'



class SerialTests(unittest.TestCase):
    def fixture(self, cid='1'*32, *, reboot_short=False, query_echo=False,
                flag=FLAG_CLEAR_SHA256, uptime='1900', answers=1, noise=b'', echo=True, wrap=False):
        serial = CouchSerial.__new__(CouchSerial)
        serial.attempted = False
        writes, pending = [], bytearray()
        def write(data, **kwargs):
            writes.append(data)
            written = data
            if data == b'\n/bin/busybox sync; /bin/busybox reboot -f\n':
                return 1 if reboot_short else len(data)
            marker = re.search(rb'COUCH_[0-9a-f]{32}', data).group()
            if wrap:
                # A terminal that wraps the echoed line can put a real line
                # break right before the marker in the echo.
                data = data.replace(marker, b'\r\n' + marker)
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
            return len(written)
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

    def test_a_wrapped_echo_is_not_evidence_either(self):
        # A real line break before the marker in the echo still leaves "%s"
        # where the CID must be, so only the real answer can match.
        serial, _ = self.fixture(query_echo=True, wrap=True)
        with self.assertRaises(Unavailable) as raised: serial.identify()
        self.assertEqual(raised.exception.reason, 'no_answer')
        serial, _ = self.fixture(query_echo=True, wrap=True)
        with self.assertRaises(Unavailable): serial.restart('1'*32)
        serial, _ = self.fixture(wrap=True)
        self.assertEqual(serial.identify(), ('1'*32, FLAG_CLEAR_SHA256, 1900))

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

    def open_couch(self, ports, *, selected=(4, 2)):
        opened = []
        class Transport:
            def __init__(self, name, usb, **kwargs):
                opened.append(name)
        ticks = itertools.count()
        result = open_couch_port(NS(bus=1, ports=selected), object(), comports=lambda: ports,
                                 transport=Transport, now=lambda: next(ticks), sleep=lambda s: None)
        return result, opened

    def test_the_windows_query_takes_only_the_exact_physical_port(self):
        couch = lambda device, location: NS(device=device, vid=0x0e8d, pid=0x201c, location=location)
        _, opened = self.open_couch([couch('COM7', '1-4.2:x.1'), couch('COM8', '1-3:x.1'),
                                     NS(device='COM9', vid=0x0e8d, pid=0x2000, location='1-4.2'),
                                     couch('COM5', None)])
        self.assertEqual(opened, ['COM7'])
        # Never a port whose location Windows did not report: it may be
        # another remote. That ends in the manual restart, not a guess.
        for ports in ([couch('COM5', None)], [couch('COM5', 'unknown')], [couch('COM8', '1-3:x.1')],
                      [couch('COM7', '1-4.2.1:x.1')], []):
            with self.assertRaises(Unavailable) as raised:
                self.open_couch(ports)
            self.assertEqual(raised.exception.reason, 'cannot_open')
        # Two ports on the same chain (different controllers) are ambiguous.
        with self.assertRaises(Unavailable) as raised:
            self.open_couch([couch('COM7', '1-4.2:x.1'), couch('COM11', '2-4.2:x.1')])
        self.assertEqual(raised.exception.reason, 'cannot_open')
        with self.assertRaises(Unavailable):
            self.open_couch([couch(r'\\.\COM7', '1-4.2:x.1')])

class FlagClearTests(unittest.TestCase):
    """A remote whose shell answers the identity query and the framed commands."""

    def remote(self, *, cid='1'*32, flag=FLAG_ARMED_SHA256, readback=ZEROS, readback_status=0,
               silent_after_write=False, cmdline='console=tty0 bootopt=64S3,32S1,32S1 buildvariant=user',
               partition='ok', silent_probes=False, wrap=False):
        serial = CouchSerial.__new__(CouchSerial)
        serial.attempted = serial.cleared = False
        state = {'flag': flag}
        writes, pending = [], bytearray()
        def write(data, **kwargs):
            writes.append(data)
            echo = data.replace(b'\n', b'\r\n')  # the tty echoes everything
            if wrap:
                # A wrapping terminal can break the echoed line before a marker.
                echo = re.sub(rb'(COUCH[-_][A-Z-]*[0-9a-f]{32})', rb'\r\n\1', echo)
            pending.extend(echo)
            if b'sha256sum' in data:
                marker = re.search(rb'COUCH_[0-9a-f]{32}', data).group()
                pending.extend(b'\r\n' + marker + b':' + cid.encode() + b':' + state['flag'].encode()
                               + b':900:END\r\n')
                return len(data)
            marker = re.search(rb'COUCH-RECOVERY-[0-9a-f]{32}', data).group()
            if PROBE_CMDLINE in data or PROBE_BCB in data:
                if silent_probes:
                    return len(data)
                body = (cmdline if PROBE_CMDLINE in data else partition).encode() + b'\r\n'
                pending.extend(b'\r\n' + marker + b':BEGIN\r\n' + body + b'\r\n' + marker
                               + b':' + (b'0' if body.strip() else b'1') + b':END\r\n')
                return len(data)
            if CLEAR_BCB in data:
                if silent_after_write:
                    return len(data)
                state['flag'] = FLAG_CLEAR_SHA256
                body, status = b'1+0 records in\r\n1+0 records out\r\n', 0
            else:
                self.assertIn(READ_BACK, data)
                body, status = readback.encode() + b'\r\n', readback_status
            pending.extend(b'\r\n' + marker + b':BEGIN\r\n' + body + b'\r\n' + marker + b':'
                           + str(status).encode() + b':END\r\n')
            return len(data)
        def read(size, **kwargs):
            if not pending:
                raise TimeoutError('nothing yet')
            value = bytes(pending[:size]); del pending[:size]; return value
        serial.outgoing = NS(write=write)
        serial.incoming = NS(read=read)
        serial.usb = NS(core=NS(USBTimeoutError=TimeoutError))
        return serial, writes, state

    def kinds(self, writes):
        return ['query' if b'sha256sum' in w else 'clear' if CLEAR_BCB in w
                else 'cmdline' if PROBE_CMDLINE in w else 'partition' if PROBE_BCB in w
                else 'readback' for w in writes]

    PROBED = ['query', 'cmdline', 'partition']

    def test_the_only_write_is_the_first_block_of_para(self):
        self.assertEqual(CLEAR_BCB, b'dd if=/dev/zero of=/dev/mmcblk0p10 bs=512 count=1 conv=notrunc; sync')
        self.assertNotIn(b'of=', READ_BACK)

    def test_clear_writes_only_after_the_expected_cid_and_the_armed_value(self):
        serial, writes, state = self.remote()
        self.assertEqual(serial.clear_boot_flag('1'*32), ZEROS)
        self.assertEqual(self.kinds(writes), self.PROBED + ['clear', 'readback', 'query'])
        self.assertEqual(state['flag'], FLAG_CLEAR_SHA256)
        self.assertTrue(serial.cleared)
        self.assertFalse(serial.attempted)
        self.assertFalse(any(b'reboot' in w for w in writes))
        # At most once per session.
        with self.assertRaises(InstallError): serial.clear_boot_flag('1'*32)
        self.assertEqual(len(writes), 6)

    def test_clear_never_writes_for_another_remote_or_an_unexpected_block(self):
        for cid, flag in (('2'*32, FLAG_ARMED_SHA256), ('1'*32, 'e'*64), ('1'*32, '')):
            serial, writes, _ = self.remote(cid=cid, flag=flag)
            with self.assertRaises(InstallError): serial.clear_boot_flag('1'*32)
            self.assertEqual(self.kinds(writes), ['query'])
            self.assertFalse(serial.cleared)
        # An already clear block is left alone.
        serial, writes, _ = self.remote(flag=FLAG_CLEAR_SHA256)
        self.assertIsNone(serial.clear_boot_flag('1'*32))
        self.assertEqual(self.kinds(writes), ['query'])
        self.assertFalse(serial.cleared)

    def test_a_block_that_does_not_read_back_as_zero_stops_hard(self):
        for readback, status in (('\\0  \\0   b  \\0', 0), ('', 0), ('0000000', 0), (ZEROS, 127)):
            serial, writes, _ = self.remote(readback=readback, readback_status=status)
            with self.assertRaises(InstallError) as raised: serial.clear_boot_flag('1'*32)
            self.assertNotIsInstance(raised.exception, Unavailable)
            self.assertEqual(self.kinds(writes), self.PROBED + ['clear', 'readback'])
            self.assertTrue(serial.cleared)

    def test_a_write_that_is_never_answered_is_a_hard_stop_not_unavailable(self):
        serial, writes, _ = self.remote(silent_after_write=True)
        with patch('couch_serial.time.monotonic', side_effect=itertools.count()):
            with self.assertRaises(InstallError) as raised: serial.clear_boot_flag('1'*32)
        self.assertNotIsInstance(raised.exception, Unavailable)
        self.assertEqual(self.kinds(writes), self.PROBED + ['clear'])
        self.assertTrue(serial.cleared)

    def test_a_silent_remote_is_unavailable_and_nothing_is_written(self):
        serial, writes, _ = self.remote()
        serial.incoming = NS(read=lambda size, **kwargs: (_ for _ in ()).throw(TimeoutError()))
        with patch('couch_serial.time.monotonic', side_effect=itertools.count()):
            with self.assertRaises(Unavailable): serial.clear_boot_flag('1'*32)
        self.assertEqual(self.kinds(writes), ['query'])
        self.assertFalse(serial.cleared)

    def test_the_recovery_actions_probes_come_first_and_can_refuse(self):
        self.assertEqual(PROBE_CMDLINE, b'cat /proc/cmdline')
        self.assertEqual(PROBE_BCB, b'test -b /dev/mmcblk0p10 && echo ok')
        self.assertEqual(HA100_CMDLINE, 'bootopt=64S3,32S1,32S1')
        # Not an HA100 Couch image, or no boot flag partition: refused, unwritten.
        for kwargs, kinds in (({'cmdline': 'console=ttyS0 root=/dev/sda1'}, ['query', 'cmdline']),
                              ({'partition': ''}, self.PROBED)):
            serial, writes, state = self.remote(**kwargs)
            with self.assertRaises(InstallError) as raised: serial.clear_boot_flag('1'*32)
            self.assertNotIsInstance(raised.exception, Unavailable)
            self.assertEqual(self.kinds(writes), kinds)
            self.assertFalse(serial.cleared)
            self.assertEqual(state['flag'], FLAG_ARMED_SHA256)
        # A probe that is never answered: unavailable, and still unwritten.
        serial, writes, _ = self.remote(silent_probes=True)
        with patch('couch_serial.time.monotonic', side_effect=itertools.count()):
            with self.assertRaises(Unavailable): serial.clear_boot_flag('1'*32)
        self.assertEqual(self.kinds(writes), ['query', 'cmdline'])
        self.assertFalse(serial.cleared)

    def test_a_wrapped_echo_of_a_framed_command_is_not_its_answer(self):
        serial, writes, _ = self.remote(wrap=True, silent_probes=True)
        with patch('couch_serial.time.monotonic', side_effect=itertools.count()):
            with self.assertRaises(Unavailable): serial.clear_boot_flag('1'*32)
        self.assertFalse(serial.cleared)
        serial, writes, _ = self.remote(wrap=True)
        self.assertEqual(serial.clear_boot_flag('1'*32), ZEROS)

    def test_the_echoed_command_is_never_read_as_its_answer(self):
        serial, writes, _ = self.remote()
        serial.clear_boot_flag('1'*32)
        clear = next(w for w in writes if CLEAR_BCB in w)
        marker = re.search(rb'COUCH-RECOVERY-[0-9a-f]{32}', clear).group()
        self.assertNotIn(b'\n' + marker + b':BEGIN', clear)
        self.assertNotIn(marker + b':0:END', clear)


if __name__ == '__main__': unittest.main()
