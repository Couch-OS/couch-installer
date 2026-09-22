import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import contextmanager

from couch_install import InstallError, IDENTITY_PARTITIONS
from couch_serial import FLAG_CLEAR_SHA256, Unavailable, open_couch_port
from mtk_adapter import Adapter, Wire, serve, MAX, REVIEWED_SOURCES, couch_query_port, failure_diagnostic
from mtk_usb import ExactUsbBackend, PacketBufferedInput, bounded_operation, supervised_operations
from mtk_writer import _open_image, _fd_stamp, _read_at, ConnectedMtkWriter


class MemoryWire:
    def __init__(self):
        self.events = []

    def send(self, value):
        self.events.append(value)

    def chunk(self, value):
        self.events.append(value)


class AdapterTests(unittest.TestCase):
    def test_failure_diagnostic_never_contains_exception_text_or_unknown_names(self):
        try:
            raise PermissionError(13, 'secret password /private/device-id')
        except PermissionError as error:
            result = failure_diagnostic(error)
        self.assertEqual(result, {'category': 'PermissionError', 'errno': 13})
        PrivateDeviceName = type('private-device-secret', (Exception,), {})
        result = failure_diagnostic(PrivateDeviceName('secret'))
        self.assertEqual(result, {'category': 'WorkerError'})

    def test_failure_diagnostic_reports_the_wrapped_cause_without_text(self):
        try:
            try:
                raise OSError(5, 'secret device path')
            except OSError as cause:
                raise InstallError('Ambiguous MTK write; session poisoned') from cause
        except InstallError as error:
            result = failure_diagnostic(error)
        self.assertEqual(result['category'], 'InstallError')
        self.assertEqual(result['cause']['category'], 'OSError')
        self.assertEqual(result['cause']['errno'], 5)
        self.assertNotIn('secret', json.dumps(result))
        self.assertIn('mtk_tty.py', REVIEWED_SOURCES)

    def test_failure_diagnostic_records_the_reviewed_call_path(self):
        import mtk_writer
        buffered = PacketBufferedInput(
            SimpleNamespace(wMaxPacketSize=64, read=lambda size, timeout: 1 / 0))
        try:
            mtk_writer.ConnectedMtkWriter._expect(SimpleNamespace(_ep_in=buffered), b'\x5a')
        except ZeroDivisionError as error:
            result = failure_diagnostic(error)
        # Only reviewed files appear; this test file is excluded even though it
        # is the outermost frame of the same traceback.
        self.assertTrue(all(frame['source'] in REVIEWED_SOURCES for frame in result['frames']))
        # Outermost reviewed frame names the protocol step, innermost the fault.
        self.assertEqual(result['frames'][0]['source'], 'mtk_writer.py')
        self.assertEqual(result['frames'][-1]['source'], 'mtk_usb.py')
        self.assertEqual(result['frames'][-1], {'source': result['source'], 'line': result['line']})

    def test_real_stdio_survives_independent_library_rewrap_and_hides_output(self):
        import subprocess
        import sys
        code = r"""
import io, os, sys
sys.path.insert(0, sys.argv[1])
from mtk_adapter import serve_stdio
class Fixture:
    def __init__(self, wire): self.wire = wire
    def dispatch(self, command):
        assert command == {'op': 'prepare'}
        # Exact pinned upstream behavior, followed by both Python and raw output.
        sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')
        print('must not enter RPC', flush=True)
        print('must not leak stderr', file=sys.stderr, flush=True)
        os.write(1, b'raw stdout must also be hidden')
        os.write(2, b'raw stderr must also be hidden')
        self.wire.send({'event': 'prepared'})
        self.wire.chunk(bytes([0, 10, 13, 26, 255]))
        return False
    def close(self): pass
raise SystemExit(serve_stdio(Fixture))
"""
        command = json.dumps({'op': 'prepare'}).encode()
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(Path(__file__).resolve().parent)],
                                input=struct.pack('<I', len(command)) + command,
                                capture_output=True, timeout=15, check=True)
        size, = struct.unpack('<I', result.stdout[:4])
        self.assertEqual(json.loads(result.stdout[4:4 + size]), {'event': 'prepared'})
        rest = result.stdout[4 + size:]
        chunk_size, = struct.unpack('<I', rest[:4])
        self.assertEqual(json.loads(rest[4:4 + chunk_size]), {'event': 'chunk', 'size': 5})
        raw = rest[4 + chunk_size:]
        self.assertEqual(struct.unpack('<III', raw[:12]), (5, 5, 0))
        self.assertEqual(raw[12:], bytes([0, 10, 13, 26, 255]))
        self.assertEqual(result.stderr, b'')

    def test_unprepared_worker_never_reaches_hardware(self):
        wire = MemoryWire()
        def forbidden(*args, **kwargs):
            self.fail('Hardware constructor used before preparation')
        adapter = Adapter(wire, backend=forbidden)
        for command in ({'op': 'enumerate'}, {'op': 'start', 'candidate': {}},
                        {'op': 'write_boot'}, {'op': 'boot'},
                        {'op': 'read', 'target': 'userdata'}, {'op': 'restore'}):
            with self.assertRaises(InstallError):
                adapter.dispatch(command)
        self.assertEqual(wire.events, [])

    def test_write_attempt_consumed_even_if_readback_fails(self):
        adapter = Adapter(MemoryWire())
        writes = []
        adapter.writer = SimpleNamespace(write=lambda *args: writes.append(args), hash=lambda name: 'bad')
        adapter.stage = Path('fixture')
        adapter.binding = {'stage_sha256': 'expected'}
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'write_boot'})
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'write_boot'})
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'boot'})
        self.assertEqual(len(writes), 1)

    def test_boot_waits_for_retained_calibration_readback(self):
        wire = MemoryWire()
        adapter = Adapter(wire)
        reset = []
        adapter.backend = SimpleNamespace(boot_after_capture=lambda: reset.append(True))
        adapter.stage = Path('fixture')
        adapter.binding = {'stage_sha256': 'newboot',
                           'identity_sha256': {name: name for name in IDENTITY_PARTITIONS},
                           'original_sha256': {name: name for name in ('boot', 'recovery', 'odmdtbo')}}
        adapter.writer = SimpleNamespace(write=lambda *args: None,
            hash=lambda name: 'newboot' if name == 'boot' else ('changed' if name == 'nvram' else name))
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'write_boot'})
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'boot'})
        self.assertEqual(reset, [])
        self.assertNotIn({'event': 'boot_verified'}, wire.events)

    def test_wire_requires_deadline_ack_before_operation(self):
        data = json.dumps({'ack': 'wrong'}).encode()
        wire = Wire(io.BytesIO(struct.pack('<I', len(data)) + data), io.BytesIO())
        entered = []
        with self.assertRaises(InstallError):
            with wire.deadline(10):
                entered.append(True)
        self.assertEqual(entered, [])
        with self.assertRaises(InstallError):
            Wire(io.BytesIO(struct.pack('<I', MAX+1)), io.BytesIO()).receive()

    def test_supervisor_scope_resets_and_failure_prevents_operation(self):
        events = []
        @contextmanager
        def supervisor(seconds):
            events.append(seconds)
            raise InstallError('Disconnected supervisor')
            yield
        with supervised_operations(supervisor):
            with self.assertRaises(InstallError):
                with bounded_operation(12):
                    events.append('unsafe')
        self.assertEqual(events, [12])
        # Normal callers still require the platform signal implementation.
        with patch('mtk_usb.threading.current_thread', return_value=object()):
            with self.assertRaises(InstallError):
                with bounded_operation(12):
                    self.fail('Missing supervisor was accepted')

    def test_worker_error_always_closes_without_retry(self):
        events = []
        class Worker:
            def dispatch(self, command):
                events.append('attempt')
                raise InstallError('ambiguous')
            def close(self):
                events.append('close')
        wire = SimpleNamespace(receive=lambda: {}, deadline=lambda seconds: None)
        with self.assertRaises(InstallError):
            serve(wire, lambda _: Worker())
        self.assertEqual(events, ['attempt', 'close'])

    def bind_adapter(self, devices):
        class DeadlineWire(MemoryWire):
            @contextmanager
            def deadline(self, seconds):
                self.events.append(('deadline', seconds))
                yield
        wire = DeadlineWire()
        adapter = Adapter(wire)
        adapter.backend = SimpleNamespace(usb=SimpleNamespace(core=SimpleNamespace(find=lambda **kw: iter(devices))),
                                          usb_backend=None)
        return adapter, wire

    def test_android_bind_survives_unreadable_descriptors_on_other_devices(self):
        class Unreadable:
            bus, port_numbers = 5, (2,)
            @property
            def serial_number(self):
                raise ValueError('The device has no langid (permission issue, no string descriptors supported or device error)')
        readable = SimpleNamespace(bus=5, port_numbers=(4, 1), serial_number='0127A260301T0463')
        adapter, wire = self.bind_adapter([Unreadable(), readable])
        adapter.dispatch({'op': 'android_bind', 'serial': '0127A260301T0463'})
        self.assertEqual(wire.events[-1], {'event': 'android_bound', 'bus': 5, 'ports': [4, 1],
                                           'serial_sha256': hashlib.sha256(b'0127A260301T0463').hexdigest()})

    def test_android_bind_names_unreadable_descriptors_when_the_remote_is_held(self):
        class Unreadable:
            bus, port_numbers = 5, (13,)
            @property
            def serial_number(self):
                raise ValueError('The device has no langid')
        adapter, wire = self.bind_adapter([Unreadable()])
        with self.assertRaisesRegex(InstallError, r'1 MediaTek USB device\(s\) had unreadable descriptors.*ADB'):
            adapter.dispatch({'op': 'android_bind', 'serial': '0127A260301T0463'})
        adapter, wire = self.bind_adapter([])
        with self.assertRaisesRegex(InstallError, r'physical USB port$'):
            adapter.dispatch({'op': 'android_bind', 'serial': '0127A260301T0463'})

    COUCH_PORT = {'bus': 2, 'address': 9, 'ports': [4, 1], 'vid': 0x0e8d, 'pid': 0x201c}

    def couch_serial(self, answers, opened, closed):
        class FakeSerial:
            def __init__(self, usb, backend, selected, *, serial_port=None):
                if answers and isinstance(answers[0], Unavailable) and answers[0].reason == 'absent':
                    raise answers.pop(0)
                opened.append((selected, serial_port))
            def identify(self):
                answer = answers.pop(0)
                if isinstance(answer, Exception):
                    raise answer
                return answer
            def restart(self, cid):
                opened.append(('restart', cid))
            def close(self):
                closed.append(True)
        return FakeSerial

    def test_couch_identify_reports_observed_and_unavailable_and_closes(self):
        adapter, wire = self.bind_adapter([])
        opened, closed = [], []
        answers = [('ab'*16, FLAG_CLEAR_SHA256, 42), Unavailable('no_answer'), Unavailable('absent'),
                   ('ab'*16, None, None)]
        with patch('mtk_adapter.CouchSerial', self.couch_serial(answers, opened, closed)), \
                patch('mtk_adapter.couch_query_port', return_value=None):
            for _ in range(4):
                adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT})
        results = [event for event in wire.events if isinstance(event, dict)]
        self.assertEqual(results, [
            {'event': 'couch_identity', 'result': 'observed', 'cid': 'ab'*16,
             'boot_flag_sha256': FLAG_CLEAR_SHA256, 'uptime': 42},
            {'event': 'couch_identity', 'result': 'unavailable', 'reason': 'no_answer'},
            {'event': 'couch_identity', 'result': 'unavailable', 'reason': 'absent'},
            {'event': 'couch_identity', 'result': 'observed', 'cid': 'ab'*16,
             'boot_flag_sha256': None, 'uptime': None}])
        # Every opened port is closed again, and each query had its own deadline.
        self.assertEqual(len(closed), 3)
        self.assertEqual(len(opened), 3)
        self.assertEqual(opened[0][0].ports, (4, 1))
        self.assertEqual(wire.events.count(('deadline', 22)), 4)
        self.assertFalse(adapter.failed)

    def test_couch_identify_repeats_but_is_refused_after_reboot_or_start(self):
        adapter, wire = self.bind_adapter([])
        opened, closed = [], []
        answers = [('ab'*16, FLAG_CLEAR_SHA256, 200)] * 2
        with patch('mtk_adapter.CouchSerial', self.couch_serial(list(answers), opened, closed)):
            adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT})
            adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT})
            adapter.dispatch({'op': 'couch_reboot', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})
            self.assertIn(('restart', 'ab'*16), opened)
            self.assertEqual(wire.events[-1], {'event': 'couch_reboot', 'result': 'requested'})
            with self.assertRaises(InstallError):
                adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT})
        adapter, wire = self.bind_adapter([])
        adapter.reader = object()
        with patch('mtk_adapter.CouchSerial', self.couch_serial(list(answers), [], [])):
            with self.assertRaises(InstallError):
                adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT})
        self.assertEqual(wire.events, [])

    def test_couch_identify_rejects_non_couch_candidate(self):
        for candidate in ({**self.COUCH_PORT, 'pid': 0x2000}, {**self.COUCH_PORT, 'extra': 1},
                          {**self.COUCH_PORT, 'ports': []}, {**self.COUCH_PORT, 'bus': 0}):
            adapter, wire = self.bind_adapter([])
            def forbidden(*args, **kwargs):
                self.fail('Couch serial opened for an invalid port')
            with patch('mtk_adapter.CouchSerial', forbidden):
                with self.assertRaises(InstallError):
                    adapter.dispatch({'op': 'couch_identify', 'candidate': candidate})
            self.assertEqual(wire.events, [])
        adapter, _ = self.bind_adapter([])
        with self.assertRaises(InstallError):
            adapter.dispatch({'op': 'couch_identify', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})

    def clearing_serial(self, outcomes, opened):
        class FakeSerial:
            def __init__(self, usb, backend, selected, *, serial_port=None):
                opened.append(serial_port)
                self.cleared = False
            def clear_boot_flag(self, cid):
                outcome = outcomes.pop(0)
                if isinstance(outcome, tuple):
                    # Fails after the write was sent.
                    self.cleared = True
                    raise outcome[1]
                if isinstance(outcome, Exception):
                    raise outcome
                self.cleared = outcome is not None
                return outcome
            def close(self):
                opened.append('closed')
        return FakeSerial

    def test_couch_clear_flag_reports_each_outcome_and_writes_at_most_once(self):
        adapter, wire = self.bind_adapter([])
        opened = []
        command = {'op': 'couch_clear_flag', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16}
        with patch('mtk_adapter.CouchSerial', self.clearing_serial(
                [Unavailable('cannot_open'), None, '\\0  \\0'], opened)), \
                patch('mtk_adapter.couch_query_port', return_value=open_couch_port):
            for _ in range(3):
                adapter.dispatch(command)
            # Nothing written yet by the first two, so they did not consume it;
            # the third wrote, so a fourth is refused.
            with self.assertRaises(InstallError):
                adapter.dispatch(command)
        results = [event for event in wire.events if isinstance(event, dict)]
        self.assertEqual(results, [
            {'event': 'couch_flag_cleared', 'result': 'unavailable', 'reason': 'cannot_open'},
            {'event': 'couch_flag_cleared', 'result': 'already_clear'},
            {'event': 'couch_flag_cleared', 'result': 'cleared', 'readback': '\\0  \\0'}])
        # The one write never takes the COM route, even where the query does.
        self.assertEqual(opened.count(None), 3)
        self.assertNotIn(open_couch_port, opened)
        self.assertEqual(opened.count('closed'), 3)
        self.assertEqual(wire.events.count(('deadline', 150)), 3)

    def test_a_clear_that_fails_after_its_write_stops_the_worker_without_an_answer(self):
        adapter, wire = self.bind_adapter([])
        opened = []
        command = {'op': 'couch_clear_flag', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16}
        with patch('mtk_adapter.CouchSerial', self.clearing_serial(
                [('after_write', InstallError('did not read back as cleared'))], opened)):
            with self.assertRaises(InstallError):
                adapter.dispatch(command)
        self.assertTrue(adapter.couch_clear_consumed)
        self.assertTrue(adapter.failed)
        self.assertEqual(opened.count('closed'), 1)
        self.assertEqual([event for event in wire.events if isinstance(event, dict)], [])
        with self.assertRaises(InstallError):
            adapter.dispatch(command)

    def test_couch_clear_flag_is_refused_after_the_reboot_or_download_mode(self):
        adapter, wire = self.bind_adapter([])
        with patch('mtk_adapter.CouchSerial', self.couch_serial([], [], [])):
            adapter.dispatch({'op': 'couch_reboot', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})
        with patch('mtk_adapter.CouchSerial', self.clearing_serial(['x'], [])):
            with self.assertRaises(InstallError):
                adapter.dispatch({'op': 'couch_clear_flag', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})
        adapter, wire = self.bind_adapter([])
        adapter.reader = object()
        with patch('mtk_adapter.CouchSerial', self.clearing_serial(['x'], [])):
            with self.assertRaises(InstallError):
                adapter.dispatch({'op': 'couch_clear_flag', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})
            adapter, wire = self.bind_adapter([])
            with self.assertRaises(InstallError):
                adapter.dispatch({'op': 'couch_clear_flag', 'candidate': self.COUCH_PORT})
        self.assertEqual(wire.events, [])

    def test_only_the_windows_identity_query_uses_the_com_port(self):
        self.assertIs(couch_query_port('win32'), open_couch_port)
        self.assertIsNone(couch_query_port('darwin'))
        self.assertIsNone(couch_query_port('linux'))
        adapter, _ = self.bind_adapter([])
        opened = []
        with patch('mtk_adapter.CouchSerial', self.couch_serial([], opened, [])), \
                patch('mtk_adapter.couch_query_port', return_value=open_couch_port):
            adapter.dispatch({'op': 'couch_reboot', 'candidate': self.COUCH_PORT, 'cid': 'ab'*16})
        # The reboot keeps its libusb route: on Windows it stays a manual restart.
        self.assertIsNone(opened[0][1])
        self.assertIn('couch_serial.py', REVIEWED_SOURCES)

    def test_verified_libusb_selection_is_explicit_and_has_no_fallback(self):
        calls = []
        backend = object()
        usb = SimpleNamespace(core=SimpleNamespace(find=lambda **kw: calls.append(kw) or []))
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / 'libusb'
            library.write_bytes(b'fixture')
            def load(find_library):
                self.assertEqual(find_library('ignored'), str(library.resolve()))
                return backend
            with patch('mtk_usb.importlib.import_module', return_value=SimpleNamespace(get_backend=load)):
                adapter = ExactUsbBackend('fixture', usb=usb, libusb_path=library)
                self.assertEqual(adapter.enumerate(), [])
            self.assertIs(calls[0]['backend'], backend)
            with patch('mtk_usb.importlib.import_module', return_value=SimpleNamespace(get_backend=lambda **kw: None)):
                with self.assertRaises(InstallError):
                    ExactUsbBackend('fixture', usb=usb, libusb_path=library)
            self.assertEqual(len(calls), 1)

    def test_image_open_rejects_symlink_and_preserves_binary_bytes(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image'
            data = b'\x00\r\n\x1a\xff'
            path.write_bytes(data)
            fd = _open_image(path)
            with os.fdopen(fd, 'rb') as file:
                self.assertEqual(file.read(), data)
            link = path.with_name('link')
            try:
                link.symlink_to(path)
            except OSError:
                return  # Windows without symlink privilege: reparse fixture separately.
            with self.assertRaises(InstallError):
                _open_image(link)

    def test_retained_image_name_and_descriptor_use_consistent_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"\x00\r\n\x1a\xff")
            fd = _open_image(path)
            try:
                writer = object.__new__(ConnectedMtkWriter)
                writer._sources = {"boot": {"path": path, "fd": fd, "stamp": _fd_stamp(fd)}}
                writer._unchanged("boot")
                self.assertFalse(os.get_inheritable(fd))
            finally:
                os.close(fd)

    def test_windows_read_at_fallback_keeps_exact_binary_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"012\r\n\x1a\xff789")
            fd = _open_image(path)
            try:
                without_pread = SimpleNamespace(lseek=os.lseek, read=os.read, SEEK_SET=os.SEEK_SET)
                with patch("mtk_writer.os", without_pread):
                    self.assertEqual(_read_at(fd, 4, 3), b"\r\n\x1a\xff")
                    self.assertEqual(_read_at(fd, 3, 0), b"012")
                    self.assertEqual(_read_at(fd, 8, 9), b"9")
            finally:
                os.close(fd)

    @unittest.skipUnless(os.name == "nt", "Windows sharing/reparse semantics")
    def test_windows_retained_image_blocks_writers_and_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"original")
            replacement = path.with_name("replacement")
            replacement.write_bytes(b"different")
            fd = _open_image(path)
            try:
                with self.assertRaises(OSError):
                    path.write_bytes(b"changed")
                with self.assertRaises(OSError):
                    os.replace(replacement, path)
                self.assertEqual(os.read(fd, 8), b"original")
            finally:
                os.close(fd)
            os.replace(replacement, path)
            self.assertEqual(path.read_bytes(), b"different")

    @unittest.skipUnless(os.name == "nt", "Windows reparse semantics")
    def test_windows_junction_cannot_be_opened_as_an_image(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            junction = Path(directory) / "junction"
            subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises((InstallError, OSError)):
                    _open_image(junction)
            finally:
                junction.rmdir()


if __name__ == '__main__':
    unittest.main()
