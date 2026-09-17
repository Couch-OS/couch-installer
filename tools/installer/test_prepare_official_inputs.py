import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile

from pin_modules import load as load_pin, nested_checkouts

inputs = load_pin('prepare_official_inputs')


class OwnerInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ota = self.root/'official.zip'
        self.members = {name: name.encode() for name in inputs.BOOTSTRAP_MEMBERS}
        with zipfile.ZipFile(self.ota, 'w') as bundle:
            for name, data in self.members.items():
                bundle.writestr(name, data)
            bundle.writestr('lk.img', b'must not extract')
            bundle.writestr('../escape', b'must not extract')
        self.pin = self.root/'pin.json'
        self.pin.write_text(json.dumps({'size': self.ota.stat().st_size,
            'sha256': hashlib.sha256(self.ota.read_bytes()).hexdigest(), 'version': 'fixture'}))
        self.approved = {name: (len(data), hashlib.sha256(data).hexdigest()) for name, data in self.members.items()}

    def prepare(self, destination):
        with patch.object(inputs.official_runtime, 'PIN', self.pin), patch.object(inputs, 'BOOTSTRAP_MEMBERS', self.approved):
            return inputs.prepare(self.ota, destination, runtime=False)

    def test_only_approved_members_are_extracted_and_not_labeled_originals(self):
        destination = self.root/'output'
        result = self.prepare(destination)
        self.assertEqual({p.name for p in (destination/'bootstrap').iterdir()}, set(self.members))
        self.assertFalse(result['original_device_backup'])
        self.assertFalse(result['installable'])
        self.assertFalse(result['redistribution_authorized'])
        self.assertFalse((self.root/'escape').exists())
        self.assertEqual(destination.stat().st_mode & 0o077, 0)

    def test_wrong_archive_or_member_hash_and_existing_destination_fail_closed(self):
        destination = self.root/'output'
        self.approved['boot.img'] = (len(self.members['boot.img']), '0'*64)
        with self.assertRaises(ValueError):
            self.prepare(destination)
        self.assertFalse(destination.exists())
        self.ota.write_bytes(self.ota.read_bytes()+b'x')
        with self.assertRaises(ValueError):
            self.prepare(destination)
        destination.mkdir()
        with self.assertRaises(ValueError):
            self.prepare(destination)

    def test_vendor_extraction_failure_does_not_publish_partial_inputs(self):
        with patch.object(inputs.official_runtime, 'PIN', self.pin), \
             patch.object(inputs, 'BOOTSTRAP_MEMBERS', self.approved), \
             patch.object(inputs.official_runtime, 'extract', side_effect=ValueError('bad vendor')):
            with self.assertRaises(ValueError):
                inputs.prepare(self.ota, self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_output_in_enclosing_superproject_is_refused_before_reading_archive(self):
        # Inside a submodule parents[3] is only the submodule root; Git names the
        # checkout that embeds it, and owner vendor inputs must stay out of that too.
        destination = self.root/'output'
        superproject = subprocess.CompletedProcess([], 0, stdout=os.fsencode(self.root) + b'\n')
        outermost = subprocess.CompletedProcess([], 0, stdout=b'')
        with patch.object(inputs.subprocess, 'run', side_effect=[superproject, outermost]), \
             patch.object(inputs, 'file_sha') as hashed:
            with self.assertRaisesRegex(ValueError, 'outside the source repository'):
                self.prepare(destination)
            hashed.assert_not_called()
        self.assertFalse(destination.exists())

    def test_without_git_the_file_relative_checkout_is_still_refused(self):
        repository = Path(inputs.__file__).resolve().parents[3]
        inside = repository/('.couch-owner-inputs-fixture-' + uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, inside, ignore_errors=True)
        failures = (FileNotFoundError('git'), subprocess.TimeoutExpired('git', 10),
                    subprocess.CompletedProcess([], 128, stdout=b'', stderr=b'fatal: not a git repository'))
        for index, failure in enumerate(failures):
            with self.subTest(failure=failure):
                effect = {'side_effect': failure} if isinstance(failure, BaseException) else {'return_value': failure}
                with patch.object(inputs.subprocess, 'run', **effect):
                    self.assertEqual(inputs.source_checkouts(), [repository])
                    with self.assertRaisesRegex(ValueError, 'outside the source repository'):
                        self.prepare(inside)
                    self.assertFalse(inside.exists())
                    self.assertFalse(self.prepare(self.root/f'output-{index}')['installable'])

    @unittest.skipUnless(shutil.which('git'), 'Git is required for the submodule fixture')
    def test_git_reports_every_superproject_enclosing_a_submodule_checkout(self):
        checkouts = nested_checkouts(self.root)
        module = checkouts[0]/'tools/installer/pins/prepare_official_inputs.py'
        self.assertEqual(inputs.source_checkouts(module), checkouts)


if __name__ == '__main__':
    unittest.main()
