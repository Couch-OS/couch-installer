from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pin_modules import load as load_pin

vendor = load_pin('private_vendor')


class PrivateVendorTests(unittest.TestCase):
    def bundle(self, root):
        base=root/'base';base.mkdir()
        contents={name:('fixture '+name).encode() for name in vendor.ALLOWED}
        for name in vendor.STATIC+vendor.FIRMWARE:
            path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(contents[name])
        image=root/'image.img';image.write_bytes(b'\0'*1080+b'\x53\xef')
        hashes={role:vendor.file_sha(image) for role in ('system','vendor')}
        output=root/'bundle'
        with patch.object(vendor,'read_image',side_effect=lambda image,name:contents[name]), patch.object(vendor.subprocess,'run',return_value=SimpleNamespace(stderr='debugfs fixture')):
            manifest=vendor.extract(base,image,image,hashes,output)
        return output,manifest

    def test_only_missing_static_configuration_is_extracted_and_all_existing_files_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);bundle,manifest=self.bundle(root)
            self.assertEqual({r['path'] for r in manifest['files'] if r['operation']=='extracted missing file'},set(vendor.MISSING))
            self.assertEqual(vendor.verify_bundle(bundle),manifest)
            self.assertFalse(manifest['redistribution_authorized'])
            self.assertEqual(bundle.stat().st_mode & 0o777,0o700)
            (bundle/'vendor/firmware/WMT_SOC.cfg').write_text('tampered')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):vendor.verify_bundle(bundle)

    def test_existing_bundle_mismatch_and_wrong_image_hash_fail_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);base=root/'base';base.mkdir()
            for name in vendor.STATIC+vendor.FIRMWARE:
                path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'changed')
            image=root/'image';image.write_bytes(b'\0'*1080+b'\x53\xef')
            digest=vendor.file_sha(image)
            with self.assertRaisesRegex(ValueError,'image hash mismatch'):
                vendor.extract(base,image,image,{'system':'0'*64,'vendor':digest},root/'bad')
            with patch.object(vendor,'read_image',return_value=b'original'), self.assertRaisesRegex(ValueError,'differs from original'):
                vendor.extract(base,image,image,{'system':digest,'vendor':digest},root/'bad')
            self.assertFalse((root/'bad').exists())

    def test_rejects_uninventoried_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);bundle,_=self.bundle(root)
            path=bundle/'authorized_keys';path.write_text('secret')
            with self.assertRaises(ValueError):vendor.verify_bundle(bundle)
            path.unlink();path.symlink_to('vendor/firmware/WMT_SOC.cfg')
            with self.assertRaises(ValueError):vendor.verify_bundle(bundle)


if __name__ == '__main__':
    unittest.main()
