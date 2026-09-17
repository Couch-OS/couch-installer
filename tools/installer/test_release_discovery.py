import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch
from urllib.request import Request

import couch_tui
from couch_install import InstallError
import release_discovery as discovery

# The shapes the repository actually publishes: a dated alpha, the dev build
# cut after it, and the release they lead to.
ALPHA = 'v0.1.0-alpha.20260913.148'
DEV = 'v0.1.0-alpha.20260913.148.dev'
OLD = 'https://github.com/dangerouslaser/couch/releases/download/'
NEW = 'https://github.com/Couch-OS/couch/releases/download/'
# Names that must never pass for Couch, before or after the transfer.
LOOKALIKES = ('couch-os/couch', 'Couch-OS/Couch', 'Couch-OS/couch-installer', 'Couch-OS/other',
              'dangerouslaser/couch-installer', 'Dangerouslaser/couch', 'other/couch', 'Couch-OS/couch.git')


def fixture(tag=ALPHA):
    metadata = {'schema': 1, 'model': discovery.MODEL, 'version': tag, 'installable': False, 'files': []}
    data = json.dumps(metadata).encode()
    name = f'couch-{tag}-{discovery.MODEL}.json'
    release = {'id': 1, 'tag_name': tag, 'draft': False, 'prerelease': '-alpha.' in tag,
               'assets': [{'id': 2, 'name': name, 'state': 'uploaded', 'size': len(data),
                           'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
                           'browser_download_url': discovery.DOWNLOAD + tag + '/' + name}]}
    return release, data


class DiscoveryTests(unittest.TestCase):
    def test_drafts_channels_exact_version_and_numeric_sort(self):
        alpha, _ = fixture()
        newer, _ = fixture('v0.1.0-alpha.20260914.150')
        old_scheme, _ = fixture('v0.1.0-alpha.9')
        stable, _ = fixture('v0.1.0')
        draft, _ = fixture('v0.2.0')
        draft['draft'] = True
        values = [alpha, draft, stable, newer, old_scheme]
        self.assertEqual([v.tag for v in discovery.selections(values)], ['v0.1.0'])
        self.assertEqual([v.tag for v in discovery.selections(values, 'alpha')],
                         ['v0.1.0-alpha.20260914.150', ALPHA, 'v0.1.0-alpha.9'])
        self.assertEqual(len(discovery.selections(values, 'alpha', ALPHA)), 1)
        self.assertEqual(discovery.selections(values, 'stable', 'v0.2.0'), [])

    def test_dev_tags_are_their_own_channel_and_sort_above_their_alpha(self):
        alpha, _ = fixture()
        dev, _ = fixture(DEV)
        later, _ = fixture('v0.1.0-alpha.20260914.150')
        values = [alpha, dev, later]
        # A dev build is not an alpha the way release.rs sees it either.
        self.assertEqual([v.tag for v in discovery.selections(values, 'alpha')],
                         ['v0.1.0-alpha.20260914.150', ALPHA])
        self.assertEqual([v.tag for v in discovery.selections(values, 'dev')], [DEV])
        self.assertEqual([discovery.order(t) > discovery.order(ALPHA) for t in (DEV, 'v0.1.0-alpha.20260914.150')],
                         [True, True])
        self.assertTrue(discovery.order('v0.1.0-alpha.20260914.150') > discovery.order(DEV))
        self.assertTrue(discovery.order('v0.1.0') > discovery.order('v0.1.0-alpha.20260914.150'))

    def test_unpublishable_tag_shapes_are_ignored(self):
        for tag in ['v0.1.0-beta.1', 'v0.1.0-alpha', 'v0.1.0-alpha.01', 'v0.1.0-dev', 'v01.0.0', 'latest']:
            release, _ = fixture(tag)
            release['prerelease'] = True
            self.assertEqual(discovery.selections([release], 'alpha'), [], tag)
            self.assertEqual(discovery.selections([release], 'dev'), [], tag)

    def test_empty_and_source_only_releases_are_not_installation_choices(self):
        release, _ = fixture()
        release['assets'] = []
        self.assertEqual(discovery.selections([release], 'alpha'), [])
        self.assertEqual(discovery.discover(fetch=lambda *_: b'[]'), [])

    def test_listing_only_calls_bounded_releases_api_never_latest_or_assets(self):
        release, _ = fixture()
        calls = []
        def fetch(url, cap):
            calls.append((url, cap))
            return json.dumps([release]).encode()
        choices = discovery.discover('alpha', fetch=fetch)
        self.assertEqual(len(choices), 1)
        self.assertEqual(calls, [(discovery.API + '?per_page=100&page=1', discovery.MAX_LIST)])

    def test_bad_filters_fail_before_network(self):
        with patch.object(discovery, 'fetch_bytes') as fetch:
            for channel, exact in [('nightly', None), ('alpha', 'v0.1.0-alpha.148.'), ('alpha', ALPHA + '.beta')]:
                with self.assertRaises(InstallError):
                    discovery.discover(channel, exact, fetch=fetch)
            fetch.assert_not_called()

    def test_asset_pin_rejects_path_size_hash_and_duplicate_confusion(self):
        release, _ = fixture()
        for field, value in [('browser_download_url', 'https://example.com/evil'),
                             ('browser_download_url', release['assets'][0]['browser_download_url'] + '?different=1'),
                             ('size', True), ('size', discovery.MAX_MANIFEST + 1),
                             ('digest', None), ('state', 'new')]:
            bad = copy.deepcopy(release)
            bad['assets'][0][field] = value
            with self.assertRaises(InstallError): discovery.selections([bad], 'alpha')
        release['assets'] *= 2
        with self.assertRaises(InstallError): discovery.selections([release], 'alpha')

    def test_asset_urls_accept_either_couch_name_and_no_other_owner(self):
        release, data = fixture()
        name = release['assets'][0]['name']
        self.assertEqual(release['assets'][0]['browser_download_url'], OLD + ALPHA + '/' + name)
        # After the transfer the API reports the new owner for every release.
        for prefix, repository in ((OLD, 'dangerouslaser/couch'), (NEW, 'Couch-OS/couch')):
            release['assets'][0]['browser_download_url'] = prefix + ALPHA + '/' + name
            selected = discovery.selections([release], 'alpha')[0]
            self.assertEqual(selected.url, prefix + ALPHA + '/' + name)
            self.assertEqual(selected.record()['repository'], repository)
            self.assertEqual(discovery.inspect_manifest(selected, fetch=lambda *_: data)['version'], ALPHA)
        for url in [NEW.replace('Couch-OS/couch', repository) + ALPHA + '/' + name for repository in LOOKALIKES] + [
                NEW + DEV + '/' + name, NEW + ALPHA + '/other.json', NEW.replace('https:', 'http:') + ALPHA + '/' + name]:
            with self.subTest(url=url):
                release['assets'][0]['browser_download_url'] = url
                with self.assertRaises(InstallError): discovery.selections([release], 'alpha')

    def test_manifest_file_urls_accept_either_couch_name_and_no_other_owner(self):
        release, data = fixture()
        release['assets'][0]['browser_download_url'] = NEW + ALPHA + '/' + release['assets'][0]['name']
        name = f'couch-installer-{ALPHA}-linux-x86_64.tar.gz'
        def inspect(url):
            metadata = json.loads(data)
            metadata['files'] = [{'name': name, 'size': 1024, 'sha256': 'a' * 64, 'url': url}]
            encoded = json.dumps(metadata).encode()
            release['assets'][0].update(size=len(encoded), digest='sha256:' + hashlib.sha256(encoded).hexdigest())
            return discovery.inspect_manifest(discovery.selections([release], 'alpha')[0], fetch=lambda *_: encoded)
        # A manifest published before the transfer still names the old owner.
        for prefix in (OLD, NEW):
            self.assertEqual(inspect(prefix + ALPHA + '/' + name)['files'][0]['name'], name)
        for repository in LOOKALIKES:
            with self.subTest(repository=repository), self.assertRaisesRegex(InstallError, 'file URL'):
                inspect(NEW.replace('Couch-OS/couch', repository) + ALPHA + '/' + name)

    def test_redirects_follow_the_transfer_to_release_assets_only(self):
        handler = discovery.MetadataRedirects()
        def follows(source, target):
            try:
                return handler.redirect_request(Request(source), None, 301, 'Moved', {}, target).full_url == target
            except InstallError:
                return False
        asset = ALPHA + '/couch-' + ALPHA + '-sanytron-ha100.json'
        storage = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sig=x'
        listing = '?per_page=100&page=2'
        self.assertEqual(discovery.API, 'https://api.github.com/repos/dangerouslaser/couch/releases')
        for source, target in ((OLD + asset, NEW + asset), (NEW + asset, storage), (OLD + asset, storage),
                               (discovery.API + listing,
                                'https://api.github.com/repositories/1363054496/releases' + listing)):
            with self.subTest(source=source, target=target):
                self.assertTrue(follows(source, target))
        refused = [(OLD + asset, NEW.replace('Couch-OS/couch', repository) + asset) for repository in LOOKALIKES]
        refused += [(OLD + asset, NEW + DEV + '/couch-' + DEV + '-sanytron-ha100.json'),
                    (OLD + asset, OLD + asset), (OLD + asset, NEW.replace('https:', 'http:') + asset),
                    (OLD + asset, storage.replace('https:', 'http:')), (OLD + asset, 'https://example.com/' + asset),
                    ('https://github.com/other/couch/releases/download/' + asset, NEW + asset),
                    ('https://github.com/other/couch/releases/download/' + asset, storage),
                    (storage, NEW + asset),
                    (discovery.API + listing, 'https://api.github.com/repositories/1/releases' + listing),
                    (discovery.API + listing, 'https://api.github.com/repositories/1363054496/releases?per_page=100&page=1'),
                    (discovery.API + listing, 'https://api.github.com/repos/Couch-OS/couch/releases' + listing),
                    (discovery.API + listing, NEW + asset)]
        for source, target in refused:
            with self.subTest(source=source, target=target):
                self.assertFalse(follows(source, target))

    def test_metadata_origins_are_the_couch_api_or_either_couch_download_name(self):
        asset = ALPHA + '/couch-' + ALPHA + '-sanytron-ha100.json'
        with patch.object(discovery, 'build_opener') as opener:
            for url in [NEW.replace('Couch-OS/couch', repository) + asset for repository in LOOKALIKES] + [
                    'https://api.github.com/repos/Couch-OS/couch/releases?page=1',
                    'https://api.github.com/repositories/1363054496/releases?page=1']:
                with self.subTest(url=url), self.assertRaisesRegex(InstallError, 'origin'):
                    discovery.fetch_bytes(url, 1)
            opener.assert_not_called()
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{}'
            for url in (OLD + asset, NEW + asset, discovery.API + '?page=1'):
                self.assertEqual(discovery.fetch_bytes(url, 2), b'{}')

    def test_selection_is_frozen_and_changed_manifest_rejected(self):
        release, data = fixture()
        selected = discovery.selections([release], 'alpha')[0]
        self.assertFalse(selected.record()['installation_authorized'])
        with self.assertRaises(AttributeError): selected.tag = 'latest'
        with self.assertRaisesRegex(InstallError, 'changed'):
            discovery.inspect_manifest(selected, fetch=lambda *_: data + b' ')
        self.assertEqual(discovery.inspect_manifest(selected, fetch=lambda *_: data)['files'], [])

    def test_manifest_model_version_file_paths_and_empty_installable(self):
        for field, value in [('model', 'other'), ('version', 'v9.9.9'), ('installable', True),
                             ('files', [{'name': '../payload'}])]:
            release, data = fixture()
            metadata = json.loads(data)
            metadata[field] = value
            data = json.dumps(metadata).encode()
            release['assets'][0].update(size=len(data), digest='sha256:' + hashlib.sha256(data).hexdigest())
            selected = discovery.selections([release], 'alpha')[0]
            with self.assertRaises(InstallError): discovery.inspect_manifest(selected, fetch=lambda *_: data)

    def test_manifest_valid_versioned_file_metadata_still_not_authorization(self):
        release, data = fixture()
        metadata = json.loads(data)
        name = f'couch-installer-{ALPHA}-linux-x86_64.tar.gz'
        metadata['files'] = [{'name': name, 'size': 1024, 'sha256': 'a'*64,
                              'url': discovery.DOWNLOAD + metadata['version'] + '/' + name}]
        metadata['installable'] = True
        data = json.dumps(metadata).encode()
        release['assets'][0].update(size=len(data), digest='sha256:' + hashlib.sha256(data).hexdigest())
        selected = discovery.selections([release], 'alpha')[0]
        self.assertTrue(discovery.inspect_manifest(selected, fetch=lambda *_: data)['installable'])
        self.assertFalse(selected.record()['installation_authorized'])

    def test_tui_explicit_metadata_browse_does_not_prepare_or_apply_install(self):
        release, data = fixture()
        choices = discovery.selections([release], 'alpha')
        output = io.StringIO()
        terminal = couch_tui.Terminal(io.StringIO('r\nalpha\n\n1\nq\n'), output)
        adapter = couch_tui.CoreAdapter(couch_tui.parser().parse_args([]))
        with patch.object(discovery, 'discover', return_value=choices), \
             patch.object(discovery, 'inspect_manifest', return_value=json.loads(data)):
            self.assertEqual(terminal.run(adapter), 0)
        self.assertIsNone(adapter.prepared)
        self.assertEqual(terminal.release_selection, choices[0])
        self.assertIn('Public flashing remains disabled', output.getvalue())
        self.assertIn('WiFi', output.getvalue())


if __name__ == '__main__':
    unittest.main()
