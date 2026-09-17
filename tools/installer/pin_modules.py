"""Load the canonical pin helpers from ``pins/`` by file path for tests.

The helpers import their siblings by plain module name (``official_runtime``
imports ``private_vendor``), exactly as they do when run from the pins directory
or copied beside the native worker. Each dependency is registered under that
name before its dependant runs, so tests patch the same module objects the
helpers use. No copy or compatibility shim sits in between.

``nested_checkouts`` builds the Git submodule layout that the owner output
guards must see through.
"""
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import subprocess
import sys

PINS = Path(__file__).resolve().parent / 'pins'
DEPENDENCIES = {
    'official_runtime': ('private_vendor',),
    'prepare_official_inputs': ('private_vendor', 'official_runtime'),
    'firmware_restore': ('private_vendor', 'official_runtime', 'prepare_official_inputs'),
}


def load(name):
    """Return one canonical pin helper, loading the siblings it imports first."""
    source = PINS / (name + '.py')
    if not source.is_file():
        raise ValueError('unknown installer pin helper: ' + name)
    loaded = sys.modules.get(name)
    if loaded is not None and Path(getattr(loaded, '__file__', '') or '').resolve() == source:
        return loaded
    for dependency in DEPENDENCIES.get(name, ()):
        load(dependency)
    spec = spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise ImportError('installer pin helper is unavailable: ' + name)
    module = module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def nested_checkouts(root):
    """Create outer/middle/installer, each checkout a gitlink in its parent's index.

    Returns the checkout roots innermost first, with an installer-layout pins
    directory in the innermost one. No network, remote or hooks are involved.
    """
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    outer = Path(root).resolve() / 'outer'

    def git(directory, *words):
        # Neutralize user configuration that would sign, prompt or run hooks.
        command = ['git', '-C', str(directory), '-c', 'user.name=Fixture',
                   '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                   '-c', 'core.hooksPath=' + str(Path(root).resolve() / 'no-hooks'), *words]
        return subprocess.run(command, check=True, capture_output=True, text=True,
                              timeout=30, env=environment).stdout.strip()

    chain = [outer, outer / 'middle', outer / 'middle' / 'installer']
    for directory in chain:
        directory.mkdir()
        git(directory, 'init', '-q')
    (chain[-1] / 'tools' / 'installer' / 'pins').mkdir(parents=True)
    for parent, child in zip(chain, chain[1:]):
        git(child, 'commit', '-q', '--allow-empty', '-m', 'fixture')
        commit = git(child, 'rev-parse', 'HEAD')
        git(parent, 'update-index', '--add', '--cacheinfo', f'160000,{commit},{child.name}')
    return chain[::-1]
