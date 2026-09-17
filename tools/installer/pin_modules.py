"""Load the canonical pin helpers from ``pins/`` by file path for tests.

The helpers import their siblings by plain module name (``official_runtime``
imports ``private_vendor``), exactly as they do when run from the pins directory
or copied beside the native worker. Each dependency is registered under that
name before its dependant runs, so tests patch the same module objects the
helpers use. No copy or compatibility shim sits in between.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
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
