"""Pinned native export program executed only in the offline tool namespace."""
import hashlib
import json

from .dependency_resolution import ResolutionError, metadata
from .policy import Invalid
from .python_runtime import select


INSPECT = r'''
import json
from pathlib import Path
from poetry.factory import Factory
from poetry.core.constraints.version import Version

poetry = Factory().create_poetry(Path.cwd(), disable_plugins=True)
# The manifest, not the untrusted lock's python-versions field, owns this
# constraint. Flatten using Poetry's parser, without translating its syntax.
ranges = [('==' + str(r)) if isinstance(r, Version) else
          '' if r.is_any() else str(r)
          for r in poetry.package.python_constraint.flatten()]
Path('project-selection.json').write_text(json.dumps(dict(
    python_ranges=ranges, groups=sorted(poetry.package.dependency_group_names(include_optional=True)))))
'''


def selection(stage, *, executable=None, version_request=None, timeout=30, directory=None):
    """Select a system runtime from native manifest ranges and discover groups.

    The runtime records its compatible PEP 440 range. The full original Poetry
    constraint remains bound by the authoritative manifest hash and is checked
    again by native export/solving. Union branches never become a custom solver.
    """
    from .poetry_tool import run
    result = run(INSPECT, {}, cwd=stage, timeout=timeout, directory=directory)
    if result.returncode:
        raise ResolutionError('unavailable', 'Native Poetry manifest inspection failed; stderr_sha256=' +
                              hashlib.sha256(result.stderr.encode()).hexdigest())
    value = json.loads(metadata(stage, 'project-selection.json', {}))
    if (not isinstance(value, dict) or set(value) != {'python_ranges', 'groups'} or
            any(not isinstance(value[k], list) or len(value[k]) > 1024 or
                any(not isinstance(v, str) for v in value[k]) for k in value)):
        raise Invalid('Malformed native Poetry project selection')
    for requirement in value['python_ranges']:
        try:
            return select(requirement, executable, version_request), value['groups']
        except Invalid:
            continue
    raise ResolutionError('unavailable', 'No installed system Python satisfies the Poetry manifest; '
                          'provision a compatible interpreter and select it with --python')

EXPORT = r'''
import json
from pathlib import Path
from cleo.io.null_io import NullIO
from poetry.factory import Factory
from poetry.core.constraints.version import Version
from poetry_plugin_export.exporter import Exporter

config = json.loads(__import__('sys').argv[1])
poetry = Factory().create_poetry(Path.cwd(), disable_plugins=True)
if not poetry.locker.is_locked() or not poetry.locker.is_fresh():
    raise ValueError('stale Poetry lock')
runtime = Version.parse(config['runtime']['version'])
if not poetry.package.python_constraint.allows(runtime):
    raise ValueError('project Python constraint excludes reviewed runtime')
groups = config['groups']
extras = config['extras']
if any(not poetry.package.has_dependency_group(g) for g in groups):
    raise ValueError('unknown Poetry group')
if any(e not in poetry.package.extras for e in extras):
    raise ValueError('unknown Poetry extra')
root = poetry.package.with_dependency_groups(groups, only=True)
# Preserve native constraint and marker semantics. No project backend is loaded.
declarations = [d.to_pep_508() for d in root.all_requires
                if not d.is_optional() or set(d.in_extras).intersection(extras)]
Exporter(poetry, NullIO()).only_groups(groups).with_extras(extras).with_hashes(True).export(
    'requirements.txt', Path.cwd(), 'exported.txt')
Path('declarations.json').write_text(json.dumps(declarations))
'''
