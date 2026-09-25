"""Identify an installed system Python without importing project or user code."""
import json
import re
from pathlib import Path
import shutil
import subprocess

from packaging.specifiers import SpecifierSet
from packaging.markers import default_environment

from .policy import Invalid, file_sha256


# Shared with the standalone marker probe; implementation versions can differ
# from language versions and must retain prerelease suffixes.
MARKER_PROBE = (
    "import sys,platform; v=sys.implementation.version; "
    "iv=f'{v.major}.{v.minor}.{v.micro}'; "
    "iv += '' if v.releaselevel == 'final' else "
    "{'alpha':'a','beta':'b','candidate':'rc'}[v.releaselevel]+str(v.serial); "
    "markers=dict(python_version='.'.join(map(str,sys.version_info[:2])), "
    "python_full_version=platform.python_version(), implementation_name=sys.implementation.name, "
    "implementation_version=iv, platform_python_implementation=platform.python_implementation()); "
)
MARKER_FIELDS = frozenset(('python_version', 'python_full_version', 'implementation_name',
                           'implementation_version', 'platform_python_implementation'))


def marker_environment(markers):
    if (not isinstance(markers, dict) or set(markers) != MARKER_FIELDS or
            not all(isinstance(v, str) and v for v in markers.values())):
        raise ValueError('Invalid interpreter marker fields')
    return {**default_environment(), **markers, 'extra': ''}


def identify(executable, *, with_environment=False):
    path = Path(executable).resolve(strict=True)
    # runtime_namespace already mounts /usr. Never turn an arbitrary PATH entry
    # or repository interpreter into an implicit directory mount.
    if (not path.is_relative_to('/usr') or not path.is_file() or
            not re.fullmatch(r'python3(?:\.[0-9]+)?', path.name)):
        raise Invalid('Python must be an operator provisioned interpreter under /usr')
    try:
        fields = ("version=platform.python_version(), implementation=sys.implementation.name, "
                  "abi=sysconfig.get_config_var('SOABI'), prefix=sys.base_prefix")
        # Keep the identity-only command stable for offline evidence verifiers
        # that permit exactly this isolated subprocess and no other launches.
        script = "import json,platform,sys,sysconfig; print(json.dumps(dict(" + fields + ")))"
        if with_environment:
            script = ("import json,platform,sys,sysconfig; info=dict(" + fields + "); " +
                      MARKER_PROBE + "info['markers']=markers; print(json.dumps(info))")
        result = subprocess.run([str(path), '-I', '-S', '-c', script],
            capture_output=True, text=True, timeout=5 if with_environment else 10, check=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        info = json.loads(result.stdout)
        environment = marker_environment(info.pop('markers')) if with_environment else None
        if (set(info) != {'version', 'implementation', 'abi', 'prefix'} or
                not all(isinstance(v, str) for v in info.values()) or
                not Path(info['prefix']).resolve().is_relative_to('/usr')):
            raise ValueError('runtime outside system namespace')
        if with_environment and (environment['python_full_version'] != info['version'] or
                                 environment['implementation_name'] != info['implementation']):
            raise ValueError('inconsistent interpreter marker fields')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        raise Invalid('Cannot identify the selected Python runtime') from exc
    runtime = {'executable': str(path), 'sha256': file_sha256(path), **info}
    return (runtime, environment) if with_environment else runtime


def version_constraint(request):
    if not re.fullmatch(r'3\.[0-9]+(?:\.[0-9]+)?', request):
        raise Invalid('.python-version must request one CPython 3.x version, not a path or download')
    return SpecifierSet('==' + request + ('.*' if request.count('.') == 1 else ''))


def select(requirement='', executable=None, version_request=None, *, with_environment=False):
    """Repository requirements constrain selection, never select executable paths."""
    if not isinstance(requirement, str):
        raise Invalid('requires-python must be a string')
    if version_request is not None:
        version_constraint(version_request)
    try:
        spec = SpecifierSet(requirement)
    except (TypeError, ValueError) as exc:
        raise Invalid('Invalid requires-python declaration') from exc
    candidates = [executable] if executable else [shutil.which('python3'), *(
        str(p) for p in sorted(Path('/usr/bin').glob('python3.[0-9]*'), reverse=True)
        if p.name.removeprefix('python3.').isdigit())]
    checked = set()
    for candidate in candidates:
        if not candidate or candidate in checked:
            continue
        checked.add(candidate)
        try:
            identified = identify(candidate, with_environment=True) if with_environment else identify(candidate)
            runtime, environment = identified if with_environment else (identified, None)
        except (Invalid, OSError):
            if executable:
                raise Invalid('Selected Python is unavailable or outside the supported system runtime layout')
            continue
        if (spec.contains(runtime['version'], prereleases=True) and
                (version_request is None or version_constraint(version_request).contains(runtime['version']))):
            selected = {**runtime, 'requires_python': requirement,
                        **({'version_request': version_request} if version_request is not None else {})}
            return (selected, environment) if with_environment else selected
    raise Invalid('No installed system Python satisfies requires-python ' + repr(requirement) +
                  '; provision a compatible interpreter and select it with --python')


def verify(runtime, *, with_environment=False):
    identified = (identify(runtime['executable'], with_environment=True) if with_environment
                  else identify(runtime['executable']))
    current, environment = identified if with_environment else (identified, None)
    if current != {k: v for k, v in runtime.items() if k not in ('requires_python', 'version_request')}:
        raise Invalid('Reviewed Python runtime changed; review the new runtime before reuse')
    if not SpecifierSet(runtime['requires_python']).contains(current['version'], prereleases=True):
        raise Invalid('Reviewed Python runtime is incompatible with requires-python')
    if 'version_request' in runtime and not version_constraint(runtime['version_request']).contains(current['version']):
        raise Invalid('Reviewed Python runtime differs from the requested .python-version')
    return (current['executable'], environment) if with_environment else current['executable']
