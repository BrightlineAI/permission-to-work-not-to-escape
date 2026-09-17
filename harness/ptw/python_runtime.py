"""Identify an installed system Python without importing project or user code."""
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess

from packaging.specifiers import SpecifierSet

from .policy import Invalid


def identify(executable):
    path = Path(executable).resolve(strict=True)
    # runtime_namespace already mounts /usr. Never turn an arbitrary PATH entry
    # or repository interpreter into an implicit directory mount.
    if (not path.is_relative_to('/usr') or not path.is_file() or
            not re.fullmatch(r'python3(?:\.[0-9]+)?', path.name)):
        raise Invalid('Python must be an operator provisioned interpreter under /usr')
    try:
        result = subprocess.run([str(path), '-I', '-S', '-c',
            "import json,platform,sys,sysconfig; print(json.dumps(dict("
            "version=platform.python_version(), implementation=sys.implementation.name, "
            "abi=sysconfig.get_config_var('SOABI'), prefix=sys.base_prefix)))"],
            capture_output=True, text=True, timeout=10, check=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        info = json.loads(result.stdout)
        if (set(info) != {'version', 'implementation', 'abi', 'prefix'} or
                not all(isinstance(v, str) for v in info.values()) or
                not Path(info['prefix']).resolve().is_relative_to('/usr')):
            raise ValueError('runtime outside system namespace')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise Invalid('Cannot identify the selected Python runtime') from exc
    return {'executable': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), **info}


def version_constraint(request):
    if not re.fullmatch(r'3\.[0-9]+(?:\.[0-9]+)?', request):
        raise Invalid('.python-version must request one CPython 3.x version, not a path or download')
    return SpecifierSet('==' + request + ('.*' if request.count('.') == 1 else ''))


def select(requirement='', executable=None, version_request=None):
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
            runtime = identify(candidate)
        except (Invalid, OSError):
            if executable:
                raise Invalid('Selected Python is unavailable or outside the supported system runtime layout')
            continue
        if (spec.contains(runtime['version'], prereleases=True) and
                (version_request is None or version_constraint(version_request).contains(runtime['version']))):
            return {**runtime, 'requires_python': requirement,
                    **({'version_request': version_request} if version_request is not None else {})}
    raise Invalid('No installed system Python satisfies requires-python ' + repr(requirement) +
                  '; provision a compatible interpreter and select it with --python')


def verify(runtime):
    current = identify(runtime['executable'])
    if current != {k: v for k, v in runtime.items() if k not in ('requires_python', 'version_request')}:
        raise Invalid('Reviewed Python runtime changed; review the new runtime before reuse')
    if not SpecifierSet(runtime['requires_python']).contains(current['version'], prereleases=True):
        raise Invalid('Reviewed Python runtime is incompatible with requires-python')
    if 'version_request' in runtime and not version_constraint(runtime['version_request']).contains(current['version']):
        raise Invalid('Reviewed Python runtime differs from the requested .python-version')
    return current['executable']
