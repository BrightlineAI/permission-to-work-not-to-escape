"""Bounded native resolution. Compatibility belongs to uv, safety to evaluate."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from .package_evidence import EvidenceError, PyPIEvidence, evaluate, pins
from .policy import Invalid, save
from .python_runtime import select, verify
from .workspace_policy import relative


class ResolutionError(Invalid):
    def __init__(self, outcome, message):
        self.outcome = outcome
        super().__init__(outcome + ': ' + message)


def resolver_environment(stage):
    """No ambient auth, proxy, Python/Node injection, HOME config or keyring."""
    home = stage / 'resolver-home'
    home.mkdir(exist_ok=True)
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LANG': 'C.UTF-8',
            'XDG_CONFIG_HOME': str(home), 'XDG_CACHE_HOME': str(home / 'cache'),
            'UV_NO_PROGRESS': '1', 'UV_KEYRING_PROVIDER': 'disabled',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0'}


def run_metadata(argv, *, cwd, env, capture_output, text, timeout):
    """Metadata tooling has networking but no host home or repository mount.

    The caller supplies only validated registry declarations and copied metadata.
    Builds remain disabled. This namespace never becomes an application sandbox.
    """
    from .supervisor import runtime_namespace
    stage = Path(cwd).resolve()
    executable = Path(argv[0]).resolve()
    command = runtime_namespace()
    index = command.index('--unshare-all')
    command[index:index + 1] = ['--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts']
    command += ['--bind', str(stage), '/resolution', '--chdir', '/resolution']
    if not executable.is_relative_to('/usr'):
        command += ['--ro-bind', str(executable), '/resolver']
    for path in ('/etc/resolv.conf', '/etc/ssl/certs', '/etc/hosts'):
        if Path(path).exists():
            command += ['--ro-bind', str(Path(path).resolve()), path]

    def mapped(value):
        return value.replace(str(stage), '/resolution')
    for key, value in env.items():
        command += ['--setenv', key, mapped(value)]
    command += ['--', str(executable) if executable.is_relative_to('/usr') else '/resolver',
                *(mapped(value) for value in argv[1:])]
    return subprocess.run(command, capture_output=capture_output, text=text, timeout=timeout,
                          env={'PATH': '/usr/bin:/bin'})


def metadata(root, name, inputs):
    from .onboarding import data
    relative(name)
    content = data(root / name, 8 * 1024 * 1024)
    inputs[name] = hashlib.sha256(content.encode()).hexdigest()
    if len(inputs) > 64:
        raise Invalid('Too many dependency input files')
    return content


def requirement_lines(content):
    """Logical lines only. uv still parses compatibility and hash semantics."""
    if len(content.encode()) > 8 * 1024 * 1024:
        raise Invalid('Dependency input exceeds size limit')
    pending = ''
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        pending += line[:-1] + ' ' if line.endswith('\\') else line
        if line.endswith('\\'):
            continue
        yield re.split(r'\s+#', pending, maxsplit=1)[0].strip()
        pending = ''
    if pending:
        raise Invalid('Unfinished requirements continuation')


def checked_requirement(line):
    # Hashes remain in the compiler input; do not confuse hashes with pins or
    # accept index/credential options disguised after an otherwise valid pin.
    parts = re.split(r'\s+--hash=', line)
    for value in parts[1:]:
        if not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', value):
            raise Invalid('Only explicit SHA256 requirement hashes are supported')
    try:
        requirement = Requirement(parts[0])
    except ValueError as exc:
        raise Invalid('Invalid Python dependency declaration') from exc
    if requirement.url:
        raise Invalid('Local and URL requirements need reviewed source preparation; no registry substitution')
    return requirement


def python_inputs(root, *, source=None, groups=('dev', 'test'), extras=()):
    """Read static declarations and confined includes, never execute a backend."""
    root = Path(root)
    inputs, constraints, requirements = {}, [], []
    requires_python = ''
    project_meta = None
    if (root / 'pyproject.toml').exists():
        project_meta = tomllib.loads(metadata(root, 'pyproject.toml', inputs))
        project = project_meta.get('project', {})
        if not isinstance(project, dict):
            raise Invalid('Expected a static project table')
        requires_python = project.get('requires-python', '')
    choices = [n for n in ('requirements.in', 'requirements.txt', 'pyproject.toml') if (root / n).exists()]
    if source is None:
        if 'requirements.in' in choices:
            source = 'requirements.in'  # .txt may be its generated lock.
        elif 'requirements.txt' in choices:
            source = 'requirements.txt'
        elif choices:
            source = 'pyproject.toml'
        else:
            return [], [], inputs, requires_python
        if project_meta and source != 'pyproject.toml' and project_meta.get('project', {}).get('dependencies'):
            raise Invalid('Both requirements and pyproject declare dependencies; select --python-source explicitly')
    if source == 'pyproject.toml':
        if project_meta is None:
            raise Invalid('Selected pyproject.toml is missing')
        project = project_meta.get('project', {})
        if not project or project_meta.get('tool', {}).get('poetry'):
            raise Invalid('Poetry metadata requires its native lock/export adapter')
        dynamic = project.get('dynamic', [])
        if not isinstance(dynamic, list) or any(k in dynamic for k in ('dependencies', 'optional-dependencies')):
            raise Invalid('Dynamic metadata needs explicitly approved offline source preparation')
        requirements = project.get('dependencies', [])
        optional = project.get('optional-dependencies', {})
        if not isinstance(requirements, list) or not isinstance(optional, dict):
            raise Invalid('Malformed Python dependencies')
        requirements = list(requirements)
        for extra in extras:
            if extra not in optional or not isinstance(optional[extra], list):
                raise Invalid('Unknown or malformed Python extra')
            requirements.extend(optional[extra])
        group_map = project_meta.get('dependency-groups', {})
        if not isinstance(group_map, dict):
            raise Invalid('Malformed Python dependency groups')

        def expand(group, trail):
            if group in trail or len(trail) >= 16:
                raise Invalid('Cyclic or excessive dependency group includes')
            entries = group_map.get(group)
            if not isinstance(entries, list):
                raise Invalid('Unknown or malformed dependency group: ' + group)
            for entry in entries:
                if isinstance(entry, str):
                    requirements.append(entry)
                elif isinstance(entry, dict) and set(entry) == {'include-group'} and isinstance(entry['include-group'], str):
                    expand(entry['include-group'], [*trail, group])
                else:
                    raise Invalid('Malformed dependency group entry')
                if len(requirements) > 1024:
                    raise Invalid('Too many dependency declarations')
        for group in groups:
            if group in group_map:
                expand(group, [])
            elif groups != ('dev', 'test'):
                raise Invalid('Selected dependency group is missing: ' + group)
        uv_config = project_meta.get('tool', {}).get('uv', {})
        if any(uv_config.get(k) for k in ('sources', 'index', 'override-dependencies', 'workspace')):
            raise Invalid('Configured sources/workspaces/overrides require a reviewed source adapter')
        constraints.extend(uv_config.get('constraint-dependencies', []))
    else:
        def include(name, constrained, trail):
            if name in trail or len(trail) >= 16:
                raise Invalid('Cyclic or excessive requirement includes')
            for line in requirement_lines(metadata(root, name, inputs)):
                match = re.fullmatch(r'(?:-([rc])\s*|--(requirement|constraint)(?:=|\s+))(.+)', line)
                if match:
                    child = match[3]
                    relative(child)
                    child = str(Path(name).parent / child)
                    include(child, constrained or match[1] == 'c' or match[2] == 'constraint', [*trail, name])
                else:
                    checked_requirement(line)
                    (constraints if constrained else requirements).append(line)
                if len(requirements) + len(constraints) > 1024:
                    raise Invalid('Too many dependency declarations')
        include(source, False, [])
    for line in [*requirements, *constraints]:
        if not isinstance(line, str):
            raise Invalid('Requirements must be strings')
        checked_requirement(line)
    return requirements, constraints, inputs, requires_python


def compiled_pins(content, environment):
    result = []
    for line in requirement_lines(content):
        requirement = checked_requirement(line)
        if requirement.marker and not requirement.marker.evaluate(environment):
            continue
        name = canonicalize_name(requirement.name)
        if requirement.extras:
            name += '[' + ','.join(sorted(requirement.extras)) + ']'
        result.append(name + str(requirement.specifier))
    if result:
        pins(result, extras={})
    return result


def resolve_python(root, stage, rules, *, executable=None, source=None, groups=('dev', 'test'), extras=(),
                   provider=None, runner=None, max_rounds=8, max_assessments=256, seconds=180):
    """Resolve compatible candidates, exclude confirmed violations, retain every attempt.

    Provider/runner injection is a test seam, never model-controlled configuration.
    Existing uv/Poetry locks cannot silently be replaced by a requirements export.
    """
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    attempts, outcome = [], 'invalid'
    started = time.monotonic()
    try:
        if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
                type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
                not isinstance(seconds, (int, float)) or not 0 < seconds <= 180):
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        for name in ('uv.lock', 'poetry.lock'):
            if (root / name).exists():
                raise Invalid(name + ' needs native locked export; refusing to discard the authoritative lock')
        requirements, constraints, inputs, requires_python = python_inputs(root, source=source, groups=groups, extras=extras)
        version_request = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        runtime = select(requires_python, executable, version_request)
        from .package_install import target_environment
        environment = target_environment(runtime['executable'])
        if not requirements:
            outcome = 'resolved'
            return {'pins': [], 'runtime': runtime, 'inputs': inputs, 'artifacts': [], 'attempts': []}
        uv = shutil.which('uv')
        if not uv:
            raise Invalid('uv is required; no resolver fallback')
        save(stage / 'resolver-tool.json', {'path': str(Path(uv).resolve()),
            'sha256': hashlib.sha256(Path(uv).read_bytes()).hexdigest(), 'runtime': runtime,
            'inputs': inputs, 'cutoff_policy': rules})
        runner = runner or run_metadata
        provider = provider or PyPIEvidence(native=rules.get('allow_native_wheels', False),
                                           python=runtime['executable'])
        source_path, output = stage / 'requirements.in', stage / 'resolved.txt'
        source_path.write_text('\n'.join(requirements) + '\n')
        # Output pins are preferences, never hard constraints on unrelated versions.
        previous = root / 'ptw-requirements.txt'
        if previous.exists():
            output.write_text(metadata(root, previous.name, inputs))
        cutoff = datetime.fromtimestamp(time.time() - rules['min_release_age_days'] * 86400, timezone.utc).isoformat()
        env = resolver_environment(stage)
        excluded, cache = set(), {}
        for index in range(max_rounds):
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'resolver deadline reached')
            constraint_path = stage / 'constraints.txt'
            constraint_path.write_text('\n'.join([*constraints, *(n + '!=' + v for n, v in sorted(excluded))]) + '\n')
            argv = [uv, '--no-config', '--no-python-downloads', '--cache-dir', str(stage / 'cache'),
                    'pip', 'compile', '--no-build', '--no-sources', '--python', runtime['executable'],
                    '--index-url', 'https://pypi.org/simple', '--exclude-newer', cutoff,
                    '--no-annotate', '--no-header', '--no-strip-extras',
                    '--constraint', str(constraint_path), str(source_path), '--output-file', str(output)]
            attempt = {'round': index + 1, 'excluded': sorted([list(x) for x in excluded]), 'outcome': 'running'}
            attempts.append(attempt)
            try:
                proc = runner(argv, cwd=stage, env=env, capture_output=True, text=True, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                attempt['outcome'] = 'timeout'
                raise ResolutionError('budget_exhausted', 'native resolver timed out') from exc
            attempt['returncode'] = proc.returncode
            if proc.returncode:
                # uv uses the same status for transport and constraint errors.
                # Only its explicit solver diagnostic establishes a conflict.
                conflict = proc.returncode == 1 and 'No solution found' in proc.stderr
                attempt['outcome'] = 'unsatisfiable' if conflict else 'unavailable'
                attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
                attempt['failure_category'] = ('sandbox_permission' if any(s in proc.stderr for s in
                    ('Operation not permitted', 'Permission denied')) else
                    'network' if any(s in proc.stderr.lower() for s in ('dns', 'connect', 'network')) else
                    'solver' if conflict else 'tool_failure')
                raise ResolutionError(attempt['outcome'], 'native uv could not resolve the original declarations with policy constraints')
            resolved = compiled_pins(output.read_text(), environment)
            selected = pins(resolved, extras={}) if resolved else {}
            artifact_hashes = {}
            for line in [*requirements, *constraints]:
                declaration = checked_requirement(line)
                if declaration.marker and not declaration.marker.evaluate(environment):
                    continue
                name = canonicalize_name(declaration.name)
                if name in selected and not declaration.specifier.contains(selected[name], prereleases=True):
                    raise Invalid('Native output violates an original dependency constraint')
                if line in requirements and name not in selected:
                    raise Invalid('Native output omitted a required dependency')
                hashes = set(re.findall(r'--hash=sha256:([0-9a-fA-F]{64})', line))
                if hashes:
                    hashes = {h.lower() for h in hashes}
                    artifact_hashes[name] = artifact_hashes.get(name, hashes) & hashes
            attempt['pins'] = selected
            rejected, records = set(), []
            for name, version in selected.items():
                key = name, version
                if key not in cache:
                    if len(cache) >= max_assessments:
                        raise ResolutionError('budget_exhausted', 'candidate assessment limit reached')
                    if time.monotonic() - started >= seconds:
                        raise ResolutionError('budget_exhausted', 'candidate assessment deadline reached')
                    cache[key] = provider.assess(name, version)
                    if time.monotonic() - started >= seconds:
                        raise ResolutionError('budget_exhausted', 'candidate evidence exceeded the deadline')
                record = cache[key]
                if record.get('name') != name or record.get('version') != version:
                    raise EvidenceError('Candidate evidence identity mismatch')
                if name in artifact_hashes and record.get('sha256') not in artifact_hashes[name]:
                    raise EvidenceError('Selected artifact does not satisfy the original requirement hashes')
                if evaluate(record, rules):
                    rejected.add(key)
                records.append(record)
            attempt['rejected'] = sorted([list(x) for x in rejected])
            if not rejected:
                verify(runtime)
                attempt['outcome'] = outcome = 'resolved'
                return {'pins': resolved, 'runtime': runtime, 'inputs': inputs,
                        'artifacts': [{k: e[k] for k in ('name', 'version', 'url', 'sha256')} for e in records],
                        'attempts': attempts}
            attempt['outcome'] = 'policy_exclusion'
            if rejected <= excluded:
                raise ResolutionError('unsatisfiable', 'native resolver retained an excluded candidate')
            excluded |= rejected
        raise ResolutionError('budget_exhausted', 'candidate retry limit reached')
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', {'outcome': outcome, 'attempts': attempts,
                                        'elapsed_seconds': time.monotonic() - started})
