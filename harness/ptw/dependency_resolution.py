"""Bounded native resolution. Compatibility belongs to uv, safety to evaluate."""
from datetime import datetime, timezone
from contextlib import nullcontext
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


METADATA_HOST_PATHS = ('/etc/resolv.conf', '/etc/ssl/certs', '/etc/hosts')


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


def resolver_failure_signals(stderr):
    """Fixed diagnostic labels only; native output can contain upstream secrets.

    These are observations for debugging, never evidence of a policy violation.
    Keep the raw output out of receipts and user-facing exceptions.
    """
    message = stderr[:65536].lower()
    patterns = {
        'argument': ('unexpected argument', 'unrecognized option', 'invalid value', 'cannot be used with'),
        'permission': ('operation not permitted', 'permission denied'),
        'read_only': ('read-only file system',),
        'missing_path': ('no such file or directory', 'not found at'),
        'interpreter': ('failed to query python', 'python interpreter not found',
                        'failed to identify base python interpreter', 'querying python at',
                        'no interpreter found'),
        'network': ('dns', 'connect', 'network'),
        'http_method': ('unsupported method', '501 not implemented'),
        'http_status': ('client error', 'server error', 'status code'),
        'metadata': ('deserialize', 'parse', 'invalid metadata', 'missing field'),
        'backend': ('build backend', 'build_wheel', 'build_editable', 'prepare_metadata_for_build'),
        'backend_import': ('modulenotfounderror', 'importerror'),
        'backend_assertion': ('assertionerror',),
        'build_disabled': ('building source distributions is disabled', 'building is disabled',
                           'marked as `--no-build`', 'marked as `--no-build-package`'),
        'offline_cache': ('not found in the cache', 'not available in the cache', 'network connectivity is disabled'),
        'timeout': ('ptw_offline_lock_error=timeout',),
        'launch': ('ptw_offline_lock_error=launch',),
        'lock_stale': ('the lockfile at `uv.lock` needs to be updated',),
        'archive': ('zip', 'central directory'),
        'range_request': ('range request', 'range header'),
        'solver': ('no solution found',),
        'panic': ('panicked',),
    }
    return sorted(key for key, values in patterns.items() if any(v in message for v in values))


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
    for path in METADATA_HOST_PATHS:
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


def optional_dependencies(project, extras=(), *, discovery=False):
    """Validate and normalize optional declarations without executing project code."""
    optional = project.get('optional-dependencies', {})
    if not isinstance(optional, dict) or not isinstance(extras, (list, tuple)):
        raise Invalid('Malformed Python optional dependencies or extra selection')
    if discovery and 'optional-dependencies' in project.get('dynamic', []):
        # Names remain requests until the approved backend supplies metadata.
        # Validate their syntax now, and require actual membership after discovery.
        optional = {e: [] for e in extras if isinstance(e, str)}
    result = {}
    try:
        for name, values in optional.items():
            key = canonicalize_name(name, validate=True)
            if key in result or not isinstance(values, list):
                raise Invalid('Ambiguous or malformed Python extra')
            for value in values:
                checked_requirement(value)
            result[key] = values
        selected = [canonicalize_name(e, validate=True) for e in extras]
    except (TypeError, ValueError) as exc:
        raise Invalid('Invalid Python extra name or requirement') from exc
    if len(selected) != len(set(selected)) or not set(selected) <= result.keys():
        raise Invalid('Unknown or duplicate Python extra')
    return result, selected


def expand_local_requirements(project, requirements, environment):
    """Expand references to this reviewed distribution, never a registry namesake."""
    optional, _ = optional_dependencies(project)
    name = canonicalize_name(project['name'], validate=True)
    pending, expanded, result = list(requirements), set(), []
    for raw in pending:
        if len(pending) > 1024:
            raise Invalid('Too many local dependency declarations')
        req = checked_requirement(raw)
        if canonicalize_name(req.name) != name:
            result.append(raw)
            continue
        if req.marker and not req.marker.evaluate({**environment, 'extra': ''}):
            continue
        version = project.get('version')
        if not version or not req.specifier.contains(version, prereleases=True):
            raise Invalid('Self-referencing requirement conflicts with reviewed local version')
        extras = {canonicalize_name(e) for e in req.extras}
        if not extras <= optional.keys():
            raise Invalid('Unknown self-referencing local extra')
        for extra in sorted(extras - expanded):
            expanded.add(extra)
            pending.extend(optional[extra])
    return result


def python_inputs(root, *, source=None, groups=('dev', 'test'), extras=(), dynamic_metadata=None, discovery=False,
                  local_mode=None, local_projects=None):
    """Read static declarations and confined includes, never execute a backend."""
    root = Path(root)
    if local_mode not in (None, 'editable', 'wheel'):
        raise Invalid('Invalid local Python installation mode')
    inputs, constraints, requirements = {}, [], []
    requires_python = ''
    project_meta = None
    if (root / 'pyproject.toml').exists():
        project_meta = tomllib.loads(metadata(root, 'pyproject.toml', inputs))
        project = project_meta.get('project', {})
        if not isinstance(project, dict):
            raise Invalid('Expected a static project table')
        if discovery or dynamic_metadata is not None:
            from .python_local import project_metadata
            entries = {'pyproject.toml': {'data': metadata(root, 'pyproject.toml', inputs).encode()}}
            project, _ = project_metadata(entries, '', dynamic_metadata, discovery=discovery)
            project_meta = {**project_meta, 'project': project}
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
        if not isinstance(dynamic, list) or (not discovery and dynamic_metadata is None and
                any(k in dynamic for k in ('dependencies', 'optional-dependencies'))):
            raise Invalid('Dynamic metadata needs explicitly approved offline source preparation')
        requirements = project.get('dependencies', [])
        optional, selected_extras = optional_dependencies(project, extras, discovery=discovery)
        if not isinstance(requirements, list):
            raise Invalid('Malformed Python dependencies')
        requirements = list(requirements)
        for extra in selected_extras:
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
        local_entries = []

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
                    # Interpret only a reference to the already selected Python
                    # root. Never pass local paths to the metadata resolver, where
                    # uv may execute first-party code even with --no-build.
                    from .python_projects import local_requirement
                    local = local_requirement(line)
                    if local:
                        path, mode, requested = local
                        if local_projects is not None:
                            if constrained:
                                raise Invalid('Local installation cannot be introduced through constraints')
                            if any(p['path'] == path for p in local_projects):
                                raise Invalid('Duplicate local project requirement')
                            local_projects.append(dict(path=path, mode=mode, extras=requested))
                            if len(local_projects) > 64:
                                raise Invalid('Too many local project requirements')
                            continue
                        if path:
                            raise Invalid('Local directory requirements need reviewed multi-project preparation')
                        if constrained or local_mode != mode:
                            raise Invalid('Local requirements need matching explicit --python-editable or --python-wheel approval; not a constraint')
                        if local_entries:
                            raise Invalid('Duplicate local project requirement')
                        if project_meta is None:
                            raise Invalid('Local requirement needs a bound pyproject.toml')
                        _, selected = optional_dependencies(project_meta['project'], extras, discovery=discovery)
                        _, required = optional_dependencies(project_meta['project'], requested, discovery=discovery)
                        if not set(required) <= set(selected):
                            raise Invalid('Local requirement extras must be explicitly selected with --python-extras')
                        local_entries.append(line)
                    else:
                        checked_requirement(line)
                        (constraints if constrained else requirements).append(line)
                if len(requirements) + len(constraints) > 1024:
                    raise Invalid('Too many dependency declarations')
        include(source, False, [])
        if local_projects is None and local_mode is not None and not local_entries:
            raise Invalid('Local preparation with requirements authority needs an explicit root entry')
        if local_entries:
            local_requirements, local_constraints, local_inputs, _ = python_inputs(
                root, source='pyproject.toml', groups=groups, extras=extras,
                dynamic_metadata=dynamic_metadata, discovery=discovery)
            requirements.extend(local_requirements)
            constraints.extend(local_constraints)
            inputs.update(local_inputs)
            if len(requirements) + len(constraints) > 1024 or len(inputs) > 64:
                raise Invalid('Too many local dependency declarations or inputs')
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
                   provider=None, runner=None, max_rounds=8, max_assessments=256, seconds=180, registry_config=None,
                   local_build=False, dynamic_metadata=None, discovery=False, build_requirements=None, local_mode=None,
                   build_only=False):
    """Resolve compatible candidates, exclude confirmed violations, retain every attempt.

    Provider/runner injection is a test seam, never model-controlled configuration.
    Existing uv/Poetry locks cannot silently be replaced by a requirements export.
    """
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    attempts, outcome = [], 'invalid'
    started = time.monotonic()
    locked_plan = None
    lock_binding = {}
    try:
        if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
                type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
                not isinstance(seconds, (int, float)) or not 0 < seconds <= 180):
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        if build_requirements is not None and not local_build:
            raise Invalid('Backend requirements require reviewed local preparation')
        if build_only and not local_build:
            raise Invalid('Build-only resolution requires reviewed local preparation')
        if local_mode is not None and not local_build:
            raise Invalid('Local requirements require reviewed local preparation')
        if any((root / name).exists() for name in ('uv.lock', 'poetry.lock')):
            if local_build and (root / 'poetry.lock').exists():
                raise Invalid('Local setup with native locks still needs build-requirement integration')
            if registry_config is not None or getattr(provider, 'routes', None):
                raise Invalid('Private Python native locks require a reviewed source adapter; use explicit requirements or static PEP 621 authority')
            from .python_lock import export_lock
            candidate_only = local_build and (discovery or dynamic_metadata is not None)
            result = export_lock(root, stage / 'native-lock', rules, executable=executable,
                source=source, groups=groups, extras=extras, provider=provider, runner=runner, seconds=seconds,
                max_assessments=max_assessments, candidate_only=candidate_only)
            if not local_build:
                outcome = 'resolved'
                return result
            # Frozen candidates are assessment data, never a freshness claim.
            # Dynamic sources require approved offline validation at installation.
            locked_plan = result
            lock_binding = ({'candidate_lock': result['candidate_lock'], 'validation': 'candidate-only'}
                            if candidate_only else {'authority': result['authority']})
            source = 'pyproject.toml'
        if (discovery or dynamic_metadata is not None) and not local_build:
            raise Invalid('Dynamic values require explicitly reviewed local preparation')
        requirements, constraints, inputs, requires_python = python_inputs(
            root, source=source, groups=groups, extras=extras, dynamic_metadata=dynamic_metadata, discovery=discovery,
            local_mode=local_mode)
        if locked_plan is not None:
            if any(inputs.get(name) != value for name, value in locked_plan['inputs'].items()
                   if name in inputs):
                raise Invalid('Local metadata changed during locked export')
            inputs.update(locked_plan['inputs'])
            # Keep every selected transitive dependency, including its artifact
            # identity, while allowing uv to resolve additional build tools.
            locked_requirements = [r['name'] + '==' + r['version'] + ' --hash=sha256:' + r['sha256']
                                   for r in locked_plan['artifacts']]
            if not discovery:
                requirements.extend(locked_requirements)
                constraints.extend(locked_requirements)
        if local_build:
            config = tomllib.loads(metadata(root, 'pyproject.toml', inputs))
            local_project = {**config.get('project', {}), **(dynamic_metadata or {})}
            local_name = canonicalize_name(local_project.get('name', ''), validate=True)
            build_system = config.get('build-system')
            if not isinstance(build_system, dict):
                raise Invalid('Local preparation requires a build-system table')
            build = build_system.get('requires')
            if not isinstance(build, list) or not all(isinstance(r, str) for r in build):
                raise Invalid('Local preparation requires explicit build-system.requires')
            for raw in build:
                if canonicalize_name(checked_requirement(raw).name) == local_name:
                    raise Invalid('Build requirement cannot resolve the local project from a registry')
            if build_requirements is not None:
                from .python_local import checked_hook_requirements
                build = build + checked_hook_requirements(build_requirements, local_name)
            if len(requirements) > 1024:
                raise Invalid('Too many local build and runtime requirements')
        version_request = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        runtime = select(requires_python, executable, version_request)
        # Discovered requires-python can refine the constraint description,
        # but cannot silently select a different interpreter for the locked graph.
        if locked_plan is not None and {k: v for k, v in runtime.items() if k != 'requires_python'} != {
                k: v for k, v in locked_plan['runtime'].items() if k != 'requires_python'}:
            raise Invalid('Local runtime changed during locked export')
        from .package_install import target_environment
        environment = target_environment(runtime['executable'])
        if local_build:
            local_constraints = [r for r in constraints
                                 if canonicalize_name(checked_requirement(r).name) == local_name]
            if any(checked_requirement(r).extras for r in local_constraints):
                raise Invalid('Local version constraints cannot request extras')
            if not discovery:
                expand_local_requirements(local_project, local_constraints, environment)
            # Unknown local versions are checked after discovery. They never
            # constrain a public namesake in the bootstrap registry resolver.
            constraints = [r for r in constraints if r not in local_constraints]
            requirements = (list(build) if discovery or build_only else
                            expand_local_requirements(local_project, requirements, environment) + build)
            if build_only:
                # Combined projects resolve runtime constraints separately. A
                # runtime pin must not constrain an isolated backend's tools.
                constraints = []
            if len(requirements) > 1024:
                raise Invalid('Too many local build and runtime requirements')
        # Bind existing preferences even for an empty graph. A later approved
        # hook can add requirements without changing the resolver's inputs.
        previous = root / 'ptw-requirements.txt'
        previous_content = metadata(root, previous.name, inputs) if previous.exists() else None
        if not requirements:
            outcome = 'resolved'
            return {'pins': [], 'runtime': runtime, 'inputs': inputs, 'artifacts': [], 'attempts': [],
                    **lock_binding}
        uv = shutil.which('uv')
        if not uv:
            raise Invalid('uv is required; no resolver fallback')
        save(stage / 'resolver-tool.json', {'path': str(Path(uv).resolve()),
            'sha256': hashlib.sha256(Path(uv).read_bytes()).hexdigest(), 'runtime': runtime,
            'inputs': inputs, 'cutoff_policy': rules})
        runner = runner or run_metadata
        if registry_config is not None:
            from .registry import RoutedPyPIEvidence
            if provider is not None:
                raise Invalid('Select one Python evidence provider')
            provider = RoutedPyPIEvidence(registry_config, native=rules.get('allow_native_wheels', False),
                                         python=runtime['executable'])
        provider = provider or PyPIEvidence(native=rules.get('allow_native_wheels', False), python=runtime['executable'])
        if isinstance(provider, PyPIEvidence):
            provider.deadline = started + seconds
        source_path, output = stage / 'requirements.in', stage / 'resolved.txt'
        source_path.write_text('\n'.join(requirements) + '\n')
        # Output pins are preferences, never hard constraints on unrelated versions.
        if previous_content is not None:
            output.write_text(previous_content)
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
            from .registry import RoutedPyPIEvidence
            from .python_index import WheelIndex
            view = (WheelIndex(provider, stage / ('index-' + str(index)), started + seconds)
                    if isinstance(provider, RoutedPyPIEvidence) else None)
            try:
                with view if view is not None else nullcontext(None) as endpoint:
                    if endpoint:
                        argv[argv.index('--index-url') + 1] = endpoint
                    proc = runner(argv, cwd=stage, env=env, capture_output=True, text=True,
                                  timeout=max(.001, started + seconds - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                attempt['outcome'] = 'timeout'
                raise ResolutionError('budget_exhausted', 'native resolver timed out') from exc
            finally:
                if view is not None:
                    attempt['index'] = {'requests': view.requests, 'documents': len(view.documents),
                        'artifacts': len(view.artifacts), 'downloaded_bytes': view.downloaded,
                        'failed': view.error is not None}
            attempt['returncode'] = proc.returncode
            if proc.returncode:
                attempt['stderr_signals'] = resolver_failure_signals(proc.stderr)
                attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
            if view is not None and view.error:
                raise EvidenceError(view.error)
            if proc.returncode:
                # uv uses the same status for transport and constraint errors.
                # Only its explicit solver diagnostic establishes a conflict.
                conflict = proc.returncode == 1 and 'No solution found' in proc.stderr
                attempt['outcome'] = 'unsatisfiable' if conflict else 'unavailable'
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
                    if len(cache) + (len(locked_plan['artifacts']) if locked_plan is not None else 0) >= max_assessments:
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
                        'attempts': attempts,
                        **lock_binding}
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
