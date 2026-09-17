"""Data-only discovery and separate native resolution for local Python projects."""
import os
from pathlib import Path
import re
import time
import tomllib

from packaging.utils import canonicalize_name
from packaging.version import Version

from .policy import Invalid, save
from .package_evidence import EvidenceError
from .workspace_policy import directory_fd, relative


def local_requirement(line):
    """Recognize a bounded local path syntax without probing arbitrary paths."""
    editable = re.match(r'(?:-e\s*|--editable(?:=|\s+))', line)
    value = line[editable.end():] if editable else line
    if not editable and not (value.startswith('.') or '/' in value):
        return None
    match = re.fullmatch(r'([^\s\[\]]+)(?:\[([^\[\]]+)\])?', value)
    if not match:
        raise Invalid('Malformed local project requirement')
    path = match[1]
    if path.startswith('/'):
        raise Invalid('Local project path must be relative')
    if path.startswith('./'):
        path = path[2:]
    path = path.removesuffix('/')
    if path == '.':
        path = ''
    relative(path, empty=True)
    if any(c in path for c in ('$','%', '~', ':', '\\')):
        raise Invalid('Local project paths cannot contain environment or URL syntax')
    extras = match[2].split(',') if match[2] else []
    try:
        extras = [canonicalize_name(e, validate=True) for e in extras]
    except ValueError as exc:
        raise Invalid('Invalid local project extra') from exc
    if len(extras) != len(set(extras)):
        raise Invalid('Duplicate local project extra')
    return path, 'editable' if editable else 'wheel', sorted(extras)


def discover_projects(root, *, source=None, groups=('dev', 'test'), discoveries=None, pending=False):
    """Return nested requirements projects; leave existing single-root paths alone.

    Includes are file-relative. Project paths are relative to the selected Python
    root. Reading a manifest grants neither source resources nor backend execution.
    """
    from .dependency_resolution import metadata, optional_dependencies, python_inputs, checked_requirement
    root = Path(root)
    if source in ('pyproject.toml', 'uv.lock', 'poetry.lock') or source is None and not any(
            (root / n).exists() for n in ('requirements.in', 'requirements.txt')):
        return None
    if discoveries is None:
        discoveries = {}
    if not isinstance(discoveries, dict):
        raise Invalid('Local discoveries must be a path-to-receipt map')
    projects = []
    requirements, constraints, inputs, requires_python = python_inputs(
        root, source=source, groups=groups, local_projects=projects)
    if not any(p['path'] for p in projects):
        return None
    if any((root / n).exists() for n in ('uv.lock', 'poetry.lock')) and not any(
            p['path'] == '' for p in projects):
        raise Invalid('Root native lock requires its local project in the selected requirements')
    for project in projects:
        path = project['path']
        prefix = path + '/' if path else ''
        try:
            fd = directory_fd(root / path)
            os.close(fd)
        except OSError as exc:
            raise Invalid('Local project must be an existing directory without links') from exc
        if (root / path / 'poetry.lock').exists():
            raise Invalid('Local Poetry lock needs its native build-requirement adapter')
        locked = (root / path / 'uv.lock').exists()
        if locked:
            metadata(root, prefix + 'uv.lock', inputs)
        content = metadata(root, prefix + 'pyproject.toml', inputs)
        try:
            config = tomllib.loads(content)
        except ValueError as exc:
            raise Invalid('Malformed local project manifest') from exc
        from .python_local import project_metadata, checked_hook_requirements
        declared = config.get('project', {})
        if not isinstance(declared, dict):
            raise Invalid('Local project metadata must be a table')
        dynamic = bool(declared.get('dynamic'))
        receipt = discoveries.get(path)
        required = {'build_requirements', 'source_sha256', 'runtime', 'runtime_sha256'}
        required |= {'dynamic_metadata'} if dynamic else {'hook'}
        if path in discoveries and (not isinstance(receipt, dict) or not required <= receipt.keys()):
            raise Invalid('Missing local discovery binding')
        if receipt is not None and not dynamic and (
                'dynamic_metadata' in receipt or receipt['hook'] != 'get_requires_for_build_' + project['mode']):
            raise Invalid('Discovery does not match the static local build mode')
        expected = receipt['dynamic_metadata'] if receipt is not None and dynamic else None
        unresolved = dynamic and receipt is None
        if unresolved and not pending:
            raise Invalid('Dynamic local source requires its approved metadata discovery')
        meta, build = project_metadata({'pyproject.toml': {'data': content.encode()}}, '', expected,
                                       discovery=unresolved)
        try:
            name = canonicalize_name(meta['name'], validate=True)
            version = None if unresolved else str(Version(meta['version']))
        except (KeyError, TypeError, ValueError) as exc:
            raise Invalid('Invalid local source identity') from exc
        if (not isinstance(build, dict) or not isinstance(build.get('requires'), list)
                or any(not isinstance(raw, str) for raw in build['requires'])):
            raise Invalid('Local source requires explicit build-system.requires')
        for raw in build['requires']:
            checked_requirement(raw)
        optional, active = optional_dependencies(meta, project['extras'], discovery=unresolved)
        local, constrained, bindings, required_python = python_inputs(
            root / path, source='pyproject.toml', groups=groups, extras=active,
            dynamic_metadata=expected, discovery=unresolved)
        for n, value in bindings.items():
            inputs[prefix + n] = value
        if (root / path / '.python-version').exists():
            metadata(root, prefix + '.python-version', inputs)
        project.update(name=name, version=version, requirements=local, constraints=constrained,
                       requires_python=required_python, build_requirements=build['requires'] + (
                           checked_hook_requirements(receipt['build_requirements'], name) if receipt else []),
                       optional=optional, dynamic=dynamic, locked=locked)
        if receipt is not None:
            project['discovery'] = receipt
    if set(discoveries) - {p['path'] for p in projects}:
        raise Invalid('Discovery supplied for an unselected local source')
    if len({p['name'] for p in projects}) != len(projects):
        raise Invalid('Duplicate local distribution identity')
    names = {p['name'] for p in projects}
    if any(canonicalize_name(checked_requirement(r).name) in names
           for p in projects for r in p['build_requirements']):
        raise Invalid('Local build dependency is not approved; no registry substitution')
    if len(inputs) > 64:
        raise Invalid('Too many dependency input files')
    return dict(projects=projects, requirements=requirements, constraints=constraints,
                inputs=inputs, requires_python=requires_python)


def runtime_requirements(discovered, environment):
    """Bind local references to reviewed identities, leaving registry solving to uv.

    Extras form a bounded monotone closure over already selected source metadata.
    No requirement can discover a source directory or grant backend access to it.
    """
    from .dependency_resolution import checked_requirement
    projects = {p['name']: p for p in discovered['projects']}
    active = {name: set(p['extras']) for name, p in projects.items()}
    for _ in range(1024):
        changed = False
        result = []
        declarations = [(raw, '') for raw in discovered['requirements']]
        for name, project in projects.items():
            declarations.extend((raw, name) for raw in project['requirements'])
            for extra in sorted(active[name]):
                declarations.extend((raw, name) for raw in project['optional'][extra])
        if len(declarations) > 1024:
            raise Invalid('Too many combined local dependency declarations')
        for raw, parent in declarations:
            req = checked_requirement(raw)
            if req.marker and not any(req.marker.evaluate({**environment, 'extra': e})
                                      for e in ['', *active.get(parent, ())]):
                continue
            name = canonicalize_name(req.name)
            if name not in projects:
                # Markers have been evaluated for the reviewed runtime and the
                # requesting source's extras, which uv's derived input lacks.
                req.marker = None
                hashes = re.split(r'\s+--hash=', raw)[1:]
                result.append(str(req) + ''.join(' --hash=' + h for h in hashes))
                continue
            if '--hash=' in raw or not req.specifier.contains(projects[name]['version'], prereleases=True):
                raise Invalid('Local requirement conflicts with reviewed source: ' + name)
            requested = {canonicalize_name(e) for e in req.extras}
            if not requested <= projects[name]['optional'].keys():
                raise Invalid('Unknown requested local extra: ' + name)
            if not requested <= active[name]:
                active[name].update(requested)
                changed = True
        if not changed:
            break
    else:
        raise Invalid('Local extras did not converge')
    constraints = []
    declared_constraints = [*discovered['constraints'], *(r for p in projects.values() for r in p['constraints'])]
    if len(declared_constraints) > 1024:
        raise Invalid('Too many combined local constraints')
    for raw in declared_constraints:
        req = checked_requirement(raw)
        name = canonicalize_name(req.name)
        if name not in projects:
            constraints.append(raw)
        else:
            if req.extras or '--hash=' in raw:
                raise Invalid('Local constraints cannot request extras or artifact hashes')
            if (not req.marker or req.marker.evaluate({**environment, 'extra': ''})) and not req.specifier.contains(
                    projects[name]['version'], prereleases=True):
                raise Invalid('Local constraint conflicts with reviewed source: ' + name)
    for name, project in projects.items():
        project['extras'] = sorted(active[name])
    return list(dict.fromkeys(result)), constraints


def review_projects(repo, directory, stage, shadow, scope, root, options, discovered,
                    goal, warn, stop, identity, *, native_wheels=False, editable_paths=(), review_hooks=False,
                    full_build=False):
    """Discover metadata and requested build hooks under one pending controller.

    Only data-only parsing precedes each approval. Earlier sources remain bound
    during refinement; their build graphs do not enter a later backend's view.
    """
    from .python_discovery import review
    from .python_runtime import select, version_constraint
    from .onboarding import data
    from .policy import load
    projects = discovered['projects']
    selected = [(i, p) for i, p in enumerate(projects) if p['dynamic'] or review_hooks]
    locations = [str(Path(root) / p['path']) for p in projects]
    locations = ['' if p == '.' else p for p in locations]
    if any(location and (n == location or location.startswith(n + '/')) for n in scope for location in locations):
        raise Invalid('Select resources inside each local project, not a containing directory')
    requirement = ','.join(r for r in [discovered['requires_python'], *(
        p['requires_python'] for p in projects)] if r)
    requests = [repo / root / '.python-version', *(repo / location / '.python-version' for location in locations)]
    versions = [str(version_constraint(data(p).strip())) for p in requests if p.exists()]
    runtime = select(','.join(r for r in [requirement, *versions] if r), options.get('executable'))
    receipts, prior = {}, None
    for index, project in selected:
        location = locations[index]
        prefix = location + '/' if location else ''
        paths = {n for n in scope if n.startswith(prefix) and not any(
            other != location and (not location or other.startswith(prefix)) and
            (n == other or n.startswith(other + '/')) for other in locations)}
        if not paths:
            raise Invalid('Select explicit source resources inside local project: ' + location)
        mutable = [n for n in editable_paths if n in paths]
        if project['mode'] == 'editable' and not mutable:
            raise Invalid('Each editable project needs explicitly selected mutable source paths')
        if project['mode'] == 'wheel' and mutable:
            raise Invalid('Wheel project cannot receive editable source approval')
        child = stage / ('project-discovery-' + str(index + 1))
        child.mkdir()
        if (stage / 'pypi-registry.json').exists():
            save(child / 'pypi-registry.json', load(stage / 'pypi-registry.json'))
        receipt = review(repo, directory, child, shadow, scope, location,
            dict(source='pyproject.toml', executable=runtime['executable'],
                 groups=options.get('groups', ('dev', 'test')), extras=project['extras']),
            goal, warn, stop, identity, native_wheels=native_wheels, full_build=full_build,
            source_identity='python-project-' + str(index + 1), prior=prior, source_paths=paths,
            local_names={p['name'] for p in projects}, hooks_only=not project['dynamic'],
            editable_paths=mutable if not project['dynamic'] else ())
        prior = load(child / ('discovery-build-approved.json' if (child / 'discovery-build-approved.json').exists()
                              else 'discovery-approved.json'))
        if project['dynamic'] and project['mode'] == 'editable':
            hook_stage = child / 'editable-discovery'
            hook_stage.mkdir()
            if (stage / 'pypi-registry.json').exists():
                save(hook_stage / 'pypi-registry.json', load(stage / 'pypi-registry.json'))
            hooks = review(repo, directory, hook_stage, shadow, scope, location,
                dict(source='pyproject.toml', executable=runtime['executable'],
                     groups=options.get('groups', ('dev', 'test')), extras=project['extras'],
                     dynamic_metadata=receipt['dynamic_metadata'], build_requirements=receipt['build_requirements']),
                goal, warn, stop, identity, native_wheels=native_wheels, full_build=full_build,
                source_identity='python-project-' + str(index + 1), prior=prior, source_paths=paths,
                local_names={p['name'] for p in projects}, hooks_only=True, editable_paths=mutable,
                previous=receipt)
            # Preserve the wheel metadata binding while adding the distinct
            # editable hook's requirements and most recent approved policy.
            receipt = {**receipt, **hooks}
            prior = load(hook_stage / ('discovery-build-approved.json'
                if (hook_stage / 'discovery-build-approved.json').exists() else 'discovery-approved.json'))
        receipts[project['path']] = receipt
    if prior:
        save(stage / 'discovery-final-approved.json', prior)
    return receipts


def resolve_projects(root, stage, rules, *, source=None, groups=('dev', 'test'), executable=None,
                     provider=None, runner=None, registry_config=None, discoveries=None):
    """Use the existing resolver for one runtime closure and each build closure.

    Only validated registry declarations enter derived resolver workspaces. The
    returned authority is the original metadata, never these derived files.
    """
    from .dependency_resolution import (checked_requirement, metadata,
                                        ResolutionError, resolve_python)
    from .package_install import target_environment
    from .python_runtime import select, version_constraint
    from .onboarding import data
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    outcome = 'invalid'
    plans = []
    try:
        discovered = discover_projects(root, source=source, groups=groups, discoveries=discoveries)
        if discovered is None:
            raise Invalid('No additional local projects in selected requirements')
        projects, inputs = discovered['projects'], discovered['inputs']
        names = {p['name'] for p in projects}
        requirement = ','.join(r for r in [discovered['requires_python'], *(
            p['requires_python'] for p in projects)] if r)
        request = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        runtime = select(requirement, executable, request)
        for project in projects:
            receipt = project.get('discovery')
            if receipt is not None and (receipt['runtime'] != runtime['executable'] or
                    receipt['runtime_sha256'] != runtime['sha256']):
                raise Invalid('Combined resolution changed the discovery runtime')
        environment = target_environment(runtime['executable'])
        for project in projects:
            version_file = root / project['path'] / '.python-version'
            if version_file.exists() and not version_constraint(data(version_file).strip()).contains(runtime['version']):
                raise Invalid('Local project .python-version conflicts with selected runtime')
        requirements, constraints = runtime_requirements(discovered, environment)
        # A runtime relationship grants no cross-source backend inputs. Local
        # build dependencies still need a separately designed build boundary.
        for raw in (r for p in projects for r in p['build_requirements']):
            if canonicalize_name(checked_requirement(raw).name) in names:
                raise Invalid('Local build dependency is not approved; no registry substitution')
        remaining_assessments = 256

        # A native lock constrains the shared runtime, never another source's
        # build environment. Preserve all exported transitive identities/hashes.
        # Dynamic exports identify candidates only. install_source requires
        # approved offline validation of each original source and lock before
        # returning a payload for atomic publication.
        from .python_lock import export_lock
        locked_artifacts = {}
        for index, project in enumerate(projects):
            if not project['locked']:
                continue
            if registry_config is not None or getattr(provider, 'routes', None):
                raise Invalid('Private Python native locks require a reviewed source adapter')
            remaining = 180 - (time.monotonic() - start)
            if remaining <= 0 or remaining_assessments <= 0:
                raise ResolutionError('budget_exhausted', 'combined local resolution budget reached')
            plan = export_lock(root / project['path'], stage / ('lock-' + str(index)), rules,
                source='uv.lock', executable=runtime['executable'], groups=groups, extras=project['extras'],
                provider=provider, runner=runner, seconds=remaining, max_assessments=remaining_assessments,
                candidate_only=project['dynamic'])
            remaining_assessments -= len(plan['artifacts'])
            plans.append({'graph': 'lock-' + str(index), 'attempts': plan['attempts']})
            if any(plan['runtime'][k] != runtime[k] for k in ('executable', 'sha256', 'version')):
                raise Invalid('Local locked export changed the selected runtime')
            prefix = project['path'] + '/' if project['path'] else ''
            if any(inputs.get(prefix + n) != v for n, v in plan['inputs'].items()):
                raise Invalid('Local dependency input changed during locked export')
            for artifact in plan['artifacts']:
                name = artifact['name']
                if name in names:
                    raise Invalid('Native lock contains a registry namesake of a reviewed local source')
                if name in locked_artifacts and artifact != locked_artifacts[name]:
                    raise Invalid('Local native locks disagree on a shared runtime artifact')
                locked_artifacts[name] = artifact
        locked_requirements = [r['name'] + '==' + r['version'] + ' --hash=sha256:' + r['sha256']
                               for r in locked_artifacts.values()]
        requirements.extend(locked_requirements)
        constraints.extend(locked_requirements)

        def resolve_graph(label, requirements, constraints):
            nonlocal remaining_assessments
            remaining = 180 - (time.monotonic() - start)
            if remaining <= 0 or remaining_assessments <= 0:
                raise ResolutionError('budget_exhausted', 'combined local resolution budget reached')
            directory = stage / label
            declarations = directory / 'declarations'
            declarations.mkdir(parents=True)
            (declarations / 'requirements.in').write_text('-c constraints.txt\n' + '\n'.join(requirements) + '\n')
            (declarations / 'constraints.txt').write_text('\n'.join(constraints) + '\n')
            plan = resolve_python(declarations, directory / 'resolution', rules,
                source='requirements.in', executable=runtime['executable'], provider=provider, runner=runner,
                registry_config=registry_config, seconds=remaining, max_assessments=remaining_assessments)
            remaining_assessments -= len({(n, v) for a in plan['attempts'] for n, v in a.get('pins', {}).items()})
            if {k: v for k, v in plan['runtime'].items() if k != 'requires_python'} != {
                    k: v for k, v in runtime.items() if k not in ('requires_python', 'version_request')}:
                raise Invalid('Local graph resolver changed the selected runtime')
            if names & {r['name'] for r in plan['artifacts']}:
                raise Invalid('Registry graph contains a reviewed local source identity')
            plans.append({'graph': label, 'attempts': plan['attempts']})
            return {key: plan[key] for key in ('pins', 'artifacts')}

        result = resolve_graph('runtime', requirements, constraints)
        if any(r not in result['artifacts'] for r in locked_artifacts.values()):
            raise Invalid('Shared runtime differs from an authoritative local lock artifact')
        sources = []
        for index, project in enumerate(projects):
            graph = resolve_graph('build-' + str(index), project['build_requirements'], [])
            sources.append({**{k: project[k] for k in ('path', 'mode', 'extras', 'name', 'version')},
                            'build_dependencies': graph,
                            **({'discovery': project['discovery']} if 'discovery' in project else {})})
        # Original data must still match after every resolver and evidence call.
        for name, expected in inputs.items():
            current = {}
            metadata(root, name, current)
            if current[name] != expected:
                raise Invalid('Local dependency input changed during resolution')
        outcome = 'resolved'
        return {**result, 'runtime': runtime, 'inputs': inputs, 'local_projects': sources,
                'authority': 'requirements', 'attempts': plans}
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    finally:
        save(stage / 'resolution.json', {'outcome': outcome, 'graphs': plans,
                                        'elapsed_seconds': time.monotonic() - start})
