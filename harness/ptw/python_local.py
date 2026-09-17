"""Reviewed local preparation using uv and the existing offline build supervisor."""
from email.parser import BytesParser
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import secrets
import tempfile
import time
import tomllib
import zipfile
from urllib.parse import quote

from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.specifiers import SpecifierSet
from packaging.markers import Marker
from packaging.version import Version

from .package_build import run_build
from .package_evidence import EvidenceError, evaluate, pins
from .package_install import (file_manifest, install_wheels, target_environment, target_tags,
                              validate_dependencies, validate_wheels)
from .policy import Invalid, OutsideScope, canonical, digest, save, scope
from .python_runtime import verify
from .supervisor import runtime_namespace
from .workspace import materialize, owner, scan, stamp
from .workspace_policy import relative
from packaging.requirements import Requirement

EDITABLE_ARTIFACTS = '.ptw-editable-artifacts'
PROJECTED_BUILD = 'setuptools-src-v1'


def native_file(path):
    with path.open('rb') as handle:
        return handle.read(4) == b'\x7fELF' or path.suffix.lower() in ('.so', '.pyd', '.dll')


def snapshot_digest(entries):
    return digest({p: [stamp(e), e.get('mode')] for p, e in entries.items()})


def reviewed_runtime(descriptor):
    """Identity checks only, never artifacts, grants or another source mount."""
    selected = pins(descriptor['pins'], extras={}) if descriptor['pins'] else {}
    for source in descriptor.get('sources', []):
        if source['mode'] != 'discovery':
            if source['name'] in selected:
                raise Invalid('Ambiguous local runtime identity')
            selected[source['name']] = source['version']
    return selected


def prepare_setup(store, bundle, task, stage):
    """Approved transaction only. Ordinary sessions remain unavailable throughout."""
    sources = bundle['policy']['project'].get('python_dependencies', {}).get('sources', [])
    if len(sources) > 1:
        return prepare_combined_setup(store, bundle, task, stage)
    from .supervisor import Supervisor
    receipts = []
    for source in bundle['policy']['project'].get('python_dependencies', {}).get('sources', []):
        actor = store.register_preparation(bundle['policy']['project']['id'], task, source['id'],
                                           bundle['approval']['sha256'])
        try:
            install = install_editable if source['mode'] == 'editable' else install_wheel
            receipt = install(store, actor['token'], source['id'])
            receipts.append(receipt)
            save(stage / ('preparation-' + source['id'] + '.json'), receipt)
        except BaseException as exc:
            save(stage / ('preparation-' + source['id'] + '-failure.json'), {'error': type(exc).__name__})
            raise
        finally:
            store.close_session(actor['token'])
            if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
                raise Invalid('Preparation termination is unconfirmed; setup cannot commit')
    return receipts


def receipt_sources(receipt):
    """One reader for legacy singular and versioned combined source bindings."""
    if not isinstance(receipt, dict):
        raise Invalid('Malformed local preparation receipt')
    if 'version' not in receipt and 'sources' not in receipt:
        parts = [receipt]
    elif receipt.get('version') == 2 and 'source_id' not in receipt:
        parts = receipt.get('sources')
        if not isinstance(parts, list) or not 2 <= len(parts) <= 64:
            raise Invalid('Malformed combined preparation receipt')
    else:
        raise Invalid('Unknown local preparation receipt version')
    identities = set()
    for part in parts:
        if (not isinstance(part, dict) or not isinstance(part.get('source_id'), str) or
                part['source_id'] in identities or 'sources' in part or 'version' in part or
                part.get('policy_sha256') != receipt.get('policy_sha256')):
            raise Invalid('Ambiguous local preparation receipt')
        identities.add(part['source_id'])
    return parts


def merge_installation(source, destination):
    """Merge validated data without allowing even identical package-file collisions."""
    incoming, existing = file_manifest(source), file_manifest(destination)
    collisions = incoming.keys() & existing.keys()
    # uv's empty target lock is not owned by a distribution.
    if incoming.get('.lock') == existing.get('.lock') == hashlib.sha256(b'').hexdigest():
        collisions.discard('.lock')
    if collisions:
        raise EvidenceError('Combined local installation files collide')
    paths = existing.keys() | incoming.keys()
    if (len(paths) > 50000 or
            sum((destination / p).stat().st_size for p in existing) +
            sum((source / p).stat().st_size for p in incoming if p not in existing) > 512 * 1024 * 1024):
        raise EvidenceError('Combined installation exceeds package set limits')
    shutil.copytree(source, destination, dirs_exist_ok=True)


def prepare_combined_setup(store, bundle, task, stage):
    """Build separately and publish once, after every preparation session ends."""
    from .supervisor import Supervisor
    sources = bundle['policy']['project']['python_dependencies']['sources']
    approval, project_id = bundle['approval']['sha256'], bundle['policy']['project']['id']
    payloads = []
    with tempfile.TemporaryDirectory(prefix='local-combined-', dir=store.directory) as temporary:
        root = Path(temporary)
        site = root / 'site'
        for index, source in enumerate(sources):
            actor = store.register_preparation(project_id, task, source['id'], approval)
            try:
                payload = install_source(store, actor['token'], source['id'], mode=source['mode'],
                                         payload=root / ('source-' + str(index)))
                payloads.append(payload)
                save(stage / ('preparation-' + source['id'] + '.json'), payload['receipt'])
                if index == len(sources) - 1:
                    # Install the shared assessed registry graph once. No backend
                    # can read or modify the assembled installation directory.
                    artifacts = root / 'registry-artifacts'
                    artifacts.mkdir()
                    selected, records = assessed_artifacts(store, actor['token'], artifacts,
                                                           payload['receipt']['runtime'])
                    if records:
                        install_wheels(artifacts, site, records, extended=True,
                                       python=payload['receipt']['runtime'])
                    else:
                        site.mkdir()
                        (site / 'sitecustomize.py').write_text(
                            'import pathlib,site\nsite.addsitedir(str(pathlib.Path(__file__).parent))\n')
            except BaseException as exc:
                save(stage / ('preparation-' + source['id'] + '-failure.json'), {'error': type(exc).__name__})
                raise
            finally:
                store.close_session(actor['token'])
                if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
                    raise Invalid('Preparation termination is unconfirmed; setup cannot commit')
        for payload in payloads:
            if (payload['selected'] != selected or
                    [{k: r[k] for k in ('name', 'version', 'url', 'sha256')} for r in payload['records']] !=
                    [{k: r[k] for k in ('name', 'version', 'url', 'sha256')} for r in records] or
                    file_manifest(payload['site']) != payload['manifest']):
                raise Invalid('Local preparation payload or registry graph changed')
            merge_installation(payload['site'], site)
        metadata = {}
        for info in site.glob('*.dist-info'):
            meta = BytesParser().parsebytes((info / 'METADATA').read_bytes())
            name = canonicalize_name(meta.get('Name', ''), validate=True)
            if name in metadata:
                raise EvidenceError('Duplicate combined distribution identity')
            metadata[name] = meta
        expected = {**selected, **{s['name']: s['version'] for s in sources}}
        if set(metadata) != set(expected):
            raise EvidenceError('Combined distribution set differs from review')
        validate_dependencies(metadata, expected, target_environment(payloads[0]['receipt']['runtime']),
                              extras={s['name']: s.get('extras', []) for s in sources})
        manifest = file_manifest(site)
        receipt = dict(version=2, sources=[p['receipt'] for p in payloads], policy_sha256=approval,
                       manifest_sha256=digest(manifest))
        with store.locked() as db:
            project, current = store.project(db, project_id)
            if project['stopped'] or not project['setup_pending'] or current != bundle:
                raise Invalid('Combined installation authority changed')
            if db.execute('SELECT 1 FROM sessions WHERE project=? AND preparation_source IS NOT NULL '
                          'AND closed=0', (project_id,)).fetchone() or db.execute(
                    'SELECT 1 FROM workloads w JOIN sessions s ON w.session=s.id WHERE w.project=? '
                    'AND s.preparation_source IS NOT NULL AND w.stopped=0', (project_id,)).fetchone():
                raise Invalid('Preparation termination must be confirmed before publication')
            from .dependency_binding import verify_inputs
            from .workspace import Workspace
            from .python_lock import verify_source_lock
            Workspace(store).integrity(db, project_id, current)
            verify_inputs(current)
            verify(current['policy']['project']['python_runtime'])
            for source, payload in zip(sources, payloads):
                verify_source_lock(current, source, payload['receipt'])
                verify_build_receipt(source, payload['receipt'])
                if (payload['source'] != source or payload['receipt']['policy_sha256'] != approval or
                        snapshot_digest(scan(current['inventory'], source['resources'])) != source['snapshot_sha256']):
                    raise Invalid('Local source changed during combined preparation')
            if any(evaluate(r, current['policy']['project']['packages']) for r in
                   [*records, *(r for p in payloads for r in p['build_records'])]):
                raise EvidenceError('Combined dependency evidence no longer permits publication')
            result = publish_set(store, db, project_id, approval, site,
                                 {'pypi:' + n for n in selected}, manifest, receipt)
        return [result]


def validate_prepared_setup(store, bundle, receipts):
    """Final file checks inside commit_setup's authority lock, before readiness."""
    sources = bundle['policy']['project'].get('python_dependencies', {}).get('sources', [])
    parts = [(receipt, part) for receipt in receipts for part in receipt_sources(receipt)]
    if [part['source_id'] for _, part in parts] != [s['id'] for s in sources]:
        raise Invalid('Setup is missing a local preparation receipt')
    for source, (receipt, part) in zip(sources, parts):
        from .python_lock import verify_source_lock
        verify_source_lock(bundle, source, part)
        verify_build_receipt(source, part)
        if (receipt['policy_sha256'] != bundle['approval']['sha256'] or
                snapshot_digest(scan(bundle['inventory'], source['resources'])) != source['snapshot_sha256'] or
                digest(file_manifest(store.directory / 'package-sets' / receipt['package_set'])) != receipt['manifest_sha256']):
            raise Invalid('Local preparation changed before setup commit')


def prepared_sets(store, token):
    """Expose usable receipt IDs, never source payloads, to a scoped adapter."""
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor['project'])
        if project['stopped'] or project['setup_pending']:
            return []
        grants, result = scope(json.loads(actor['grants'])), []
        for row in db.execute('SELECT * FROM package_sets WHERE project=? AND policy_sha256=? '
                              'AND local_source IS NOT NULL', (actor['project'], bundle['approval']['sha256'])):
            receipt = json.loads(row['local_source'])
            parts = receipt_sources(receipt)
            approved = {s['id']: s for s in bundle['policy']['project']['python_dependencies'].get('sources', [])}
            if any(p['source_id'] not in approved for p in parts):
                continue
            resources = {r for p in parts for r in approved[p['source_id']]['resources']}
            if (any('read' not in grants.get(r, set()) for r in resources) or
                    not set(json.loads(row['names'])) <= set(json.loads(actor['packages']))):
                continue
            commands = [c['id'] for c in bundle['policy']['project']['commands']
                        if c['id'] in json.loads(actor['commands']) and resources <= set(c['resources'])]
            if commands:
                identity = ({'source_id': parts[0]['source_id']} if len(parts) == 1 else
                            {'source_ids': [p['source_id'] for p in parts]})
                result.append({'package_set': row['id'], **identity, 'commands': commands})
        return result


def validate_sources(policy, inv):
    descriptor = policy['project'].get('python_dependencies', {})
    registry = pins(descriptor['pins'], extras={}) if descriptor.get('pins') else {}
    names, paths, identities = set(registry), set(), set()
    grants = scope(policy['project']['grants'])
    local_names = {s['name'] for s in descriptor.get('sources', [])}
    for source in descriptor.get('sources', []):
        if 'build_dependencies' in source:
            graph = source['build_dependencies']
            selected = pins(graph['pins'], extras={}) if graph['pins'] else {}
            if (len(graph['artifacts']) != len(selected) or
                    {r['name']: r['version'] for r in graph['artifacts']} != selected):
                raise Invalid('Build artifact identities do not match source pins')
            if set(selected) & local_names:
                raise Invalid('Build graph cannot resolve a local identity from a registry')
            if not {'pypi:' + n for n in selected} <= set(policy['project']['packages']['allowed_names']):
                raise Invalid('Source build graph expands package scope')
        path = relative(source['path'], empty=True)
        name = canonicalize_name(source['name'], validate=True)
        if source['mode'] != 'discovery':
            if 'version' not in source:
                raise Invalid('An installed local source requires a reviewed version')
            Version(source['version'])
        elif 'version' in source or source.get('dynamic_metadata'):
            raise Invalid('Discovery cannot claim reviewed output metadata')
        if name != source['name'] or name in names or path in paths or source['id'] in identities:
            raise Invalid('Duplicate or ambiguous Python local source identity')
        names.add(name)
        paths.add(path)
        identities.add(source['id'])
        editable = source.get('editable_resources', [])
        if source['mode'] == 'editable':
            if not editable or not set(editable) <= set(source['resources']) or 'build_sha256' not in source:
                raise Invalid('Editable source requires explicit mutable resources and build binding')
        elif editable or 'build_sha256' in source or 'native_build_view' in source:
            raise Invalid('Wheel sources cannot contain editable approval fields')
        for resource in source['resources']:
            item = inv['resources'].get(resource)
            if (item is None or (path and not item['path'].startswith(path + '/')) or
                    'read' not in grants.get(resource, set())):
                raise Invalid('Python local source requires explicitly bound project read resources')


def project_metadata(entries, path, dynamic_metadata=None, *, discovery=False):
    """Read declarations and explicit expected dynamic values, without hooks."""
    prefix = path + '/' if path else ''
    try:
        config = tomllib.loads(entries[prefix + 'pyproject.toml']['data'].decode())
        meta = config['project']
        if not isinstance(meta, dict) or not isinstance(config.get('build-system'), dict):
            raise Invalid('Project and build-system metadata must be tables')
        dynamic = meta.get('dynamic', [])
        if (not isinstance(dynamic, list) or any(not isinstance(f, str) for f in dynamic)
                or len(dynamic) != len(set(dynamic)) or any(f in meta for f in dynamic)):
            raise Invalid('Invalid or conflicting dynamic metadata declaration')
        if discovery:
            if not dynamic or not set(dynamic) <= {'version', 'dependencies', 'requires-python', 'optional-dependencies'}:
                raise Invalid('Discovery requires supported dynamic metadata fields')
            if dynamic_metadata is not None:
                raise Invalid('Discovery cannot use expected dynamic values')
        elif dynamic:
            if (not isinstance(dynamic_metadata, dict) or set(dynamic_metadata) != set(dynamic)
                    or not set(dynamic) <= {'version', 'dependencies', 'requires-python', 'optional-dependencies'}):
                raise Invalid('Dynamic metadata needs explicit expected values in the source review')
        elif dynamic_metadata is not None:
            raise Invalid('Dynamic metadata approval does not match project declarations')
        result = {**meta, **(dynamic_metadata or {})}
        if (not isinstance(result.get('dependencies', []), list)
                or any(not isinstance(r, str) for r in result.get('dependencies', []))
                or not isinstance(result.get('requires-python', ''), str)
                or (not discovery and not isinstance(result.get('version'), str))):
            raise Invalid('Invalid reviewed local project metadata')
        SpecifierSet(result.get('requires-python', ''))
        return result, config['build-system']
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid('Invalid or missing local project metadata') from exc


def declared_dependencies(meta, extras=(), *, discovery=False):
    """PEP 621 extras become PEP 508 markers in wheel metadata, including inactive extras."""
    from .dependency_resolution import optional_dependencies
    optional, active = optional_dependencies(meta, extras, discovery=discovery)
    requirements = list(meta.get('dependencies', []))
    for extra, values in optional.items():
        for raw in values:
            req = Requirement(raw)
            marker = '(' + str(req.marker) + ') and ' if req.marker else ''
            req.marker = Marker(marker + 'extra == ' + json.dumps(extra))
            requirements.append(str(req))
    return requirements, optional, active


def static_metadata(entries, path, *, selected=None, environment=None, dynamic_metadata=None, extras=(), discovery=False,
                    build_selected=None, hooks_only=False):
    """Parse data only. Never import a backend to discover its identity."""
    prefix = path + '/' if path else ''
    try:
        meta, build = project_metadata(entries, path, dynamic_metadata, discovery=discovery)
        name = canonicalize_name(meta['name'], validate=True)
        version = None if discovery else str(Version(meta['version']))
        if not isinstance(build.get('build-backend'), str) or not build['build-backend']:
            raise Invalid('An explicit build backend is required')
        requirements = build.get('requires')
        if not isinstance(requirements, list):
            raise Invalid('build-system.requires must be an array')
        # Parsing never executes a backend. Resolve and approve these requirements
        # through the existing Python descriptor before preparation.
        declarations, optional, active = declared_dependencies(meta, extras, discovery=discovery)
        for raw in requirements + declarations:
            requirement = Requirement(raw)
            if requirement.url:
                raise Invalid('Local metadata cannot introduce URL dependencies')
        if any(canonicalize_name(Requirement(raw).name) == name for raw in requirements):
            raise Invalid('Build requirement cannot resolve the local project from a registry')
        if selected is not None:
            from .dependency_resolution import expand_local_requirements
            runtime = list(meta.get('dependencies', []))
            for extra in active:
                runtime.extend(optional[extra])
            checked = [] if discovery or hooks_only else expand_local_requirements(meta, runtime, environment or {})
            for raw, graph in [(r, selected if build_selected is None else build_selected) for r in requirements] + [
                    (r, selected) for r in checked]:
                requirement = Requirement(raw)
                if requirement.marker and not any(requirement.marker.evaluate({**(environment or {}), 'extra': e})
                                                  for e in ['', *active]):
                    continue
                name = canonicalize_name(requirement.name)
                if (name not in graph or not requirement.specifier.contains(graph[name], prereleases=True)):
                    raise Invalid('Local requirement needs reviewed compatible resolution: ' + name)
        backend_paths = build.get('backend-path', [])
        if not isinstance(backend_paths, list):
            raise Invalid('backend-path must be an array')
        for backend in backend_paths:
            if backend != '.':
                relative(backend)
            location = prefix + (backend + '/' if backend != '.' else '')
            if not any(p.startswith(location) and e['kind'] == 'file'
                       for p, e in entries.items()):
                raise Invalid('Backend path is absent from bound source resources')
        return canonicalize_name(meta['name'], validate=True), version
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid('Invalid or missing static local project metadata') from exc


def build_entries(entries, inv, source):
    """Only explicitly mutable implementation resources may change on reuse."""
    # Arbitrary backends can derive metadata from any source file. Without a
    # backend-specific proof, every dynamic-project input remains fixed. This
    # also binds new/deleted files in mutable trees, not just known config names.
    if source.get('dynamic_metadata'):
        prefix = source['path'] + '/' if source['path'] else ''
        config = tomllib.loads(entries[prefix + 'pyproject.toml']['data'].decode())
        backend = config['build-system']
        dynamic = config.get('tool', {}).get('setuptools', {}).get('dynamic', {})
        paths = set()
        # Only declarative setuptools file directives have a known read set.
        # Attribute imports and arbitrary backends retain the full binding.
        known = (backend.get('build-backend') == 'setuptools.build_meta' and
                 not backend.get('backend-path') and
                 all(canonicalize_name(Requirement(r).name) in {'setuptools', 'wheel'} and
                     not Requirement(r).extras for r in backend.get('requires', [])) and
                 not any(prefix + p in entries for p in ('setup.py', 'setup.cfg')))
        for field in source['dynamic_metadata']:
            directive = dynamic.get(field, {})
            files = directive.get('file') if isinstance(directive, dict) else None
            files = [files] if isinstance(files, str) else files
            if not isinstance(files, list) or not files or set(directive) != {'file'}:
                known = False
                break
            for path in files:
                relative(path)
                name = prefix + path
                if name not in entries or entries[name]['kind'] != 'file':
                    raise Invalid('Dynamic metadata input is absent from bound source resources')
                paths.add(name)
        if not known:
            return {p: e for p, e in entries.items() if owner(inv, p) in source['resources']}
        fixed = set(source['resources']) - set(source.get('editable_resources', []))
        return {p: e for p, e in entries.items() if p in paths or owner(inv, p) in fixed}
    fixed = set(source['resources']) - set(source.get('editable_resources', []))
    return {p: e for p, e in entries.items() if owner(inv, p) in fixed}


def validate_editable_scope(entries, inv, source):
    prefix = source['path'] + '/' if source['path'] else ''
    config = tomllib.loads(entries[prefix + 'pyproject.toml']['data'].decode())
    mutable = source.get('editable_resources', [])
    protected = [prefix + p for p in ('pyproject.toml', 'setup.py', 'setup.cfg')]
    backends = [prefix + (p if p != '.' else '') for p in config['build-system'].get('backend-path', [])]
    for resource in mutable:
        item = inv['resources'][resource]
        path = item['path']
        if (any(p == path or p.startswith(path + '/') for p in protected) or
                any(not p or path == p or path.startswith(p + '/') or p.startswith(path + '/') for p in backends)):
            raise Invalid('Editable resources cannot include backend or build configuration')


def describe_source(inv, resources, *, identity, path='', allow_build=False, editable_resources=(),
                    dynamic_metadata=None, extras=(), discovery=False, full_build=False):
    """Create review data from explicit resource IDs; a root path grants nothing."""
    relative(path, empty=True)
    if not resources or len(resources) != len(set(resources)):
        raise Invalid('Unique explicit source resources are required')
    for resource in resources:
        item = inv['resources'].get(resource)
        if item is None or (path and not item['path'].startswith(path + '/')):
            raise Invalid('Source resource is outside its local project')
    entries = scan(inv, resources)
    if discovery and editable_resources:
        raise Invalid('Discovery cannot grant editable reuse')
    name, version = static_metadata(entries, path, dynamic_metadata=dynamic_metadata, extras=extras, discovery=discovery)
    source = dict(id=identity, path=path, name=name,
                  mode='discovery' if discovery else 'editable' if editable_resources else 'wheel',
                  allow_build=allow_build, resources=list(resources),
                  snapshot_sha256=snapshot_digest(entries))
    if not discovery:
        source['version'] = version
    if extras:
        source['extras'] = sorted(canonicalize_name(e) for e in extras)
    if dynamic_metadata is not None:
        # Copy review data so the caller cannot later mutate its nested arrays.
        source['dynamic_metadata'] = json.loads(canonical(dynamic_metadata))
    if editable_resources:
        if len(editable_resources) != len(set(editable_resources)) or not set(editable_resources) <= set(resources):
            raise Invalid('Editable resources must be a unique subset of source resources')
        source['editable_resources'] = list(editable_resources)
        validate_editable_scope(entries, inv, source)
        source['build_sha256'] = snapshot_digest(build_entries(entries, inv, source))
        source['native_build_view'] = ('full' if full_build or
            native_build_entries(entries, inv, source) == entries else PROJECTED_BUILD)
    return source


def reuse_source(bundle, actor, identity, definition, entries):
    """Source-bearing installed data is usable only with a full authorized snapshot."""
    source = next((s for s in bundle['policy']['project'].get('python_dependencies', {}).get('sources', [])
                   if s['id'] == identity), None)
    if source is None or not source['allow_build'] or source['mode'] == 'discovery':
        raise OutsideScope('Local source has no current approval')
    if definition is None or entries is None:
        raise OutsideScope('Local package reuse requires a workspace command snapshot')
    grants = scope(json.loads(actor['grants']))
    if any('read' not in grants.get(r, set()) for r in source['resources']):
        raise OutsideScope('Local package source exceeds session read grants')
    if not set(source['resources']) <= set(definition['resources']):
        raise OutsideScope('Local package source exceeds command inputs')
    if source['mode'] == 'wheel':
        selected_entries = {p: e for p, e in entries.items()
                            if owner(bundle['inventory'], p) in source['resources']}
        if snapshot_digest(selected_entries) != source['snapshot_sha256']:
            raise Invalid('Local wheel source changed; review and prepare again')
        return source
    try:
        validate_editable_scope(entries, bundle['inventory'], source)
    except (KeyError, ValueError, UnicodeError) as exc:
        raise Invalid('Local build configuration missing or malformed; review and prepare again') from exc
    if snapshot_digest(build_entries(entries, bundle['inventory'], source)) != source['build_sha256']:
        raise Invalid('Local build configuration changed; review and prepare again')
    return source


def authorized_snapshot(store, token, identity, *, hooks_only=False):
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        if actor['preparation_source'] is not None and actor['preparation_source'] != identity:
            raise OutsideScope('Preparation session is bound to another source')
        project, bundle = store.project(db, actor['project'])
        if project['stopped']:
            raise Invalid('Project stopped')
        from .workspace import Workspace
        Workspace(store).integrity(db, actor['project'], bundle)
        sources = bundle['policy']['project'].get('python_dependencies', {}).get('sources', [])
        source = next((s for s in sources if s['id'] == identity), None)
        if source is None or not source['allow_build']:
            raise OutsideScope('Local build has no explicit approval')
        discovery = source['mode'] == 'discovery'
        if hooks_only and (not project['setup_pending'] or actor['preparation_source'] != identity):
            raise OutsideScope('Build requirement discovery requires pending source preparation')
        if discovery and (not project['setup_pending'] or actor['preparation_source'] != identity):
            raise OutsideScope('Discovery requires a source-bound pending preparation session')
        grants = scope(json.loads(actor['grants']))
        if any('read' not in grants.get(r, set()) for r in source['resources']):
            raise OutsideScope('Local build source exceeds session read grants')
        from .dependency_binding import verify_inputs
        verify_inputs(bundle)
        python = verify(bundle['policy']['project']['python_runtime'])
        entries = scan(bundle['inventory'], source['resources'])
        if snapshot_digest(entries) != source['snapshot_sha256']:
            raise Invalid('Local source changed since build review')
        if source['mode'] == 'editable':
            validate_editable_scope(entries, bundle['inventory'], source)
            if snapshot_digest(build_entries(entries, bundle['inventory'], source)) != source['build_sha256']:
                raise Invalid('Editable build binding differs from the approved source')
        descriptor = bundle['policy']['project']['python_dependencies']
        selected = reviewed_runtime(descriptor)
        from .dependency_binding import source_graph
        graph = source_graph(descriptor, identity)
        build_selected = pins(graph['pins'], extras={}) if graph['pins'] else {}
        if static_metadata(entries, source['path'], selected=selected,
                           build_selected=build_selected, hooks_only=hooks_only,
                           environment=target_environment(python),
                           dynamic_metadata=source.get('dynamic_metadata'),
                           extras=source.get('extras', ()), discovery=discovery) != (source['name'], source.get('version')):
            raise Invalid('Local metadata differs from reviewed identity')
        metadata, _ = project_metadata(entries, source['path'], source.get('dynamic_metadata'), discovery=discovery)
        requirement = metadata.get('requires-python', '')
        try:
            supported = SpecifierSet(requirement).contains(
                bundle['policy']['project']['python_runtime']['version'])
        except (TypeError, ValueError) as exc:
            raise Invalid('Invalid local Python runtime requirement') from exc
        if not supported:
            raise Invalid('Local project does not support the reviewed Python runtime')
        return source, entries, python, bundle['approval']['sha256']


def metadata_requirement(value):
    req = Requirement(value)
    if req.url:
        raise EvidenceError('Local output cannot introduce URL dependencies')
    return (canonicalize_name(req.name), tuple(sorted(canonicalize_name(e) for e in req.extras)),
            str(req.specifier), str(req.marker) if req.marker else '')


def validate_output_metadata(meta, entries, source):
    """A compatible graph alone does not allow a backend to change declarations."""
    expected, _ = project_metadata(entries, source['path'], source.get('dynamic_metadata'))
    try:
        actual = {metadata_requirement(r) for r in meta.get_all('Requires-Dist', [])}
        declarations, optional, _ = declared_dependencies(expected, source.get('extras', ()))
        declared = {metadata_requirement(r) for r in declarations}
        provided = [canonicalize_name(e, validate=True) for e in meta.get_all('Provides-Extra', [])]
        if len(provided) != len(set(provided)) or set(provided) != set(optional):
            raise EvidenceError('Local output extras differ from source review')
        # PEP 660 permits extra editable runtime dependencies. They still have to
        # fit the independently assessed graph checked by validate_dependencies.
        if (not declared <= actual or (source['mode'] == 'wheel' and actual != declared)
                or SpecifierSet(meta.get('Requires-Python', '')) != SpecifierSet(expected.get('requires-python', ''))):
            raise EvidenceError('Local output metadata differs from source review')
    except ValueError as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError('Invalid local output metadata') from exc


def assessed_artifacts(store, token, destination, python, *, provider=None, identity=None):
    """Use the existing reviewed graph and evidence policy, including build tools.

    Only checked wheels enter the offline backend environment. No ambient site
    packages, registry credentials or unreviewed hook requirements are supplied.
    """
    from .dependency_binding import verify_artifacts, verify_inputs
    from .registry import provider_for
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        project, bundle = store.project(db, actor['project'])
        if project['stopped']:
            raise Invalid('Project stopped')
        descriptor = bundle['policy']['project']['python_dependencies']
        if identity is not None:
            from .dependency_binding import source_graph
            if actor['preparation_source'] is not None and actor['preparation_source'] != identity:
                raise OutsideScope('Preparation session is bound to another source build graph')
            graph = source_graph(descriptor, identity)
            source = next(s for s in descriptor['sources'] if s['id'] == identity)
            grants = scope(json.loads(actor['grants']))
            if not source['allow_build'] or any('read' not in grants.get(r, set()) for r in source['resources']):
                raise OutsideScope('Source build graph requires approved source read grants')
            descriptor = graph
        extras = {}
        selected = pins(descriptor['pins'], extras=extras) if descriptor['pins'] else {}
        if not {'pypi:' + n for n in selected} <= set(json.loads(actor['packages'])):
            raise OutsideScope('Local build dependencies exceed session package grants')
        verify_inputs(bundle)
    rules = bundle['policy']['project']['packages']
    provider = provider or provider_for(store, bundle, 'pypi')
    records = []
    for name, version in selected.items():
        record = provider.assess(name, version)
        if record.get('name') != name or record.get('version') != version:
            raise EvidenceError('Local build dependency evidence identity mismatch')
        if evaluate(record, rules):
            raise EvidenceError('Local build dependency violates the reviewed package policy')
        records.append(record)
    verify_artifacts(bundle, records, source=identity)
    total, wheels = 0, {}
    compatible = set(target_tags(python)) if records else set()
    for record in records:
        filename = record.get('filename', '')
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise EvidenceError('Unsafe local build dependency filename')
        try:
            name, version, _, tags = parse_wheel_filename(filename)
        except ValueError as exc:
            raise EvidenceError('Local build dependencies must be reviewed wheels') from exc
        if (name != record['name'] or str(version) != record['version'] or
                not {str(t) for t in tags} & compatible):
            raise EvidenceError('Incompatible local build dependency identity or runtime')
        if not rules.get('allow_native_wheels', False) and not any(
                t.interpreter == 'py3' and t.abi == 'none' and t.platform == 'any' for t in tags):
            raise EvidenceError('Native build dependency needs native-wheel approval')
        path = destination / filename
        provider.download(record, path)
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise EvidenceError('Local build dependency is not a regular artifact')
        total += path.stat().st_size
        if total > 512 * 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise EvidenceError('Local build dependency size or digest mismatch')
        wheels[name] = path
    validate_wheels(wheels, selected, environment=target_environment(python), extended=True, extras=extras)
    (destination / 'constraints.txt').write_text(''.join(n + '==' + v + '\n' for n, v in selected.items()))
    return selected, records


def run_source_build(store, token, identity, command, output):
    """Only this source adapter opts a pending credential into build supervision."""
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        purpose = actor['preparation_source']
        if purpose is not None and purpose != identity:
            raise OutsideScope('Preparation session is bound to another source')
    return run_build(store, token, command, output, **({'preparation': True} if purpose is not None else {}))


HOOK_REQUIREMENTS = r'''
import importlib,json,os,pathlib,site,sys
config = json.loads(sys.argv[1])
os.chdir('/target/source' + ('/' + config['path'] if config['path'] else ''))
site.addsitedir('/bootstrap')
sys.path[:0] = [str(pathlib.Path(p).resolve()) for p in config['backend_path']]
module, separator, attribute = config['backend'].partition(':')
backend = importlib.import_module(module)
if config['backend_path']:
    origin = pathlib.Path(backend.__file__).resolve()
    if not any(origin.is_relative_to(pathlib.Path(p).resolve()) for p in config['backend_path']):
        raise RuntimeError('Backend did not originate in its declared backend-path')
if separator:
    for part in attribute.split('.'):
        backend = getattr(backend, part)
hook = getattr(backend, config['hook'], lambda config_settings: [])
requirements = hook(config_settings=None)
pathlib.Path('/target/requirements.json').write_text(json.dumps(requirements))
'''


def checked_hook_requirements(value, source_name):
    """Hook output is a bounded proposal, never a package grant or resolver input yet."""
    if (not isinstance(value, list) or len(value) > 64 or
            any(not isinstance(r, str) or not r or len(r) > 4096 for r in value)):
        raise EvidenceError('Invalid or excessive backend requirements')
    result = []
    for raw in value:
        try:
            requirement = Requirement(raw)
        except ValueError:
            raise EvidenceError('Malformed backend requirement') from None
        if (requirement.url or canonicalize_name(requirement.name) == source_name or
                any(ord(c) < 32 or ord(c) == 127 for c in raw)):
            raise EvidenceError('Backend requirement has an unsafe source or identity')
        normalized = str(requirement)
        if normalized not in result:
            result.append(normalized)
    return result


def discover_build_requirements(store, token, identity, *, provider=None):
    """Call only the approved PEP 517/660 requirement hook in pending preparation.

    This returns untrusted requirements for a later operator review. It never
    resolves them, installs them, changes policy, or publishes a package set.
    Actual wheel/editable construction remains owned by uv.
    """
    source, entries, python, approval = authorized_snapshot(store, token, identity, hooks_only=True)
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        project, bundle = store.project(db, actor['project'])
        if not project['setup_pending'] or actor['preparation_source'] != identity:
            raise OutsideScope('Build requirement discovery requires pending source preparation')
    _, build = project_metadata(entries, source['path'], source.get('dynamic_metadata'),
                                discovery=source['mode'] == 'discovery')
    hook = 'get_requires_for_build_' + ('editable' if source['mode'] == 'editable' else 'wheel')
    config = dict(path=source['path'], backend=build['build-backend'],
                  backend_path=build.get('backend-path', []), hook=hook)
    with tempfile.TemporaryDirectory(prefix='local-hooks-', dir=store.directory) as temporary:
        root = Path(temporary)
        output, artifacts, bootstrap = root / 'result', root / 'artifacts', root / 'bootstrap'
        output.mkdir()
        artifacts.mkdir()
        seed = output / 'source'
        seed.mkdir()
        materialize(entries, seed)
        _, records = assessed_artifacts(store, token, artifacts, python, provider=provider, identity=identity)
        if records:
            # The existing offline uv installer only unpacks assessed wheels.
            # Their startup hooks are executed below, inside the supervised build.
            install_wheels(artifacts, bootstrap, records, python=python)
        else:
            bootstrap.mkdir()
        command = runtime_namespace() + [
            '--ro-bind', str(bootstrap), '/bootstrap', '--bind', str(output), '/target',
            '--setenv', 'PATH', '/bootstrap/bin:/usr/bin:/bin',
            '--', python, '-I', '-S', '-c', HOOK_REQUIREMENTS, canonical(config)]
        current = authorized_snapshot(store, token, identity, hooks_only=True)
        if current[3] != approval or current[0] != source:
            raise Invalid('Build requirement approval changed; no hook executed')
        try:
            run_source_build(store, token, identity, command, output)
        except EvidenceError:
            raise EvidenceError('Confined build requirement discovery failed; no installation published') from None
        result = output / 'requirements.json'
        try:
            if (result.is_symlink() or not result.is_file() or result.stat().st_size > 64 * 4096 + 1024):
                raise EvidenceError('Missing or excessive backend requirement output')
            requirements = checked_hook_requirements(json.loads(result.read_bytes()), source['name'])
        except (ValueError, OSError) as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError('Malformed backend requirement output') from None
        current = authorized_snapshot(store, token, identity, hooks_only=True)
        if current[3] != approval or current[0] != source:
            raise Invalid('Build requirement approval changed; no proposal returned')
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            project, bundle = store.project(db, actor['project'])
            if project['stopped'] or bundle['approval']['sha256'] != approval:
                raise Invalid('Build requirement approval is no longer active')
            if not {'pypi:' + r['name'] for r in records} <= set(json.loads(actor['packages'])):
                raise OutsideScope('Build requirements exceed session package grants')
            if any(evaluate(r, bundle['policy']['project']['packages']) for r in records):
                raise EvidenceError('Build requirement evidence no longer permits discovery')
        return dict(source_id=identity, source_sha256=source['snapshot_sha256'],
                    policy_sha256=approval, hook=hook, requirements=requirements,
                    requirements_sha256=digest(requirements), runtime=python,
                    runtime_sha256=hashlib.sha256(Path(python).read_bytes()).hexdigest(),
                    runner_sha256=hashlib.sha256(HOOK_REQUIREMENTS.encode()).hexdigest(),
                    dependencies=[{k: r[k] for k in ('name', 'version', 'sha256')} for r in records])


def build_wheel(store, token, identity, *, provider=None):
    """Build exact approved bytes, then recheck authority before returning data.

    The caller must retain source authorization when publishing or using these
    bytes. This API deliberately does not put source-bearing data in registry caches.
    """
    source, entries, python, approval = authorized_snapshot(store, token, identity)
    if source['mode'] not in ('wheel', 'discovery'):
        raise Invalid('Editable approval requires editable installation')
    uv = os.environ.get('PTW_UV') or shutil.which('uv')
    if not uv or not Path(uv).is_file():
        raise EvidenceError('uv is required; no local build fallback')
    uv = Path(uv).resolve()
    tool_hash = hashlib.sha256(uv.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='local-build-', dir=store.directory) as temporary:
        root = Path(temporary)
        output = root / 'result'
        output.mkdir()
        seed = output / 'source'
        seed.mkdir()
        materialize(entries, seed)
        artifacts = root / 'artifacts'
        artifacts.mkdir()
        selected, records = assessed_artifacts(store, token, artifacts, python, provider=provider, identity=identity)
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            _, bundle = store.project(db, actor['project'])
            runtime_selected = reviewed_runtime(bundle['policy']['project']['python_dependencies'])
        # Only the explicitly bound snapshot is mounted. The original repository,
        # ambient home, network and registry configuration are unavailable.
        command = runtime_namespace() + [
            '--ro-bind', str(uv), '/uv', '--ro-bind', str(artifacts), '/artifacts',
            '--bind', str(output), '/target', '--', '/uv', '--no-config',
            '--offline', '--no-cache', '--no-python-downloads', 'build', '--wheel',
            '--no-sources', '--no-index', '--find-links', '/artifacts',
            '--build-constraints', '/artifacts/constraints.txt',
            '--python', python, '--out-dir', '/target/out',
            '/target/source' + ('/' + source['path'] if source['path'] else '')]
        current = authorized_snapshot(store, token, identity)
        if current[3] != approval or current[0] != source:
            raise Invalid('Local build approval changed; no backend executed')
        try:
            run_source_build(store, token, identity, command, output)
        except EvidenceError:
            # Backend diagnostics are untrusted and may contain source data.
            raise EvidenceError('Confined local build failed; no artifact published') from None
        wheels = list((output / 'out').glob('*.whl'))
        if len(wheels) != 1 or wheels[0].is_symlink() or not wheels[0].is_file():
            raise EvidenceError('Local build must produce exactly one regular wheel')
        wheel = wheels[0]
        try:
            name, version, _, tags = parse_wheel_filename(wheel.name)
        except ValueError as exc:
            raise EvidenceError('Invalid local wheel filename') from exc
        if name != source['name'] or (source['mode'] != 'discovery' and version != Version(source['version'])):
            raise EvidenceError('Local build produced an unexpected identity')
        if not {str(t) for t in tags} & set(target_tags(python)):
            raise EvidenceError('Local wheel is incompatible with reviewed runtime')
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            _, bundle = store.project(db, actor['project'])
            allow_native = bundle['policy']['project']['packages']['allow_native_wheels']
        validate_local_wheel_tags(wheel, tags, allow_native)
        discovered = None
        if source['mode'] != 'discovery':
            validate_wheels({name: wheel}, {**runtime_selected, name: str(version)},
                            environment=target_environment(python), extended=True,
                            extras={name: source.get('extras', [])})
        try:
            with zipfile.ZipFile(wheel) as archive:
                metadata_files = [m for m in archive.infolist() if m.filename.endswith('.dist-info/METADATA')]
                if len(metadata_files) != 1 or metadata_files[0].file_size > 1024 * 1024:
                    raise EvidenceError('Exactly one bounded local metadata file required')
                meta = BytesParser().parsebytes(archive.read(metadata_files[0]))
                if source['mode'] == 'discovery':
                    discovered = discovered_metadata(meta, entries, source, str(version))
                else:
                    validate_output_metadata(meta, entries, source)
        except (ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            if isinstance(exc, Invalid):
                raise
            raise EvidenceError('Invalid local build metadata') from exc
        data = wheel.read_bytes()
        current = authorized_snapshot(store, token, identity)
        if current[3] != approval or current[0] != source:
            raise Invalid('Local build approval changed; no artifact published')
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            _, bundle = store.project(db, actor['project'])
            if not {'pypi:' + n for n in selected} <= set(json.loads(actor['packages'])):
                raise OutsideScope('Local build dependencies exceed session package grants')
            if any(evaluate(record, bundle['policy']['project']['packages']) for record in records):
                raise EvidenceError('Local build dependency evidence no longer permits publication')
        receipt = dict(source_id=identity, source_sha256=source['snapshot_sha256'],
                          dependencies=[{k: r[k] for k in ('name', 'version', 'sha256')} for r in records],
                          policy_sha256=approval, runtime=python, uv_sha256=tool_hash,
                          runtime_sha256=hashlib.sha256(Path(python).read_bytes()).hexdigest(),
                          filename=wheel.name, sha256=hashlib.sha256(data).hexdigest())
        if discovered is not None:
            receipt['dynamic_metadata'] = discovered
            # Discovery never returns executable artifacts or publishes a set.
            return None, receipt
        return data, receipt


def validate_local_wheel_tags(path, tags, allow_native):
    """Check backend output declarations as data; native output needs policy approval."""
    from packaging.tags import parse_tag
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 50000 or sum(m.file_size for m in members) > 400 * 1024 * 1024:
                raise EvidenceError('Wheel exceeds expanded size limit')
            headers = [m for m in members if m.filename.endswith('.dist-info/WHEEL')]
            if len(headers) != 1 or headers[0].file_size > 65536:
                raise EvidenceError('Exactly one bounded WHEEL header required')
            header = BytesParser().parsebytes(archive.read(headers[0]))
            declared = set().union(*(parse_tag(t) for t in header.get_all('Tag', [])))
            pure = header.get_all('Root-Is-Purelib', [])
            if declared != tags or pure not in (['true'], ['false']):
                raise EvidenceError('Local wheel tags or library kind differ from filename')
            native = pure == ['false'] or any(t.abi != 'none' or t.platform != 'any' for t in tags)
            # Labels alone are insufficient for ordinary embedded native payloads.
            # This is a bounded format check, not arbitrary-code classification.
            for member in members:
                if member.is_dir():
                    continue
                with archive.open(member) as content:
                    magic = content.read(4)
                native |= (magic == b'\x7fELF' or Path(member.filename).suffix.lower() in ('.so', '.pyd', '.dll'))
            if native and not allow_native:
                raise EvidenceError('Local native output requires native-wheel approval')
    except (ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError('Invalid local wheel compatibility metadata') from exc


def discovered_optional(meta):
    """Invert the conventional PEP 621 extra guard, retaining environment markers.

    This is a bounded metadata adapter, not a general marker equivalence solver.
    Packaging validates both the original and the reconstructed requirements.
    Noncanonical boolean combinations of extra guards fail closed.
    """
    provided = meta.get_all('Provides-Extra', [])
    if len(provided) > 64 or any(len(e) > 128 for e in provided):
        raise EvidenceError('Discovered extras exceed review bounds')
    try:
        names = [canonicalize_name(e, validate=True) for e in provided]
        if len(names) != len(set(names)):
            raise EvidenceError('Duplicate discovered extra')
        optional, base = {n: [] for n in names}, []
        for raw in meta.get_all('Requires-Dist', []):
            req = Requirement(raw)
            metadata_requirement(raw)  # Reject URLs even for inactive extras.
            marker = str(req.marker) if req.marker else ''
            # Ignore quoted strings when detecting the PEP 508 extra variable.
            tokens = re.findall(r'"[^"]*"|\bextra\b', marker)
            if 'extra' not in tokens:
                base.append(raw)
                continue
            match = re.fullmatch(r'(?:\((.*)\) and |(.*) and )?extra == "([^"]+)"', marker)
            if match is None or tokens.count('extra') != 1:
                raise EvidenceError('Unsupported discovered extra guard; expected a final extra equality')
            extra = canonicalize_name(match[3], validate=True)
            if extra not in optional:
                raise EvidenceError('Discovered requirement references an undeclared extra')
            remaining = match[1] or match[2]
            req.marker = Marker(remaining) if remaining else None
            optional[extra].append(str(req))
        return optional, base
    except ValueError as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError('Invalid discovered optional metadata') from exc


def discovered_metadata(meta, entries, source, version):
    """Read untrusted output as bounded review data, without dependency approval."""
    declarations, _ = project_metadata(entries, source['path'], discovery=True)
    if (len(meta.get_all('Name', [])) != 1 or len(meta.get_all('Version', [])) != 1 or
            canonicalize_name(meta['Name']) != source['name'] or meta['Version'] != version or
            len(meta.get_all('Requires-Python', [])) > 1):
        raise EvidenceError('Invalid discovered distribution identity')
    values = {'version': version, 'dependencies': meta.get_all('Requires-Dist', []),
              'requires-python': meta.get('Requires-Python', '')}
    if 'version' not in declarations['dynamic'] and Version(version) != Version(declarations['version']):
        raise EvidenceError('Discovery changed a static version')
    if (len(version) > 128 or len(values['requires-python']) > 1024 or
            len(values['dependencies']) > 64 or any(len(r) > 4096 for r in values['dependencies'])):
        raise EvidenceError('Discovered requirements exceed review bounds')
    if 'optional-dependencies' in declarations['dynamic']:
        values['optional-dependencies'], values['dependencies'] = discovered_optional(meta)
    result = {k: values[k] for k in declarations['dynamic']}
    if 'dependencies' in result and 'optional-dependencies' not in result:
        # Requires-Dist also contains static optional declarations. Preserve their
        # source authority instead of relabeling them as discovered base inputs.
        optional, _, _ = declared_dependencies({**declarations, 'dependencies': []})
        static = {metadata_requirement(r) for r in optional}
        result['dependencies'] = [r for r in result['dependencies'] if metadata_requirement(r) not in static]
    # Static fields cannot be changed by discovery. The final resolver, policy
    # review and installation will separately require dependency closure.
    validate_output_metadata(meta, entries, {**source, 'mode': 'wheel', 'dynamic_metadata': result})
    return result


def validate_editable_install(site, source, selected, python, entries, *, allow_native=False):
    """Inspect installed data only; .pth and finder code run solely in confinement."""
    manifest = file_manifest(site)
    if any(v.startswith('symlink:') for v in manifest.values()):
        raise EvidenceError('Editable installed files must be regular files')
    if any(Path(p).name in ('sitecustomize.py', 'usercustomize.py') for p in manifest):
        raise EvidenceError('Editable backend supplied an unsupported startup hook')
    infos = list(site.glob('*.dist-info'))
    if len(infos) != 1:
        raise EvidenceError('Editable install must contain exactly one distribution')
    info = infos[0]
    try:
        name, version = info.name[:-10].rsplit('-', 1)
        if canonicalize_name(name) != source['name'] or Version(version) != Version(source['version']):
            raise ValueError()
        raw = (info / 'METADATA').read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError()
        meta = BytesParser().parsebytes(raw)
        validate_dependencies({source['name']: meta}, {**selected, source['name']: source['version']},
                              target_environment(python), extras={source['name']: source.get('extras', [])})
        validate_output_metadata(meta, entries, source)
        direct = json.loads((info / 'direct_url.json').read_text())
        url = 'file:///target' + ('/' + quote(source['path']) if source['path'] else '')
        if direct != {'url': url, 'dir_info': {'editable': True}}:
            raise ValueError()
        from packaging.tags import parse_tag
        header = (info / 'WHEEL').read_bytes()
        if len(header) > 65536:
            raise EvidenceError('Editable WHEEL header exceeds limit')
        wheel = BytesParser().parsebytes(header)
        tags = set().union(*(parse_tag(t) for t in wheel.get_all('Tag', [])))
        pure = wheel.get_all('Root-Is-Purelib', [])
        if pure not in (['true'], ['false']) or not tags:
            raise EvidenceError('Invalid editable wheel tags or library kind')
        if not {str(t) for t in tags} & set(target_tags(python)):
            raise EvidenceError('Editable output is incompatible with reviewed runtime')
        native = (pure == ['false'] or any(t.abi != 'none' or t.platform != 'any' for t in tags)
                  or any(native_file(site / p) for p in manifest))
        if native and not allow_native:
            raise EvidenceError('Editable native output requires native-wheel approval')
    except (KeyError, ValueError, OSError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError('Invalid editable installation metadata or origin') from exc
    return manifest, native


def collect_editable_artifacts(output, site, entries, inv, source, *, allow_native, omitted=()):
    """Retain in-place native outputs only inside explicitly bound source trees.

    Backend scratch and metadata outside those resources are discarded. Original
    inputs cannot be replaced. Artifacts stay private and are never host edits.
    """
    if (site / EDITABLE_ARTIFACTS).exists():
        raise EvidenceError('Editable output conflicts with reserved artifact storage')
    result = scan({**inv, 'root': str(output)}, source['resources'])
    if set(omitted) & result.keys():
        raise EvidenceError('Editable backend generated an excluded source path')
    for path, entry in entries.items():
        if (path not in result or stamp(result[path]) != stamp(entry)
                or result[path].get('mode') != entry.get('mode')):
            raise EvidenceError('Editable backend changed a reviewed source input')
    artifacts = {}
    for path, entry in result.items():
        if path in entries or entry['kind'] != 'file' or not native_file(output / path):
            continue
        if not allow_native:
            raise EvidenceError('Editable native output requires native-wheel approval')
        # Keep the runtime overlay within already reviewed directories. Generated
        # build trees and symlink-based editable layouts need a separate adapter.
        if str(Path(path).parent) not in entries:
            raise EvidenceError('Editable native artifact has no reviewed parent directory')
        destination = site / EDITABLE_ARTIFACTS / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(entry['data'])
        artifacts[path] = stamp(entry)
    return artifacts


def native_build_entries(entries, inv, source):
    """Select the actual build view, never infer a compiler's read set.

    Excluded files must not be materialized in the seed. This deliberately
    changes the build's inputs, including existence tests and include lookup.
    Unknown configurations retain the complete snapshot without a retry.
    """
    selected = {p: e for p, e in entries.items() if owner(inv, p) in source['resources']}
    prefix = source['path'] + '/' if source['path'] else ''
    config = tomllib.loads(entries[prefix + 'pyproject.toml']['data'].decode())
    backend = config['build-system']
    settings = config.get('tool', {}).get('setuptools', {})
    extensions = settings.get('ext-modules', [])
    if (source.get('native_build_view') == 'full' or
            backend.get('build-backend') != 'setuptools.build_meta' or backend.get('backend-path') or
            source.get('dynamic_metadata') or settings.get('cmdclass') or
            any(prefix + p in entries for p in ('setup.py', 'setup.cfg')) or
            not backend.get('requires') or
            any(canonicalize_name(Requirement(r).name) not in {'setuptools', 'wheel'} or
                Requirement(r).extras for r in backend['requires']) or
            not isinstance(extensions, list) or not extensions):
        return selected
    # Only src-layout implicit namespace discovery tolerates omitted __init__.py
    # files. Do not rewrite the authoritative pyproject to enable discovery.
    if (selected.get(prefix + 'src', {}).get('kind') != 'dir' or
            set(settings) - {'ext-modules', 'packages', 'package-dir'} or
            settings.get('package-dir', {'': 'src'}) != {'': 'src'}):
        return selected
    packages = settings.get('packages', {'find': {'where': ['src']}})
    if not isinstance(packages, dict) or set(packages) != {'find'}:
        return selected
    find = packages['find']
    if (not isinstance(find, dict) or set(find) - {'where', 'namespaces'} or
            find.get('where') != ['src'] or find.get('namespaces', True) is not True):
        return selected
    dependencies = set()
    for extension in extensions:
        if (not isinstance(extension, dict) or not extension.get('sources') or
                set(extension) - {'name', 'sources', 'depends'}):
            return selected
        for field in ('sources', 'depends'):
            paths = extension.get(field, [])
            if not isinstance(paths, list):
                return selected
            for path in paths:
                # Globs, directories and external compiler dependencies do not
                # establish a bounded input set. Retain the full binding.
                if not isinstance(path, str) or any(c in path for c in '*?['):
                    return selected
                try:
                    relative(path)
                except Invalid:
                    return selected
                name = prefix + path
                if name not in selected or selected[name]['kind'] != 'file':
                    return selected
                dependencies.add(name)
    fixed = build_entries(selected, inv, source)
    return {p: e for p, e in selected.items() if p in fixed or p in dependencies or
            e['kind'] != 'file' or not p.endswith('.py') or not p.startswith(prefix + 'src/') or
            inv['resources'][owner(inv, p)].get('kind') != 'tree'}


def verify_build_receipt(source, receipt):
    if 'build_dependencies' in source:
        expected = [{k: r[k] for k in ('name', 'version', 'sha256')}
                    for r in source['build_dependencies']['artifacts']]
        actual = receipt.get('build_dependencies')
        if (not isinstance(actual, list) or
                sorted(actual, key=canonical) != sorted(expected, key=canonical)):
            raise Invalid('Source build dependency receipt differs from review')


def verify_native_reuse(bundle, source, receipt, entries):
    verify_build_receipt(source, receipt)
    if receipt.get('native_editable'):
        binding = receipt.get('native_binding')
        if binding is not None:
            if (not isinstance(binding, dict) or set(binding) != {'version', 'view', 'sha256'} or
                    type(binding['version']) is not int or binding['version'] != 1 or
                    binding['view'] not in ('full', PROJECTED_BUILD) or
                    binding['view'] != source.get('native_build_view', 'full') or
                    receipt.get('source_sha256') != source['snapshot_sha256']):
                raise Invalid('Invalid compiled editable binding; review and prepare again')
            selected = (native_build_entries(entries, bundle['inventory'], source)
                        if binding['view'] == PROJECTED_BUILD else
                        {p: e for p, e in entries.items() if owner(bundle['inventory'], p) in source['resources']})
            expected = binding['sha256']
        else:
            # Old suffix-based native_inputs_sha256 receipts did not enforce a
            # projected namespace. They must retain full original binding.
            selected = {p: e for p, e in entries.items() if owner(bundle['inventory'], p) in source['resources']}
            expected = receipt['source_sha256']
        if snapshot_digest(selected) != expected:
            raise Invalid('Compiled editable source changed; review and prepare again')


def editable_artifact_entries(mount, receipt):
    """Read an already authorized, integrity-checked package set as bounded data."""
    paths = {}
    for part in receipt_sources(receipt):
        additions = part.get('editable_artifacts', {})
        if paths.keys() & additions.keys():
            raise Invalid('Combined editable artifacts collide')
        paths.update(additions)
    if not paths:
        return {}
    result = scan({'root': str(mount / EDITABLE_ARTIFACTS), 'resources': {
        str(i): {'path': relative(p)} for i, p in enumerate(paths)}}, [str(i) for i in range(len(paths))])
    if set(result) != set(paths) or any(e['kind'] != 'file' or stamp(e) != paths[p] for p, e in result.items()):
        raise Invalid('Editable build artifact integrity check failed')
    return result


def install_editable(store, token, identity, *, provider=None):
    """Publish a real PEP 660 installation, bound to command-specific source access."""
    return install_source(store, token, identity, mode='editable', provider=provider)


def install_wheel(store, token, identity, *, provider=None):
    """Publish an approved local wheel without registry classification or grants."""
    return install_source(store, token, identity, mode='wheel', provider=provider)


def install_source(store, token, identity, *, mode, provider=None, payload=None):
    """Share installation validation and atomic publication for local sources.

    Trusted operator adapter, not an approval endpoint. Registry graph and source
    execution must already be reviewed in the active policy. Editable wheels are
    discarded by uv; only the installed tree and a bound receipt are retained.
    """
    source, entries, python, approval = authorized_snapshot(store, token, identity)
    if source['mode'] != mode or mode not in ('editable', 'wheel'):
        raise OutsideScope('Local installation has no explicit ' + mode + ' approval')
    if any(p == '.ptw-local-site' or p.startswith('.ptw-local-site/') for p in entries):
        raise Invalid('Local source conflicts with the reserved installation directory')
    uv = os.environ.get('PTW_UV') or shutil.which('uv')
    if not uv or not Path(uv).is_file():
        raise EvidenceError('uv is required; no local install fallback')
    uv = Path(uv).resolve()
    from .python_lock import source_lock_required, validate_source_lock
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        _, bundle = store.project(db, actor['project'])
    descriptor = bundle['policy']['project']['python_dependencies']
    if len(descriptor.get('sources', [])) > 1 and payload is None:
        raise OutsideScope('Multiple local sources require atomic combined preparation')
    runtime_selected = reviewed_runtime(descriptor)
    lock_validation = None
    if source_lock_required(bundle, source):
        lock_validation = validate_source_lock(store, token, identity, provider=provider,
            groups=tuple(bundle['policy']['project']['python_dependencies'].get('groups', ('dev', 'test'))))
    with tempfile.TemporaryDirectory(prefix='local-install-', dir=store.directory) as temporary:
        root = Path(temporary)
        output, artifacts = root / 'result', root / 'artifacts'
        output.mkdir()
        artifacts.mkdir()
        selected, records = assessed_artifacts(store, token, artifacts, python, provider=provider)
        build_artifacts, build_records = artifacts, records
        if 'build_dependencies' in source:
            build_artifacts = root / 'build-artifacts'
            build_artifacts.mkdir()
            _, build_records = assessed_artifacts(store, token, build_artifacts, python,
                                                  provider=provider, identity=identity)
        build_receipt = None
        editable_receipt = {}
        if mode == 'wheel':
            materialize(entries, output)
            data, build_receipt = build_wheel(store, token, identity, provider=provider)
            if (build_receipt['policy_sha256'] != approval or
                    build_receipt['source_sha256'] != source['snapshot_sha256'] or
                    build_receipt['dependencies'] != [{k: r[k] for k in ('name', 'version', 'sha256')} for r in build_records]):
                raise Invalid('Local build inputs changed before installation')
            local_artifacts = root / 'local-artifacts'
            local_artifacts.mkdir()
            wheel = local_artifacts / build_receipt['filename']
            wheel.write_bytes(data)
            site = output / '.ptw-local-site'
            # This is an artifact identity, not fabricated registry evidence.
            artifact = dict(name=source['name'], filename=wheel.name, sha256=build_receipt['sha256'])
            install_wheels(local_artifacts, site, [artifact], python=python)
            local_manifest = file_manifest(site)
            if any(v.startswith('symlink:') for v in local_manifest.values()):
                raise EvidenceError('Local wheel installation contains a symbolic link')
            infos = list(site.glob('*.dist-info'))
            if len(infos) != 1:
                raise EvidenceError('Local wheel installation must contain one distribution')
            meta = BytesParser().parsebytes((infos[0] / 'METADATA').read_bytes())
            validate_dependencies({source['name']: meta}, runtime_selected,
                                  target_environment(python), extras={source['name']: source.get('extras', [])})
            validate_output_metadata(meta, entries, source)
        else:
            local_manifest, editable_receipt = prepare_editable(store, token, identity, source, entries, python,
                                                                approval, uv, output, build_artifacts, runtime_selected)
        site = output / '.ptw-local-site'
        # Install the assessed registry graph separately. A backend cannot modify
        # these files, and no local output may overwrite a registry file.
        if records and payload is None:
            registry_site = root / 'registry-site'
            install_wheels(artifacts, registry_site, records, extended=True, python=python)
            registry_manifest = file_manifest(registry_site)
            collisions = local_manifest.keys() & registry_manifest.keys()
            # uv's empty target lock is inert after both installers have exited.
            empty_hash = hashlib.sha256(b'').hexdigest()
            if local_manifest.get('.lock') == registry_manifest.get('.lock') == empty_hash:
                collisions.discard('.lock')
            if collisions:
                raise EvidenceError('Local and registry installed files collide')
            shutil.copytree(registry_site, site, dirs_exist_ok=True)
        elif payload is None:
            (site / 'sitecustomize.py').write_text(
                'import pathlib,site\nsite.addsitedir(str(pathlib.Path(__file__).parent))\n')
        # Validate the combined metadata so extras requested by the local project
        # propagate through registry dependencies, including editable hook additions.
        metadata = {}
        for info in site.glob('*.dist-info'):
            meta = BytesParser().parsebytes((info / 'METADATA').read_bytes())
            name = canonicalize_name(meta.get('Name', ''), validate=True)
            if name in metadata:
                raise EvidenceError('Duplicate local installation distribution')
            metadata[name] = meta
        expected = {source['name']} if payload is not None else {*selected, source['name']}
        if set(metadata) != expected:
            raise EvidenceError('Local installation distribution set differs from review')
        validate_dependencies(metadata, runtime_selected,
                              target_environment(python), extras={source['name']: source.get('extras', [])})
        manifest = file_manifest(site)
        receipt = dict(source_id=identity, source_sha256=source['snapshot_sha256'],
                       dependencies=[{k: r[k] for k in ('name', 'version', 'sha256')} for r in records],
                       policy_sha256=approval, runtime=python,
                       runtime_sha256=hashlib.sha256(Path(python).read_bytes()).hexdigest(),
                       uv_sha256=hashlib.sha256(uv.read_bytes()).hexdigest(), manifest_sha256=digest(manifest))
        if build_receipt is not None:
            receipt['wheel'] = build_receipt
        if 'build_dependencies' in source:
            receipt['build_dependencies'] = [{k: r[k] for k in ('name', 'version', 'sha256')} for r in build_records]
        if lock_validation is not None:
            receipt['lock_validation'] = lock_validation
        receipt.update(editable_receipt)
        if payload is not None:
            # Trusted setup-only staging, never a published or mountable set.
            # The next backend receives its own source namespace, not this tree.
            current = authorized_snapshot(store, token, identity)
            if current[0] != source or current[3] != approval:
                raise Invalid('Local source changed before staging')
            shutil.copytree(site, payload)
            return dict(site=payload, source=source, selected=selected, records=records, build_records=build_records,
                        manifest=manifest, receipt=receipt)
        if any(evaluate(r, bundle['policy']['project']['packages']) for r in build_records):
            raise EvidenceError('Build dependency evidence no longer permits publication')
        return publish_install(store, token, identity, source, approval, site, selected, records, manifest, receipt)


def prepare_editable(store, token, identity, source, entries, python, approval, uv, output, artifacts, selected):
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        _, bundle = store.project(db, actor['project'])
        inv = bundle['inventory']
    view = source.get('native_build_view', 'full')
    if view not in ('full', PROJECTED_BUILD):
        raise Invalid('Unknown editable build view')
    seed = native_build_entries(entries, inv, source) if view == PROJECTED_BUILD else entries
    # No original source mount, cache or backup enters this namespace. The
    # supervisor terminates all builders before exporting the projected tree.
    materialize(seed, output)
    command = runtime_namespace() + [
        '--ro-bind', str(uv), '/uv', '--ro-bind', str(artifacts), '/artifacts',
        '--bind', str(output), '/target', '--', '/uv', '--no-config', '--offline',
        '--no-cache', '--no-python-downloads', 'pip', 'install', '--no-deps',
        '--no-sources', '--no-index', '--find-links', '/artifacts',
        '--build-constraints', '/artifacts/constraints.txt', '--link-mode', 'copy',
        '--python', python, '--target', '/target/.ptw-local-site',
        '--editable', '/target' + ('/' + source['path'] if source['path'] else '')]
    current = authorized_snapshot(store, token, identity)
    if current[3] != approval or current[0] != source:
        raise Invalid('Local build approval changed; no backend executed')
    try:
        run_source_build(store, token, identity, command, output)
    except EvidenceError:
        raise EvidenceError('Confined editable install failed; no package set published') from None
    site = output / '.ptw-local-site'
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        _, bundle = store.project(db, actor['project'])
        if bundle['approval']['sha256'] != approval:
            raise Invalid('Local build approval changed; no package set published')
        allow_native = bundle['policy']['project']['packages']['allow_native_wheels']
    _, native = validate_editable_install(site, source, selected, python, entries, allow_native=allow_native)
    generated = collect_editable_artifacts(output, site, seed, bundle['inventory'], source,
                                            allow_native=allow_native, omitted=entries.keys() - seed.keys())
    receipt = {'native_editable': native or bool(generated), 'editable_artifacts': generated}
    if receipt['native_editable']:
        receipt['native_binding'] = {'version': 1, 'view': view, 'sha256': snapshot_digest(seed)}
    return file_manifest(site), receipt


def publish_install(store, token, identity, source, approval, site, selected, records, manifest, receipt):
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        project, bundle = store.project(db, actor['project'])
        if project['stopped'] or bundle['approval']['sha256'] != approval:
            raise Invalid('Local installation authority changed; no package set published')
        from .dependency_binding import verify_inputs
        from .workspace import Workspace
        Workspace(store).integrity(db, actor['project'], bundle)
        verify_inputs(bundle)
        verify(bundle['policy']['project']['python_runtime'])
        from .python_lock import verify_source_lock
        verify_source_lock(bundle, source, receipt)
        verify_build_receipt(source, receipt)
        current_entries = scan(bundle['inventory'], source['resources'])
        reuse_source(bundle, actor, identity, {'resources': source['resources']}, current_entries)
        if snapshot_digest(current_entries) != source['snapshot_sha256']:
            raise Invalid('Local source changed during installation; no package set published')
        names = {'pypi:' + n for n in selected}
        if not names <= set(json.loads(actor['packages'])):
            raise OutsideScope('Local build dependencies exceed session package grants')
        if any(evaluate(r, bundle['policy']['project']['packages']) for r in records):
            raise EvidenceError('Local dependency evidence no longer permits publication')
        return publish_set(store, db, actor['project'], approval, site, names, manifest, receipt)


def publish_set(store, db, project, approval, site, names, manifest, receipt):
    """Caller holds the controller lock and has revalidated all constituent inputs."""
    sets = store.directory / 'package-sets'
    sets.mkdir(mode=0o700, exist_ok=True)
    package_id = 'pkg_' + secrets.token_hex(12)
    destination = sets / package_id
    try:
        db.execute('BEGIN IMMEDIATE')
        os.rename(site, destination)
        db.execute('INSERT INTO package_sets(id,project,names,manifest,created,ecosystem,policy_sha256,local_source) '
                   'VALUES(?,?,?,?,?,?,?,?)', (package_id, project, canonical(sorted(names)),
                   canonical(manifest), time.time(), 'pypi', approval, canonical(receipt)))
        db.commit()
    except BaseException:
        db.rollback()
        if destination.exists():
            shutil.rmtree(destination)
        raise
    return {'package_set': package_id, **receipt}
