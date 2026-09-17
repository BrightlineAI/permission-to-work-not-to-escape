"""Bind preparation and reuse to reviewed declarations and artifact identities."""
import hashlib
import json
import os

from .policy import Invalid, OutsideScope, digest, open_resource, scope
from .workspace_policy import relative


def verify_inputs(bundle):
    inputs = {}
    for ecosystem in ('python_dependencies', 'npm_dependencies'):
        descriptor = bundle['policy']['project'].get(ecosystem)
        if descriptor:
            for name, expected in descriptor['inputs'].items():
                if name in inputs and inputs[name] != expected:
                    raise Invalid('Conflicting dependency input bindings')
                inputs[name] = expected
    for name, expected in inputs.items():
        relative(name)
        try:
            fd = open_resource(bundle['inventory'], name, os.O_RDONLY)
            with os.fdopen(fd, 'rb') as stream:
                content = stream.read(8 * 1024 * 1024 + 1)
        except OSError as exc:
            raise Invalid('Reviewed dependency input is missing or replaced; review a dependency revision') from exc
        if len(content) > 8 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected:
            raise Invalid('Reviewed dependency input changed; review a dependency revision')


def verify_npm(bundle, lock, evidence=None):
    descriptor = bundle['policy']['project'].get('npm_dependencies')
    if isinstance(lock, dict) and lock.get('manager') == 'pnpm' and not descriptor:
        raise Invalid('pnpm installation requires reviewed authoritative inputs')
    if descriptor:
        if digest(lock) != descriptor['lock_sha256']:
            raise Invalid('Install differs from the reviewed npm lock')
        if evidence is not None:
            actual = [{k: e[k] for k in ('name', 'version', 'url', 'integrity')} for e in evidence]
            order = lambda e: (e['name'], e['version'])
            if sorted(actual, key=order) != sorted(descriptor['artifacts'], key=order):
                raise Invalid('npm artifact origin or integrity changed after review')
    from .npm import installation_plan
    plan = installation_plan(lock)
    if isinstance(lock, dict) and lock.get('manager') == 'pnpm':
        prefix = descriptor.get('root', '')
        expected = {(prefix + '/' if prefix else '') + name: hashlib.sha256(text.encode()).hexdigest()
                    for name, text in plan.files.items()}
        if expected != descriptor['inputs']:
            raise Invalid('pnpm request metadata differs from reviewed input bindings')
    if set(plan.locals) != {s['path'] for s in (descriptor or {}).get('sources', [])}:
        raise Invalid('Local npm packages require their exact approved source descriptor')


def verify_local_sources(bundle, actor, definition=None):
    """A package grant never implies source read authority, even for a cached set."""
    descriptor = bundle['policy']['project'].get('npm_dependencies', {})
    grants = scope(json.loads(actor['grants']))
    sources = []
    for source in descriptor.get('sources', []):
        if definition is not None and not set(source['resources']) & set(definition['resources']):
            continue
        if any('read' not in grants.get(r, set()) for r in source['resources']):
            raise OutsideScope('Local package source exceeds session read grants')
        if definition is not None and not set(source['resources']) <= set(definition['resources']):
            raise OutsideScope('Local package source exceeds command inputs')
        sources.append(source)
    return {**descriptor, 'sources': sources,
            'excluded_sources': [s['path'] for s in descriptor.get('sources', []) if s not in sources]}


def verify_selection(bundle, selected, extras):
    descriptor = bundle['policy']['project'].get('python_dependencies')
    if descriptor:
        from .package_evidence import pins
        approved_extras = {}
        approved = pins(descriptor['pins'], extras=approved_extras) if descriptor['pins'] else {}
        if approved != selected or approved_extras != (extras or {}):
            raise Invalid('Install differs from the reviewed dependency resolution')


def verify_artifacts(bundle, evidence, *, source=None):
    descriptor = bundle['policy']['project'].get('python_dependencies')
    if source is not None:
        descriptor = source_graph(descriptor, source)
    if descriptor:
        expected = descriptor['artifacts']
        actual = [{k: record[k] for k in ('name', 'version', 'url', 'sha256')} for record in evidence]
        if sorted(actual, key=lambda e: e['name']) != sorted(expected, key=lambda e: e['name']):
            raise Invalid('Registry artifact identity or digest changed after dependency review')


def source_graph(descriptor, identity):
    """Explicit source build graph; legacy policies retain their reviewed union."""
    source = next((s for s in descriptor.get('sources', []) if s['id'] == identity), None)
    if source is None:
        raise Invalid('Unknown local source build graph')
    return source.get('build_dependencies', descriptor)
