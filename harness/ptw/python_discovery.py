"""Operator review for unknown local metadata, using the pending controller."""
import getpass
import copy
from .policy import Invalid, approve, compile_policy, digest, load, save
from .store import Store


def recover(directory):
    """Interrupted discovery cannot leave live preparation authority on retry."""
    journal = directory / 'discovery-journal.json'
    if not journal.exists():
        return
    from .supervisor import Supervisor
    record = load(journal)
    store = Store(directory / 'controller')
    with store.locked() as db:
        row = db.execute('SELECT setup_pending FROM projects WHERE id=?', (record['project'],)).fetchone()
    if row is not None and row['setup_pending']:
        store.stop(record['project'], 'Interrupted or rejected metadata discovery; history retained')
        if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
            raise Invalid('Discovery termination is unconfirmed')


def review(repo, directory, stage, shadow, scope, root, options, goal, warn, stop, identity, *,
           native_wheels=False, hooks_only=False, editable_paths=(), previous=None, full_build=False,
           source_identity='python-project', prior=None, source_paths=None, local_names=()):
    from .dependency_resolution import resolve_python
    from .monitor import ensure
    from .onboarding import ask, safe_text
    from .python_local import build_wheel, describe_source, discover_build_requirements
    from .setup_templates import RULES, template
    from .setup_transaction import atomic
    from .supervisor import Supervisor
    provider_options = {}
    if prior is not None and (not local_names or
            previous is not None and previous['policy_sha256'] != prior['approval']['sha256']):
        raise Invalid('Combined discovery requires the current pending approval')
    if local_names:
        provider_options['build_only'] = True
    if (stage / 'pypi-registry.json').exists():
        from .registry import private_json
        provider_options['registry_config'] = private_json(stage / 'pypi-registry.json')
    plan = resolve_python(shadow / root, stage / 'discovery-resolution', {**RULES, 'allow_native_wheels': native_wheels},
                          **options, **provider_options, local_build=True, discovery=not hooks_only)
    if set(local_names) & {a['name'] for a in plan['artifacts']}:
        raise Invalid('Discovery graph contains a reviewed local source identity')
    save(stage / 'discovery-plan.json', plan)
    from .package_evidence import pins
    names = ['pypi:' + n for n in pins(plan['pins'], extras={})] if plan['pins'] else []
    prefix = root + '/' if root else ''
    old = prior['policy']['project']['python_dependencies'] if prior else None
    metadata = sorted(set([prefix + n for n in plan['inputs']] + (list(old['inputs']) if old else [])))
    proposal, inv = template(repo, identity, goal, scope, metadata, [], names, warn, stop)
    proposal['project']['packages']['allow_native_wheels'] = native_wheels
    mapping = {v['path']: k for k, v in inv['resources'].items()}
    paths = ({n for n in scope if n.startswith(prefix)} if source_paths is None else set(source_paths)) | {
        prefix + 'pyproject.toml'}
    if any(n not in scope or not n.startswith(prefix) for n in paths - {prefix + 'pyproject.toml'}):
        raise Invalid('Discovery source paths must be explicitly selected inside the project')
    if 'uv.lock' in plan['inputs']:
        paths.add(prefix + 'uv.lock')
    if editable_paths and (not hooks_only or any(n not in scope or n not in paths for n in editable_paths)):
        raise Invalid('Editable hook discovery requires explicitly selected source paths')
    source = describe_source(inv, [mapping[n] for n in sorted(paths)], identity=source_identity,
                             path=root, allow_build=True, discovery=not hooks_only,
                             editable_resources=[mapping[n] for n in editable_paths], extras=options.get('extras', ()),
                             dynamic_metadata=options.get('dynamic_metadata'), full_build=full_build)
    if previous is not None and (not hooks_only or not editable_paths or
            source['snapshot_sha256'] != previous['source_sha256']):
        raise Invalid('Editable discovery requires the unchanged metadata discovery source')
    proposal['project']['python_runtime'] = plan['runtime']
    proposal['project']['python_dependencies'] = {
        'inputs': {prefix + n: h for n, h in plan['inputs'].items()},
        'pins': plan['pins'], 'artifacts': plan['artifacts'], 'sources': [source]}
    combined_sources = bool(local_names)
    if combined_sources:
        # Discovery policies retain earlier reviewed source bindings, but each
        # backend receives only its own graph and registered source namespace.
        descriptor = proposal['project']['python_dependencies']
        source['build_dependencies'] = {k: plan[k] for k in ('pins', 'artifacts')}
        descriptor.update(pins=[], artifacts=[])
        if prior:
            runtime = lambda r: {k: v for k, v in r.items() if k not in ('requires_python', 'version_request')}
            if runtime(plan['runtime']) != runtime(prior['policy']['project']['python_runtime']):
                raise Invalid('Combined discovery changed the selected runtime')
            if any(old['inputs'][p] != h for p, h in descriptor['inputs'].items() if p in old['inputs']):
                raise Invalid('Combined discovery input binding changed')
            descriptor['inputs'] = {**old['inputs'], **descriptor['inputs']}
            previous_sources = copy.deepcopy(old['sources'])
            for item in previous_sources:
                for field in ('resources', 'editable_resources'):
                    if field in item:
                        item[field] = [mapping[prior['inventory']['resources'][r]['path']] for r in item[field]]
            matching = [s for s in previous_sources if s['id'] == source_identity]
            if matching:
                if not (hooks_only and previous is not None and len(matching) == 1 and
                        matching[0]['mode'] == 'discovery'):
                    raise Invalid('Combined discovery cannot replace an unrelated source')
                descriptor['sources'] = [source if s['id'] == source_identity else s for s in previous_sources]
            else:
                descriptor['sources'] = previous_sources + [source]
        names = sorted({'pypi:' + a['name'] for s in descriptor['sources']
                        for a in s['build_dependencies']['artifacts']})
        proposal['project']['packages']['allowed_names'] = names
        for task in proposal['tasks']:
            task['packages'] = names
    if 'registry_config' in provider_options:
        proposal['project']['python_dependencies']['registry_config_sha256'] = digest(provider_options['registry_config'])
    compiled = compile_policy(proposal, inv)
    save(stage / 'discovery-draft.json', compiled)
    description = ('Build requirement discovery: execute only the offline ' + source['mode'] + ' requirement hook'
                   if hooks_only else 'Dynamic metadata discovery: execute offline requirement hooks and a wheel build')
    print(safe_text(description + ' on these source paths: ' +
          ', '.join(sorted(paths)) + '\nBuild dependencies: ' + (', '.join(plan['pins']) or 'none') +
          '\nRuntime: ' + plan['runtime']['executable'] + '\nWarning/stop: ' + str(warn) + '/' + str(stop) +
          '\nNative wheels: ' + str(native_wheels) +
          ('\nEditable native build view: ' + source['native_build_view'] +
           ('; compiled output binds every source file' if source['native_build_view'] == 'full' else
            '; mutable Python implementation files are absent during build, except declared inputs')
           if editable_paths else '') +
          '\nNo installation or ordinary session is authorized. A second review is required.' +
          '\nDiscovery policy hash: ' + digest(compiled)), flush=True)
    while True:
        answer = ask('Approve ' + ('build requirement discovery' if hooks_only else 'metadata discovery') +
                     '? Type yes, details, reject or cancel', 'no').lower()
        if answer != 'details':
            break
        from .onboarding import review_text
        print(safe_text(review_text(compiled)), flush=True)
    if answer != 'yes':
        raise Invalid('Metadata discovery not approved; no backend executed')
    bundle = approve(proposal, inv, digest(compiled), getpass.getuser())
    save(stage / 'discovery-approved.json', bundle)
    # Durable identity precedes activation. No generated project file exists yet.
    if previous is None and prior is None:
        atomic(directory / 'discovery-journal.json', {'project': identity, 'stage': str(stage)})
    store = Store(directory / 'controller')
    if 'registry_config' in provider_options:
        config = provider_options['registry_config']
        destination = store.directory / ('pypi-registry-' + digest(config) + '.json')
        if destination.exists():
            if load(destination) != config:
                raise Invalid('Private registry configuration integrity failure')
        else:
            save(destination, config)
    ensure(store)
    store.activate(bundle, setup_pending=True,
                   **({'discovery_sha256': previous['policy_sha256']} if previous is not None else
                      {'discovery_sha256': prior['approval']['sha256']} if prior is not None else {}))
    actor = store.register_preparation(identity, 'work', source['id'], bundle['approval']['sha256'])
    try:
        requirements = discover_build_requirements(store, actor['token'], source['id'])
        save(stage / 'discovery-build-requirements.json', requirements)
    finally:
        store.close_session(actor['token'])
        if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
            raise Invalid('Discovery termination is unconfirmed')
    combined = list(dict.fromkeys([*options.get('build_requirements', []), *requirements['requirements']]))
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    if set(local_names) & {canonicalize_name(Requirement(r).name) for r in combined}:
        raise Invalid('Discovery hook cannot introduce a local build dependency')
    if requirements['requirements']:
        # Hook output is only a proposal. Resolve with the original constraints,
        # assess every artifact, then request a new approval before using it.
        expanded = resolve_python(shadow / root, stage / 'discovery-build-resolution',
            {**RULES, 'allow_native_wheels': native_wheels},
            **{**options, 'build_requirements': combined}, **provider_options,
            local_build=True, discovery=not hooks_only)
        save(stage / 'discovery-build-plan.json', expanded)
        if set(local_names) & {a['name'] for a in expanded['artifacts']}:
            raise Invalid('Discovery graph contains a reviewed local source identity')
        if expanded['runtime'] != plan['runtime'] or expanded['inputs'] != plan['inputs']:
            raise Invalid('Discovery runtime or metadata changed during build requirement resolution')
        refined = copy.deepcopy(proposal)
        if combined_sources:
            descriptor = refined['project']['python_dependencies']
            current = next(s for s in descriptor['sources'] if s['id'] == source_identity)
            current['build_dependencies'] = {k: expanded[k] for k in ('pins', 'artifacts')}
            names = sorted({'pypi:' + a['name'] for s in descriptor['sources']
                            for a in s['build_dependencies']['artifacts']})
        else:
            names = ['pypi:' + n for n in pins(expanded['pins'], extras={})] if expanded['pins'] else []
        refined['project']['packages']['allowed_names'] = names
        for task in refined['tasks']:
            task['packages'] = names
        if not combined_sources:
            refined['project']['python_dependencies'].update(
                {key: expanded[key] for key in ('pins', 'artifacts')})
        compiled = compile_policy(refined, inv)
        save(stage / 'discovery-build-draft.json', compiled)
        print(safe_text('Additional backend requirements: ' + ', '.join(requirements['requirements']) +
            '\nAssessed build graph: ' + ', '.join(expanded['pins']) +
            ('\nNo build or installation is authorized until the final review.' if hooks_only else
             '\nApproval authorizes one confined metadata build. No installation is authorized.') +
            '\nBuild policy hash: ' + digest(compiled)), flush=True)
        while True:
            answer = ask('Approve additional build requirements? Type yes, details, reject or cancel', 'no').lower()
            if answer != 'details':
                break
            from .onboarding import review_text
            print(safe_text(review_text(compiled)), flush=True)
        if answer != 'yes':
            raise Invalid('Additional build requirements not approved; no build or installation authorized')
        approved = approve(refined, inv, digest(compiled), getpass.getuser())
        store.activate(approved, setup_pending=True, discovery_sha256=bundle['approval']['sha256'])
        save(stage / 'discovery-build-approved.json', approved)
        bundle = approved
    if hooks_only:
        receipt = {**requirements, 'build_requirements': combined,
                   'policy_sha256': bundle['approval']['sha256']}
        save(stage / 'discovery-result.json', receipt)
        return receipt
    actor = store.register_preparation(identity, 'work', source['id'], bundle['approval']['sha256'])
    try:
        artifact, receipt = build_wheel(store, actor['token'], source['id'])
        if artifact is not None:
            raise Invalid('Discovery must not return an executable artifact')
        receipt['build_requirements'] = requirements['requirements']
        save(stage / 'discovery-result.json', receipt)
    finally:
        store.close_session(actor['token'])
        if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
            raise Invalid('Discovery termination is unconfirmed')
    print(safe_text('Discovered metadata for the final review: ' + str(receipt['dynamic_metadata'])), flush=True)
    return receipt
