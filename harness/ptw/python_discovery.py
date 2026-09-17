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
           native_wheels=False, hooks_only=False, editable_paths=(), previous=None):
    from .dependency_resolution import resolve_python
    from .monitor import ensure
    from .onboarding import ask, safe_text
    from .python_local import build_wheel, describe_source, discover_build_requirements
    from .setup_templates import RULES, template
    from .setup_transaction import atomic
    from .supervisor import Supervisor
    provider_options = {}
    if (stage / 'pypi-registry.json').exists():
        from .registry import private_json
        provider_options['registry_config'] = private_json(stage / 'pypi-registry.json')
    plan = resolve_python(shadow / root, stage / 'discovery-resolution', {**RULES, 'allow_native_wheels': native_wheels},
                          **options, **provider_options, local_build=True, discovery=not hooks_only)
    save(stage / 'discovery-plan.json', plan)
    from .package_evidence import pins
    names = ['pypi:' + n for n in pins(plan['pins'], extras={})] if plan['pins'] else []
    prefix = root + '/' if root else ''
    metadata = [prefix + n for n in plan['inputs']]
    proposal, inv = template(repo, identity, goal, scope, metadata, [], names, warn, stop)
    proposal['project']['packages']['allow_native_wheels'] = native_wheels
    mapping = {v['path']: k for k, v in inv['resources'].items()}
    paths = {n for n in scope if n.startswith(prefix)} | {prefix + 'pyproject.toml'}
    if editable_paths and (not hooks_only or any(n not in scope or n not in paths for n in editable_paths)):
        raise Invalid('Editable hook discovery requires explicitly selected source paths')
    source = describe_source(inv, [mapping[n] for n in sorted(paths)], identity='python-project',
                             path=root, allow_build=True, discovery=not hooks_only,
                             editable_resources=[mapping[n] for n in editable_paths], extras=options.get('extras', ()),
                             dynamic_metadata=options.get('dynamic_metadata'))
    if previous is not None and (not hooks_only or not editable_paths or
            source['snapshot_sha256'] != previous['source_sha256']):
        raise Invalid('Editable discovery requires the unchanged metadata discovery source')
    proposal['project']['python_runtime'] = plan['runtime']
    proposal['project']['python_dependencies'] = {
        'inputs': {prefix + n: h for n, h in plan['inputs'].items()},
        'pins': plan['pins'], 'artifacts': plan['artifacts'], 'sources': [source]}
    if provider_options:
        proposal['project']['python_dependencies']['registry_config_sha256'] = digest(provider_options['registry_config'])
    compiled = compile_policy(proposal, inv)
    save(stage / 'discovery-draft.json', compiled)
    description = ('Build requirement discovery: execute only the offline ' + source['mode'] + ' requirement hook'
                   if hooks_only else 'Dynamic metadata discovery: execute offline requirement hooks and a wheel build')
    print(safe_text(description + ' on these source paths: ' +
          ', '.join(sorted(paths)) + '\nBuild dependencies: ' + (', '.join(plan['pins']) or 'none') +
          '\nRuntime: ' + plan['runtime']['executable'] + '\nWarning/stop: ' + str(warn) + '/' + str(stop) +
          '\nNative wheels: ' + str(native_wheels) +
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
    if previous is None:
        atomic(directory / 'discovery-journal.json', {'project': identity, 'stage': str(stage)})
    store = Store(directory / 'controller')
    if provider_options:
        config = provider_options['registry_config']
        destination = store.directory / ('pypi-registry-' + digest(config) + '.json')
        if destination.exists():
            if load(destination) != config:
                raise Invalid('Private registry configuration integrity failure')
        else:
            save(destination, config)
    ensure(store)
    store.activate(bundle, setup_pending=True,
                   **({'discovery_sha256': previous['policy_sha256']} if previous is not None else {}))
    actor = store.register_preparation(identity, 'work', source['id'], bundle['approval']['sha256'])
    try:
        requirements = discover_build_requirements(store, actor['token'], source['id'])
        save(stage / 'discovery-build-requirements.json', requirements)
    finally:
        store.close_session(actor['token'])
        if any(not r['confirmed_stopped'] for r in Supervisor(store).reconcile()):
            raise Invalid('Discovery termination is unconfirmed')
    combined = list(dict.fromkeys([*options.get('build_requirements', []), *requirements['requirements']]))
    if requirements['requirements']:
        # Hook output is only a proposal. Resolve with the original constraints,
        # assess every artifact, then request a new approval before using it.
        expanded = resolve_python(shadow / root, stage / 'discovery-build-resolution',
            {**RULES, 'allow_native_wheels': native_wheels},
            **{**options, 'build_requirements': combined}, **provider_options,
            local_build=True, discovery=not hooks_only)
        save(stage / 'discovery-build-plan.json', expanded)
        if expanded['runtime'] != plan['runtime'] or expanded['inputs'] != plan['inputs']:
            raise Invalid('Discovery runtime or metadata changed during build requirement resolution')
        refined = copy.deepcopy(proposal)
        names = ['pypi:' + n for n in pins(expanded['pins'], extras={})] if expanded['pins'] else []
        refined['project']['packages']['allowed_names'] = names
        for task in refined['tasks']:
            task['packages'] = names
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
