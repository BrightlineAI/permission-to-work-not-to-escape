"""One operator entry point; repository data never approves its own authority."""
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
import tomllib

from .monitor import ensure
from .policy import Invalid, approve, compile_policy, digest, load, parse_json, save
from .store import Store
from .supervisor import Supervisor


def ask(label, default=""):
    if not sys.stdin.isatty():
        raise Invalid("Setup requires a real terminal and explicit operator review.")
    suffix = " [" + json.dumps(str(default), ensure_ascii=True)[1:-1] + "]" if default != "" else ""
    answer = input(label + suffix + ": ").strip()
    return answer or str(default)


def data(path, limit=1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > limit:
        raise Invalid("Expected bounded regular metadata file: " + str(path))
    from .policy import open_resource
    fd = open_resource({"root": str(path.absolute().parent)}, path.name, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise Invalid("Metadata exceeds configured size limit")
    return content.decode("utf-8")


def detect(repo):
    if ((repo / 'frontend/package.json').is_file() and
            any((repo / ('backend/' + n)).is_file() for n in ('pyproject.toml', 'requirements.txt', 'requirements.in'))):
        return 'mixed'
    if (repo / "package.json").exists():
        if any((repo / n).exists() for n in ('pyproject.toml', 'requirements.in', 'requirements.txt')):
            return 'mixed'
        meta = parse_json(data(repo / "package.json"))
        if not isinstance(meta, dict) or any(not isinstance(meta.get(k, {}), dict) for k in ("dependencies", "devDependencies")):
            raise Invalid("Expected package.json object and dependency maps")
        deps = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
        return "typescript" if "typescript" in deps or (repo / "tsconfig.json").exists() else "javascript"
    if any((repo / n).exists() for n in ("pyproject.toml", "requirements.in", "requirements.txt")) or any(repo.glob("*.py")):
        return "python"
    if any(repo.glob("*.ts")) or (repo / "tsconfig.json").exists():
        return "typescript"
    return "javascript" if any(repo.glob("*.js")) else None


def resolve_python(repo, stage, *, native_wheels=False):
    from .dependency_resolution import resolve_python as resolve
    from .setup_templates import RULES
    options = load(stage / 'python-options.json') if (stage / 'python-options.json').exists() else {}
    if (stage / 'pypi-registry.json').exists():
        from .registry import private_json
        options['registry_config'] = private_json(stage / 'pypi-registry.json')
    result = resolve(repo, stage / 'python-resolution', {**RULES, 'allow_native_wheels': native_wheels}, **options)
    save(stage / 'python-plan.json', result)
    if not result['pins']:
        return None
    content = '\n'.join(result['pins']) + '\n'
    destination = repo / "ptw-requirements.txt"
    if destination.exists():
        if data(destination) != content:
            raise Invalid("ptw-requirements.txt differs; review/update it explicitly before setup.")
    else:
        destination.write_text(content)
    return destination


def resolve_npm(repo, stage):
    from .npm_resolution import resolve_npm as resolve
    from .setup_templates import RULES
    provider = None
    if (stage / 'npm-registry.json').exists():
        from .registry import RoutedNpmEvidence, private_json
        provider = RoutedNpmEvidence(private_json(stage / 'npm-registry.json'))
    result = resolve(repo, stage / 'npm-resolution', RULES, provider=provider)
    save(stage / 'npm-plan.json', result)
    if result['lock'] is None:
        return None
    lock = repo / 'package-lock.json'
    if not lock.exists():
        save(lock, result['lock'])
    return lock


def candidates(repo, language, editable, metadata, *, metadata_root=None, python='/usr/bin/python3'):
    if language == 'mixed':
        commands = []
        for kind in ('python', 'javascript'):
            commands.extend({**c, 'id': kind + '-' + c['id']} for c in candidates(
                repo, kind, editable, metadata, metadata_root=metadata_root, python=python))
        return commands
    resources = sorted(set(editable + metadata))
    config = metadata_root or repo
    commands = []
    if language == "python":
        inputs = [n for n in editable if (repo / n).is_dir() or not (repo / n).exists() or n.endswith(".py")]
        if inputs:
            syntax = ("import pathlib,sys; paths=[p for n in sys.argv[1:] for p in "
                      "([pathlib.Path(n)] if pathlib.Path(n).is_file() else pathlib.Path(n).rglob('*.py'))]; "
                      "paths=[p for p in paths if p.suffix=='.py']; "
                      "assert paths, 'No Python source files found'; "
                      "[compile(p.read_bytes(),str(p),'exec') for p in paths]; "
                      "print('Syntax checked',len(paths),'files; no tests executed')")
            commands.append(("syntax", ["/usr/bin/python3", "-B", "-c", syntax, *inputs]))
        test_dirs = [n for n in ("tests", "test") if n in editable]
        requirements = data(config / "ptw-requirements.txt") if (config / "ptw-requirements.txt").exists() else ""
        if test_dirs:
            if re.search(r"(?m)^pytest==", requirements):
                commands.append(("test", ["/usr/bin/python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", *test_dirs]))
            else:
                script = ("import sys,unittest; suite=unittest.TestSuite("
                          "unittest.defaultTestLoader.discover(p) for p in sys.argv[1:]); "
                          "count=suite.countTestCases(); "
                          "print('Discovered',count,'tests'); "
                          "sys.exit(0 if count and unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)")
                commands.append(("test", ["/usr/bin/python3", "-B", "-c", script, *test_dirs]))
    else:
        meta = parse_json(data(config / "package.json"))
        scripts = meta.get("scripts", {})
        if not isinstance(scripts, dict) or any(not isinstance(v, str) for v in scripts.values()):
            raise Invalid("package.json scripts must be a string map")
        for name in ("test", "build", "lint", "typecheck"):
            if name in scripts:
                commands.append((name, ["/usr/bin/npm", "--ignore-scripts", "run", name]))
        if "test" not in scripts and any(n in editable for n in ("tests", "test")):
            script = ("const fs=require('node:fs'),cp=require('node:child_process');"
                      "const paths=process.argv.slice(1).flatMap(d=>fs.existsSync(d)?"
                      "fs.readdirSync(d,{recursive:true}).filter(p=>/\\.(test|spec)\\.[cm]?js$/.test(p)).map(p=>d+'/'+p):[]);"
                      "if(!paths.length){console.error('No test files found');process.exit(1)}"
                      "const r=cp.spawnSync(process.execPath,['--test',...paths],{stdio:'inherit'});process.exit(r.status??1)")
            commands.append(("test", ["/usr/bin/node", "-e", script, *[n for n in ("tests", "test") if n in editable]]))
        js_files = [n for n in editable if n.endswith((".js", ".mjs", ".cjs"))]
        # Exact-file syntax checks do not execute repository code or publish writes.
        if len(js_files) == 1:
            commands.append(("syntax", ["/usr/bin/node", "--check", js_files[0]]))
    return [{"id": name, "argv": [python if arg == '/usr/bin/python3' else arg for arg in argv],
             "resources": resources, "timeout_seconds": 120}
            for name, argv in commands]


def review_text(bundle):
    policy, inv = bundle["policy"], bundle["inventory"]
    lines = ["\nPROJECT POLICY REVIEW", "Goal: " + policy["project"]["description"]]
    for task in policy["tasks"]:
        lines.append("Task " + task["id"] + ": " + task["description"])
        for grant in task["grants"]:
            lines.append("  " + inv["resources"][grant["resource"]]["path"] + ": " + ", ".join(grant["actions"]))
        lines.append("  Commands: " + ", ".join(task["commands"]))
        lines.append("  Packages: " + (", ".join(task["packages"]) or "none"))
        levels = task["escalation"]
        lines.append(f"  Warn at {levels['warn_at']}; stop project at {levels['stop_at']}")
    lines.append("Reviewed command definitions (repository scripts remain confined):")
    for command in policy["project"]["commands"]:
        lines.append("  " + command["id"] + ": " + json.dumps(command["argv"]) +
                     "; inputs=" + ", ".join(inv["resources"][r]["path"] for r in command["resources"]))
    granted = {g["resource"] for g in policy["project"]["grants"]}
    lines.append("Denied: " + ", ".join(r["path"] for k, r in inv["resources"].items() if k not in granted))
    levels = policy["project"]["escalation"]
    lines.append(f"Combined project violations: warn at {levels['warn_at']}; stop at {levels['stop_at']}")
    rules = policy["project"]["packages"]
    lines.append(f"Packages: minimum age {rules['min_release_age_days']} days; reject CVSS >= {rules['deny_cvss_at_or_above']}")
    lines.append("Allowed package identities: " + (", ".join(rules["allowed_names"]) or "none"))
    lines.append("Native wheels: " + str(rules["allow_native_wheels"]) +
                 "; reviewed source builds: " + (", ".join(rules["build_packages"]) or "none"))
    lines.append("All undeclared resources and direct network access are denied.")
    lines.append("Commands run confined; only permitted output changes reach this repository.")
    lines.append("Policy hash: " + digest(bundle))
    if 'python_runtime' in policy['project']:
        lines.append('Reviewed Python runtime: ' + json.dumps(policy['project']['python_runtime'], sort_keys=True))
    if 'python_dependencies' in policy['project']:
        lines.append('Reviewed dependency inputs and artifacts: ' + json.dumps(policy['project']['python_dependencies'], sort_keys=True))
    if 'npm_dependencies' in policy['project']:
        lines.append('Reviewed npm inputs and artifacts: ' + json.dumps(policy['project']['npm_dependencies'], sort_keys=True))
    return "\n".join(lines)


def private_directory(repo):
    base = Path(os.environ.get("PTW_USER_STATE", str(Path.home() / ".local/state/permission-to-work"))).absolute()
    if base == repo or base.is_relative_to(repo) or repo.is_relative_to(base):
        raise Invalid("Protected state must be outside the project.")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    if base.resolve() != base or base.stat().st_mode & 0o077:
        raise Invalid("PTW_USER_STATE must be canonical and private (mode 0700).")
    identity = hashlib.sha256(str(repo).encode()).hexdigest()[:24]
    directory = base / identity
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise Invalid("Unsafe project state directory.")
    return directory


def safe_text(value):
    return "".join(c if c.isprintable() or c == "\n" else "\\u%04x" % ord(c) for c in str(value))


def split_scope(value):
    return [part.strip() for part in value.split(",") if part.strip()]


def setup(repo, directory, args, previous=None):
    from .codex import require_login
    from .workflow import package_names
    from .setup_templates import METADATA, optional_proposal, selected, suggestions, template
    from .setup_transaction import fingerprint, publish
    require_login()
    if not sys.stdin.isatty():
        raise Invalid("Setup requires a real terminal and explicit operator review.")
    language = args.language or detect(repo) or ask("Language (python/javascript/typescript/mixed)", "python")
    if language not in ("python", "javascript", "typescript", 'mixed'):
        raise Invalid("Choose python, javascript, typescript or mixed.")
    local_editable = getattr(args, 'python_editable', None)
    local_wheel = getattr(args, 'python_wheel', False)
    native_wheels = getattr(args, 'python_native_wheels', False)
    local_build = local_editable is not None or local_wheel
    if native_wheels and not local_build:
        raise Invalid('--python-native-wheels requires --python-wheel or --python-editable')
    review_hooks = getattr(args, 'python_build_requirements', False)
    if review_hooks and not local_build:
        raise Invalid('--python-build-requirements requires local wheel or editable preparation')
    if review_hooks and local_editable is not None and not split_scope(local_editable):
        raise Invalid('--python-editable must name explicitly selected source paths')
    if local_editable is not None and local_wheel:
        raise Invalid('Choose one local Python installation mode')
    if local_build and language not in ('python', 'mixed'):
        raise Invalid('Local Python preparation requires a Python project')
    from .workspace_policy import directory_fd, relative
    python_root = getattr(args, 'python_root', None)
    node_root = getattr(args, 'node_root', None)
    if python_root is None:
        python_root = 'backend' if language == 'mixed' and (repo / 'backend').is_dir() and not any(
            (repo / n).exists() for n in ('pyproject.toml', 'requirements.txt', 'requirements.in')) else ''
    if node_root is None:
        node_root = 'frontend' if language == 'mixed' and not (repo / 'package.json').exists() and (repo / 'frontend/package.json').exists() else ''
    for root in (python_root, node_root):
        relative(root, empty=True)
        fd = directory_fd(repo / root)
        os.close(fd)
    roots = sorted(set(([python_root] if language in ('python', 'mixed') else []) +
                       ([node_root] if language != 'python' else [])))
    metadata_names = [str(Path(root) / name) for root in roots for name in METADATA]
    if language != 'python' and (repo / node_root / 'package.json').exists():
        from .npm_resolution import node_inputs
        _, node_metadata = node_inputs(repo / node_root)
        metadata_names = sorted(set(metadata_names) | {str(Path(node_root) / name) for name in node_metadata})

    def command_catalog(scope, metadata, shadow, python):
        result = []
        for kind, root in ([('python', python_root)] if language == 'python' else
                           [('javascript', node_root)] if language != 'mixed' else
                           [('python', python_root), ('javascript', node_root)]):
            prefix = root + '/' if root else ''
            editable = [n[len(prefix):] for n in scope if n.startswith(prefix)]
            config = [n[len(prefix):] for n in metadata if n.startswith(prefix)]
            for command in candidates(repo / root, kind, editable, config, metadata_root=shadow / root, python=python):
                result.append({**command, 'id': (kind + '-' if language == 'mixed' else '') + command['id'],
                    'resources': [prefix + n for n in command['resources']], **({'cwd': root} if root else {})})
        return result
    goal = args.goal or ask("What should this project do, and what must it not do?")
    if not goal or len(goal) > 8000:
        raise Invalid("A project goal of 1 to 8000 characters is required.")
    suggested_dirs, suggested_files = suggestions(repo)
    directories = split_scope(args.editable if args.editable is not None else ask(
        "Editable directories (comma separated; '-' for none)", ",".join(suggested_dirs) or "-"))
    file_argument = getattr(args, "files", None)
    if file_argument is None and args.editable is not None:
        file_argument = ""  # Preserve explicit directory-only scope from earlier clients.
    files = split_scope(file_argument if file_argument is not None else ask(
        "Editable exact files (comma separated; '-' for none)", ",".join(suggested_files) or "-"))
    directories = [] if directories == ["-"] else directories
    files = [] if files == ["-"] else files
    warn = args.warn_at if args.warn_at is not None else 1
    stop = args.stop_at if args.stop_at is not None else 3
    stage = directory / ("setup-" + secrets.token_hex(6))
    stage.mkdir(mode=0o700)
    started = time.monotonic()
    try:
        registry_config = None
        python_registry_config = None
        if getattr(args, 'npm_registry_config', None):
            from .registry import private_json, outside_repository
            if Path(args.npm_registry_config).resolve().is_relative_to(repo):
                raise Invalid('Registry configuration must remain outside project source')
            registry_config = private_json(args.npm_registry_config)
            outside_repository(registry_config, repo)
            save(stage / 'npm-registry.json', registry_config)
        if getattr(args, 'python_registry_config', None):
            from .registry import outside_repository, private_json
            if language not in ('python', 'mixed'):
                raise Invalid('Python registry configuration requires a Python project')
            if Path(args.python_registry_config).resolve().is_relative_to(repo):
                raise Invalid('Registry configuration must remain outside project source')
            python_registry_config = private_json(args.python_registry_config)
            outside_repository(python_registry_config, repo)
            save(stage / 'pypi-registry.json', python_registry_config)
        if not 1 <= warn <= stop <= 100:
            raise Invalid("Use thresholds 1 <= warning <= stop <= 100.")
        scope = selected(repo, directories, files)
        # Metadata is copied into an external workspace. Resolvers may write only there.
        inputs = {name: fingerprint(repo / name) for name in sorted(set(scope) | set(metadata_names) | {".ptw"})}
        inputs[""] = fingerprint(repo)
        if inputs[".ptw"] is not None:
            if inputs[".ptw"]["kind"] != "directory":
                raise Invalid(".ptw must be a regular directory")
            inputs[".ptw/policy.json"] = fingerprint(repo / ".ptw/policy.json")
        shadow = stage / "metadata"
        shadow.mkdir()
        for root in roots:
            (shadow / root).mkdir(parents=True, exist_ok=True)
        for name in metadata_names:
            if inputs[name] is not None:
                (shadow / name).parent.mkdir(parents=True, exist_ok=True)
                (shadow / name).write_text(data(repo / name, 8 * 1024 * 1024))
        python_options = {key: getattr(args, flag) for key, flag in
                          (('executable', 'python'), ('source', 'python_source')) if getattr(args, flag, None)}
        if local_build:
            python_options['local_mode'] = 'editable' if local_editable is not None else 'wheel'
        for key in ('groups', 'extras'):
            value = getattr(args, 'python_' + key, None)
            if value is not None:
                python_options[key] = split_scope(value)
        discovery = None
        dynamic = False
        if local_build and (shadow / python_root / 'pyproject.toml').exists():
            project = tomllib.loads(data(shadow / python_root / 'pyproject.toml')).get('project', {})
            if not isinstance(project, dict):
                raise Invalid('Local project metadata must be a table')
            dynamic = bool(project.get('dynamic'))
            if dynamic and review_hooks:
                raise Invalid('--python-build-requirements currently requires static metadata; dynamic discovery has its own review')
        identity = "repo-" + directory.name + "-" + secrets.token_hex(4)
        if language in ('python', 'mixed'):
            from .dependency_resolution import python_inputs
            if any((repo / python_root / n).exists() for n in ('uv.lock', 'poetry.lock')):
                # Native exporters validate these declarations with their lock.
                # All authoritative files were already copied to staging above.
                source_inputs = {}
            else:
                _, _, source_inputs, _ = python_inputs(repo / python_root,
                    **{k: v for k, v in python_options.items() if k != 'executable'}, discovery=dynamic)
            for local_name in source_inputs:
                name = str(Path(python_root) / local_name)
                inputs.setdefault(name, fingerprint(repo / name))
                if name not in metadata_names:
                    metadata_names.append(name)
                destination = shadow / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(data(repo / name, 8 * 1024 * 1024))
            if dynamic or review_hooks:
                from .python_discovery import review
                discovery = review(repo, directory, stage, shadow, scope, python_root, python_options,
                                   goal, warn, stop, identity, native_wheels=native_wheels,
                                   **({'hooks_only': True, 'editable_paths': split_scope(local_editable)
                                       if local_editable is not None else ()} if review_hooks else {}))
                if dynamic:
                    python_options['dynamic_metadata'] = discovery['dynamic_metadata']
                python_options['build_requirements'] = discovery['build_requirements']
                if dynamic and local_editable is not None:
                    # Wheel metadata cannot stand in for PEP 660's distinct hook.
                    # Preserve both reviews and use the same pending controller.
                    hook_stage = stage / 'editable-discovery'
                    hook_stage.mkdir()
                    if (stage / 'pypi-registry.json').exists():
                        save(hook_stage / 'pypi-registry.json', load(stage / 'pypi-registry.json'))
                    discovery = review(repo, directory, hook_stage, shadow, scope, python_root, python_options,
                        goal, warn, stop, identity, native_wheels=native_wheels, hooks_only=True,
                        editable_paths=split_scope(local_editable), previous=discovery)
                    python_options['build_requirements'] = discovery['build_requirements']
                    approved = hook_stage / ('discovery-build-approved.json'
                        if (hook_stage / 'discovery-build-approved.json').exists() else 'discovery-approved.json')
                    save(stage / 'discovery-final-approved.json', load(approved))
            save(stage / 'python-options.json', {**python_options, **({'local_build': True} if local_build else {})})
        if language != "python" and not (shadow / node_root / "package.json").exists():
            manifest = {"name": "project", "version": "1.0.0", "private": True, "type": "module"}
            if language == "typescript":
                manifest["devDependencies"] = {"typescript": "5.8.3"}
                manifest["scripts"] = {"build": "tsc"}
            save(shadow / node_root / "package.json", manifest)
            if language == "typescript":
                save(shadow / node_root / "tsconfig.json", {"compilerOptions": {"target": "ES2022", "module": "NodeNext",
                     "outDir": "dist", "strict": True},
                     "include": [name + "/**/*.ts" if kind == "tree" else name
                                 for name, kind in scope.items() if kind == "tree" or name.endswith(".ts")]})
        print("Preparing typed template; resolving dependency metadata without running project code...", flush=True)
        requirements = resolve_python(shadow / python_root, stage, **({'native_wheels': True} if native_wheels else {})) if language in ('python', 'mixed') else None
        npm_lock = resolve_npm(shadow / node_root, stage) if language != "python" else None
        metadata = [name for name in metadata_names if (shadow / name).exists()]
        names = package_names(requirements, npm_lock)
        generated = {name: data(shadow / name, 8 * 1024 * 1024) for name in metadata if inputs[name] is None}
        python_plan = load(stage / 'python-plan.json') if (stage / 'python-plan.json').exists() else None
        npm_plan = load(stage / 'npm-plan.json') if (stage / 'npm-plan.json').exists() else None
        if npm_plan and npm_plan.get('migration'):
            print('Yarn Classic migration: review the generated npm graph. package-lock.json becomes '
                  'the installation authority; the original yarn.lock remains in project history.', flush=True)
        python = python_plan['runtime']['executable'] if python_plan else '/usr/bin/python3'
        catalog = command_catalog(scope, metadata, shadow, python)
        revision = 0
        while True:
            if not 1 <= warn <= stop <= 100:
                raise Invalid("Use thresholds 1 <= warning <= stop <= 100.")
            if "tsconfig.json" in generated:
                tsconfig = {"compilerOptions": {"target": "ES2022", "module": "NodeNext", "strict": True,
                            **({"outDir": "dist"} if scope.get("dist") == "tree" else {"noEmit": True})},
                            "include": [name + "/**/*.ts" if kind == "tree" else name
                                        for name, kind in scope.items() if name != "dist" and
                                        (kind == "tree" or name.endswith(".ts"))]}
                generated["tsconfig.json"] = json.dumps(tsconfig, indent=2) + "\n"
            trees = [name for name, kind in scope.items() if kind == "tree" and not (repo / name).exists()]
            proposal, inv = template(repo, identity, goal, scope, metadata, catalog, names, warn, stop)
            proposal['project']['packages']['allow_native_wheels'] = native_wheels
            if python_plan:
                proposal['project']['python_runtime'] = python_plan['runtime']
                dependency_inputs = {str(Path(python_root) / name): value for name, value in python_plan['inputs'].items()}
                if requirements:
                    dependency_inputs[str(requirements.relative_to(shadow))] = hashlib.sha256(data(requirements).encode()).hexdigest()
                proposal['project']['python_dependencies'] = {
                    'inputs': dependency_inputs, 'pins': python_plan['pins'], 'artifacts': python_plan['artifacts'],
                    'groups': list(python_options.get('groups', ('dev', 'test'))),
                    'extras': list(python_options.get('extras', ())),
                    'authority': python_plan.get('authority', 'pyproject.toml' if
                        python_options.get('source') == 'pyproject.toml' or not any(
                        (shadow / python_root / n).exists() for n in ('requirements.in', 'requirements.txt')) else 'requirements')}
                if python_registry_config:
                    proposal['project']['python_dependencies']['registry_config_sha256'] = digest(python_registry_config)
                if local_build:
                    from .python_local import describe_source
                    prefix = python_root + '/' if python_root else ''
                    # Only selected paths and existing Python metadata belong to
                    # this source. Generated pins are bound separately at commit.
                    paths = {n for n in scope if n.startswith(prefix)}
                    paths.add(prefix + 'pyproject.toml')
                    mapping = {v['path']: k for k, v in inv['resources'].items()}
                    mutable = split_scope(local_editable) if local_editable is not None else []
                    if local_editable is not None and (not mutable or any(n not in paths or n not in scope for n in mutable)):
                        raise Invalid('--python-editable must name explicitly selected source paths')
                    if any(n not in mapping for n in paths):
                        raise Invalid('Local preparation requires a bound pyproject.toml')
                    source = describe_source(inv, [mapping[n] for n in sorted(paths)],
                        identity='python-project', path=python_root, allow_build=True,
                        editable_resources=[mapping[n] for n in mutable], extras=python_options.get('extras', ()),
                        dynamic_metadata=python_options.get('dynamic_metadata'))
                    if discovery and source['snapshot_sha256'] != discovery['source_sha256']:
                        raise Invalid('Source changed after discovery; restart preparation review')
                    proposal['project']['python_dependencies']['sources'] = [source]
            if npm_plan:
                dependency_inputs = {str(Path(node_root) / name): value for name, value in npm_plan['inputs'].items()}
                if npm_lock:
                    dependency_inputs[str(npm_lock.relative_to(shadow))] = hashlib.sha256(data(npm_lock, 8 * 1024 * 1024).encode()).hexdigest()
                proposal['project']['npm_dependencies'] = {'inputs': dependency_inputs,
                    'lock_sha256': digest(npm_plan['lock']), 'artifacts': npm_plan['artifacts'], 'root': node_root}
                if npm_plan.get('sources'):
                    from .workspace import scan, stamp
                    source_descriptors = []
                    for path in npm_plan['sources']:
                        location = str(Path(node_root) / path)
                        resources = [key for key, value in inv['resources'].items()
                                     if value['path'].startswith(location + '/')]
                        if not any(inv['resources'][key]['path'] != location + '/package.json' for key in resources):
                            raise Invalid('Select explicit source resources for npm local package: ' + location)
                        snapshot = scan(inv, resources)
                        source_descriptors.append({'path': path, 'resources': resources,
                            'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snapshot.items()})})
                    proposal['project']['npm_dependencies'].update(root=node_root, sources=source_descriptors)
                if registry_config:
                    proposal['project']['npm_dependencies']['registry_config_sha256'] = digest(registry_config)
            if getattr(args, "model_proposal", False):
                print("OPTIONAL MODEL PROPOSAL: additional model latency; authority remains fixed.", flush=True)
                proposal, generation = optional_proposal(proposal, inv, trees, args.history,
                    attempt=stage / ("model-" + str(revision) + ".json"))
            elif args.history:
                print("Selected history is evidence only; use ptw audit after approval. No model call.", flush=True)
            compiled = compile_policy(proposal, inv, planned_trees=trees)
            draft = stage / ("draft" if revision == 0 else "draft-" + str(revision))
            save(draft / "draft.json", proposal)
            save(draft / "inventory.json", inv)
            save(draft / "publication.json", {"generated": generated, "directories": trees, "inputs": inputs})
            print(safe_text(short_review(compiled, generated, trees)), flush=True)
            publication_hash = digest({"generated": generated, "directories": trees})
            print("Publication hash: " + publication_hash, flush=True)
            answer = ask("Approve exactly this policy? Type yes, details, customize, reject or cancel", "no").lower()
            if answer == "details":
                print(safe_text(review_text(compiled)), flush=True)
                for name, content in generated.items():
                    print(safe_text("Generated " + name + ":\n" + content), flush=True)
                # No new proposal or model call is needed to expand details.
                while answer == "details":
                    answer = ask("Approve exactly this policy? Type yes, customize, reject or cancel", "no").lower()
            if answer == "customize":
                directories = split_scope(ask("Editable directories ('-' for none)", ",".join(directories) or "-"))
                files = split_scope(ask("Editable exact files ('-' for none)", ",".join(files) or "-"))
                directories = [] if directories == ["-"] else directories
                files = [] if files == ["-"] else files
                scope = selected(repo, directories, files)
                for name in scope:
                    inputs.setdefault(name, fingerprint(repo / name))
                warn = int(ask("Warn after this many violations", str(warn)))
                stop = int(ask("Stop the whole project after", str(stop)))
                catalog = command_catalog(scope, metadata, shadow, python)
                revision += 1
                continue
            if answer != "yes":
                raise Invalid("Not activated. Project unchanged; attempt retained at " + str(stage))
            # Recheck all configuration, selected root identities and review-copy destination.
            for name, expected in inputs.items():
                if fingerprint(repo / name) != expected:
                    raise Invalid("Repository changed since review: " + name)
            bundle = approve(proposal, inv, digest(compiled), getpass.getuser(), planned_trees=trees)
            save(stage / "approved.json", bundle)
            save(stage / "setup-approval.json", {"policy_sha256": digest(compiled),
                 "publication_sha256": publication_hash, "reviewer": getpass.getuser()})
            record = {"repo": str(repo), "project": identity, "state": str(directory / "controller"),
                      "bundle": str(stage / "approved.json"), "language": language, "task": "work",
                      "policy_sha256": bundle["approval"]["sha256"], "publication_sha256": publication_hash}
            save(stage / "registration.json", record)
            for ecosystem, config in (('npm', registry_config), ('pypi', python_registry_config)):
                if config is None:
                    continue
                # Only references are retained, never the credential bytes.
                # This content-addressed private file is inert until its exact
                # descriptor is activated by the publication transaction.
                controller = Store(directory / 'controller')
                destination = controller.directory / (ecosystem + '-registry-' + digest(config) + '.json')
                if destination.exists():
                    if load(destination) != config:
                        raise Invalid('Private registry configuration integrity failure')
                else:
                    save(destination, config)
            publish(repo, directory, stage, bundle, record, generated, trees, inputs, previous)
            save(stage / "outcome.json", {"committed": True, "setup_review_seconds": time.monotonic() - started,
                                         "model_proposal": bool(getattr(args, "model_proposal", False))})
            print("Approved. Repository policy is a review copy; only the protected approval is active.", flush=True)
            return record
    except BaseException as exc:
        from .python_discovery import recover as recover_discovery
        recover_discovery(directory)
        save(stage / "failure.json", {"type": type(exc).__name__, "message": safe_text(str(exc)),
                                    "elapsed_seconds": time.monotonic() - started})
        raise


def short_review(bundle, generated, trees):
    policy, inv = bundle["policy"], bundle["inventory"]
    project = policy["project"]
    writable = [inv["resources"][g["resource"]]["path"] for g in project["grants"] if "write" in g["actions"]]
    readonly = [inv["resources"][g["resource"]]["path"] for g in project["grants"] if g["actions"] == ["read"]]
    rules = project["packages"]
    runtime = project.get('python_runtime')
    return "\n".join(["\nPROJECT POLICY REVIEW", "Goal: " + project["description"],
        "Editable: " + ", ".join(writable), "Read only: " + (", ".join(readonly) or "none"),
        "Commands: " + (", ".join(c["id"] for c in project["commands"]) or "none"),
        'Python runtime: ' + (runtime['executable'] + ' (' + runtime['version'] +
            '); requires-python ' + (runtime['requires_python'] or 'unspecified') if runtime else 'not selected'),
        "No test-suite success is implied by setup or a syntax check; tests must actually exist and pass.",
        "Packages: " + (", ".join(rules["allowed_names"]) or "none") +
        f"; minimum age {rules['min_release_age_days']} days; reject CVSS >= {rules['deny_cvss_at_or_above']}" +
        f"; evidence <= {rules['evidence_max_age_seconds']}s; native wheels {rules['allow_native_wheels']}" +
        "; source builds " + (", ".join(rules["build_packages"]) or "none"),
        'Local Python preparation: ' + ('; '.join(
            s['name'] + '==' + s['version'] + ' (' + s['mode'] + ' at ' + (s['path'] or '.') +
            '); execute backend offline after approval; live edits: ' +
            (', '.join(inv['resources'][r]['path'] for r in s.get('editable_resources', [])) or 'none (rebuild after source changes)') +
            '; extras: ' + (', '.join(s.get('extras', [])) or 'none') +
            '; snapshot ' + s['snapshot_sha256']
            for s in project.get('python_dependencies', {}).get('sources', [])) or 'none'),
        f"Combined violations: warn at {project['escalation']['warn_at']}; stop at {project['escalation']['stop_at']}",
        "Tasks: work; verify (read only, syntax checks only). All other paths/network denied.",
        "On approval create: " + (", ".join([*trees, *generated, ".ptw/policy.json"]) or "none"),
        "Policy hash: " + digest(bundle), "Use details for exact argv, inputs and generated content."])


def start(args):
    started = time.monotonic()
    repo = Path(args.repo).absolute()
    if repo.resolve() != repo or not repo.is_dir():
        raise Invalid("Use an existing canonical repository directory.")
    directory = private_directory(repo)
    fd = os.open(directory / "onboarding.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        from .setup_transaction import recover
        recover(directory)
        from .python_discovery import recover as recover_discovery
        recover_discovery(directory)
        from .dependency_revision import recover as recover_dependencies
        recover_dependencies(directory)
        record = load(directory / "project.json") if (directory / "project.json").exists() else None
        if record is None:
            if args.status or args.stop or args.review:
                raise Invalid("This repository has not been set up. Run ptw codex.")
            record = setup(repo, directory, args)
        elif args.revise:
            print("Current project history:", Store(record["state"]).status(record["project"]), flush=True)
            print("A new approval will stop all current project sessions. Existing history is retained.", flush=True)
            record = setup(repo, directory, args, previous=record)
        elif (any(getattr(args, name, None) is not None for name in ("goal", "editable", "files", "language", "warn_at", "stop_at", "history",
                    'python', 'python_source', 'python_editable', 'python_extras', 'python_groups', 'python_root', 'node_root', 'npm_registry_config', 'python_registry_config'))
              or getattr(args, 'python_wheel', False) or getattr(args, 'python_native_wheels', False)
              or getattr(args, 'python_build_requirements', False)
              or getattr(args, "model_proposal", False)):
            raise Invalid("This project already has an approved policy. Use ptw codex --revise to change it.")
    finally:
        os.close(fd)
    if record["repo"] != str(repo):
        raise Invalid("Project registration does not match this repository.")
    store = Store(record["state"])
    if args.stop:
        store.stop(record["project"])
        return {"termination": Supervisor(store).reconcile(), **store.status(record["project"])}
    if args.status:
        return store.status(record["project"])
    if args.review:
        return load(record["bundle"])
    if store.status(record["project"])["stopped"]:
        raise Invalid("Project is stopped. Starting another Codex cannot reset it. The operator may review a new version with ptw codex --revise.")
    from .setup_transaction import validate_registration
    validate_registration(record)
    ensure(store)
    if args.setup_only:
        return {"project": record["project"], "setup_seconds": round(time.monotonic() - started, 3),
                "setup_only": True, "protected_terminal_ready": False}
    session = store.register(record["project"], args.task or record["task"])
    try:
        run_dir = directory / "sessions" / session["session"]
        save(run_dir / "session.json", session)
        readiness = round(time.monotonic() - started, 3)
        print(f"PROTECTED: {record['project']} | task {session['task']} | launcher ready in {readiness}s", flush=True)
        from .terminal import launch
        result = launch(store, session, run_dir / "session.json", run_dir, prompt=args.prompt)
    finally:
        store.close_session(session["token"])
        Supervisor(store).reconcile()
    return {**result, "launcher_ready_seconds": readiness}
