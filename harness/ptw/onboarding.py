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
import subprocess
import sys
import time
import tomllib

from packaging.requirements import Requirement

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
    if (repo / "package.json").exists():
        meta = parse_json(data(repo / "package.json"))
        if not isinstance(meta, dict) or any(not isinstance(meta.get(k, {}), dict) for k in ("dependencies", "devDependencies")):
            raise Invalid("Expected package.json object and dependency maps")
        deps = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
        return "typescript" if "typescript" in deps or (repo / "tsconfig.json").exists() else "javascript"
    if any((repo / n).exists() for n in ("pyproject.toml", "requirements.txt")) or any(repo.glob("*.py")):
        return "python"
    if any(repo.glob("*.ts")) or (repo / "tsconfig.json").exists():
        return "typescript"
    return "javascript" if any(repo.glob("*.js")) else None


def resolve_python(repo, stage):
    dependencies = []
    if (repo / "requirements.txt").exists():
        dependencies = [line.strip() for line in data(repo / "requirements.txt").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]
    elif (repo / "pyproject.toml").exists():
        meta = tomllib.loads(data(repo / "pyproject.toml"))
        project = meta.get("project", {})
        if not isinstance(project, dict) or not isinstance(project.get("dependencies", []), list):
            raise Invalid("Expected static Python project dependency list")
        if not isinstance(project.get("dynamic", []), list) or not isinstance(meta.get("dependency-groups", {}), dict):
            raise Invalid("Malformed Python dynamic fields or dependency groups")
        if "dependencies" in project.get("dynamic", []):
            raise Invalid("Dynamic Python dependencies need an operator supplied lock; no build backend runs during setup.")
        dependencies = list(project.get("dependencies", []))
        for group in ("dev", "test"):
            entries = meta.get("dependency-groups", {}).get(group, [])
            if not isinstance(entries, list):
                raise Invalid("Python dependency groups must be lists")
            for dependency in entries:
                if not isinstance(dependency, str):
                    raise Invalid("Nested dependency groups need an exported requirements file for this version.")
                dependencies.append(dependency)
    if not dependencies:
        return None
    for spec in dependencies:
        if not isinstance(spec, str):
            raise Invalid("Python dependencies must be requirement strings")
        parsed = Requirement(spec)
        if parsed.url:
            raise Invalid("Python direct URLs/local packages need a reviewed source adapter.")
    source = stage / "requirements.in"
    source.write_text("\n".join(dependencies) + "\n")
    output = stage / "requirements.txt"
    uv = shutil.which("uv")
    if not uv:
        raise Invalid("uv is required to resolve Python dependencies.")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UV_", "PIP_"))}
    result = subprocess.run([uv, "--no-config", "--cache-dir", str(stage / "cache"), "pip", "compile",
                             "--no-build", "--no-sources", "--python", "/usr/bin/python3",
                             "--index-url", "https://pypi.org/simple",
                             "--no-annotate", "--no-header", str(source), "--output-file", str(output)],
                            capture_output=True, text=True, timeout=180, env=env)
    if result.returncode:
        raise Invalid("Python lock resolution failed without executing builds: " + result.stderr[-1000:])
    from .package_evidence import pins
    lines = [s.strip() for s in output.read_text().splitlines() if s.strip() and not s.startswith("#")]
    pins(lines, extras={})
    destination = repo / "ptw-requirements.txt"
    if destination.exists():
        if data(destination) != output.read_text():
            raise Invalid("ptw-requirements.txt differs; review/update it explicitly before setup.")
    else:
        destination.write_text(output.read_text())
    return destination


def resolve_npm(repo, stage):
    lock = repo / "package-lock.json"
    manifest = parse_json(data(repo / "package.json"))
    if not isinstance(manifest, dict) or any(not isinstance(manifest.get(k, {}), dict) for k in
            ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")):
        raise Invalid("Expected package.json object and dependency maps")
    if manifest.get("workspaces"):
        raise Invalid("npm workspaces require the separate workspace adapter; no unsafe fallback.")
    has_dependencies = any(manifest.get(k) for k in
                           ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
    if lock.exists():
        resolved = parse_json(data(lock, 8 * 1024 * 1024))
        if (not isinstance(resolved, dict) or resolved.get("lockfileVersion") not in (2, 3)
                or not isinstance(resolved.get("packages"), dict)):
            raise Invalid("Expected package-lock.json version 2/3 with a packages object")
        if not has_dependencies and resolved["packages"] == {"": resolved["packages"].get("")}:
            root = resolved["packages"][""]
            if isinstance(root, dict) and not any(root.get(k) for k in
                    ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "workspaces")):
                return None
        from .npm import NpmPlan
        NpmPlan(resolved)
        return lock
    if not has_dependencies:
        return None
    cleaned = {"name": "ptw-resolution", "version": "1.0.0", "private": True}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        cleaned[key] = manifest.get(key, {})
        for name, spec in cleaned[key].items():
            if not isinstance(spec, str) or not re.fullmatch(r"[A-Za-z0-9.*<>=~^|+ -]+", spec):
                raise Invalid("Only npm public registry version ranges are supported during automatic locking.")
            if not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", name):
                raise Invalid("Invalid npm dependency name")
    npm = shutil.which("npm")
    if not npm:
        raise Invalid("Node/npm are missing.")
    folder = stage / "npm"
    folder.mkdir(mode=0o700)
    save(folder / "package.json", cleaned)
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
    result = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                             "--registry=https://registry.npmjs.org", "--userconfig=/dev/null",
                             "--globalconfig=" + str(folder / "empty-global"), "--cache=" + str(folder / "cache")],
                            cwd=folder, capture_output=True, text=True, timeout=180, env=env)
    if result.returncode:
        raise Invalid("npm metadata-only locking failed: " + result.stderr[-1000:])
    resolved = load(folder / "package-lock.json")
    # The root name is metadata, not an installed registry identity.
    resolved["name"] = manifest.get("name", "project")
    resolved["version"] = manifest.get("version", "1.0.0")
    resolved["packages"][""]["name"] = resolved["name"]
    resolved["packages"][""]["version"] = resolved["version"]
    from .npm import NpmPlan
    NpmPlan(resolved)
    save(lock, resolved)
    return lock


def candidates(repo, language, editable, metadata, *, metadata_root=None):
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
    return [{"id": name, "argv": argv, "resources": resources, "timeout_seconds": 120}
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
    language = args.language or detect(repo) or ask("Language (python/javascript/typescript)", "python")
    if language not in ("python", "javascript", "typescript"):
        raise Invalid("Choose python, javascript or typescript.")
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
        if not 1 <= warn <= stop <= 100:
            raise Invalid("Use thresholds 1 <= warning <= stop <= 100.")
        scope = selected(repo, directories, files)
        # Metadata is copied into an external workspace. Resolvers may write only there.
        inputs = {name: fingerprint(repo / name) for name in sorted(set(scope) | set(METADATA) | {".ptw"})}
        inputs[""] = fingerprint(repo)
        if inputs[".ptw"] is not None:
            if inputs[".ptw"]["kind"] != "directory":
                raise Invalid(".ptw must be a regular directory")
            inputs[".ptw/policy.json"] = fingerprint(repo / ".ptw/policy.json")
        shadow = stage / "metadata"
        shadow.mkdir()
        for name in METADATA:
            if inputs[name] is not None:
                (shadow / name).write_text(data(repo / name, 8 * 1024 * 1024))
        if language != "python" and not (shadow / "package.json").exists():
            manifest = {"name": "project", "version": "1.0.0", "private": True, "type": "module"}
            if language == "typescript":
                manifest["devDependencies"] = {"typescript": "5.8.3"}
                manifest["scripts"] = {"build": "tsc"}
            save(shadow / "package.json", manifest)
            if language == "typescript":
                save(shadow / "tsconfig.json", {"compilerOptions": {"target": "ES2022", "module": "NodeNext",
                     "outDir": "dist", "strict": True},
                     "include": [name + "/**/*.ts" if kind == "tree" else name
                                 for name, kind in scope.items() if kind == "tree" or name.endswith(".ts")]})
        print("Preparing typed template; resolving dependency metadata without running project code...", flush=True)
        requirements = resolve_python(shadow, stage) if language == "python" else None
        npm_lock = resolve_npm(shadow, stage) if language != "python" else None
        metadata = [name for name in METADATA if (shadow / name).exists()]
        names = package_names(requirements, npm_lock)
        generated = {name: data(shadow / name, 8 * 1024 * 1024) for name in metadata if inputs[name] is None}
        catalog = candidates(repo, language, list(scope), metadata, metadata_root=shadow)
        identity = "repo-" + directory.name + "-" + secrets.token_hex(4)
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
                catalog = candidates(repo, language, list(scope), metadata, metadata_root=shadow)
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
            publish(repo, directory, stage, bundle, record, generated, trees, inputs, previous)
            save(stage / "outcome.json", {"committed": True, "setup_review_seconds": time.monotonic() - started,
                                         "model_proposal": bool(getattr(args, "model_proposal", False))})
            print("Approved. Repository policy is a review copy; only the protected approval is active.", flush=True)
            return record
    except BaseException as exc:
        save(stage / "failure.json", {"type": type(exc).__name__, "message": safe_text(str(exc)),
                                    "elapsed_seconds": time.monotonic() - started})
        raise


def short_review(bundle, generated, trees):
    policy, inv = bundle["policy"], bundle["inventory"]
    project = policy["project"]
    writable = [inv["resources"][g["resource"]]["path"] for g in project["grants"] if "write" in g["actions"]]
    readonly = [inv["resources"][g["resource"]]["path"] for g in project["grants"] if g["actions"] == ["read"]]
    rules = project["packages"]
    return "\n".join(["\nPROJECT POLICY REVIEW", "Goal: " + project["description"],
        "Editable: " + ", ".join(writable), "Read only: " + (", ".join(readonly) or "none"),
        "Commands: " + (", ".join(c["id"] for c in project["commands"]) or "none"),
        "No test-suite success is implied by setup or a syntax check; tests must actually exist and pass.",
        "Packages: " + (", ".join(rules["allowed_names"]) or "none") +
        f"; minimum age {rules['min_release_age_days']} days; reject CVSS >= {rules['deny_cvss_at_or_above']}" +
        f"; evidence <= {rules['evidence_max_age_seconds']}s; native wheels {rules['allow_native_wheels']}" +
        "; source builds " + (", ".join(rules["build_packages"]) or "none"),
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
        record = load(directory / "project.json") if (directory / "project.json").exists() else None
        if record is None:
            if args.status or args.stop or args.review:
                raise Invalid("This repository has not been set up. Run ptw codex.")
            record = setup(repo, directory, args)
        elif args.revise:
            print("Current project history:", Store(record["state"]).status(record["project"]), flush=True)
            print("A new approval will stop all current project sessions. Existing history is retained.", flush=True)
            record = setup(repo, directory, args, previous=record)
        elif (any(getattr(args, name, None) is not None for name in ("goal", "editable", "files", "language", "warn_at", "stop_at", "history"))
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
