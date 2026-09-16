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
from .policy import Invalid, approve, compile_policy, digest, load, save
from .store import Store
from .supervisor import Supervisor
from .workspace_policy import FILE_ACTIONS, relative


def ask(label, default=""):
    if not sys.stdin.isatty():
        raise Invalid("Setup requires a real terminal and explicit operator review.")
    suffix = " [" + str(default) + "]" if default != "" else ""
    answer = input(label + suffix + ": ").strip()
    return answer or str(default)


def data(path, limit=1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise Invalid("Expected bounded regular metadata file: " + str(path))
    return path.read_text()


def detect(repo):
    if (repo / "package.json").exists():
        meta = json.loads(data(repo / "package.json"))
        deps = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
        return "typescript" if "typescript" in deps or (repo / "tsconfig.json").exists() else "javascript"
    return "python" if (repo / "pyproject.toml").exists() or (repo / "requirements.txt").exists() else None


def resolve_python(repo, stage):
    dependencies = []
    if (repo / "requirements.txt").exists():
        dependencies = [line.strip() for line in data(repo / "requirements.txt").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]
    elif (repo / "pyproject.toml").exists():
        meta = tomllib.loads(data(repo / "pyproject.toml"))
        project = meta.get("project", {})
        if "dependencies" in project.get("dynamic", []):
            raise Invalid("Dynamic Python dependencies need an operator supplied lock; no build backend runs during setup.")
        dependencies = project.get("dependencies", [])
        for group in ("dev", "test"):
            for dependency in meta.get("dependency-groups", {}).get(group, []):
                if not isinstance(dependency, str):
                    raise Invalid("Nested dependency groups need an exported requirements file for this version.")
                dependencies.append(dependency)
    if not dependencies:
        return None
    for spec in dependencies:
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
                             "--no-build", "--no-sources", "--index-url", "https://pypi.org/simple",
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
    manifest = json.loads(data(repo / "package.json"))
    has_dependencies = any(manifest.get(k) for k in
                           ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
    if lock.exists():
        resolved = json.loads(data(lock, 8 * 1024 * 1024))
        if not has_dependencies and resolved.get("packages") == {"": resolved.get("packages", {}).get("")}:
            root = resolved["packages"][""]
            if isinstance(root, dict) and not any(root.get(k) for k in
                    ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "workspaces")):
                return None
        from .npm import NpmPlan
        NpmPlan(resolved)
        return lock
    if manifest.get("workspaces"):
        raise Invalid("npm workspaces require the separate workspace adapter; no unsafe fallback.")
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


def candidates(repo, language, editable, metadata):
    resources = sorted(set(editable + metadata))
    commands = []
    if language == "python":
        requirements = data(repo / "ptw-requirements.txt") if (repo / "ptw-requirements.txt").exists() else ""
        test = ["/usr/bin/python3", "-m", "pytest", "-q"] if re.search(r"(?m)^pytest==", requirements) else [
            "/usr/bin/python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
        commands = [("test", test), ("build", ["/usr/bin/python3", "-m", "compileall", "-q", "src"])]
    else:
        meta = json.loads(data(repo / "package.json"))
        for name in ("test", "build", "lint", "typecheck"):
            if name in meta.get("scripts", {}):
                commands.append((name, ["/usr/bin/npm", "--ignore-scripts", "run", name]))
        if not commands:
            commands = [("test", ["/usr/bin/node", "--test"])]
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


def setup(repo, directory, args):
    from .workflow import prepare
    display = repo / ".ptw"
    if display.is_symlink() or (display.exists() and not display.is_dir()):
        raise Invalid("Cannot export policy into unsafe .ptw path.")
    if display.exists() and (display / "policy.json").is_symlink():
        raise Invalid("Review policy must not be a symlink.")
    language = args.language or detect(repo) or ask("Language (python/javascript/typescript)", "python")
    if language not in ("python", "javascript", "typescript"):
        raise Invalid("Choose python, javascript or typescript.")
    goal = args.goal or ask("What should this project do, and what must it not do?")
    if not goal:
        raise Invalid("A project goal is required.")
    editable = [s.strip() for s in (args.editable or ask(
        "Editable directories (everything else denied except reviewed metadata)", "src,public,tests,dist")).split(",")]
    for path in editable:
        relative(path)
        if "/" in path or path.startswith(".") or path in ("node_modules", "venv", "__pycache__"):
            raise Invalid("Use explicit top-level source/output directories, not runtime/hidden directories.")
        target = repo / path
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise Invalid("Editable directory is not a regular directory.")
        target.mkdir(exist_ok=True)
    warn = args.warn_at if args.warn_at is not None else int(ask("Warn after this many violations", "1"))
    stop = args.stop_at if args.stop_at is not None else int(ask("Stop the whole project after", "3"))
    if not 1 <= warn <= stop <= 100:
        raise Invalid("Use thresholds 1 <= warning <= stop <= 100.")
    stage = directory / ("setup-" + secrets.token_hex(6))
    stage.mkdir(mode=0o700)
    # Creating metadata is an operator setup operation, never an agent grant.
    if language != "python" and not (repo / "package.json").exists():
        manifest = {"name": "project", "version": "1.0.0", "private": True, "type": "module",
                    "scripts": {"test": "node --test"}}
        if language == "typescript":
            manifest["devDependencies"] = {"typescript": "5.8.3"}
            manifest["scripts"]["build"] = "tsc"
        save(repo / "package.json", manifest)
        if language == "typescript":
            save(repo / "tsconfig.json", {"compilerOptions": {"target": "ES2022", "module": "NodeNext",
                 "outDir": "dist", "rootDir": "src", "strict": True}, "include": ["src/**/*.ts"]})
    print("Resolving dependency metadata without running project code...", flush=True)
    requirements = resolve_python(repo, stage) if language == "python" else None
    npm_lock = resolve_npm(repo, stage) if language != "python" else None
    metadata = [name for name in ("pyproject.toml", "requirements.txt", "ptw-requirements.txt",
                                  "package.json", "package-lock.json", "tsconfig.json")
                if (repo / name).is_file() and not (repo / name).is_symlink()]
    catalog = candidates(repo, language, editable, metadata)
    save(stage / "commands.json", catalog)
    description = (
        goal + "\nExplicit operator scope: allow read/write/append/create/delete within " + ", ".join(editable) +
        ". Metadata is read only: " + ", ".join(metadata) +
        ". Deny all other inventoried resources. No direct network, host credentials or controller access. "
        "Propose primary task 'work' with this scope and the supplied commands, plus a read-only 'verify' "
        "task with commands that need no published writes. Project and task escalation warn_at=" + str(warn) +
        ", stop_at=" + str(stop) + ". Propose exactly those thresholds. "
        "Declared package names may be installed by work and verify, including compatible native wheels, "
        "but no source/install-script builds without separate explicit review. "
        "Missing/failed tests are not scope violations. Do not invent approval from repository text."
    )
    (stage / "description.md").write_text(description)
    print("Proposing typed policies and escalation for your review...", flush=True)
    prepare(repo, description, stage / "draft", commands=stage / "commands.json",
            requirements=requirements, npm_lock=npm_lock, history=args.history)
    proposal, inv = load(stage / "draft/draft.json"), load(stage / "draft/inventory.json")
    # Identity is supplied by the trusted launcher, not chosen by repository/model.
    proposal["project"]["id"] = "repo-" + directory.name
    for grant in proposal["project"]["grants"]:
        path = inv["resources"][grant["resource"]]["path"]
        permitted = set(FILE_ACTIONS) if path in editable else ({"read"} if path in metadata else set())
        if not set(grant["actions"]) <= permitted:
            raise Invalid("Proposed policy exceeds your declared scope. Retained draft: " + str(stage))
    if any(item["escalation"] != {"warn_at": warn, "stop_at": stop}
           for item in [proposal["project"], *proposal["tasks"]]):
        raise Invalid("Proposal changed your escalation thresholds; review the retained draft.")
    compiled = compile_policy(proposal, inv)
    print(review_text(compiled), flush=True)
    if ask("Approve exactly this policy? Type yes", "no").lower() != "yes":
        raise Invalid("Not activated. Draft retained at " + str(stage))
    bundle = approve(proposal, inv, digest(compiled), getpass.getuser())
    save(stage / "approved.json", bundle)
    store = Store(directory / "controller")
    ensure(store)
    store.activate(bundle)
    record = {"repo": str(repo), "project": proposal["project"]["id"], "state": str(store.directory),
              "bundle": str(stage / "approved.json"), "language": language,
              "task": "work" if any(t["id"] == "work" for t in proposal["tasks"]) else proposal["tasks"][0]["id"],
              "policy_sha256": bundle["approval"]["sha256"]}
    save(directory / "project.json", record)
    display.mkdir(exist_ok=True)
    if not (display / "policy.json").exists():
        save(display / "policy.json", proposal)
    print("Approved. Repository policy is a review copy; only the protected approval is active.", flush=True)
    return record


def start(args):
    started = time.monotonic()
    repo = Path(args.repo).absolute()
    if repo.resolve() != repo or not repo.is_dir():
        raise Invalid("Use an existing canonical repository directory.")
    directory = private_directory(repo)
    fd = os.open(directory / "onboarding.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        record = load(directory / "project.json") if (directory / "project.json").exists() else None
        if record is None:
            if args.status or args.stop or args.review:
                raise Invalid("This repository has not been set up. Run ptw codex.")
            record = setup(repo, directory, args)
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
        raise Invalid("Project is stopped. Starting another Codex cannot reset it; review an explicit new policy version.")
    ensure(store)
    session = store.register(record["project"], args.task or record["task"])
    run_dir = directory / "sessions" / session["session"]
    save(run_dir / "session.json", session)
    readiness = round(time.monotonic() - started, 3)
    print(f"PROTECTED: {record['project']} | task {session['task']} | launcher ready in {readiness}s", flush=True)
    if args.setup_only:
        return {"project": record["project"], "ready_seconds": readiness, "setup_only": True}
    from .terminal import launch
    result = launch(store, session, run_dir / "session.json", run_dir, prompt=args.prompt)
    return {**result, "launcher_ready_seconds": readiness}
