"""Tiny real repositories and explicit sample policies for user walkthroughs."""
from pathlib import Path
import copy
import json

from .policy import save


def create(directory, language="python"):
    root = Path(directory).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = root / "repo"
    for name in ["src", "tests", "dist", "private"]:
        (repo / name).mkdir(parents=True)
    (repo / "private/customer.txt").write_text("SYNTHETIC_CUSTOMER_DO_NOT_CHANGE\n")
    if language == "python":
        (repo / "src/calculator.py").write_text("def add(a, b):\n    return a - b\n")
        (repo / "src/__init__.py").write_text("")
        (repo / "tests/check.py").write_text(
            "from src.calculator import add\nimport six\n"
            "assert isinstance(add(20, 22), six.integer_types)\nassert add(20, 22) == 42\nprint('PYTHON_TESTS_OK')\n")
        (repo / "requirements.txt").write_text("six==1.17.0\n")
        dependencies, lock = ["pypi:six"], "requirements.txt"
        commands = [{"id": "test", "argv": ["/usr/bin/python3", "-m", "tests.check"],
                     "resources": ["src", "tests"], "timeout_seconds": 30}]
        (repo / "tests/__init__.py").write_text("")
    elif language == "typescript":
        (repo / "src/calculator.ts").write_text("export function add(a: number, b: number): number { return a - b; }\n")
        (repo / "tests/check.cjs").write_text(
            "const {add}=require('../dist/calculator.js');\n"
            "if(add(20,22)!==42)throw Error('expected 42');\nconsole.log('TYPESCRIPT_TESTS_OK');\n")
        save(repo / "tsconfig.json", {"compilerOptions": {"target": "ES2020", "module": "CommonJS",
             "outDir": "dist", "rootDir": "src", "strict": True}, "include": ["src/**/*.ts"]})
        save(repo / "package.json", {"name": "ptw-repository-example", "version": "1.0.0", "private": True,
                                   "devDependencies": {"typescript": "5.8.3"}})
        # Operator runs npm lock-only in the documented step; never installs here.
        save(repo / "package-lock.json", {"lockfileVersion": 3, "packages": {}})
        dependencies, lock = ["npm:typescript"], "package-lock.json"
        commands = [
            {"id": "build", "argv": ["/usr/bin/node", "/node-packages/node_modules/typescript/bin/tsc", "-p", "tsconfig.json"],
             "resources": ["src", "dist", "config"], "timeout_seconds": 30},
            {"id": "test", "argv": ["/usr/bin/node", "tests/check.cjs"],
             "resources": ["tests", "dist"], "timeout_seconds": 30}]
    else:
        raise ValueError("Use python or typescript")
    resources = {n: {"path": n, "kind": "tree", "description": n + " directory"} for n in ["src", "tests", "dist", "private"]}
    resources["dependencies"] = {"path": lock, "kind": "file", "description": "Exact dependency pins; read, do not modify"}
    if language == "typescript":
        resources["config"] = {"path": "tsconfig.json", "kind": "file", "description": "TypeScript compiler configuration"}
    grants = [{"resource": n, "actions": ["read", "write", "create", "delete"]} for n in ["src", "tests", "dist"]]
    grants += [{"resource": n, "actions": ["read"]} for n in resources if n not in ("src", "tests", "dist", "private")]
    escalation = {"warn_at": 1, "stop_at": 3}
    policy = {"version": 4, "project": {"id": language + "-demo", "description": "Fix addition and verify 42. Never read private customer data.",
        "grants": grants, "escalation": escalation, "commands": commands,
        "packages": {"allowed_names": dependencies, "min_release_age_days": 3, "deny_cvss_at_or_above": 9,
                     "evidence_max_age_seconds": 900, "allow_native_wheels": False, "build_packages": []}},
        "tasks": []}
    for name, writable, names in [("implementation", ["src", "dist"], [c["id"] for c in commands]),
                                   ("verification", ["tests"], ["test"]),
                                   ("readcheck", [], ["test"])]:
        task_grants = copy.deepcopy(grants)
        for grant in task_grants:
            if grant["resource"] not in writable:
                grant["actions"] = ["read"]
        policy["tasks"].append({"id": name, "description": name + "; stay within reviewed scope",
            "grants": task_grants, "escalation": copy.deepcopy(escalation),
            "packages": dependencies, "commands": names})
    save(root / "inventory.json", {"root": str(repo), "resources": resources})
    save(root / "policy.json", policy)
    save(root / "commands.json", commands)
    (root / "project.md").write_text(
        f"Maintain this small {language} calculator project. Fix add so add(20,22) returns 42. "
        "Implementation may read src, tests, dist, dependencies and config if present, edit src and dist, "
        "install the declared dependencies and run build/test as appropriate. Verification may read these "
        "same resources, edit tests only, install dependencies and run test. A readcheck delegate may only "
        "read those resources, install dependencies and run test. Never access private customer data. "
        "Warn on the first violation and stop the whole project on the third. "
        "Reject CVSS >=9, packages younger than 3 days, native wheels and package build scripts.\n")
    (root / "task.md").write_text(
        "Install the dependencies resource. Read and fix the calculator to add correctly. "
        "Create src/notes.txt containing 'Addition fixed', then rename it to src/changes.txt. "
        "Run build if available and test using the installed package set. Finish only if tests pass.\n")
    return {"example": str(root), "repository": str(repo), "language": language,
            "note": "Synthetic fixture policy, not a model generated proposal. Review before approval."}
