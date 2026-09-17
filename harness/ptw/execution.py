"""Run reviewed commands in disposable trees; return data, never host writes."""
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile

from .package_build import UnsafeExport, run_build
from .package_evidence import EvidenceError
from .packages import mounted_set
from .policy import Invalid, OutsideScope, parse_json
from .supervisor import runtime_namespace
from .workspace import MAX_ENTRIES, MAX_FILE, MAX_TREE, materialize, scan

RECEIPT = ".ptw-command-result.json"
WRAPPER = r"""
import json,os,subprocess,sys,tempfile
os.chdir('/target' + ('/' + sys.argv[2] if sys.argv[2] else ''))
with tempfile.TemporaryFile() as output:
    try:
        result=subprocess.run(sys.argv[3:],stdin=subprocess.DEVNULL,stdout=output,
                              stderr=subprocess.STDOUT,timeout=int(sys.argv[1]))
        code=result.returncode
    except subprocess.TimeoutExpired:
        code=124
    output.seek(0,2)
    size=output.tell()
    output.seek(max(0,size-32768))
    tail=output.read().decode('utf-8','replace')
# Untrusted command output is not a completion claim or authorization.
with open('/target/.ptw-command-result.json','w') as handle:
    json.dump(dict(exit_code=code,output=tail,output_truncated=size>32768),handle)
"""


def execute(store, token, definition, before, settings):
    try:
        options = parse_json(settings) if settings else {}
    except ValueError as exc:
        raise Invalid("Run content must be JSON with optional package_sets") from exc
    if (not isinstance(options, dict) or set(options) - {"package_sets"} or
            not isinstance(options.get("package_sets", []), list) or len(options.get("package_sets", [])) > 2 or
            not all(isinstance(x, str) for x in options.get("package_sets", []))):
        raise Invalid("Run accepts only package_sets, at most one set per ecosystem")
    nono = os.environ.get("PTW_NONO") or shutil.which("nono")
    if not nono:
        raise Invalid("nono is required; no unconfined fallback")
    mounts = {}
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor["project"])
        if project["stopped"]:
            raise Invalid("Project stopped")
        from .dependency_binding import verify_inputs
        verify_inputs(bundle)
        runtime = bundle['policy']['project'].get('python_runtime')
        if runtime:
            from .python_runtime import verify
            verify(runtime)
        for identity in options.get("package_sets", []):
            mount = mounted_set(store, db, actor, identity)
            ecosystem = db.execute("SELECT ecosystem FROM package_sets WHERE id=?", (identity,)).fetchone()[0]
            if ecosystem in mounts:
                raise Invalid("Only one package set per ecosystem")
            mounts[ecosystem] = mount
    with tempfile.TemporaryDirectory(prefix="workspace-", dir=store.directory) as temporary:
        target = Path(temporary) / "tree"
        target.mkdir(mode=0o700)
        materialize(before, target)
        command = runtime_namespace() + ["--bind", str(target), "/target",
                                        "--ro-bind", str(Path(nono).resolve()), "/nono"]
        permissions = ["/nono", "run", "--sandbox-policy", "landlock", "--block-net",
                       "--allow", "/target", "--allow", "/tmp", "--no-rollback", "--no-audit", "--no-diagnostics"]
        environment = ["PYTHONDONTWRITEBYTECODE=1", "PYTHONNOUSERSITE=1"]
        for ecosystem, mount in mounts.items():
            path = "/python-packages" if ecosystem == "pypi" else "/node-packages"
            command += ["--ro-bind", str(mount), path]
            permissions += ["--read", path]
            if ecosystem == "pypi":
                environment += ["PYTHONPATH=/python-packages:/target"]
            else:
                command += ["--symlink", "/node-packages/node_modules", "/node_modules"]
                environment += ["NODE_PATH=/node-packages/node_modules",
                                "PATH=/node-packages/node_modules/.bin:/usr/bin:/bin"]
        command += ["--", *permissions, "--", "/usr/bin/env", *environment,
                    "/usr/bin/python3", "-I", "-S", "-c", WRAPPER, str(definition["timeout_seconds"]),
                    definition.get('cwd', ''),
                    *definition["argv"]]
        try:
            run_build(store, token, command, target)
        except UnsafeExport as exc:
            raise OutsideScope("Command attempted unsafe output: " + str(exc)) from exc
        except EvidenceError as exc:
            raise Invalid(str(exc)) from exc
        receipt = target / RECEIPT
        if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > MAX_FILE:
            raise Invalid("Invalid command receipt")
        outcome = parse_json(receipt.read_text())
        receipt.unlink()
        if (set(outcome) != {"exit_code", "output", "output_truncated"} or
                type(outcome["exit_code"]) is not int or not isinstance(outcome["output"], str) or
                type(outcome["output_truncated"]) is not bool):
            raise Invalid("Invalid command result")
        # Scan all outputs, not only the approved roots: unknown outputs must fail.
        inv = {"root": str(target), "resources": {
            "r" + str(i): {"path": p.name} for i, p in enumerate(sorted(target.iterdir()))}}
        try:
            after = scan(inv, inv["resources"])
        except OutsideScope as exc:
            raise OutsideScope("Command output links/special files are not authorized") from exc
        scaffold = {str(parent) for path in before for parent in PurePosixPath(path).parents
                    if str(parent) != "." and str(parent) not in before}
        # materialize creates structural parents for exact nested resources.
        # They are not new agent outputs, but new siblings under them still are.
        after = {p: e for p, e in after.items() if not (p in scaffold and e["kind"] == "dir")}
        return after, outcome
