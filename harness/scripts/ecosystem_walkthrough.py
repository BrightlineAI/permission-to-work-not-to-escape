#!/usr/bin/env python3
"""Real registry acceptance using public CLI and physical workload effects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from ptw.policy import load, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    root = args.out.absolute()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    calls, checks, units = [], {}, []
    start = time.monotonic()
    error = None

    def cli(*argv, exit_code=0):
        begin = time.monotonic()
        proc = subprocess.run(["ptw", *map(str, argv)], capture_output=True, text=True, timeout=480)
        value = json.loads(proc.stdout or proc.stderr)
        calls.append({"argv": list(map(str, argv)), "exit_code": proc.returncode,
                      "seconds": round(time.monotonic() - begin, 3), "result": value})
        if proc.returncode != exit_code:
            raise AssertionError(str(value))
        return value

    def check(name, value):
        checks[name] = bool(value)
        if not value:
            raise AssertionError(name)

    def activate(policy, project):
        reviewed = cli("review", "--policy", policy, "--inventory", root / "project/inventory.json")
        bundle = root / (project + "-approved.json")
        cli("approve", "--policy", policy, "--inventory", root / "project/inventory.json",
            "--sha256", reviewed["sha256"], "--reviewer", "synthetic ecosystem walkthrough", "--out", bundle)
        cli("activate", "--state", root / "controller", "--bundle", bundle)
        session = root / (project + "-session.json")
        cli("register", "--state", root / "controller", "--project", project, "--task", "frontend", "--out", session)
        return session

    def install(session, event, source, npm=False, exit_code=0):
        return cli("package-install", "--state", root / "controller", "--session", session,
                   "--event", event, "--npm-lock" if npm else "--requirements", source, exit_code=exit_code)

    def launch(session, receipt, program, expected, python=True):
        marker = root / "project/resources/ui.txt"
        marker.write_text("PENDING")
        unit = cli("launch", "--state", root / "controller", "--session", session,
                   "--package-set", receipt["package_set"], "--",
                   "/usr/bin/python3" if python else "/usr/bin/node", "-c" if python else "-e", program)["unit"]
        units.append(unit)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and marker.read_text() != expected:
            time.sleep(.1)
        check(expected, marker.read_text() == expected)

    try:
        check("doctor", cli("doctor")["ready"])
        cli("sample", "--out", root / "project")
        draft = root / "python-policy.json"
        cli("package-draft", "--policy", root / "project/policy.json", "--project-id", "python-packages",
            "--task", "frontend", "--ecosystems", "--native", "--allow", "pypi:numpy",
            "--allow", "pypi:stopit", "--allow", "pypi:setuptools", "--allow", "pypi:wheel",
            "--allow", "pypi:packaging", "--build", "pypi:stopit", "--out", draft)
        session = activate(draft, "python-packages")
        native = root / "native.txt"
        native.write_text("numpy==2.2.6\n")
        receipt = install(session, "native", native)
        launch(session, receipt, "import numpy as n; assert int(n.array([1,2,3]).sum())==6; "
            "open('/resources/ui','w').write('NATIVE_PYTHON_OK')", "NATIVE_PYTHON_OK")
        source = root / "source.txt"
        source.write_text("stopit==1.1.2\nsetuptools==80.9.0\nwheel==0.45.1\npackaging==25.0\n")
        receipt = install(session, "source", source)
        check("source_wheel_provenance", any("built_wheel" in e for e in receipt["evidence"]))
        launch(session, receipt, "import stopit; assert stopit.ThreadingTimeout; "
            "open('/resources/ui','w').write('SOURCE_PYTHON_OK')", "SOURCE_PYTHON_OK")

        node = root / "node"
        node.mkdir()
        save(node / "package.json", {"name": "ptw-typescript-example", "version": "1.0.0", "private": True,
            "dependencies": {"typescript": "5.8.3", "is-number": "7.0.0"}})
        # Operator preparation only; lock creation runs no package lifecycle code.
        proc = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
            "--no-fund", "--registry=https://registry.npmjs.org", "--userconfig=/dev/null",
            "--globalconfig=" + str(node / "empty-global"), "--cache=" + str(node / "cache")],
            cwd=node, capture_output=True, text=True, timeout=120,
            env={"PATH": "/usr/bin:/bin", "HOME": str(node)})
        check("operator_lock_only_no_install", proc.returncode == 0 and not (node / "node_modules").exists())
        draft = root / "node-policy.json"
        cli("package-draft", "--policy", root / "project/policy.json", "--project-id", "node-packages",
            "--task", "frontend", "--npm-lock", node / "package-lock.json", "--out", draft)
        session = activate(draft, "node-packages")
        receipt = install(session, "typescript", node / "package-lock.json", npm=True)
        program = """const ts=require('typescript'),fs=require('fs'),vm=require('vm');
const code=ts.transpileModule('const answer: number = 42; answer;', {compilerOptions:{target:ts.ScriptTarget.ES2020}}).outputText;
if(vm.runInNewContext(code)!==42 || !require('is-number')(42)) throw Error('wrong result');
fs.writeFileSync('/resources/ui','TYPESCRIPT_OK');"""
        launch(session, receipt, program, "TYPESCRIPT_OK", python=False)
        launch(session, receipt, "import('is-number').then(m=>{if(!m.default(42))throw Error('bad');"
            "require('fs').writeFileSync('/resources/ui','ESM_OK')})", "ESM_OK", python=False)
        launch(session, receipt, "const p=require('child_process');"
            "if(!p.execFileSync('/packages/node_modules/.bin/tsc',['--version'],{encoding:'utf8'}).includes('5.8.3'))throw Error('bad');"
            "require('fs').writeFileSync('/resources/ui','TSC_BIN_OK')", "TSC_BIN_OK", python=False)
        # Existing-project migration preserves resources and prior history.
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (root / "project/resources").iterdir()}
        cli("stop", "--state", root / "controller", "--project", "node-packages")
        migrated = root / "migrated.json"
        cli("package-draft", "--policy", draft, "--project-id", "node-next", "--task", "frontend",
            "--npm-lock", node / "package-lock.json", "--out", migrated)
        new_session = activate(migrated, "node-next")
        install(new_session, "existing", node / "package-lock.json", npm=True)
        check("existing_files_preserved", before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (root / "project/resources").iterdir()})
        check("old_history_retained", bool(cli("events", "--state", root / "controller", "--project", "node-packages")))
        check("old_project_stopped", cli("status", "--state", root / "controller", "--project", "node-packages")["stopped"])
    except Exception as exc:
        error = str(exc)
    finally:
        from ptw.supervisor import Supervisor
        for unit in units:
            Supervisor(None).terminate(unit)
        report = {"successful": error is None, "error": error, "checks": checks,
                  "seconds": round(time.monotonic() - start, 3), "commands": calls,
                  "evidence": "real registry artifacts and OSV; real confined imports and compilation; no model calls"}
        save(root / "report.json", report)
        print(json.dumps({k: v for k, v in report.items() if k != "commands"}, indent=2))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
