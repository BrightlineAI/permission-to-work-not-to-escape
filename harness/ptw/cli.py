import argparse
import json
from pathlib import Path
import sys
import time

from . import __version__
from . import audit as audit_module
from .policy import Invalid, approve, check_approval, compile_policy, digest, load, save
from .store import Store


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'demo':
        from .demo import main as demo_main
        raise SystemExit(demo_main(argv[1:]))
    parser = argparse.ArgumentParser(description="Reviewed project controls for local agents")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser('demo', help='Run or verify the bundled deterministic demos')
    commands.add_parser("doctor", help="Check installation with real permitted, forbidden and stop probes")
    interactive = commands.add_parser("codex", help="Set up once, then open protected interactive Codex")
    interactive.add_argument("--repo", default=str(Path.cwd()))
    interactive.add_argument("--goal")
    interactive.add_argument("--editable", help="Comma separated top-level editable directories")
    interactive.add_argument("--files", help="Comma separated exact top-level editable files, including missing files")
    interactive.add_argument("--model-proposal", action="store_true", help="Optional model proposal with additional latency; same scope constraints")
    interactive.add_argument("--language", choices=["python", "javascript", "typescript", "mixed"])
    interactive.add_argument('--preview-python', metavar='PATH:PORT', help='Review a Python entry script and fixed localhost preview port; script receives PORT and HOST')
    interactive.add_argument('--preview-node', metavar='PATH:PORT', help='Review a Node entry script and fixed localhost preview port; script receives PORT and HOST')
    interactive.add_argument('--preview-seconds', type=int, help='Reviewed preview lifetime, 1 to 3600 seconds (default 900)')
    interactive.add_argument('--git', action='store_true', help='Review scoped local Git status/diff and operator-approved checkpoint refs')
    interactive.add_argument('--python', help='Installed system Python executable to review')
    interactive.add_argument('--python-source', help='Authoritative relative requirements file or pyproject.toml')
    local_python = interactive.add_mutually_exclusive_group()
    local_python.add_argument('--python-editable', help='Comma-separated selected source paths whose edits remain live in the local Python project; backend execution requires policy approval')
    local_python.add_argument('--python-wheel', action='store_true', help='Build and install the selected local Python project as a wheel after explicit policy review')
    interactive.add_argument('--python-native-wheels', action='store_true', help='Request native output in the local wheel/editable review, including assessed Python dependencies')
    interactive.add_argument('--python-full-build', action='store_true', help='Bind all editable source to the native build; changes require reviewed preparation')
    interactive.add_argument('--python-build-requirements', action='store_true', help='Review offline build requirement discovery before preparing a static local wheel or editable project')
    interactive.add_argument('--python-extras', help='Comma-separated pyproject extras to include')
    interactive.add_argument('--python-groups', help='Comma-separated pyproject dependency groups (default dev,test)')
    interactive.add_argument('--python-root', help='Relative Python project root (default root or detected backend)')
    interactive.add_argument('--node-root', help='Relative Node project root (default root or detected frontend)')
    interactive.add_argument('--npm-registry-config', help='Private operator registry configuration outside the repository; credentials are broker-only references')
    interactive.add_argument('--pnpm-build', action='append', metavar='NAME', help='Request an exact pnpm registry dependency lifecycle build in the policy review; repeat for each package')
    interactive.add_argument('--yarn-build', action='append', metavar='NAME', help='Request an exact Yarn registry dependency lifecycle build in the policy review; repeat for each package')
    interactive.add_argument('--python-registry-config', help='Private operator PyPI-compatible registry routes outside the repository; credentials remain in the broker')
    interactive.add_argument("--warn-at", type=int)
    interactive.add_argument("--stop-at", type=int)
    interactive.add_argument("--history", help="Optional selected, sanitized history as untrusted evidence")
    interactive.add_argument("--task")
    interactive.add_argument("--prompt", help="Optional first message in the genuine Codex terminal")
    operations = interactive.add_mutually_exclusive_group()
    operations.add_argument("--status", action="store_true")
    operations.add_argument("--stop", action="store_true")
    operations.add_argument("--review", action="store_true")
    operations.add_argument('--resume', nargs='?', const='', metavar='ID',
                            help='Resume a recorded protected conversation for this project and task')
    interactive.add_argument("--setup-only", action="store_true", help="Finish reviewed setup or revision without opening Codex")
    operations.add_argument("--revise", action="store_true", help="Review a new policy version; stop old work before switching")
    checkpoint = commands.add_parser('checkpoint', help='Review and explicitly approve one local checkpoint requested by protected Codex')
    checkpoint.add_argument('identity')
    checkpoint.add_argument('--repo', default=str(Path.cwd()))
    checkpoint.add_argument('--finding', action='append', help='Record an operator suspicion before exact candidate review; never waives missing evidence')
    checkpoint.add_argument('--event-ref', action='append', help='Original operation ID supporting each supplied finding (at most 32)')
    sequence = commands.add_parser('project-review', help='Inspect bounded linked project evidence offline; never approves a checkpoint')
    sequence.add_argument('--state', required=True)
    sequence.add_argument('--project', required=True)
    sequence.add_argument('--checkpoint', help='Inspect the exact existing checkpoint request/result')
    sequence.add_argument('--out', required=True, help='New private operator export; metadata plus scoped candidate only')
    sequence.add_argument('--codex', action='store_true', help='Export the exact selected optional Codex request; no call without --approve-upload')
    sequence.add_argument('--approve-upload', help='SHA256 of inspected Codex request; send only this bounded content using existing login')
    evidence = commands.add_parser('evidence', help='Export versioned metadata; no transcripts or tool output')
    evidence.add_argument('--state', required=True)
    evidence.add_argument('--project', required=True)
    evidence.add_argument('--out', required=True, help='Private operator export path')
    evidence_config = commands.add_parser('evidence-config', help='Review/adopt bounded evidence without clearing project history')
    evidence_config.add_argument('--state', required=True)
    evidence_config.add_argument('--project', required=True)
    evidence_config.add_argument('--project-bytes', type=int, default=1073741824)
    evidence_config.add_argument('--content-resource', action='append', default=[])
    evidence_config.add_argument('--approve', help='Exact displayed review hash; omit to review')
    evidence_config.add_argument('--reviewer', default='')
    retention = commands.add_parser('evidence-expire', help='Expire only eligible optional content, keeping tombstones')
    retention.add_argument('--state', required=True)
    retention.add_argument('--project', required=True)
    archive = commands.add_parser('evidence-archive', help='Explicit metadata export of closed history; no deletion')
    archive.add_argument('--state', required=True)
    archive.add_argument('--project', required=True)
    archive.add_argument('--out', required=True)
    dependencies = commands.add_parser('deps', help='Review an add/remove/update while preserving project history')
    dependencies.add_argument('operation', choices=['add', 'remove', 'update'])
    dependencies.add_argument('specs', nargs='+')
    dependencies.add_argument('--repo', default=str(Path.cwd()))
    dependencies.add_argument('--ecosystem', choices=['pypi', 'npm'], required=True)
    dependencies.add_argument('--root', default='', help='Relative ecosystem root, for example backend or frontend')
    dependencies.add_argument('--source', help='Requirements file, pyproject.toml, or reviewed workspace package.json relative to --root')
    dependencies.add_argument('--group', help='Python dependency group or extra:NAME; npm dependencies/devDependencies/optionalDependencies/peerDependencies')
    dependencies.add_argument('--task', default='work')
    sample = commands.add_parser("sample", help="Create a fresh synthetic project")
    sample.add_argument("--out", required=True)
    sample.add_argument("--packages", action="store_true", help="Include reviewed Python package control example")
    sample.add_argument("--workspace", choices=["python", "typescript"], help="Create a small real repository and version 4 policy")
    prepare = commands.add_parser("prepare", help="Inventory an existing repository and propose a reviewed version 4 workflow")
    prepare.add_argument("--repo", required=True)
    prepare.add_argument("--description", required=True)
    prepare.add_argument("--commands", help="Operator candidate commands JSON; resource names are repository paths")
    prepare.add_argument("--requirements")
    prepare.add_argument("--npm-lock")
    prepare.add_argument("--history")
    prepare.add_argument("--model", default="gpt-5.6-sol")
    prepare.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    prepare.add_argument("--out", required=True)
    propose = commands.add_parser("propose", help="Codex drafts policy, never approves it")
    propose.add_argument("--description", required=True)
    propose.add_argument("--inventory", required=True)
    propose.add_argument("--history")
    propose.add_argument("--out", required=True)
    propose.add_argument("--model", default="gpt-5.6-sol")
    propose.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    review = commands.add_parser("review", help="Inspect exact draft and review hash")
    approval = commands.add_parser("approve", help="Operator approves the exact reviewed bundle")
    for command in [review, approval]:
        command.add_argument("--policy", required=True)
        command.add_argument("--inventory", required=True)
    approval.add_argument("--sha256", required=True)
    approval.add_argument("--reviewer", required=True)
    approval.add_argument("--out", required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--bundle", required=True)
    register = commands.add_parser("register")
    register.add_argument("--project", required=True)
    register.add_argument("--task", required=True)
    register.add_argument("--parent", help="Private parent session file, for a narrower delegate")
    register.add_argument("--grants", help="Optional JSON grant array, to narrow further")
    register.add_argument("--packages", help="Optional JSON name array, to narrow package scope further")
    register.add_argument("--commands", help="Optional JSON command ID array, to narrow further")
    register.add_argument("--out", required=True)
    request = commands.add_parser("request")
    request.add_argument("--session", required=True)
    request.add_argument("--event", required=True)
    request.add_argument("--action", required=True)
    request.add_argument("--resource", required=True)
    request.add_argument("--content", default="")
    action = commands.add_parser("action", help="Unified repository/package/command request through reviewed scope")
    action.add_argument("--session", required=True)
    action.add_argument("--event", required=True)
    action.add_argument("--request", required=True, help="Structured request JSON file, not executable code")
    action.add_argument("--out", help="Optional private result JSON")
    status = commands.add_parser("status")
    stop = commands.add_parser("stop")
    for command in [status, stop]:
        command.add_argument("--project", required=True)
    run = commands.add_parser("run", help="Codex resource task through the protected broker")
    run.add_argument("--project")
    run.add_argument("--task")
    run.add_argument("--session", help="Use an existing private registered session")
    run.add_argument("--assignment", required=True)
    run.add_argument("--parent", help="Private parent session file")
    run.add_argument("--model", default="gpt-5.6-sol")
    run.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    run.add_argument("--max-steps", type=int, default=8)
    run.add_argument("--out", required=True)
    launch = commands.add_parser("launch", help="Operator launches a confined local workload")
    launch.add_argument("--session", required=True)
    launch.add_argument("--package-set", help="Approved package set returned by package-install")
    launch.add_argument("argv", nargs=argparse.REMAINDER)
    package = commands.add_parser("package-install", help="Check and install pinned Python packages or an npm lock")
    package.add_argument("--session", required=True)
    package.add_argument("--event", required=True)
    inputs = package.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--requirements", help="Exact Python pins, including runtime and build dependencies")
    inputs.add_argument("--npm-lock", help="npm package-lock.json version 2 or 3")
    inputs.add_argument("--pnpm-lock", help="Reviewed pnpm-lock.yaml with its original project metadata")
    inputs.add_argument("--yarn-lock", help="Reviewed yarn.lock with its original project metadata")
    package.add_argument("--out", help="Optional new receipt file")
    package_draft = commands.add_parser("package-draft", help="Add package controls to a version 1 draft; never approve or activate")
    package_draft.add_argument("--policy", required=True)
    package_draft.add_argument("--project-id", required=True, help="Explicit new project version identity")
    package_draft.add_argument("--task", required=True)
    package_draft.add_argument("--allow", action="append", default=[], help="Package identity, repeat for each dependency")
    package_draft.add_argument("--ecosystems", action="store_true", help="Create version 3 qualified Python/npm policy")
    package_draft.add_argument("--npm-lock", help="Propose all package names from this npm lock; requires operator review")
    package_draft.add_argument("--requirements", help="Propose all names from exact Python pins; requires operator review")
    package_draft.add_argument("--native", action="store_true", help="Propose compatible native Python wheels")
    package_draft.add_argument("--build", action="append", default=[], help="Explicit qualified package permitted an offline build")
    package_draft.add_argument("--min-age-days", type=int)
    package_draft.add_argument("--deny-cvss", type=float)
    package_draft.add_argument("--out", required=True)
    watch = commands.add_parser("watch", help="Retry and verify pending project terminations")
    watch.add_argument("--once", action="store_true")
    monitor = commands.add_parser("monitor", help="Inspect, install/restart or safely remove automatic monitoring")
    monitor.add_argument("operation", choices=["status", "ensure", "remove"])
    recover = commands.add_parser("recover", help="Reconcile interrupted work; never reset stopped history")
    recover.add_argument("--project", required=True)
    change = commands.add_parser("change", help="Draft one narrow operator permission change for review")
    for name in ["project", "task", "resource", "action", "reason", "project-id", "out"]:
        change.add_argument("--" + name, required=True)
    replace = commands.add_parser("replace", help="Stop old work, confirm termination, activate a separately approved new version")
    replace.add_argument("--project", required=True)
    replace.add_argument("--bundle", required=True)
    events = commands.add_parser("events", help="Export content free policy event metadata")
    events.add_argument("--project", required=True)
    audit = commands.add_parser("audit", help="Compare selected Codex logs with reviewed scope")
    audit.add_argument("--bundle", required=True)
    audit.add_argument("--history", required=True)
    audit.add_argument("--task", required=True)
    audit.add_argument("--out", required=True)
    for command in [activate, register, request, status, stop, run, launch, package, watch, events,
                    action, monitor, recover, change, replace]:
        command.add_argument("--state", required=True, help="Private controller directory outside resources")
    args = parser.parse_args(argv)
    if args.command == 'codex' and args.setup_only and (args.status or args.stop or args.review or args.resume is not None):
        parser.error('--setup-only cannot be combined with --status, --stop, --review or --resume')
    try:
        result = execute(args)
        print(json.dumps(result, indent=2))
        if args.command == "doctor" and not result["ready"]:
            raise SystemExit(1)
        if args.command == "package-install" and not result["allowed"]:
            raise SystemExit(1)
        if args.command == "action" and (not result.get("allowed") or result.get("exit_code", 0) != 0):
            raise SystemExit(1)
    except (EOFError, KeyboardInterrupt):
        print("\nCanceled. Rerun ptw codex to recover any interrupted setup.", file=sys.stderr)
        raise SystemExit(130)
    except (Invalid, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)


def execute(args):
    if args.command == 'project-review':
        from .sequence_review import project_review, reviewer_request, selected_review
        from .evidence_storage import private_export
        result = project_review(Store(args.state), args.project, checkpoint=args.checkpoint)
        if args.approve_upload and not args.codex:
            raise Invalid('--approve-upload requires --codex')
        if args.codex:
            if not args.checkpoint:
                raise Invalid('Optional reviewer requires an exact checkpoint')
            selected = reviewer_request(result)
            if args.approve_upload:
                result = selected_review(Store(args.state), args.project, args.checkpoint, args.approve_upload)
                private_export(args.out, result)
                return result
            private_export(args.out, selected)
            return {'upload_sha256': digest(selected), 'calls': 0,
                    'disclosure': 'Only the exported request will be sent; inspect before --approve-upload'}
        private_export(args.out, result)
        return {'export_sha256': digest(result), 'review_sha256': result['review_sha256'],
                'coverage': result['review_input']['coverage'], 'acceptance': result['acceptance']}
    if args.command == 'evidence-config':
        store = Store(args.state)
        profile = {'version': 1, 'project_bytes': args.project_bytes, 'content_resources': args.content_resource}
        if args.approve:
            return store.adopt_evidence(args.project, profile, args.approve, args.reviewer)
        packet = store.evidence_review(args.project, profile)
        return {'review': packet, 'review_sha256': digest(packet)}
    if args.command == 'evidence-expire':
        return Store(args.state).expire_evidence(args.project)
    if args.command == 'evidence-archive':
        return Store(args.state).archive_evidence(args.project, args.out)
    if args.command == 'evidence':
        from .evidence_storage import private_export
        result = Store(args.state).audit_export(args.project)
        private_export(args.out, result)
        return {'export_sha256': digest(result), 'events': result['manifest']['count']}
    if args.command == 'checkpoint':
        from .local_git import review_checkpoint
        return review_checkpoint(args)
    if args.command == 'deps':
        from .dependency_revision import start
        return start(args)
    if args.command == "codex":
        from .onboarding import start
        return start(args)
    if args.command == "doctor":
        from .doctor import check
        return check()
    if args.command == "sample":
        if args.workspace:
            from .project_example import create
            return create(args.out, args.workspace)
        from .sample import create
        return create(args.out, packages=args.packages)
    if args.command == "prepare":
        from .workflow import prepare
        return prepare(args.repo, Path(args.description).read_text(), args.out,
                       commands=args.commands, requirements=args.requirements, npm_lock=args.npm_lock,
                       history=args.history, model=args.model, effort=args.effort)
    if args.command == "package-draft":
        from .policy import PACKAGE_SCHEMA, ECOSYSTEM_SCHEMA, validate
        draft = load(args.policy)
        if draft.get("version") not in (1, 2, 3):
            raise Invalid("Unknown draft policy version")
        extended = args.ecosystems or args.npm_lock or args.requirements or args.native or args.build
        if draft.get("version") != 1 and not extended:
            raise Invalid("Existing package policies need --ecosystems for a version 3 migration")
        if draft["project"]["id"] == args.project_id:
            raise Invalid("Use an explicit new project identity; active history cannot be reset")
        if args.task not in {task["id"] for task in draft["tasks"]}:
            raise Invalid("Unknown task")
        names = set(args.allow)
        if args.requirements:
            from .package_evidence import pins
            raw = Path(args.requirements).read_text()
            if len(raw) > 65536:
                raise Invalid("Requirements file too large")
            names.update("pypi:" + n for n in pins(
                [line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")], extras={}))
        if args.npm_lock:
            from .npm import NpmPlan
            names.update("npm:" + x.rsplit("@", 1)[0] for x in NpmPlan(load(args.npm_lock)).selected)
        if not names:
            raise Invalid("Provide --allow or --npm-lock for the selected task")
        # Retain other tasks' existing scopes, but never change a live policy.
        old_version = draft["version"]
        old_rules = draft["project"].get("packages", {})
        existing = draft["project"].get("packages", {}).get("allowed_names", [])
        if extended and old_version == 2:
            existing = ["pypi:" + x for x in existing]
        draft["version"] = 3 if extended else 2
        draft["project"]["id"] = args.project_id
        draft["project"]["packages"] = {"allowed_names": sorted(set(existing) | names),
            "min_release_age_days": args.min_age_days if args.min_age_days is not None else old_rules.get("min_release_age_days", 3),
            "deny_cvss_at_or_above": args.deny_cvss if args.deny_cvss is not None else old_rules.get("deny_cvss_at_or_above", 9.0),
            "evidence_max_age_seconds": old_rules.get("evidence_max_age_seconds", 900)}
        for task in draft["tasks"]:
            retained = task.get("packages", [])
            if extended and old_version == 2:
                retained = ["pypi:" + x for x in retained]
            task["packages"] = sorted(names) if task["id"] == args.task else retained
        if extended:
            draft["project"]["packages"].update(
                allow_native_wheels=args.native or old_rules.get("allow_native_wheels", False),
                build_packages=sorted(set(args.build) | set(old_rules.get("build_packages", []))))
        validate(ECOSYSTEM_SCHEMA if extended else PACKAGE_SCHEMA, draft)
        save(args.out, draft)
        return {"draft": args.out, "approved": False, "note": "Review all scope before approval. Stop the old project before switching."}
    if args.command == "propose":
        from .codex import propose
        if any(Path(args.out + suffix).exists() for suffix in ["", ".meta.json", ".attempts.json"]):
            raise Invalid("Draft output already exists")
        policy, metadata = propose(Path(args.description).read_text(), load(args.inventory), history=args.history,
                                   model=args.model, effort=args.effort, attempts_path=args.out + ".attempts.json")
        save(args.out, policy)
        save(args.out + ".meta.json", metadata)
        return {"draft": args.out, "approved": False, "generation": metadata}
    if args.command == "review":
        compiled = compile_policy(load(args.policy), load(args.inventory))
        return {"sha256": digest(compiled), **compiled,
                "review": "Check project intent, every grant and task, and escalation. Inventory is not permission."}
    if args.command == "approve":
        bundle = approve(load(args.policy), load(args.inventory), args.sha256, args.reviewer)
        save(args.out, bundle)
        return {"bundle": args.out, "sha256": args.sha256}
    if args.command == "audit":
        bundle = load(args.bundle)
        check_approval(bundle)
        result = audit_module.audit(args.history, bundle["policy"], bundle["inventory"], args.task)
        save(args.out, result)
        return result
    store = Store(args.state)
    from .supervisor import Supervisor
    supervisor = Supervisor(store)
    supervisor.reconcile()
    if args.command == "activate":
        bundle = load(args.bundle)
        if bundle["policy"]["version"] == 4:
            from .monitor import ensure
            ensure(store)
        return store.activate(bundle)
    if args.command == "monitor":
        from .monitor import health, ensure, remove
        return {"status": health, "ensure": ensure, "remove": remove}[args.operation](store)
    if args.command == "recover":
        from .monitor import ensure
        monitoring = ensure(store)
        return {"monitor": monitoring, "termination": supervisor.reconcile(),
                "status": store.status(args.project),
                "next": "Stopped projects stay stopped. Inspect uncertain effects and explicitly review a new version."}
    if args.command == "change":
        from .workflow import change
        return change(store, args.project, args.task, args.resource, args.action, args.reason, args.out, args.project_id)
    if args.command == "replace":
        bundle = load(args.bundle)
        check_approval(bundle)  # Fail before stopping current work on an invalid draft.
        if bundle["policy"]["project"]["id"] == args.project:
            raise Invalid("Replacement must have an explicit new project identity")
        with store.locked() as db:
            old, old_bundle = store.project(db, args.project)
            if old_bundle["inventory"]["root"] != bundle["inventory"]["root"]:
                raise Invalid("Replacement must refer to the same repository")
            if db.execute("SELECT 1 FROM projects WHERE id=?", (bundle["policy"]["project"]["id"],)).fetchone():
                raise Invalid("Replacement identity already exists")
        from .monitor import ensure
        monitoring = ensure(store)
        store.stop(args.project, "operator approved replacement: " + bundle["policy"]["project"]["id"])
        outcomes = supervisor.reconcile()
        old_status = store.status(args.project)
        if any(not w["stopped"] for w in old_status["workloads"]):
            raise Invalid("Old work has pending termination; new project was not activated")
        return {"previous": args.project, "previous_history_retained": True,
                "termination": outcomes, "monitor": monitoring, **store.activate(bundle)}
    if args.command == "register":
        parent = load(args.parent)["token"] if args.parent else None
        result = store.register(args.project, args.task, parent_token=parent,
                                grants=load(args.grants) if args.grants else None,
                                packages=load(args.packages) if args.packages else None,
                                commands=load(args.commands) if args.commands else None)
        save(args.out, result)
        return {k: v for k, v in result.items() if k != "token"}
    if args.command == "request":
        return store.request(load(args.session)["token"], args.event,
                             {"action": args.action, "resource": args.resource, "content": args.content})
    if args.command == "action":
        from .workflow import dispatch
        from .monitor import ensure
        if args.out and Path(args.out).exists():
            raise Invalid("Result output already exists")
        ensure(store)
        session = load(args.session)
        # Identity comes from the registered token, not editable session labels.
        with store.locked() as db:
            actor = store.session(db, session["token"])
            session.update(project=actor["project"], task=actor["task"])
        result = dispatch(store, session, args.event, load(args.request))
        if not result.get("allowed"):
            result = {**result, "next": "Read the reason. Fix an input/conflict, or ask the operator to draft a narrow reviewed change. Do not bypass."}
        if args.out:
            save(args.out, result)
        return result
    if args.command == "package-install":
        from .packages import PackageControl
        if args.out and Path(args.out).exists():
            raise Invalid("Receipt output already exists")
        if args.yarn_lock:
            from .yarn import read_inputs
            lock = Path(args.yarn_lock).absolute()
            if lock.name != 'yarn.lock':
                raise Invalid('Select the authoritative yarn.lock')
            specs, ecosystem = {'manager': 'yarn', 'files': read_inputs(lock.parent)[0]}, 'npm'
        elif args.pnpm_lock:
            from .pnpm import read_inputs
            lock = Path(args.pnpm_lock).absolute()
            if lock.name != 'pnpm-lock.yaml':
                raise Invalid('Select the authoritative pnpm-lock.yaml')
            specs, ecosystem = {'manager': 'pnpm', 'files': read_inputs(lock.parent)[0]}, 'npm'
        elif args.npm_lock:
            if Path(args.npm_lock).stat().st_size > 8 * 1024 * 1024:
                raise Invalid("npm lock too large")
            specs, ecosystem = load(args.npm_lock), "npm"
        else:
            raw = Path(args.requirements).read_text()
            if len(raw) > 65536:
                raise Invalid("Requirements file too large")
            specs = [line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            ecosystem = "pypi"
        result = PackageControl(store).install(load(args.session)["token"], args.event, specs, ecosystem=ecosystem)
        if args.out:
            save(args.out, result)
        return result
    if args.command == "status":
        from .monitor import health
        return {**store.status(args.project), "monitor": health(store)}
    if args.command == "stop":
        store.stop(args.project)
        return {"project": args.project, "termination": supervisor.reconcile(), "status": store.status(args.project)}
    if args.command == "events":
        return store.audit_events(args.project)
    if args.command == "launch":
        command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        return {"unit": supervisor.launch(load(args.session)["token"], command, package_set=args.package_set)}
    if args.command == "watch":
        if args.once:
            return supervisor.reconcile()
        try:
            while True:
                supervisor.reconcile()
                time.sleep(.25)
        except KeyboardInterrupt:
            return {"watch": "stopped; project admission state remains durable"}
    if args.command == "run":
        from .codex import drive
        if Path(args.out).exists():
            raise Invalid("Run output already exists")
        if args.session:
            if args.project or args.task or args.parent:
                raise Invalid("Use --session or --project/--task/--parent, not both")
            raw = load(args.session)
            with store.locked() as db:
                actor = store.session(db, raw["token"])
                session = {"token": raw["token"], "session": actor["id"], "project": actor["project"], "task": actor["task"],
                           "grants": json.loads(actor["grants"]), "packages": json.loads(actor["packages"]),
                           "commands": json.loads(actor["commands"])}
        else:
            if not args.project or not args.task:
                raise Invalid("Specify --session or both --project and --task")
            session = store.register(args.project, args.task, parent_token=load(args.parent)["token"] if args.parent else None)
        with store.locked() as db:
            _, bundle = store.project(db, session["project"])
        if bundle["policy"]["version"] == 4:
            from .monitor import ensure
            ensure(store)
            from .workflow import drive
        result = drive(store, session, Path(args.assignment).read_text(), model=args.model, effort=args.effort, max_steps=args.max_steps)
        save(args.out, result)
        return {"outcome": result["outcome"], "output": args.out, "requests": len(result["steps"]),
                "model_calls": len(result["model_calls"]), "extra_runtime_authorization_model_calls": 0}
