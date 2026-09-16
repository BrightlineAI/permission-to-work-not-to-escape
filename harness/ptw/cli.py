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
    parser = argparse.ArgumentParser(description="Reviewed project controls for local agents")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("sample", help="Create a fresh synthetic project")
    sample.add_argument("--out", required=True)
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
    register.add_argument("--out", required=True)
    request = commands.add_parser("request")
    request.add_argument("--session", required=True)
    request.add_argument("--event", required=True)
    request.add_argument("--action", required=True)
    request.add_argument("--resource", required=True)
    request.add_argument("--content", default="")
    status = commands.add_parser("status")
    stop = commands.add_parser("stop")
    for command in [status, stop]:
        command.add_argument("--project", required=True)
    run = commands.add_parser("run", help="Codex resource task through the protected broker")
    run.add_argument("--project", required=True)
    run.add_argument("--task", required=True)
    run.add_argument("--assignment", required=True)
    run.add_argument("--parent", help="Private parent session file")
    run.add_argument("--model", default="gpt-5.6-sol")
    run.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    run.add_argument("--max-steps", type=int, default=8)
    run.add_argument("--out", required=True)
    launch = commands.add_parser("launch", help="Operator launches a confined local workload")
    launch.add_argument("--session", required=True)
    launch.add_argument("argv", nargs=argparse.REMAINDER)
    watch = commands.add_parser("watch", help="Retry and verify pending project terminations")
    watch.add_argument("--once", action="store_true")
    events = commands.add_parser("events", help="Export content free policy event metadata")
    events.add_argument("--project", required=True)
    audit = commands.add_parser("audit", help="Compare selected Codex logs with reviewed scope")
    audit.add_argument("--bundle", required=True)
    audit.add_argument("--history", required=True)
    audit.add_argument("--task", required=True)
    audit.add_argument("--out", required=True)
    for command in [activate, register, request, status, stop, run, launch, watch, events]:
        command.add_argument("--state", required=True, help="Private controller directory outside resources")
    args = parser.parse_args(argv)
    try:
        result = execute(args)
        print(json.dumps(result, indent=2))
    except (Invalid, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)


def execute(args):
    if args.command == "sample":
        from .sample import create
        return create(args.out)
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
        return store.activate(load(args.bundle))
    if args.command == "register":
        parent = load(args.parent)["token"] if args.parent else None
        result = store.register(args.project, args.task, parent_token=parent,
                                grants=load(args.grants) if args.grants else None)
        save(args.out, result)
        return {k: v for k, v in result.items() if k != "token"}
    if args.command == "request":
        return store.request(load(args.session)["token"], args.event,
                             {"action": args.action, "resource": args.resource, "content": args.content})
    if args.command == "status":
        return store.status(args.project)
    if args.command == "stop":
        store.stop(args.project)
        return {"project": args.project, "termination": supervisor.reconcile(), "status": store.status(args.project)}
    if args.command == "events":
        return store.audit_events(args.project)
    if args.command == "launch":
        command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        return {"unit": supervisor.launch(load(args.session)["token"], command)}
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
        session = store.register(args.project, args.task, parent_token=load(args.parent)["token"] if args.parent else None)
        result = drive(store, session, Path(args.assignment).read_text(), model=args.model, effort=args.effort, max_steps=args.max_steps)
        save(args.out, result)
        return {"outcome": result["outcome"], "output": args.out, "requests": len(result["steps"]),
                "model_calls": len(result["model_calls"]), "extra_runtime_authorization_model_calls": 0}
