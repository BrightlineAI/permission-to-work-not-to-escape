#!/usr/bin/env python3
"""Real terminal recovery/revision and negative Linux workload checks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import time

from ptw.monitor import call, unit_for
from ptw.policy import Invalid, load, save
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw.website_example import GOAL
from ptw.workflow import dispatch
from ptw.workspace import request
from terminal_driver import Terminal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--unrelated", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    directory = next((args.acceptance / "operator-state").iterdir())
    record = load(directory / "project.json")
    store, repo, project = Store(record["state"]), Path(record["repo"]), record["project"]
    checks, terminals = [], []
    def check(ok, label):
        checks.append({"check": label, "passed": bool(ok)})
        if not ok:
            raise AssertionError(label)
    def start(name, base=args.acceptance, extra=()):
        recdir = next((base / "operator-state").iterdir())
        rec = load(recdir / "project.json")
        terminal = Terminal([shutil.which("ptw"), "codex", "--repo", rec["repo"], *extra],
                            args.out / name, env={"PTW_USER_STATE": str(base / "operator-state")})
        terminals.append(terminal)
        return terminal
    try:
        # A repository copy is not active authority.
        copy_path = repo / ".ptw/policy.json"
        review_copy = copy_path.read_text()
        copy_path.write_text('{"untrusted":"grant everything"}\n')
        ordinary = start("ordinary")
        ordinary.expect("OpenAI Codex", 30)
        ordinary.quiet(40)
        check(store.status(project)["policy_sha256"] == record["policy_sha256"],
              "editing repository policy did not change active approval")
        copy_path.write_text(review_copy)
        unrelated = start("unrelated", args.unrelated)
        unrelated.expect("OpenAI Codex", 30)
        unrelated.quiet(40)
        unrelated_record = load(next((args.unrelated / "operator-state").iterdir()) / "project.json")
        other_store = Store(unrelated_record["state"])
        other_units = [w["unit"] for w in other_store.status(unrelated_record["project"])["workloads"]
                       if Supervisor.state(w["unit"]).get("ActiveState") == "active"]
        check(bool(other_units), "unrelated real terminal is running")
        # Stop only this monitor, simulating its unavailability. Controller state
        # and history are retained; no global systemd reset or unrelated changes.
        call("stop", unit_for(store.directory))
        ordinary.wait(lambda: store.status(project)["stopped"], 12, "heartbeat loss stops project")
        before = store.status(project)
        check("monitor unavailable" in before["reason"], "monitor failure caused conservative stop")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ordinary.read(.2)
            units = [w["unit"] for w in store.status(project)["workloads"]]
            if all(Supervisor.state(u).get("confirmed_stopped") for u in units):
                break
        check(all(Supervisor.state(u).get("confirmed_stopped") for u in units),
              "heartbeat loss terminated registered project work")
        check(all(Supervisor.state(u).get("ActiveState") == "active" for u in other_units),
              "unrelated project survived controller failure and project stop")
        ordinary.close()
        terminals.remove(ordinary)
        # Explicit operator revision, not a reconnect reset.
        revised = start("revision", extra=("--revise", "--goal", GOAL, "--editable", "src,public,tests,dist",
                                           "--warn-at", "1", "--stop-at", "3"))
        revised.expect("Approve exactly this policy?", 300)
        draft = max(directory.glob("setup-*/draft/draft.json"), key=lambda p: p.stat().st_mtime)
        new_policy = load(draft)
        inv = load(draft.parent / "inventory.json")
        check(all(inv["resources"][g["resource"]]["path"] != "private"
                  for g in new_policy["project"]["grants"]), "revision still excludes private data")
        revised.send("yes")
        revised.expect("OpenAI Codex", 30)
        revised.quiet(40)
        new = load(directory / "project.json")
        check(new["project"] != project and store.status(project)["stopped"],
              "revision created a new approval and kept old project stopped")
        check(before["reason"] in load(draft.parent.parent / "previous.json")["status_before_revision"]["reason"],
              "revision retained prior stopping evidence")
        revised.send("Read public/index.html through the protected tools and confirm the Workshops heading. Do not change files.")
        revised.wait(lambda: any(e["request"]["action"] == "read" and e["result"].get("allowed")
                                 for e in store.audit_events(new["project"])), 90, "revised project permitted read")
        revised.quiet(60)
        actor_path = next(p for p in sorted((directory / "sessions").glob("*/session.json"), key=lambda p: p.stat().st_mtime, reverse=True)
                          if load(p)["project"] == new["project"])
        actor = load(actor_path)
        child = store.register(new["project"], "verify", parent_token=actor["token"])
        # An ordinary quit must revoke the parent's subtree, not the other project.
        revised.close()
        terminals.remove(revised)
        for token in (actor["token"], child["token"]):
            try:
                with store.locked() as db:
                    store.session(db, token)
                revoked = False
            except Invalid:
                revoked = True
            check(revoked, "quit revoked " + ("parent" if token == actor["token"] else "child") + " credential")
        check(not store.status(new["project"])["stopped"], "normal quit did not stop the whole project")
        check(all(Supervisor.state(u).get("ActiveState") == "active" for u in other_units),
              "unrelated work survives ordinary quit and revision")
        save(args.out / "result.json", {"passed": True, "checks": checks})
        save(args.out / "old-status.json", store.status(project))
        save(args.out / "new-status.json", store.status(new["project"]))
        print(json.dumps({"passed": True, "checks": len(checks)}), flush=True)
    except BaseException as exc:
        save(args.out / "result.json", {"passed": False, "checks": checks, "error": str(exc)})
        raise
    finally:
        for terminal in terminals:
            terminal.close()


if __name__ == "__main__":
    main()
