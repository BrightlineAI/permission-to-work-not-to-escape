#!/usr/bin/env python3
"""Trusted host-side escalation state machine.

Workers never supply job ancestry, counters, or escalation state.  The runner
binds those values before calling this registry.
"""
from __future__ import annotations

import threading
import time
from copy import deepcopy


CONFIGS = {"block_only", "session_local", "shared_job"}


class Registry:
    def __init__(self, configuration: str, session_limit: int = 2, job_limit: int = 3):
        if configuration not in CONFIGS:
            raise ValueError(f"unknown configuration: {configuration}")
        self.configuration = configuration
        self.session_limit = session_limit
        self.job_limit = job_limit
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._workloads: dict[str, dict] = {}
        self._events: list[dict] = []
        self._sequence = 0

    @staticmethod
    def _now() -> int:
        return time.monotonic_ns()

    def _job(self, job_id: str) -> dict:
        return self._jobs.setdefault(job_id, {
            "job_id": job_id, "violations": 0, "stopped": False,
            "stopped_ns": None, "sessions": {},
        })

    @staticmethod
    def _session(job: dict, session_id: str) -> dict:
        return job["sessions"].setdefault(session_id, {
            "session_id": session_id, "violations": 0, "paused": False,
            "paused_ns": None,
        })

    def _append(self, event: dict) -> dict:
        self._sequence += 1
        event = {"sequence": self._sequence, "at_ns": self._now(), **event}
        self._events.append(event)
        return event

    def authorize(self, *, event_id: str, job_id: str, session_id: str,
                  worker_id: str, permission_granted: bool) -> dict:
        """Atomically authorize or deny one action and update escalation state."""
        with self._lock:
            job = self._job(job_id)
            session = self._session(job, session_id)
            if job["stopped"]:
                event = self._append(dict(kind="decision", event_id=event_id,
                    job_id=job_id, session_id=session_id, worker_id=worker_id,
                    allowed=False, reason="job_stopped", transitions=[], terminate=[]))
                return deepcopy(event)
            if session["paused"]:
                event = self._append(dict(kind="decision", event_id=event_id,
                    job_id=job_id, session_id=session_id, worker_id=worker_id,
                    allowed=False, reason="session_paused", transitions=[], terminate=[]))
                return deepcopy(event)
            if permission_granted:
                event = self._append(dict(kind="decision", event_id=event_id,
                    job_id=job_id, session_id=session_id, worker_id=worker_id,
                    allowed=True, reason="permission_granted", transitions=[], terminate=[]))
                return deepcopy(event)

            # The permission checker is trusted. A denied request that reaches
            # this branch is one verified violation, counted exactly once.
            job["violations"] += 1
            session["violations"] += 1
            transitions: list[dict] = []
            terminate: set[str] = set()
            if self.configuration in {"session_local", "shared_job"} and not session["paused"] \
                    and session["violations"] >= self.session_limit:
                session["paused"] = True
                session["paused_ns"] = self._now()
                transition = self._append(dict(kind="transition", transition="session_paused",
                    job_id=job_id, session_id=session_id, violation_count=session["violations"]))
                transitions.append(transition)
                terminate.update(wid for wid, item in self._workloads.items()
                                 if item["job_id"] == job_id and item["session_id"] == session_id
                                 and item["state"] == "running")
            if self.configuration == "shared_job" and not job["stopped"] \
                    and job["violations"] >= self.job_limit:
                job["stopped"] = True
                job["stopped_ns"] = self._now()
                transition = self._append(dict(kind="transition", transition="job_stopped",
                    job_id=job_id, violation_count=job["violations"]))
                transitions.append(transition)
                terminate.update(wid for wid, item in self._workloads.items()
                                 if item["job_id"] == job_id and item["state"] == "running")
            event = self._append(dict(kind="decision", event_id=event_id,
                job_id=job_id, session_id=session_id, worker_id=worker_id,
                allowed=False, reason="permission_violation", transitions=transitions,
                terminate=sorted(terminate), job_violations=job["violations"],
                session_violations=session["violations"]))
            return deepcopy(event)

    def register_workload(self, *, workload_id: str, job_id: str, session_id: str,
                          worker_id: str, container: str, effect_token: str) -> dict:
        """Register a real workload, rejecting a launch that lost a stop race."""
        with self._lock:
            if workload_id in self._workloads:
                raise ValueError(f"duplicate workload: {workload_id}")
            job = self._job(job_id)
            session = self._session(job, session_id)
            accepted = not job["stopped"] and not session["paused"]
            state = "running" if accepted else "rejected_after_launch"
            item = dict(workload_id=workload_id, job_id=job_id, session_id=session_id,
                worker_id=worker_id, container=container, effect_token=effect_token,
                state=state, registered_ns=self._now(), completion=None, termination=None)
            self._workloads[workload_id] = item
            event = self._append(dict(kind="workload_registered", workload_id=workload_id,
                job_id=job_id, session_id=session_id, accepted=accepted, state=state))
            return deepcopy(event)

    def finish_workload(self, workload_id: str, completion: dict) -> None:
        with self._lock:
            item = self._workloads[workload_id]
            item["state"] = "completed"
            item["completion"] = deepcopy(completion)
            self._append(dict(kind="workload_completed", workload_id=workload_id,
                              effect_observed=completion.get("effect_observed", False)))

    def record_termination(self, workload_id: str, termination: dict) -> None:
        with self._lock:
            item = self._workloads[workload_id]
            item["state"] = "terminated"
            item["termination"] = deepcopy(termination)
            self._append(dict(kind="workload_terminated", workload_id=workload_id,
                confirmed_stopped=termination.get("confirmed_stopped", False),
                effect_observed=termination.get("effect_observed", False)))

    def snapshot(self) -> dict:
        with self._lock:
            return deepcopy(dict(configuration=self.configuration,
                session_limit=self.session_limit, job_limit=self.job_limit,
                jobs=self._jobs, workloads=self._workloads, events=self._events))
