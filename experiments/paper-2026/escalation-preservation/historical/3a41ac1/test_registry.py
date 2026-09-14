#!/usr/bin/env python3
import threading
import unittest

from registry import Registry


class RegistryTests(unittest.TestCase):
    def deny(self, registry, event, session="s", job="j"):
        return registry.authorize(event_id=event, job_id=job, session_id=session,
                                  worker_id="w", permission_granted=False)

    def test_block_only_never_escalates(self):
        registry = Registry("block_only")
        for index in range(5):
            self.assertEqual(self.deny(registry, str(index))["reason"], "permission_violation")
        snap = registry.snapshot()
        self.assertEqual(snap["jobs"]["j"]["violations"], 5)
        self.assertFalse(snap["jobs"]["j"]["stopped"])
        self.assertFalse(snap["jobs"]["j"]["sessions"]["s"]["paused"])

    def test_session_pause_is_local(self):
        registry = Registry("session_local")
        self.deny(registry, "1")
        second = self.deny(registry, "2")
        self.assertEqual([t["transition"] for t in second["transitions"]], ["session_paused"])
        self.assertEqual(self.deny(registry, "3")["reason"], "session_paused")
        allowed = registry.authorize(event_id="4", job_id="j", session_id="other",
            worker_id="w", permission_granted=True)
        self.assertTrue(allowed["allowed"])

    def test_shared_counter_cannot_be_reset_by_sessions(self):
        registry = Registry("shared_job")
        for index in range(3):
            self.deny(registry, str(index), session=f"s{index}")
        snap = registry.snapshot()
        self.assertTrue(snap["jobs"]["j"]["stopped"])
        self.assertEqual(snap["jobs"]["j"]["violations"], 3)
        self.assertEqual(self.deny(registry, "later", session="fresh")["reason"], "job_stopped")

    def test_pause_selects_only_registered_session_work(self):
        registry = Registry("session_local")
        for wid, session in (("one", "s1"), ("two", "s2")):
            registry.register_workload(workload_id=wid, job_id="j", session_id=session,
                worker_id="w", container="c-" + wid, effect_token="t-" + wid)
        self.deny(registry, "1", session="s1")
        result = self.deny(registry, "2", session="s1")
        self.assertEqual(result["terminate"], ["one"])

    def test_unrelated_job_is_not_terminated(self):
        registry = Registry("shared_job")
        registry.register_workload(workload_id="target", job_id="j", session_id="run",
            worker_id="w", container="ct", effect_token="tt")
        registry.register_workload(workload_id="other", job_id="other", session_id="run",
            worker_id="w", container="co", effect_token="to")
        for index in range(3):
            result = self.deny(registry, str(index), session=f"s{index}")
        self.assertEqual(result["terminate"], ["target"])

    def test_atomic_job_transition_occurs_once(self):
        registry = Registry("shared_job")
        barrier = threading.Barrier(12)
        results = []
        lock = threading.Lock()

        def attempt(index):
            barrier.wait()
            value = self.deny(registry, str(index), session=f"s{index}")
            with lock:
                results.append(value)

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snap = registry.snapshot()
        self.assertEqual(snap["jobs"]["j"]["violations"], 3)
        self.assertEqual(sum(e.get("transition") == "job_stopped" for e in snap["events"]), 1)
        self.assertEqual(sum(r["reason"] == "job_stopped" for r in results), 9)


if __name__ == "__main__":
    unittest.main()
