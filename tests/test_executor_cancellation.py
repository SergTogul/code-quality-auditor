"""Adversarial coverage for executor timeout termination and cancellation.

These tests exercise the executor directly. They are not a full audit integration
run, and they do not mark requirements verified in the traceability checklist.
"""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".cursor" / "skills" / "code-quality-auditor"
sys.path.insert(0, str(SKILL / "scripts"))

spec = importlib.util.spec_from_file_location("auditor", SKILL / "scripts" / "auditor.py")
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)

import cqa.audit as audit_module  # noqa: E402
import cqa.executor as executor_module  # noqa: E402
from cqa.executor import (  # noqa: E402
    Tombstone,
    TransientFailure,
    _dict_delta,
    _list_change,
    _merge_dict,
    _run_thread_task,
    execute,
)


REGISTRY = {
    "left": {"id": "left", "depends_on": []},
    "right": {"id": "right", "depends_on": ["left"]},
}


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _running(pid):
    """Like _alive, but a killed zombie still waiting for init to reap it counts as dead."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rpartition(b")")[2].split()[0] != b"Z"
    except FileNotFoundError:
        return False
    except OSError:
        return _alive(pid)


# A stopped fallback attempt has its closure lists rolled back, so runners
# record their calls in a file the rollback cannot reach.
def _log_call(path, entry="call"):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{entry}\n")


def _logged(path):
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


class ExecutorCancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-cancel-"))

    def test_timeout_kills_the_attempt_before_return(self):
        marker = self.tmp / "late"

        def sleepy(_task, _store):
            time.sleep(30)
            marker.write_text("late", encoding="utf-8")
            return {"late": True}

        started = time.monotonic()
        result = execute(
            {"left"},
            REGISTRY,
            {"left": sleepy},
            {},
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 0.2},
        )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5)
        self.assertFalse(marker.exists())
        self.assertFalse(result["ok"])
        self.assertEqual(result["tasks"][0]["attempts"][0]["outcome"], "timeout")
        self.assertEqual(result["tasks"][0]["error"], "timeout")

    def test_retries_do_not_overlap_and_previous_process_is_dead(self):
        log = self.tmp / "attempts"
        stop = self.tmp / "watch-stop"
        report = self.tmp / "overlaps"
        watcher = subprocess.Popen(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    """
                    import os, sys, time
                    log, stop, report = sys.argv[1:]
                    overlaps = 0
                    while not os.path.exists(stop):
                        if os.path.exists(log):
                            pids = []
                            for line in open(log, encoding="utf-8"):
                                if line.startswith("start "):
                                    pids.append(int(line.split()[1]))
                            living = []
                            for pid in pids:
                                try:
                                    os.kill(pid, 0)
                                except OSError:
                                    continue
                                living.append(pid)
                            if len(set(living)) > 1:
                                overlaps += 1
                        time.sleep(0.01)
                    open(report, "w", encoding="utf-8").write(str(overlaps))
                    """
                ),
                str(log),
                str(stop),
                str(report),
            ]
        )
        counter = self.tmp / "count"

        def flaky(_task, _store):
            count = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
            count += 1
            counter.write_text(str(count), encoding="utf-8")
            with log.open("a", encoding="utf-8") as handle:
                handle.write(f"start {os.getpid()} {count}\n")
            if count == 1:
                time.sleep(30)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(f"end {os.getpid()} {count}\n")
            return {"count": count}

        started = time.monotonic()
        try:
            result = execute(
                {"left"},
                REGISTRY,
                {"left": flaky},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.2},
            )
        finally:
            stop.write_text("stop", encoding="utf-8")
            watcher.wait(timeout=2)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(report.read_text(encoding="utf-8"), "0")
        self.assertTrue(result["ok"])
        attempts = result["tasks"][0]["attempts"]
        self.assertEqual(attempts[0]["outcome"], "timeout")
        self.assertEqual(attempts[1]["outcome"], "success")
        starts = [line for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("start ")]
        first_pid = int(starts[0].split()[1])
        self.assertFalse(_alive(first_pid))
        self.assertTrue(any(line.startswith("end ") for line in log.read_text(encoding="utf-8").splitlines()))

    def test_two_timed_out_attempts_never_overlap_and_leave_no_late_side_effect(self):
        late = self.tmp / "late"
        late.mkdir()
        attempt_pids = []
        overlaps = []
        real_fork = executor_module._fork_attempt

        def tracking_fork(*args):
            overlaps.extend(pid for pid in attempt_pids if _alive(pid))
            pid, ready = real_fork(*args)
            attempt_pids.append(pid)
            return pid, ready

        def sleepy(_task, _store):
            time.sleep(0.5)
            (late / str(os.getpid())).write_text("late", encoding="utf-8")
            return {"late": True}

        started = time.monotonic()
        with mock.patch.object(executor_module, "_fork_attempt", tracking_fork):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": sleepy},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.05},
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(attempt_pids), 2)
        self.assertEqual(overlaps, [])
        for pid in attempt_pids:
            self.assertFalse(_alive(pid), pid)
        task = result["tasks"][0]
        self.assertFalse(result["ok"])
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "timeout")
        self.assertNotIn("value", task)
        self.assertEqual([record["outcome"] for record in task["attempts"]], ["timeout", "timeout"])
        self.assertEqual([record["attempt"] for record in task["attempts"]], [1, 2])
        time.sleep(0.8)
        self.assertEqual(list(late.iterdir()), [])

    def test_noncooperative_runner_and_descendant_cannot_survive_or_publish(self):
        leader_marker = self.tmp / "leader-late"
        child_marker = self.tmp / "child-late"
        pid_file = self.tmp / "stubborn-pids"
        cache_dir = self.tmp / "cache"
        child_script = textwrap.dedent(
            """
            import signal, sys, time
            for name in ("SIGTERM", "SIGINT", "SIGHUP"):
                signal.signal(getattr(signal, name), signal.SIG_IGN)
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                try:
                    time.sleep(0.05)
                except BaseException:
                    pass
            open(sys.argv[1], "w", encoding="utf-8").write("late")
            """
        )

        def stubborn(_task, store):
            for name in ("SIGTERM", "SIGINT", "SIGHUP"):
                signal.signal(getattr(signal, name), signal.SIG_IGN)
            child = subprocess.Popen([sys.executable, "-c", child_script, str(child_marker)])
            pid_file.write_text(f"{os.getpid()} {child.pid}", encoding="utf-8")
            store["findings"]["leaked"] = True
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                try:
                    time.sleep(0.05)
                except BaseException:
                    pass
            leader_marker.write_text("late", encoding="utf-8")
            return {"published": True}

        evidence = {"findings": {}}
        started = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": stubborn},
                evidence,
                {
                    "concurrency": 1,
                    "max_retries": 1,
                    "task_timeout_seconds": 0.5,
                    "cache_dir": str(cache_dir),
                    "fingerprint": lambda _task: "stubborn",
                },
            )
        self.assertLess(time.monotonic() - started, 5)
        task = result["tasks"][0]
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "timeout")
        self.assertNotIn("value", task)
        self.assertEqual(evidence, {"findings": {}})
        self.assertFalse((cache_dir / "stubborn.json").exists())
        leader, child = (int(value) for value in pid_file.read_text(encoding="utf-8").split())
        self.assertFalse(_alive(leader))
        self._wait_until_dead(child)
        time.sleep(1.2)
        self.assertFalse(leader_marker.exists())
        self.assertFalse(child_marker.exists())

    def test_run_deadline_stops_inflight_attempt_and_blocks_pending_and_dependents(self):
        registry = {
            "a_slow": {"id": "a_slow", "depends_on": []},
            "b_pending": {"id": "b_pending", "depends_on": []},
            "c_dependent": {"id": "c_dependent", "depends_on": ["a_slow"]},
        }
        pid_file = self.tmp / "slow-pid"
        ran = self.tmp / "ran"
        ran.mkdir()

        def slow(_task, _store):
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(30)
            (ran / "a_slow").write_text("late", encoding="utf-8")
            return {"ok": True}

        def record(task_id, _store):
            (ran / task_id).write_text("ran", encoding="utf-8")
            return {"ok": True}

        started = time.monotonic()
        result = execute(
            set(registry),
            registry,
            {"a_slow": slow, "b_pending": record, "c_dependent": record},
            {},
            {
                "concurrency": 1,
                "max_retries": 3,
                "retry_backoff_seconds": 0,
                "task_timeout_seconds": 30,
                "deadline": time.monotonic() + 0.3,
            },
        )
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        tasks = {task["task_id"]: task for task in result["tasks"]}
        slow_task = tasks["a_slow"]
        self.assertEqual(slow_task["error"], "budget exhausted")
        self.assertEqual(len(slow_task["attempts"]), 1)
        self.assertEqual(slow_task["attempts"][0]["reason"], "run budget exhausted")
        self.assertFalse(slow_task["attempts"][0]["transient"])
        self.assertEqual(tasks["b_pending"]["error"], "budget exhausted")
        self.assertEqual(tasks["b_pending"]["attempts"][0]["diagnostic"], "cancelled before start")
        self.assertEqual(tasks["c_dependent"]["error"], "dependency failed")
        self.assertFalse(_alive(int(pid_file.read_text(encoding="utf-8"))))
        self.assertEqual(list(ran.iterdir()), [])

    def _exited_job_with_payload(self, evidence, cache_dir, deadline_offset):
        def runner(_task, _store):
            return {"late": True}

        job = executor_module._Job("left", runner, evidence, "late-key")
        job.cache_dir = str(cache_dir)
        descriptor, path = tempfile.mkstemp(prefix="payload-", dir=self.tmp)
        os.close(descriptor)
        executor_module._write_payload(
            path,
            {"status": "ok", "value": {"late": True}, "error": None, "evidence": {"late": True}, "cells": []},
        )
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        os.waitpid(pid, 0)
        job.pid = pid
        job.ready_read = None
        job.group_ready = False
        job.result_path = path
        job.started = time.monotonic() - 1
        job.deadline = time.monotonic() + deadline_offset
        return job

    def test_stop_condition_outranks_a_payload_from_an_exited_leader(self):
        cases = (
            ("timeout", -0.5, False, False, "timeout"),
            ("cancel", 30, True, False, "cancelled"),
            ("budget", 30, True, True, "budget exhausted"),
        )
        for name, offset, cancel_set, budget_spent, error in cases:
            with self.subTest(name=name):
                evidence = {}
                cache_dir = self.tmp / f"cache-{name}"
                job = self._exited_job_with_payload(evidence, cache_dir, offset)
                cancel = threading.Event()
                if cancel_set:
                    cancel.set()
                result, running = executor_module._poll_job(job, time.monotonic(), cancel, 1, 0, budget_spent)
                self.assertFalse(running)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], error)
                self.assertNotIn("value", result)
                self.assertEqual(evidence, {})
                self.assertFalse((cache_dir / "late-key.json").exists())
                self.assertFalse(Path(job.result_path).exists())

        evidence = {}
        cache_dir = self.tmp / "cache-control"
        job = self._exited_job_with_payload(evidence, cache_dir, 30)
        result, _running = executor_module._poll_job(job, time.monotonic(), threading.Event(), 1, 0)
        self.assertTrue(result["ok"])
        self.assertEqual(evidence, {"late": True})
        self.assertTrue((cache_dir / "late-key.json").exists())

    def test_new_session_descendants_die_when_the_attempt_times_out(self):
        child_sentinel = self.tmp / "session-child-late"
        grandchild_sentinel = self.tmp / "session-grandchild-late"
        child_pid_file = self.tmp / "session-child-pid"
        grandchild_pid_file = self.tmp / "session-grandchild-pid"
        grandchild_script = "import sys, time\ntime.sleep(2.0)\nopen(sys.argv[1], 'w').write('late')\n"
        child_script = textwrap.dedent(
            """
            import subprocess, sys, time
            grandchild = subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2]], start_new_session=True)
            open(sys.argv[3], "w").write(str(grandchild.pid))
            time.sleep(2.0)
            open(sys.argv[4], "w").write("late")
            """
        )

        def runner(_task, _store):
            process = subprocess.Popen(
                [sys.executable, "-c", child_script, grandchild_script, str(grandchild_sentinel), str(grandchild_pid_file), str(child_sentinel)],
                start_new_session=True,
            )
            child_pid_file.write_text(str(process.pid), encoding="utf-8")
            end = time.monotonic() + 5
            while not grandchild_pid_file.exists() and time.monotonic() < end:
                time.sleep(0.01)
            time.sleep(30)
            return {"ok": True}

        started = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 1.0},
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["tasks"][0]["error"], "timeout")
        self._wait_until_dead(int(child_pid_file.read_text(encoding="utf-8")))
        self._wait_until_dead(int(grandchild_pid_file.read_text(encoding="utf-8")))
        time.sleep(max(0.0, started + 2.6 - time.monotonic()))
        self.assertFalse(child_sentinel.exists())
        self.assertFalse(grandchild_sentinel.exists())

    def test_new_session_descendant_dies_when_the_attempt_leader_exits(self):
        sentinel = self.tmp / "session-leader-exit-late"
        pid_file = self.tmp / "session-leader-exit-pid"
        script = "import sys, time\ntime.sleep(1.0)\nopen(sys.argv[1], 'w').write('late')\n"

        def runner(_task, _store):
            process = subprocess.Popen([sys.executable, "-c", script, str(sentinel)], start_new_session=True)
            pid_file.write_text(str(process.pid), encoding="utf-8")
            return {"ok": True}

        started = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 5},
            )
        self.assertTrue(result["ok"], result)
        self._wait_until_dead(int(pid_file.read_text(encoding="utf-8")))
        time.sleep(max(0.0, started + 1.5 - time.monotonic()))
        self.assertFalse(sentinel.exists())

    def test_new_session_descendant_dies_when_the_runner_raises_system_exit(self):
        sentinel = self.tmp / "system-exit-late"
        pid_log = self.tmp / "system-exit-pids"
        script = "import sys, time\ntime.sleep(1.0)\nopen(sys.argv[1], 'w').write('late')\n"
        overlaps = []
        real_fork = executor_module._fork_attempt

        def sleeper_pids():
            if not pid_log.exists():
                return []
            return [int(line) for line in pid_log.read_text(encoding="utf-8").split()]

        def tracking_fork(*args):
            overlaps.extend(pid for pid in sleeper_pids() if _running(pid))
            return real_fork(*args)

        def runner(_task, _store):
            process = subprocess.Popen([sys.executable, "-c", script, str(sentinel)], start_new_session=True)
            with pid_log.open("a", encoding="utf-8") as handle:
                handle.write(f"{process.pid}\n")
            raise SystemExit(3)

        started = time.monotonic()
        with warnings.catch_warnings(), mock.patch.object(executor_module, "_fork_attempt", tracking_fork):
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 10},
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(result["ok"])
        pids = sleeper_pids()
        self.assertEqual(len(pids), 2)
        self.assertEqual(overlaps, [])
        for pid in pids:
            self._wait_until_dead(pid)
        time.sleep(max(0.0, started + 1.5 - time.monotonic()))
        self.assertFalse(sentinel.exists())

    def test_unreaped_leader_is_terminal_and_publishes_nothing(self):
        attempt_pids = []
        real_fork = executor_module._fork_attempt

        def tracking_fork(*args):
            pid, ready = real_fork(*args)
            attempt_pids.append(pid)
            return pid, ready

        def reap_later():
            for pid in attempt_pids:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

        self.addCleanup(reap_later)

        def sleepy(_task, store):
            store["findings"]["leaked"] = True
            time.sleep(30)
            return {"late": True}

        evidence = {"findings": {}}
        cache_dir = self.tmp / "unreaped-cache"
        with mock.patch.object(executor_module, "_fork_attempt", tracking_fork), mock.patch.object(executor_module, "_reap", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": sleepy},
                evidence,
                {
                    "concurrency": 1,
                    "max_retries": 3,
                    "retry_backoff_seconds": 0,
                    "task_timeout_seconds": 0.2,
                    "cache_dir": str(cache_dir),
                    "fingerprint": lambda _task: "unreaped",
                },
            )
        task = result["tasks"][0]
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "termination could not be guaranteed")
        self.assertEqual(len(task["attempts"]), 1)
        self.assertFalse(task["attempts"][0]["transient"])
        self.assertEqual(len(attempt_pids), 1)
        self.assertNotIn("value", task)
        self.assertEqual(evidence, {"findings": {}})
        self.assertFalse((cache_dir / "unreaped.json").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "PR_SET_CHILD_SUBREAPER is Linux-only")
    def test_double_forked_new_session_descendant_dies_before_the_retry(self):
        sentinel = self.tmp / "double-fork-late"
        pid_file = self.tmp / "double-fork-pid"
        counter = self.tmp / "double-fork-count"
        overlaps = []
        real_fork = executor_module._fork_attempt

        def grandchild_pid():
            return int(pid_file.read_text(encoding="utf-8")) if pid_file.exists() else None

        def tracking_fork(*args):
            pid = grandchild_pid()
            if pid is not None and _running(pid):
                overlaps.append(pid)
            return real_fork(*args)

        def runner(_task, _store):
            count = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
            count += 1
            counter.write_text(str(count), encoding="utf-8")
            if count > 1:
                return {"count": count}
            intermediate = os.fork()
            if intermediate == 0:
                try:
                    if os.fork() == 0:
                        os.setsid()
                        temporary = self.tmp / "double-fork-pid.tmp"
                        temporary.write_text(str(os.getpid()), encoding="utf-8")
                        os.replace(temporary, pid_file)
                        time.sleep(2.0)
                        sentinel.write_text("late", encoding="utf-8")
                finally:
                    os._exit(0)
            os.waitpid(intermediate, 0)
            end = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < end:
                time.sleep(0.01)
            time.sleep(30)
            return {"count": count}

        started = time.monotonic()
        with mock.patch.object(executor_module, "_fork_attempt", tracking_fork):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 1.0},
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual([record["outcome"] for record in result["tasks"][0]["attempts"]], ["timeout", "success"])
        pid = grandchild_pid()
        self.assertIsNotNone(pid)
        self.assertEqual(overlaps, [])
        self._wait_until_dead(pid)
        time.sleep(max(0.0, started + 2.6 - time.monotonic()))
        self.assertFalse(sentinel.exists())

    def test_unreadable_process_table_is_terminal_and_not_retried(self):
        for mode in ("timeout", "exit"):
            with self.subTest(mode=mode):
                attempt_pids = []
                real_fork = executor_module._fork_attempt

                def tracking_fork(*args):
                    pid, ready = real_fork(*args)
                    attempt_pids.append(pid)
                    return pid, ready

                def runner(_task, store, mode=mode):
                    store["findings"]["leaked"] = True
                    if mode == "timeout":
                        time.sleep(30)
                    return {"late": True}

                evidence = {"findings": {}}
                cache_dir = self.tmp / f"unreadable-{mode}"
                with mock.patch.object(executor_module, "_fork_attempt", tracking_fork), mock.patch.object(
                    executor_module, "_process_table", return_value=None
                ):
                    result = execute(
                        {"left"},
                        REGISTRY,
                        {"left": runner},
                        evidence,
                        {
                            "concurrency": 1,
                            "max_retries": 3,
                            "retry_backoff_seconds": 0,
                            "task_timeout_seconds": 0.3 if mode == "timeout" else 10,
                            "cache_dir": str(cache_dir),
                            "fingerprint": lambda _task: "unreadable",
                        },
                    )
                task = result["tasks"][0]
                self.assertFalse(task["ok"])
                self.assertEqual(task["error"], "termination could not be guaranteed")
                self.assertEqual(len(task["attempts"]), 1)
                self.assertEqual(task["attempts"][0]["reason"], "termination could not be guaranteed")
                self.assertEqual(task["attempts"][0]["diagnostic"], "attempt descendants could not be enumerated")
                self.assertFalse(task["attempts"][0]["transient"])
                self.assertEqual(len(attempt_pids), 1)
                self.assertFalse(_alive(attempt_pids[0]))
                self.assertNotIn("value", task)
                self.assertEqual(evidence, {"findings": {}})
                self.assertFalse((cache_dir / "unreadable.json").exists())

    def test_subreaper_failure_does_not_run_the_runner_or_retry(self):
        marker = self.tmp / "subreaper-ran"

        def runner(_task, _store):
            marker.write_text("ran", encoding="utf-8")
            return {"ok": True}

        with mock.patch.object(executor_module, "_enable_subreaper", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 3, "retry_backoff_seconds": 0, "task_timeout_seconds": 10},
            )
        task = result["tasks"][0]
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "termination could not be guaranteed")
        self.assertEqual(len(task["attempts"]), 1)
        self.assertEqual(task["attempts"][0]["diagnostic"], "child subreaper could not be enabled")
        self.assertFalse(task["attempts"][0]["transient"])
        self.assertFalse(marker.exists())

    def _scripted_sweep(self, root, tables):
        def table():
            return tables.pop(0) if len(tables) > 1 else tables[0]

        sent = []
        with mock.patch.object(executor_module, "_process_table", side_effect=table), mock.patch.object(
            executor_module, "_send", side_effect=lambda pid, sig, group=False: sent.append((pid, sig, group))
        ):
            killed = executor_module._kill_descendants(root)
        return killed, sent

    def test_sweep_waits_for_stopped_state_before_declaring_the_tree_empty(self):
        me = os.getpid()
        root, child, grandchild = 999_001, 999_002, 999_003
        base = {me: (1, me, "R"), root: (me, root, "T")}
        killed, sent = self._scripted_sweep(
            root,
            [
                {**base, child: (root, child, "S")},
                {**base, child: (root, child, "S")},
                {**base, child: (root, child, "T"), grandchild: (child, grandchild, "R")},
                {**base, child: (root, child, "T"), grandchild: (child, grandchild, "T")},
                {**base, child: (root, child, "Z"), grandchild: (child, grandchild, "Z")},
            ],
        )
        self.assertEqual(killed, {child, grandchild})
        first_kill = next(index for index, item in enumerate(sent) if item[1] == signal.SIGKILL)
        self.assertGreater(first_kill, sent.index((grandchild, signal.SIGSTOP, False)))
        self.assertIn((child, signal.SIGKILL, False), sent)
        self.assertIn((grandchild, signal.SIGKILL, False), sent)

    def test_sweep_that_never_settles_kills_what_it_found_and_reports_none(self):
        me = os.getpid()
        root, child = 999_011, 999_012
        cases = {
            "descendant keeps running": {me: (1, me, "R"), root: (me, root, "T"), child: (root, child, "S")},
            "root keeps running": {me: (1, me, "R"), root: (me, root, "R")},
            "killed pid never exits": {me: (1, me, "R"), root: (me, root, "T"), child: (root, child, "T")},
        }
        for name, table in cases.items():
            with self.subTest(name=name), mock.patch.object(executor_module, "_SWEEP_SECONDS", 0.1):
                killed, sent = self._scripted_sweep(root, [table])
                self.assertIsNone(killed)
                if child in table:
                    self.assertIn((child, signal.SIGKILL, False), sent)

    def test_runner_still_forking_new_sessions_at_timeout_leaves_no_survivor(self):
        late = self.tmp / "fork-loop-late"
        late.mkdir()
        pid_log = self.tmp / "fork-loop-pids"
        counter = self.tmp / "fork-loop-count"
        leaders = []
        overlaps = []
        real_fork = executor_module._fork_attempt

        def grandchildren():
            return [int(line) for line in _logged(pid_log)]

        def tracking_fork(*args):
            overlaps.extend(pid for pid in grandchildren() if _running(pid))
            pid, ready = real_fork(*args)
            leaders.append(pid)
            return pid, ready

        def runner(_task, _store):
            count = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
            count += 1
            counter.write_text(str(count), encoding="utf-8")
            if count > 1:
                return {"count": count}
            for _ in range(40):
                if os.fork() == 0:
                    try:
                        os.setsid()
                        _log_call(pid_log, str(os.getpid()))
                        time.sleep(1.5)
                        (late / str(os.getpid())).write_text("late", encoding="utf-8")
                    finally:
                        os._exit(0)
                time.sleep(0.02)
            time.sleep(30)
            return {"count": count}

        started = time.monotonic()
        try:
            with mock.patch.object(executor_module, "_fork_attempt", tracking_fork):
                result = execute(
                    {"left"},
                    REGISTRY,
                    {"left": runner},
                    {},
                    {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.3},
                )
            task = result["tasks"][0]
            outcomes = [record["outcome"] for record in task["attempts"]]
            if task["ok"]:
                self.assertEqual(outcomes, ["timeout", "success"])
                self.assertEqual(overlaps, [])
            else:
                self.assertEqual(task["error"], "termination could not be guaranteed")
                self.assertEqual(len(task["attempts"]), 1)
                self.assertFalse(task["attempts"][0]["transient"])
            self.assertTrue(grandchildren())
            time.sleep(max(0.0, started + 2.3 - time.monotonic()))
            for pid in grandchildren():
                self.assertFalse(_running(pid), pid)
            self.assertEqual(list(late.iterdir()), [])
        finally:
            for pid in grandchildren() + leaders:
                if _alive(pid):
                    os.kill(pid, signal.SIGKILL)
            for pid in leaders:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    def test_queued_jobs_after_an_expired_deadline_report_budget_not_cancel(self):
        ran = []

        def runner(task_id, _store):
            ran.append(task_id)
            return {"ok": True}

        for name, deadline, error, reason in (
            ("expired", time.monotonic() - 1, "budget exhausted", "run budget exhausted"),
            ("caller", time.monotonic() + 60, "cancelled", "cancelled"),
        ):
            with self.subTest(name=name):
                cancel = threading.Event()
                cancel.set()
                job = executor_module._Job("left", runner, {}, "key")
                results, failed = executor_module._run_processes([job], 1, 30, 2, 0, cancel, deadline, None, None)
                self.assertEqual(failed, {"left"})
                self.assertEqual(results["left"]["error"], error)
                self.assertEqual(results["left"]["attempts"][0]["reason"], reason)
                self.assertFalse(results["left"]["attempts"][0]["transient"])
        self.assertEqual(ran, [])

    def test_cancel_event_stops_a_running_attempt_and_a_pending_one(self):
        marker = self.tmp / "ran"
        cancel = threading.Event()

        def sleepy(_task, _store):
            time.sleep(30)
            marker.write_text("ran", encoding="utf-8")
            return {"ran": True}

        def alarm(_signum, _frame):
            cancel.set()

        previous = signal.signal(signal.SIGALRM, alarm)
        signal.setitimer(signal.ITIMER_REAL, 0.2)
        started = time.monotonic()
        try:
            result = execute(
                {"left"},
                REGISTRY,
                {"left": sleepy},
                {},
                {"concurrency": 1, "max_retries": 2, "task_timeout_seconds": 10, "cancel_event": cancel},
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(marker.exists())
        self.assertFalse(result["ok"])
        self.assertTrue(result["cancelled"])
        self.assertEqual(result["tasks"][0]["attempts"][0]["outcome"], "timeout")

        pending = self.tmp / "pending"

        def pending_runner(_task, _store):
            pending.write_text("ran", encoding="utf-8")
            return {"ran": True}

        preset = threading.Event()
        preset.set()
        skipped = execute(
            {"left"},
            REGISTRY,
            {"left": pending_runner},
            {},
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2, "cancel_event": preset},
        )
        self.assertFalse(pending.exists())
        self.assertFalse(skipped["ok"])
        self.assertTrue(skipped["cancelled"])
        self.assertEqual(skipped["tasks"][0]["attempts"][0]["diagnostic"], "cancelled before start")

    def test_deterministic_failure_is_not_retried(self):
        calls = self.tmp / "deterministic-calls"
        calls.write_text("0", encoding="utf-8")

        def broken(_task, _store):
            calls.write_text(str(int(calls.read_text(encoding="utf-8")) + 1), encoding="utf-8")
            raise ValueError("deterministic")

        result = execute(
            {"right"},
            REGISTRY,
            {"left": lambda *_args: {"ok": True}, "right": broken},
            {},
            {"concurrency": 1, "max_retries": 3, "task_timeout_seconds": 2},
        )
        self.assertFalse(result["ok"])
        failed = next(task for task in result["tasks"] if task["task_id"] == "right")
        self.assertEqual(len(failed["attempts"]), 1)
        self.assertFalse(failed["attempts"][0]["transient"])
        self.assertEqual(calls.read_text(encoding="utf-8"), "1")
        dependent = next(task for task in result["tasks"] if task["task_id"] == "left")
        self.assertTrue(dependent["ok"])

    def test_parallel_tasks_do_not_restore_stale_context(self):
        class Context:
            def __init__(self):
                self.graph = None
                self.analyses = None
                self.requirements = None
                self.duplicate_groups = None

        registry = {
            "left": {"id": "left", "depends_on": []},
            "right": {"id": "right", "depends_on": []},
        }
        def make_runner(writer_delay, reader_delay, context):
            def runner(task_id, _store):
                if task_id == "left":
                    time.sleep(writer_delay)
                    context.graph = {"from": "writer"}
                    context.analyses = ["kept"]
                    return {"role": "writer"}
                time.sleep(reader_delay)
                return {"role": "reader"}

            return runner

        for writer_delay, reader_delay in ((0.0, 0.25), (0.25, 0.0)):
            context = Context()
            runner = make_runner(writer_delay, reader_delay, context)
            result = execute(
                {"left", "right"},
                registry,
                {"left": runner, "right": runner},
                {},
                {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(context.graph, {"from": "writer"})
            self.assertEqual(context.analyses, ["kept"])

    def test_parallel_writers_keep_distinct_list_elements(self):
        class Context:
            def __init__(self):
                self.analyses = [{"a": 0}, {"b": 0}]

        registry = {
            "left": {"id": "left", "depends_on": []},
            "right": {"id": "right", "depends_on": []},
        }

        def make_runner(left_delay, right_delay, context):
            def runner(task_id, _store):
                if task_id == "left":
                    time.sleep(left_delay)
                    context.analyses[0]["a"] = 1
                else:
                    time.sleep(right_delay)
                    context.analyses[1]["b"] = 1
                return {"task": task_id}

            return runner

        for left_delay, right_delay in ((0.0, 0.25), (0.25, 0.0)):
            context = Context()
            runner = make_runner(left_delay, right_delay, context)
            result = execute(
                {"left", "right"},
                registry,
                {"left": runner, "right": runner},
                {},
                {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(context.analyses, [{"a": 1}, {"b": 1}])

    def _wait_until_dead(self, pid):
        def stop():
            if _alive(pid):
                os.kill(pid, signal.SIGKILL)

        self.addCleanup(stop)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.05)
        self.assertFalse(_alive(pid))

    def test_background_child_dies_when_the_attempt_leader_exits(self):
        pid_file = self.tmp / "leader-child"

        def runner(_task, _store):
            process = subprocess.Popen(["sleep", "30"])
            pid_file.write_text(str(process.pid), encoding="utf-8")
            return {"ok": True}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2},
            )
        self.assertTrue(result["ok"], result)
        self.assertTrue(pid_file.exists())
        self._wait_until_dead(int(pid_file.read_text(encoding="utf-8").strip()))

    def test_background_child_dies_when_the_attempt_times_out(self):
        pid_file = self.tmp / "timeout-child"

        def runner(_task, _store):
            process = subprocess.Popen(["sleep", "30"])
            pid_file.write_text(str(process.pid), encoding="utf-8")
            time.sleep(30)
            return {"ok": True}

        started = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 0.6},
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["tasks"][0]["attempts"][0]["outcome"], "timeout")
        self.assertTrue(pid_file.exists())
        self._wait_until_dead(int(pid_file.read_text(encoding="utf-8").strip()))

    def test_blocking_io_without_fork_reports_unterminated_work(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        marker = self.tmp / "after-release"
        cache_dir = self.tmp / "cache"
        calls = self.tmp / "calls"

        def blocked(_task, _store):
            _log_call(calls)
            os.read(read_fd, 1)
            marker.write_text("late", encoding="utf-8")
            return {"done": True}

        started = time.monotonic()
        result = _run_thread_task("left", blocked, {}, "key", 0.2, 2, 0, threading.Event(), None, str(cache_dir))
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "termination could not be guaranteed")
        self.assertNotIn("value", result)
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["reason"], "termination could not be guaranteed")
        self.assertFalse(result["attempts"][0]["transient"])
        os.write(write_fd, b"x")
        time.sleep(0.5)
        self.assertEqual(_logged(calls), ["call"])
        self.assertFalse(marker.exists())
        self.assertFalse((cache_dir / "key.json").exists())

    def test_fallback_without_async_exception_api_fails_closed(self):
        release = threading.Event()
        self.addCleanup(release.set)
        calls = self.tmp / "calls"

        def waits(_task, _store):
            _log_call(calls)
            release.wait(10)
            return {"done": True}

        started = time.monotonic()
        with mock.patch("ctypes.pythonapi", new=object()):
            result = _run_thread_task("left", waits, {}, "key", 0.1, 3, 0, threading.Event(), None, None)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "termination could not be guaranteed")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertFalse(result["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), ["call"])

    def _spinning_runner(self, marker, calls):
        def spin(_task, _store):
            _log_call(calls)
            end = time.monotonic() + 30
            while time.monotonic() < end:
                time.sleep(0.01)
            marker.write_text("late", encoding="utf-8")
            return {"late": True}

        return spin

    def test_fallback_attempt_stops_at_the_run_deadline(self):
        marker = self.tmp / "fallback-deadline"
        calls = self.tmp / "calls"
        started = time.monotonic()
        result = _run_thread_task(
            "left",
            self._spinning_runner(marker, calls),
            {},
            None,
            30,
            3,
            0,
            threading.Event(),
            time.monotonic() + 0.2,
            None,
        )
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "budget exhausted")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["reason"], "run budget exhausted")
        self.assertFalse(result["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), ["call"])
        self.assertFalse(marker.exists())

    def test_fallback_attempt_stops_on_external_cancel(self):
        marker = self.tmp / "fallback-cancel"
        calls = self.tmp / "calls"
        cancel = threading.Event()
        timer = threading.Timer(0.2, cancel.set)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        result = _run_thread_task("left", self._spinning_runner(marker, calls), {}, None, 30, 3, 0, cancel, None, None)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "cancelled")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["reason"], "cancelled")
        self.assertFalse(result["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), ["call"])
        self.assertFalse(marker.exists())

    def test_fallback_run_deadline_blocks_pending_and_dependent_tasks(self):
        registry = {
            "left": {"id": "left", "depends_on": []},
            "other": {"id": "other", "depends_on": []},
            "right": {"id": "right", "depends_on": ["left"]},
        }
        marker = self.tmp / "fallback-late"
        ran = []
        calls = self.tmp / "calls"

        def record(task_id, _store):
            ran.append(task_id)
            return {"ok": True}

        started = time.monotonic()
        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                set(registry),
                registry,
                {"left": self._spinning_runner(marker, calls), "other": record, "right": record},
                {},
                {"concurrency": 1, "max_retries": 3, "task_timeout_seconds": 30, "deadline": time.monotonic() + 0.2},
            )
        self.assertLess(time.monotonic() - started, 3)
        tasks = {task["task_id"]: task for task in result["tasks"]}
        self.assertEqual(tasks["left"]["error"], "budget exhausted")
        self.assertEqual(len(tasks["left"]["attempts"]), 1)
        self.assertEqual(tasks["other"]["error"], "budget exhausted")
        self.assertEqual(tasks["right"]["error"], "dependency failed")
        self.assertEqual(ran, [])
        self.assertEqual(_logged(calls), ["call"])
        self.assertFalse(marker.exists())

    def test_fallback_unterminated_thread_cannot_mutate_caller_evidence(self):
        finished = threading.Event()
        calls = self.tmp / "calls"

        def swallowing(_task, store):
            _log_call(calls)
            store["leaked"] = 1
            end = time.monotonic() + 1.0
            while True:
                try:
                    while time.monotonic() < end:
                        time.sleep(0.02)
                    break
                except BaseException:
                    continue
            store["leaked"] = 2
            finished.set()
            return {"late": True}

        evidence = {"findings": {}}
        cache_dir = self.tmp / "fallback-cache"
        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": swallowing},
                evidence,
                {
                    "concurrency": 1,
                    "max_retries": 3,
                    "retry_backoff_seconds": 0,
                    "task_timeout_seconds": 0.1,
                    "cache_dir": str(cache_dir),
                    "fingerprint": lambda _task: "swallowing",
                },
            )
        task = result["tasks"][0]
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "termination could not be guaranteed")
        self.assertEqual(len(task["attempts"]), 1)
        self.assertEqual(_logged(calls), ["call"])
        self.assertEqual(evidence, {"findings": {}})
        self.assertTrue(finished.wait(5))
        self.assertEqual(evidence, {"findings": {}})
        self.assertFalse((cache_dir / "swallowing.json").exists())

    def test_fallback_stopped_attempt_restores_closures_and_keeps_evidence(self):
        closed = {"kept": 1}

        class Context:
            def __init__(self):
                self.analyses = ["before"]

        context = Context()

        def partial(_task, store):
            closed["leaked"] = True
            context.analyses.append("partial")
            store["findings"]["leaked"] = True
            while True:
                time.sleep(0.01)

        evidence = {"findings": {}}
        result = _run_thread_task("left", partial, evidence, None, 0.1, 1, 0, threading.Event(), None, None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")
        self.assertEqual(closed, {"kept": 1})
        self.assertEqual(context.analyses, ["before"])
        self.assertEqual(evidence, {"findings": {}})

    def test_fallback_restores_added_deleted_and_rebound_closure_state(self):
        for mode in ("error", "stopped"):
            with self.subTest(mode=mode):
                self._fallback_closure_restore(mode)

    def _fallback_closure_restore(self, mode):
        class Context:
            def __init__(self):
                self.existing = "orig"

        context = Context()
        closed = {"kept": 1}
        counter = 0
        observed = self.tmp / f"observed-{mode}"

        def runner(_task, _store):
            nonlocal counter
            _log_call(observed, repr((hasattr(context, "added"), getattr(context, "existing", None), counter, dict(closed))))
            context.added = True
            del context.existing
            counter = 99
            closed["added"] = 1
            del closed["kept"]
            if len(_logged(observed)) == 1:
                if mode == "stopped":
                    while True:
                        time.sleep(0.01)
                raise TransientFailure("retry me")
            raise ValueError("deterministic")

        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.3},
            )
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["tasks"][0]["attempts"]), 2)
        original = repr((False, "orig", 0, {"kept": 1}))
        self.assertEqual(_logged(observed), [original, original])
        self.assertFalse(hasattr(context, "added"))
        self.assertEqual(context.existing, "orig")
        self.assertEqual(counter, 0)
        self.assertEqual(closed, {"kept": 1})

    def test_fallback_retry_sees_original_closure_list_set_and_bytearray(self):
        items = ["orig"]
        tags = {"orig"}
        raw = bytearray(b"orig")
        log = self.tmp / "sequence-observed"

        def runner(_task, _store):
            attempt = len(_logged(log)) + 1
            _log_call(log, repr((list(items), sorted(tags), bytes(raw))))
            items.append(f"attempt-{attempt}")
            tags.add(f"attempt-{attempt}")
            raw.extend(b"-%d" % attempt)
            if attempt == 1:
                while True:
                    time.sleep(0.01)
            return {"attempt": attempt}

        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.3},
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual([record["outcome"] for record in result["tasks"][0]["attempts"]], ["timeout", "success"])
        original = repr((["orig"], ["orig"], b"orig"))
        self.assertEqual(_logged(log), [original, original])
        self.assertEqual(items, ["orig", "attempt-2"])
        self.assertEqual(tags, {"orig", "attempt-2"})
        self.assertEqual(raw, bytearray(b"orig-2"))

    def test_fallback_uncopyable_closure_list_is_terminal_without_running(self):
        class Uncopyable:
            def __deepcopy__(self, _memo):
                raise TypeError("cannot copy")

        items = [Uncopyable()]
        calls = self.tmp / "calls"

        def runner(_task, _store):
            _log_call(calls)
            items.append("partial")
            return {"ok": True}

        result = _run_thread_task("left", runner, {}, None, 5, 3, 0, threading.Event(), None, None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "evidence could not be isolated")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertFalse(result["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), [])
        self.assertEqual(len(items), 1)

    def test_fallback_event_in_closure_dict_is_terminal_without_running(self):
        state = {"flag": threading.Event()}
        calls = self.tmp / "calls"

        def runner(_task, _store):
            _log_call(calls)
            state["flag"].set()
            time.sleep(30)
            return {"ok": True}

        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": runner},
                {},
                {"concurrency": 1, "max_retries": 3, "retry_backoff_seconds": 0, "task_timeout_seconds": 0.3},
            )
        task = result["tasks"][0]
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "evidence could not be isolated")
        self.assertEqual(len(task["attempts"]), 1)
        self.assertFalse(task["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), [])
        self.assertFalse(state["flag"].is_set())

    def test_fallback_capture_of_an_audit_context_omits_only_its_lock(self):
        from cqa.security import ExecutionLog

        ctx = audit_module.AuditContext(self.tmp, [self.tmp / "app.py"], {"budgets": {"concurrency": 1}}, ExecutionLog())
        ctx.analyses = [{"path": "app.py", "functions": [{"name": "main"}]}]
        ctx.texts["app.py"] = "x = 1\n"
        lock = ctx.lock

        def runner(_task, _store):
            return ctx.config

        saved = executor_module._capture_closures(runner)
        entries = saved[0][3]
        self.assertNotIn("lock", entries)
        self.assertIsNot(entries["config"], ctx.config)
        self.assertIsNot(entries["analyses"][0], ctx.analyses[0])
        ctx.files.append(self.tmp / "partial.py")
        ctx.config["budgets"]["concurrency"] = 9
        ctx.analyses[0]["functions"].append({"name": "partial"})
        ctx.log.record("partial", "ran")
        ctx.limitations.append("partial")
        ctx.partial = True
        executor_module._restore_closures(saved)
        self.assertEqual(ctx.files, [self.tmp / "app.py"])
        self.assertEqual(ctx.config, {"budgets": {"concurrency": 1}})
        self.assertEqual(ctx.analyses, [{"path": "app.py", "functions": [{"name": "main"}]}])
        self.assertEqual(ctx.log.commands, [])
        self.assertEqual(ctx.limitations, [])
        self.assertFalse(hasattr(ctx, "partial"))
        self.assertIs(ctx.lock, lock)

    def test_fallback_success_merges_isolated_evidence(self):
        evidence = {"findings": {"stale": 1, "kept": 2}}

        def edit(_task, store):
            del store["findings"]["stale"]
            store["findings"]["fresh"] = 3
            return {"ok": True}

        result = _run_thread_task("left", edit, evidence, None, 5, 1, 0, threading.Event(), None, None)
        self.assertTrue(result["ok"], result)
        self.assertEqual(evidence, {"findings": {"kept": 2, "fresh": 3}})

    def test_fallback_completion_after_the_timeout_is_not_success(self):
        class FinishedThread:
            def __init__(self, target=None, daemon=None):
                self._target = target
                self.ident = None

            def start(self):
                self._target()

            def is_alive(self):
                return False

            def join(self, _timeout=None):
                return None

        immediate = type(threading)("immediate_threading")
        immediate.Thread = FinishedThread
        immediate.Event = threading.Event
        closed = {"kept": 1}
        cache_dir = self.tmp / "late-cache"

        def late(_task, store):
            closed["late"] = True
            store["late"] = True
            return {"late": True}

        evidence = {"findings": {}}
        with mock.patch.object(executor_module, "threading", immediate):
            result = _run_thread_task("left", late, evidence, "late", 0, 1, 0, threading.Event(), None, str(cache_dir))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")
        self.assertNotIn("value", result)
        self.assertEqual(evidence, {"findings": {}})
        self.assertEqual(closed, {"kept": 1})
        self.assertFalse((cache_dir / "late.json").exists())

    def test_fallback_system_exit_is_a_terminal_error(self):
        closed = {"kept": 1}
        calls = self.tmp / "calls"
        cache_dir = self.tmp / "system-exit-cache"

        def exits(_task, store):
            _log_call(calls)
            store["findings"]["leaked"] = True
            closed["leaked"] = True
            raise SystemExit(3)

        evidence = {"findings": {}}
        with mock.patch.object(executor_module, "_isolated_processes", return_value=False):
            result = execute(
                {"left"},
                REGISTRY,
                {"left": exits},
                evidence,
                {
                    "concurrency": 1,
                    "max_retries": 2,
                    "retry_backoff_seconds": 0,
                    "task_timeout_seconds": 5,
                    "cache_dir": str(cache_dir),
                    "fingerprint": lambda _task: "system-exit",
                },
            )
        task = result["tasks"][0]
        self.assertFalse(result["ok"])
        self.assertFalse(task["ok"])
        self.assertEqual(len(task["attempts"]), 1)
        self.assertEqual(task["attempts"][0]["outcome"], "error")
        self.assertEqual(task["attempts"][0]["diagnostic"], "SystemExit")
        self.assertFalse(task["attempts"][0]["transient"])
        self.assertEqual(_logged(calls), ["call"])
        self.assertEqual(evidence, {"findings": {}})
        self.assertEqual(closed, {"kept": 1})
        self.assertFalse((cache_dir / "system-exit.json").exists())

    def test_fallback_deadline_during_grace_is_terminal_budget(self):
        calls = self.tmp / "calls"

        def slow_exit(_task, _store):
            _log_call(calls)
            time.sleep(0.15)
            return {"late": True}

        started = time.monotonic()
        result = _run_thread_task(
            "left",
            slow_exit,
            {},
            None,
            0.05,
            2,
            0,
            threading.Event(),
            started + 0.10,
            None,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "budget exhausted")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["reason"], "run budget exhausted")
        self.assertEqual(_logged(calls), ["call"])

    def _timeout_only_execution(self, selected, ok_values=None):
        ok_values = ok_values or {}
        timeout_records = [
            {"attempt": 1, "outcome": "timeout", "reason": "exceeded 0.050s", "transient": True, "diagnostic": "elapsed>0.050"},
            {"attempt": 2, "outcome": "timeout", "reason": "exceeded 0.050s", "transient": True, "diagnostic": "elapsed>0.050"},
        ]

        def fake_execute(chosen, _registry, _runners, _evidence, _options=None):
            tasks = []
            for task_id in sorted(chosen):
                if task_id in ok_values:
                    tasks.append({"task_id": task_id, "ok": True, "cached": False, "value": ok_values[task_id], "attempts": []})
                else:
                    tasks.append({"task_id": task_id, "ok": False, "cached": False, "error": "timeout", "attempts": list(timeout_records)})
            return {
                "ok": False,
                "tasks": tasks,
                "order": sorted(chosen),
                "layers": [sorted(chosen)],
                "cache_hits": [],
                "cancelled": False,
            }

        repo = self.tmp / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        (repo / "quality-auditor.yaml").write_text(
            "version: 1\ndefault_profile: focused\nprofiles:\n  focused:\n    include: [" + ", ".join(selected) + "]\n",
            encoding="utf-8",
        )
        with mock.patch.object(audit_module, "execute", fake_execute):
            report = auditor.audit(repo, skill_root=SKILL, profile="focused", output_dir=self.tmp / "out")
        return report, timeout_records

    def test_timeout_only_audit_is_incomplete_with_error_metrics(self):
        report, timeout_records = self._timeout_only_execution(["syntax_static"])
        self.assertEqual(report["decision"], "INCOMPLETE")
        metric = next(item for item in report["metrics"] if item["metric_id"] == "REL-004")
        self.assertEqual(metric["status"], "ERROR")
        self.assertEqual(metric["reason"], "timeout")
        task = next(item for item in report["execution"]["tasks"] if item["task_id"] == "syntax_static")
        self.assertFalse(task["ok"])
        self.assertEqual(task["error"], "timeout")
        self.assertEqual(task["attempts"], timeout_records)

    def test_confirmed_blocking_breach_still_fails_beside_a_timeout(self):
        report, _records = self._timeout_only_execution(
            ["syntax_static", "insecure_config"],
            {"insecure_config": {"measurements": {"SEC-006": {"value": 1}, "SEC-012": {"value": 0}}}},
        )
        self.assertEqual(report["decision"], "FAIL")
        statuses = {item["metric_id"]: item["status"] for item in report["metrics"]}
        self.assertEqual(statuses["SEC-006"], "FAIL")
        self.assertEqual(statuses["REL-004"], "ERROR")

    def test_audit_keeps_graph_evidence_across_parallel_checks(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n", encoding="utf-8")
        (repo / "quality-auditor.yaml").write_text(
            "version: 1\ndefault_profile: focused\nprofiles:\n  focused:\n    include: [syntax_static, symbol_index]\n",
            encoding="utf-8",
        )
        report = auditor.audit(
            repo,
            skill_root=SKILL,
            profile="focused",
            output_dir=self.tmp / "out",
            invocation={"budgets": {"concurrency": 2}},
        )
        self.assertGreater(report["graph_completeness"].get("indexed_files", 0), 0)

    def test_failed_attempt_does_not_keep_partial_findings(self):
        class Context:
            def __init__(self):
                self.analyses = []

        def make_runner(counter, context):
            def runner(_task, store):
                count = int(counter.read_text(encoding="utf-8")) + 1
                counter.write_text(str(count), encoding="utf-8")
                context.analyses.append("partial")
                store["findings"]["leaked"] = count
                if count == 1:
                    raise TransientFailure("temporary")
                context.analyses[:] = ["final"]
                store["findings"] = {"final": True}
                return {"ok": True}

            return runner

        context = Context()
        counter = self.tmp / "tries"
        counter.write_text("0", encoding="utf-8")
        evidence = {"findings": {}}
        result = execute(
            {"left"},
            REGISTRY,
            {"left": make_runner(counter, context)},
            evidence,
            {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 2},
        )
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(len(result["tasks"][0]["attempts"]), 2)
        self.assertEqual(context.analyses, ["final"])
        self.assertEqual(evidence["findings"], {"final": True})

        terminal = Context()
        terminal_evidence = {"findings": {}}

        def broken(_task, store):
            terminal.analyses.append("partial")
            store["findings"]["leaked"] = True
            raise ValueError("deterministic")

        failed = execute(
            {"left"},
            REGISTRY,
            {"left": broken},
            terminal_evidence,
            {"concurrency": 1, "max_retries": 2, "task_timeout_seconds": 2},
        )
        self.assertFalse(failed["ok"])
        self.assertEqual(len(failed["tasks"][0]["attempts"]), 1)
        self.assertEqual(terminal.analyses, [])
        self.assertEqual(terminal_evidence["findings"], {})

    def test_parallel_writers_keep_distinct_nested_evidence_keys(self):
        registry = {
            "left": {"id": "left", "depends_on": []},
            "right": {"id": "right", "depends_on": []},
        }

        def make_runner(left_delay, right_delay):
            def runner(task_id, store):
                if task_id == "left":
                    time.sleep(left_delay)
                    store["findings"]["a"] = 1
                else:
                    time.sleep(right_delay)
                    store["findings"]["b"] = 1
                return {"task": task_id}

            return runner

        for left_delay, right_delay in ((0.0, 0.25), (0.25, 0.0)):
            evidence = {"findings": {"a": 0, "b": 0}}
            runner = make_runner(left_delay, right_delay)
            result = execute(
                {"left", "right"},
                registry,
                {"left": runner, "right": runner},
                evidence,
                {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(evidence["findings"], {"a": 1, "b": 1})

    def test_successful_task_removes_and_clears_nested_findings(self):
        removed = {"findings": {"stale": {"status": "failed"}, "valid": 1}}

        def drop(_task, store):
            del store["findings"]["stale"]
            return {"ok": True}

        result = execute(
            {"left"},
            REGISTRY,
            {"left": drop},
            removed,
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(removed["findings"], {"valid": 1})

        cleared = {"findings": {"stale": {"status": "failed"}, "valid": 1}}

        def clear(_task, store):
            store["findings"]["stale"] = None
            return {"ok": True}

        result = execute(
            {"left"},
            REGISTRY,
            {"left": clear},
            cleared,
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(cleared["findings"], {"stale": None, "valid": 1})

        closed = {"stale": {"status": "failed"}, "valid": 1}

        def drop_closed(_task, _store):
            del closed["stale"]
            return {"ok": True}

        result = execute(
            {"left"},
            REGISTRY,
            {"left": drop_closed},
            {},
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(closed, {"valid": 1})

    def test_failed_attempt_does_not_publish_a_deletion(self):
        evidence = {"findings": {"stale": 1}}

        def broken(_task, store):
            del store["findings"]["stale"]
            raise ValueError("deterministic")

        failed = execute(
            {"left"},
            REGISTRY,
            {"left": broken},
            evidence,
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertFalse(failed["ok"])
        self.assertEqual(evidence["findings"], {"stale": 1})

    def _run_both_orders(self, evidence_factory, left, right):
        registry = {
            "left": {"id": "left", "depends_on": []},
            "right": {"id": "right", "depends_on": []},
        }
        outcomes = []
        for left_delay, right_delay in ((0.0, 0.3), (0.3, 0.0)):
            held = evidence_factory()
            delays = {"left": left_delay, "right": right_delay}
            if isinstance(held, dict):
                def runner(task_id, store):
                    time.sleep(delays[task_id])
                    (left if task_id == "left" else right)(store)
                    return {"task": task_id}

                evidence = held
            else:
                def runner(task_id, _store):
                    time.sleep(delays[task_id])
                    (left if task_id == "left" else right)(held)
                    return {"task": task_id}

                evidence = {}
            result = execute(
                {"left", "right"},
                registry,
                {"left": runner, "right": runner},
                evidence,
                {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
            )
            self.assertTrue(result["ok"], result)
            outcomes.append(held)
        return outcomes

    def test_parallel_delete_and_update_keep_both_changes(self):
        def left(store):
            del store["findings"]["stale"]

        def right(store):
            store["findings"]["fresh"] = 1

        outcomes = self._run_both_orders(lambda: {"findings": {"stale": 1}}, left, right)
        for evidence in outcomes:
            self.assertEqual(evidence["findings"], {"fresh": 1})

    def test_parallel_delete_and_update_of_same_key_keeps_the_update(self):
        def left(store):
            del store["findings"]["stale"]

        def right(store):
            store["findings"]["stale"] = 9

        outcomes = self._run_both_orders(lambda: {"findings": {"stale": 1, "kept": 2}}, left, right)
        for evidence in outcomes:
            self.assertEqual(evidence["findings"], {"stale": 9, "kept": 2})

    def test_parallel_nested_delete_and_patch_keeps_the_patch(self):
        def left(store):
            del store["findings"]["stale"]

        def right(store):
            store["findings"]["stale"]["x"] = 3

        outcomes = self._run_both_orders(
            lambda: {"findings": {"stale": {"x": 1, "y": 2}}},
            left,
            right,
        )
        for evidence in outcomes:
            self.assertEqual(evidence["findings"], {"stale": {"x": 3, "y": 2}})

    def test_parallel_null_and_update_of_same_key_keeps_the_update(self):
        def left(store):
            store["findings"]["stale"] = None

        def right(store):
            store["findings"]["stale"] = 9

        outcomes = self._run_both_orders(lambda: {"findings": {"stale": 1}}, left, right)
        for evidence in outcomes:
            self.assertEqual(evidence["findings"], {"stale": 9})

    def test_explicit_null_stays_distinct_from_deletion(self):
        before = {"stale": 1, "kept": 2}
        self.assertIsInstance(_dict_delta(before, {"stale": None, "kept": 2})["stale"], Tombstone)
        self.assertEqual(_dict_delta(before, {"stale": None, "kept": 2})["stale"].kind, "null")
        self.assertEqual(_dict_delta(before, {"kept": 2})["stale"].kind, "delete")
        present = {"stale": 1, "kept": 2}
        _merge_dict(present, _dict_delta(before, {"stale": None, "kept": 2}))
        self.assertEqual(present, {"stale": None, "kept": 2})
        absent = {"stale": 1, "kept": 2}
        _merge_dict(absent, _dict_delta(before, {"kept": 2}))
        self.assertEqual(absent, {"kept": 2})

    def test_list_truncation_keeps_sibling_element_edit(self):
        class Context:
            def __init__(self):
                self.analyses = [{"a": 0}, {"b": 0}]

        def left(evidence):
            evidence.analyses.pop()

        def right(evidence):
            evidence.analyses[0]["a"] = 1

        outcomes = self._run_both_orders(Context, left, right)
        for evidence in outcomes:
            self.assertEqual(evidence.analyses, [{"a": 1}])

    def test_list_truncation_does_not_replace_a_sibling_edit_of_the_removed_element(self):
        class Context:
            def __init__(self):
                self.analyses = [{"a": 0}, {"b": 0}]

        def left(evidence):
            evidence.analyses.pop()

        def right(evidence):
            evidence.analyses[1]["b"] = 1

        outcomes = self._run_both_orders(Context, left, right)
        for evidence in outcomes:
            self.assertEqual(evidence.analyses, [{"a": 0}, {"b": 1}])

    def test_shorter_list_delta_is_index_deletion_not_replacement(self):
        change = _list_change([{"a": 0}, {"b": 0}], [{"a": 1}])
        self.assertEqual(change[0], "elements")
        self.assertEqual(change[1]["deleted"][0][0], 1)
        self.assertNotEqual(change[0], "value")

    def test_overlapping_audits_keep_separate_deletion_batches(self):
        for first_to_finish in ("left", "right"):
            with self.subTest(first_to_finish=first_to_finish):
                self._overlapping_audits(first_to_finish)

    def _overlapping_audits(self, first_to_finish):
        directory = Path(tempfile.mkdtemp(prefix="cqa-overlap-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))

        def flag(name):
            return directory / name

        def signal(name):
            flag(name).write_text("1", encoding="utf-8")

        def wait_for(name, timeout=4):
            deadline = time.monotonic() + timeout
            while not flag(name).exists():
                if time.monotonic() > deadline:
                    return False
                time.sleep(0.01)
            return True

        registry = {
            "drop": {"id": "drop", "depends_on": []},
            "patch": {"id": "patch", "depends_on": []},
        }
        errors = []

        def run(name):
            evidence = {"findings": {"stale": {"old": 1}}}

            def drop(_task, store):
                signal(f"{name}-entered")
                del store["findings"]["stale"]
                return {"ok": True}

            def patch(_task, store):
                other = "right" if name == "left" else "left"
                wait_for(f"{name}-dropped")
                wait_for(f"{other}-entered")
                if first_to_finish == other:
                    wait_for(f"{other}-finished")
                store["findings"]["stale"]["mark"] = name
                return {"ok": True}

            def on_result(task_id, _result):
                if task_id == "drop":
                    signal(f"{name}-dropped")

            try:
                result = execute(
                    {"drop", "patch"},
                    registry,
                    {"drop": drop, "patch": patch},
                    evidence,
                    {
                        "concurrency": 2,
                        "max_retries": 1,
                        "task_timeout_seconds": 6,
                        "on_result": on_result,
                    },
                )
                if not result["ok"] or evidence["findings"].get("stale") != {"old": 1, "mark": name}:
                    errors.append((name, result, dict(evidence)))
            except Exception as exc:  # noqa: BLE001 - reported by the assertion below
                errors.append((name, exc))
            finally:
                signal(f"{name}-finished")
                signal(f"{name}-entered")
                signal(f"{name}-dropped")

        threads = [threading.Thread(target=run, args=(name,)) for name in ("left", "right")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(8)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_later_insert_does_not_resurrect_a_deleted_dict(self):
        evidence = {"a": {"old": 1}}
        _merge_dict(evidence, {"a": Tombstone("delete", {"old": 1})})
        _merge_dict(evidence, {"a": {"new": 2}})
        self.assertEqual(evidence, {"a": {"new": 2}})

    def test_later_task_replaces_a_deleted_dict_without_resurrecting_it(self):
        registry = {
            "drop": {"id": "drop", "depends_on": []},
            "insert": {"id": "insert", "depends_on": ["drop"]},
        }
        evidence = {"findings": {"stale": {"old": 1}, "other": 1}}

        def drop(_task, store):
            del store["findings"]["stale"]
            return {"ok": True}

        def insert(_task, store):
            self.assertNotIn("stale", store["findings"])
            store["findings"]["stale"] = {"new": 2}
            return {"ok": True}

        result = execute(
            {"drop", "insert"},
            registry,
            {"drop": drop, "insert": insert},
            evidence,
            {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(evidence["findings"], {"stale": {"new": 2}, "other": 1})
