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

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".cursor" / "skills" / "code-quality-auditor"
sys.path.insert(0, str(SKILL / "scripts"))

spec = importlib.util.spec_from_file_location("auditor", SKILL / "scripts" / "auditor.py")
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)

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

        def blocked(_task, _store):
            os.read(read_fd, 1)
            return {"done": True}

        started = time.monotonic()
        result = _run_thread_task("left", blocked, {}, "key", 0.2, 2, 0, threading.Event(), None, None)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "termination could not be guaranteed")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertFalse(result["attempts"][0]["transient"])
        os.close(write_fd)
        os.close(read_fd)

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
