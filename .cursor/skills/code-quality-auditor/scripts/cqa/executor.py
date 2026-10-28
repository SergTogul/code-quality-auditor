"""Lightweight deterministic DAG planner and executor."""

from __future__ import annotations

import json
import os
import pickle
import select
import signal
import tempfile
import threading
import time
from pathlib import Path


class TransientFailure(Exception):
    """A timeout or other failure that may be retried. Deterministic defects are not transient."""


class _AttemptCancelled(BaseException):
    """Injected into a thread only when process isolation is unavailable."""


def dag(selected, registry):
    """Return task nodes for the selected checks plus declared dependencies, in dependency order."""
    nodes = {}
    stack = []

    def visit(check_id):
        if check_id in nodes:
            return
        if check_id in stack:
            cycle = " -> ".join(stack + [check_id])
            raise ValueError(f"dependency cycle: {cycle}")
        if check_id not in registry:
            raise ValueError(f"unknown check: {check_id}")
        stack.append(check_id)
        for dep in registry[check_id].get("depends_on") or []:
            visit(dep)
        stack.pop()
        nodes[check_id] = registry[check_id]

    for check_id in sorted(selected):
        visit(check_id)
    return nodes


def layers_of(nodes):
    indegree = {check_id: 0 for check_id in nodes}
    dependents = {check_id: [] for check_id in nodes}
    for check_id, spec in nodes.items():
        for dep in spec.get("depends_on") or []:
            if dep not in nodes:
                raise ValueError(f"unknown check: {dep}")
            indegree[check_id] += 1
            dependents[dep].append(check_id)
    ready = sorted(check_id for check_id, degree in indegree.items() if degree == 0)
    layers = []
    seen = 0
    while ready:
        layers.append(list(ready))
        seen += len(ready)
        nxt = []
        for check_id in ready:
            for child in dependents[check_id]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    nxt.append(child)
        ready = sorted(nxt)
    if seen != len(nodes):
        raise ValueError("dependency cycle")
    return layers


def _cache_file(cache_dir, key):
    return Path(cache_dir) / f"{key}.json"


def _read_cache(cache_dir, key):
    if not cache_dir or not key:
        return None
    path = _cache_file(cache_dir, key)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(cache_dir, key, payload):
    if not cache_dir or not key:
        return
    path = _cache_file(cache_dir, key)
    try:
        encoded = json.dumps(payload, sort_keys=True)
    except TypeError:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")


def _isolated_processes():
    return os.name == "posix" and hasattr(os, "fork") and hasattr(os, "setsid")


def _json_key(value):
    return json.dumps(value, sort_keys=True, default=str)


def _extend_unique(existing, extra):
    seen = {_json_key(item) for item in existing}
    for item in extra:
        key = _json_key(item)
        if key not in seen:
            existing.append(item)
            seen.add(key)


def _pickleable(value):
    try:
        pickle.dumps(value)
    except Exception:
        return False
    return True


def _snapshot(value):
    """Copy values before an attempt so later in-place edits stay visible as deltas."""
    return pickle.loads(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL))


def _export_object(obj):
    data = {}
    for key, value in obj.__dict__.items():
        if key == "lock" or not _pickleable(value):
            continue
        data[key] = value
    return data


def _skip_cell(value):
    if any(cls.__name__ == "TestCase" for cls in type(value).__mro__):
        return True
    return type(value).__name__ in {"module", "function", "method", "RLock", "Lock", "Event"}


def _export_closures(fn):
    closure = getattr(fn, "__closure__", None) or ()
    exported = []
    for cell in closure:
        try:
            current = cell.cell_contents
        except ValueError:
            exported.append(("skip", None))
            continue
        if isinstance(current, dict):
            copied = {key: value for key, value in current.items() if _pickleable(value)}
            exported.append(("dict", copied))
        elif hasattr(current, "__dict__") and not _skip_cell(current):
            exported.append(("object", _export_object(current)))
        else:
            exported.append(("skip", None))
    return exported


def _same(left, right):
    try:
        return pickle.dumps(left, protocol=pickle.HIGHEST_PROTOCOL) == pickle.dumps(right, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        return False


def _dict_delta(before, after):
    """Changed keys only. Nested dicts stay nested so siblings are not replaced."""
    before = before or {}
    delta = {}
    for key, value in (after or {}).items():
        if key not in before:
            delta[key] = value
            continue
        previous = before[key]
        if _same(previous, value):
            continue
        if isinstance(previous, dict) and isinstance(value, dict):
            nested = _dict_delta(previous, value)
            if nested:
                delta[key] = nested
        elif value is None:
            continue
        else:
            delta[key] = value
    return delta


def _merge_dict(current, delta):
    for key, value in delta.items():
        existing = current.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            _merge_dict(existing, value)
        elif value is None and key in current and existing is not None:
            continue
        else:
            current[key] = value


def _element_change(before, after):
    if isinstance(before, dict) and isinstance(after, dict):
        nested = _dict_delta(before, after)
        if not nested:
            return None
        if set(before) - set(after):
            return ("value", after)
        return ("dict", nested)
    if after is None and before is not None:
        return None
    return ("value", after)


def _list_change(before, after):
    """Append a pure tail. Same-length edits merge per element so siblings do not replace the list."""
    if not isinstance(before, list) or not isinstance(after, list):
        return ("value", after)
    if len(after) >= len(before) and all(_same(before[index], after[index]) for index in range(len(before))):
        extra = after[len(before):]
        if not extra:
            return None
        return ("list", extra)
    if len(after) < len(before):
        return ("value", after)
    changes = []
    for index, previous in enumerate(before):
        change = _element_change(previous, after[index])
        if change:
            changes.append((index, change[0], change[1]))
    extra = after[len(before):]
    if not changes:
        return ("list", extra) if extra else None
    return ("elements", {"changes": changes, "extra": extra})


def _object_delta(before, after):
    """Return only fields whose value changed during this attempt."""
    delta = {}
    for key, value in after.items():
        if key == "lock" or key not in before:
            continue
        previous = before[key]
        if _same(previous, value):
            continue
        if isinstance(previous, dict) and isinstance(value, dict):
            nested = _dict_delta(previous, value)
            if nested:
                delta[key] = ("dict", nested)
        elif isinstance(previous, list) and isinstance(value, list):
            change = _list_change(previous, value)
            if change:
                delta[key] = change
        elif hasattr(previous, "__dict__") and hasattr(value, "__dict__") and not _skip_cell(value):
            nested = _object_delta(_export_object(previous), _export_object(value))
            if nested:
                delta[key] = ("object", nested)
        elif value is None:
            continue
        else:
            delta[key] = ("value", value)
    return delta


def _closure_delta(before, after):
    deltas = []
    for previous, current in zip(before, after):
        kind = current[0]
        if kind == "dict":
            deltas.append(("dict", _dict_delta(previous[1], current[1])))
        elif kind == "object":
            deltas.append(("object", _object_delta(previous[1] or {}, current[1] or {})))
        else:
            deltas.append(("skip", None))
    return deltas


def _merge_object(current, exported):
    for key, change in exported.items():
        if key == "lock" or not isinstance(change, tuple) or len(change) != 2:
            continue
        kind, value = change
        existing = getattr(current, key, None)
        if kind == "dict" and isinstance(existing, dict):
            _merge_dict(existing, value)
        elif kind == "dict" and existing is None:
            setattr(current, key, dict(value))
        elif kind == "list" and isinstance(existing, list):
            _extend_unique(existing, value)
        elif kind == "list" and existing is None:
            setattr(current, key, list(value))
        elif kind == "elements" and isinstance(existing, list) and isinstance(value, dict):
            for index, ekind, payload in value.get("changes") or []:
                if not isinstance(index, int) or index < 0 or index >= len(existing):
                    continue
                current_item = existing[index]
                if ekind == "dict" and isinstance(current_item, dict):
                    _merge_dict(current_item, payload)
                elif ekind == "value" and not (payload is None and current_item is not None):
                    existing[index] = payload
            _extend_unique(existing, value.get("extra") or [])
        elif kind == "object" and hasattr(existing, "__dict__"):
            _merge_object(existing, value)
        elif kind == "value":
            if value is None and existing is not None:
                continue
            setattr(current, key, value)


def _merge_closures(fn, exported):
    closure = getattr(fn, "__closure__", None) or ()
    for cell, item in zip(closure, exported):
        kind, payload = item
        try:
            current = cell.cell_contents
        except ValueError:
            continue
        if kind == "dict" and isinstance(current, dict) and isinstance(payload, dict):
            _merge_dict(current, payload)
        elif kind == "object" and isinstance(payload, dict) and hasattr(current, "__dict__"):
            _merge_object(current, payload)


def _merge_evidence(evidence, exported):
    if isinstance(evidence, dict) and isinstance(exported, dict):
        _merge_dict(evidence, exported)


def _attempt_payload(runner, task_id, evidence):
    before_cells = _snapshot(_export_closures(runner))
    before_evidence = _snapshot(dict(evidence)) if isinstance(evidence, dict) else None
    try:
        value = runner(task_id, evidence)
        status = "ok"
        error = None
    except Exception as exc:  # noqa: BLE001 - classified by the parent
        value = None
        status = "error"
        error = {
            "type": exc.__class__.__name__,
            "message": str(exc),
            "transient": isinstance(exc, (TransientFailure, TimeoutError)),
        }
    evidence_delta = _dict_delta(before_evidence, dict(evidence)) if isinstance(evidence, dict) else None
    return {
        "status": status,
        "value": value if _pickleable(value) else None,
        "error": error,
        "evidence": evidence_delta,
        "cells": _closure_delta(before_cells, _export_closures(runner)),
    }


def _write_payload(path, payload):
    temporary = path + ".tmp"
    with open(temporary, "wb") as handle:
        pickle.dump(payload, handle)
    os.replace(temporary, path)


def _fork_attempt(runner, task_id, evidence, result_path):
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.setsid()
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            if hasattr(signal, "setitimer"):
                signal.setitimer(signal.ITIMER_REAL, 0)
            os.write(ready_write, b"1")
            os.close(ready_write)
            _write_payload(result_path, _attempt_payload(runner, task_id, evidence))
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(ready_write)
    return pid, ready_read


def _group_ready(ready_read):
    if ready_read is None:
        return False
    readable, _, _ = select.select([ready_read], [], [], 0)
    if not readable:
        return False
    try:
        os.read(ready_read, 1)
    except OSError:
        return False
    return True


def _signal_pid(pid, group_ready):
    try:
        if group_ready:
            os.killpg(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return


def _reap(pid, seconds=2):
    deadline = time.monotonic() + seconds
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if waited == pid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _read_payload(path):
    try:
        with open(path, "rb") as handle:
            return pickle.load(handle)
    except (OSError, pickle.UnpicklingError, EOFError):
        return None


def _close_pipe(ready_read):
    if ready_read is None:
        return
    try:
        os.close(ready_read)
    except OSError:
        pass


def _apply_payload(runner, evidence, payload):
    if not payload:
        return
    _merge_closures(runner, payload.get("cells") or [])
    _merge_evidence(evidence, payload.get("evidence"))


class _Job:
    def __init__(self, task_id, runner, evidence, key):
        self.task_id = task_id
        self.runner = runner
        self.evidence = evidence
        self.key = key
        self.attempt = 1
        self.records = []
        self.next_time = 0.0
        self.pid = None
        self.ready_read = None
        self.group_ready = False
        self.result_path = None
        self.started = None
        self.deadline = None


def _timeout_record(attempt, task_timeout, diagnostic, transient):
    return {
        "attempt": attempt,
        "outcome": "timeout",
        "reason": f"exceeded {task_timeout}s",
        "transient": transient,
        "diagnostic": diagnostic,
    }


def _finish_job(job, ok, error, value, cache_dir):
    if ok:
        _write_cache(cache_dir, job.key, {"ok": True, "value": value})
        return {
            "task_id": job.task_id,
            "ok": True,
            "cached": False,
            "value": value,
            "attempts": job.records,
        }
    return {
        "task_id": job.task_id,
        "ok": False,
        "cached": False,
        "error": error,
        "attempts": job.records,
    }


def _poll_job(job, now, cancel, max_attempts, backoff):
    """Return (finished_result_or_none, still_running)."""
    if not job.group_ready:
        job.group_ready = _group_ready(job.ready_read)
    try:
        waited, _status = os.waitpid(job.pid, os.WNOHANG)
    except ChildProcessError:
        waited = job.pid
    timed_out = now >= job.deadline
    cancelled = cancel.is_set()
    if waited != job.pid and not timed_out and not cancelled:
        return None, True
    killed = False
    if waited != job.pid:
        _signal_pid(job.pid, job.group_ready)
        killed = True
        reaped = _reap(job.pid)
    else:
        reaped = True
        if job.group_ready:
            _signal_pid(job.pid, True)
    payload = None if killed else _read_payload(job.result_path)
    if payload and payload.get("status") == "ok":
        _apply_payload(job.runner, job.evidence, payload)
    _close_pipe(job.ready_read)
    if job.result_path:
        try:
            os.unlink(job.result_path)
        except OSError:
            pass
    job.pid = None
    if killed or payload is None:
        transient = bool(reaped and not cancelled)
        reason = "cancelled" if cancelled else f"exceeded {job.deadline - job.started:.3f}s"
        diagnostic = "cancelled" if cancelled else (f"elapsed>{job.deadline - job.started:.3f}" if reaped else "attempt did not terminate")
        if not cancelled:
            reason = f"exceeded {job.deadline - job.started:.3f}s"
        job.records.append(
            {
                "attempt": job.attempt,
                "outcome": "timeout",
                "reason": "cancelled" if cancelled else reason,
                "transient": False if cancelled or not reaped else True,
                "diagnostic": diagnostic,
            }
        )
        if cancelled or not transient or job.attempt >= max_attempts:
            error = "cancelled" if cancelled else "timeout"
            return _finish_job(job, False, error, None, None), False
        job.attempt += 1
        job.next_time = time.monotonic() + (backoff * (job.attempt - 1))
        return None, False
    if payload.get("status") == "error":
        error = payload.get("error") or {}
        transient = bool(error.get("transient"))
        job.records.append(
            {
                "attempt": job.attempt,
                "outcome": "error",
                "reason": error.get("message") or "attempt failed",
                "transient": transient,
                "diagnostic": error.get("type") or "Exception",
            }
        )
        if not transient or job.attempt >= max_attempts:
            return _finish_job(job, False, error.get("message") or "attempt failed", None, None), False
        job.attempt += 1
        job.next_time = time.monotonic() + (backoff * (job.attempt - 1))
        return None, False
    job.records.append(
        {
            "attempt": job.attempt,
            "outcome": "success",
            "reason": None,
            "transient": False,
            "diagnostic": f"elapsed={time.monotonic() - job.started:.3f}s",
        }
    )
    return _finish_job(job, True, None, payload.get("value"), job.cache_dir), False


def _start_job(job, task_timeout):
    descriptor, path = tempfile.mkstemp(prefix="cqa-attempt-")
    os.close(descriptor)
    job.result_path = path
    job.started = time.monotonic()
    job.deadline = job.started + task_timeout
    job.group_ready = False
    job.pid, job.ready_read = _fork_attempt(job.runner, job.task_id, job.evidence, path)


def _raise_in_thread(thread):
    ident = thread.ident
    if not ident:
        return False
    import ctypes

    exception = ctypes.py_object(_AttemptCancelled)
    ident_value = ctypes.c_ulong(ident)
    count = ctypes.pythonapi.PyThreadState_SetAsyncExc(ident_value, exception)
    if count > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ident_value, None)
        return False
    return count == 1


def _run_thread_attempt(runner, task_id, evidence, task_timeout, cancel):
    """Fallback for platforms without fork. A live thread is never overlapped by a retry."""
    holder = {}

    def invoke():
        try:
            if cancel.is_set():
                raise _AttemptCancelled("cancelled")
            holder["value"] = runner(task_id, evidence)
        except _AttemptCancelled as exc:
            holder["cancelled"] = exc
        except Exception as exc:  # noqa: BLE001 - classified by the caller
            holder["error"] = exc

    worker = threading.Thread(target=invoke, daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(task_timeout)
    if worker.is_alive() or cancel.is_set():
        cancel_requested = cancel.is_set()
        _raise_in_thread(worker)
        worker.join(0.2)
        reaped = not worker.is_alive()
        return {
            "kind": "timeout",
            "reaped": reaped,
            "cancelled": cancel_requested,
            "unterminated": not reaped,
            "elapsed": time.monotonic() - started,
        }
    if "error" in holder:
        exc = holder["error"]
        return {
            "kind": "error",
            "type": exc.__class__.__name__,
            "message": str(exc),
            "transient": isinstance(exc, (TransientFailure, TimeoutError)),
            "elapsed": time.monotonic() - started,
        }
    if "cancelled" in holder:
        return {"kind": "timeout", "reaped": True, "cancelled": True, "elapsed": time.monotonic() - started}
    return {"kind": "ok", "value": holder.get("value"), "elapsed": time.monotonic() - started}


def _run_thread_task(task_id, runner, evidence, key, task_timeout, max_attempts, backoff, cancel, deadline, cache_dir):
    records = []
    for attempt in range(1, max_attempts + 1):
        if cancel.is_set() or (deadline is not None and time.monotonic() > deadline):
            records.append(
                {
                    "attempt": attempt,
                    "outcome": "timeout",
                    "reason": "cancelled" if cancel.is_set() else "run budget exhausted",
                    "transient": False,
                    "diagnostic": "cancelled before start",
                }
            )
            error = "cancelled" if cancel.is_set() else "budget exhausted"
            return {"task_id": task_id, "ok": False, "cached": False, "error": error, "attempts": records}
        outcome = _run_thread_attempt(runner, task_id, evidence, task_timeout, cancel)
        if outcome["kind"] == "timeout":
            if outcome.get("unterminated"):
                records.append(
                    {
                        "attempt": attempt,
                        "outcome": "timeout",
                        "reason": "termination could not be guaranteed",
                        "transient": False,
                        "diagnostic": "termination could not be guaranteed",
                    }
                )
                return {"task_id": task_id, "ok": False, "cached": False, "error": "termination could not be guaranteed", "attempts": records}
            transient = bool(outcome["reaped"] and not outcome["cancelled"])
            records.append(_timeout_record(attempt, task_timeout, "cancelled" if outcome["cancelled"] else (f"elapsed>{task_timeout}" if transient else "attempt did not terminate"), transient))
            if outcome["cancelled"]:
                records[-1]["reason"] = "cancelled"
                records[-1]["transient"] = False
            if not transient or attempt == max_attempts:
                return {"task_id": task_id, "ok": False, "cached": False, "error": "cancelled" if outcome["cancelled"] else "timeout", "attempts": records}
            time.sleep(backoff * attempt)
            continue
        if outcome["kind"] == "error":
            records.append(
                {
                    "attempt": attempt,
                    "outcome": "error",
                    "reason": outcome["message"],
                    "transient": outcome["transient"],
                    "diagnostic": outcome["type"],
                }
            )
            if not outcome["transient"] or attempt == max_attempts:
                return {"task_id": task_id, "ok": False, "cached": False, "error": outcome["message"], "attempts": records}
            time.sleep(backoff * attempt)
            continue
        records.append(
            {
                "attempt": attempt,
                "outcome": "success",
                "reason": None,
                "transient": False,
                "diagnostic": f"elapsed={outcome['elapsed']:.3f}s",
            }
        )
        _write_cache(cache_dir, key, {"ok": True, "value": outcome["value"]})
        return {"task_id": task_id, "ok": True, "cached": False, "value": outcome["value"], "attempts": records}
    return {"task_id": task_id, "ok": False, "cached": False, "error": "retries exhausted", "attempts": records}


def _run_processes(jobs, concurrency, task_timeout, max_attempts, backoff, cancel, deadline, cache_dir, on_result):
    results = {}
    failed = set()
    queue = list(jobs)
    delayed = []
    inflight = []
    for job in jobs:
        job.cache_dir = cache_dir

    def store(job, result):
        results[job.task_id] = result
        if on_result is not None:
            on_result(job.task_id, result)
        if not result.get("ok"):
            failed.add(job.task_id)

    while queue or delayed or inflight:
        now = time.monotonic()
        if deadline is not None and now > deadline:
            cancel.set()
        if cancel.is_set() and not inflight:
            for job in queue + delayed:
                job.records.append(
                    {
                        "attempt": job.attempt,
                        "outcome": "timeout",
                        "reason": "cancelled" if cancel.is_set() and (deadline is None or now <= deadline) else "run budget exhausted",
                        "transient": False,
                        "diagnostic": "cancelled before start",
                    }
                )
                error = "budget exhausted" if deadline is not None and now > deadline else "cancelled"
                store(job, _finish_job(job, False, error, None, None))
            break
        still_delayed = []
        for job in delayed:
            if job.next_time <= now and not cancel.is_set():
                queue.append(job)
            elif cancel.is_set():
                job.records.append(
                    {
                        "attempt": job.attempt,
                        "outcome": "timeout",
                        "reason": "cancelled",
                        "transient": False,
                        "diagnostic": "cancelled before start",
                    }
                )
                store(job, _finish_job(job, False, "cancelled", None, None))
            else:
                still_delayed.append(job)
        delayed = still_delayed
        while queue and len(inflight) < concurrency and not cancel.is_set():
            job = queue.pop(0)
            _start_job(job, task_timeout)
            inflight.append(job)
        if not inflight:
            if delayed:
                time.sleep(min(0.01, max(0.0, min(job.next_time for job in delayed) - time.monotonic())))
            continue
        progressed = False
        for job in list(inflight):
            result, running = _poll_job(job, time.monotonic(), cancel, max_attempts, backoff)
            if running:
                continue
            inflight.remove(job)
            progressed = True
            if result is None:
                delayed.append(job)
            else:
                if result.get("ok"):
                    _write_cache(cache_dir, job.key, {"ok": True, "value": result.get("value")})
                store(job, result)
        if not progressed:
            time.sleep(0.01)
    return results, failed


def execute(selected, registry, runners, evidence, options=None):
    """Run independent tasks in parallel, reuse cached successful results, and retry transient failures.

    Deterministic exceptions are not retried. Each attempt runs in a killable
    process session on POSIX. The next attempt starts only after the previous
    process has been reaped. Exhausted retries and timeouts are terminal errors;
    callers must treat them as fail-closed.
    """
    options = options or {}
    nodes = dag(selected, registry)
    layers = layers_of(nodes)
    concurrency = max(1, int(options.get("concurrency") or 1))
    max_attempts = max(1, int(options.get("max_retries") or 1))
    backoff = float(options.get("retry_backoff_seconds") or 0)
    task_timeout = float(options.get("task_timeout_seconds") or 60)
    cache_dir = options.get("cache_dir")
    fingerprint = options.get("fingerprint") or (lambda _task: "")
    deadline = options.get("deadline")
    cancel = options.get("cancel_event") or threading.Event()
    results = {}
    cache_hits = []
    on_result = options.get("on_result")
    failed = set()
    isolate = _isolated_processes()

    def remember(task_id, result):
        results[task_id] = result
        if on_result is not None:
            on_result(task_id, result)
        if not result.get("ok"):
            failed.add(task_id)

    for layer in layers:
        jobs = []
        for task_id in layer:
            deps = nodes[task_id].get("depends_on") or []
            blocked = [dep for dep in deps if dep in failed or not results.get(dep, {}).get("ok", False)]
            if blocked:
                failed.add(task_id)
                remember(
                    task_id,
                    {
                        "task_id": task_id,
                        "ok": False,
                        "cached": False,
                        "error": "dependency failed",
                        "attempts": [
                            {
                                "attempt": 1,
                                "outcome": "skipped",
                                "reason": "dependency failed: " + ", ".join(blocked),
                                "transient": False,
                                "diagnostic": "fail-closed",
                            }
                        ],
                    },
                )
                continue
            if deadline is not None and time.monotonic() > deadline:
                cancel.set()
                failed.add(task_id)
                remember(
                    task_id,
                    {
                        "task_id": task_id,
                        "ok": False,
                        "cached": False,
                        "error": "budget exhausted",
                        "attempts": [
                            {
                                "attempt": 1,
                                "outcome": "timeout",
                                "reason": "run budget exhausted",
                                "transient": True,
                                "diagnostic": "fail-closed",
                            }
                        ],
                    },
                )
                continue
            if cancel.is_set():
                failed.add(task_id)
                remember(
                    task_id,
                    {
                        "task_id": task_id,
                        "ok": False,
                        "cached": False,
                        "error": "cancelled",
                        "attempts": [
                            {
                                "attempt": 1,
                                "outcome": "timeout",
                                "reason": "cancelled before start",
                                "transient": False,
                                "diagnostic": "cancelled before start",
                            }
                        ],
                    },
                )
                continue
            key = fingerprint(task_id)
            cached = _read_cache(cache_dir, key)
            if cached is not None and cached.get("ok"):
                cache_hits.append(task_id)
                remember(
                    task_id,
                    {
                        "task_id": task_id,
                        "ok": True,
                        "cached": True,
                        "value": cached.get("value"),
                        "attempts": [{"attempt": 0, "outcome": "cache_hit", "reason": key}],
                    },
                )
                continue
            runner = runners.get(task_id)
            if runner is None:
                remember(
                    task_id,
                    {
                        "task_id": task_id,
                        "ok": False,
                        "cached": False,
                        "error": "missing runner",
                        "attempts": [
                            {
                                "attempt": 1,
                                "outcome": "error",
                                "reason": f"no runner for {task_id}",
                                "transient": False,
                                "diagnostic": "missing runner",
                            }
                        ],
                    },
                )
                continue
            if not isolate:
                result = _run_thread_task(task_id, runner, evidence, key, task_timeout, max_attempts, backoff, cancel, deadline, cache_dir)
                remember(task_id, result)
                continue
            jobs.append(_Job(task_id, runner, evidence, key))
        if jobs:
            layer_results, layer_failed = _run_processes(jobs, concurrency, task_timeout, max_attempts, backoff, cancel, deadline, cache_dir, on_result)
            results.update(layer_results)
            failed.update(layer_failed)
    ordered = [results[task_id] for task_id in nodes if task_id in results]
    return {
        "ok": not failed and all(item.get("ok") for item in ordered),
        "tasks": ordered,
        "order": list(nodes),
        "layers": layers,
        "cache_hits": cache_hits,
        "cancelled": cancel.is_set(),
    }
