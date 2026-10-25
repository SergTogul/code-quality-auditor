"""Lightweight deterministic DAG planner and executor."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path


class TransientFailure(Exception):
    """A timeout or other failure that may be retried. Deterministic defects are not transient."""


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


def execute(selected, registry, runners, evidence, options=None):
    """Run independent tasks in parallel, reuse cached successful results, and retry transient failures.

    Deterministic exceptions are not retried. Exhausted retries and timeouts are
    terminal errors; callers must treat them as fail-closed.
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
    lock = threading.Lock()
    on_result = options.get("on_result")

    def run_one(task_id):
        attempts = []
        key = fingerprint(task_id)
        cached = _read_cache(cache_dir, key)
        if cached is not None and cached.get("ok"):
            with lock:
                cache_hits.append(task_id)
            return {
                "task_id": task_id,
                "ok": True,
                "cached": True,
                "value": cached.get("value"),
                "attempts": [{"attempt": 0, "outcome": "cache_hit", "reason": key}],
            }
        runner = runners.get(task_id)
        if runner is None:
            attempts.append(
                {
                    "attempt": 1,
                    "outcome": "error",
                    "reason": f"no runner for {task_id}",
                    "transient": False,
                    "diagnostic": "missing runner",
                }
            )
            return {"task_id": task_id, "ok": False, "cached": False, "error": "missing runner", "attempts": attempts}
        for attempt in range(1, max_attempts + 1):
            if cancel.is_set() and attempt == 1 and deadline is not None and time.monotonic() > deadline:
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "timeout",
                        "reason": "run budget exhausted",
                        "transient": True,
                        "diagnostic": "cancelled before start",
                    }
                )
                return {"task_id": task_id, "ok": False, "cached": False, "error": "budget exhausted", "attempts": attempts}
            started = time.monotonic()
            holder = {}

            def invoke(holder=holder, runner=runner, task_id=task_id):
                try:
                    holder["value"] = runner(task_id, evidence)
                except Exception as exc:  # noqa: BLE001 - classified below
                    holder["error"] = exc

            worker = threading.Thread(target=invoke, daemon=True)
            worker.start()
            worker.join(task_timeout)
            if worker.is_alive():
                cancel.set()
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "timeout",
                        "reason": f"exceeded {task_timeout}s",
                        "transient": True,
                        "diagnostic": f"elapsed>{task_timeout}",
                    }
                )
                if attempt == max_attempts:
                    return {"task_id": task_id, "ok": False, "cached": False, "error": "timeout", "attempts": attempts}
                time.sleep(backoff * attempt)
                continue
            if "error" in holder:
                exc = holder["error"]
                transient = isinstance(exc, (TransientFailure, TimeoutError))
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "error",
                        "reason": str(exc),
                        "transient": transient,
                        "diagnostic": exc.__class__.__name__,
                    }
                )
                if not transient or attempt == max_attempts:
                    return {"task_id": task_id, "ok": False, "cached": False, "error": str(exc), "attempts": attempts}
                time.sleep(backoff * attempt)
                continue
            attempts.append(
                {
                    "attempt": attempt,
                    "outcome": "success",
                    "reason": None,
                    "transient": False,
                    "diagnostic": f"elapsed={time.monotonic() - started:.3f}s",
                }
            )
            payload = {"ok": True, "value": holder.get("value")}
            _write_cache(cache_dir, key, payload)
            return {"task_id": task_id, "ok": True, "cached": False, "value": holder.get("value"), "attempts": attempts}
        return {"task_id": task_id, "ok": False, "cached": False, "error": "retries exhausted", "attempts": attempts}

    failed = set()
    for layer in layers:
        runnable = []
        for task_id in layer:
            deps = nodes[task_id].get("depends_on") or []
            blocked = [dep for dep in deps if dep in failed or not results.get(dep, {}).get("ok", False)]
            if blocked:
                failed.add(task_id)
                results[task_id] = {
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
                }
            elif deadline is not None and time.monotonic() > deadline:
                cancel.set()
                failed.add(task_id)
                results[task_id] = {
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
                }
            else:
                runnable.append(task_id)
        if not runnable:
            continue
        with ThreadPoolExecutor(max_workers=min(concurrency, len(runnable))) as pool:
            futures = {pool.submit(run_one, task_id): task_id for task_id in runnable}
            done, pending = wait(futures)
            for future in pending:
                cancel.set()
                task_id = futures[future]
                failed.add(task_id)
                results[task_id] = {
                    "task_id": task_id,
                    "ok": False,
                    "cached": False,
                    "error": "timeout",
                    "attempts": [
                        {
                            "attempt": 1,
                            "outcome": "timeout",
                            "reason": "layer wait expired",
                            "transient": True,
                            "diagnostic": "fail-closed",
                        }
                    ],
                }
            for future in done:
                task_id = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    result = {
                        "task_id": task_id,
                        "ok": False,
                        "cached": False,
                        "error": str(exc),
                        "attempts": [
                            {
                                "attempt": 1,
                                "outcome": "error",
                                "reason": str(exc),
                                "transient": False,
                                "diagnostic": exc.__class__.__name__,
                            }
                        ],
                    }
                with lock:
                    results[task_id] = result
                if on_result is not None:
                    on_result(task_id, result)
                if not result.get("ok"):
                    failed.add(task_id)
    ordered = [results[task_id] for task_id in nodes if task_id in results]
    return {
        "ok": not failed and all(item.get("ok") for item in ordered),
        "tasks": ordered,
        "order": list(nodes),
        "layers": layers,
        "cache_hits": cache_hits,
        "cancelled": cancel.is_set(),
    }
