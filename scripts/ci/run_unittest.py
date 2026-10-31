#!/usr/bin/env python3
"""Run unittest discovery and write a machine-readable result file.

Selection matches ``python -m unittest discover -s START -p PATTERN``. The JSON
file is written even when discovery or tests fail, and the exit status is zero
only when the run was successful.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import traceback
import unittest
from pathlib import Path

SCHEMA_VERSION = 1
EXIT_FAILED = 1
EXIT_DISCOVERY_ERROR = 2
EXIT_NO_TESTS = 5


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--start-directory", default="tests")
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--result-json", required=True, type=Path)
    parser.add_argument("--verbosity", default=2, type=int)
    return parser.parse_args(argv)


def _test_id(test):
    return test.id() if hasattr(test, "id") else str(test)


def _details(entries):
    return [{"id": _test_id(test), "traceback": text} for test, text in entries]


def _payload(args, result, elapsed, discovery_errors):
    tests_run = result.testsRun if result else 0
    skipped = list(result.skipped) if result else []
    return {
        "schema_version": SCHEMA_VERSION,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": sys.platform,
        "start_directory": args.start_directory,
        "pattern": args.pattern,
        "tests_run": tests_run,
        "failures": len(result.failures) if result else 0,
        "errors": len(result.errors) if result else 0,
        "skipped": len(skipped),
        "expected_failures": len(result.expectedFailures) if result else 0,
        "unexpected_successes": len(result.unexpectedSuccesses) if result else 0,
        "discovery_errors": discovery_errors,
        "failure_details": _details(result.failures) if result else [],
        "error_details": _details(result.errors) if result else [],
        "skipped_details": [{"id": _test_id(test), "reason": reason} for test, reason in skipped],
        "unexpected_success_ids": [_test_id(test) for test in result.unexpectedSuccesses] if result else [],
        "elapsed_seconds": round(elapsed, 3),
    }


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
    args = _parse_args(argv)
    started = time.perf_counter()
    loader = unittest.TestLoader()
    try:
        suite = loader.discover(args.start_directory, pattern=args.pattern)
    except Exception:  # discovery raises for a missing or unimportable start directory
        message = traceback.format_exc()
        sys.stdout.write(message)
        payload = _payload(args, None, time.perf_counter() - started, [message])
        payload["success"] = False
        _write(args.result_json, payload)
        return EXIT_DISCOVERY_ERROR

    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=args.verbosity)
    result = runner.run(suite)
    elapsed = time.perf_counter() - started
    payload = _payload(args, result, elapsed, list(loader.errors))
    # Mirrors `python -m unittest`, which exits 5 when nothing ran, so an empty
    # selection is never reported as a passing check.
    no_tests = result.testsRun == 0 and not result.skipped
    success = result.wasSuccessful() and not loader.errors and not no_tests
    payload["success"] = success
    _write(args.result_json, payload)
    sys.stdout.write(f"result JSON: {args.result_json}\n")
    if success:
        return 0
    if no_tests:
        sys.stdout.write("no tests were run\n")
        return EXIT_NO_TESTS
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
