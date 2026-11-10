# Security model and known limitations

**Read-only by default.** An audit inspects source without installing tools, modifying the audited repository, or executing repository-controlled code.

## Approval boundaries

- External analyzers require explicit approval and `--allow-tools`. They must already be installed outside the audited repository; the registry does not authorize downloads.
- Running repository tests, build scripts, mutation tests, or other repository-controlled executables requires explicit approval, `--allow-repo-execution`, and `--sandbox-confirmed`.
- Approved host analyzers still need containment because they process repository-controlled input. Repository binaries, plugins, or analyzer configs are not trusted host analyzers.
- Installation approval (`--approve`) and initialization approval (`--approve-write`) **do not** authorize execution.
- If containment is unavailable, approved external execution is reported unavailable; the engine continues available built-in static checks instead of falling back to unsandboxed execution.

## Platform behavior

The only currently supported containment mechanism is the root-owned `/usr/bin/sandbox-exec` on macOS, invoked by a fixed path. The policy is deny-by-default with scoped file reads, constrained scratch writes, and denied network. The preflight probe verifies blocking of sibling file reads/writes and loopback network access.

On **Linux and Windows**, containment is unavailable in the current implementation. It does **not** silently run approved tools or repository code without isolation.

Custom wrappers, including `CQA_SANDBOX_CMD`, cannot authorize containment. A sandbox launch failure is not retried outside the sandbox.

## Security limitations (important)

- The macOS Seatbelt policy still has unfiltered compatibility allowances for `sysctl-read`, `mach-lookup`, and `ipc-posix*`. They are **not** least privilege. `mach-lookup` can reach system services outside simple file/network restrictions.
- Native macOS enforcement has **not yet been independently verified**. Existing unit tests mock parts of sandbox trust and inspect policy text or dispatch behavior; they cannot prove kernel enforcement. Track [issue #10](https://github.com/SergTogul/code-quality-auditor/issues/10).
- Terminating a timed-out or excessive-output process is best-effort cleanup, not a containment guarantee. Descendants can escape process-group cleanup by `setsid` or reparenting, particularly on macOS.
- Some metric measurements require approved third-party analyzers or executable test suites. When unavailable or unauthorized, missing blocking evidence results in `INCOMPLETE`, never `PASS`.
- GitHub Actions Linux checks are useful for Python behavior but are not macOS `sandbox-exec` integration tests.

## Reporting and provenance

A confirmed blocking breach includes repository revision, location, source check/metric, observation, analysis tool, profile/configuration hash, and evidence reference. Reports are written outside the audited repository by default. Unmeasured values are not synthesized, and suggestions are not represented as applied changes.

For security and native integration work, check [issue #10](https://github.com/SergTogul/code-quality-auditor/issues/10).
