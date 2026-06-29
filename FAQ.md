# VeritasCore — FAQ & troubleshooting

## General

**Q: Why does a clearly dangerous line show as `unknown` instead of a finding?**
Because the engine could not *prove* untrusted input reaches it (e.g. the value
comes from a function parameter, a module global, or runtime state). `unknown` is
honest abstention — the gate does not block on it. This is by design: it is how
VeritasCore keeps false positives near zero. Use `--audit` to see `unknown` items for
manual review.

**Q: Why didn't it flag `os.system(config["key"])`?**
The content of `config["key"]` is only known at runtime. No static analyser can
prove it is tainted without guessing. VeritasCore answers `unknown` rather than guess.

**Q: It reported `unguarded` but I sanitised the input — false positive?**
Check whether your sanitiser is allowlisted for that sink *type*. A SQL escape
does not clear a shell sink; `shlex.quote` does not clear `eval`. If you wrap a
real guard in a helper (`def safe(x): return shlex.quote(x)`), the engine infers
it — but only when that helper unambiguously wraps the guard and is defined once.
If you believe it is a genuine false positive, it is worth reporting: Zero-FP is
the project's core promise.

**Q: How do I suppress a finding I've reviewed?**
Add `# veritas-core: skip <reason>` on the sink line. A reason is mandatory — a bare
`# veritas-core: skip` is itself reported, so suppressions stay reviewable. Skipped
findings are honored by both the gate and the audit report (counted under
`skipped`).

## Performance

**Q: Cross-file analysis is slow.**
Cross-file holds all files in memory and builds project-wide summaries, so it is
inherently heavier than single-file. It now runs in parallel across all cores —
pass `--jobs N` (or it uses `cpu_count()` in the dashboard). For very large repos,
prefer incremental mode (`--changed`/`--since`) which only analyses changed files.

**Q: How do I scan a huge repository quickly?**
Use `--fast` (all cores, parallelise sooner) for a full scan, or `--changed`
/`--since main` to scan only what changed (seconds on a PR). The content-hash
cache makes repeat scans near-instant.

**Q: Parallel scan seems no faster.**
Parallelism is gated behind a size threshold — on a small project, serial is
actually faster (no process-startup overhead). It engages automatically on larger
workloads. You can tune the thresholds in `.veritascore.json`.

## CI / team

**Q: How do I gate a pull request?**
`veritas_core.py . --since main` exits non-zero on a proven issue in changed code.
Wire it as a required check (see `.github/workflows/veritas.yml`).

**Q: `veritas <dir>` with no flags didn't scan anything.**
The bare command is the *gate*, which operates on git-staged changes. For a full
scan use `--audit`. In a non-git directory the gate just generates a policy.

**Q: Pre-commit hook?**
`cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`.
Bypass once with `git commit --no-verify`.

## Configuration

**Q: Where are the settings?**
Optional `.veritascore.json` at the project root tunes file-size caps, parallel
thresholds, default cross-file, extra ignore globs, and minimum confidence. Absent
file = sensible defaults. Bad values are ignored; these knobs can never weaken what
counts as a guard. See USAGE.md.

**Q: How do I ignore files?**
`.veritascoreignore` (gitignore-style globs) or the `ignore` key in `.veritascore.json`.
Defaults already skip `.git`, `node_modules`, `venv`, build dirs.

## Secrets

**Q: A real key in a test file shows as low confidence.**
Findings in test/fixture/example paths are demoted to `low` (and labelled), not
suppressed — a real key in a test is still a leak, but it is not treated as
high-confidence production exposure. Documented dummy values (e.g. AWS's
`AKIA…EXAMPLE`) and obviously synthetic tokens are never reported.

## Extending

**Q: How do I add a sink/source/sanitiser?**
Edit the tables in `veritas_core.py` and add a test (including a negative case). See
EXTENDING.md. There is no external rule file by design — an external "X sanitises
Y" claim would be unverifiable, and the allowlist is what lets the engine promise
it never reports `guarded` without proof.
