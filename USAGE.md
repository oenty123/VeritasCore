# VeritasCore Security Pro — usage reference

Zero dependencies (Python 3.10+ standard library only). No `pip install` needed.

## CLI flags (`veritas_core.py`)

| Flag | Meaning |
|------|---------|
| *(none)* | Gate mode: scan the path, exit non-zero if a proven `unguarded` violation is found. Use in CI/pre-commit. |
| `--audit` | Repository audit: status counts per sink, worst files, high-risk advisories. Non-blocking. |
| `--json` | Emit machine-readable JSON instead of text (works with gate and `--audit`). |
| `--file <path>` | With `--json`, restrict output to one file's findings (used by the editor integration). |
| `--learn` | Advisory mode: report the contracts the engine derived from the code, without gating. |
| `--apply` | Autofix: insert the required guard (e.g. `shlex.quote`) and the matching import. Never edits line 1 before a shebang/`__future__`. |
| `--fast` | Speed mode for large repos / big files: uses all cores and parallelises sooner; skips the slower cross-file pass. |
| `--cross-file` | Enable import-aware cross-file taint (opt-in; see note below). |
| `--jobs N` | Analyse files across N processes (parallel audit). Combine with the content-hash cache for fast re-scans. |
| `--learn-into <db>` | After an audit, fold this project's contracts into a cross-project knowledge base. |
| `--knowledge <db>` | During an audit, surface ecosystem deviations (anti-contracts) using a knowledge base. |
| `--min-confidence <0..1>` | Only enforce contracts whose derived confidence is at least this value. |

Exit codes: `0` clean, `1` violations found, `2` usage error.

### Examples
```bash
python3 veritas_core.py ./src                       # gate (CI)
python3 veritas_core.py ./src --audit               # human audit
python3 veritas_core.py ./src --audit --json        # machine audit
python3 veritas_core.py ./src --apply               # autofix
python3 veritas_core.py ./src --audit --jobs 8      # parallel
python3 veritas_core.py ~/flask  --audit --learn-into ~/.veritascore/kb.json
python3 veritas_core.py ./src    --audit --knowledge ~/.veritascore/kb.json
python3 secrets_scan.py ./src                      # secret/credential scan
python3 veritas_web.py ./repos                        # web dashboard
```

## `# veritas-core: skip <reason>`
Put this comment on a sink line to bypass it. A reason is required; a bare
`# veritas-core: skip` is itself reported (so suppressions stay honest and reviewable).
```python
os.system(trusted_cmd)  # veritas-core: skip value is a hardcoded constant
```

## `.veritascoreignore`
One glob pattern per line (like `.gitignore`); matching files are skipped.
Defaults already skip `.git`, `node_modules`, `__pycache__`, `venv`, build dirs.
```
# .veritascoreignore
tests/fixtures/*
migrations/*
vendor/**
generated_*.py
```

## `.gate_policy.json` (optional)
Pin the contracts the gate enforces, instead of deriving them each run. Useful to
freeze a reviewed policy in CI. Shape:
```json
{
  "os.system":       {"guard": "shlex.quote",   "confidence": 1.0},
  "subprocess.run":  {"guard": "shlex.quote",   "confidence": 1.0},
  "sqlite3.execute": {"guard": "parameterized", "confidence": 1.0},
  "eval":            {"guard": "ast.literal_eval", "confidence": 1.0}
}
```
Only allowlist-admissible guards are accepted; a bogus guard is ignored.



## Team / CI incremental scan (coop mode)
Scan only the code that changed — fast on big repos, ideal for pull-request gates
and pre-commit. Requires a git repo.
```bash
veritas_core.py . --changed          # uncommitted + staged changes vs HEAD
veritas_core.py . --since main       # everything changed since the main branch
veritas_core.py . --changed --fast   # ...and use all cores
veritas_core.py . --changed --json   # machine-readable for CI
```
Exit code is 1 if a proven issue exists in changed code, else 0. A ready
pre-commit hook is in `hooks/pre-commit`:
```bash
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

## `.veritascore.json` (optional advanced settings)
Everything works without this file. Drop one at the project root only to tune
behaviour. All keys are optional; unknown keys and invalid values are ignored,
and a malformed file falls back to defaults. These settings tune performance,
scope and gate strictness only — they can never change what the engine accepts
as a guard, so they cannot weaken detection.
```json
{
  "max_file_bytes":     1500000,   // skip files larger than this (generated code)
  "parallel_min_files": 64,        // only parallelise above this many files
  "parallel_min_bytes": 1000000,   // ...or this much total source
  "min_confidence":     0.0,       // min contract confidence to enforce (0..1)
  "cross_file":         false,     // enable cross-file taint by default
  "ignore":             [],        // extra ignore globs (merged with .veritascoreignore)
  "secret_scan":        true       // include the secret scan in the dashboard
}
```
Explicit CLI flags always override the config file.

## Cross-file analysis note
`--cross-file` resolves calls through imports (`from mod import f`, `import mod`)
and propagates parameter and return taint one hop across files. It is **opt-in**:
module resolution is by file basename, which covers most projects but not complex
packages, relative-import chains, or `sys.path` tricks. On those it abstains
(stays `unknown`) rather than guessing — so enabling it never fabricates a
`guarded`, but should be validated on your codebase before relying on it in a gate.

## Extending coverage (without forking the engine)
The engine's safety rests on **sink-typed allowlists**, not external rule files.
To add a sanitiser or sink, edit these tables in `veritas_core.py`:
- `SINKS` — the set of dangerous calls to track.
- `SINK_GUARD_ALLOW` — per-sink set of admissible sanitisers (empty set = no
  wrapper is ever a guard, e.g. `pickle.loads`, `yaml.load`, `requests.get`).
- `SOURCES` / `SOURCE_ATTRS` / `SOURCE_SUBSCRIPTS` — where untrusted input enters.

This is deliberate: a guard can only become a contract if it is a real, named
sanitiser admitted by the allowlist — which is why the engine never reports
`guarded` without proof (Principle Zero).
