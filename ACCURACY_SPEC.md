# VeritasCore accuracy specification

## Principle Zero — only truth, no lies

Everything below descends from one rule:

> **The tool never asserts more than it can prove.** Every output carries a
> verifiable basis — a rule, a test, or provenance. Where proof is absent, the
> honest answer is `unknown`, never a guess wearing the mask of certainty.

This is not a slogan; it is enforced by construction:
- A finding is `guarded`/`unguarded`/`safe` only when a concrete rule fires;
  otherwise it is `unknown`. (Engine: the four-state classifier.)
- A learned contract may exist only if it passes the allowlist gate AND records
  which projects taught it. No provenance → no contract. (`knowledge.py`.)
- Confidence reflects evidence, never decoration. A fallback/default guard is
  labelled as such, not dressed up as 100%.
- What the maintainers cannot verify (live VS Code behaviour, real network clone)
  is marked unverified in the docs, not implied to work.

If a result cannot be explained from its basis, it must not be emitted. Truth
the tool cannot support is removed, not softened.

---

This is the contract the engine must satisfy. Every classification rule and test
traces back to a principle here. The goal is **trust**: a false "guarded" (saying
something is safe when it is not) and a false "unguarded" (crying wolf) are both
worse than an honest "unknown".

## Core principle

> A guard is a function that **provably reduces the attack surface of THIS sink**.
> Nothing else is a guard — not serialization, not type conversion, not path
> building, not an arbitrary project helper that merely wraps the argument.

When the engine cannot prove a value is sanitized for the specific sink, it must
say `unknown`, never `guarded`.

## The four states

- **guarded** — a recognized, sink-appropriate sanitizer is provably applied.
- **unguarded** — external/tainted input provably reaches the sink unsanitized.
- **safe** — the argument is a constant / literal with no external input.
- **unknown** — origin or safety cannot be proven (parameter, cross-call,
  branch, opaque object). Advisory only; never blocks.

## Sink-specific guard rules (allowlists, not denylists)

The number of *real* sanitizers per sink is small and finite; the number of
arbitrary wrapper functions is unbounded. Therefore each dangerous sink defines
an **allowlist** of guards. A call not on the list is never a guard.

| Sink | Real guard(s) | Notes |
|---|---|---|
| `os.system`, `subprocess.run/call/Popen/check_output/check_call` | `shlex.quote`, `shlex.split`, `shlex.join`, `pipes.quote` | see "argument list" rule below |
| `eval`, `exec` | `ast.literal_eval` | arbitrary parsing helpers are not guards |
| `sqlite3.execute` | parameterization (`?`, `:name`, `%s`, `$1`) **with** a params argument | a wrapping call (`delete()`, `generate_password_hash()`) is never a guard |
| `open` | `secure_filename`, `werkzeug.utils.secure_filename` | `os.path.join`/`realpath` do NOT stop traversal |
| `pickle.loads` | **none** | there is no wrapper that makes untrusted pickle safe; `pickle.dumps` is serialization, not a guard |
| `yaml.load` | (use `yaml.safe_load` instead — a different call, not a wrapper) | |

## Special structural rules

1. **subprocess argument lists are not shell-injectable.**
   `subprocess.run([cmd, arg1, arg2])` (a list/tuple, and `shell=True` absent or
   False) passes arguments directly to `execve` with no shell parsing, so command
   injection via the list elements is not possible. Such a call is **safe** with
   respect to shell injection, regardless of what builds the elements. Only a
   **string** command, or `shell=True`, is shell-injectable.
   → A function appearing inside the arg list (e.g. `_find_executable_or_die(...)`)
   must NOT be learned as a guard. The whole call is `safe`/`unknown`, not
   `guarded:<helper>`.

2. **Serialization/round-trip is not sanitization.**
   `pickle.loads(pickle.dumps(x))` is a test round-trip, not a guard. `pickle.dumps`
   is never a guard for `pickle.loads`.

3. **Type conversion and path building are transparent, not guards.**
   `str`, `int`, `bytes`, `os.path.join`, `Path`, … pass taint through; they
   neither sanitize nor are sources.

## False-positive / false-negative budget

- **Never** emit `guarded:<x>` unless `<x>` is on that sink's allowlist (or, for
  SQL, structural parameterization is present).
- Prefer `unknown` over `unguarded` when taint origin is unproven.
- A learned contract with confidence based on a non-allowlisted guard is a bug.

## Validation

Every rule above has at least one regression test reproducing a real-world false
contract found on a public repo (Flask, FastAPI template, FastAPI, TensorFlow):
`subprocess.run -> str/_find_executable_or_die`, `sqlite3.execute -> delete/
generate_password_hash`, `open -> os.path.join`, `pickle.loads -> pickle.dumps`.

## Return-value taint (coverage, accuracy-preserving)

A function whose return value is provably a **source** propagates `unguarded` to
its callers; one that returns a **constant** propagates `safe`. A function that
returns a **guard-wrapped** value does NOT propagate `guarded` — a guard valid in
the function's context may not fit the calling sink, so the call stays `unknown`.
Passthrough returns (returning a parameter) and ambiguous function names also stay
`unknown`. This raises coverage on real code (injections crossing a function
boundary) without introducing false "guarded".

## Cross-project learning safety

Learning across projects refines confidence WITHIN proven-safe guards; it can
never introduce an unsafe one. A guard is admissible to the knowledge base only
if it passes the same per-sink allowlist used by the engine. Promotion to an
ACTIVE (applied) contract additionally requires >= MIN_PROJECTS projects,
>= MIN_FREQ average in-project frequency, and >= MIN_CONSENSUS cross-project
agreement; otherwise it stays in quarantine (observed, not applied). Every
contract records its provenance and can be rolled back per project.
