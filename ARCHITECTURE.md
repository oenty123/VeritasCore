# VeritasCore — architecture & how the engine works

This document explains the engine internals: the model, how taint flows, how
guards are recognised, and — just as importantly — what the engine deliberately
refuses to claim. It is written so a new contributor (or a future you) can reason
about any verdict the tool produces.

---

## 1. The guiding principle: Principle Zero

> Only report what is provably true. Where proof is absent, answer `unknown` —
> never guess.

Every design decision filters through this. A false `safe` (saying code is fine
when it is vulnerable — a "false-clear") is the worst possible error, worse than
a missed detection. A false `unguarded` (crying wolf) is the second-worst. So the
engine is built to make both kinds of lie structurally hard, accepting honest
`unknown` as the price.

This is the whole competitive thesis: a near-zero false-positive rate, earned by
abstaining instead of guessing.

---

## 2. The four-state model

Every dangerous call (a *sink*) is classified into exactly one of four states:

| State | Meaning | Reported? |
|-------|---------|-----------|
| `safe` | The argument is provably constant or a number — it cannot carry an injection. | No |
| `guarded` | An admissible sanitiser is provably applied to the argument. | No |
| `unguarded` | Untrusted input provably reaches the sink with no sanitiser. | **Yes** |
| `unknown` | The flow cannot be proven either way (runtime value, dynamic dispatch, deep interprocedural). | No (honest abstention) |

`unknown` is not a bug or a gap to be embarrassed about — it is the engine being
honest about the limits of static analysis. The gate blocks only on `unguarded`.

---

## 3. Sources, sinks, and guards

The engine knows three small, audited tables (in `veritas_core.py`):

**Sources** — where untrusted input enters: `input()`, `os.getenv`, `sys.argv`,
`request.args/form/values/cookies/headers`, `request.data/json`, environment and
argv subscripts, `getpass`. Three forms are tracked: calls (`SOURCES`), attributes
(`SOURCE_ATTRS`), and subscripts (`SOURCE_SUBSCRIPTS`).

**Sinks** — dangerous calls: `os.system`, `os.popen`, the `subprocess` family,
`eval`, `exec`, `sqlite3.execute`/`executescript`, `pickle.loads`, `yaml.load`
and friends, `marshal.loads`, the `requests`/`urllib`/`httpx` request calls,
template-string rendering (SSTI), and XML parsers (XXE).

**Guards** — sanitisers, declared **per sink type** in `SINK_GUARD_ALLOW`. This is
the heart of Principle Zero:

- Command sinks accept `shlex.quote`/`shlex.split`/`pipes.quote`.
- `eval`/`exec` accept only `ast.literal_eval`.
- `pickle.loads`, `yaml.load`, `requests.get`, … map to the **empty set**: no
  wrapper ever sanitises them, so they can only be `safe` (constant) or
  `unguarded`/`unknown`.

A guard is admissible only for the sink types it actually protects. A shell
sanitiser never clears an `eval`. This sink-typing is enforced everywhere a guard
could be inferred, including across files.

---

## 4. Taint propagation

The core question for each sink argument: *does untrusted input reach here, and is
it sanitised on the way?* `_expr_status(expr)` answers it, returning one of the
four states. It handles:

- **Direct sources** — `input()`, `request.args.get(...)`, etc.
- **Numeric coercion** — `int(x)`, `float(x)`, `len(x)`, `bool(x)`, `ord(x)`, … →
  `safe`. The result is a number; it cannot carry a shell/SQL/code payload
  (`int("rm -rf /")` raises rather than executes). This both closes coverage and
  removes false positives like `os.system(str(int(user_input)))`.
- **Transparent wrappers** — `str`, `repr`, `list`, `os.path.join`, … pass taint
  through unchanged (they don't sanitise).
- **String transforms** — `.split/.strip/.lower/.replace/.encode/.decode/…` derive
  a value from their receiver without reliably sanitising it, so taint flows
  through.
- **f-strings, `.format()`, `%`, concatenation** — taint of any interpolated part
  propagates. For SQL specifically, an f-string with any non-numeric interpolation
  is `unguarded` (the injection pattern; the fix is parameterisation).
- **Ternary (`a if c else b`) and boolean (`a or b`)** — the result combines all
  branches; if any branch is tainted, the result is tainted. A guard in one branch
  does **not** clear the whole value.
- **Containers** — list/set/dict literals, comprehensions, subscripts, dict views
  (`.values()/.keys()/.items()`), `dict.get/.pop/.setdefault` on a tainted dict,
  and **mutations** (`.append/.extend/.insert/.add/.update`) all propagate taint.
  A clean unconditional reassignment after a mutation clears it.
- **Bindings** — for-loop variables over a tainted iterable, walrus (`:=`), and
  tuple/list unpacking (`a, b = source`).

### Combining rule
When several values could reach a point, `_combine` takes the worst-known:
`unguarded` dominates, then `unknown`, then `guarded`, then `safe`. This is what
makes a guard-in-one-branch ternary correctly `unguarded`.

---

## 5. Flow sensitivity

Assignments are resolved by reaching-definition, not by lexical last-write:

- An **unconditional** reassignment replaces earlier taint (`x = input(); x = "ok"`
  → safe).
- A **conditional** assignment (guard only inside an `if` whose branch does not
  contain the sink) does **not** clear the other path — so conditional
  sanitisation is correctly `unguarded`.
- **Augmented assignment** (`x += input()`) augments rather than replaces, so
  appended taint is never lost.

`_control_span` determines whether an assignment sits inside a branch relative to
the sink.

---

## 6. Guards through functions (interprocedural, one hop)

Two symmetric, body-proven inferences let taint and sanitisation cross function
boundaries *soundly*:

**Return taint** — a function that returns a source propagates taint to callers;
one that returns a constant/number is `safe`.

**Guard-wrapper inference** — `def safe(x): return shlex.quote(x)` is recognised as
a guard wrapper *from its body*. It clears a sink only when the wrapped guard fits
that sink's type. This is proven, never guessed from usage statistics (usage
correlation would break Zero-FP: a `log(msg)` called only with tainted input does
not sanitise anything).

Both are deliberately **one hop** in-file. Multi-hop chains are left `unknown`
rather than risk losing context.

---

## 7. Cross-file analysis (opt-in)

With `--cross-file` (or `"cross_file": true`), the engine resolves calls through
imports and propagates, across files and one hop:

- **parameter taint** — a function called with a tainted argument from another file
  has its parameter treated as tainted;
- **return taint** — a function returning a source in one file taints its callers
  elsewhere;
- **guard wrappers** — a sanitiser defined in a shared module (`utils.security`)
  clears calls in files that import it.

Soundness rails: module resolution is by file basename; an ambiguous name (defined
in 2+ files) is **skipped** (stays `unknown`) rather than guessed; sink-typing
still applies. So cross-file can never fabricate a `guarded`.

It is opt-in because basename resolution doesn't cover every packaging trick;
validate on your codebase before gating on it.

---

## 8. What the engine deliberately cannot do

These are honest `unknown`s, not defects — and a correct tool must not pretend
otherwise:

- **Runtime values** — `os.system(config["key"])`: the value exists only at run
  time. Undecidable statically (Rice's theorem) for any tool.
- **Dynamic dispatch / reflection** — `getattr(obj, name)()`, `eval`-built names.
- **External state** — data from a database, network, or environment.
- **Deep interprocedural / whole-call-graph** chains — solvable in principle but
  engineering we keep one-hop to protect Zero-FP until validated.

A noisy tool guesses here and produces false positives; VeritasCore answers `unknown`.

---

## 9. Performance

- **Content-hash cache** (`.veritascore_cache.json`) — unchanged files are not
  re-analysed; warm re-runs are near-instant.
- **Parallel audit** — files are independent, so analysis runs across all cores.
  Gated by a workload-size threshold so small scans don't pay multiprocessing
  overhead. The cross-file path is parallel too: project-wide summaries are built
  once, then files are analysed in parallel with identical results to serial.
- **Per-scope memoisation** — parent maps, scope assignments, name binders,
  mutations, and function returns are cached per scope and cleared between files,
  removing redundant AST walks.
- **Incremental (team) mode** — `--changed`/`--since` analyse only files changed in
  git, so large repos are scanned in seconds on pull requests.

---

## 10. Module map

| File | Responsibility |
|------|----------------|
| `veritas_core.py` | The engine: sources/sinks/guards, taint, classification, audit, gate, autofix, cross-file, CLI. |
| `knowledge.py` | Cross-project contract learning with consensus weighting, quarantine, provenance, and anti-contracts. |
| `secrets_scan.py` | High-precision credential/secret scanner with dummy/synthetic filtering and test-path demotion. |
| `veritas_web.py` | The dashboard: audit a folder/GitHub repo/upload, explained findings, settings, team panel. |
| `benchmark.py` | Accuracy benchmark across CWE categories; asserts FP=0, FN=0. |
| `test_*.py` | The test suite — every fixed bug becomes a permanent test. |

---

## 11. How to trust a verdict

For any finding, you can trace it: the sink is in `SINKS`; the verdict came from
`_expr_status` on its argument; a `guarded` verdict means an allowlisted sanitiser
for that sink type was proven applied; an `unguarded` verdict means a source
reached it with none; `unknown` means the engine could not prove either way. No
verdict rests on heuristics or statistics — which is what lets the tool promise it
never reports `guarded` without proof.
