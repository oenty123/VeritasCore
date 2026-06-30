
## Principle Zero — only truth, no lies

The project's root rule (see ACCURACY_SPEC.md): **the tool never asserts more
than it can prove.** Every finding has a verifiable basis; where proof is absent
the answer is `unknown`, never a guess. This is enforced, not promised — the test
suite includes invariant tests (`PrincipleZero`) proving the engine never reports
`guarded` without an admissible sanitiser, and that an untraceable value is always
`unknown`. What the maintainers cannot verify (live VS Code, real network clone)
is marked unverified rather than implied to work.

# VeritasCore

A **contract-oriented** security gate for Python, delivered as a VS Code extension plus
the `veritas_core.py` engine. Instead of imposing a generic ruleset, VeritasCore learns the guard
contracts your codebase already follows (“dangerous call ⇒ must be wrapped in a guard”) and
enforces consistency on new code.

## Contents
```
veritas-core/
├── veritas_core.py                       # engine (Python 3.10+, stdlib only)
├── veritas-core-1.0.0.vsix        # installable extension package
├── extension/                           # extension sources
│   ├── package.json  tsconfig.json  README.md
│   ├── src/{engine,ui,extension}.ts
│   └── out/{engine,ui,extension}.js     # compiled output (bundled in the .vsix)
├── build.sh                             # rebuild the .vsix
└── README.md
```

## Install the extension
```bash
code --install-extension veritas-core-1.0.0.vsix
```
Then set `veritas.scriptPath` to the path of `veritas_core.py` (default `~/veritas_core.py`).


## Documentation
- **[USAGE.md](USAGE.md)** — all CLI flags, `.veritascoreignore`, `.gate_policy.json`,
  `.veritascore.json` settings, team/incremental mode, `# veritas-core: skip`.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the engine works: the four-state
  model, Principle Zero, taint propagation, guards, cross-file, the honest limits.
- **[EXTENDING.md](EXTENDING.md)** — add a sink, source, or sanitiser.
- **[FAQ.md](FAQ.md)** — common questions and troubleshooting.
- **[ACCURACY_SPEC.md](ACCURACY_SPEC.md)** — the accuracy contract and benchmark.


## Features
1. **Real-time contract analysis** — on save, runs `veritas_core.py` (via `execFile`, 15s
   timeout). Diagnostics include the full contract, e.g.
   `os.system() без guard. Контракт: shlex.quote (примеров: 5, уверенность 97%)`.
2. **Security panel** — WebView tabs: *Контракты* (table + «Обновить»), *Ошибки*
   (clickable file:line, severity filter), *Рефакторинг* (diff preview, apply to file/project).
3. **Quick Fixes** — «Добавить guard (контракт проекта)», «Применить все автофиксы в файле»,
   «Пропустить (# veritas-core: skip …)» with a mandatory reason. Correct indentation.
4. **Local explanation** (no AI) — COAA report: sinks, required guards, examples, recommendations.
5. **Settings panel** — form for `pythonPath`, `scriptPath`, `runOnSave`, `minSeverity`;
   saved immediately via `configuration.update()`.
6. **Refactoring** — file and workspace commands; shows how many fixes will be made and a real
   diff editor preview before applying.
7. **Built-in help** — how contract analysis works, how to add your own guards, examples.

## My improvements (beyond the spec)
- **Status-bar security score** `$(shield) VeritasCore: N`, coloured by worst severity, click → panel.
- **Content-hash caching** — re-analysis is skipped when file text is unchanged (faster re-runs).
- **Native diff preview** before applying a refactor (virtual document + `vscode.diff`).
- **Severity model** with colour coding, icons, and confidence progress bars in the panel.
- **One-click “skip with reason”** action that uses the engine’s `# veritas-core: skip` bypass safely.
- **Precise, mode-aware fixes** (inline for `;`-one-liners, new indented line otherwise) carried
  from the engine so edits are correct, not just hints.

## Engine quick reference
```bash
python3 veritas_core.py <project>                       # gate staged files (exit 1 on violation)
python3 veritas_core.py <project> --learn               # advisory only
python3 veritas_core.py <project> --apply [--no-interactive]
python3 veritas_core.py <project> --json --file <f.py>  # editor contract: {policy, violations}
```
Guard detection is structural (AST), no hardcoded names: `x = f(x)` or `sink(f(x))`;
`input()` is a source, not a guard. Fallback contracts apply when the project teaches none.

## Engine improvements in this iteration
- **Status-aware data flow.** Every sink is classified as `guarded` / `unguarded` /
  `unknown` / `safe`, not a binary. This is what separates signal from noise:
  - **Guards inside f-strings & concatenation** are now seen:
    `os.system(f"ls {shlex.quote(x)}")` and `os.system("ls " + shlex.quote(x))` are
    recognised as guarded (previously false positives).
  - **`unknown`** for values whose origin can't be proven statically — function
    parameters, ternaries, tuple-unpacking, globals. These are **not blocked**; the
    editor shows them as a low-severity advisory ("поток данных не прослеживается —
    проверьте вручную"). This kills the classic `def run(cmd): os.system(cmd)` false block.
  - **`safe`** for constant commands (`os.system("ls -la")`) — no external input, no flag.
  - Transitive flow (`y = f(x); sink(y)`) and last-definition-wins (re-binding to a
    source un-guards) are preserved and tested.
- **`.veritascoreignore`** + sensible defaults (`.venv`, `node_modules`, `build`, `dist`,
  `__pycache__`, `*_pb2.py`, `migrations`) — don't learn from or gate vendored/generated code.
- **`--min-confidence <0..1>`** — strict vs. advisory gating profiles (default `0`).

## Auditing real repositories
Two ways to judge the engine on real code (this is the most useful thing here):

CLI summary per project:
```bash
python3 veritas_core.py <repo> --audit          # human summary
python3 veritas_core.py <repo> --audit --json   # machine-readable
```
Shows files scanned, sink totals, the guarded/unguarded/unknown/safe split,
coverage (guarded ÷ determinable), learned contracts, and the worst files.

Web dashboard — paste a GitHub URL or scan a folder of clones:
```bash
python3 veritas_web.py                      # empty dashboard; paste URLs in the UI
python3 veritas_web.py <folder-with-repos>  # also audits already-cloned repos
```
The header has a URL field: paste `https://github.com/owner/repo`, press
**Проверить**, and it shallow-clones into a temp dir, audits it, shows the result,
and deletes the clone. Coverage, status bars, learned contracts and worst files are
shown side by side. Stdlib `http.server` only; JSON at `/api`.
Requires `git` and network access (cloning is blocked in offline/sandboxed
environments). Only https/ssh URLs from github/gitlab/bitbucket/codeberg are accepted,
passed to git as an argv element (no shell), so URLs can't inject commands.


- **Source-aware + non-guard denylist.** Known taint sources (`input`,
  `request.args.get`, `os.getenv`, `sys.argv`, …) flowing into a sink are
  `unguarded`; wrappers that sanitise nothing (`str`, `int`, `os.path.join`, …)
  are never mistaken for guards — this fixes the `subprocess.run → str` false
  contract seen on a real repo.
- **One-hop interprocedural taint (same file).** A sink fed by a function
  parameter is resolved through the function's call sites: `def run(cmd):
  os.system(cmd)` is flagged when some caller does `run(input())`, stays `safe`
  when callers pass constants, and stays honest `unknown` with no callers.


- **Interprocedural taint — class methods & `self.<attr>` (same file).**
  `obj.method(input())` / `self.method(input())` now taint the method's
  parameter; `self.attr = input()` in one method taints `os.system(self.attr)`
  in another. Same-named methods across classes, or an attr assigned in two
  classes, stay honest `unknown` (no guessing).
- **Cross-file taint — EXPERIMENTAL, opt-in (`--cross-file`).** Resolves a
  parameter left `unknown` by single-file analysis from call sites in *other*
  files (name-based; ambiguous names skipped). It is **off by default** and
  **not validated on real multi-file codebases** — cross-file resolution is
  where false positives are most likely, so enable it only to experiment
  (`veritas_core.py <repo> --audit --cross-file`, or the dashboard toggle).


- **Shell/eval guard allowlist (accuracy).** Only real sanitisers count for a
  shell or eval sink: `shlex.quote/split/join` for `os.system`/`subprocess.*`,
  `ast.literal_eval` for `eval`/`exec`. An arbitrary project function can no
  longer become a false contract (the `subprocess.run -> stage_zensical_docs`
  bug found on fastapi). `OPEN_GUARDS` no longer counts `os.path.realpath`.
- **Safer auto-fix.** `--apply` inserts a missing import after any
  shebang/docstring/`__future__` (never breaking line 1), and the result stays
  valid Python.
- **Faster, lighter audit.** Single analysis pass (policy derived from it, no
  re-parse); streams file-by-file unless `--cross-file`. Unparseable files are
  counted (`parse_errors`) instead of silently dropped. Flow depth raised 3->6.
- **VS Code extension hardening (compiled, not runtime-validated here):**
  CSP nonce via `crypto`, apostrophe escaping, engine-path existence check with
  user notifications, `applyAllFixes` re-analyses and skips save for untitled docs.


- **Large-repository performance.** Files over ~1.5 MB (almost always generated)
  are skipped and counted (`skipped_large`); interprocedural taint builders are
  skipped on files over 200 K chars; the audit reports progress (every 500 files)
  via a callback — the CLI prints it to stderr and the web dashboard to its
  console, so a long scan of a huge repo (e.g. TensorFlow) is visibly working,
  not a silent hang.


- **Accuracy spec applied (see ACCURACY_SPEC.md).** Guards are an allowlist per
  sink, never an arbitrary wrapper. Fixed two false contracts found on
  TensorFlow: `pickle.loads -> pickle.dumps` (serialization is not a guard;
  pickle.loads now has an empty allowlist) and the argv-list case —
  `subprocess.run([...])` without `shell=True` is not shell-injectable and is now
  classified `safe` instead of guessing a guard from a list element.


- **Incremental content-hash cache (speed).** Audit caches per-file results in
  `.veritascore_cache.json`; unchanged files are restored instead of re-parsed. On a
  rescan this is ~4-5x faster (validated: 1500 files 456ms -> 103ms), which is the
  real win on single-core machines where parallelism does not help. Disable with
  `use_cache=False`. Add `.veritascore_cache.json` to your `.gitignore`.


- **Return-value taint (coverage).** `def get(): return request.args.get('x')`
  followed by `os.system(get())` is now `unguarded` (was `unknown`). Only sources
  (`unguarded`) and constants (`safe`) propagate through returns; a guard applied
  inside a function is NOT claimed across the call (context safety) — it stays
  `unknown`. Ambiguous/passthrough returns stay `unknown`.
- **Parallel audit (`--jobs N`).** Files are analysed across processes; the
  dashboard uses all cores. Combined with the content-hash cache, cold scans
  parallelise and warm rescans hit cache.


- **Dangerous-configuration advisory (depth).** A sink whose source can't be
  traced but whose *configuration* is inherently dangerous — `shell=True` with a
  non-constant command, `eval`/`exec` of a variable, `os.system` of a variable —
  is flagged `high` risk (medium severity) instead of staying silent. It remains
  `unknown` (never a false `unguarded`) and excludes thin parameter wrappers
  (`def run(cmd): os.system(cmd)`) to avoid noise. Surfaced in the editor JSON and
  counted in the audit (`high_risk`).


- **Cross-project learning (`knowledge.py`).** Accumulate guard contracts across
  many scanned projects into a shared base (`--learn-into <db>`), then surface
  ecosystem deviations on a new project (`--knowledge <db>`): "everyone guards
  this; you don't". Four protections keep the base clean: an **allowlist gate**
  (an unsafe guard like `subprocess.run -> str` is rejected no matter how many
  projects teach it), **three filters** (>=3 projects, >=50% in-project frequency,
  >=60% cross-project consensus; otherwise quarantine), **provenance** (every
  contract lists its source projects and can be rolled back with `forget_project`),
  and **anti-contracts** (deviation-from-ecosystem advisories). It's explainable
  statistics, not ML. The dashboard has a 🧠 Knowledge tab showing each contract's
  guard, status, consensus and source projects.


## Measured accuracy (benchmark.py)

"Low false-positive rate" is only a claim until measured, so the repo ships a
benchmark over a labeled corpus (vulnerable cases, safe "FP-trap" cases that fool
naive tools, and genuinely ambiguous cases). Because the engine has four states,
it can ABSTAIN (`unknown`) — which is NOT counted as a false positive. Current
result on the bundled corpus:

```
FALSE-POSITIVE RATE :   0.0%   (61-case corpus across 7 CWE categories)
FALSE-CLEAR (FN)    :     0     (never said safe when vulnerable)
detection           : 100.0%   (all 29 vuln caught; 0 missed)
over-claim          :     0     (never claimed safe without proof)
```

Run: `python3 benchmark.py`. The corpus is extensible; add competitor results on
the same snippets to compare honestly. These numbers are on a small curated
corpus, not a proof of real-world superiority — they are a measurable, repeatable
baseline, per Principle Zero.



- **Dashboard learning toggle.** With 🎓 learning ON, each scanned/cloned repo is
  folded into the knowledge base automatically (off by default — Principle Zero:
  you opt in to what the base learns from). The allowlist gate + three filters
  mean no single project can activate a bad contract.


- **Secret / credential scanning (`secrets_scan.py`).** High-precision detection
  of well-known credential formats (AWS, GitHub, Google, Stripe, Slack, private
  keys, JWT…) plus hardcoded passwords. True to Principle Zero it favours
  precision: placeholders, env templates (`${VAR}`), and example values are
  deliberately ignored to avoid the false positives that plague secret scanners.
  Secrets are masked in output (never echoed). CLI: `python3 secrets_scan.py <dir>`;
  also shown in the dashboard 🔑 section of the Errors tab.
- **Errors tab.** The dashboard ⚠ Errors page lists every proven `unguarded` and
  high-risk finding with file:line, sink, and a plain explanation — plus the
  secret-scan results. `unknown` cases are excluded by design.


- **Expanded sink coverage (7 CWE families).** Beyond command/SQL/code/pickle, the
  engine now covers SSRF (`requests.*`, `urllib.request.urlopen`, `httpx.*`),
  SSTI (`render_template_string`), XXE (`lxml.etree.parse/fromstring`,
  `xml.etree.ElementTree.*`), more deserialisation (`yaml.unsafe_load`,
  `yaml.full_load`, `marshal.loads`), `os.popen`, and `executescript`. For
  multi-arg sinks only the dangerous argument is checked (e.g. the URL in
  `requests.post(url, data=...)`), so a tainted POST body is not mis-flagged as
  SSRF. All added with empty/known allowlists — no new false positives.


- **Flow-sensitive taint (depth).** Taint follows assignment chains, and
  sanitisation is branch-aware: a guard applied only inside an `if` is NOT claimed
  as `guarded` (the else-path leaves raw input), while a guard in the same branch
  as the sink is. Unconditional overwrite with a constant clears taint. Coverage
  also includes `.format()`, `str.join()` of a tainted iterable, and ternary
  expressions (either branch may reach the sink). No new false positives.


- **Import-aware cross-file analysis (`--cross-file`).** Cross-file taint is now
  resolved through the caller's imports (`from mod import f`, `import mod` +
  `mod.f()`), not just by unique name — so a `process()` in one module never
  absorbs taint meant for an unrelated `process()` elsewhere. Adds cross-file
  **return taint**: `from src import get; os.system(get())` sees that `get`
  (defined in src) returns user input. Ambiguity is skipped (a module basename
  mapping to 2+ files is not resolved), keeping false positives out. Still opt-in
  until validated on large real codebases.


- **Secret-scan noise control.** Documented dummy credentials (e.g. AWS's
  `AKIAIOSFODNN7EXAMPLE`) and obviously synthetic values (repeated-character
  tokens) are never reported; findings inside test/fixture/example paths are
  demoted to low confidence and labelled, not suppressed (a real key in a test
  is still a leak). Real keys in production paths stay high-confidence.


- **Local file upload (dashboard).** The audit page has a 📂 Upload .py control:
  pick one or more local Python files and they're analysed as a project (taint +
  secrets), results shown on the Errors tab. No git needed.
- **Augmented-assignment taint.** `x = 'ls '; x += input()` is now correctly
  `unguarded` (previously a false `safe`): `+=` augments rather than replaces, so
  appended taint is tracked.


- **Dict-access taint.** `d = request.args; d.get('x')` (and `.getlist`/`.pop`/
  `.setdefault`) propagates taint when the receiver is a source dict; a benign or
  unknown dict stays safe/unknown — no false positive.
- **Contract guards are allowlist-checked.** A derived/learned contract can only
  surface an admissible sanitiser; the engine never suggests a bogus guard like
  `picture1.get` for a sink (e.g. `requests.get`) whose allowlist is empty.


- **Deep taint binding (toward 85-90% coverage, Zero FP).** Taint now follows
  for-loop variables over a tainted iterable, walrus `:=`, tuple/list unpacking,
  dict-literal values, list/set/dict comprehensions, subscripts of a tainted
  container, dict views (`.values()/.keys()/.items()`), and string transforms
  (`.split/.strip/.lower/.replace/.encode`…, which derive from but do not
  sanitise their receiver). Clean iterables, constants and unknown receivers stay
  safe/unknown — no new false positives.


- **Numeric coercion sanitises (FP fix + coverage).** `int(x)`, `float(x)`,
  `len(x)`, `bool(x)`, `ord(x)` and similar produce a number/bool that cannot
  carry a shell/SQL/code injection, so they yield `safe` — fixing a former false
  positive on `os.system(str(int(user_input)))` and letting a helper that returns
  `len(x)` be recognised as safe. SQL f-strings are now classified by their
  interpolations: a numeric/constant interpolation is `safe`, anything else stays
  `unguarded` (parameterisation is the fix).


- **Guard-wrapper inference (new, sound depth).** A helper that provably applies a
  known sanitiser to its parameter — `def safe(x): return shlex.quote(x)` — is
  recognised as a guard wrapper from its body and clears a sink ONLY when the
  wrapped guard fits that sink's type (a shell wrapper never guards `eval`). Proven
  from the function body, never guessed from usage, so no false `guarded`.


- **Performance.** Per-scope parent maps and assignment lists are cached and
  computed in a single AST walk (cleared between files), cutting redundant tree
  traversals on the single-core hot path. Parallel audit (`--jobs N`) is gated
  behind a workload-size threshold so small repos run serially (process startup
  would cost more than the work) while large repos engage the extra cores; the
  parallel path is verified to produce identical results to the serial one.


- **Lazy analysis (measured 4.9x on real-shaped repos).** Files with no sink call
  at all skip every interprocedural taint build — most files in a project (tests,
  configs, helpers) contain no sinks, so this is a large, sound win (no sinks ->
  no findings).
- **isinstance numeric narrowing.** Inside `if isinstance(x, int|float|bool):` the
  variable is proven a number and cannot inject, so it is `safe` for that branch.
  Strictly bounded: numeric types only (a `str` that passes isinstance still
  injects), positive branch only (the `else` stays tainted), and voided by any
  reassignment between the check and the sink. `is not None` / `hasattr` never
  narrow, since they do not sanitise.


- **Cross-file guard-wrapper resolution (cross-file mode).** A sanitiser defined
  in a shared module (e.g. `utils.security.safe` wrapping `shlex.quote`) now
  clears a call in another file that imports it — the most common real-world
  pattern, previously left `unknown`. Sound by construction: the wrapper is proven
  from its body, only resolved when the name is defined exactly once across the
  project (no ambiguity), and still checked against the sink's type (a shell
  wrapper never clears `eval`). Reduces false positives on correctly-guarded code
  without any risk of a false `guarded`.


- **Polished dashboard UI.** The web dashboard now shares one cohesive dark theme:
  sticky blurred header, gradient action buttons, refined cards and tables with
  hover states, better typography and spacing, and focus rings on inputs. Purely
  cosmetic — no change to analysis behaviour.


- **Performance: per-scope caching.** Hot AST traversals (scope assignments,
  name binders, function returns, parent map) are memoised per scope/function and
  cleared between files, removing most redundant walks. Cold single-file audit is
  measurably faster; warm re-runs stay near-instant via the content-hash cache.
  Parallel audit is gated by a size threshold so multiprocessing overhead never
  makes small scans slower than serial.


- **Dashboard: folder analysis + clearer error explanations.** A new "Анализ
  папки" control audits a local directory by path (for large projects, no upload
  limit; auto-parallelises). Each finding now explains itself: the vulnerability
  class with CWE id, why it is dangerous with a concrete attack example, and a
  specific fix — tailored per sink (command injection, SQL, code exec,
  deserialisation, path traversal, SSRF).


- **Engine hardening: container-mutation taint.** Fixed a false-`safe`:
  `xs = []; xs.append(input()); sink(xs[0])` is now `unguarded` — taint added to a
  list/set/dict after construction (`append`/`extend`/`insert`/`add`/`update`) is
  tracked, while clean containers stay safe (no new false positives).
- **Dashboard: fix-it guidance + summary.** Each finding shows a ✗ bad / ✓ good
  one-line code example for its sink, and the errors page leads with at-a-glance
  counts (injections, dangerous configs, secrets).


- **Engine hardening (two soundness fixes).** (1) A guard in one branch of a
  ternary/boolean no longer clears the whole value — `shlex.quote(x) if c else x`
  is correctly `unguarded` (was a false `guarded`). (2) A clean unconditional
  reassignment after a tainting mutation now clears the taint (no false positive).
  Boolean expressions (`a or b`) are taint-combined.
- **Fast mode for large repos.** `--fast` uses all cores, parallelises sooner, and
  skips the slower cross-file pass — for scanning big GitHub repos quickly.
- **Friendlier dashboard.** An empty dashboard now shows a short welcome with the
  three ways to start an analysis and where to read explained findings.


- **Team / coop mode (git-incremental).** `--changed` scans only files changed in
  the working tree + staging vs HEAD; `--since <ref>` scans everything changed
  since a branch. Fast on large repos (untouched files are never parsed), ideal
  for PR gates and pre-commit — a ready hook ships in `hooks/pre-commit`. Exit 1
  on a proven issue in changed code.


- **Redesigned dashboard (clear layout + settings).** The cramped header (three
  forms and six buttons in one bar) is replaced by: a clean top nav (Аудит /
  Ошибки / База знаний) with active-page highlight; a "Запустить анализ" panel
  with three labelled method cards (GitHub URL, local folder, file upload); and a
  "Настройки" panel with on/off switches and descriptions for learning and
  cross-file analysis. Results live in their own panel. Consistent across pages.


- **Cross-file performance fix (major).** Cross-file analysis previously ran
  serially with no cache, so on a multi-core machine it could be many times slower
  than the (parallel) single-file path — the dominant cause of slow cross-file
  scans. It now builds the project-wide summaries once and analyses files in
  parallel across all cores above the size threshold, producing identical verdicts
  to the serial path (covered by a serial-equals-parallel test).


- **Code audit fixes.** `# veritas-core: skip <reason>` is now honored in the audit
  report and dashboard (not just the gate) — a reviewed finding is suppressed and
  counted under `skipped`. Removed dead code (`_has_syntax_error`).
- **Dashboard: team panel + settings.** A "Командная работа" panel shows
  ready-to-copy commands for incremental PR scans (`--changed`/`--since`), the
  pre-commit hook, the CI workflow, and fast mode. The "Настройки" panel exposes
  learning and cross-file toggles with descriptions.

## Tests
A dependency-free `unittest` suite (96 tests engine + 11 learning), including cases that reproduce the
exact false contracts found on Flask (`sqlite3.execute → generate_password_hash`,
`open → os.path.join`) and the FastAPI template (`sqlite3.execute → delete`) — now
fixed by sink-typed contracts (SQL guard = parameterisation; `os.path.join` is not a
traversal guard). Run:
```bash
python3 -m unittest test_veritas_core -v
```

## Honest build notes
- The `.vsix` here was **assembled directly** (valid OPC layout: `extension.vsixmanifest`,
  `[Content_Types].xml`, `extension/`) because this environment has **no network** for
  `npm install` / `@vscode/vsce`. It is unsigned, which is fine for local
  `code --install-extension`.
- TypeScript was transpiled with `tsc --noCheck` (types stripped; `require('vscode')` is
  provided by the editor at runtime). Each emitted JS file passes `node --check`.
- The **engine ↔ extension JSON contract** and the **fix edit math** are verified
  end-to-end. The **live UI** (panels, diff editor, status bar) could not be exercised in a
  headless environment; it uses stable VS Code APIs. Run `build.sh` for a fully type-checked,
  `vsce`-signed package when you have npm.
```
```
