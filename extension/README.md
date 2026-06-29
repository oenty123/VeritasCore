# VeritasCore Security Pro

Contract-oriented security gate for Python, in your editor. On save it runs
`veritas_core.py`, learns the guard contracts your codebase already follows, and flags
new code that breaks them — with project-aware Quick Fixes and refactoring.

## Features
- **Real-time contract analysis** on save (diagnostics carry the full contract:
  `os.system() без guard. Контракт: shlex.quote (примеров: 5, уверенность 97%)`).
- **Security panel** (WebView) with tabs: *Контракты* (Sink → Guard → Примеров → Уверенность,
  «Обновить»), *Ошибки* (clickable file:line, severity filter), *Рефакторинг* (diff preview,
  «Применить к файлу» / «Применить к проекту»).
- **Quick Fixes**: «Добавить guard (контракт проекта)», «Применить все автофиксы в файле»,
  and «Пропустить (# veritas-core: skip …)» with a mandatory reason. Correct indentation.
- **Local explanation** (no AI): sinks found, required guards, examples from the codebase,
  general recommendations.
- **Settings panel** (WebView form) — changes saved immediately via `configuration.update()`.
- **Refactoring** for file and workspace, with a stats confirmation and a real diff editor
  preview before applying.
- **Built-in help** panel.

## Extra touches
- **Status bar security score** (`$(shield) VeritasCore: N`) coloured by worst severity; click to open the panel.
- **Content-hash caching** — re-analysis is skipped when the file text is unchanged.
- **Diff preview before apply** via a virtual document + native diff editor.
- **Severity model** (critical/high/medium/low) with colour coding, icons and confidence bars.

## Settings
`veritas.pythonPath` (default `python3`), `veritas.scriptPath` (default `~/veritas_core.py`),
`veritas.runOnSave` (default `true`), `veritas.minSeverity` (`critical|high|medium|low`).

Point `veritas.scriptPath` at the bundled `veritas_core.py`.

## Engine contract
`veritas_core.py <project> --json --file <f.py>` prints:
```json
{ "policy": { "os.system": {"guard":"shlex.quote","examples":["safe.py:1"],"confidence":0.97,"count":5} },
  "violations": [ {"file":"...","line":3,"sink":"os.system","guard":"shlex.quote",
                   "message":"...","fix":"cmd = shlex.quote(cmd)","severity":"high","insert":{...}} ] }
```
The engine writes no temp files in `--json` mode; the extension runs it via `execFile` with a
15s timeout.
