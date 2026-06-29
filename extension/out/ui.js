"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityHtml = securityHtml;
exports.settingsHtml = settingsHtml;
exports.helpHtml = helpHtml;
const SEV_COLOR = {
    critical: "#ff4d4f", high: "#ff7a45", medium: "#faad14", low: "#52c41a",
};
const SEV_ICON = {
    critical: "⛔", high: "🔴", medium: "🟠", low: "🟢",
};
function nonce() {
    // cryptographically strong, unpredictable nonce (CSP bypass-resistant)
    const bytes = require("crypto").randomBytes(18);
    return bytes.toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
}
function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function shell(title, body, script) {
    const n = nonce();
    return `<!DOCTYPE html><html lang="ru"><head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${n}';">
<style>
  :root { color-scheme: light dark; }
  body { font-family: var(--vscode-font-family, sans-serif); color: var(--vscode-foreground);
         padding: 0 14px 24px; font-size: 13px; }
  h1 { font-size: 16px; } h2 { font-size: 13px; margin: 18px 0 6px; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid #8884; margin: 8px 0 14px; position: sticky; top: 0;
          background: var(--vscode-editor-background); }
  .tab { padding: 8px 14px; cursor: pointer; border-bottom: 2px solid transparent; }
  .tab.active { border-bottom-color: var(--vscode-focusBorder, #4ea1ff); font-weight: 600; }
  .panel { display: none; } .panel.active { display: block; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #8883; vertical-align: middle; }
  th { font-weight: 600; opacity: .8; }
  code { background: #8882; padding: 1px 5px; border-radius: 4px; }
  button { background: var(--vscode-button-background, #0a6); color: var(--vscode-button-foreground, #fff);
           border: none; border-radius: 6px; padding: 6px 12px; cursor: pointer; margin: 4px 6px 4px 0; }
  button.secondary { background: var(--vscode-button-secondaryBackground, #555); }
  .bar { height: 8px; width: 90px; background: #8883; border-radius: 4px; overflow: hidden; display: inline-block; }
  .bar > i { display: block; height: 100%; }
  .link { color: var(--vscode-textLink-foreground, #4ea1ff); cursor: pointer; text-decoration: underline; }
  .pill { padding: 1px 8px; border-radius: 10px; color: #111; font-weight: 600; font-size: 11px; }
  .muted { opacity: .65; } .empty { padding: 20px; text-align: center; opacity: .6; }
  pre.diff { background: #8881; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
  pre.diff .add { color: #52c41a; } pre.diff .del { color: #ff7a45; }
  label { display: block; margin: 10px 0 4px; font-weight: 600; }
  input, select { width: 100%; max-width: 460px; padding: 6px 8px; border-radius: 6px;
                  border: 1px solid #8885; background: var(--vscode-input-background); color: inherit; }
  input[type=checkbox] { width: auto; }
</style></head>
<body><h1>${esc(title)}</h1>${body}
<script nonce="${n}">${script}</script></body></html>`;
}
function securityHtml(data, diff) {
    const policyRows = Object.entries(data.policy)
        .filter(([, c]) => c.guard)
        .map(([sink, c]) => {
        const pct = Math.round((c.confidence || 0) * 100);
        return `<tr><td><code>${esc(sink)}</code></td><td><code>${esc(c.guard || "")}</code></td>
        <td>${c.count}</td><td><span class="bar"><i style="width:${pct}%;background:#4ea1ff"></i></span> ${pct}%</td></tr>`;
    }).join("") || `<tr><td colspan="4" class="empty">Контракты не обнаружены</td></tr>`;
    const errorRows = data.violations.map((v) => {
        const color = SEV_COLOR[v.severity] || "#888";
        return `<tr data-sev="${v.severity}">
      <td><span class="pill" style="background:${color}">${SEV_ICON[v.severity] || ""} ${esc(v.severity)}</span></td>
      <td><span class="link" data-file="${esc(v.file)}" data-line="${v.line}">${esc(v.file.split(/[\\/]/).pop() || v.file)}:${v.line}</span></td>
      <td><code>${esc(v.sink)}</code></td>
      <td>${esc(v.message)}</td></tr>`;
    }).join("") || `<tr><td colspan="4" class="empty">Нарушений нет 🎉</td></tr>`;
    const diffHtml = diff
        ? `<pre class="diff">${diff.split("\n").map((l) => l.startsWith("+") ? `<span class="add">${esc(l)}</span>`
            : l.startsWith("-") ? `<span class="del">${esc(l)}</span>` : esc(l)).join("\n")}</pre>`
        : `<p class="muted">Diff появится после нажатия «Просмотреть diff».</p>`;
    const body = `
  <div class="tabs">
    <div class="tab active" data-tab="contracts">Контракты</div>
    <div class="tab" data-tab="errors">Ошибки (${data.violations.length})</div>
    <div class="tab" data-tab="refactor">Рефакторинг</div>
  </div>

  <div class="panel active" id="contracts">
    <button id="refresh">⟳ Обновить</button>
    <table><thead><tr><th>Sink</th><th>Guard</th><th>Примеров</th><th>Уверенность</th></tr></thead>
    <tbody>${policyRows}</tbody></table>
  </div>

  <div class="panel" id="errors">
    <label for="sev">Фильтр по серьёзности</label>
    <select id="sev" style="max-width:240px">
      <option value="all">Все</option><option value="critical">critical+</option>
      <option value="high">high+</option><option value="medium">medium+</option><option value="low">low+</option>
    </select>
    <table><thead><tr><th>Серьёзность</th><th>Где</th><th>Sink</th><th>Сообщение</th></tr></thead>
    <tbody id="errBody">${errorRows}</tbody></table>
  </div>

  <div class="panel" id="refactor">
    <p>Нарушений с автофиксом: <b>${data.violations.filter((v) => v.insert).length}</b></p>
    <button id="preview" class="secondary">👁 Просмотреть diff</button>
    <button id="applyFile">✓ Применить к файлу</button>
    <button id="applyProject">✓✓ Применить к проекту</button>
    ${diffHtml}
  </div>`;
    const script = `
  const vscode = acquireVsCodeApi();
  const RANK = {low:0,medium:1,high:2,critical:3};
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById(t.dataset.tab).classList.add('active');
  });
  document.getElementById('refresh').onclick = () => vscode.postMessage({cmd:'refresh'});
  document.getElementById('preview').onclick = () => vscode.postMessage({cmd:'preview'});
  document.getElementById('applyFile').onclick = () => vscode.postMessage({cmd:'applyFile'});
  document.getElementById('applyProject').onclick = () => vscode.postMessage({cmd:'applyProject'});
  document.querySelectorAll('.link').forEach(a => a.onclick = () =>
    vscode.postMessage({cmd:'goto', file:a.dataset.file, line:+a.dataset.line}));
  const sev = document.getElementById('sev');
  sev.onchange = () => {
    const min = sev.value;
    document.querySelectorAll('#errBody tr').forEach(tr => {
      const s = tr.dataset.sev;
      tr.style.display = (min==='all' || (s && RANK[s] >= RANK[min])) ? '' : 'none';
    });
  };`;
    return shell("Nexus Security — панель", body, script);
}
function settingsHtml(s) {
    const body = `
  <p class="muted">Изменения сохраняются сразу.</p>
  <label for="pythonPath">Python (nexus.pythonPath)</label>
  <input id="pythonPath" value="${esc(String(s.pythonPath ?? "python3"))}">
  <label for="scriptPath">Путь к nexus_guard.py (nexus.scriptPath)</label>
  <input id="scriptPath" value="${esc(String(s.scriptPath ?? "~/nexus_guard.py"))}">
  <label><input type="checkbox" id="runOnSave" ${s.runOnSave ? "checked" : ""}> Анализ при сохранении (nexus.runOnSave)</label>
  <label for="minSeverity">Минимальная серьёзность (nexus.minSeverity)</label>
  <select id="minSeverity">
    ${["critical", "high", "medium", "low"].map((o) => `<option value="${o}" ${s.minSeverity === o ? "selected" : ""}>${o}</option>`).join("")}
  </select>`;
    const script = `
  const vscode = acquireVsCodeApi();
  const set = (key, value) => vscode.postMessage({cmd:'set', key, value});
  document.getElementById('pythonPath').onchange = e => set('pythonPath', e.target.value);
  document.getElementById('scriptPath').onchange = e => set('scriptPath', e.target.value);
  document.getElementById('runOnSave').onchange = e => set('runOnSave', e.target.checked);
  document.getElementById('minSeverity').onchange = e => set('minSeverity', e.target.value);`;
    return shell("Nexus — настройки", body, script);
}
function helpHtml() {
    const body = `
  <h2>Как работает контрактный анализ</h2>
  <p>Nexus не навязывает чужие правила. Он <b>извлекает контракты из вашего кода</b>: видит, что
  опасный вызов уже оборачивают в guard (например <code>cmd = shlex.quote(cmd); os.system(cmd)</code>),
  и требует того же от нового кода. Guard определяется структурно (AST): паттерн
  <code>x = f(x)</code> или прямой <code>sink(f(x))</code>. <code>input()</code> — это источник, не guard.</p>

  <h2>Серьёзность</h2>
  <p>${["critical", "high", "medium", "low"].map((s) => `<span class="pill" style="background:${SEV_COLOR[s]}">${SEV_ICON[s]} ${s}</span>`).join(" ")}</p>

  <h2>Как добавить свой guard</h2>
  <p>Просто напишите безопасный код хотя бы раз — Nexus выучит контракт сам. Уверенность растёт
  с числом примеров. Если в проекте примеров нет, действуют запасные контракты:
  <code>os.system → shlex.quote</code>, <code>eval → ast.literal_eval</code>,
  <code>pickle.loads → json.loads</code>, <code>yaml.load → yaml.safe_load</code>.</p>

  <h2>Пропустить вызов</h2>
  <p>Добавьте <code># nexus: skip &lt;причина&gt;</code> в строку с вызовом. Причина обязательна —
  пустой skip сам считается нарушением.</p>

  <h2>Быстрые исправления</h2>
  <p>Ctrl/Cmd + . на подчёркнутой строке → «Добавить guard (контракт проекта)» или
  «Применить все автофиксы в файле».</p>`;
    return shell("Nexus — справка", body, "/* no-op */");
}
//# sourceMappingURL=ui.js.map