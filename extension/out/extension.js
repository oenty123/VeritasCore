"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
// extension.ts — Nexus Security Pro entry point.
const vscode = __importStar(require("vscode"));
const engine_1 = require("./engine");
const ui_1 = require("./ui");
const SOURCE = "Nexus";
const SEV_DIAG = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
};
let diagnostics;
let status;
const lastResult = new Map(); // uri -> last analysis
let securityPanel;
let settingsPanel;
let helpPanel;
// Virtual docs for the "preview before apply" diff editor.
const previewContent = new Map();
const previewEmitter = new vscode.EventEmitter();
const previewProvider = {
    onDidChange: previewEmitter.event,
    provideTextDocumentContent: (uri) => previewContent.get(uri.toString()) || "",
};
function cfg() { return vscode.workspace.getConfiguration("nexus"); }
function passesMinSeverity(sev) {
    const min = cfg().get("minSeverity") || "low";
    return (0, engine_1.severityRank)(sev) >= (0, engine_1.severityRank)(min);
}
// ---------------------------------------------------------------- diagnostics
function buildDiagnostics(result) {
    const out = [];
    for (const v of result.violations) {
        if (!v.skipNoReason && !passesMinSeverity(v.severity))
            continue;
        const range = new vscode.Range(Math.max(0, v.line - 1), Math.max(0, v.col), Math.max(0, (v.endLine || v.line) - 1), Math.max(v.col + 1, v.endCol));
        const d = new vscode.Diagnostic(range, v.message, SEV_DIAG[v.severity] ?? vscode.DiagnosticSeverity.Warning);
        d.source = SOURCE;
        d.code = v.sink;
        out.push(d);
    }
    return out;
}
function worstSeverity(violations) {
    let worst = null;
    for (const v of violations) {
        if (!passesMinSeverity(v.severity))
            continue;
        if (worst === null || (0, engine_1.severityRank)(v.severity) > (0, engine_1.severityRank)(worst))
            worst = v.severity;
    }
    return worst;
}
function updateStatus(result) {
    if (!result) {
        status.hide();
        return;
    }
    const shown = result.violations.filter((v) => passesMinSeverity(v.severity));
    const worst = worstSeverity(result.violations);
    if (shown.length === 0) {
        status.text = "$(shield) Nexus: чисто";
        status.color = new vscode.ThemeColor("charts.green");
    }
    else {
        status.text = `$(shield) Nexus: ${shown.length}`;
        status.color = new vscode.ThemeColor(worst === "critical" || worst === "high" ? "charts.red"
            : worst === "medium" ? "charts.yellow" : "charts.blue");
    }
    status.tooltip = "Nexus Security — открыть панель";
    status.show();
}
async function refresh(doc, force = false) {
    if (doc.languageId !== "python")
        return null;
    const result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: "Nexus: анализ…" }, () => (0, engine_1.analyze)(doc, force));
    if (!result)
        return null;
    lastResult.set(doc.uri.toString(), result);
    diagnostics.set(doc.uri, buildDiagnostics(result));
    updateStatus(result);
    if (securityPanel)
        renderSecurity(doc);
    return result;
}
// ------------------------------------------------------------------- editing
function insertEdit(edit, uri, ins) {
    const line = Math.max(0, ins.line - 1);
    edit.insert(uri, new vscode.Position(line, ins.mode === "inline" ? ins.col : 0), ins.text);
}
function fixedText(doc, violations) {
    const lines = doc.getText().split(/(?<=\n)/); // keep newlines
    const inserts = violations.filter((v) => v.insert).map((v) => v.insert);
    inserts.sort((a, b) => (b.line - a.line) || (b.col - a.col));
    for (const ins of inserts) {
        const idx = ins.line - 1;
        if (idx < 0 || idx >= lines.length)
            continue;
        if (ins.mode === "inline") {
            const l = lines[idx];
            lines[idx] = l.slice(0, ins.col) + ins.text + l.slice(ins.col);
        }
        else {
            lines.splice(idx, 0, ins.text);
        }
    }
    return lines.join("");
}
async function applyAllFixes(doc) {
    const result = lastResult.get(doc.uri.toString()) || (await refresh(doc, true));
    if (!result)
        return 0;
    const inserts = result.violations.filter((v) => v.insert).map((v) => v.insert);
    if (!inserts.length)
        return 0;
    inserts.sort((a, b) => (b.line - a.line) || (b.col - a.col));
    const edit = new vscode.WorkspaceEdit();
    for (const ins of inserts)
        insertEdit(edit, doc.uri, ins);
    await vscode.workspace.applyEdit(edit);
    if (!doc.isUntitled)
        await doc.save(); // don't pop a save dialog for untitled docs
    (0, engine_1.clearCache)(doc.uri); // edited text invalidates the cached result
    await refresh(doc, true); // re-analyze so diagnostics/panels update
    return inserts.length;
}
// --------------------------------------------------------------- quick fixes
const codeActions = {
    provideCodeActions(document, range, context) {
        const result = lastResult.get(document.uri.toString());
        if (!result)
            return [];
        const actions = [];
        const here = result.violations.filter((v) => v.line - 1 === range.start.line && v.insert);
        for (const v of here) {
            const a = new vscode.CodeAction("Добавить guard (контракт проекта)", vscode.CodeActionKind.QuickFix);
            a.isPreferred = true;
            a.edit = new vscode.WorkspaceEdit();
            insertEdit(a.edit, document.uri, v.insert);
            const matching = context.diagnostics.find((d) => d.range.start.line === v.line - 1);
            if (matching)
                a.diagnostics = [matching];
            actions.push(a);
            const skip = new vscode.CodeAction("Пропустить (# nexus: skip …)", vscode.CodeActionKind.QuickFix);
            skip.command = { command: "nexus.skipWithReason", title: "skip",
                arguments: [document.uri, v.line] };
            actions.push(skip);
        }
        if (result.violations.some((v) => v.insert)) {
            const all = new vscode.CodeAction("Применить все автофиксы в файле", vscode.CodeActionKind.QuickFix);
            all.command = { command: "nexus.applyAllFixes", title: "apply all" };
            actions.push(all);
        }
        return actions;
    },
};
// ------------------------------------------------------------------ refactor
async function refactorFile(doc) {
    const result = (await refresh(doc, true));
    if (!result)
        return;
    const n = result.violations.filter((v) => v.insert).length;
    if (n === 0) {
        vscode.window.showInformationMessage("Nexus: нечего исправлять в этом файле.");
        return;
    }
    // Preview diff in a real diff editor before applying.
    const previewUri = vscode.Uri.parse(`nexus-fixed:${doc.uri.fsPath}.fixed.py`);
    previewContent.set(previewUri.toString(), fixedText(doc, result.violations));
    previewEmitter.fire(previewUri);
    await vscode.commands.executeCommand("vscode.diff", doc.uri, previewUri, `Nexus: предпросмотр (${n} исправлений)`);
    const pick = await vscode.window.showInformationMessage(`Применить ${n} исправлений к файлу?`, "Применить", "Отмена");
    if (pick === "Применить") {
        const applied = await applyAllFixes(doc);
        vscode.window.showInformationMessage(`Nexus: применено ${applied} исправлений.`);
    }
}
async function refactorWorkspace() {
    const files = await vscode.workspace.findFiles("**/*.py", "**/{.git,node_modules,.venv,venv}/**", 2000);
    if (!files.length) {
        vscode.window.showInformationMessage("Nexus: Python-файлы не найдены.");
        return;
    }
    const plan = [];
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Nexus: анализ workspace…", cancellable: false }, async (progress) => {
        let i = 0;
        for (const uri of files) {
            progress.report({ message: `${++i}/${files.length}`, increment: 100 / files.length });
            const doc = await vscode.workspace.openTextDocument(uri);
            const res = await (0, engine_1.analyze)(doc, true);
            const count = res ? res.violations.filter((v) => v.insert).length : 0;
            if (count) {
                plan.push({ doc, count });
                lastResult.set(uri.toString(), res);
            }
        }
    });
    const total = plan.reduce((s, p) => s + p.count, 0);
    if (total === 0) {
        vscode.window.showInformationMessage("Nexus: нарушений с автофиксом не найдено 🎉");
        return;
    }
    const pick = await vscode.window.showWarningMessage(`Будет исправлено ${total} нарушений в ${plan.length} файлах. Применить?`, { modal: true }, "Применить ко всему проекту");
    if (pick !== "Применить ко всему проекту")
        return;
    let applied = 0;
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Nexus: применение…" }, async (progress) => {
        for (const p of plan) {
            progress.report({ message: p.doc.fileName });
            applied += await applyAllFixes(p.doc);
        }
    });
    vscode.window.showInformationMessage(`Nexus: применено ${applied} исправлений в ${plan.length} файлах.`);
}
// ------------------------------------------------------- local explanation
async function explainFile() {
    const ed = vscode.window.activeTextEditor;
    if (!ed)
        return;
    const result = (await refresh(ed.document, true));
    if (!result) {
        vscode.window.showInformationMessage("Nexus: анализ недоступен.");
        return;
    }
    const lines = ["# Nexus — локальное объяснение (COAA, без ИИ)", ""];
    const bySink = new Map();
    for (const v of result.violations) {
        (bySink.get(v.sink) || bySink.set(v.sink, []).get(v.sink)).push(v);
    }
    if (bySink.size === 0) {
        lines.push("Опасных вызовов без guard не найдено. 🎉");
    }
    else {
        lines.push(`Найдено опасных вызовов без guard: ${result.violations.length}`, "");
        for (const [sink, vs] of bySink) {
            const c = result.policy[sink];
            lines.push(`## ${sink}  (${vs.length})`);
            if (c && c.guard) {
                lines.push(`- Требуется guard: \`${c.guard}\`  (уверенность ${Math.round((c.confidence || 0) * 100)}%, примеров ${c.count})`);
                if (c.examples?.length)
                    lines.push(`- Примеры из кодовой базы: ${c.examples.join(", ")}`);
            }
            for (const v of vs)
                lines.push(`- строка ${v.line}: ${v.message}`);
            lines.push("");
        }
        lines.push("## Общие рекомендации", "- Оборачивайте внешний ввод guard-функцией до передачи в sink.", "- Для команд — shlex.quote; для разбора — ast.literal_eval/json.loads; для YAML — yaml.safe_load.", "- Сознательные исключения помечайте `# nexus: skip <причина>`.");
    }
    const doc = await vscode.workspace.openTextDocument({ language: "markdown", content: lines.join("\n") });
    await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
}
// ----------------------------------------------------------------- panels
function diffText(doc, violations) {
    // Localised, per-violation diff (clear and correct without a full differ).
    const src = doc.getText().split("\n");
    const out = [];
    for (const v of violations) {
        if (!v.insert)
            continue;
        const idx = v.line - 1;
        const orig = src[idx] ?? "";
        out.push(`@@ строка ${v.line} (${v.sink}) @@`);
        if (v.insert.mode === "inline") {
            out.push(`-${orig}`);
            out.push(`+${orig.slice(0, v.insert.col)}${v.insert.text}${orig.slice(v.insert.col)}`);
        }
        else {
            out.push(`+${v.insert.text.replace(/\n$/, "")}`);
            out.push(` ${orig}`);
        }
        out.push("");
    }
    return out.join("\n");
}
function renderSecurity(doc, diff = "") {
    if (!securityPanel)
        return;
    const result = lastResult.get(doc.uri.toString()) || { policy: {}, violations: [] };
    securityPanel.webview.html = (0, ui_1.securityHtml)(result, diff);
}
function openSecurity(context) {
    if (securityPanel) {
        securityPanel.reveal();
        return;
    }
    securityPanel = vscode.window.createWebviewPanel("nexusSecurity", "Nexus Security", vscode.ViewColumn.Beside, { enableScripts: true, retainContextWhenHidden: true });
    securityPanel.onDidDispose(() => (securityPanel = undefined), null, context.subscriptions);
    securityPanel.webview.onDidReceiveMessage(async (m) => {
        const ed = vscode.window.activeTextEditor;
        const doc = ed?.document;
        if (m.cmd === "goto") {
            const d = await vscode.workspace.openTextDocument(vscode.Uri.file(m.file));
            const e = await vscode.window.showTextDocument(d, vscode.ViewColumn.One);
            const pos = new vscode.Position(Math.max(0, m.line - 1), 0);
            e.selection = new vscode.Selection(pos, pos);
            e.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        }
        else if (m.cmd === "refresh" && doc) {
            await refresh(doc, true);
        }
        else if (m.cmd === "preview" && doc) {
            const r = lastResult.get(doc.uri.toString());
            renderSecurity(doc, r ? diffText(doc, r.violations) : "");
        }
        else if (m.cmd === "applyFile" && doc) {
            const n = await applyAllFixes(doc);
            vscode.window.showInformationMessage(`Nexus: применено ${n} исправлений.`);
            await refresh(doc, true);
        }
        else if (m.cmd === "applyProject") {
            await refactorWorkspace();
        }
    }, null, context.subscriptions);
    const doc = vscode.window.activeTextEditor?.document;
    if (doc)
        refresh(doc, true).then(() => renderSecurity(doc));
    else
        renderSecurity({ uri: vscode.Uri.parse("untitled:none") });
}
function openSettings(context) {
    if (settingsPanel) {
        settingsPanel.reveal();
        return;
    }
    settingsPanel = vscode.window.createWebviewPanel("nexusSettings", "Nexus — настройки", vscode.ViewColumn.Active, { enableScripts: true });
    settingsPanel.onDidDispose(() => (settingsPanel = undefined), null, context.subscriptions);
    const snapshot = () => ({
        pythonPath: cfg().get("pythonPath"), scriptPath: cfg().get("scriptPath"),
        runOnSave: cfg().get("runOnSave"), minSeverity: cfg().get("minSeverity"),
    });
    settingsPanel.webview.html = (0, ui_1.settingsHtml)(snapshot());
    settingsPanel.webview.onDidReceiveMessage(async (m) => {
        if (m.cmd === "set") {
            await cfg().update(m.key, m.value, vscode.ConfigurationTarget.Global);
            const ed = vscode.window.activeTextEditor;
            if (ed) {
                (0, engine_1.clearCache)(ed.document.uri);
                await refresh(ed.document, true);
            }
        }
    }, null, context.subscriptions);
}
function openHelp(context) {
    if (helpPanel) {
        helpPanel.reveal();
        return;
    }
    helpPanel = vscode.window.createWebviewPanel("nexusHelp", "Nexus — справка", vscode.ViewColumn.Active, { enableScripts: true });
    helpPanel.onDidDispose(() => (helpPanel = undefined), null, context.subscriptions);
    helpPanel.webview.html = (0, ui_1.helpHtml)();
}
// ------------------------------------------------------------------ activate
function activate(context) {
    diagnostics = vscode.languages.createDiagnosticCollection(SOURCE);
    status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    status.command = "nexus.openPanel";
    context.subscriptions.push(diagnostics, status, vscode.workspace.registerTextDocumentContentProvider("nexus-fixed", previewProvider), vscode.workspace.onDidSaveTextDocument((doc) => {
        if (cfg().get("runOnSave")) {
            (0, engine_1.clearCache)(doc.uri);
            refresh(doc, true);
        }
    }), vscode.workspace.onDidOpenTextDocument((doc) => refresh(doc)), vscode.window.onDidChangeActiveTextEditor((ed) => {
        if (ed) {
            const r = lastResult.get(ed.document.uri.toString());
            updateStatus(r || null);
        }
        else
            status.hide();
    }), vscode.workspace.onDidCloseTextDocument((doc) => { diagnostics.delete(doc.uri); (0, engine_1.clearCache)(doc.uri); }), vscode.commands.registerCommand("nexus.scanFile", () => {
        const ed = vscode.window.activeTextEditor;
        if (ed)
            refresh(ed.document, true);
    }), vscode.commands.registerCommand("nexus.openPanel", () => openSecurity(context)), vscode.commands.registerCommand("nexus.openSettings", () => openSettings(context)), vscode.commands.registerCommand("nexus.openHelp", () => openHelp(context)), vscode.commands.registerCommand("nexus.explainFile", explainFile), vscode.commands.registerCommand("nexus.applyAllFixes", async () => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const n = await applyAllFixes(ed.document);
        vscode.window.showInformationMessage(`Nexus: применено ${n} исправлений.`);
        await refresh(ed.document, true);
    }), vscode.commands.registerCommand("nexus.refactorFile", () => {
        const ed = vscode.window.activeTextEditor;
        if (ed)
            refactorFile(ed.document);
    }), vscode.commands.registerCommand("nexus.refactorWorkspace", refactorWorkspace), vscode.commands.registerCommand("nexus.skipWithReason", async (uri, line) => {
        const reason = await vscode.window.showInputBox({ prompt: "Причина пропуска (обязательно)" });
        if (!reason)
            return;
        const doc = await vscode.workspace.openTextDocument(uri);
        const idx = Math.max(0, line - 1);
        const text = doc.lineAt(idx).text;
        const edit = new vscode.WorkspaceEdit();
        edit.insert(uri, new vscode.Position(idx, text.length), `  # nexus: skip ${reason}`);
        await vscode.workspace.applyEdit(edit);
        await doc.save();
        (0, engine_1.clearCache)(uri);
        await refresh(doc, true);
    }), vscode.languages.registerCodeActionsProvider({ language: "python" }, codeActions, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
    const ed = vscode.window.activeTextEditor;
    if (ed)
        refresh(ed.document, true);
}
function deactivate() {
    diagnostics?.dispose();
    status?.dispose();
}
//# sourceMappingURL=extension.js.map