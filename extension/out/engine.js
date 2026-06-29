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
exports.clearCache = clearCache;
exports.severityRank = severityRank;
exports.projectDir = projectDir;
exports.analyze = analyze;
// engine.ts — runs nexus_guard.py and caches results by content hash.
const child_process_1 = require("child_process");
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const vscode = __importStar(require("vscode"));
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const cache = new Map();
function clearCache(uri) {
    if (uri)
        cache.delete(uri.toString());
    else
        cache.clear();
}
function severityRank(s) {
    return SEV_RANK[s] ?? 0;
}
function projectDir(doc) {
    const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
    return folder ? folder.uri.fsPath : path.dirname(doc.fileName);
}
function cfg() {
    return vscode.workspace.getConfiguration("nexus");
}
function resolveScript(p) {
    if (p.startsWith("~"))
        return path.join(os.homedir(), p.slice(1));
    return p;
}
/**
 * Analyse a document. The engine in --json mode writes no temp files, so there
 * is nothing to clean up; the 15s timeout kills a runaway interpreter.
 * Results are memoised per-URI keyed by a SHA-1 of the document text.
 */
function analyze(doc, force = false) {
    const python = cfg().get("pythonPath") || "python3";
    const script = resolveScript(cfg().get("scriptPath") || "~/nexus_guard.py");
    const dir = projectDir(doc);
    const text = doc.getText();
    const hash = crypto.createHash("sha1").update(text).digest("hex");
    const cached = cache.get(doc.uri.toString());
    if (!force && cached && cached.hash === hash)
        return Promise.resolve(cached.result);
    // Fail loudly (once) if the engine script is missing, instead of silent null.
    try {
        if (!require("fs").existsSync(script)) {
            notifyOnce("missing-script", `Nexus: движок не найден по пути "${script}". Укажите nexus.scriptPath в настройках.`);
            return Promise.resolve(null);
        }
    }
    catch {
        /* fs check best-effort */
    }
    return new Promise((resolve) => {
        let proc;
        try {
            proc = (0, child_process_1.execFile)(python, [script, dir, "--json", "--file", doc.fileName], { cwd: dir, timeout: 15000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
                if ((err && !stdout) || !stdout) {
                    if (err) {
                        console.error("nexus engine:", err.message, stderr);
                        const anyErr = err;
                        if (anyErr.code === "ENOENT") {
                            notifyOnce("missing-python", `Nexus: не удалось запустить "${python}". Проверьте nexus.pythonPath.`);
                        }
                    }
                    resolve(null);
                    return;
                }
                try {
                    const result = JSON.parse(stdout);
                    cache.set(doc.uri.toString(), { hash, result });
                    resolve(result);
                }
                catch (e) {
                    console.error("nexus engine: invalid JSON —", e.message, stderr);
                    notifyOnce("bad-json", "Nexus: движок вернул некорректный JSON — анализ пропущен. Подробности в консоли.");
                    resolve(null);
                }
            });
        }
        catch (e) {
            console.error("nexus engine: spawn failed —", e.message);
            resolve(null);
            return;
        }
        if (proc) {
            proc.on("error", (e) => {
                console.error("nexus engine: process error —", e.message);
                resolve(null);
            });
        }
    });
}
// Show a given error at most once per session (avoids notification spam).
const _notified = new Set();
function notifyOnce(key, message) {
    if (_notified.has(key))
        return;
    _notified.add(key);
    try {
        vscode.window.showErrorMessage(message);
    }
    catch {
        /* window may be unavailable in tests */
    }
}
//# sourceMappingURL=engine.js.map