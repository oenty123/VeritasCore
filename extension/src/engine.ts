// engine.ts — runs nexus_guard.py and caches results by content hash.
import { execFile } from "child_process";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import * as vscode from "vscode";

export interface Insert {
  title: string;
  mode: "inline" | "newline";
  line: number; // 1-based
  col: number;  // 0-based
  text: string;
}
export interface Violation {
  file: string;
  line: number; col: number; endLine: number; endCol: number;
  sink: string; guard: string; confidence: number; count: number;
  severity: "critical" | "high" | "medium" | "low";
  arg: string | null; skipNoReason: boolean;
  message: string; fix: string | null; insert: Insert | null;
}
export interface Contract {
  guard: string | null; confidence: number; count: number; examples: string[];
}
export interface AnalysisResult {
  policy: Record<string, Contract>;
  violations: Violation[];
}

const SEV_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const cache = new Map<string, { hash: string; result: AnalysisResult }>();

export function clearCache(uri?: vscode.Uri): void {
  if (uri) cache.delete(uri.toString());
  else cache.clear();
}

export function severityRank(s: string): number {
  return SEV_RANK[s] ?? 0;
}

export function projectDir(doc: vscode.TextDocument): string {
  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  return folder ? folder.uri.fsPath : path.dirname(doc.fileName);
}

function cfg() {
  return vscode.workspace.getConfiguration("nexus");
}

function resolveScript(p: string): string {
  if (p.startsWith("~")) return path.join(os.homedir(), p.slice(1));
  return p;
}

/**
 * Analyse a document. The engine in --json mode writes no temp files, so there
 * is nothing to clean up; the 15s timeout kills a runaway interpreter.
 * Results are memoised per-URI keyed by a SHA-1 of the document text.
 */
export function analyze(doc: vscode.TextDocument, force = false): Promise<AnalysisResult | null> {
  const python = cfg().get<string>("pythonPath") || "python3";
  const script = resolveScript(cfg().get<string>("scriptPath") || "~/nexus_guard.py");
  const dir = projectDir(doc);
  const text = doc.getText();
  const hash = crypto.createHash("sha1").update(text).digest("hex");

  const cached = cache.get(doc.uri.toString());
  if (!force && cached && cached.hash === hash) return Promise.resolve(cached.result);

  // Fail loudly (once) if the engine script is missing, instead of silent null.
  try {
    if (!require("fs").existsSync(script)) {
      notifyOnce(
        "missing-script",
        `Nexus: движок не найден по пути "${script}". Укажите nexus.scriptPath в настройках.`
      );
      return Promise.resolve(null);
    }
  } catch {
    /* fs check best-effort */
  }

  return new Promise((resolve) => {
    let proc;
    try {
      proc = execFile(
        python, [script, dir, "--json", "--file", doc.fileName],
        { cwd: dir, timeout: 15000, maxBuffer: 8 * 1024 * 1024 },
        (err, stdout, stderr) => {
          if ((err && !stdout) || !stdout) {
            if (err) {
              console.error("nexus engine:", err.message, stderr);
              const anyErr = err as { code?: string };
              if (anyErr.code === "ENOENT") {
                notifyOnce(
                  "missing-python",
                  `Nexus: не удалось запустить "${python}". Проверьте nexus.pythonPath.`
                );
              }
            }
            resolve(null);
            return;
          }
          try {
            const result = JSON.parse(stdout) as AnalysisResult;
            cache.set(doc.uri.toString(), { hash, result });
            resolve(result);
          } catch (e) {
            console.error("nexus engine: invalid JSON —", (e as Error).message, stderr);
            notifyOnce(
              "bad-json",
              "Nexus: движок вернул некорректный JSON — анализ пропущен. Подробности в консоли."
            );
            resolve(null);
          }
        }
      );
    } catch (e) {
      console.error("nexus engine: spawn failed —", (e as Error).message);
      resolve(null);
      return;
    }
    if (proc) {
      proc.on("error", (e: Error) => {
        console.error("nexus engine: process error —", e.message);
        resolve(null);
      });
    }
  });
}

// Show a given error at most once per session (avoids notification spam).
const _notified = new Set<string>();
function notifyOnce(key: string, message: string): void {
  if (_notified.has(key)) return;
  _notified.add(key);
  try {
    vscode.window.showErrorMessage(message);
  } catch {
    /* window may be unavailable in tests */
  }
}
