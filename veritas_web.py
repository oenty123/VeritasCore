#!/usr/bin/env python3
"""veritas_web.py — local web dashboard for auditing Python repositories.

Версия 1.0.0 — переименование в VeritasCore, улучшенный интерфейс.
"""
import os
import re
import sys
import json
import html
import shutil
import tempfile
import subprocess
import webbrowser
import uuid
import difflib
import logging
import threading
import glob
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

# === ЛОГИРОВАНИЕ ===
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('veritas_web')

# === ИМПОРТ ДВИЖКА ===
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import veritas_core as ng
except ImportError:
    ng = None
    logger.warning("veritas_core.py не найден, некоторые функции недоступны")
try:
    import veritas_knowledge as kb
except ImportError:
    kb = None
    logger.warning("veritas_knowledge.py не найден, обучение недоступно")
try:
    import veritas_secrets as secrets
except ImportError:
    secrets = None
    logger.warning("veritas_secrets.py не найден, сканирование секретов недоступно")

# === ГЛОБАЛЬНЫЕ КОНСТАНТЫ ===
KNOWLEDGE_DB = os.path.join(os.path.expanduser("~"), ".veritascore", "veritas_knowledge.json")
URL_RE = re.compile(
    r'^(https://|git@)(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)[/:][\w.\-]+/[\w.\-]+?(\.git)?/?$'
)
SEV_COLOR = {"guarded": "#52c41a", "unguarded": "#ff4d4f", "unknown": "#faad14", "safe": "#9aa0a6"}
MAX_PROJECTS = 50
STATE_FILE = ".veritascore_state.json"

# === УЛУЧШЕННАЯ CSS ТЕМА (быстрая, без лагов, тёмная) ===
_THEME = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;background:#0b0f17;color:#e4e8ee;line-height:1.5;min-height:100vh}
header{position:sticky;top:0;z-index:100;padding:14px 28px;background:#111827;border-bottom:1px solid #1e293b;display:flex;gap:14px;align-items:center;flex-wrap:wrap;box-shadow:0 4px 12px rgba(0,0,0,0.3)}
h1{font-size:18px;font-weight:700;margin:0;display:flex;align-items:center;gap:10px}
h1::before{content:"";width:10px;height:10px;border-radius:50%;background:linear-gradient(135deg,#5b8cff,#9b6bff);box-shadow:0 0 12px #5b8cff99}
a{color:#8db1ff;text-decoration:none;transition:color .2s}
a:hover{color:#b3cfff}
a.btn,button{background:#1e293b;color:#e4e8ee;padding:9px 16px;border-radius:10px;text-decoration:none;border:1px solid #334155;font-size:13px;font-weight:550;cursor:pointer;transition:all .2s ease;display:inline-flex;align-items:center;gap:6px;box-shadow:0 2px 4px rgba(0,0,0,0.2)}
a.btn:hover,button:hover{background:#2d3a4f;border-color:#475569;transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.3)}
a.btn.primary,button.primary{background:linear-gradient(135deg,#3b6cf0,#5b8cff);border-color:transparent;color:#fff;box-shadow:0 4px 12px rgba(59,108,240,0.3)}
a.btn.primary:hover,button.primary:hover{background:linear-gradient(135deg,#4d7aff,#6a9aff);box-shadow:0 6px 16px rgba(59,108,240,0.45)}
a.btn.accent{background:linear-gradient(135deg,#2f9e54,#46c46f);border-color:transparent;color:#fff;box-shadow:0 4px 12px rgba(47,158,84,0.3)}
a.btn.accent:hover{background:linear-gradient(135deg,#3ab55f,#53d37d);box-shadow:0 6px 16px rgba(47,158,84,0.45)}
.wrap{padding:28px 32px;max-width:1440px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:28px}
.card{background:#161c2a;border:1px solid #1e293b;border-radius:16px;padding:20px 24px;box-shadow:0 4px 12px rgba(0,0,0,0.25);transition:box-shadow .2s}
.card:hover{box-shadow:0 8px 24px rgba(0,0,0,0.4)}
.num{font-size:34px;font-weight:720;margin-top:4px;letter-spacing:-1px;color:#f0f4ff}
input,select{background:#0f1520;border:1px solid #334155;border-radius:8px;padding:8px 12px;color:#e4e8ee;font-size:13px;outline:none;transition:all .2s}
input:focus,select:focus{border-color:#5b8cff;box-shadow:0 0 0 3px rgba(91,140,255,0.15)}
table{width:100%;border-collapse:separate;border-spacing:0;background:#161c2a;border:1px solid #1e293b;border-radius:16px;overflow:hidden}
th,td{text-align:left;padding:12px 16px;border-bottom:1px solid #1e293b;font-size:13px}
th{background:#1c2538;font-weight:600;color:#a2adc4;text-transform:uppercase;letter-spacing:.5px;font-size:11px}
tbody tr:hover{background:#1e2a3a}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:#1e293b;box-shadow:inset 0 1px 3px rgba(0,0,0,0.3)}
.bar>i{display:block;height:100%}
.pill{padding:3px 10px;border-radius:20px;color:#0a0e14;font-weight:680;font-size:11px;display:inline-block}
.mono{font-family:ui-monospace,'SF Mono',Menlo,monospace;font-size:12.5px}
.small{font-size:12px}
.muted{color:#8b94a4}
.err{color:#ff8585}
code{background:#1a2332;padding:3px 8px;border-radius:7px;font-size:12.5px;font-family:ui-monospace,Menlo,monospace;border:1px solid #2d3a4f}
nav{display:flex;gap:4px;align-items:center}
nav a{padding:8px 14px;border-radius:9px;color:#b0bdd0;font-size:13px;font-weight:550;transition:all .2s}
nav a:hover,nav a.active{background:#1e293b;color:#fff}
.panel{background:#161c2a;border:1px solid #1e293b;border-radius:18px;padding:24px 28px;margin-bottom:22px;box-shadow:0 4px 12px rgba(0,0,0,0.2)}
.methods{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.method{background:#101723;border:1px solid #1e293b;border-radius:14px;padding:18px;transition:all .2s}
.method:hover{border-color:#334155;box-shadow:0 6px 20px rgba(0,0,0,0.3)}
.method .mhint{color:#8b94a4;font-size:12px;margin-bottom:14px;min-height:32px}
.method form{display:flex;flex-direction:column;gap:10px}
.toggle{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #1e293b}
.toggle .tinfo{flex:1;padding-right:16px}
.sw{min-width:80px;text-align:center;padding:8px 14px;border-radius:9px;font-size:12.5px;font-weight:620;border:1px solid #334155;transition:all .2s}
.sw.on{background:linear-gradient(135deg,#2f9e54,#46c46f);border-color:transparent;color:#fff;box-shadow:0 4px 10px rgba(47,158,84,0.25)}
.sw.off{background:#1e293b;color:#9aa3b2}
.editor-layout{display:flex;gap:16px;margin-top:16px;height:calc(100vh - 220px);min-height:500px}
.file-tree{width:270px;background:#161c2a;border:1px solid #1e293b;border-radius:14px;padding:14px;overflow-y:auto;flex-shrink:0}
.file-tree .file{cursor:pointer;padding:5px 10px;border-radius:5px;font-size:13px;font-family:monospace;transition:background .15s}
.file-tree .file:hover{background:#1e293b}
.file-tree .file.active{background:rgba(59,108,240,0.25);color:#fff}
.editor-container{flex:1;display:flex;flex-direction:column;border:1px solid #1e293b;border-radius:14px;overflow:hidden;background:#0f1520}
.editor-toolbar{display:flex;gap:8px;padding:10px 16px;background:#161c2a;border-bottom:1px solid #1e293b;align-items:center;flex-wrap:wrap}
.editor-toolbar .filename{flex:1;font-family:monospace;color:#9aa0a6}
.monaco-editor-holder{flex:1;min-height:300px}
.issues-panel{max-height:200px;overflow-y:auto;background:#161c2a;border-top:1px solid #1e293b;padding:10px 16px;font-size:13px}
.issues-panel .issue{padding:5px 0;border-bottom:1px solid #1e293b;display:flex;gap:12px;align-items:center}
.issues-panel .issue .line{color:#8db1ff;cursor:pointer;font-family:monospace}
.issues-panel .issue .msg{flex:1}
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:14px}
.settings-grid .field{display:flex;flex-direction:column;gap:6px}
.settings-grid .field label{font-weight:550;font-size:13px}
.settings-grid .field .hint{font-size:11px;color:#8b94a4}
"""

# === БЕЗОПАСНЫЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
def esc(s):
    return html.escape(str(s))

def _safe_path(base, path):
    base_real = os.path.realpath(base)
    full = os.path.realpath(os.path.join(base_real, path))
    if not full.startswith(base_real) or '..' in os.path.normpath(full).split(os.sep):
        raise ValueError("Path traversal detected")
    return full

def _safe_filename(filename):
    safe = os.path.basename(filename)
    if not safe.lower().endswith('.py'):
        raise ValueError("Only .py files are allowed")
    return safe

# === КЛАСС СОСТОЯНИЯ ПРИЛОЖЕНИЯ С ПЕРСИСТЕНТНОСТЬЮ ===
class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.root = "."
        self.audits = []
        self.projects = {}
        self.project_order = []
        self.cross = False
        self.learn = False
        self._load_state()

    def _state_path(self):
        return os.path.join(self.root if self.root != "." else ".", STATE_FILE)

    def _load_state(self):
        path = self._state_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self.lock:
                self.cross = data.get('cross', False)
                self.learn = data.get('learn', False)
                self.audits = []
                for a in data.get('audits', []):
                    self.audits.append({
                        "name": a["name"],
                        "path": a.get("path", ""),
                        "error": a.get("error"),
                        "summary": a.get("summary", {}),
                    })
                self.projects = {}
                self.project_order = []
                for pid, proj in data.get('projects', {}).items():
                    self.projects[pid] = {
                        "name": proj.get("name", ""),
                        "path": proj.get("path", ""),
                        "report": None,
                        "summary": proj.get("summary", {}),
                    }
                    self.project_order.append(pid)
                logger.info(f"State loaded from {path}")
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")

    def _save_state(self):
        path = self._state_path()
        try:
            with self.lock:
                light_audits = []
                for a in self.audits:
                    entry = {"name": a["name"], "path": a.get("path", ""),
                             "error": a.get("error")}
                    rep = a.get("report")
                    if rep:
                        entry["summary"] = {
                            "files_scanned": rep.get("files_scanned", 0),
                            "sinks_total": rep.get("sinks_total", 0),
                            "coverage": rep.get("coverage", 0.0),
                            "totals": rep.get("totals", {}),
                        }
                    light_audits.append(entry)

                light_projects = {}
                for pid, proj in self.projects.items():
                    light_projects[pid] = {
                        "name": proj.get("name", ""),
                        "path": proj.get("path", ""),
                        "summary": proj.get("summary", {}),
                    }

                data = {
                    "audits": light_audits,
                    "projects": light_projects,
                    "project_order": self.project_order[:],
                    "cross": self.cross,
                    "learn": self.learn,
                }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"State saved to {path}")
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def add_audit(self, entry):
        with self.lock:
            if "report" in entry and entry["report"] is not None:
                r = entry["report"]
                entry["summary"] = {
                    "files_scanned": r.get("files_scanned", 0),
                    "sinks_total": r.get("sinks_total", 0),
                    "coverage": r.get("coverage", 0.0),
                    "totals": r.get("totals", {}),
                }
            self.audits.insert(0, entry)
        self._save_state()

    def get_audits(self):
        with self.lock:
            return self.audits.copy()

    def add_project(self, pid, data):
        with self.lock:
            if len(self.projects) >= MAX_PROJECTS:
                old_pid = self.project_order.pop(0)
                self.projects.pop(old_pid, None)
            if "report" in data and data["report"] is not None:
                r = data["report"]
                data["summary"] = {
                    "files_scanned": r.get("files_scanned", 0),
                    "sinks_total": r.get("sinks_total", 0),
                    "coverage": r.get("coverage", 0.0),
                    "totals": r.get("totals", {}),
                }
            self.projects[pid] = data
            self.project_order.append(pid)
        self._save_state()

    def get_project(self, pid):
        with self.lock:
            return self.projects.get(pid)

    def get_projects(self):
        with self.lock:
            return self.projects.copy()

    def update_project(self, pid, updates):
        with self.lock:
            if pid in self.projects:
                self.projects[pid].update(updates)
        self._save_state()

    def set_cross(self, value):
        with self.lock:
            self.cross = value
        self._save_state()

    def set_learn(self, value):
        with self.lock:
            self.learn = value
        self._save_state()

# === НАСТРОЙКИ (расширенные) ===
def get_project_settings(project_root):
    defaults = {
        "max_file_bytes": getattr(ng, '_MAX_FILE_BYTES', 1_500_000),
        "parallel_min_files": getattr(ng, '_PARALLEL_MIN_FILES', 64),
        "parallel_min_bytes": getattr(ng, '_PARALLEL_MIN_BYTES', 1_000_000),
        "min_confidence": 0.0,
        "cross_file": False,
        "ignore": [],
        "secret_scan": True,
        "sca": False,
        "jobs": 1,
        "fast": False,
        "cache_enabled": True,
        "max_findings": 500,
        "skip_tests": False,
    }
    cfg_path = os.path.join(project_root, ".veritascore.json")
    settings = defaults.copy()
    try:
        with open(cfg_path, encoding="utf-8") as f:
            user = json.load(f)
        if isinstance(user, dict):
            for k in defaults:
                if k in user:
                    settings[k] = user[k]
    except Exception:
        pass
    changed = False
    if settings.get('parallel_min_bytes', 0) < 100000:
        settings['parallel_min_bytes'] = defaults['parallel_min_bytes']
        changed = True
    if settings.get('parallel_min_files', 0) < 1:
        settings['parallel_min_files'] = defaults['parallel_min_files']
        changed = True
    if settings.get('max_file_bytes', 0) < 10000:
        settings['max_file_bytes'] = defaults['max_file_bytes']
        changed = True
    if not (0.0 <= settings.get('min_confidence', 0.0) <= 1.0):
        settings['min_confidence'] = defaults['min_confidence']
        changed = True
    if settings.get('jobs', 0) < 1:
        settings['jobs'] = defaults['jobs']
        changed = True
    if not isinstance(settings.get('cache_enabled'), bool):
        settings['cache_enabled'] = defaults['cache_enabled']
        changed = True
    if not isinstance(settings.get('max_findings', 500), int) or settings['max_findings'] < 1:
        settings['max_findings'] = defaults['max_findings']
        changed = True
    if not isinstance(settings.get('skip_tests'), bool):
        settings['skip_tests'] = defaults['skip_tests']
        changed = True
    if changed:
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
        except Exception:
            pass
    return settings

def save_project_settings(project_root, settings):
    errors = []
    if not (0.0 <= settings.get('min_confidence', 0.0) <= 1.0):
        errors.append("min_confidence must be between 0 and 1")
    if settings.get('jobs', 1) < 1:
        errors.append("jobs must be at least 1")
    if settings.get('max_file_bytes', 10000) < 10000:
        errors.append("max_file_bytes must be at least 10000")
    if settings.get('parallel_min_files', 1) < 1:
        errors.append("parallel_min_files must be at least 1")
    if settings.get('parallel_min_bytes', 100000) < 100000:
        errors.append("parallel_min_bytes must be at least 100000")
    if settings.get('max_findings', 0) < 1:
        errors.append("max_findings must be at least 1")
    if errors:
        raise ValueError("; ".join(errors))
    cfg_path = os.path.join(project_root, ".veritascore.json")
    existing = {}
    try:
        with open(cfg_path, encoding="utf-8") as f:
            existing = json.load(f)
    except Exception:
        pass
    existing.update(settings)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    return settings

# === ФУНКЦИИ ДЛЯ РАБОТЫ С РЕПОЗИТОРИЯМИ (оптимизированные) ===
def _has_py(path, patterns):
    if not ng:
        return False
    for dp, _d, fs in os.walk(path):
        if ".git" in dp.split(os.sep):
            continue
        for f in fs:
            if f.endswith(".py"):
                rel = os.path.relpath(os.path.join(dp, f), path)
                if not ng.is_ignored(rel, patterns):
                    return True
    return False

def discover_repos(root, state):
    root = os.path.abspath(root)
    repos = []
    patterns = getattr(ng, 'DEFAULT_IGNORE', [])
    try:
        children = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        children = []
    for entry in children:
        if entry.is_dir() and not entry.name.startswith("."):
            if _has_py(entry.path, patterns):
                repos.append((entry.name, entry.path))
    top_py = any(f.endswith(".py") for f in os.listdir(root)
                 if os.path.isfile(os.path.join(root, f)))
    if top_py or not repos:
        repos.insert(0, (os.path.basename(root) or "(root)", root))
    return repos

def _progress(name):
    def _p(n):
        logger.info(f"[{name}] scanned {n} files…")
    return _p

def _maybe_learn(name, report, state):
    if not (state.learn and kb and isinstance(report, dict) and report.get("policy")):
        return
    try:
        db = kb.load_db(KNOWLEDGE_DB)
        kb.learn_project(db, name, report["policy"])
        kb.save_db(KNOWLEDGE_DB, db)
    except Exception as exc:
        logger.error(f"[learn] {name}: {exc}")

def run_audits(state):
    if not ng:
        logger.error("veritas_core.py not available, skipping audits")
        return
    with state.lock:
        state.audits.clear()
    settings = get_project_settings(state.root)
    jobs = settings.get('jobs', os.cpu_count() or 1)
    cross = settings.get('cross_file', state.cross)
    cache_enabled = settings.get('cache_enabled', True)
    for name, path in discover_repos(state.root, state):
        try:
            logger.info(f"Auditing {name} ...")
            report = ng.audit(path, cross_file=cross, progress=_progress(name),
                              jobs=jobs, use_cache=cache_enabled)
            _maybe_learn(name, report, state)
            state.add_audit({"name": name, "path": path, "report": report})
        except Exception as exc:
            logger.error(f"Error auditing {name}: {exc}")
            state.add_audit({"name": name, "path": path, "error": str(exc)})

def _parse_uploaded_files(content_type, body):
    import email
    if "multipart/form-data" not in content_type:
        return {}
    raw = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    try:
        msg = email.message_from_bytes(raw)
    except Exception:
        return {}
    out = {}
    max_files = 100
    count = 0
    for part in msg.walk():
        if count >= max_files:
            logger.warning("Too many files uploaded, stopping at 100")
            break
        fn = part.get_filename()
        if not fn:
            continue
        try:
            safe_name = _safe_filename(fn)
        except ValueError:
            continue
        data = part.get_payload(decode=True)
        if data is None:
            continue
        try:
            out[safe_name] = data.decode("utf-8", errors="replace")
            count += 1
        except Exception:
            continue
    return out

def audit_folder(folder, state):
    if not ng or not folder or not os.path.isdir(folder):
        return {}
    if state.root != ".":
        folder_abs = os.path.realpath(folder)
        root_abs = os.path.realpath(state.root)
        if not folder_abs.startswith(root_abs):
            return {"name": folder, "path": folder, "error": "folder outside project root"}
    try:
        logger.info(f"Auditing folder {folder} ...")
        settings = get_project_settings(folder)
        jobs = settings.get('jobs', os.cpu_count() or 1)
        cross = settings.get('cross_file', state.cross)
        cache_enabled = settings.get('cache_enabled', True)
        try:
            report = ng.audit(folder, cross_file=cross, jobs=jobs, use_cache=cache_enabled)
        except Exception as e:
            return {"name": folder, "path": folder, "error": f"audit failed: {e}"}
        _maybe_learn(os.path.basename(folder.rstrip("/")) or folder, report, state)
        return {"name": os.path.basename(folder.rstrip("/")) or folder,
                "path": folder, "report": report}
    except Exception as exc:
        return {"name": folder, "path": folder, "error": str(exc)}

def audit_uploaded(files, state):
    tmp = tempfile.mkdtemp(prefix="veritas_upload_")
    try:
        for name, src in files.items():
            safe_name = _safe_filename(name)
            full = os.path.join(tmp, safe_name)
            if not os.path.realpath(full).startswith(os.path.realpath(tmp)):
                logger.error(f"Path traversal attempt: {name}")
                continue
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(src)
        if not ng:
            return {"name": "uploaded", "path": tmp, "error": "veritas_core not available"}
        settings = get_project_settings(state.root)
        jobs = settings.get('jobs', os.cpu_count() or 1)
        cross = settings.get('cross_file', state.cross)
        cache_enabled = settings.get('cache_enabled', True)
        try:
            report = ng.audit(tmp, cross_file=cross, jobs=jobs, use_cache=cache_enabled)
        except Exception as e:
            return {"name": "uploaded", "path": tmp, "error": f"audit failed: {e}"}
        _maybe_learn("uploaded", report, state)
        return {"name": f"загружено ({len(files)} файлов)", "path": tmp, "report": report}
    except Exception as exc:
        return {"name": "загружено", "path": tmp, "error": str(exc)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def clone_and_audit(url, state):
    url = url.strip()
    if len(url) > 512:
        return {"name": url[:60] + "…", "error": "URL слишком длинный (>512)"}
    if not URL_RE.match(url):
        hint = "(ожидается https://github.com/owner/repo)"
        if "/blob/" in url or "/tree/" in url:
            base = url.split("/blob/")[0].split("/tree/")[0]
            hint = f"это ссылка на файл/ветку — используйте сам репозиторий: {base}"
        elif url.rstrip("/").count("/") == 3:
            hint = "не хватает имени репозитория: .../owner/<repo>"
        return {"name": url, "error": f"недопустимый git URL {hint}"}
    if not shutil.which("git"):
        return {"name": url, "error": "git не найден в PATH"}

    # === Очистка старых клонов ===
    clone_dir = os.path.join(tempfile.gettempdir(), ".private", os.getlogin(), "")
    for old in glob.glob(os.path.join(clone_dir, "veritas_clone_*")):
        try:
            shutil.rmtree(old, ignore_errors=True)
        except Exception:
            pass

    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    tmp = tempfile.mkdtemp(prefix="veritas_clone_")
    dest = os.path.join(tmp, name)
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            return {"name": name, "error": "git clone не удался: "
                    + (proc.stderr.strip()[:300] or "неизвестная ошибка")}
        if not ng:
            return {"name": name, "path": url, "error": "veritas_core not available"}
        settings = get_project_settings(dest)
        jobs = settings.get('jobs', os.cpu_count() or 1)
        cross = settings.get('cross_file', state.cross)
        cache_enabled = settings.get('cache_enabled', True)
        try:
            rep = ng.audit(dest, cross_file=cross, progress=_progress(name),
                           jobs=jobs, use_cache=cache_enabled)
        except Exception as e:
            return {"name": name, "path": url, "error": f"audit failed: {e}"}
        _maybe_learn(name, rep, state)
        return {"name": name, "path": url, "report": rep}
    except subprocess.TimeoutExpired:
        return {"name": name, "error": "клонирование превысило 5 мин"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def aggregate(state):
    tot = {"guarded": 0, "unguarded": 0, "unknown": 0, "safe": 0}
    files = 0
    for a in state.get_audits():
        r = a.get("report")
        if not r:
            s = a.get("summary", {})
            t = s.get("totals", {})
            for k in tot:
                tot[k] += t.get(k, 0)
            files += s.get("files_scanned", 0)
            continue
        files += r["files_scanned"]
        for k in tot:
            tot[k] += r["totals"][k]
    determinable = tot["guarded"] + tot["unguarded"]
    cov = round(tot["guarded"] / determinable, 3) if determinable else 0.0
    return {"totals": tot, "files": files, "coverage": cov, "repos": len(state.get_audits())}

def bar(counts):
    total = sum(counts.get(k, 0) for k in SEV_COLOR) or 1
    segs = ""
    for k, color in SEV_COLOR.items():
        pct = counts.get(k, 0) / total * 100
        if pct:
            segs += (f'<i title="{k}: {counts.get(k,0)}" '
                     f'style="width:{pct:.1f}%;background:{color}"></i>')
    return f'<div class="bar">{segs}</div>'

def _sink_fix_code(sink):
    ex = {
        "os.system": ("os.system(f'ping {host}')",
                      "subprocess.run(['ping', host])  # список, без shell"),
        "subprocess.run": ("subprocess.run(f'ls {d}', shell=True)",
                           "subprocess.run(['ls', d])  # без shell=True"),
        "subprocess.Popen": ("Popen(cmd, shell=True)", "Popen([prog, arg])"),
        "eval": ("eval(user_value)", "ast.literal_eval(user_value)"),
        "sqlite3.execute": ("cur.execute(f'... WHERE id={uid}')",
                            "cur.execute('... WHERE id=?', (uid,))"),
        "open": ("open(user_path)",
                 "open(os.path.join(BASE, secure_filename(user_path)))"),
        "yaml.load": ("yaml.load(data)", "yaml.safe_load(data)"),
        "pickle.loads": ("pickle.loads(untrusted)", "json.loads(untrusted)"),
        "requests.get": ("requests.get(user_url)",
                         "assert urlparse(user_url).hostname in ALLOWED\nrequests.get(user_url)"),
    }
    return ex.get(sink)

def _sink_explainer(sink, need):
    g = f"<code>{esc(str(need))}</code>" if need else None
    table = {
        "os.system": ("Внедрение команд ОС (CWE-78)",
            "пользовательский ввод попадает в shell-команду — атакующий может "
            "выполнить произвольные команды (напр. <code>; rm -rf /</code>).",
            "оберните аргумент в <code>shlex.quote()</code> или передавайте "
            "список аргументов без <code>shell=True</code>."),
        "os.popen": ("Внедрение команд ОС (CWE-78)",
            "ввод уходит в shell через popen — те же риски, что и os.system.",
            "используйте <code>subprocess.run([...])</code> со списком аргументов."),
        "subprocess.run": ("Внедрение команд (CWE-78)",
            "ввод в subprocess с риском shell-инъекции.",
            "список аргументов без <code>shell=True</code>, либо <code>shlex.quote()</code>."),
        "subprocess.Popen": ("Внедрение команд (CWE-78)",
            "ввод в Popen с возможной shell-инъекцией.",
            "список аргументов без <code>shell=True</code>."),
        "subprocess.call": ("Внедрение команд (CWE-78)",
            "ввод в subprocess.call с риском shell-инъекции.",
            "список аргументов без <code>shell=True</code>."),
        "eval": ("Выполнение кода (CWE-94)",
            "ввод исполняется как Python-код — полный захват процесса.",
            "используйте <code>ast.literal_eval()</code> для данных; никогда не eval пользовательский ввод."),
        "exec": ("Выполнение кода (CWE-94)",
            "ввод исполняется как код — критическая уязвимость.",
            "уберите exec ввода; используйте безопасный разбор/диспетчер."),
        "sqlite3.execute": ("SQL-инъекция (CWE-89)",
            "запрос собран из ввода строкой — можно подменить логику SQL.",
            "параметризация: <code>execute(\"... WHERE x=?\", (val,))</code>."),
        "sqlite3.executescript": ("SQL-инъекция (CWE-89)",
            "executescript со строкой из ввода исполняет несколько операторов.",
            "избегайте динамического SQL; параметризуйте."),
        "pickle.loads": ("Небезопасная десериализация (CWE-502)",
            "pickle над недоверенными данными выполняет произвольный код.",
            "используйте <code>json</code> для недоверенных данных."),
        "yaml.load": ("Небезопасная десериализация (CWE-502)",
            "yaml.load может конструировать произвольные объекты.",
            "используйте <code>yaml.safe_load()</code>."),
        "marshal.loads": ("Небезопасная десериализация (CWE-502)",
            "marshal над недоверенными данными опасен.",
            "не десериализуйте недоверенные данные через marshal."),
        "open": ("Обход пути (CWE-22)",
            "путь зависит от ввода — возможен доступ к <code>../../etc/passwd</code>.",
            "нормализуйте путь, <code>secure_filename()</code> и фиксированный базовый каталог."),
        "urllib.request.urlopen": ("SSRF (CWE-918)",
            "URL из ввода — запрос к внутренним адресам (метаданные облака).",
            "allowlist схемы/хоста перед запросом."),
        "requests.get": ("SSRF (CWE-918)",
            "URL из ввода — возможен запрос к внутренним ресурсам.",
            "allowlist хостов; запрет приватных диапазонов."),
    }
    what, why, fix = table.get(sink, ("Возможная инъекция",
        "недоверенный источник дотекает до опасного вызова без проверяемого санитайзера.",
        "добавьте подходящий санитайзер для этого типа стока."))
    if g:
        fix = f"нужен guard: {g}. " + fix
    return what, why, fix

# === РЕНДЕРИНГ СТРАНИЦ (оптимизирован) ===
def render_errors(state):
    SEV = {"unguarded": ("#ff4d4f", "Внедрение"), "high-risk": ("#fa8c16", "Опасная конфигурация")}
    rows = ""
    inj_n = cfg_n = 0
    skip = get_project_settings(state.root).get('skip_tests', False)
    for a in state.get_audits():
        rep = a.get("report")
        if not rep:
            continue
        for f in rep.get("findings", []):
            if skip and ('/test_' in f['file'] or '/tests/' in f['file'] or f['file'].endswith('_test.py')):
                continue
            kind = "unguarded" if f["status"] == "unguarded" else "high-risk"
            if kind == "unguarded": inj_n += 1
            else: cfg_n += 1
            color, label = SEV[kind]
            if kind == "unguarded":
                what, why, fix = _sink_explainer(f["sink"], f.get("guard_needed"))
                code = _sink_fix_code(f["sink"])
            else:
                what, why, fix = ("Опасная конфигурация",
                    "источник не прослеживается, но вызов опасен сам по себе "
                    "(<code>shell=True</code> / eval / yaml.load) — проверьте вручную.",
                    "уберите динамику или зафиксируйте безопасные значения.")
                code = None
            snippet = ""
            if code:
                bad, good = code
                snippet = (
                    "<div style='margin-top:6px;display:flex;gap:8px;flex-wrap:wrap'>"
                    f"<div style='flex:1;min-width:170px'><div class='muted small'>"
                    f"✗ так нельзя</div><code style='color:#ff9b9b;display:block;"
                    f"white-space:pre-wrap'>{esc(bad)}</code></div>"
                    f"<div style='flex:1;min-width:170px'><div class='muted small'>"
                    f"✓ так нужно</div><code style='color:#8fe3a8;display:block;"
                    f"white-space:pre-wrap'>{esc(good)}</code></div></div>")
            rows += (
                f"<tr><td><span class='pill' style='background:{color}'>"
                f"{label}</span></td>"
                f"<td class='mono'>{esc(a['name'])}</td>"
                f"<td class='mono small'>{esc(f['file'])}<b>:{f['line']}</b></td>"
                f"<td class='mono'>{esc(f['sink'])}</td>"
                f"<td class='small'><b>{what}</b><br>"
                f"<span class='muted'>{why}</span><br>"
                f"<span style='color:#7fd6a0'>→ {fix}</span>{snippet}</td></tr>")
    if not rows:
        rows = ("<tr><td colspan='5' class='muted'>Нарушений не найдено — "
                "либо чисто, либо движок честно абстрагировался (unknown).</td></tr>")
    sec_rows = ""
    sec_n = 0
    if secrets:
        for a in state.get_audits():
            p = a.get("path")
            if not p or not os.path.isdir(p):
                continue
            try:
                for f in secrets.scan_dir(p):
                    sec_n += 1
                    c = "#ff4d4f" if f["confidence"] == "high" else "#faad14"
                    sec_rows += (
                        f"<tr><td><span class='pill' style='background:{c}'>"
                        f"{f['confidence']}</span></td>"
                        f"<td class='mono'>{esc(a['name'])}</td>"
                        f"<td class='mono small'>{esc(f['file'])}<b>:"
                        f"{f['line']}</b></td><td>{esc(f['type'])}</td>"
                        f"<td class='mono small'>{esc(f['preview'])}</td></tr>")
            except Exception:
                pass
    if not sec_rows:
        sec_rows = ("<tr><td colspan='5' class='muted'>Секретов не найдено "
                    "(placeholder'ы и шаблоны игнорируются).</td></tr>")
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>VeritasCore — ошибки</title><style>{_THEME}</style></head><body>
<header><h1>VeritasCore</h1><nav>
<a href="/">Аудит</a>
<a href="/errors" class="active">⚠ Ошибки</a>
<a href="/veritas_knowledge">🧠 База знаний</a>
<a href="/editor">📝 Редактор</a>
<a href="/settings">⚙️ Настройки</a>
<a href="/api-docs">📘 API</a>
</nav></header>
<div class="wrap">
<div class="cards">
<div class="card"><div class="lbl">Внедрения</div><div class="num" style="color:#ff6b6e">{inj_n}</div></div>
<div class="card"><div class="lbl">Опасные конфиги</div><div class="num" style="color:#ffa940">{cfg_n}</div></div>
<div class="card"><div class="lbl">Секреты</div><div class="num" style="color:#ff6b6e">{sec_n}</div></div>
</div>
<p class="muted">Только доказанные нарушения (<b>unguarded</b>) и опасные конфигурации (<b>high-risk</b>). Случаи <b>unknown</b> сюда не попадают.</p>
<table><thead><tr><th>Тип</th><th>Репозиторий</th><th>Файл:строка</th><th>Сток</th><th>Объяснение</th></tr></thead><tbody>{rows}</tbody></table>
<h2 style="font-size:16px;margin-top:28px">🔑 Секреты и ключи ({sec_n})</h2>
<p class="muted">Высокоточный поиск известных форматов (AWS, GitHub, Google, Stripe, приватные ключи) и захардкоженных паролей. Значения замаскированы.</p>
<table><thead><tr><th>Уверенность</th><th>Репозиторий</th><th>Файл:строка</th><th>Тип</th><th>Превью (маска)</th></tr></thead><tbody>{sec_rows}</tbody></table>
</div></body></html>"""

def render_veritas_knowledge(state):
    rows = ""
    note = ""
    if kb is None:
        note = "<p class='muted'>модуль veritas_knowledge.py недоступен</p>"
    else:
        db = kb.load_db(KNOWLEDGE_DB)
        agg = kb.aggregate(db)
        if not agg:
            note = (f"<p class='muted'>База пуста. Накопите контракты: "
                    f"<code>python3 veritas_core.py &lt;repo&gt; --audit "
                    f"--learn-into {esc(KNOWLEDGE_DB)}</code> на нескольких "
                    f"проверенных проектах.</p>")
        for sink, c in sorted(agg.items()):
            badge = "#52c41a" if c["status"] == "active" else "#faad14"
            rows += (
                f"<tr><td><b>{esc(sink)}</b></td>"
                f"<td>{esc(c['guard'])}</td>"
                f"<td><span class='pill' style='background:{badge}'>"
                f"{c['status']}</span></td>"
                f"<td>{c['n_projects']}</td>"
                f"<td>{round(c['consensus']*100)}%</td>"
                f"<td>{round(c['avg_freq']*100)}%</td>"
                f"<td class='small muted'>{esc(', '.join(c['projects'][:8]))}</td></tr>")
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>VeritasCore — база знаний</title><style>{_THEME}</style></head><body>
<header><h1>VeritasCore</h1><nav>
<a href="/">Аудит</a>
<a href="/errors">⚠ Ошибки</a>
<a href="/veritas_knowledge" class="active">🧠 База знаний</a>
<a href="/editor">📝 Редактор</a>
<a href="/settings">⚙️ Настройки</a>
<a href="/api-docs">📘 API</a>
</nav></header>
<div class="wrap">
<p class="muted">Контракты, выученные из экосистемы. <b>active</b> — прошёл три фильтра (≥{getattr(kb,'MIN_PROJECTS',3)} проектов, согласие ≥ {round(getattr(kb,'MIN_CONSENSUS',0.6)*100)}%, частота ≥ {round(getattr(kb,'MIN_FREQ',0.5)*100)}%) и применяется; <b>quarantine</b> — наблюдается.</p>
{note}
<table><thead><tr><th>Сток</th><th>Guard</th><th>Статус</th><th>Проектов</th><th>Согласие</th><th>Частота</th><th>Откуда (provenance)</th></tr></thead><tbody>{rows}</tbody></table>
</div></body></html>"""

def render_settings(state):
    settings = get_project_settings(state.root)
    content = f"""
<div class="wrap">
 <div class="panel">
  <h2>⚙️ Расширенные настройки проекта</h2>
  <p class="sub">Изменения сохраняются в <code>.veritascore.json</code>.</p>
  <div class="settings-grid">
    <div class="field">
      <label for="max_file_bytes">Максимальный размер файла (байт)</label>
      <input type="number" id="max_file_bytes" value="{settings.get('max_file_bytes', getattr(ng, '_MAX_FILE_BYTES', 1500000))}" min="10000" step="10000">
      <span class="hint">Файлы больше этого размера пропускаются.</span>
    </div>
    <div class="field">
      <label for="parallel_min_files">Минимум файлов для параллелизации</label>
      <input type="number" id="parallel_min_files" value="{settings.get('parallel_min_files', getattr(ng, '_PARALLEL_MIN_FILES', 64))}" min="1">
      <span class="hint">При меньшем количестве файлов анализ выполняется последовательно.</span>
    </div>
    <div class="field">
      <label for="parallel_min_bytes">Минимум байт для параллелизации</label>
      <input type="number" id="parallel_min_bytes" value="{settings.get('parallel_min_bytes', 1_000_000)}" min="100000" step="100000">
      <span class="hint">Общий размер кода для включения параллельного режима.</span>
    </div>
    <div class="field">
      <label for="min_confidence">Минимальная уверенность контракта (0.0 – 1.0)</label>
      <input type="number" id="min_confidence" value="{settings.get('min_confidence', 0.0)}" min="0" max="1" step="0.05">
      <span class="hint">Контракты с уверенностью ниже этого порога не применяются в гейте.</span>
    </div>
    <div class="field">
      <label for="jobs">Количество потоков (jobs)</label>
      <input type="number" id="jobs" value="{settings.get('jobs', 1)}" min="1" max="{os.cpu_count() or 4}">
      <span class="hint">Число параллельных процессов анализа.</span>
    </div>
    <div class="field">
      <label for="max_findings">Максимум находок в отчёте</label>
      <input type="number" id="max_findings" value="{settings.get('max_findings', 500)}" min="1" max="5000">
      <span class="hint">Ограничение количества записей в findings (экономия памяти).</span>
    </div>
    <div class="field" style="grid-column: span 2; display: flex; flex-wrap: wrap; gap: 20px;">
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="cross_file" {'checked' if settings.get('cross_file', False) else ''}> Межфайловый анализ
      </label>
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="secret_scan" {'checked' if settings.get('secret_scan', True) else ''}> Сканирование секретов
      </label>
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="sca" {'checked' if settings.get('sca', False) else ''}> SCA (проверка зависимостей)
      </label>
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="fast" {'checked' if settings.get('fast', False) else ''}> Быстрый режим (--fast)
      </label>
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="cache_enabled" {'checked' if settings.get('cache_enabled', True) else ''}> Кэширование (быстрее при повторах)
      </label>
      <label style="display: flex; align-items: center; gap: 6px;">
        <input type="checkbox" id="skip_tests" {'checked' if settings.get('skip_tests', False) else ''}> Пропускать тестовые файлы
      </label>
    </div>
  </div>
  <button id="save-settings" class="btn primary" style="margin-top:12px">💾 Сохранить настройки</button>
  <span id="settings-status" class="muted" style="margin-left:12px"></span>
 </div>
</div>
<script>
document.getElementById('save-settings').addEventListener('click', async function() {{
    const data = {{
        max_file_bytes: parseInt(document.getElementById('max_file_bytes').value),
        parallel_min_files: parseInt(document.getElementById('parallel_min_files').value),
        parallel_min_bytes: parseInt(document.getElementById('parallel_min_bytes').value),
        min_confidence: parseFloat(document.getElementById('min_confidence').value),
        jobs: parseInt(document.getElementById('jobs').value),
        max_findings: parseInt(document.getElementById('max_findings').value),
        cross_file: document.getElementById('cross_file').checked,
        secret_scan: document.getElementById('secret_scan').checked,
        sca: document.getElementById('sca').checked,
        fast: document.getElementById('fast').checked,
        cache_enabled: document.getElementById('cache_enabled').checked,
        skip_tests: document.getElementById('skip_tests').checked,
    }};
    const status = document.getElementById('settings-status');
    status.textContent = '⏳ Сохранение...';
    try {{
        const resp = await fetch('/save_settings', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(data)
        }});
        if (!resp.ok) {{
            const err = await resp.json();
            throw new Error(err.error || 'Ошибка сохранения');
        }}
        const result = await resp.json();
        if (result.error) throw new Error(result.error);
        status.textContent = '✅ Настройки сохранены. Страница обновится...';
        status.style.color = '#52c41a';
        setTimeout(() => location.reload(), 800);
    }} catch (e) {{
        status.textContent = '❌ Ошибка: ' + e.message;
        status.style.color = '#ff6b6e';
    }}
}});
</script>
"""
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VeritasCore — настройки</title>
<style>{_THEME}</style>
</head>
<body>
<header>
 <h1>VeritasCore</h1>
 <nav>
  <a href="/">Аудит</a>
  <a href="/errors">⚠ Ошибки</a>
  <a href="/veritas_knowledge">🧠 База знаний</a>
  <a href="/editor">📝 Редактор</a>
  <a href="/settings" class="active">⚙️ Настройки</a>
  <a href="/api-docs">📘 API</a>
 </nav>
</header>
{content}
</body></html>"""

def render(state):
    agg_data = aggregate(state)
    cards = "".join(
        f'<div class="card"><div class="num">{v}</div><div>{label}</div></div>'
        for v, label in [
            (agg_data["repos"], "репозиториев"),
            (agg_data["files"], "файлов"),
            (sum(agg_data["totals"].values()), "sink всего"),
            (f'{round(agg_data["coverage"]*100)}%', "покрытие (guarded)"),
        ])
    legend = " ".join(
        f'<span class="pill" style="background:{c}">{k}</span>' for k, c in SEV_COLOR.items())
    skip = get_project_settings(state.root).get('skip_tests', False)
    rows = ""
    for a in state.get_audits():
        if a.get("error"):
            rows += (f'<tr><td>{esc(a["name"])}</td><td colspan="6" '
                     f'class="err">ошибка: {esc(a["error"])}</td></tr>')
            continue
        r = a.get("report")
        if not r:
            s = a.get("summary", {})
            t = s.get("totals", {})
            cov = round(s.get("coverage", 0) * 100)
            files_scanned = s.get("files_scanned", "?")
            contracts = "—"
            worst = "—"
        else:
            t = r["totals"]
            cov = round(r["coverage"] * 100)
            files_scanned = r["files_scanned"]
            def _contract(s, c):
                g = c.get("guard")
                if not g:
                    return f"{esc(s)}→—"
                if c.get("count", 0) == 0 and not c.get("confidence"):
                    return f"{esc(s)}→{esc(g)} (по умолчанию)"
                return f"{esc(s)}→{esc(g)} ({round(c.get('confidence',0)*100)}%)"
            contracts = ", ".join(_contract(s, c)
                                  for s, c in sorted(r["by_sink"].items())) or "—"
            worst_files = r.get("files", [])
            if skip:
                worst_files = [f for f in worst_files if not ('/test_' in f.get('file','') or '/tests/' in f.get('file','') or f.get('file','').endswith('_test.py'))]
            worst = "<br>".join(
                f'{esc(f["file"])} <span class="muted">U={f["unguarded"]} ?={f["unknown"]}</span>'
                for f in worst_files[:5]) or '<span class="muted">—</span>'
        rows += (
            f'<tr><td><b>{esc(a["name"])}</b><div class="muted small">{esc(a["path"])}</div></td>'
            f'<td>{files_scanned}</td>'
            f'<td>{sum(t.values())}</td>'
            f'<td>{cov}%</td>'
            f'<td style="min-width:160px">{bar(t)}</td>'
            f'<td class="small">{contracts}</td>'
            f'<td class="small">{worst}</td></tr>')

    welcome = ""
    if not rows:
        welcome = (
            "<div class='card' style='margin-bottom:18px;padding:22px 24px'>"
            "<h2 style='margin:0 0 8px'>Добро пожаловать в VeritasCore 👋</h2>"
            "<p class='muted' style='margin:0 0 14px'>Анализатор безопасности "
            "Python с упором на низкий уровень ложных срабатываний. Начните "
            "одним из трёх способов.</p>"
            "<div style='display:flex;gap:16px;flex-wrap:wrap'>"
            "<div style='flex:1;min-width:200px'><b>⤵ Проверить GitHub</b>"
            "<div class='muted small'>вставьте URL репозитория в поле сверху</div></div>"
            "<div style='flex:1;min-width:200px'><b>📁 Анализ папки</b>"
            "<div class='muted small'>укажите путь к локальному проекту</div></div>"
            "<div style='flex:1;min-width:200px'><b>📂 Загрузить .py</b>"
            "<div class='muted small'>выберите один или несколько файлов</div></div>"
            "</div>"
            "<p class='muted small' style='margin:14px 0 0'>После анализа "
            "откройте <a href='/errors'>⚠ Ошибки</a> или <a href='/editor'>📝 Редактор</a>.</p>"
            "</div>")

    results = ""
    if rows:
        results = (
            f'<div class="cards">{cards}</div>'
            f'<div style="margin-bottom:10px">{legend}</div>'
            '<div class="panel"><h2>Результаты аудита</h2>'
            '<table><thead><tr><th>Репозиторий</th><th>Файлов</th><th>Sink</th>'
            '<th>Покрытие</th><th>Статусы</th><th>Контракты</th>'
            f'<th>Худшие файлы</th></tr></thead><tbody>{rows}</tbody></table>'
            '<p class="muted small" style="margin-top:14px">'
            'guarded — обёрнут в guard · unguarded — внешний ввод без guard · '
            'unknown — поток не прослеживается, не блокируется · '
            'safe — константа. JSON: <code>/api</code></p></div>')

    ln_on, ln_off = ("sw on", "sw off") if state.learn else ("sw off", "sw on")
    xf_on, xf_off = ("sw on", "sw off") if state.cross else ("sw off", "sw on")

    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VeritasCore — анализатор безопасности</title>
<style>{_THEME}</style>
</head>
<body>
<header>
 <h1>VeritasCore</h1>
 <nav>
  <a href="/" class="active">Аудит</a>
  <a href="/errors">⚠ Ошибки</a>
  <a href="/veritas_knowledge">🧠 База знаний</a>
  <a href="/editor">📝 Редактор</a>
  <a href="/settings">⚙️ Настройки</a>
  <a href="/api-docs">📘 API</a>
 </nav>
 <a class="btn" href="/rescan" style="margin-left:auto">⟳ Пересканировать</a>
</header>
<div class="wrap">
 {welcome}
 <div class="panel">
  <h2>Запустить анализ</h2>
  <p class="sub">Выберите источник кода — результаты появятся во вкладке «Ошибки».</p>
  <div class="methods">
   <div class="method">
    <div class="mlabel">⤵ GitHub репозиторий</div>
    <div class="mhint">Вставьте ссылку — VeritasCore склонирует и проверит репозиторий.</div>
    <form action="/clone" method="get">
     <input name="url" placeholder="https://github.com/owner/repo" required>
     <button type="submit" class="primary">Проверить</button>
    </form>
   </div>
   <div class="method">
    <div class="mlabel">📁 Локальная папка</div>
    <div class="mhint">Укажите путь к проекту. Подходит для больших кодовых баз.</div>
    <form action="/scan" method="get">
     <input name="path" placeholder="/путь/к/проекту">
     <button type="submit" class="primary">Анализ папки</button>
    </form>
   </div>
   <div class="method">
    <div class="mlabel">📂 Загрузить файлы</div>
    <div class="mhint">Выберите один или несколько .py файлов с компьютера.</div>
    <form action="/upload" method="post" enctype="multipart/form-data">
     <input type="file" name="files" accept=".py" multiple
       style="color:#9aa0a6;font-size:12px">
     <button type="submit" class="accent">Загрузить</button>
    </form>
   </div>
  </div>
 </div>
 <div class="panel">
  <h2>Базовые настройки</h2>
  <div class="toggle">
   <div class="tinfo"><div class="tname">🎓 Обучение контрактам</div>
    <div class="tdesc">Запоминать guard-контракты из сканируемых репозиториев в базу знаний.</div></div>
   <a class="{ln_on}" href="/toggle_learn">{'ВКЛ' if state.learn else 'выкл'}</a>
  </div>
  <div class="toggle">
   <div class="tinfo"><div class="tname">⇄ Межфайловый анализ</div>
    <div class="tdesc">Прослеживать поток между файлами (источники и санитайзеры из общих модулей).</div></div>
   <a class="{xf_on}" href="/toggle_cross">{'ВКЛ' if state.cross else 'выкл'}</a>
  </div>
 </div>
 <div class="panel">
  <h2>🤝 Командная работа</h2>
  <p class="sub">Готовые команды для CI и совместной работы.</p>
  <div class="methods">
   <div class="method">
    <div class="mlabel">Только изменённое (PR / коммит)</div>
    <div class="mhint">Проверить файлы, изменённые относительно ветки.</div>
    <code style="display:block;white-space:pre-wrap">veritas_core.py . --changed
veritas_core.py . --since main</code>
   </div>
   <div class="method">
    <div class="mlabel">Pre-commit хук</div>
    <div class="mhint">Блокирует коммит при доказанной уязвимости в изменениях.</div>
    <code style="display:block;white-space:pre-wrap">cp hooks/pre-commit \\
  .git/hooks/pre-commit</code>
   </div>
   <div class="method">
    <div class="mlabel">CI (GitHub Actions)</div>
    <div class="mhint">Готовый workflow — гейт безопасности на каждый push/PR.</div>
    <code style="display:block;white-space:pre-wrap">.github/workflows/veritas.yml</code>
   </div>
   <div class="method">
    <div class="mlabel">Скоростной режим</div>
    <div class="mhint">Все ядра, быстрый скан больших репозиториев.</div>
    <code style="display:block;white-space:pre-wrap">veritas_core.py . --audit --fast</code>
   </div>
  </div>
 </div>
 {results}
</div></body></html>"""

def render_editor(state):
    projects_list = list(state.get_projects().keys())
    js_code = """
  require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.39.0/min/vs' } });
  let editor;
  require(['vs/editor/editor.main'], function () {
    editor = monaco.editor.create(document.getElementById('monaco-holder'), {
      value: '# Выберите проект и файл',
      language: 'python',
      theme: 'vs-dark',
      automaticLayout: true,
      minimap: { enabled: false },
      fontSize: 13,
      lineNumbers: 'on',
      scrollBeyondLastLine: false
    });
  });

  let currentProject = null;
  let currentFile = null;
  let currentContent = '';

  function addIssue(f) {
    const div = document.createElement('div');
    div.className = 'issue';
    div.dataset.file = f.file;
    div.dataset.line = f.line;
    div.dataset.sink = f.sink;
    div.dataset.guard = f.guard_needed || '';

    const lineSpan = document.createElement('span');
    lineSpan.className = 'line';
    lineSpan.textContent = f.file + ':' + f.line;
    lineSpan.onclick = () => goToLine(f.file, f.line);
    div.appendChild(lineSpan);

    const msgSpan = document.createElement('span');
    msgSpan.className = 'msg';
    const severity = f.status === 'unguarded' ? '🔴' : '🟠';
    msgSpan.textContent = severity + ' ' + f.sink + ' — ' + f.status + (f.guard_needed ? ' (нужен ' + f.guard_needed + ')' : '');
    div.appendChild(msgSpan);

    if (f.guard_needed) {
      const btn = document.createElement('button');
      btn.className = 'fix-btn btn';
      btn.style.cssText = 'font-size:11px;padding:2px 8px';
      btn.textContent = 'Исправить';
      btn.onclick = () => applyFix(f.file, f.line, f.sink, f.guard_needed);
      div.appendChild(btn);
    }
    return div;
  }

  document.getElementById('load-project').addEventListener('click', async () => {
    const pid = document.getElementById('project-select').value;
    if (!pid) { alert('Выберите проект'); return; }
    currentProject = pid;
    document.getElementById('status-msg').textContent = 'Загрузка файлов...';
    try {
      const resp = await fetch(`/api/project/${pid}/files`);
      if (!resp.ok) throw new Error('Failed to load files');
      const files = await resp.json();
      const list = document.getElementById('file-list');
      list.innerHTML = '';
      files.forEach(f => {
        const div = document.createElement('div');
        div.className = 'file';
        div.textContent = f;
        div.dataset.path = f;
        div.addEventListener('click', () => loadFile(pid, f));
        list.appendChild(div);
      });
      document.getElementById('status-msg').textContent = `Загружено ${files.length} файлов`;
    } catch (e) {
      document.getElementById('status-msg').textContent = 'Ошибка: ' + e.message;
    }
  });

  async function loadFile(pid, path) {
    currentFile = path;
    document.getElementById('status-msg').textContent = `Загрузка ${path}...`;
    try {
      const resp = await fetch(`/api/project/${pid}/file/${encodeURIComponent(path)}`);
      if (!resp.ok) throw new Error('Failed to load file');
      const content = await resp.text();
      currentContent = content;
      if (editor) {
        editor.setValue(content);
        monaco.editor.setModelMarkers(editor.getModel(), 'veritas', []);
      }
      document.getElementById('current-file').textContent = path;
      document.getElementById('status-msg').textContent = `Файл ${path} загружен`;
      document.querySelectorAll('.file').forEach(el => el.classList.remove('active'));
      const active = document.querySelector(`.file[data-path="${path}"]`);
      if (active) active.classList.add('active');
    } catch (e) {
      document.getElementById('status-msg').textContent = 'Ошибка: ' + e.message;
    }
  }

  document.getElementById('save-file').addEventListener('click', async () => {
    if (!currentProject || !currentFile) { alert('Нет открытого файла'); return; }
    const content = editor ? editor.getValue() : '';
    try {
      const resp = await fetch(`/api/project/${currentProject}/file/${encodeURIComponent(currentFile)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: content
      });
      if (!resp.ok) throw new Error('Save failed');
      document.getElementById('status-msg').textContent = 'Файл сохранён';
    } catch (e) {
      document.getElementById('status-msg').textContent = 'Ошибка сохранения: ' + e.message;
    }
  });

  document.getElementById('analyze-btn').addEventListener('click', async () => {
    if (!currentProject) { alert('Выберите проект'); return; }
    document.getElementById('status-msg').textContent = 'Анализ запущен...';
    try {
      const resp = await fetch(`/api/project/${currentProject}/analyze`, { method: 'POST' });
      if (!resp.ok) throw new Error('Analysis failed');
      const report = await resp.json();
      const panel = document.getElementById('issues-panel');
      const findings = report.findings || [];
      panel.innerHTML = '';
      if (findings.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.style.padding = '8px';
        empty.textContent = '✅ Нарушений не найдено';
        panel.appendChild(empty);
      } else {
        findings.forEach(f => {
          const el = addIssue(f);
          panel.appendChild(el);
        });
        if (editor) {
          const model = editor.getModel();
          if (model) {
            const markers = findings.filter(f => f.file === currentFile).map(f => ({
              severity: monaco.MarkerSeverity.Error,
              startLineNumber: f.line,
              endLineNumber: f.line,
              startColumn: 1,
              endColumn: 1000,
              message: `${f.sink} — ${f.status} ${f.guard_needed ? '(нужен ' + f.guard_needed + ')' : ''}`,
              source: 'veritas'
            }));
            monaco.editor.setModelMarkers(model, 'veritas', markers);
          }
        }
      }
      document.getElementById('status-msg').textContent = 'Анализ завершён';
    } catch (e) {
      document.getElementById('status-msg').textContent = 'Ошибка: ' + e.message;
    }
  });

  window.goToLine = function(file, line) {
    if (file !== currentFile) {
      loadFile(currentProject, file).then(() => {
        if (editor) {
          editor.revealLineInCenter(line);
          editor.setPosition({ lineNumber: line, column: 1 });
        }
      });
    } else {
      if (editor) {
        editor.revealLineInCenter(line);
        editor.setPosition({ lineNumber: line, column: 1 });
      }
    }
  };

  window.applyFix = async function(file, line, sink, guard) {
    if (!currentProject) return;
    if (!confirm(`Применить фикс для ${sink} на строке ${line}?`)) return;
    try {
      const resp = await fetch(`/api/project/${currentProject}/fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file, line, sink, guard })
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || 'Fix failed');
      }
      const data = await resp.json();
      if (file === currentFile && editor) {
        editor.setValue(data.new_content);
        currentContent = data.new_content;
        monaco.editor.setModelMarkers(editor.getModel(), 'veritas', []);
      }
      document.getElementById('status-msg').textContent = 'Фикс применён';
      document.getElementById('analyze-btn').click();
    } catch (e) {
      document.getElementById('status-msg').textContent = 'Ошибка фикса: ' + e.message;
    }
  };

  document.getElementById('refresh-projects').addEventListener('click', async () => {
    location.reload();
  });
"""
    html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VeritasCore — Редактор</title>
<style>{_THEME}</style>
<link rel="stylesheet" data-name="vs/editor/editor.main" href="https://cdn.jsdelivr.net/npm/monaco-editor@0.39.0/min/vs/editor/editor.main.min.css">
<script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.39.0/min/vs/loader.js"></script>
</head>
<body>
<header>
 <h1>VeritasCore</h1>
 <nav>
  <a href="/">Аудит</a>
  <a href="/errors">⚠ Ошибки</a>
  <a href="/veritas_knowledge">🧠 База знаний</a>
  <a href="/editor" class="active">📝 Редактор</a>
  <a href="/settings">⚙️ Настройки</a>
  <a href="/api-docs">📘 API</a>
 </nav>
 <div style="flex:1"></div>
 <button id="refresh-projects" class="btn" style="font-size:12px">⟳ Обновить проекты</button>
</header>
<div class="wrap">
 <div class="panel" style="margin-bottom:12px">
  <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
    <label style="font-weight:600">Проект:</label>
    <select id="project-select" style="flex:1;min-width:200px;background:#0d1017;border:1px solid #2c3344;border-radius:6px;padding:6px 10px;color:#e7e9ee">
      <option value="">-- выберите проект --</option>
      {''.join(f'<option value="{p}">{esc(state.get_project(p)["name"])}</option>' for p in projects_list)}
    </select>
    <button id="load-project" class="btn primary" style="font-size:12px">Загрузить</button>
    <button id="analyze-btn" class="btn accent" style="font-size:12px">🔍 Анализировать</button>
    <span id="status-msg" class="muted" style="font-size:13px"></span>
  </div>
 </div>
 <div class="editor-layout">
  <div class="file-tree" id="file-tree">
    <div style="font-weight:600;margin-bottom:8px;color:#9aa0a6">Файлы</div>
    <div id="file-list"></div>
  </div>
  <div class="editor-container">
    <div class="editor-toolbar">
      <span class="filename" id="current-file">(нет файла)</span>
      <button id="save-file" class="btn" style="font-size:12px">💾 Сохранить</button>
    </div>
    <div class="monaco-editor-holder" id="monaco-holder"></div>
    <div class="issues-panel" id="issues-panel">
      <div class="muted" style="padding:8px">Нажмите «Анализировать», чтобы увидеть проблемы.</div>
    </div>
  </div>
 </div>
</div>
<script>
{js_code}
</script>
</body></html>"""
    return html

def render_api_docs():
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>VeritasCore API</title><style>{_THEME}</style></head><body>
<header><h1>VeritasCore</h1><nav>
<a href="/">Аудит</a>
<a href="/errors">⚠ Ошибки</a>
<a href="/veritas_knowledge">🧠 База знаний</a>
<a href="/editor">📝 Редактор</a>
<a href="/settings">⚙️ Настройки</a>
<a href="/api-docs" class="active">📘 API</a>
</nav></header>
<div class="wrap">
<h2>API VeritasCore Web</h2>
<p class="muted">Все ответы в JSON, если не указано иное.</p>

<h3>GET /api</h3>
<p>Возвращает список аудитов (сводки).</p>

<h3>GET /api/projects</h3>
<p>Список проектов (id, name, path).</p>

<h3>GET /api/project/&lt;pid&gt;/files</h3>
<p>Список .py файлов проекта (относительные пути).</p>

<h3>GET /api/project/&lt;pid&gt;/file/&lt;path&gt;</h3>
<p>Содержимое файла (text/plain). Путь должен быть URL-кодирован.</p>

<h3>POST /api/project/&lt;pid&gt;/analyze</h3>
<p>Запускает аудит проекта и возвращает отчёт.</p>

<h3>POST /api/project/&lt;pid&gt;/fix</h3>
<p>Применяет автофикс. Тело: <code>{{"file": "...", "line": 10, "sink": "...", "guard": "..."}}</code>.
Возвращает дифф и новое содержимое.</p>

<h3>POST /save_settings</h3>
<p>Сохраняет настройки в .veritascore.json. Тело: все поля настроек.</p>

<h3>Загрузка файлов</h3>
<p>POST /upload (multipart/form-data). Возвращает редирект на /errors.</p>

<h3>Клонирование и сканирование</h3>
<p>GET /clone?url=... (редирект на /errors), GET /scan?path=... (редирект на /errors).</p>
</div></body></html>"""

# === HTTP ОБРАБОТЧИК (с поддержкой очистки клонов) ===
class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, state=None, **kwargs):
        self.state = state
        super().__init__(*args, **kwargs)

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            logger.error(f"Send error: {e}")

    def _send_error_json(self, msg, code=400):
        self._send(json.dumps({"error": msg}).encode(), "application/json", code)

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api":
                self._send(json.dumps(self.state.get_audits()).encode(), "application/json")
            elif path == "/api/projects":
                proj_info = {pid: {"name": data["name"], "path": data["path"]} for pid, data in self.state.get_projects().items()}
                self._send(json.dumps(proj_info).encode(), "application/json")
            elif path.startswith("/api/project/") and path.endswith("/files"):
                parts = path.split("/")
                if len(parts) >= 4:
                    pid = parts[3]
                    proj = self.state.get_project(pid)
                    if proj:
                        if 'files_cache' in proj:
                            self._send(json.dumps(proj['files_cache']).encode(), "application/json")
                            return
                        base = proj["path"]
                        py_files = []
                        for root, dirs, files in os.walk(base):
                            for f in files:
                                if f.endswith(".py"):
                                    rel = os.path.relpath(os.path.join(root, f), base)
                                    py_files.append(rel)
                        self.state.update_project(pid, {"files_cache": py_files})
                        self._send(json.dumps(py_files).encode(), "application/json")
                    else:
                        self._send_error_json("Project not found", 404)
            elif path.startswith("/api/project/") and "/file/" in path:
                parts = path.split("/")
                if len(parts) >= 6:
                    pid = parts[3]
                    filepath = unquote("/".join(parts[5:]))
                    proj = self.state.get_project(pid)
                    if proj:
                        try:
                            full = _safe_path(proj["path"], filepath)
                            if os.path.exists(full) and os.path.isfile(full):
                                with open(full, "r", encoding="utf-8") as f:
                                    content = f.read()
                                self._send(content.encode(), "text/plain")
                            else:
                                self._send_error_json("File not found", 404)
                        except ValueError:
                            self._send_error_json("Invalid path", 403)
                    else:
                        self._send_error_json("Project not found", 404)
            elif path == "/editor":
                self._send(render_editor(self.state).encode())
            elif path == "/errors":
                self._send(render_errors(self.state).encode())
            elif path == "/veritas_knowledge":
                self._send(render_veritas_knowledge(self.state).encode())
            elif path == "/settings":
                self._send(render_settings(self.state).encode())
            elif path == "/api-docs":
                self._send(render_api_docs().encode())
            elif path == "/toggle_learn":
                self.state.set_learn(not self.state.learn)
                run_audits(self.state)
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            elif path == "/toggle_cross":
                self.state.set_cross(not self.state.cross)
                run_audits(self.state)
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            elif path == "/rescan":
                run_audits(self.state)
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            elif path == "/clone":
                qs = parse_qs(parsed.query)
                url = (qs.get("url") or [""])[0]
                entry = clone_and_audit(url, self.state)
                if "report" in entry:
                    pid = str(uuid.uuid4())
                    self.state.add_project(pid, {"path": entry["path"], "name": entry["name"], "report": entry["report"], "files_cache": []})
                self.state.add_audit(entry)
                self.send_response(302)
                self.send_header("Location", "/errors")
                self.end_headers()
            elif path == "/scan":
                qs = parse_qs(parsed.query)
                folder = (qs.get("path") or [""])[0].strip()
                entry = audit_folder(folder, self.state)
                if entry and "report" in entry:
                    pid = str(uuid.uuid4())
                    self.state.add_project(pid, {"path": folder, "name": entry["name"], "report": entry["report"], "files_cache": []})
                    self.state.add_audit(entry)
                    self.send_response(302)
                    self.send_header("Location", "/errors")
                else:
                    error_msg = entry.get("error", "unknown error") if entry else "unknown error"
                    self.send_response(302)
                    self.send_header("Location", f"/?error={esc(error_msg)}")
                self.end_headers()
            elif path == "/clear_clones":
                clone_dir = os.path.join(tempfile.gettempdir(), ".private", os.getlogin(), "")
                for old in glob.glob(os.path.join(clone_dir, "veritas_clone_*")):
                    shutil.rmtree(old, ignore_errors=True)
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            elif path in ("/", "/index.html"):
                self._send(render(self.state).encode())
            else:
                self._send(b"not found", "text/plain", 404)
        except Exception as e:
            logger.error(f"GET error: {e}")
            self._send_error_json(str(e), 500)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/upload":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length <= 0 or length > 25 * 1024 * 1024:
                    self.send_response(302)
                    self.send_header("Location", "/?error=file too large")
                    self.end_headers()
                    return
                body = self.rfile.read(length)
                files = _parse_uploaded_files(self.headers.get("Content-Type", ""), body)
                if files:
                    entry = audit_uploaded(files, self.state)
                    if "report" in entry:
                        pid = str(uuid.uuid4())
                        self.state.add_project(pid, {"path": entry["path"], "name": entry["name"], "report": entry["report"], "files_cache": []})
                    self.state.add_audit(entry)
                    self.send_response(302)
                    self.send_header("Location", "/errors")
                else:
                    self.send_response(302)
                    self.send_header("Location", "/?error=no files uploaded")
                self.end_headers()
            elif path == "/save_settings":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0:
                        self._send_error_json("Empty body", 400)
                        return
                    data = json.loads(self.rfile.read(length).decode("utf-8"))
                    save_project_settings(self.state.root, data)
                    self._send(b'{"status":"ok"}', "application/json")
                except json.JSONDecodeError:
                    self._send_error_json("Invalid JSON", 400)
                except ValueError as e:
                    self._send_error_json(str(e), 400)
                except Exception as e:
                    logger.error(f"Save settings error: {e}")
                    self._send_error_json(str(e), 500)
            elif path.startswith("/api/project/") and path.endswith("/analyze"):
                parts = path.split("/")
                if len(parts) >= 4:
                    pid = parts[3]
                    proj = self.state.get_project(pid)
                    if proj and ng:
                        try:
                            settings = get_project_settings(proj["path"])
                            jobs = settings.get("jobs", os.cpu_count() or 1)
                            cross = settings.get("cross_file", self.state.cross)
                            cache_enabled = settings.get('cache_enabled', True)
                            report = ng.audit(proj["path"], cross_file=cross, jobs=jobs, use_cache=cache_enabled)
                            self.state.update_project(pid, {"report": report})
                            self._send(json.dumps(report).encode(), "application/json")
                        except Exception as e:
                            self._send_error_json(str(e), 500)
                    else:
                        self._send_error_json("Project not found", 404)
            elif path.startswith("/api/project/") and path.endswith("/fix"):
                parts = path.split("/")
                if len(parts) >= 4:
                    pid = parts[3]
                    proj = self.state.get_project(pid)
                    if proj and ng:
                        try:
                            length = int(self.headers.get("Content-Length", "0"))
                            if length <= 0:
                                self._send_error_json("Empty body", 400)
                                return
                            data = json.loads(self.rfile.read(length).decode("utf-8"))
                            file = data.get("file")
                            line = data.get("line")
                            sink = data.get("sink")
                            guard = data.get("guard")
                            if not all([file, line, sink, guard]):
                                self._send_error_json("Missing fields", 400)
                                return
                            try:
                                line = int(line)
                            except (ValueError, TypeError):
                                self._send_error_json("'line' must be an integer", 400)
                                return
                            if not ng.is_guard_allowed(sink, guard):
                                self._send_error_json(f"Guard '{guard}' not allowed for sink '{sink}'", 400)
                                return
                            report = proj.get("report")
                            if not report:
                                self._send_error_json("No report for project", 400)
                                return
                            violations = [v for v in report.get("findings", [])
                                          if v.get("file") == file and v.get("line") == line and v.get("sink") == sink]
                            if not violations:
                                self._send_error_json("Violation not found", 404)
                                return
                            try:
                                full_path = _safe_path(proj["path"], file)
                            except ValueError:
                                self._send_error_json("Invalid path", 403)
                                return
                            if not os.path.exists(full_path):
                                self._send_error_json("File not found", 404)
                                return
                            with open(full_path, "r", encoding="utf-8") as f:
                                source = f.read()
                            from veritas_core import Sink, apply_fixes
                            arg = violations[0].get("arg")
                            sink_obj = Sink(name=sink, lineno=line, col=0, end_lineno=line,
                                            args=(arg,) if arg else (), guard=None,
                                            stmt_lineno=line, stmt_col=0, end_col=0,
                                            status="unguarded", risk="")
                            new_source = apply_fixes(source, [(sink_obj, guard)])
                            diff = "".join(difflib.unified_diff(
                                source.splitlines(keepends=True),
                                new_source.splitlines(keepends=True),
                                fromfile="a/"+file, tofile="b/"+file
                            ))
                            with open(full_path, "w", encoding="utf-8") as f:
                                f.write(new_source)
                            self.state.update_project(pid, {"files_cache": None})
                            self._send(json.dumps({"diff": diff, "new_content": new_source}).encode(), "application/json")
                        except Exception as e:
                            self._send_error_json(str(e), 500)
                    else:
                        self._send_error_json("Project not found or veritas_core unavailable", 404)
            else:
                self._send_error_json("Not found", 404)
        except Exception as e:
            logger.error(f"POST error: {e}")
            self._send_error_json(str(e), 500)

    def do_PUT(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path.startswith("/api/project/") and "/file/" in path:
                parts = path.split("/")
                if len(parts) >= 6:
                    pid = parts[3]
                    filepath = unquote("/".join(parts[5:]))
                    proj = self.state.get_project(pid)
                    if proj:
                        try:
                            full = _safe_path(proj["path"], filepath)
                        except ValueError:
                            self._send_error_json("Invalid path", 403)
                            return
                        length = int(self.headers.get("Content-Length", "0"))
                        if length > 0:
                            content = self.rfile.read(length).decode("utf-8")
                            os.makedirs(os.path.dirname(full), exist_ok=True)
                            with open(full, "w", encoding="utf-8") as f:
                                f.write(content)
                            self.state.update_project(pid, {"files_cache": None})
                            self.send_response(204)
                            self.end_headers()
                        else:
                            self.send_response(400)
                            self.end_headers()
                        return
            self._send_error_json("Invalid request", 400)
        except Exception as e:
            logger.error(f"PUT error: {e}")
            self._send_error_json(str(e), 500)

    def log_message(self, *args):
        logger.info(" ".join(str(a) for a in args))

# === ЗАПУСК ===
def main(argv):
    state = AppState()
    port = 8765
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--port" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
            except ValueError:
                print("error: --port expects a number", file=sys.stderr)
                return 2
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        args.append(a)
        i += 1
    explicit = any(a == "--port" for a in argv)
    if args:
        state.root = args[0]
        if not os.path.isdir(state.root):
            print(f"error: not a directory: {state.root}", file=sys.stderr)
            return 2
        logger.info(f"Scanning {os.path.abspath(state.root)} …")
        run_audits(state)
    else:
        logger.info("No folder given — paste a GitHub URL in the dashboard.")

    def handler_factory(*handler_args, **handler_kwargs):
        return Handler(*handler_args, state=state, **handler_kwargs)

    server = None
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), handler_factory)
            port = p
            break
        except OSError:
            if explicit:
                print(f"error: port {p} busy. Use --port <N>", file=sys.stderr)
                return 2
            continue
    if server is None:
        print(f"error: no free port in range {port}-{port+19}", file=sys.stderr)
        return 2

    url = f"http://localhost:{port}/"
    print(f"VeritasCore dashboard: {url}  (Ctrl+C to stop)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0

def cli():
    return main(sys.argv[1:])

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))