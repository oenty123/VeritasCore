#!/usr/bin/env python3
"""veritas_core.py — contract security gate (single file, stdlib only, 3.10+).

Версия 1.0.0 — переименование в VeritasCore, все улучшения точности.
"""
from __future__ import annotations
__version__ = "1.0.0"

import sys, os, ast, json, subprocess, difflib, fnmatch, re, hashlib, shutil, tempfile, time
from collections import defaultdict
from typing import (
    NamedTuple, Optional, Iterator, Dict, List, Set, Tuple, Any, Union, Callable
)

print(f"DEBUG: loaded veritas_core.py version {__version__} (ultimate)", file=sys.stderr)

# ============================================================================
#  КОНСТАНТЫ И НАСТРОЙКИ
# ============================================================================
SINKS = {
    "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "sqlite3.execute", "sqlite3.executescript",
    "eval", "exec",
    "open",
    "pickle.loads", "pickle.load",
    "yaml.load", "yaml.unsafe_load", "yaml.full_load", "yaml.safe_load",
    "marshal.loads",
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request",
    "urllib.request.urlopen", "httpx.get", "httpx.post",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
    "cryptography.hazmat.primitives.hashes.MD5",
    "cryptography.hazmat.primitives.hashes.SHA1",
    "urllib3.disable_warnings",
    "render_template_string", "flask.render_template_string",
    "jinja2.Template", "django.template.Template",
    "lxml.etree.parse", "lxml.etree.fromstring",
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
    "json.loads",
    "hashlib.md5", "hashlib.sha1", "hashlib.sha224", "hashlib.sha256",
    "Crypto.Cipher.AES.new",
    "sqlalchemy.text", "sqlalchemy.sql.text",
    "django.db.models.query.QuerySet.raw",
    "django.db.models.manager.Manager.raw",
    "hashlib.pbkdf2_hmac",
}

SINK_PRIMARY_ARG = {
    "requests.get": 0, "requests.post": 0, "requests.put": 0,
    "requests.patch": 0, "requests.delete": 0, "requests.head": 0,
    "requests.request": 1, "urllib.request.urlopen": 0,
    "httpx.get": 0, "httpx.post": 0,
    "aiohttp.ClientSession.get": 0, "aiohttp.ClientSession.post": 0,
    "render_template_string": 0, "flask.render_template_string": 0,
    "jinja2.Template": 0, "django.template.Template": 0,
    "lxml.etree.parse": 0, "lxml.etree.fromstring": 0,
    "xml.etree.ElementTree.parse": 0, "xml.etree.ElementTree.fromstring": 0,
    "json.loads": 0,
    "hashlib.md5": 0, "hashlib.sha1": 0, "hashlib.sha224": 0, "hashlib.sha256": 0,
    "sqlalchemy.text": 0, "sqlalchemy.sql.text": 0,
    "django.db.models.query.QuerySet.raw": 0,
    "django.db.models.manager.Manager.raw": 0,
    "hashlib.pbkdf2_hmac": 1,
}

DEFAULT_GUARDS = {
    "os.system": "shlex.quote",
    "os.popen": "shlex.quote",
    "subprocess.call": "shlex.quote",
    "subprocess.run": "shlex.quote",
    "subprocess.Popen": "shlex.quote",
    "eval": "ast.literal_eval",
    "exec": "ast.literal_eval",
    "pickle.loads": "json.loads",
    "pickle.load": "json.loads",
    "yaml.load": "yaml.safe_load",
    "yaml.unsafe_load": "yaml.safe_load",
    "yaml.full_load": "yaml.safe_load",
    "yaml.safe_load": "yaml.safe_load",
    "marshal.loads": "json.loads",
    "sqlite3.execute": "parameterized",
    "sqlite3.executescript": "parameterized",
    "open": "secure_filename",
    "requests.get": None,
    "requests.post": None,
    "render_template_string": None,
    "jinja2.Template": "escape",
    "django.template.Template": "escape",
    "json.loads": None,
    "lxml.etree.parse": None,
    "hashlib.md5": None,
    "hashlib.sha1": None,
    "sqlalchemy.text": "parameterized",
    "sqlalchemy.sql.text": "parameterized",
    "django.db.models.query.QuerySet.raw": "parameterized",
    "django.db.models.manager.Manager.raw": "parameterized",
    "hashlib.pbkdf2_hmac": None,
}

SEVERITY = {
    "os.system": "high", "subprocess.call": "high", "subprocess.run": "high",
    "subprocess.Popen": "high", "eval": "critical", "exec": "critical",
    "pickle.loads": "high", "yaml.load": "medium", "sqlite3.execute": "medium",
    "open": "low",
    "hashlib.md5": "medium", "hashlib.sha1": "medium",
    "sqlalchemy.text": "medium", "django.db.models.query.QuerySet.raw": "medium",
    "hashlib.pbkdf2_hmac": "medium",
}

DEFAULT_IGNORE = [
    "__pycache__", "*.pyc", ".git", ".venv", "venv", "node_modules",
    "build", "dist", ".tox", "*_pb2.py", "migrations",
]

SELF = os.path.basename(__file__)

GUARDED, UNGUARDED, UNKNOWN, SAFE = "guarded", "unguarded", "unknown", "safe"
_MAX_DEPTH = 10
_MAX_CALL_DEPTH = 3           # глубина межпроцедурного анализа
_MAX_FILE_BYTES = 1_500_000
_PARALLEL_MIN_FILES = 64
_PARALLEL_MIN_BYTES = 1_000_000
_INTERPROC_MAX_CHARS = 1_000_000
SKIP = "# veritas-core: skip"
_SQL_RESOLVE_DEPTH = 5        # была 3

CMD_GUARDS = {"shlex.quote", "shlex.split", "shlex.join", "pipes.quote", "quote"}
SINK_GUARD_ALLOW = {
    "os.system": CMD_GUARDS, "os.popen": CMD_GUARDS,
    "subprocess.run": CMD_GUARDS, "subprocess.call": CMD_GUARDS,
    "subprocess.Popen": CMD_GUARDS, "subprocess.check_output": CMD_GUARDS,
    "subprocess.check_call": CMD_GUARDS,
    "eval": {"ast.literal_eval"}, "exec": {"ast.literal_eval"},
    "pickle.loads": set(), "pickle.load": set(),
    "yaml.load": set(), "yaml.unsafe_load": set(), "yaml.full_load": set(),
    "yaml.safe_load": set(), "marshal.loads": set(),
    "open": {"secure_filename", "werkzeug.utils.secure_filename"},
    "requests.get": set(), "requests.post": set(), "requests.put": set(),
    "requests.patch": set(), "requests.delete": set(), "requests.head": set(),
    "requests.request": set(), "urllib.request.urlopen": set(),
    "httpx.get": set(), "httpx.post": set(),
    "aiohttp.ClientSession.get": set(), "aiohttp.ClientSession.post": set(),
    "cryptography.hazmat.primitives.hashes.MD5": set(),
    "cryptography.hazmat.primitives.hashes.SHA1": set(),
    "urllib3.disable_warnings": set(),
    "render_template_string": set(), "flask.render_template_string": set(),
    "jinja2.Template": {"escape", "markupsafe.escape"},
    "django.template.Template": {"escape"},
    "lxml.etree.parse": set(), "lxml.etree.fromstring": set(),
    "xml.etree.ElementTree.parse": set(), "xml.etree.ElementTree.fromstring": set(),
    "json.loads": set(), "hashlib.md5": set(), "hashlib.sha1": set(),
    "sqlalchemy.text": set(), "sqlalchemy.sql.text": set(),
    "django.db.models.query.QuerySet.raw": set(),
    "django.db.models.manager.Manager.raw": set(),
    "hashlib.pbkdf2_hmac": set(),
}

NON_GUARDS = {
    "str", "repr", "int", "float", "bool", "list", "dict", "tuple", "set",
    "len", "bytes", "bytearray", "format", "print", "type", "id",
    "os.path.join", "os.path.dirname", "os.path.basename", "os.path.abspath",
    "os.path.normpath", "os.path.expanduser", "pathlib.Path", "Path",
    "escape", "markupsafe.escape",
}
NUMERIC_SAFE = {"int", "float", "bool", "len", "ord", "hash", "abs", "round",
                "id", "divmod", "complex"}
TAINT_METHODS = {
    "split", "rsplit", "strip", "lstrip", "rstrip", "lower", "upper", "title",
    "capitalize", "swapcase", "replace", "encode", "decode", "expandtabs",
    "splitlines", "format_map", "removeprefix", "removesuffix",
}
_SCOPE_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_PLACEHOLDER = re.compile(r"\?|:\w+|%\(?\w*\)?s|\$\d+")
OPEN_GUARDS = {"secure_filename", "werkzeug.utils.secure_filename"}

# Расширенные источники
SOURCES = {
    "input", "os.getenv", "os.environ.get", "sys.argv", "getpass.getpass",
    "sys.stdin.read",
    "request.args.get", "request.form.get", "request.values.get",
    "request.cookies.get", "request.headers.get", "request.get_json",
    "request.get_data",
    "flask.request.args.get",
    "request.GET.get", "request.POST.get", "request.META.get",
    "request.query_params.get", "request.path_params.get",
    "request.query.get", "request.post.get",
    "self.get_argument", "self.get_body_argument",
    "req.get_param",
    "request.files.get", "request.stream.read",
    "fastapi.Request.body", "fastapi.Request.query_params",
    "self.request.body", "self.request.query",
    "self.get_body_argument", "self.get_query_argument",
    # Новые из популярных фреймворков
    "starlette.requests.Request.query_params",
    "fastapi.Request.path_params",
    "django.http.HttpRequest.body",
    "tornado.web.RequestHandler.get_query_argument",
    "aiohttp.web.Request.query",
    "sanic.request.Request.args",
    "falcon.Request.params",
}
SOURCE_ATTRS = {
    "request.data", "request.json", "request.form", "request.values",
    "request.cookies", "request.headers", "request.body", "request.text",
    "request.args", "request.GET", "request.POST", "request.META",
    "request.files", "request.stream",
    "flask.request.data", "sys.stdin",
    "request.query_params", "request.path_params", "request.query", "request.post",
    "req.params", "req.media", "req.stream", "self.request.body",
    "req._params", "req.params",
    "django.request.FILES", "fastapi.Request.body",
    "starlette.requests.Request.query_params",
    "fastapi.Request.path_params",
    "django.http.HttpRequest.body",
    "aiohttp.web.Request.query",
    "sanic.request.Request.args",
    "falcon.Request.params",
}
SOURCE_SUBSCRIPTS = {
    "os.environ", "sys.argv", "request.args", "request.form",
    "request.cookies", "request.headers", "request.values",
    "request.GET", "request.POST", "request.META",
    "request.query_params", "request.path_params", "request.query", "request.post",
    "req._params", "req.params",
    "request.files", "request.stream",
    "starlette.requests.Request.query_params",
    "fastapi.Request.path_params",
    "django.http.HttpRequest.body",
    "aiohttp.web.Request.query",
    "sanic.request.Request.args",
    "falcon.Request.params",
}

# ============================================================================
#  УТИЛИТЫ ДЛЯ РАБОТЫ С AST
# ============================================================================
def iter_ast(node: ast.AST) -> Iterator[ast.AST]:
    yield from ast.walk(node)

def call_name(node: ast.AST) -> Optional[str]:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return None

def sink_name(call: ast.Call) -> Optional[str]:
    name = call_name(call)
    if name in SINKS:
        return name
    if name and name.endswith(".execute"):
        return "sqlite3.execute"
    if name and name.endswith(".executescript"):
        return "sqlite3.executescript"
    if name:
        tail = name.rsplit(".", 1)[-1]
        if tail in ("render_template_string",):
            return "render_template_string"
        if tail == "Template":
            if "jinja2" in name or "django" in name:
                return name
            return "jinja2.Template"
        if tail == "new" and len(call.args) >= 1:
            if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                alg = call.args[0].value.lower()
                if alg in ("md5", "sha1", "sha224", "sha256"):
                    return f"hashlib.{alg}"
        if tail == "text" and ("sqlalchemy" in name or name.startswith("sqlalchemy")):
            return "sqlalchemy.text"
        if tail == "raw" and "django.db.models" in name:
            return "django.db.models.query.QuerySet.raw"
        if tail == "pbkdf2_hmac" and "hashlib" in name:
            return "hashlib.pbkdf2_hmac"
    return None

def dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None

def is_constant(expr: ast.AST) -> bool:
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in expr.values)
    if isinstance(expr, ast.BinOp):
        return is_constant(expr.left) and is_constant(expr.right)
    if isinstance(expr, ast.UnaryOp):
        return is_constant(expr.operand)
    return False

def referenced_names(node: ast.AST) -> Set[str]:
    names = set()
    for n in iter_ast(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            names.add(n.id)
    return names

def resolve_type_annotation(ann: ast.AST) -> Optional[str]:
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Subscript):
        if isinstance(ann.value, ast.Name) and ann.value.id in ("Optional", "Union"):
            inner = ann.slice
            if hasattr(inner, 'value'):
                inner = inner.value
            if isinstance(inner, ast.Name):
                return inner.id
            if isinstance(inner, ast.Tuple):
                if inner.elts and isinstance(inner.elts[0], ast.Name):
                    return inner.elts[0].id
    return None

# ============================================================================
#  КОНТЕКСТ АНАЛИЗА (расширен для межпроцедурного анализа)
# ============================================================================
class AnalysisContext:
    def __init__(self):
        self.route_params: Dict[str, Set[str]] = {}
        self.param_annotations: Dict[Tuple[str, str], str] = {}
        self.param_taint: Dict[Tuple[str, str], Tuple[str, Optional[str]]] = {}
        self.attr_taint: Dict[str, Tuple[str, Optional[str]]] = {}
        self.return_taint: Dict[str, Tuple[str, Optional[str]]] = {}
        self.guard_wrappers: Dict[str, str] = {}
        self.cross_taint: Dict[Tuple[str, str], Tuple[str, Optional[str]]] = {}
        self.cross_return: Dict[str, Tuple[str, Optional[str]]] = {}
        self.cross_guard_wrappers: Dict[str, str] = {}
        self.allowed_guards: Optional[Set[str]] = None
        self.module_globals: Dict[str, Tuple[ast.AST, ast.AST]] = {}
        self.scope_assign_cache: Dict[int, Tuple[List[ast.Assign], List[ast.AugAssign]]] = {}
        self.scope_binder_cache: Dict[int, Dict[str, List[Tuple[ast.AST, ast.AST]]]] = {}
        self.own_returns_cache: Dict[int, List[ast.AST]] = {}
        self.scope_mut_cache: Dict[int, Dict[str, List[Tuple[ast.AST, ast.AST]]]] = {}
        self.parent_cache: Dict[int, ast.AST] = {}
        self.global_decl_cache: Dict[int, Set[str]] = {}
        self.nonlocal_decl_cache: Dict[int, Set[str]] = {}
        self._expr_cache: Dict[int, Tuple[str, Optional[str]]] = {}
        # Для межпроцедурного анализа
        self._tree: Optional[ast.AST] = None
        self._func_def_cache: Dict[str, Optional[ast.AST]] = {}

    def clear_caches(self):
        self.scope_assign_cache.clear()
        self.scope_binder_cache.clear()
        self.own_returns_cache.clear()
        self.scope_mut_cache.clear()
        self.parent_cache.clear()
        self.global_decl_cache.clear()
        self.nonlocal_decl_cache.clear()
        self._expr_cache.clear()
        self._func_def_cache.clear()

# ============================================================================
#  ПОТОК ДАННЫХ (исправленная SSA)
# ============================================================================
def scope_assignments(ctx: AnalysisContext, scope_node: ast.AST):
    key = id(scope_node)
    cached = ctx.scope_assign_cache.get(key)
    if cached is None:
        assigns, augs = [], []
        stack = [scope_node]
        while stack:
            node = stack.pop()
            for child in ast.iter_child_nodes(node):
                if child is None: continue
                if isinstance(child, _SCOPE_DEFS):
                    continue
                if isinstance(child, ast.Assign):
                    assigns.append(child)
                elif isinstance(child, ast.AugAssign):
                    augs.append(child)
                stack.append(child)
        cached = (assigns, augs)
        ctx.scope_assign_cache[key] = cached
    return cached

def assignments_in_scope(ctx, scope_node):
    return iter(scope_assignments(ctx, scope_node)[0])

def aug_assignments_in_scope(ctx, scope_node):
    return iter(scope_assignments(ctx, scope_node)[1])

def last_def(ctx, scope_node: ast.AST, name: str, before: Tuple[int, int]):
    best = None
    best_pos = None
    for assign in assignments_in_scope(ctx, scope_node):
        apos = (assign.lineno, assign.col_offset)
        if apos >= before:
            continue
        for target in assign.targets:
            if isinstance(target, ast.Name) and target.id == name:
                if best_pos is None or apos > best_pos:
                    best_pos, best = apos, assign.value
    return best

def control_span(ctx, scope: ast.AST, node: ast.AST):
    parent = ctx.parent_cache.get(id(scope))
    if parent is None:
        def build(parent_node):
            for child in ast.iter_child_nodes(parent_node):
                if child is None: continue
                ctx.parent_cache[id(child)] = parent_node
                build(child)
        build(scope)
        parent = ctx.parent_cache.get(id(scope))
    CTRL = (ast.If, ast.For, ast.While, ast.Try, ast.With,
            getattr(ast, "AsyncFor", ast.For), getattr(ast, "AsyncWith", ast.With),
            ast.Match)
    cur = parent
    while cur is not None and cur is not scope:
        if isinstance(cur, CTRL):
            return (cur.lineno, getattr(cur, "end_lineno", cur.lineno) or cur.lineno)
        cur = ctx.parent_cache.get(id(cur))
    return None

def get_nonlocal_decls(ctx, func):
    key = id(func)
    if key not in ctx.nonlocal_decl_cache:
        names = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Nonlocal):
                names.update(node.names)
        ctx.nonlocal_decl_cache[key] = names
    return ctx.nonlocal_decl_cache[key]

def reaching_values(ctx, scope: ast.AST, name: str, before: Tuple[int, int]):
    hits = []
    for assign in assignments_in_scope(ctx, scope):
        apos = (assign.lineno, assign.col_offset)
        if apos >= before:
            continue
        for target in assign.targets:
            if isinstance(target, ast.Name) and target.id == name:
                span = control_span(ctx, scope, assign)
                conditional = bool(span) and not (span[0] <= before[0] <= span[1])
                hits.append((apos, assign.value, conditional, True))
    for aug in aug_assignments_in_scope(ctx, scope):
        apos = (aug.lineno, aug.col_offset)
        if apos >= before:
            continue
        if isinstance(aug.target, ast.Name) and aug.target.id == name:
            span = control_span(ctx, scope, aug)
            conditional = bool(span) and not (span[0] <= before[0] <= span[1])
            hits.append((apos, aug.value, conditional, False))
    binders = scope_binders(ctx, scope).get(name, [])
    for binder, value in binders:
        apos = (binder.lineno, binder.col_offset)
        if apos >= before:
            continue
        span = control_span(ctx, scope, binder)
        conditional = bool(span) and not (span[0] <= before[0] <= span[1])
        hits.append((apos, value, conditional, True))

    is_global = False
    is_nonlocal = False
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        global_names = get_global_decls(ctx, scope)
        if name in global_names:
            is_global = True
        nonlocal_names = get_nonlocal_decls(ctx, scope)
        if name in nonlocal_names:
            is_nonlocal = True

    # Глобалы: если нет локальных присваиваний и нет биндингов
    if name in ctx.module_globals:
        if is_global:
            node, val = ctx.module_globals[name]
            hits.append(((node.lineno, node.col_offset), val, False, True))
        else:
            has_local_assignment = any(True for assign in assignments_in_scope(ctx, scope)
                                       for target in assign.targets
                                       if isinstance(target, ast.Name) and target.id == name)
            has_local_binding = name in scope_binders(ctx, scope)
            if not (has_local_assignment or has_local_binding):
                node, val = ctx.module_globals[name]
                hits.append(((node.lineno, node.col_offset), val, False, True))

    if is_nonlocal:
        parent_scope = scope
        while True:
            parent = ctx.parent_cache.get(id(parent_scope))
            if parent is None:
                break
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent_scope = parent
                break
            parent_scope = parent
        if parent_scope is not scope:
            parent_hits = reaching_values(ctx, parent_scope, name, before)
            for val in parent_hits:
                hits.append(((0, 0), val, False, True))

    if not hits:
        return []
    hits.sort(key=lambda h: h[0])
    unconditional_repl = [(pos, val) for pos, val, cond, repl in hits if repl and not cond]
    if unconditional_repl:
        return [max(unconditional_repl, key=lambda x: x[0])[1]]
    reaching = []
    for _pos, val, conditional, replaces in reversed(hits):
        reaching.append(val)
        if replaces and not conditional:
            break
    return reaching

def get_global_decls(ctx, func):
    key = id(func)
    if key not in ctx.global_decl_cache:
        names = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Global):
                names.update(node.names)
        ctx.global_decl_cache[key] = names
    return ctx.global_decl_cache[key]

def scope_binders(ctx, scope_node: ast.AST) -> Dict[str, List[Tuple[ast.AST, ast.AST]]]:
    key = id(scope_node)
    cached = ctx.scope_binder_cache.get(key)
    if cached is None:
        result = defaultdict(list)
        def add_targets(tgt, node, value):
            for nm in unpack_names(tgt):
                result[nm].append((node, value))
        stack = [scope_node]
        while stack:
            node = stack.pop()
            for child in ast.iter_child_nodes(node):
                if child is None: continue
                if isinstance(child, _SCOPE_DEFS):
                    continue
                if isinstance(child, (ast.For, getattr(ast, "AsyncFor", ast.For))):
                    add_targets(child.target, child, child.iter)
                elif isinstance(child, ast.Assign):
                    for tgt in child.targets:
                        if isinstance(tgt, (ast.Tuple, ast.List)):
                            add_targets(tgt, child, child.value)
                elif isinstance(child, ast.NamedExpr):
                    if isinstance(child.target, ast.Name):
                        result[child.target.id].append((child, child.value))
                elif isinstance(child, ast.Match):
                    for case in child.cases:
                        pattern = case.pattern
                        if isinstance(pattern, ast.MatchAs) and pattern.name:
                            result[pattern.name].append((pattern, pattern))
                        elif isinstance(pattern, ast.MatchOr):
                            for p in pattern.patterns:
                                if isinstance(p, ast.MatchAs) and p.name:
                                    result[p.name].append((p, p))
                        elif isinstance(pattern, ast.MatchClass):
                            for subpat in pattern.patterns:
                                if isinstance(subpat, ast.MatchAs) and subpat.name:
                                    result[subpat.name].append((subpat, subpat))
                elif isinstance(child, ast.Nonlocal):
                    for name in child.names:
                        result[name].append((child, None))
                stack.append(child)
        cached = dict(result)
        ctx.scope_binder_cache[key] = cached
    return cached

def unpack_names(target: ast.AST):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            yield from unpack_names(e)
    elif isinstance(target, ast.Starred):
        yield from unpack_names(target.value)

def scope_mutations(ctx, scope_node: ast.AST) -> Dict[str, List[Tuple[ast.AST, ast.AST]]]:
    key = id(scope_node)
    cached = ctx.scope_mut_cache.get(key)
    if cached is None:
        result = defaultdict(list)
        stack = [scope_node]
        while stack:
            node = stack.pop()
            for child in ast.iter_child_nodes(node):
                if child is None: continue
                if isinstance(child, _SCOPE_DEFS):
                    continue
                if (isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Attribute)
                        and child.func.attr in {"append", "extend", "insert", "add", "update"}
                        and isinstance(child.func.value, ast.Name)
                        and child.args):
                    result[child.func.value.id].append((child, child.args[0]))
                stack.append(child)
        cached = dict(result)
        ctx.scope_mut_cache[key] = cached
    return cached

def own_returns(ctx, func: ast.AST) -> List[ast.AST]:
    key = id(func)
    cached = ctx.own_returns_cache.get(key)
    if cached is None:
        result = []
        stack = [func]
        while stack:
            node = stack.pop()
            for ch in ast.iter_child_nodes(node):
                if ch is None: continue
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                if isinstance(ch, ast.Return) and ch.value:
                    result.append(ch.value)
                stack.append(ch)
        cached = result
        ctx.own_returns_cache[key] = result
    return cached

# ============================================================================
#  МЕЖПРОЦЕДУРНЫЙ АНАЛИЗ ВЫЗОВОВ (НОВЫЙ)
# ============================================================================
def resolve_call_return(ctx: AnalysisContext, scope: ast.AST, call: ast.Call, depth: int = 0) -> Optional[Tuple[str, Optional[str]]]:
    """Разрешает возвращаемое значение функции (до _MAX_CALL_DEPTH)."""
    if depth > _MAX_CALL_DEPTH:
        return None
    func_name = call_name(call)
    if not func_name:
        return None
    if not hasattr(ctx, '_func_def_cache'):
        ctx._func_def_cache = {}
    if func_name not in ctx._func_def_cache:
        found = None
        tree = getattr(ctx, '_tree', None)
        if tree:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                    found = node
                    break
        ctx._func_def_cache[func_name] = found
    func_def = ctx._func_def_cache.get(func_name)
    if not func_def:
        return None
    rets = own_returns(ctx, func_def)
    if not rets:
        return None
    statuses = []
    for ret_expr in rets:
        st, g = expr_status(ctx, ret_expr, func_def, (call.lineno, call.col_offset), depth + 1)
        statuses.append((st, g))
    return combine_statuses(statuses)

# ============================================================================
#  ОСНОВНЫЕ ФУНКЦИИ АНАЛИЗА
# ============================================================================
def is_source_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and call_name(node) in SOURCES

def is_source_attr(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and dotted_name(node) in SOURCE_ATTRS

def is_source_subscript(node: ast.AST) -> bool:
    return isinstance(node, ast.Subscript) and dotted_name(node.value) in SOURCE_SUBSCRIPTS

def is_guard_call(ctx: AnalysisContext, node: ast.AST) -> bool:
    if node is None:
        return False
    if not (isinstance(node, ast.Call) and any(referenced_names(a) for a in node.args)):
        return False
    name = call_name(node)
    if name is None or name in NON_GUARDS:
        return False
    if ctx.allowed_guards is not None and name not in ctx.allowed_guards:
        return False
    return True

def embedded_guard(ctx: AnalysisContext, expr: ast.AST) -> Optional[str]:
    if expr is None:
        return None
    if is_guard_call(ctx, expr):
        return call_name(expr)
    if isinstance(expr, (ast.IfExp, ast.BoolOp)):
        for child in ast.iter_child_nodes(expr):
            if child is None: continue
            g = embedded_guard(ctx, child)
            if g:
                return g
        return None
    for child in ast.iter_child_nodes(expr):
        if child is None: continue
        g = embedded_guard(ctx, child)
        if g:
            return g
    return None

def combine_statuses(results: List[Tuple[str, Optional[str]]]) -> Tuple[str, Optional[str]]:
    guard = None
    all_guarded = True
    for st, g in results:
        if st == GUARDED:
            if guard is None:
                guard = g
            elif g != guard:
                all_guarded = False
        elif st == UNGUARDED:
            return (UNGUARDED, None)
        elif st == UNKNOWN:
            return (UNKNOWN, None)
        else:
            all_guarded = False
    if all_guarded and guard is not None:
        return (GUARDED, guard)
    if guard is not None:
        return (GUARDED, guard)
    return (SAFE, None)

def expr_status(ctx: AnalysisContext, expr: ast.AST, scope: ast.AST,
                before: Tuple[int, int], depth: int = 0, seen: Set[str] = None) -> Tuple[str, Optional[str]]:
    if seen is None:
        seen = set()
    if expr is None:
        return (UNKNOWN, None)
    cache_key = (id(expr), id(scope), before, depth)
    if cache_key in ctx._expr_cache:
        return ctx._expr_cache[cache_key]

    g = embedded_guard(ctx, expr)
    if g:
        result = (GUARDED, g)
        ctx._expr_cache[cache_key] = result
        return result

    if isinstance(expr, ast.Call):
        if is_source_call(expr):
            result = (UNGUARDED, None)
            ctx._expr_cache[cache_key] = result
            return result
        if call_name(expr) in NUMERIC_SAFE:
            result = (SAFE, None)
            ctx._expr_cache[cache_key] = result
            return result
        if call_name(expr) in NON_GUARDS:
            if not expr.args:
                result = (SAFE, None)
                ctx._expr_cache[cache_key] = result
                return result
            if depth >= _MAX_DEPTH:
                result = (UNKNOWN, None)
                ctx._expr_cache[cache_key] = result
                return result
            res = combine_statuses([expr_status(ctx, a, scope, before, depth+1, seen) for a in expr.args])
            ctx._expr_cache[cache_key] = res
            return res
        if isinstance(expr.func, ast.Attribute) and depth < _MAX_DEPTH:
            method = expr.func.attr
            if method == "format":
                parts = list(expr.args) + [kw.value for kw in expr.keywords]
                if parts:
                    res = combine_statuses([expr_status(ctx, p, scope, before, depth+1, seen) for p in parts])
                    ctx._expr_cache[cache_key] = res
                    return res
            if method == "join":
                if expr.args:
                    res = expr_status(ctx, expr.args[0], scope, before, depth+1, seen)
                    ctx._expr_cache[cache_key] = res
                    return res
            if method in ("get", "getlist", "pop", "setdefault", "values", "keys", "items"):
                recv = expr_status(ctx, expr.func.value, scope, before, depth+1, seen)
                if recv[0] == UNGUARDED:
                    result = (UNGUARDED, None)
                    ctx._expr_cache[cache_key] = result
                    return result
            if method in TAINT_METHODS:
                res = expr_status(ctx, expr.func.value, scope, before, depth+1, seen)
                ctx._expr_cache[cache_key] = res
                return res
        # Межпроцедурный анализ
        resolved = resolve_call_return(ctx, scope, expr, depth)
        if resolved:
            ctx._expr_cache[cache_key] = resolved
            return resolved
        res = propagate_call(ctx, expr)
        ctx._expr_cache[cache_key] = res
        return res

    # Анализ атрибутов: если объект — источник, то и атрибут — источник
    if isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name):
            st, _ = name_status(ctx, expr.value.id, scope, before, depth, seen)
            if st == UNGUARDED:
                result = (UNGUARDED, None)
                ctx._expr_cache[cache_key] = result
                return result
    if isinstance(expr, ast.Subscript):
        if isinstance(expr.value, ast.Name):
            st, _ = name_status(ctx, expr.value.id, scope, before, depth, seen)
            if st == UNGUARDED:
                result = (UNGUARDED, None)
                ctx._expr_cache[cache_key] = result
                return result

    # Только self.attr
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and expr.value.id == "self":
        t = ctx.attr_taint.get(expr.attr)
        if t and t[0] != UNKNOWN:
            result = t
            ctx._expr_cache[cache_key] = result
            return result

    if is_source_attr(expr) or is_source_subscript(expr):
        result = (UNGUARDED, None)
        ctx._expr_cache[cache_key] = result
        return result

    if is_constant(expr):
        result = (SAFE, None)
        ctx._expr_cache[cache_key] = result
        return result

    if isinstance(expr, ast.JoinedStr):
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                g2 = embedded_guard(ctx, v.value)
                if g2:
                    result = (GUARDED, g2)
                    ctx._expr_cache[cache_key] = result
                    return result
        parts = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                continue
            if isinstance(v, ast.FormattedValue):
                val = v.value
                if isinstance(val, ast.Call) and call_name(val) in NUMERIC_SAFE:
                    continue
                if is_constant(val):
                    continue
                parts.append(val)
        if not parts:
            result = (SAFE, None)
            ctx._expr_cache[cache_key] = result
            return result
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([expr_status(ctx, p, scope, before, depth+1, seen) for p in parts])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.BinOp):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([
            expr_status(ctx, expr.left, scope, before, depth+1, seen),
            expr_status(ctx, expr.right, scope, before, depth+1, seen)
        ])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        if depth >= _MAX_DEPTH or not expr.elts:
            result = (UNKNOWN, None) if expr.elts else (SAFE, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([expr_status(ctx, e, scope, before, depth+1, seen) for e in expr.elts])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.IfExp):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([
            expr_status(ctx, expr.body, scope, before, depth+1, seen),
            expr_status(ctx, expr.orelse, scope, before, depth+1, seen)
        ])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.BoolOp):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([expr_status(ctx, v, scope, before, depth+1, seen) for v in expr.values])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.NamedExpr):
        res = expr_status(ctx, expr.value, scope, before, depth, seen)
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.Subscript):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = expr_status(ctx, expr.value, scope, before, depth+1, seen)
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, ast.Dict):
        if depth >= _MAX_DEPTH or not expr.values:
            result = (SAFE, None) if not expr.values else (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        vals = [v for v in expr.values if v is not None]
        if not vals:
            result = (SAFE, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = combine_statuses([expr_status(ctx, v, scope, before, depth+1, seen) for v in vals])
        ctx._expr_cache[cache_key] = res
        return res

    if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = expr_status(ctx, expr.elt, scope, before, depth+1, seen)
        ctx._expr_cache[cache_key] = res
        return res
    if isinstance(expr, ast.DictComp):
        if depth >= _MAX_DEPTH:
            result = (UNKNOWN, None)
            ctx._expr_cache[cache_key] = result
            return result
        res = expr_status(ctx, expr.value, scope, before, depth+1, seen)
        ctx._expr_cache[cache_key] = res
        return res

    names = referenced_names(expr)
    if not names or depth >= _MAX_DEPTH:
        result = (UNKNOWN, None)
        ctx._expr_cache[cache_key] = result
        return result
    statuses = []
    for n in names:
        st, g = name_status(ctx, n, scope, before, depth+1, seen)
        statuses.append((st, g))
    res = combine_statuses(statuses)
    ctx._expr_cache[cache_key] = res
    return res

def name_status(ctx: AnalysisContext, name: str, scope: ast.AST,
                before: Tuple[int, int], depth: int, seen: Set[str]) -> Tuple[str, Optional[str]]:
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if name in ctx.route_params.get(scope.name, set()):
            return (UNGUARDED, None)
        if (scope.name, name) in ctx.param_annotations:
            typ = ctx.param_annotations[(scope.name, name)]
            if typ in ("int", "float", "bool", "complex"):
                return (SAFE, None)
    if name in seen:
        return (UNKNOWN, None)
    if proven_numeric(ctx, name, scope, before):
        return (SAFE, None)
    seen = seen | {name}
    vals = reaching_values(ctx, scope, name, before)
    if not vals:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            t = ctx.param_taint.get((scope.name, name))
            if t and t[0] != UNKNOWN:
                return t
            t = ctx.cross_taint.get((scope.name, name))
            if t and t[0] != UNKNOWN:
                return t
        return (UNKNOWN, None)
    statuses = []
    for val in vals:
        st, g = expr_status(ctx, val, scope, before, depth, seen)
        statuses.append((st, g))
    has_unguarded = any(st == UNGUARDED for st, _ in statuses)
    has_safe_guarded = any(st in (SAFE, GUARDED) for st, _ in statuses)
    if has_unguarded and has_safe_guarded:
        return (UNKNOWN, None)
    if all(st == UNKNOWN for st, _ in statuses):
        return (UNKNOWN, None)
    return combine_statuses(statuses)

def proven_numeric(ctx: AnalysisContext, name: str, scope: ast.AST,
                   before: Tuple[int, int]) -> bool:
    for node in iter_ast(scope):
        if not (isinstance(node, ast.If) and name in isinstance_numeric_names(node.test)):
            continue
        if node.lineno >= before[0]:
            continue
        if isinstance(node.test, ast.Constant) and node.test.value is False:
            continue
        reassign = False
        for n2 in iter_ast(scope):
            if isinstance(n2, ast.Assign):
                for t in n2.targets:
                    if isinstance(t, ast.Name) and t.id == name:
                        if node.lineno < n2.lineno < before[0]:
                            reassign = True
                            break
                if reassign:
                    break
        if not reassign:
            return True
    return False

def isinstance_numeric_names(test: ast.AST) -> Set[str]:
    names = set()
    def check(t):
        if (isinstance(t, ast.Call) and isinstance(t.func, ast.Name)
                and t.func.id == "isinstance" and len(t.args) == 2
                and isinstance(t.args[0], ast.Name)):
            typ = t.args[1]
            typs = typ.elts if isinstance(typ, (ast.Tuple, ast.List)) else [typ]
            if typs and all(isinstance(x, ast.Name) and x.id in ("int", "float", "bool", "complex") for x in typs):
                names.add(t.args[0].id)
        elif isinstance(t, ast.BoolOp) and isinstance(t.op, ast.And):
            for v in t.values:
                check(v)
    check(test)
    return names

def propagate_call(ctx: AnalysisContext, expr: ast.Call) -> Tuple[str, Optional[str]]:
    nm = callee_name(expr)
    if nm:
        gw = ctx.guard_wrappers.get(nm) or ctx.cross_guard_wrappers.get(nm)
        if gw:
            if ctx.allowed_guards is not None and gw in ctx.allowed_guards:
                return (GUARDED, gw)
            else:
                return (UNKNOWN, None)
        t = ctx.return_taint.get(nm) or ctx.cross_return.get(nm)
        if t and t[0] in (UNGUARDED, SAFE):
            return t
    return (UNKNOWN, None)

def callee_name(call: ast.Call) -> Optional[str]:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None

# ============================================================================
#  КЛАССИФИКАЦИЯ СТОКОВ
# ============================================================================
def classify_sql(ctx: AnalysisContext, scope: ast.AST, call: ast.Call) -> Tuple[str, Optional[str]]:
    if not call.args:
        return (SAFE, None)
    has_params = len(call.args) >= 2
    param_keywords = {"parameters", "params", "args"}
    for kw in call.keywords:
        if kw.arg in param_keywords and kw.value is not None:
            has_params = True
            break
    q = resolve_query(ctx, scope, call.args[0], (call.lineno, call.col_offset))

    if isinstance(q, ast.Constant) and isinstance(q.value, str):
        if _PLACEHOLDER.search(q.value):
            return (GUARDED, "parameterized") if has_params else (UNKNOWN, None)
        return (SAFE, None)

    if isinstance(q, ast.JoinedStr):
        for v in q.values:
            if isinstance(v, ast.FormattedValue):
                g = embedded_guard(ctx, v.value)
                if g:
                    return (GUARDED, g)
        unsafe_parts = []
        for v in q.values:
            if isinstance(v, ast.Constant):
                continue
            if isinstance(v, ast.FormattedValue):
                val = v.value
                if isinstance(val, ast.Call) and call_name(val) in NUMERIC_SAFE:
                    continue
                if is_constant(val):
                    continue
                unsafe_parts.append(val)
        if not unsafe_parts:
            return (SAFE, None)
        st, _ = combine_statuses([expr_status(ctx, p, scope, (call.lineno, call.col_offset)) for p in unsafe_parts])
        if st == UNGUARDED:
            return (UNGUARDED, None)
        return (UNKNOWN, None)

    if isinstance(q, ast.BinOp) and isinstance(q.op, ast.Mod):
        left = q.left
        right = q.right
        if isinstance(right, ast.Tuple):
            all_safe = True
            for elt in right.elts:
                if not is_sql_constant(ctx, scope, elt, (call.lineno, call.col_offset)):
                    g = embedded_guard(ctx, elt)
                    if not g:
                        return (UNGUARDED, None)
            return (SAFE, None) if all_safe else (UNKNOWN, None)
        left_const = is_sql_constant(ctx, scope, left, (call.lineno, call.col_offset))
        right_const = is_sql_constant(ctx, scope, right, (call.lineno, call.col_offset))
        if left_const and right_const:
            return (SAFE, None)
        if left_const and not right_const:
            g = embedded_guard(ctx, right)
            if g:
                return (GUARDED, g)
            st, _ = expr_status(ctx, right, scope, (call.lineno, call.col_offset))
            if st == SAFE or st == GUARDED:
                return (SAFE, None)
            return (UNGUARDED, None)
        return (UNKNOWN, None)

    if isinstance(q, ast.Call):
        if isinstance(q.func, ast.Attribute) and q.func.attr == "format":
            return (UNGUARDED, None)
        return (UNKNOWN, None)

    return (UNKNOWN, None)

def resolve_query(ctx, scope: ast.AST, expr: ast.AST, before: Tuple[int, int],
                  depth: int = 0, seen: Set[str] = None) -> ast.AST:
    if seen is None:
        seen = set()
    if isinstance(expr, ast.Name) and depth < _SQL_RESOLVE_DEPTH and expr.id not in seen:
        seen.add(expr.id)
        val = last_def(ctx, scope, expr.id, before)
        if val is not None:
            return resolve_query(ctx, scope, val, before, depth+1, seen)
    return expr

def is_sql_constant(ctx, scope: ast.AST, expr: ast.AST, before: Tuple[int, int]) -> bool:
    resolved = resolve_query(ctx, scope, expr, before)
    if is_constant(resolved):
        return True
    if isinstance(resolved, ast.JoinedStr):
        for v in resolved.values:
            if isinstance(v, ast.FormattedValue):
                val = v.value
                if isinstance(val, ast.Call) and call_name(val) in NUMERIC_SAFE:
                    continue
                return False
        return True
    return False

def classify_open(ctx: AnalysisContext, scope: ast.AST, call: ast.Call) -> Tuple[str, Optional[str]]:
    if not call.args:
        return (SAFE, None)
    p = call.args[0]
    if is_constant(p):
        return (SAFE, None)
    old_allowed = ctx.allowed_guards
    ctx.allowed_guards = SINK_GUARD_ALLOW.get("open")
    try:
        g = embedded_guard(ctx, p)
        if g:
            return (GUARDED, g)
        st, _ = expr_status(ctx, p, scope, (call.lineno, call.col_offset))
        if st == UNGUARDED:
            return (UNGUARDED, None)
        return (UNKNOWN, None)
    finally:
        ctx.allowed_guards = old_allowed

def classify_sink(ctx: AnalysisContext, scope_node: ast.AST, sink_call: ast.Call) -> Tuple[str, Optional[str]]:
    name = sink_name(sink_call)
    if name in ("sqlite3.execute", "sqlite3.executescript"):
        return classify_sql(ctx, scope_node, sink_call)
    if name == "open":
        return classify_open(ctx, scope_node, sink_call)
    before = (sink_call.lineno, sink_call.col_offset)
    if not sink_call.args:
        return (SAFE, None)

    # Проверка verify=False
    if name in ("requests.get", "requests.post", "requests.put", "requests.patch",
                "requests.delete", "requests.head", "requests.request",
                "urllib.request.urlopen", "httpx.get", "httpx.post"):
        for kw in sink_call.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return (UNGUARDED, None)
        if len(sink_call.args) >= 2 and isinstance(sink_call.args[1], ast.Constant) and sink_call.args[1].value is False:
            return (UNGUARDED, None)

    if name == "hashlib.pbkdf2_hmac":
        iterations = None
        if len(sink_call.args) >= 4:
            iter_arg = sink_call.args[3]
            if isinstance(iter_arg, ast.Constant):
                iterations = iter_arg.value
        else:
            for kw in sink_call.keywords:
                if kw.arg == "iterations":
                    if isinstance(kw.value, ast.Constant):
                        iterations = kw.value.value
                    break
        if iterations is not None and isinstance(iterations, int) and iterations < 100000:
            return (UNGUARDED, None)
        check_args = []
        if len(sink_call.args) >= 2:
            check_args.append(sink_call.args[1])
        if len(sink_call.args) >= 3:
            check_args.append(sink_call.args[2])
        for kw in sink_call.keywords:
            if kw.arg == "password":
                check_args.append(kw.value)
            elif kw.arg == "salt":
                check_args.append(kw.value)
        if check_args:
            old_allowed = ctx.allowed_guards
            ctx.allowed_guards = SINK_GUARD_ALLOW.get(name)
            try:
                return combine_statuses([expr_status(ctx, a, scope_node, before) for a in check_args])
            finally:
                ctx.allowed_guards = old_allowed
        return (UNKNOWN, None)

    if name in ("hashlib.md5", "hashlib.sha1", "hashlib.sha224", "hashlib.sha256"):
        arg = sink_call.args[0] if sink_call.args else None
        if arg is None:
            return (UNKNOWN, None)
        if is_constant(arg):
            return (SAFE, None)
        st, _ = expr_status(ctx, arg, scope_node, before)
        if st == UNGUARDED:
            return (UNGUARDED, None)
        return (UNKNOWN, None)

    if name == "Crypto.Cipher.AES.new":
        mode_arg = None
        for kw in sink_call.keywords:
            if kw.arg == "mode":
                mode_arg = kw.value
                break
        if mode_arg is None and len(sink_call.args) >= 2:
            mode_arg = sink_call.args[1]
        if mode_arg is not None:
            if isinstance(mode_arg, ast.Constant) and mode_arg.value in (0, 1):
                data_arg = sink_call.args[0] if sink_call.args else None
                if data_arg and not is_constant(data_arg):
                    st, _ = expr_status(ctx, data_arg, scope_node, before)
                    if st == UNGUARDED:
                        return (UNGUARDED, None)
                    else:
                        return (UNKNOWN, "high")
            else:
                return (UNKNOWN, "high")
        return (SAFE, None)

    if name and name.startswith("subprocess."):
        arg0 = sink_call.args[0]
        is_listish = isinstance(arg0, (ast.List, ast.Tuple)) or name_holds_list(ctx, scope_node, arg0, before)
        if is_listish:
            shell_true = any(kw.arg == "shell" and kw_truthy(kw.value) for kw in sink_call.keywords)
            shell_dynamic = any(kw.arg == "shell" and not isinstance(kw.value, ast.Constant) for kw in sink_call.keywords)
            if not shell_true and not shell_dynamic:
                return (SAFE, None)

    idx = SINK_PRIMARY_ARG.get(name)
    if idx is not None:
        if idx >= len(sink_call.args):
            return (UNKNOWN, None)
        check_args = [sink_call.args[idx]]
    else:
        check_args = sink_call.args

    old_allowed = ctx.allowed_guards
    ctx.allowed_guards = SINK_GUARD_ALLOW.get(name)
    try:
        return combine_statuses([expr_status(ctx, a, scope_node, before) for a in check_args])
    finally:
        ctx.allowed_guards = old_allowed

def kw_truthy(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant):
        return bool(value.value)
    if isinstance(value, ast.Name) and value.id == "True":
        return True
    return False

def name_holds_list(ctx, scope: ast.AST, node: ast.AST, before: Tuple[int, int]) -> bool:
    if not isinstance(node, ast.Name) or scope is None:
        return False
    best = None
    for stmt in iter_ast(scope):
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.List, ast.Tuple)):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id == node.id:
                    pos = (stmt.lineno, stmt.col_offset)
                    if pos <= before and (best is None or pos > best):
                        best = pos
    return best is not None

def iter_sinks(tree: ast.AST) -> Iterator[Tuple[Optional[ast.AST], Optional[ast.AST], ast.Call]]:
    def walk(node, scope, stmt):
        for child in ast.iter_child_nodes(node):
            if child is None: continue
            new_stmt = child if isinstance(child, ast.stmt) else stmt
            if isinstance(child, _SCOPE_DEFS):
                yield from walk(child, child, new_stmt)
            else:
                if isinstance(child, ast.Call):
                    if (isinstance(child.func, ast.Name) and child.func.id == "getattr"
                        and len(child.args) >= 2
                        and isinstance(child.args[1], ast.Constant)
                        and isinstance(child.args[1].value, str)):
                        attr = child.args[1].value
                        fake_func = ast.Attribute(value=child.args[0], attr=attr, ctx=ast.Load())
                        fake_call = ast.Call(func=fake_func, args=child.args[2:], keywords=child.keywords)
                        if sink_name(fake_call):
                            yield scope, new_stmt, fake_call
                if isinstance(child, ast.Call) and sink_name(child):
                    yield scope, new_stmt, child
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in child.decorator_list:
                        if isinstance(decorator, ast.Call) and sink_name(decorator):
                            yield scope, child, decorator
                yield from walk(child, scope, new_stmt)
    yield from walk(tree, tree, None)

class Sink(NamedTuple):
    name: str
    lineno: int
    col: int
    end_lineno: int
    args: tuple
    guard: Optional[str]
    stmt_lineno: int
    stmt_col: int
    end_col: int
    status: str
    risk: str

# ============================================================================
#  ПОСТРОЕНИЕ ВНУТРЕННИХ ТАБЛИЦ
# ============================================================================
def build_attr_taint(ctx: AnalysisContext, tree: ast.AST) -> None:
    assigns = defaultdict(list)
    for cls in iter_ast(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for meth in iter_ast(cls):
            if not isinstance(meth, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in iter_ast(meth):
                if not isinstance(node, ast.Assign):
                    continue
                for tgt in node.targets:
                    if (isinstance(tgt, ast.Attribute)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == "self"):
                        assigns[tgt.attr].append((node.value, meth, cls.name))
    taint = {}
    for attr, lst in assigns.items():
        classes = {c for _, _, c in lst}
        if len(classes) != 1:
            continue
        results = [expr_status(ctx, rhs, scope, (rhs.lineno, rhs.col_offset))
                   for rhs, scope, _ in lst]
        st, g = combine_statuses(results)
        if st != UNKNOWN:
            taint[attr] = (st, g)
    ctx.attr_taint = taint

def build_return_taint(ctx: AnalysisContext, tree: ast.AST) -> None:
    defs = defaultdict(list)
    for node in iter_ast(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs[node.name].append(node)
    taint = {}
    for name, deflist in defs.items():
        if len(deflist) != 1:
            continue
        rets = own_returns(ctx, deflist[0])
        if not rets:
            continue
        results = [expr_status(ctx, rv, deflist[0], (rv.lineno, rv.col_offset))
                   for rv in rets]
        st, g = combine_statuses(results)
        if st in (UNGUARDED, SAFE):
            taint[name] = (st, g)
    ctx.return_taint = taint

def build_param_taint(ctx: AnalysisContext, tree: ast.AST) -> None:
    defs = defaultdict(list)
    def collect(node):
        for ch in ast.iter_child_nodes(node):
            if ch is None: continue
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[ch.name].append((ch, isinstance(node, ast.ClassDef)))
                collect(ch)
            else:
                collect(ch)
    collect(tree)
    if not defs:
        return

    callsites = defaultdict(list)
    def walk(node, scope):
        for ch in ast.iter_child_nodes(node):
            if ch is None: continue
            ns = ch if isinstance(ch, _SCOPE_DEFS) else scope
            if isinstance(ch, ast.Call):
                fn = ch.func
                nm = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
                if nm in defs:
                    callsites[nm].append((ch, scope, isinstance(fn, ast.Attribute)))
            walk(ch, ns)
    walk(tree, tree)

    taint = {}
    for name, deflist in defs.items():
        if len(deflist) != 1:
            continue
        fdef, is_method = deflist[0]
        sites = [(c, s) for (c, s, is_attr) in callsites.get(name, []) if is_attr == is_method]
        if not sites:
            continue
        params = [a.arg for a in fdef.args.args]
        start = 1 if is_method else 0
        for idx in range(start, len(params)):
            p = params[idx]
            call_pos = idx - start
            results = []
            for call, scope in sites:
                arg = call.args[call_pos] if call_pos < len(call.args) else None
                if arg is None:
                    for kw in call.keywords:
                        if kw.arg == p:
                            arg = kw.value
                results.append(
                    expr_status(ctx, arg, scope, (call.lineno, call.col_offset))
                    if arg is not None else (UNKNOWN, None))
            st, g = combine_statuses(results)
            if st != UNKNOWN:
                taint[(name, p)] = (st, g)
    ctx.param_taint = taint

def build_guard_wrappers(ctx: AnalysisContext, tree: ast.AST) -> None:
    known_guards = set()
    for s in SINK_GUARD_ALLOW.values():
        known_guards |= s
    known_guards |= {"secure_filename", "werkzeug.utils.secure_filename", "escape", "markupsafe.escape"}
    defs = defaultdict(list)
    for node in iter_ast(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs[node.name].append(node)
    wrappers = {}
    for name, dl in defs.items():
        if len(dl) != 1:
            continue
        rets = own_returns(ctx, dl[0])
        if len(rets) != 1 or not isinstance(rets[0], ast.Call):
            continue
        g = call_name(rets[0])
        if g not in known_guards:
            continue
        params = {a.arg for a in dl[0].args.args}
        if referenced_names(rets[0]) & params:
            wrappers[name] = g
    ctx.guard_wrappers = wrappers

# ============================================================================
#  МЕЖФАЙЛОВЫЙ АНАЛИЗ
# ============================================================================
def _build_module_map(files: Dict[str, str]) -> Dict[str, str]:
    module_map = {}
    for path in files:
        rel = os.path.relpath(path, start=os.path.commonpath([os.path.dirname(p) for p in files]) or "")
        if rel.startswith("."):
            rel = rel[1:]
        mod = os.path.splitext(rel)[0].replace(os.sep, '.')
        if mod.startswith('.'):
            mod = mod[1:]
        module_map[mod] = path
    return module_map

def _file_imports(tree: ast.AST) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, str]]:
    names = {}
    modules = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            for a in node.names:
                names[a.asname or a.name] = (module, a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                base = a.name.split(".")[-1]
                modules[a.asname or a.name.split(".")[0]] = a.name
    return names, modules

def _resolve_call_target(call: ast.Call, imports: Tuple[Dict, Dict],
                         module_map: Dict[str, str], current_file: str) -> Optional[Tuple[str, str]]:
    names, modules = imports
    fn = call.func
    target_file = None
    func_name = None

    if isinstance(fn, ast.Name):
        local = fn.id
        if local in names:
            mod, func = names[local]
            if mod.startswith('.'):
                return None
            if mod in module_map:
                target_file = module_map[mod]
                func_name = func
            else:
                return None
        else:
            return None
    elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        alias = fn.value.id
        if alias in modules:
            mod = modules[alias]
            if mod in module_map:
                target_file = module_map[mod]
                func_name = fn.attr
            else:
                return None
        else:
            return None
    else:
        return None

    if target_file and func_name:
        return (target_file, func_name)
    return None

def _build_cross_taint(files: Dict[str, str], trees: Dict[str, ast.AST],
                       depth: int = 3) -> Dict[Tuple[str, str, str], Tuple[str, Optional[str]]]:
    module_map = _build_module_map(files)
    imports_cache = {path: _file_imports(tree) for path, tree in trees.items()}
    func_defs = {}
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_defs[(path, node.name)] = node

    call_sites = defaultdict(list)
    for caller_path, tree in trees.items():
        imports = imports_cache[caller_path]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = _resolve_call_target(node, imports, module_map, caller_path)
                if resolved and resolved in func_defs:
                    call_sites[resolved].append((node, caller_path))

    cross_taint = {}
    for _ in range(depth):
        changed = False
        new_cross_taint = {}
        for (def_path, funcname), fdef in func_defs.items():
            call_list = call_sites.get((def_path, funcname), [])
            params = [a.arg for a in fdef.args.args]
            for i, pname in enumerate(params):
                statuses = []
                for call, caller_path in call_list:
                    arg = call.args[i] if i < len(call.args) else None
                    if arg is None:
                        for kw in call.keywords:
                            if kw.arg == pname:
                                arg = kw.value
                                break
                    if arg is not None:
                        ctx = AnalysisContext()
                        for (path, f, p), (st, g) in cross_taint.items():
                            if path == caller_path:
                                ctx.cross_taint[(f, p)] = (st, g)
                        st, g = expr_status(ctx, arg, call, (call.lineno, call.col_offset))
                        statuses.append((st, g))
                    else:
                        statuses.append((UNKNOWN, None))
                if statuses:
                    st, g = combine_statuses(statuses)
                    key = (def_path, funcname, pname)
                    if st != UNKNOWN:
                        old = new_cross_taint.get(key)
                        if old != (st, g):
                            changed = True
                            new_cross_taint[key] = (st, g)
        cross_taint = new_cross_taint
        if not changed:
            break
    return cross_taint

def _build_cross_return_taint(files: Dict[str, str], trees: Dict[str, ast.AST],
                              depth: int = 3) -> Dict[Tuple[str, str], Tuple[str, Optional[str]]]:
    module_map = _build_module_map(files)
    imports_cache = {path: _file_imports(tree) for path, tree in trees.items()}
    return_taint_per_file = {}
    for path, tree in trees.items():
        ctx = AnalysisContext()
        defs = defaultdict(list)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[node.name].append(node)
        taint = {}
        for name, deflist in defs.items():
            if len(deflist) != 1:
                continue
            rets = own_returns(ctx, deflist[0])
            if not rets:
                continue
            results = [expr_status(ctx, rv, deflist[0], (rv.lineno, rv.col_offset)) for rv in rets]
            st, g = combine_statuses(results)
            if st in (UNGUARDED, SAFE):
                taint[name] = (st, g)
        return_taint_per_file[path] = taint

    cross_return = {}
    for _ in range(depth):
        changed = False
        new_cross_return = {}
        for caller_path, tree in trees.items():
            imports = imports_cache[caller_path]
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    resolved = _resolve_call_target(node, imports, module_map, caller_path)
                    if resolved:
                        def_path, funcname = resolved
                        t = return_taint_per_file.get(def_path, {}).get(funcname)
                        if t:
                            key = (caller_path, funcname)
                            old = new_cross_return.get(key)
                            if old != t:
                                changed = True
                                new_cross_return[key] = t
        cross_return = new_cross_return
        if not changed:
            break
    return cross_return

def _build_cross_guard_wrappers(files: Dict[str, str], trees: Dict[str, ast.AST]) -> Dict[str, str]:
    known_guards = set()
    for s in SINK_GUARD_ALLOW.values():
        known_guards |= s
    known_guards |= {"secure_filename", "werkzeug.utils.secure_filename", "escape", "markupsafe.escape"}

    guard_wrappers = {}
    for path, tree in trees.items():
        ctx = AnalysisContext()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rets = own_returns(ctx, node)
                if len(rets) == 1 and isinstance(rets[0], ast.Call):
                    g = call_name(rets[0])
                    if g in known_guards:
                        params = {a.arg for a in node.args.args}
                        if referenced_names(rets[0]) & params:
                            guard_wrappers[node.name] = g
    return guard_wrappers

# ============================================================================
#  ОСНОВНАЯ ФУНКЦИЯ АНАЛИЗА ФАЙЛА
# ============================================================================
def analyze(source: str, filename: str = "<src>", ctx: Optional[AnalysisContext] = None) -> List[Sink]:
    if ctx is None:
        ctx = AnalysisContext()

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        print(f"Syntax error in {filename}: {e}", file=sys.stderr)
        return []
    except MemoryError:
        print(f"Memory error: file too large? {filename}", file=sys.stderr)
        return []

    ctx._tree = tree  # для межпроцедурного анализа

    ctx.module_globals.clear()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    ctx.module_globals[target.id] = (node, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            ctx.module_globals[node.target.id] = (node, node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            ctx.module_globals[node.target.id] = (node, node.value)

    for node in iter_ast(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for arg in node.args.args:
            if arg.annotation:
                typ = resolve_type_annotation(arg.annotation)
                if typ:
                    ctx.param_annotations[(node.name, arg.arg)] = typ
        is_route = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr in ("get", "post", "put", "delete", "patch", "head", "options", "route"):
                    is_route = True
                    break
            elif isinstance(decorator, ast.Attribute) and decorator.attr in ("get", "post", "put", "delete", "patch", "head", "options", "route"):
                is_route = True
                break
            elif isinstance(decorator, ast.Name) and decorator.id in ("route", "get", "post", "put", "delete", "patch", "head", "options"):
                is_route = True
                break
        if is_route:
            params = set()
            for arg in node.args.args:
                param_name = arg.arg
                if param_name in ("request", "response", "req", "res", "file", "files", "upload"):
                    continue
                if arg.annotation:
                    typ = resolve_type_annotation(arg.annotation)
                    if typ in ("int", "float", "bool", "complex"):
                        continue
                params.add(param_name)
            if node.args.vararg:
                params.add(node.args.vararg.arg)
            if node.args.kwarg:
                params.add(node.args.kwarg.arg)
            if params:
                ctx.route_params[node.name] = params

    has_sink = any(isinstance(node, ast.Call) and sink_name(node) for node in iter_ast(tree))
    if not has_sink:
        return []

    if len(source) <= _INTERPROC_MAX_CHARS:
        build_attr_taint(ctx, tree)
        build_return_taint(ctx, tree)
        build_guard_wrappers(ctx, tree)
        build_param_taint(ctx, tree)

    found = []
    try:
        for scope_node, stmt, call in iter_sinks(tree):
            status, guard = classify_sink(ctx, scope_node, call)
            risk = dangerous_config(ctx, call, status, scope_node)
            safe_stmt_lineno = call.lineno
            safe_stmt_col = call.col_offset
            if stmt is not None and hasattr(stmt, 'lineno'):
                safe_stmt_lineno = stmt.lineno
                safe_stmt_col = stmt.col_offset
            found.append(Sink(
                name=sink_name(call),
                lineno=call.lineno,
                col=call.col_offset,
                end_lineno=getattr(call, "end_lineno", call.lineno) or call.lineno,
                args=tuple(a.id for a in call.args if isinstance(a, ast.Name)),
                guard=guard,
                stmt_lineno=safe_stmt_lineno,
                stmt_col=safe_stmt_col,
                end_col=getattr(call, "end_col_offset", call.col_offset) or call.col_offset,
                status=status,
                risk=risk,
            ))
    finally:
        ctx.clear_caches()
    return found

def dangerous_config(ctx: AnalysisContext, call: ast.Call, status: str, scope: ast.AST) -> str:
    name = sink_name(call)
    if not call.args:
        return ""
    first = call.args[0]
    if is_constant(first):
        return ""

    is_param = arg_is_param(scope, first)
    if is_param:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if isinstance(first, ast.Name) and first.id in ctx.route_params.get(scope.name, set()):
                return "high"
        return ""

    if name in ("eval", "exec"):
        return "high"
    if name in ("yaml.load", "pickle.loads", "yaml.unsafe_load",
                "yaml.full_load", "marshal.loads", "pickle.load"):
        return "high"
    if name in ("render_template_string", "flask.render_template_string",
                "jinja2.Template", "django.template.Template"):
        if not is_constant(first):
            return "high"
    if name in ("os.system", "os.popen"):
        return "high"
    if name and name.startswith("subprocess."):
        if any(kw.arg == "shell" and kw_truthy(kw.value) for kw in call.keywords):
            return "high"
    if name == "open":
        return "medium"
    if name in ("hashlib.md5", "hashlib.sha1", "hashlib.sha224"):
        return "medium"
    if name == "hashlib.pbkdf2_hmac":
        if status == UNGUARDED:
            return "medium"
        if status == UNKNOWN:
            return "medium"
    return ""

def arg_is_param(scope: ast.AST, expr: ast.AST) -> bool:
    if not isinstance(expr, ast.Name) or not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    a = scope.args
    names = {p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return expr.id in names

# ============================================================================
#  ПОЛИТИКА, АВТОФИКСЫ, GIT, АУДИТ
# ============================================================================
def is_guard_allowed(sink: str, guard: str) -> bool:
    if guard is None:
        return False
    if not re.match(r'^[\w.]+$', guard):
        return False
    if guard in ("parameterized", "secure_filename",
                 "werkzeug.utils.secure_filename", "escape", "markupsafe.escape"):
        return True
    allow = SINK_GUARD_ALLOW.get(sink)
    if allow is None:
        return guard in {"shlex.quote", "ast.literal_eval", "json.loads",
                         "yaml.safe_load", "markupsafe.escape"}
    return guard in allow

def policy_from_sinks(sink_iter) -> dict:
    votes = defaultdict(lambda: defaultdict(int))
    examples = defaultdict(list)
    total = defaultdict(int)
    seen = set()
    for rel, sinks in sink_iter:
        for sink in sinks:
            if sink.status not in ("guarded", "unguarded"):
                continue
            seen.add(sink.name)
            total[sink.name] += 1
            if sink.status == "guarded" and sink.guard:
                votes[sink.name][sink.guard] += 1
                examples[sink.name].append(f"{rel}:{sink.lineno}")
    policy = {}
    for name in sorted(seen):
        v = votes[name]
        if v:
            guard = max(v, key=v.get)
            confidence = round(v[guard] / total[name], 2)
        else:
            guard, confidence = DEFAULT_GUARDS.get(name), 0.0
        if guard is not None and not is_guard_allowed(name, guard):
            guard, confidence = None, 0.0
        policy[name] = {"guard": guard, "confidence": confidence,
                        "count": len(examples[name]),
                        "examples": examples[name][:5]}
    return policy

def build_policy(root: str) -> dict:
    def walk():
        patterns = load_ignore(root)
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            if ".git" in dirpath.split(os.sep):
                continue
            for fname in files:
                if not fname.endswith(".py") or fname == SELF:
                    continue
                full = os.path.join(dirpath, fname)
                if os.path.islink(full):
                    continue
                rel = os.path.relpath(full, root)
                if is_ignored(rel, patterns):
                    continue
                try:
                    with open(full, encoding="utf-8") as fh:
                        yield rel, analyze(fh.read(), filename=rel)
                except (OSError, UnicodeDecodeError, SyntaxError, MemoryError):
                    continue
    return policy_from_sinks(walk())

def load_ignore(root: str) -> list:
    patterns = list(DEFAULT_IGNORE)
    path = os.path.join(root, ".veritascoreignore")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    patterns.extend(load_config(root).get("ignore", []))
    return patterns

_CONFIG_CACHE = {}
def load_config(root: str) -> dict:
    global _CONFIG_CACHE
    if root in _CONFIG_CACHE:
        return _CONFIG_CACHE[root]
    cfg = {
        "max_file_bytes": _MAX_FILE_BYTES,
        "parallel_min_files": _PARALLEL_MIN_FILES,
        "parallel_min_bytes": _PARALLEL_MIN_BYTES,
        "min_confidence": 0.0,
        "cross_file": False,
        "ignore": [],
        "secret_scan": True,
        "sca": False,
        "skip_tests": False,
        "test_patterns": [],
        "cache_enabled": True,
        "max_findings": 500,
    }
    try:
        with open(os.path.join(root, ".veritascore.json"), encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            for key in cfg:
                if key not in user:
                    continue
                val = user[key]
                if key in ("max_file_bytes", "parallel_min_files", "parallel_min_bytes") and isinstance(val, int) and val > 0:
                    cfg[key] = val
                elif key == "min_confidence" and isinstance(val, (int, float)) and 0.0 <= val <= 1.0:
                    cfg[key] = float(val)
                elif key in ("cross_file", "secret_scan", "sca", "skip_tests", "cache_enabled") and isinstance(val, bool):
                    cfg[key] = val
                elif key == "ignore" and isinstance(val, list):
                    cfg[key] = [p for p in val if isinstance(p, str)]
                elif key == "test_patterns" and isinstance(val, list):
                    cfg[key] = [p for p in val if isinstance(p, str)]
    except (OSError, ValueError) as e:
        print(f"Warning: could not parse .veritascore.json: {e}", file=sys.stderr)
    _CONFIG_CACHE[root] = cfg
    return cfg

def is_ignored(rel: str, patterns: list) -> bool:
    rel = rel.replace(os.sep, "/")
    base = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(base, pat) or fnmatch.fnmatch("/" + rel, pat):
            return True
    return False

def is_test_file(rel: str, patterns: list) -> bool:
    """Проверяет, является ли файл тестовым."""
    rel_norm = rel.replace(os.sep, '/')
    if not patterns:
        patterns = ['/test_', '/tests/', '_test.py']
    for pat in patterns:
        if pat in rel_norm or fnmatch.fnmatch(rel_norm, pat):
            return True
    return False

def module_imported(source: str, module: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in iter_ast(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] == module for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == module:
                return True
    return False

def import_insert_index(source: str, lines: list) -> int:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    insert_at = 0
    i = 0
    while i < len(lines) and (lines[i].lstrip().startswith("#!") or lines[i].strip() == ""):
        i += 1
    insert_at = i
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
        insert_at = max(insert_at, tree.body[0].end_lineno or insert_at)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insert_at = max(insert_at, node.end_lineno or insert_at)
    return min(insert_at, len(lines))

def fix_sql_query(source: str, sink: Sink) -> Optional[str]:
    """Переписывает f-строку в параметризованный запрос (экспериментально)."""
    if sink.name not in ("sqlite3.execute", "sqlite3.executescript"):
        return None
    lines = source.splitlines(keepends=True)
    idx = sink.stmt_lineno - 1
    if idx < 0 or idx >= len(lines):
        return None
    line = lines[idx]
    import re
    m = re.search(r'execute\s*\(\s*(f?["\'])(.*?)\1', line, re.DOTALL)
    if not m:
        return None
    prefix = line[:m.start()]
    suffix = line[m.end():]
    quote = m.group(1)
    body = m.group(2)
    if quote == 'f"' or quote == "f'":
        parts = re.split(r'\{([^}]+)\}', body)
        if len(parts) > 1:
            new_query = 'execute("' + ''.join('?' if i % 2 else part for i, part in enumerate(parts)) + '", ('
            params = [p.strip() for p in parts[1::2]]
            new_query += ', '.join(params) + '))'
            return prefix + new_query + suffix
    return None

def apply_fixes(source: str, fixes: list) -> str:
    for sink, guard in fixes:
        if not is_guard_allowed(sink.name, guard):
            raise ValueError(f"Guard '{guard}' not allowed for sink '{sink.name}'")

    lines = source.splitlines(keepends=True)
    needed_imports = set()
    for sink, guard in sorted(fixes, key=lambda f: (f[0].stmt_lineno, f[0].stmt_col), reverse=True):
        # Попытка умного SQL-фикса
        if sink.name.startswith("sqlite3."):
            new_line = fix_sql_query(source, sink)
            if new_line:
                lines[sink.stmt_lineno - 1] = new_line
                continue

        if not sink.args or guard is None:
            continue
        arg = sink.args[0]
        if "." in arg:
            guard_stmt = f"{arg} = {guard}({arg})"
            idx = sink.stmt_lineno - 1
            line = lines[idx]
            col = sink.stmt_col
            before = line[:col]
            if before.strip() == "":
                lines.insert(idx, f"{before}{guard_stmt}  # veritas-core: auto-guard\n")
            else:
                lines[idx] = f"{before}{guard_stmt}; {line[col:]}"
            if "." in guard:
                needed_imports.add(guard.split(".")[0])
            continue

        scope_start = 0
        scope_end = len(lines)
        def_start = None
        for i in range(sink.stmt_lineno - 1, -1, -1):
            if re.match(r'^\s*(def|class|async def)\s+', lines[i]):
                def_start = i
                break
        if def_start is not None:
            indent = re.match(r'^\s*', lines[def_start]).group(0)
            scope_start = def_start
            for i in range(def_start + 1, len(lines)):
                if re.match(r'^\s*(def|class|async def)\s+', lines[i]):
                    if len(re.match(r'^\s*', lines[i]).group(0)) <= len(indent):
                        scope_end = i
                        break
        else:
            scope_start = 0

        override_found = False
        for i in range(sink.stmt_lineno, scope_end):
            line = lines[i]
            if re.search(rf'\b{re.escape(arg)}\s*=', line) and i != sink.stmt_lineno - 1:
                override_found = True
                break

        if override_found:
            guard_stmt = f"{arg} = {guard}({arg})"
            idx = sink.stmt_lineno - 1
            line = lines[idx]
            col = sink.stmt_col
            before = line[:col]
            if before.strip() == "":
                lines.insert(idx, f"{before}{guard_stmt}  # veritas-core: auto-guard\n")
            else:
                lines[idx] = f"{before}{guard_stmt}; {line[col:]}"
            if "." in guard:
                needed_imports.add(guard.split(".")[0])
            continue

        safe_name = f"safe_{arg}"
        counter = 1
        base = safe_name
        while any(re.search(rf'\b{re.escape(base)}\b', line) for line in lines[scope_start:scope_end]):
            base = f"{safe_name}_{counter}"
            counter += 1
        safe_name = base

        guard_stmt = f"{safe_name} = {guard}({arg})"
        idx = sink.stmt_lineno - 1
        if not (0 <= idx < len(lines)):
            continue
        line = lines[idx]
        col = sink.stmt_col
        before = line[:col]
        if before.strip() == "":
            lines.insert(idx, f"{before}{guard_stmt}  # veritas-core: auto-guard\n")
        else:
            indent = re.match(r'^\s*', line).group(0)
            lines.insert(idx, f"{indent}{guard_stmt}  # veritas-core: auto-guard\n")

        for i in range(idx + 1, scope_end):
            line = lines[i]
            if re.search(rf'\b{re.escape(arg)}\s*=', line):
                break
            new_line = re.sub(rf'\b{re.escape(arg)}\b', safe_name, line)
            lines[i] = new_line

        if "." in guard:
            needed_imports.add(guard.split(".")[0])

    missing = sorted(m for m in needed_imports if not module_imported(source, m))
    if missing:
        ins = import_insert_index(source, lines)
        block = "".join(f"import {m}\n" for m in missing)
        lines.insert(ins, block)

    return "".join(lines)

def fix_diff(rel: str, source: str, sink: Sink, guard: str) -> str:
    if not is_guard_allowed(sink.name, guard):
        raise ValueError(f"Guard '{guard}' not allowed for sink '{sink.name}'")
    new = apply_fixes(source, [(sink, guard)])
    return "".join(difflib.unified_diff(
        source.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}"))

def find_repo_root(start: str) -> Optional[str]:
    d = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(d, ".git")) or os.path.isfile(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent

def git_changed_files(root: str, ref: str = None) -> list:
    if ref and (not re.match(r'^[\w\-./]+$', ref) or ref.startswith('-')):
        return []
    try:
        if ref:
            args = ["git", "diff", "--name-only", ref, "HEAD", "--"]
        else:
            args = ["git", "diff", "--name-only", "HEAD", "--"]
        out = subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            out = subprocess.run(["git", "diff", "--name-only"], cwd=root,
                                 capture_output=True, text=True, timeout=30)
        names = set(out.stdout.splitlines())
        staged = subprocess.run(["git", "diff", "--name-only", "--cached"],
                                cwd=root, capture_output=True, text=True, timeout=30)
        if staged.returncode == 0:
            names |= set(staged.stdout.splitlines())
        return [f for f in names if f.endswith(".py")]
    except Exception:
        return []

def staged_files(root: str) -> list:
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=root, capture_output=True, text=True, check=True, timeout=10
        )
        return [f for f in out.stdout.splitlines() if f.endswith(".py")]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []

def skip_directive(lines: list, sink: Sink):
    start_line = max(1, sink.lineno - 5)
    end_line = min(len(lines), sink.end_lineno + 2)
    for ln in range(start_line, end_line + 1):
        if 1 <= ln <= len(lines):
            pos = lines[ln - 1].find(SKIP)
            if pos != -1:
                reason = lines[ln - 1][pos + len(SKIP):].strip()
                return ("ok", reason) if reason else ("noreason", None)
    return (None, None)

class Violation(NamedTuple):
    rel: str
    sink: Optional[Sink]
    required: Optional[str]
    examples: list
    note: Optional[str]
    diff: str
    source: str

def collect_violations(root: str, policy: dict, min_conf: float = 0.0) -> list:
    result = []
    patterns = load_ignore(root)
    root_real = os.path.realpath(root)
    for rel in staged_files(root):
        if not rel.endswith(".py") or os.path.basename(rel) == SELF:
            continue
        if is_ignored(rel, patterns):
            continue
        path = os.path.join(root, rel)
        path_real = os.path.realpath(path)
        if not os.path.isfile(path_real) or not path_real.startswith(root_real):
            continue
        with open(path_real, encoding="utf-8") as fh:
            source = fh.read()
        try:
            sinks = analyze(source, filename=rel)
        except SyntaxError as exc:
            result.append(Violation(rel, None, None, [], f"syntax error: {exc.msg}", "", source))
            continue
        lines = source.splitlines()
        for sink in sinks:
            entry = policy.get(sink.name)
            if entry is None:
                continue
            if not entry.get("guard"):
                continue
            if entry.get("confidence", 0.0) < min_conf:
                continue
            required = entry["guard"]
            if sink.status in ("safe", "unknown"):
                continue
            if sink.status == "guarded" and sink.guard == required:
                continue
            kind, _ = skip_directive(lines, sink)
            if kind == "ok":
                continue
            note = f"{SKIP} requires a reason" if kind == "noreason" else None
            try:
                diff = fix_diff(rel, source, sink, required)
            except Exception as e:
                diff = ""
                note = f"Fix generation failed: {e}"
            result.append(Violation(rel, sink, required, entry.get("examples") or [],
                                 note, diff, source))
    return result

def print_violation(v: Violation, learn: bool) -> None:
    if v.sink is None:
        print(f"  {v.rel}: {v.note}\n", file=sys.stderr)
        return
    print(f"  {v.rel}:{v.sink.lineno}  {v.sink.name}() is missing guard "
          f"'{v.required}'", file=sys.stderr)
    ex = ", ".join(v.examples) or "(none)"
    print(f"      learned from: {ex}", file=sys.stderr)
    if v.note:
        print(f"      note: {v.note}", file=sys.stderr)
    if v.diff:
        print("      suggested fix:", file=sys.stderr)
        for line in v.diff.splitlines():
            print(f"      | {line}", file=sys.stderr)
    print(file=sys.stderr)

def ask_yes(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower().startswith("y")
    except EOFError:
        return False

def build_fix(lines: list, sink: Sink, guard: str) -> Optional[dict]:
    if not is_guard_allowed(sink.name, guard):
        raise ValueError(f"Guard '{guard}' not allowed for sink '{sink.name}'")
    if not sink.args or guard is None:
        return None
    arg = sink.args[0]
    guard_stmt = f"{arg} = {guard}({arg})"
    idx = sink.stmt_lineno - 1
    if not (0 <= idx < len(lines)):
        return None
    line = lines[idx]
    col = sink.stmt_col
    before = line[:col]
    if before.strip() == "":
        return {"title": f"Add guard: {guard}", "mode": "newline",
                "line": sink.stmt_lineno, "col": 0,
                "text": f"{before}{guard_stmt}  # veritas-core: auto-guard\n"}
    return {"title": f"Add guard: {guard}", "mode": "inline",
            "line": sink.stmt_lineno, "col": col, "text": f"{guard_stmt}; "}

def violations_json(root: str, target: Optional[str]) -> dict:
    policy = build_policy(root)
    root_real = os.path.realpath(root)
    if target:
        target_real = os.path.realpath(target)
        if not target_real.startswith(root_real):
            return {"error": "target outside project root"}
        paths = [target_real]
    else:
        paths = [os.path.join(root, r) for r in staged_files(root)]
    results = []
    for path in paths:
        if not path.endswith(".py") or os.path.basename(path) == SELF:
            continue
        if not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, root)
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        try:
            sinks = analyze(source, filename=path)
        except SyntaxError:
            continue
        lines = source.splitlines()
        for sink in sinks:
            entry = policy.get(sink.name)
            if getattr(sink, "risk", "") == "high":
                kind, _ = skip_directive(lines, sink)
                if kind == "ok":
                    continue
                cfg = ("shell=True" if sink.name.startswith("subprocess.")
                       or sink.name == "os.system" else sink.name + "()")
                results.append({
                    "file": rel, "line": sink.lineno,
                    "col": sink.col, "endLine": sink.end_lineno,
                    "endCol": sink.end_col, "sink": sink.name, "guard": None,
                    "message": (f"{sink.name}(): dangerous configuration ({cfg}) with "
                                f"untrusted source — likely injection, please review manually"),
                    "fix": None, "severity": "medium",
                    "arg": sink.args[0] if sink.args else None,
                    "skipNoReason": kind == "noreason", "insert": None,
                    "status": sink.status, "advisory": True})
                continue
            if entry is None or not entry.get("guard"):
                continue
            required = entry["guard"]
            if sink.status == "safe":
                continue
            if sink.status == "guarded" and sink.guard == required:
                continue
            kind, _ = skip_directive(lines, sink)
            if kind == "ok":
                continue
            arg = sink.args[0] if sink.args else None
            conf = entry.get("confidence", 0.0)
            count = entry.get("count", 0)
            advisory = sink.status == "unknown"
            wrappable = (required not in ("parameterized",)
                         and sink.name not in ("sqlite3.execute", "open")
                         and arg is not None)
            insert = (build_fix(lines, sink, required)
                      if (wrappable and kind != "noreason" and not advisory) else None)
            if kind == "noreason":
                message = f"{sink.name}(): '# veritas-core: skip' requires a reason"
                fix_text = None
                severity = SEVERITY.get(sink.name, "medium")
            elif advisory:
                if getattr(sink, "risk", "") == "high":
                    cfg = ("shell=True" if sink.name.startswith("subprocess.")
                           or sink.name == "os.system" else sink.name + "()")
                    message = (f"{sink.name}(): dangerous configuration ({cfg}) with "
                               f"untrusted source — please review manually")
                    severity = "medium"
                else:
                    message = (f"{sink.name}(): data flow not traceable "
                               f"(e.g., function parameter) — please review manually. "
                               f"Contract: {required}")
                    severity = "low"
                fix_text = None
            elif sink.name == "sqlite3.execute":
                message = ("sqlite3.execute(): query built from string — "
                           "use parameterization (?, :name), not concatenation/f-string")
                fix_text = None
                severity = SEVERITY.get(sink.name, "medium")
            else:
                message = (f"{sink.name}() without guard. Contract: {required} "
                           f"(examples: {count}, confidence {round(conf * 100)}%)")
                fix_text = f"{arg} = {required}({arg})" if wrappable else None
                severity = SEVERITY.get(sink.name, "medium")
            results.append({
                "file": rel,
                "line": sink.lineno, "col": sink.col,
                "endLine": sink.end_lineno, "endCol": sink.end_col,
                "sink": sink.name, "guard": required,
                "confidence": conf, "count": count,
                "severity": severity,
                "status": sink.status,
                "advisory": advisory,
                "arg": arg,
                "skipNoReason": kind == "noreason",
                "message": message,
                "fix": fix_text,
                "insert": insert,
            })
    return {"policy": policy, "violations": results}

# ============================================================================
#  SCA, SARIF, veritas_secrets
# ============================================================================
def _sca_scan(root: str) -> list:
    findings = []
    req_files = []
    for fname in os.listdir(root):
        if fname in ("requirements.txt", "pyproject.toml"):
            req_files.append(os.path.join(root, fname))
    if not req_files:
        return findings

    for req_file in req_files:
        try:
            cmd = ["pip-audit", "-r", req_file, "--json"]
            if req_file.endswith(".toml"):
                cmd = ["pip-audit", "--project", root, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "file": os.path.basename(req_file),
                        "line": 0,
                        "sink": vuln.get("name", "unknown"),
                        "status": "unguarded",
                        "risk": "medium",
                        "guard_needed": None,
                        "message": f"Уязвимая зависимость: {vuln.get('name')} {vuln.get('version')} – {vuln.get('description', '')}",
                    })
        except Exception:
            continue
    return findings

def generate_sarif(report: dict) -> dict:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VeritasCore Security Pro", "version": __version__}},
            "results": []
        }]
    }
    for f in report.get("findings", []):
        level = "error" if f.get("status") == "unguarded" else "warning"
        result = {
            "ruleId": f.get("sink", "unknown"),
            "level": level,
            "message": {"text": f.get("message", f"{f.get('sink')} – {f.get('status')}")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": f.get("line", 1), "startColumn": 1}
                }
            }]
        }
        sarif["runs"][0]["results"].append(result)
    return sarif

def _veritas_secrets(root: str) -> list:
    try:
        import veritas_secrets as secrets
        return secrets.scan_dir(root)
    except ImportError:
        return []

# ============================================================================
#  АУДИТ (с фильтрацией тестов)
# ============================================================================
def audit_changed(root: str, ref: str = None, cross_file: bool = False) -> dict:
    changed = git_changed_files(root, ref)
    if not changed:
        return {"error": "no git repo or no changes", "findings": []}
    files = {}
    cfg = load_config(root)
    max_file_bytes = cfg.get("max_file_bytes", _MAX_FILE_BYTES)
    skip_tests = cfg.get("skip_tests", False)
    test_patterns = cfg.get("test_patterns", [])
    max_files = 1000
    count = 0
    for full in changed:
        if count >= max_files:
            print(f"[WARN] Too many changed files, stopped at {max_files}", file=sys.stderr)
            break
        try:
            if os.path.getsize(full) > max_file_bytes:
                print(f"[WARN] Skipping large file {full} (> {max_file_bytes} bytes)", file=sys.stderr)
                continue
            rel = os.path.relpath(full, root)
            if skip_tests and is_test_file(rel, test_patterns):
                continue
            with open(full, encoding="utf-8") as fh:
                files[rel] = fh.read()
                count += 1
        except Exception as e:
            print(f"[WARN] Failed to read {full}: {e}", file=sys.stderr)
            continue
    if cross_file:
        results = analyze_project(files, cross_file=True)
    else:
        results = {}
        for rel, src in files.items():
            try:
                results[rel] = analyze(src, filename=rel)
            except Exception as e:
                print(f"[ERROR] analyzing {rel}: {e}", file=sys.stderr)
                results[rel] = []
    findings = []
    for rel, sinks in results.items():
        for s in sinks:
            if s.status == UNGUARDED or (s.status == UNKNOWN and s.risk == "high"):
                findings.append({"file": rel, "line": s.lineno, "sink": s.name,
                                 "status": s.status, "risk": s.risk,
                                 "guard_needed": s.guard})
    return {"changed_files": len(files), "findings": findings}

def analyze_project(files: dict, cross_file: bool = False) -> dict:
    if not cross_file:
        return {rel: analyze(src, filename=rel) for rel, src in files.items()}

    trees = {}
    for rel, src in files.items():
        try:
            trees[rel] = ast.parse(src, filename=rel)
        except SyntaxError:
            continue

    cross_taint = _build_cross_taint(files, trees, depth=3)
    cross_return = _build_cross_return_taint(files, trees, depth=3)
    cross_guard_wrappers = _build_cross_guard_wrappers(files, trees)

    results = {}
    for rel, src in files.items():
        if rel not in trees:
            results[rel] = []
            continue
        ctx = AnalysisContext()
        for (path, func, param), (st, g) in cross_taint.items():
            if path == rel:
                ctx.cross_taint[(func, param)] = (st, g)
        for (path, func), (st, g) in cross_return.items():
            if path == rel:
                ctx.cross_return[func] = (st, g)
        for func, guard in cross_guard_wrappers.items():
            ctx.cross_guard_wrappers[func] = guard

        results[rel] = analyze(src, filename=rel, ctx=ctx)
    return results

def audit(root, cross_file=False, progress=None, use_cache=True, jobs=1, fast=False) -> dict:
    if jobs <= 0:
        jobs = 1
    cfg = load_config(root)
    max_file_bytes = cfg["max_file_bytes"]
    patterns = load_ignore(root)
    skip_tests = cfg.get("skip_tests", False)
    test_patterns = cfg.get("test_patterns", [])
    totals = {GUARDED: 0, UNGUARDED: 0, UNKNOWN: 0, SAFE: 0}
    by_sink = defaultdict(lambda: {GUARDED: 0, UNGUARDED: 0, UNKNOWN: 0, SAFE: 0})
    files = []
    parse_errors = 0
    skipped_large = 0
    high_risk = 0
    scanned = 0
    root_real = os.path.realpath(root)
    collected = []

    def iter_py():
        nonlocal skipped_large
        for dirpath, _dirs, fnames in os.walk(root, followlinks=False):
            if ".git" in dirpath.split(os.sep):
                continue
            for fname in fnames:
                if not fname.endswith(".py") or fname == SELF:
                    continue
                full = os.path.join(dirpath, fname)
                if os.path.islink(full):
                    continue
                full_real = os.path.realpath(full)
                if not full_real.startswith(root_real):
                    continue
                rel = os.path.relpath(full_real, root)
                if is_ignored(rel, patterns):
                    continue
                if skip_tests and is_test_file(rel, test_patterns):
                    continue
                try:
                    if os.path.getsize(full_real) > max_file_bytes:
                        skipped_large += 1
                        continue
                    with open(full_real, encoding="utf-8") as fh:
                        yield rel, fh.read()
                except (OSError, UnicodeDecodeError, FileNotFoundError, PermissionError):
                    continue

    def tally(rel, sinks):
        nonlocal scanned, high_risk
        scanned += 1
        if progress and scanned % 500 == 0:
            progress(scanned)
        collected.append((rel, sinks))
        per = {GUARDED: 0, UNGUARDED: 0, UNKNOWN: 0, SAFE: 0}
        for s in sinks:
            totals[s.status] += 1
            by_sink[s.name][s.status] += 1
            per[s.status] += 1
            if getattr(s, "risk", "") == "high":
                high_risk += 1
        if per[UNGUARDED] or per[UNKNOWN]:
            files.append({"file": rel, **per})

    if use_cache:
        cache = _load_cache(root)
    else:
        cache = {}
    new_cache = {}
    cache_hits = 0
    misses = []

    for rel, src in iter_py():
        h = hashlib.sha1(src.encode("utf-8", "replace")).hexdigest()
        hit = cache.get(rel)
        if hit and hit.get("h") == h:
            sinks = [Sink(*s) for s in hit["s"] if s is not None]
            cache_hits += 1
            new_cache[rel] = {"h": h, "s": hit["s"]}
            tally(rel, sinks)
        else:
            misses.append((rel, src, h))

    if cross_file and misses:
        all_sources = {rel: src for rel, src, _ in misses}
        results = analyze_project(all_sources, cross_file=True)
        for rel, sinks in results.items():
            if rel in all_sources:
                new_cache[rel] = {"h": hashlib.sha1(all_sources[rel].encode()).hexdigest(),
                                  "s": [list(s) for s in sinks]}
                tally(rel, sinks)
        misses = []
    else:
        if misses:
            if jobs > 1 and len(misses) > jobs:
                from multiprocessing import Pool
                payload = [(rel, src) for rel, src, _ in misses]
                hashes = {rel: h for rel, src, h in misses}
                results = []
                with Pool(jobs) as pool:
                    for rel, serial, perr in pool.imap_unordered(_analyze_src_worker, payload, chunksize=16):
                        if perr:
                            parse_errors += 1
                            scanned += 1
                            continue
                        results.append((rel, serial))
                for rel, serial in results:
                    sinks = [Sink(*s) for s in serial]
                    new_cache[rel] = {"h": hashes[rel], "s": serial}
                    tally(rel, sinks)
            else:
                for rel, src, h in misses:
                    try:
                        sinks = analyze(src, filename=rel)
                    except SyntaxError:
                        parse_errors += 1
                        scanned += 1
                        continue
                    new_cache[rel] = {"h": h, "s": [list(s) for s in sinks]}
                    tally(rel, sinks)

    if use_cache:
        _save_cache(root, new_cache)

    policy = policy_from_sinks(collected)
    for name, counts in by_sink.items():
        counts["guard"] = policy.get(name, {}).get("guard")
        counts["confidence"] = policy.get(name, {}).get("confidence", 0.0)
    files.sort(key=lambda f: (f[UNGUARDED], f[UNKNOWN]), reverse=True)

    sinks_total = sum(totals.values())
    determinable = totals[GUARDED] + totals[UNGUARDED]
    coverage = round(totals[GUARDED] / determinable, 3) if determinable else 0.0
    findings = []
    skipped = 0
    skip_cache = {}
    for rel, sinks in collected:
        for s in sinks:
            risk = getattr(s, "risk", "")
            if s.status == UNGUARDED or risk == "high":
                if rel not in skip_cache:
                    try:
                        with open(os.path.join(root, rel), encoding="utf-8") as fh:
                            skip_cache[rel] = fh.readlines()
                    except OSError:
                        skip_cache[rel] = []
                kind, _ = skip_directive(skip_cache[rel], s)
                if kind == "ok":
                    skipped += 1
                    continue
                findings.append({
                    "file": rel, "line": s.lineno, "sink": s.name,
                    "status": s.status, "risk": risk,
                    "guard_needed": (policy.get(s.name, {}) or {}).get("guard"),
                })
    findings.sort(key=lambda f: (f["status"] != "unguarded", f["file"], f["line"]))

    if cfg.get("sca"):
        sca_findings = _sca_scan(root)
        findings.extend(sca_findings)

    if cfg.get("secret_scan"):
        sec_findings = _veritas_secrets(root)
        for f in sec_findings:
            findings.append({
                "file": f.get("file"),
                "line": f.get("line", 0),
                "sink": f.get("type", "secret"),
                "status": "unguarded",
                "risk": "high" if f.get("confidence") == "high" else "medium",
                "guard_needed": None,
                "message": f"Найден секрет: {f.get('type')} – {f.get('preview')}",
            })

    return {
        "root": root_real,
        "files_scanned": scanned,
        "parse_errors": parse_errors,
        "skipped_large": skipped_large,
        "skipped": skipped,
        "high_risk": high_risk,
        "cache_hits": cache_hits,
        "sinks_total": sinks_total,
        "coverage": coverage,
        "totals": totals,
        "by_sink": dict(by_sink),
        "files": files[:50],
        "findings": findings[:500],
        "policy": policy,
    }

def _analyze_src_worker(args):
    rel, src = args
    try:
        return (rel, [list(s) for s in analyze(src, filename=rel)], False)
    except SyntaxError:
        return (rel, None, True)
    except MemoryError:
        return (rel, None, True)

def _load_cache(root: str) -> dict:
    try:
        with open(os.path.join(root, ".veritascore_cache.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("v") == 1 and "files" in data:
            return data["files"]
    except (OSError, ValueError, UnicodeDecodeError):
        pass
    return {}

def _save_cache(root: str, files: dict) -> None:
    if not files:
        return
    tmp_path = os.path.join(root, f".veritascore_cache_{os.getpid()}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump({"v": 1, "files": files}, fh)
        os.replace(tmp_path, os.path.join(root, ".veritascore_cache.json"))
    except OSError as e:
        print(f"[WARN] Failed to save cache: {e}", file=sys.stderr)
        try:
            os.remove(tmp_path)
        except OSError:
            pass

def print_audit(report: dict) -> None:
    try:
        t = report["totals"]
        print(f"VeritasCore audit: {report['root']}")
        print(f"  files scanned : {report['files_scanned']}")
        if report.get("parse_errors"):
            print(f"  parse errors  : {report['parse_errors']} (unparseable, skipped)")
        if report.get("skipped_large"):
            print(f"  skipped large : {report['skipped_large']} (>1.5MB, likely generated)")
        if report.get("high_risk"):
            print(f"  HIGH-RISK     : {report['high_risk']} (shell=True / eval of an "
                  f"untraceable variable — manual review)")
        print(f"  sinks total   : {report['sinks_total']}")
        print(f"  guarded={t['guarded']}  unguarded={t['unguarded']}  "
              f"unknown={t['unknown']}  safe={t['safe']}")
        print(f"  coverage      : {round(report['coverage'] * 100)}%  "
              f"(guarded / determinable)")
        print("  by sink:")
        for name, c in sorted(report["by_sink"].items(),
                              key=lambda kv: -kv[1]["unguarded"]):
            print(f"    {name:<18} guard={c.get('guard')}  conf={c.get('confidence')}  "
                  f"G={c['guarded']} U={c['unguarded']} ?={c['unknown']} ok={c['safe']}")
        if report["files"]:
            print("  worst files (unguarded, unknown):")
            for f in report["files"][:10]:
                print(f"    {f['file']}: U={f['unguarded']} ?={f['unknown']}")
    except BrokenPipeError:
        pass

# ============================================================================
#  CLI
# ============================================================================
def arg_value(argv: list, flag: str) -> Optional[str]:
    if flag in argv:
        i = argv.index(flag)
        if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            return argv[i + 1]
    return None

def main(argv: list) -> int:
    try:
        positional, flags, file_target = [], set(), None
        min_conf = 0.0
        i = 0
        while i < len(argv):
            a = argv[i]
            if a == "--file" and i + 1 < len(argv):
                file_target = argv[i + 1]
                i += 2
                continue
            if a == "--min-confidence" and i + 1 < len(argv):
                try:
                    min_conf = float(argv[i + 1])
                except ValueError:
                    print("error: --min-confidence expects a number", file=sys.stderr)
                    return 2
                i += 2
                continue
            if a in ("--jobs", "--learn-into", "--veritas_knowledge") and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                flags.add(a)
                i += 2
                continue
            if a.startswith("--"):
                flags.add(a)
                i += 1
                continue
            positional.append(a)
            i += 1

        apply_mode = "--apply" in flags
        learn_mode = "--learn" in flags
        non_interactive = "--no-interactive" in flags
        json_mode = "--json" in flags
        audit_mode = "--audit" in flags
        sarif_mode = "--sarif" in flags

        if not positional:
            print("usage: veritas_core.py <project> [--apply] [--learn] "
                  "[--no-interactive] [--json [--file PATH]] [--sarif]", file=sys.stderr)
            return 2
        root = os.path.abspath(positional[0])
        if not os.path.isdir(root):
            print(f"error: not a directory: {root}", file=sys.stderr)
            return 2

        if "--changed" in flags or "--since" in argv:
            ref = arg_value(argv, "--since")
            result = audit_changed(root, ref, cross_file="--cross-file" in flags)
            if result.get("error"):
                print(f"veritas_core: {result['error']}", file=sys.stderr)
                return 2
            findings = result["findings"]
            if json_mode:
                print(json.dumps(result, indent=2))
            else:
                scope = f"since {ref}" if ref else "working tree"
                print(f"Incremental scan ({scope}): {result['changed_files']} changed file(s)")
                for f in findings:
                    print(f"  {f['status']:9} {f['file']}:{f['line']}  {f['sink']}")
                print(f"\n{len(findings)} issue(s) in changed code."
                      if findings else "\nNo issues in changed code.")
            return 1 if findings else 0

        if audit_mode:
            def progress(n):
                print(f"  …scanned {n} files", file=sys.stderr, flush=True)
            fast = "--fast" in flags
            jobs = 1
            if fast:
                jobs = os.cpu_count() or 1
            if "--jobs" in argv:
                idx = argv.index("--jobs")
                if idx + 1 < len(argv) and argv[idx + 1].isdigit():
                    jobs = max(1, int(argv[idx + 1]))
                else:
                    jobs = os.cpu_count() or 1

            report = audit(root, cross_file=(not fast) and "--cross-file" in flags,
                           progress=progress, jobs=jobs, fast=fast)
            if "--aggressive" in flags:
                report["aggressive_mode"] = True

            db_path = arg_value(argv, "--learn-into") or arg_value(argv, "--veritas_knowledge")
            if db_path:
                try:
                    import veritas_knowledge as _kb
                    db = _kb.load_db(db_path)
                    proj_policy = report.get("policy", {})
                    if "--learn-into" in argv:
                        name = os.path.basename(os.path.abspath(root)) or "project"
                        _kb.learn_project(db, name, proj_policy)
                        _kb.save_db(db_path, db)
                        report["learned_into"] = db_path
                    report["anti_contracts"] = _kb.anti_contracts(db, proj_policy)
                    report["ecosystem"] = _kb.aggregate(db)
                except Exception as exc:
                    report["veritas_knowledge_error"] = str(exc)

            if sarif_mode:
                sarif_report = generate_sarif(report)
                print(json.dumps(sarif_report, indent=2))
                return 0

            if json_mode:
                print(json.dumps(report))
            else:
                print_audit(report)
                for f in report.get("anti_contracts", []):
                    print(f"  ⚠ deviation from ecosystem: {f['message']}")
            return 0

        if json_mode:
            print(json.dumps(violations_json(root, file_target)))
            return 0

        policy = build_policy(root)
        file_policy = {name: {"guard": e["guard"], "examples": e["examples"]}
                       for name, e in policy.items()}
        with open(os.path.join(root, ".gate_policy.json"), "w", encoding="utf-8") as fh:
            json.dump(file_policy, fh, indent=2)
        print(f"policy written: {os.path.join(root, '.gate_policy.json')}")
        for name, entry in policy.items():
            print(f"  {name}: guard={entry['guard']}")

        repo = find_repo_root(root)
        if repo is None:
            print("veritas_core: not a git repo - policy generated, nothing to gate.")
            return 0

        violations = collect_violations(repo, policy, min_conf)
        if not violations:
            print("veritas_core: OK - all staged sinks are guarded.")
            return 0

        if learn_mode:
            print("LEARN MODE - warnings only:\n", file=sys.stderr)
            stats = defaultdict(int)
            for v in violations:
                print_violation(v, learn=True)
                if v.sink is not None:
                    stats[v.sink.name] += 1
            print("stats (violations per sink):", file=sys.stderr)
            for name, count in sorted(stats.items(), key=lambda kv: -kv[1]):
                print(f"  {name}: {count}", file=sys.stderr)
            print(f"\n{len(violations)} warning(s).", file=sys.stderr)
            return 0

        if apply_mode:
            per_file = defaultdict(list)
            remaining = []
            for v in violations:
                fixable = v.sink is not None and v.sink.args and not v.note and v.required is not None
                if not fixable:
                    remaining.append(v)
                    continue
                print_violation(v, learn=False)
                if non_interactive or ask_yes(f"apply fix to {v.rel}:{v.sink.lineno}? [y/N] "):
                    per_file[v.rel].append((v.sink, v.required, v.source))
                else:
                    remaining.append(v)

            for rel, items in per_file.items():
                source = items[0][2]
                try:
                    new = apply_fixes(source, [(s, g) for s, g, _ in items])
                except ValueError as e:
                    print(f"[ERROR] {rel}: {e}", file=sys.stderr)
                    remaining.extend(items)
                    continue
                orig_path = os.path.join(repo, rel)
                try:
                    shutil.copy2(orig_path, orig_path + ".orig")
                except OSError:
                    pass
                with open(orig_path, "w", encoding="utf-8") as fh:
                    fh.write(new)
                subprocess.run(["git", "add", rel], cwd=repo,
                               capture_output=True, text=True)
                print(f"fixed: {rel}")
                try:
                    os.remove(orig_path + ".orig")
                except OSError:
                    pass

            if remaining:
                print("\nUnresolved violations remain:\n", file=sys.stderr)
                for v in remaining:
                    print_violation(v, learn=False)
                print(f"{len(remaining)} violation(s). Commit blocked.", file=sys.stderr)
                return 1
            print("veritas_core: all violations fixed and re-staged.")
            return 0

        print("COMMIT BLOCKED - unguarded dangerous sinks:\n", file=sys.stderr)
        for v in violations:
            print_violation(v, learn=False)
        print(f"{len(violations)} violation(s). Commit blocked.", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 1
    except BrokenPipeError:
        sys.stderr.close()
        return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))