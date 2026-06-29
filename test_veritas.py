#!/usr/bin/env python3
"""Test suite for veritas_core.py — stdlib unittest, no third-party deps.

Run:  python3 -m unittest test_veritas_core -v
  or:  python3 test_veritas_core.py
"""
import ast
import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "veritas_core.py")
sys.path.insert(0, HERE)
import veritas_core as ng  # noqa: E402


def guard_of(src: str):
    """Guard detected for the first sink in a snippet (or None)."""
    sinks = ng.analyze(src)
    assert sinks, "no sink found in snippet"
    return sinks[0].guard


class GuardDetection(unittest.TestCase):
    def test_assignment_wrap(self):
        self.assertEqual(
            guard_of("import os,shlex\ncmd=shlex.quote(cmd)\nos.system(cmd)"),
            "shlex.quote")

    def test_direct_wrap(self):
        self.assertEqual(
            guard_of("import os,shlex\nos.system(shlex.quote(cmd))"),
            "shlex.quote")

    def test_transitive_flow(self):
        # y = shlex.quote(x); sink(y)  — guard found via data flow
        self.assertEqual(
            guard_of("import os,shlex\ndef r(x):\n y=shlex.quote(x)\n os.system(y)"),
            "shlex.quote")

    def test_arbitrary_call_is_not_a_shell_guard(self):
        # an arbitrary project function must NOT be assumed to sanitise a command
        # (this is the subprocess.run -> stage_zensical_docs false-contract bug)
        self.assertIsNone(
            guard_of("import os\ndef r(x):\n y=clean(x)\n os.system(y)"))

    def test_input_is_not_a_guard(self):
        self.assertIsNone(
            guard_of("import os\ncmd=input()\nos.system(cmd)"))

    def test_rebind_to_source_unguards(self):
        # cleaned, then overwritten by a source before the sink -> NOT guarded
        self.assertIsNone(
            guard_of("import os,shlex\nv=shlex.quote(x)\nv=input()\nos.system(v)"))

    def test_scope_isolation(self):
        # guard in one function must not leak into another
        src = ("import os,shlex\n"
               "def a(c):\n c=shlex.quote(c)\n return c\n"
               "def b(c):\n os.system(c)\n")
        sinks = ng.analyze(src)
        syscall = [s for s in sinks if s.name == "os.system"][0]
        self.assertIsNone(syscall.guard)

    def test_one_liner_semicolons(self):
        self.assertEqual(
            guard_of("import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)"),
            "shlex.quote")

    def test_sink_detection_names(self):
        names = {s.name for s in ng.analyze(
            "import os,subprocess,pickle\n"
            "os.system(a)\nsubprocess.run(b)\npickle.loads(c)\nopen(d)\neval(e)")}
        self.assertTrue({"os.system", "subprocess.run", "pickle.loads",
                         "open", "eval"} <= names)


class PolicyGeneration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(content)

    def test_learns_guard_and_confidence(self):
        self._write("safe.py", "import os,shlex\ncmd=shlex.quote(cmd)\nos.system(cmd)\n")
        self._write("vuln.py", "import os\ncmd=input()\nos.system(cmd)\n")
        pol = ng.build_policy(self.d)
        self.assertEqual(pol["os.system"]["guard"], "shlex.quote")
        self.assertAlmostEqual(pol["os.system"]["confidence"], 0.5)
        self.assertEqual(pol["os.system"]["count"], 1)

    def test_fallback_when_no_example(self):
        self._write("vuln.py", "import os\ncmd=input()\nos.system(cmd)\n")
        pol = ng.build_policy(self.d)
        # no project example -> fallback contract, confidence 0
        self.assertEqual(pol["os.system"]["guard"], "shlex.quote")
        self.assertEqual(pol["os.system"]["confidence"], 0.0)

    def test_veritascoreignore_excludes_path(self):
        os.makedirs(os.path.join(self.d, "vendor"))
        self._write(os.path.join("vendor", "lib.py"),
                    "import os,shlex\ncmd=shlex.quote(cmd)\nos.system(cmd)\n")
        # without ignore: vendor teaches the contract
        self.assertIn("os.system", ng.build_policy(self.d))
        # with ignore: vendor excluded -> sink no longer observed at all
        self._write(".veritascoreignore", "*/vendor/*\n")
        pol = ng.build_policy(self.d)
        self.assertNotIn("os.system", pol)


class CliGating(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        shutil.copy(ENGINE, os.path.join(self.d, "veritas_core.py"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(content)

    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.d, check=True,
                       capture_output=True, text=True)

    def _run(self, *args, stdin=""):
        return subprocess.run([sys.executable, "veritas_core.py", *args],
                              cwd=self.d, input=stdin,
                              capture_output=True, text=True)

    def _repo(self):
        self._git("init"); self._git("add", "-A")

    def test_blocks_vuln_passes_safe(self):
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._write("vuln.py", "import os; cmd=input(); os.system(cmd)\n")
        self._repo()
        self.assertEqual(self._run(".").returncode, 1)

    def test_only_safe_staged_passes(self):
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._git("init"); self._git("add", "safe.py")
        self.assertEqual(self._run(".").returncode, 0)

    def test_learn_never_blocks(self):
        self._write("vuln.py", "import os; cmd=input(); os.system(cmd)\n")
        self._repo()
        self.assertEqual(self._run(".", "--learn").returncode, 0)

    def test_skip_with_reason_passes(self):
        self._write("v.py", "import os; cmd=input(); os.system(cmd)  # veritas-core: skip legacy JIRA-1\n")
        self._git("init"); self._git("add", "v.py")
        self.assertEqual(self._run(".").returncode, 0)

    def test_skip_without_reason_blocks(self):
        self._write("v.py", "import os; cmd=input(); os.system(cmd)  # veritas-core: skip\n")
        self._git("init"); self._git("add", "v.py")
        r = self._run(".")
        self.assertEqual(r.returncode, 1)
        self.assertIn("requires a reason", r.stderr)

    def test_apply_inserts_guard(self):
        self._write("vuln.py", "import os; cmd=input(); os.system(cmd)\n")
        self._repo()
        self.assertEqual(self._run(".", "--apply", "--no-interactive").returncode, 0)
        with open(os.path.join(self.d, "vuln.py")) as fh:
            fixed = fh.read()
        self.assertIn("shlex.quote(cmd)", fixed)
        # fix must keep the file syntactically valid
        import ast
        ast.parse(fixed)

    def test_min_confidence_relaxes_low_confidence(self):
        # one guarded + one unguarded -> confidence 0.5; require 0.9 -> not enforced
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._write("vuln.py", "import os; cmd=input(); os.system(cmd)\n")
        self._repo()
        self.assertEqual(self._run(".").returncode, 1)  # default min-conf 0
        self.assertEqual(self._run(".", "--min-confidence", "0.9").returncode, 0)

    def test_json_shape(self):
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._write("vuln.py", "import os; cmd=input(); os.system(cmd)\n")
        self._repo()
        out = self._run(".", "--json", "--file", os.path.join(self.d, "vuln.py")).stdout
        data = json.loads(out)
        self.assertIn("policy", data)
        self.assertIn("violations", data)
        v = data["violations"][0]
        for key in ("file", "line", "sink", "guard", "message", "fix", "severity"):
            self.assertIn(key, v)
        self.assertEqual(v["sink"], "os.system")
        self.assertEqual(v["severity"], "high")


class StatusClassification(unittest.TestCase):
    """New: data-flow status (guarded/unguarded/unknown/safe)."""

    def _status(self, src):
        sinks = ng.analyze(src)
        assert sinks
        return sinks[0].status

    def test_fstring_with_guard_is_guarded(self):
        # previously a FALSE POSITIVE: guard hidden inside the f-string
        self.assertEqual(
            self._status("import os,shlex\nos.system(f'ls {shlex.quote(x)}')"),
            "guarded")

    def test_fstring_with_source_is_unguarded(self):
        self.assertEqual(
            self._status("import os\ncmd=input()\nos.system(f'ls {cmd}')"),
            "unguarded")

    def test_concatenation_with_guard_is_guarded(self):
        self.assertEqual(
            self._status("import os,shlex\nos.system('ls ' + shlex.quote(x))"),
            "guarded")

    def test_nested_call_guard(self):
        self.assertEqual(
            self._status("import os\nos.system(quote(strip(x)))"),
            "guarded")

    def test_reassigned_param_is_guarded(self):
        # a parameter re-bound to a guarded value before the sink IS guarded
        self.assertEqual(
            self._status("import os,shlex\ndef a(c):\n c=shlex.quote(c)\n os.system(c)"),
            "guarded")

    def test_function_parameter_is_unknown(self):
        # previously a FALSE POSITIVE block: caller may have sanitised cmd
        self.assertEqual(
            self._status("import os\ndef run(cmd):\n os.system(cmd)"),
            "unknown")

    def test_ternary_is_unknown(self):
        self.assertEqual(
            self._status("import os\ncmd = a if cond else b\nos.system(cmd)"),
            "unknown")

    def test_constant_command_is_safe(self):
        self.assertEqual(self._status("import os\nos.system('ls -la')"), "safe")

    def test_unpacking_target_is_unknown(self):
        self.assertEqual(
            self._status("import os\ncmd, other = something()\nos.system(cmd)"),
            "unknown")

    def test_source_call_is_unguarded(self):
        self.assertEqual(self._status("import os\nos.system(input())"), "unguarded")


class StatusGating(unittest.TestCase):
    """New: status changes what blocks a commit."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        shutil.copy(ENGINE, os.path.join(self.d, "veritas_core.py"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(content)

    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.d, check=True, capture_output=True, text=True)

    def _run(self, *args):
        return subprocess.run([sys.executable, "veritas_core.py", *args],
                              cwd=self.d, capture_output=True, text=True)

    def test_unknown_param_does_not_block(self):
        # only a parameter-fed sink -> unknown -> must NOT block the commit
        self._write("h.py", "import os\ndef run(cmd):\n os.system(cmd)\n")
        self._git("init"); self._git("add", "h.py")
        self.assertEqual(self._run(".").returncode, 0)

    def test_constant_does_not_block(self):
        self._write("c.py", "import os\nos.system('ls -la')\n")
        self._git("init"); self._git("add", "c.py")
        self.assertEqual(self._run(".").returncode, 0)

    def test_guarded_fstring_does_not_block(self):
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._write("ok.py", "import os,shlex\nos.system(f'ls {shlex.quote(x)}')\n")
        self._git("init"); self._git("add", "safe.py", "ok.py")
        self.assertEqual(self._run(".").returncode, 0)

    def test_unguarded_fstring_blocks(self):
        self._write("safe.py", "import os,shlex; cmd=input(); cmd=shlex.quote(cmd); os.system(cmd)\n")
        self._write("bad.py", "import os\ncmd=input()\nos.system(f'ls {cmd}')\n")
        self._git("init"); self._git("add", "safe.py", "bad.py")
        self.assertEqual(self._run(".").returncode, 1)


class SinkTypedSql(unittest.TestCase):
    """Reproduces the false contracts seen on flask / fastapi-template."""

    def _status(self, src):
        return ng.analyze(src)[0].status

    def _guard(self, src):
        return ng.analyze(src)[0].guard

    def test_orm_delete_is_not_a_guard(self):
        # fastapi-template bug: sqlite3.execute -> delete (100%) was wrong
        s = ng.analyze("import x\ncur.execute(delete(User).where(c))")[0]
        self.assertEqual(s.status, "unknown")
        self.assertIsNone(s.guard)

    def test_password_hash_is_not_a_guard(self):
        # flask bug: sqlite3.execute -> generate_password_hash (100%) was wrong
        s = ng.analyze("import x\ncur.execute('insert', generate_password_hash(pw))")[0]
        # constant query string with no placeholder -> safe, NOT guarded-by-hash
        self.assertIn(s.status, ("safe", "unknown"))
        self.assertNotEqual(s.guard, "generate_password_hash")

    def test_parameterized_query_is_guarded(self):
        s = ng.analyze("import x\ncur.execute('select * from t where id=?', (i,))")[0]
        self.assertEqual(s.status, "guarded")
        self.assertEqual(s.guard, "parameterized")

    def test_fstring_query_is_unguarded(self):
        self.assertEqual(
            self._status("import x\ncur.execute(f'select * from t where id={i}')"),
            "unguarded")

    def test_concat_query_is_unguarded(self):
        self.assertEqual(
            self._status("import x\ncur.execute('select * from t where id=' + i)"),
            "unguarded")

    def test_static_query_is_safe(self):
        self.assertEqual(
            self._status("import x\ncur.execute('select 1')"), "safe")

    def test_query_variable_fstring_is_unguarded(self):
        self.assertEqual(
            self._status("import x\nq = f'select {i}'\ncur.execute(q)"),
            "unguarded")


class SinkTypedOpen(unittest.TestCase):
    def _status(self, src):
        return ng.analyze(src)[0].status

    def test_ospath_join_is_not_a_guard(self):
        # flask bug: open -> os.path.join (67%) was wrong
        s = ng.analyze("import os\nopen(os.path.join(base, name))")[0]
        self.assertEqual(s.status, "unknown")
        self.assertIsNone(s.guard)

    def test_constant_path_is_safe(self):
        self.assertEqual(self._status("open('/etc/config.txt')"), "safe")

    def test_secure_filename_is_guarded(self):
        s = ng.analyze("from werkzeug.utils import secure_filename\n"
                       "open(secure_filename(name))")[0]
        self.assertEqual(s.status, "guarded")
        self.assertEqual(s.guard, "secure_filename")


class Interprocedural(unittest.TestCase):
    """One-hop, same-file taint through function parameters."""

    def _status_of_sink(self, src, sink="os.system"):
        for s in ng.analyze(src):
            if s.name == sink:
                return s.status
        raise AssertionError("sink not found")

    def test_caller_passes_source_taints_param(self):
        # def run(cmd): os.system(cmd)  +  run(input())  -> unguarded inside run
        src = ("import os\n"
               "def run(cmd):\n os.system(cmd)\n"
               "run(input())\n")
        self.assertEqual(self._status_of_sink(src), "unguarded")

    def test_caller_passes_constant_keeps_safe(self):
        src = ("import os\n"
               "def run(cmd):\n os.system(cmd)\n"
               "run('ls -la')\n")
        self.assertEqual(self._status_of_sink(src), "safe")

    def test_caller_passes_guarded_value(self):
        src = ("import os, shlex\n"
               "def run(cmd):\n os.system(cmd)\n"
               "run(shlex.quote(x))\n")
        self.assertEqual(self._status_of_sink(src), "guarded")

    def test_no_callers_stays_unknown(self):
        src = "import os\ndef run(cmd):\n os.system(cmd)\n"
        self.assertEqual(self._status_of_sink(src), "unknown")

    def test_any_tainted_caller_wins(self):
        # one safe + one tainted caller -> conservative: tainted
        src = ("import os\n"
               "def run(cmd):\n os.system(cmd)\n"
               "run('safe')\n"
               "run(input())\n")
        self.assertEqual(self._status_of_sink(src), "unguarded")


class SourceAndDenylist(unittest.TestCase):
    def _status(self, src):
        return ng.analyze(src)[0].status

    def test_str_is_not_a_guard(self):
        # the subprocess.run -> str bug from veritas-core
        self.assertEqual(self._status("import subprocess\nsubprocess.run(str(x))"),
                         "unknown")

    def test_source_through_str_is_unguarded(self):
        self.assertEqual(self._status("import subprocess\nsubprocess.run(str(input()))"),
                         "unguarded")

    def test_web_source_is_unguarded(self):
        self.assertEqual(self._status("import os\nos.system(request.args.get('c'))"),
                         "unguarded")

    def test_int_wrapper_constant_is_safe(self):
        self.assertEqual(self._status("import os\nos.system(str(123))"), "safe")


class InterproceduralMethods(unittest.TestCase):
    """One-hop taint through class methods and self.<attr> (same file)."""

    def _status(self, src, sink="os.system"):
        for s in ng.analyze(src):
            if s.name == sink:
                return s.status
        raise AssertionError("sink not found")

    def test_method_tainted_via_self_call(self):
        self.assertEqual(self._status(
            "import os\nclass C:\n def run(self, cmd):\n  os.system(cmd)\n"
            " def h(self):\n  self.run(input())\n"), "unguarded")

    def test_method_tainted_via_obj_call(self):
        self.assertEqual(self._status(
            "import os\nclass C:\n def run(self, cmd):\n  os.system(cmd)\n"
            "c=C()\nc.run(input())\n"), "unguarded")

    def test_method_constant_caller_is_safe(self):
        self.assertEqual(self._status(
            "import os\nclass C:\n def run(self, cmd):\n  os.system(cmd)\n"
            "c=C()\nc.run('ls')\n"), "safe")

    def test_ambiguous_method_name_is_unknown(self):
        self.assertEqual(self._status(
            "import os\nclass A:\n def run(self, cmd):\n  os.system(cmd)\n"
            "class B:\n def run(self, cmd):\n  pass\n"
            "a=A()\na.run(input())\n"), "unknown")

    def test_self_attr_source_is_unguarded(self):
        self.assertEqual(self._status(
            "import os\nclass C:\n def __init__(self):\n  self.cmd=input()\n"
            " def run(self):\n  os.system(self.cmd)\n"), "unguarded")

    def test_self_attr_constant_is_safe(self):
        self.assertEqual(self._status(
            "import os\nclass C:\n def __init__(self):\n  self.cmd='ls'\n"
            " def run(self):\n  os.system(self.cmd)\n"), "safe")

    def test_self_attr_guarded(self):
        self.assertEqual(self._status(
            "import os, shlex\nclass C:\n def s(self, x):\n  self.cmd=shlex.quote(x)\n"
            " def run(self):\n  os.system(self.cmd)\n"), "guarded")

    def test_self_attr_ambiguous_across_classes_is_unknown(self):
        self.assertEqual(self._status(
            "import os\nclass A:\n def __init__(self):\n  self.cmd=input()\n"
            "class B:\n def __init__(self):\n  self.cmd='ls'\n"
            " def run(self):\n  os.system(self.cmd)\n"), "unknown")


class CrossFile(unittest.TestCase):
    """Experimental cross-file taint via analyze_project(cross_file=True)."""

    def _sink(self, res, path, sink="os.system"):
        return next((s.status for s in res[path] if s.name == sink), "no-sink")

    def test_cross_file_guard_wrapper_clears_call(self):
        # a sanitiser defined in utils.py clears a guarded call in handlers.py
        files = {"utils.py": "import shlex\ndef safe(x):\n return shlex.quote(x)\n",
                 "h.py": "import os\nfrom utils import safe\ndef h():\n"
                         " os.system(safe(input()))\n"}
        self.assertEqual(self._sink(
            ng.analyze_project(files, cross_file=True), "h.py"), "guarded")

    def test_cross_file_wrapper_respects_sink_type(self):
        # a shell wrapper from another file must NOT clear eval
        files = {"utils.py": "import shlex\ndef safe(x):\n return shlex.quote(x)\n",
                 "e.py": "from utils import safe\ndef e():\n eval(safe(input()))\n"}
        self.assertNotEqual(self._sink(
            ng.analyze_project(files, cross_file=True), "e.py", "eval"), "guarded")

    def test_cross_file_ambiguous_wrapper_not_resolved(self):
        # two different defs of `safe` -> ambiguous -> never resolved as a guard
        files = {"a.py": "import shlex\ndef safe(x):\n return shlex.quote(x)\n",
                 "b.py": "def safe(x):\n return x\n",
                 "h.py": "import os\nfrom b import safe\ndef h():\n"
                         " os.system(safe(input()))\n"}
        self.assertNotEqual(self._sink(
            ng.analyze_project(files, cross_file=True), "h.py"), "guarded")

    def test_default_single_file_leaves_param_unknown(self):
        files = {"b.py": "import os\ndef run(cmd):\n os.system(cmd)\n",
                 "a.py": "from b import run\nrun(input())\n"}
        res = ng.analyze_project(files, cross_file=False)
        self.assertEqual(self._sink(res, "b.py"), "unknown")

    def test_cross_file_taints_param_from_other_file(self):
        files = {"b.py": "import os\ndef run(cmd):\n os.system(cmd)\n",
                 "a.py": "from b import run\nrun(input())\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "b.py"), "unguarded")

    def test_cross_file_constant_caller_is_safe(self):
        files = {"b.py": "import os\ndef run(cmd):\n os.system(cmd)\n",
                 "a.py": "from b import run\nrun('ls')\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "b.py"), "safe")

    def test_import_resolves_specific_function(self):
        # `from b import run` disambiguates even though c.py also defines run:
        # import resolution correctly targets b.run -> taint propagates
        files = {"b.py": "import os\ndef run(cmd):\n os.system(cmd)\n",
                 "c.py": "def run(cmd):\n pass\n",
                 "a.py": "from b import run\nrun(input())\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "b.py"), "unguarded")

    def test_ambiguous_module_basename_skipped(self):
        # two files share a module basename -> resolution can't be sure -> skip
        files = {"pkg1/util.py": "import os\ndef run(cmd):\n os.system(cmd)\n",
                 "pkg2/util.py": "def run(cmd):\n pass\n",
                 "a.py": "from util import run\nrun(input())\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "pkg1/util.py"), "unknown")

    def test_cross_file_return_taint(self):
        files = {"src.py": "def get_input():\n return input()\n",
                 "app.py": "import os\nfrom src import get_input\n"
                           "os.system(get_input())\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "app.py"), "unguarded")

    def test_cross_file_constant_return_is_safe_not_fp(self):
        files = {"safe.py": "def proc(x):\n return 'constant'\n",
                 "app.py": "import os\nfrom safe import proc\nos.system(proc(y))\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "app.py"), "safe")

    def test_cross_file_module_alias_call(self):
        files = {"helpers.py": "def build():\n return input()\n",
                 "app.py": "import os\nimport helpers\n"
                           "os.system(helpers.build())\n"}
        res = ng.analyze_project(files, cross_file=True)
        self.assertEqual(self._sink(res, "app.py"), "unguarded")


class ShellGuardAllowlist(unittest.TestCase):
    """Only real command-line sanitisers count for shell sinks."""

    def _sg(self, src, sink="subprocess.run"):
        return next(((s.status, s.guard) for s in ng.analyze(src) if s.name == sink),
                    ("no-sink", None))

    def test_arbitrary_helper_is_not_a_contract(self):
        # the fastapi bug: subprocess.run -> stage_zensical_docs (50%)
        st, g = self._sg("import subprocess\nsubprocess.run(stage_zensical_docs(x))")
        self.assertEqual(st, "unknown")
        self.assertIsNone(g)

    def test_shlex_quote_is_guarded(self):
        st, g = self._sg("import subprocess, shlex\nsubprocess.run(shlex.quote(x))")
        self.assertEqual((st, g), ("guarded", "shlex.quote"))

    def test_os_system_arbitrary_call_unknown(self):
        st, g = self._sg("import os\nos.system(build_cmd(x))", sink="os.system")
        self.assertEqual(st, "unknown")

    def test_eval_arbitrary_call_not_guard(self):
        st, _ = self._sg("v=helper(x)\neval(v)", sink="eval")
        self.assertEqual(st, "unknown")

    def test_eval_literal_eval_is_guard(self):
        st, g = self._sg("import ast\neval(ast.literal_eval(x))", sink="eval")
        self.assertEqual((st, g), ("guarded", "ast.literal_eval"))


class ApplyFixHeader(unittest.TestCase):
    def test_import_inserted_after_shebang_and_docstring(self):
        src = ('#!/usr/bin/env python3\n"""Doc."""\nimport os\n'
               'def r():\n    cmd=input()\n    os.system(cmd)\n')
        sinks = ng.analyze(src)
        fixes = [(s, "shlex.quote") for s in sinks
                 if s.name == "os.system" and s.args]
        out = ng.apply_fixes(src, fixes)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("#!"))
        self.assertTrue(lines[1].startswith('"""'))
        self.assertIn("import shlex", out)
        self.assertLess(out.index("import shlex"), out.index("import os"))
        ast.parse(out)   # still valid Python

    def test_deeper_chain_resolves(self):
        # 4-hop assignment chain resolves past the old depth-3 limit
        src = ("import os, shlex\n"
               "def r(x):\n a=x\n b=a\n c=shlex.quote(b)\n d=c\n os.system(d)\n")
        st = next(s.status for s in ng.analyze(src) if s.name == "os.system")
        self.assertEqual(st, "guarded")


class LargeRepoGuards(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_oversize_file_is_skipped(self):
        with open(os.path.join(self.d, "giant.py"), "w") as f:
            f.write("x = 1\n" * 300000)          # ~1.8 MB
        with open(os.path.join(self.d, "ok.py"), "w") as f:
            f.write("import os\nos.system('ls')\n")
        rep = ng.audit(self.d)
        self.assertGreaterEqual(rep["skipped_large"], 1)
        self.assertEqual(rep["files_scanned"], 1)   # only ok.py analyzed

    def test_progress_callback_fires(self):
        for i in range(1100):
            with open(os.path.join(self.d, f"m{i}.py"), "w") as f:
                f.write("import os\nos.system('ls')\n")
        seen = []
        ng.audit(self.d, progress=lambda n: seen.append(n))
        self.assertTrue(seen and seen[0] == 500)


class SpecAccuracy(unittest.TestCase):
    """Regression tests for false contracts found on real repos (see ACCURACY_SPEC)."""

    def _sg(self, src, sink):
        return next(((s.status, s.guard) for s in ng.analyze(src) if s.name == sink),
                    ("no-sink", None))

    def test_pickle_dumps_is_not_a_guard(self):
        # TensorFlow bug: pickle.loads -> pickle.dumps (100%)
        st, g = self._sg("import pickle\npickle.loads(pickle.dumps(x))", "pickle.loads")
        self.assertEqual(st, "unknown")
        self.assertIsNone(g)

    def test_subprocess_argv_list_is_safe(self):
        # argv list without shell=True is not shell-injectable
        st, g = self._sg("import subprocess\nsubprocess.run([helper(x), a])",
                         "subprocess.run")
        self.assertEqual((st, g), ("safe", None))

    def test_subprocess_list_with_shell_true_not_safe(self):
        st, _ = self._sg("import subprocess\nsubprocess.run([x], shell=True)",
                         "subprocess.run")
        self.assertNotEqual(st, "safe")

    def test_subprocess_string_source_shell_true_unguarded(self):
        st, _ = self._sg("import subprocess\nsubprocess.run(input(), shell=True)",
                         "subprocess.run")
        self.assertEqual(st, "unguarded")

    def test_subprocess_shlex_quote_still_guarded(self):
        st, g = self._sg("import subprocess, shlex\nsubprocess.run(shlex.quote(x))",
                         "subprocess.run")
        self.assertEqual((st, g), ("guarded", "shlex.quote"))


class IncrementalCache(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def _w(self, name, txt):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(txt)

    def test_warm_scan_hits_cache_same_result(self):
        self._w("a.py", "import os\nos.system(input())\n")
        r1 = ng.audit(self.d)
        r2 = ng.audit(self.d)
        self.assertEqual(r2["cache_hits"], 1)
        self.assertEqual(r1["totals"], r2["totals"])

    def test_changed_file_invalidates_cache(self):
        self._w("a.py", "import os\nos.system('ls')\n")        # safe
        ng.audit(self.d)
        self._w("a.py", "import os\nos.system(input())\n")     # now unguarded
        r = ng.audit(self.d)
        self.assertEqual(r["cache_hits"], 0)
        self.assertEqual(r["totals"]["unguarded"], 1)

    def test_cache_can_be_disabled(self):
        self._w("a.py", "import os\nos.system('ls')\n")
        ng.audit(self.d, use_cache=False)
        r = ng.audit(self.d, use_cache=False)
        self.assertEqual(r["cache_hits"], 0)


class ParallelAudit(unittest.TestCase):
    def test_parallel_matches_serial(self):
        d = tempfile.mkdtemp()
        try:
            for i in range(40):
                with open(os.path.join(d, f"m{i}.py"), "w") as f:
                    f.write("import os,shlex\ndef f(x):\n os.system(shlex.quote(x))\n"
                            "def g(y):\n os.system(y)\n")
            r1 = ng.audit(d, use_cache=False, jobs=1)
            r4 = ng.audit(d, use_cache=False, jobs=4)
            self.assertEqual(r1["totals"], r4["totals"])
            self.assertEqual(r1["files_scanned"], r4["files_scanned"])
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class ReturnTaint(unittest.TestCase):
    """Taint propagation through function return values (coverage)."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_function_returning_source_taints_caller(self):
        self.assertEqual(self._st(
            "import os\ndef get_cmd():\n return input()\nos.system(get_cmd())\n"),
            "unguarded")

    def test_function_returning_web_source(self):
        self.assertEqual(self._st(
            "import os\ndef p():\n return request.args.get('c')\n"
            "cmd=p()\nos.system(cmd)\n"), "unguarded")

    def test_function_returning_constant_is_safe(self):
        self.assertEqual(self._st(
            "import os\ndef name():\n return 'ls -la'\nos.system(name())\n"), "safe")

    def test_passthrough_return_not_overclaimed(self):
        self.assertEqual(self._st(
            "import os\ndef f(x):\n return x\nos.system(f(y))\n"), "unknown")

    def test_guard_wrapper_recognised_for_matching_sink(self):
        # def g(x): return shlex.quote(x) is a provable shell guard wrapper ->
        # guarded for a shell sink (sink-type matches)
        self.assertEqual(self._st(
            "import os, shlex\ndef g(x):\n return shlex.quote(x)\n"
            "os.system(g(y))\n"), "guarded")

    def test_guard_wrapper_rejected_for_wrong_sink(self):
        # the same shell wrapper must NOT count as a guard for eval (wrong type)
        self.assertEqual(self._st(
            "import shlex\ndef g(x):\n return shlex.quote(x)\neval(g(y))\n",
            sink="eval"), "unknown")

    def test_ambiguous_function_name_unknown(self):
        self.assertEqual(self._st(
            "import os\ndef get():\n return input()\ndef get():\n return 'x'\n"
            "os.system(get())\n"), "unknown")


class DangerousConfig(unittest.TestCase):
    """High-risk advisory for shell=True / eval of an untraceable variable
    (the examples/vulnerable.py pattern), without false 'unguarded'."""

    def _risk(self, src, sink):
        return next(((s.status, s.risk) for s in ng.analyze(src) if s.name == sink),
                    ("no-sink", ""))

    def test_shell_true_undefined_var_is_high_risk(self):
        self.assertEqual(
            self._risk("import subprocess\nsubprocess.run(cmd, shell=True)",
                       "subprocess.run"), ("unknown", "high"))

    def test_eval_undefined_var_is_high_risk(self):
        self.assertEqual(self._risk("eval(user_input)", "eval"), ("unknown", "high"))

    def test_os_system_undefined_var_is_high_risk(self):
        self.assertEqual(self._risk("import os\nos.system(cmd)", "os.system"),
                         ("unknown", "high"))

    def test_param_wrapper_is_not_high_risk(self):
        # def run(cmd): os.system(cmd) defers to callers -> no noise
        self.assertEqual(
            self._risk("import os\ndef run(cmd):\n os.system(cmd)", "os.system"),
            ("unknown", ""))

    def test_shell_true_param_not_high_risk(self):
        self.assertEqual(
            self._risk("import subprocess\ndef r(cmd):\n subprocess.run(cmd, shell=True)",
                       "subprocess.run"), ("unknown", ""))

    def test_constant_eval_not_risk(self):
        self.assertEqual(self._risk("eval('1+1')", "eval"), ("safe", ""))

    def test_subprocess_no_shell_not_high_risk(self):
        self.assertEqual(self._risk("import subprocess\nsubprocess.run(cmd)",
                                    "subprocess.run"), ("unknown", ""))


class PrincipleZero(unittest.TestCase):
    """'Only truth': the engine never claims `guarded` without an admissible,
    sink-appropriate sanitiser, and never invents a contract without basis."""

    ADMISSIBLE = {"shlex.quote", "shlex.split", "shlex.join", "pipes.quote",
                  "quote", "ast.literal_eval", "parameterized",
                  "secure_filename", "werkzeug.utils.secure_filename"}

    def test_no_guarded_with_inadmissible_guard(self):
        # wrap dangerous sinks in arbitrary non-sanitiser functions; none may
        # ever be reported as guarded
        bad_wrappers = ["str", "helper", "clean", "process", "transform",
                        "pickle.dumps", "delete", "generate_password_hash",
                        "os.path.join", "build_cmd", "_find_executable_or_die"]
        sinks = [("os.system", "import os\nos.system({w}(x))"),
                 ("subprocess.run", "import subprocess\nsubprocess.run({w}(x))"),
                 ("eval", "eval({w}(x))"),
                 ("pickle.loads", "import pickle\npickle.loads({w}(x))")]
        for sink, tmpl in sinks:
            for w in bad_wrappers:
                src = tmpl.format(w=w)
                for s in ng.analyze(src):
                    if s.name == sink and s.status == "guarded":
                        self.fail(f"false guarded: {sink} via {w} in {src!r}")

    def test_every_guarded_basis_is_admissible(self):
        # any genuinely guarded result must name an admissible guard
        good = ["import os, shlex\nos.system(shlex.quote(x))",
                "import ast\neval(ast.literal_eval(x))",
                "import sqlite3\ncur.execute('select * from t where id=?', (i,))"]
        for src in good:
            for s in ng.analyze(src):
                if s.status == "guarded":
                    self.assertIn(s.guard, self.ADMISSIBLE,
                                  f"guarded by non-admissible {s.guard!r}: {src!r}")

    def test_unprovable_origin_is_unknown_not_guessed(self):
        # a value we cannot trace must be unknown, never silently safe/guarded
        for src, sink in [("import os\ndef f(x):\n os.system(x)", "os.system"),
                          ("import os\nos.system(mystery_global)", "os.system")]:
            st = next(s.status for s in ng.analyze(src) if s.name == sink)
            self.assertEqual(st, "unknown")


class ConcatAndFstringTaint(unittest.TestCase):
    """Sources inside string concatenation / f-strings reach shell sinks."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_concat_with_source_is_unguarded(self):
        self.assertEqual(self._st('import os\nos.system("echo " + input())'),
                         "unguarded")

    def test_fstring_with_source_is_unguarded(self):
        self.assertEqual(self._st('import os\nos.system(f"echo {input()}")'),
                         "unguarded")

    def test_concat_with_param_is_unknown_no_fp(self):
        self.assertEqual(self._st('import os\ndef f(x):\n os.system("a" + x)'),
                         "unknown")

    def test_fstring_with_param_is_unknown_no_fp(self):
        self.assertEqual(self._st('import os\ndef f(x):\n os.system(f"a{x}")'),
                         "unknown")

    def test_concat_with_guard_is_guarded(self):
        self.assertEqual(
            self._st('import os, shlex\nos.system("a" + shlex.quote(x))'), "guarded")

    def test_constant_fstring_is_safe(self):
        self.assertEqual(self._st('import os\nos.system(f"ls -la")'), "safe")


class AttributeAndSubscriptSources(unittest.TestCase):
    def _st(self, src, sink):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_request_data_attr_is_source(self):
        self.assertEqual(
            self._st("import pickle\npickle.loads(request.data)", "pickle.loads"),
            "unguarded")

    def test_os_environ_subscript_is_source(self):
        self.assertEqual(
            self._st("import os\nos.system(os.environ['X'])", "os.system"),
            "unguarded")

    def test_sys_argv_subscript_is_source(self):
        self.assertEqual(
            self._st("import os, sys\nos.system(sys.argv[1])", "os.system"),
            "unguarded")


class OpenPathTraversal(unittest.TestCase):
    def _st(self, src):
        return next((s.status for s in ng.analyze(src) if s.name == "open"), "no-sink")

    def test_open_of_source_is_unguarded(self):
        self.assertEqual(self._st("open(input())"), "unguarded")

    def test_open_of_web_source_is_unguarded(self):
        self.assertEqual(self._st("open(request.args.get('f'))"), "unguarded")

    def test_open_constant_is_safe(self):
        self.assertEqual(self._st("open('/etc/config')"), "safe")

    def test_open_secure_filename_is_guarded(self):
        self.assertEqual(self._st(
            "from werkzeug.utils import secure_filename\nopen(secure_filename(n))"),
            "guarded")

    def test_open_join_of_param_is_unknown(self):
        self.assertEqual(self._st("import os\nopen(os.path.join(base, name))"),
                         "unknown")

    def test_open_join_with_source_is_unguarded(self):
        self.assertEqual(self._st("import os\nopen(os.path.join(b, input()))"),
                         "unguarded")


class YamlLoadContract(unittest.TestCase):
    """yaml.load has no sanitiser wrapper: open() is not a guard (use safe_load)."""

    def _r(self, src):
        return next(((s.status, s.guard, s.risk) for s in ng.analyze(src)
                     if s.name == "yaml.load"), ("no-sink", None, ""))

    def test_open_is_not_a_yaml_guard(self):
        st, guard, _ = self._r("import yaml\nyaml.load(open(path))")
        self.assertEqual(st, "unknown")
        self.assertIsNone(guard)            # was falsely 'open'

    def test_yaml_load_nonconst_is_high_risk(self):
        st, _g, risk = self._r("import yaml\nyaml.load(data)")
        self.assertEqual((st, risk), ("unknown", "high"))

    def test_yaml_load_param_wrapper_not_noisy(self):
        _st, _g, risk = self._r("import yaml\ndef f(d):\n yaml.load(d)")
        self.assertEqual(risk, "")


class ContainerTaint(unittest.TestCase):
    """Taint through list/tuple containers, without breaking argv safety."""

    def _st(self, src, sink):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_tainted_list_var_with_shell_is_unguarded(self):
        self.assertEqual(self._st(
            "import subprocess\nargs=[input()]\nsubprocess.run(args, shell=True)",
            "subprocess.run"), "unguarded")

    def test_argv_var_without_shell_stays_safe(self):
        # a variable holding a list is argv, not a shell string -> no false positive
        self.assertEqual(self._st(
            "import subprocess\nargs=[input()]\nsubprocess.run(args)",
            "subprocess.run"), "safe")

    def test_argv_literal_without_shell_safe(self):
        self.assertEqual(self._st(
            "import subprocess\nsubprocess.run([input()])", "subprocess.run"), "safe")

    def test_list_in_eval_is_unguarded(self):
        self.assertEqual(self._st("eval([input()])", "eval"), "unguarded")

    def test_clean_list_is_safe(self):
        self.assertEqual(self._st(
            "import subprocess\nsubprocess.run(['ls', '-la'], shell=True)",
            "subprocess.run"), "safe")


class ExpandedSinks(unittest.TestCase):
    """New CWE coverage: SSRF, SSTI, XXE, more deserialisation/command/SQL."""

    def _r(self, src, sink):
        return next(((s.status, s.risk) for s in ng.analyze(src) if s.name == sink),
                    ("no-sink", ""))

    def test_ssrf_tainted_url_unguarded(self):
        self.assertEqual(self._r("import requests\nrequests.get(input())",
                                 "requests.get")[0], "unguarded")

    def test_ssrf_constant_url_safe(self):
        self.assertEqual(self._r("import requests\nrequests.get('https://a.com')",
                                 "requests.get")[0], "safe")

    def test_ssrf_post_tainted_data_not_flagged(self):
        # only the URL matters for SSRF; tainted POST body is not SSRF
        self.assertEqual(self._r(
            "import requests\nrequests.post('https://a.com', data=input())",
            "requests.post")[0], "safe")

    def test_urlopen_tainted_unguarded(self):
        self.assertEqual(self._r(
            "import urllib.request\nurllib.request.urlopen(input())",
            "urllib.request.urlopen")[0], "unguarded")

    def test_ssti_unguarded(self):
        self.assertEqual(self._r(
            "from flask import render_template_string\n"
            "render_template_string(input())", "render_template_string")[0],
            "unguarded")

    def test_xxe_lxml_unguarded(self):
        self.assertEqual(self._r("import lxml.etree\nlxml.etree.parse(input())",
                                 "lxml.etree.parse")[0], "unguarded")

    def test_os_popen_tainted_unguarded(self):
        self.assertEqual(self._r("import os\nos.popen(input())", "os.popen")[0],
                         "unguarded")

    def test_unsafe_yaml_high_risk(self):
        self.assertEqual(self._r("import yaml\nyaml.unsafe_load(data)",
                                 "yaml.unsafe_load"), ("unknown", "high"))

    def test_marshal_loads_high_risk(self):
        self.assertEqual(self._r("import marshal\nmarshal.loads(data)",
                                 "marshal.loads"), ("unknown", "high"))

    def test_executescript_fstring_unguarded(self):
        self.assertEqual(self._r("import sqlite3\ncur.executescript(f'x {y}')",
                                 "sqlite3.executescript")[0], "unguarded")

    def test_executescript_constant_safe(self):
        self.assertEqual(self._r("import sqlite3\ncur.executescript('drop t')",
                                 "sqlite3.executescript")[0], "safe")


class FlowSensitivity(unittest.TestCase):
    """Branch-aware taint: conditional sanitisation is not claimed as guarded."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_conditional_sanitization_not_guarded(self):
        # sanitised only inside `if` -> the else-path leaves raw input -> unguarded
        self.assertEqual(self._st(
            "import os, shlex\nx=input()\nif ok:\n x=shlex.quote(x)\nos.system(x)"),
            "unguarded")

    def test_sanitize_and_sink_same_branch_is_guarded(self):
        self.assertEqual(self._st(
            "import os, shlex\nif ok:\n x=shlex.quote(input())\n os.system(x)"),
            "guarded")

    def test_unconditional_overwrite_is_safe(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nx='safe'\nos.system(x)"), "safe")

    def test_unconditional_sanitize_is_guarded(self):
        self.assertEqual(self._st(
            "import os, shlex\nx=input()\nx=shlex.quote(x)\nos.system(x)"), "guarded")

    def test_augmented_assign_appends_taint(self):
        # x = 'ls '; x += input() -> x is tainted (was falsely 'safe')
        self.assertEqual(self._st(
            "import os\nx='ls '\nx+=input()\nos.system(x)"), "unguarded")

    def test_augmented_assign_clean_stays_safe(self):
        self.assertEqual(self._st(
            "import os\nx='ls '\nx+=' -la'\nos.system(x)"), "safe")

    def test_augmented_assign_onto_source(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nx+='a'\nos.system(x)"), "unguarded")


class FormatJoinTernaryTaint(unittest.TestCase):
    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_format_with_source(self):
        self.assertEqual(self._st("import os\nos.system('ls {}'.format(input()))"),
                         "unguarded")

    def test_format_constant_safe(self):
        self.assertEqual(self._st("import os\nos.system('ls {}'.format('x'))"), "safe")

    def test_join_tainted_list(self):
        self.assertEqual(self._st("import os\nos.system(' '.join([input()]))"),
                         "unguarded")

    def test_join_clean_list_safe(self):
        self.assertEqual(self._st("import os\nos.system(' '.join(['a','b']))"), "safe")

    def test_ternary_source_branch_unguarded(self):
        self.assertEqual(self._st("import os\nos.system(input() if x else 'safe')"),
                         "unguarded")

    def test_ternary_both_safe(self):
        self.assertEqual(self._st("import os\nos.system('a' if x else 'b')"), "safe")

    def test_ternary_with_guard(self):
        self.assertEqual(self._st(
            "import os, shlex\nos.system(shlex.quote(y) if x else 'safe')"), "guarded")

    def test_format_with_param_not_noisy(self):
        self.assertEqual(self._st(
            "import os\ndef f(p):\n os.system('ls {}'.format(p))"), "unknown")


class DictAccessTaint(unittest.TestCase):
    """Taint through dict-access methods on a tainted dict (request.args etc.)."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_get_on_tainted_dict_var(self):
        self.assertEqual(self._st(
            "import os\nd=request.args\nos.system(d.get('x'))"), "unguarded")

    def test_getlist_on_tainted_dict(self):
        self.assertEqual(self._st(
            "import os\nd=request.args\nos.system(d.getlist('x')[0])"), "unguarded")

    def test_get_on_unknown_object_is_unknown_no_fp(self):
        # a .get() on an object we can't prove is a source -> honest unknown
        self.assertEqual(self._st(
            "import os\ndef f(cfg):\n os.system(cfg.get('x'))"), "unknown")

    def test_get_on_plain_dict_not_unguarded(self):
        # the key property: a benign dict is NOT flagged as a vulnerability
        self.assertNotEqual(self._st(
            "import os\nd={'k':'v'}\nos.system(d.get('k'))"), "unguarded")


class BindingAndComprehensionTaint(unittest.TestCase):
    """Taint through for-loops, walrus, unpacking, comprehensions, subscripts,
    dict literals and string transforms — with no false positives on clean code."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    # --- should propagate taint ---
    def test_for_over_tainted_iterable(self):
        self.assertEqual(self._st(
            "import os\nfor a in request.args.values():\n os.system(a)"), "unguarded")

    def test_tuple_unpacking_from_source(self):
        self.assertEqual(self._st(
            "import os\na,b=input().split()\nos.system(a)"), "unguarded")

    def test_walrus_binding(self):
        self.assertEqual(self._st(
            "import os\nif (y:=input()):\n os.system(y)"), "unguarded")

    def test_dict_literal_value(self):
        self.assertEqual(self._st(
            "import os\nd={'k':input()}\nos.system(d['k'])"), "unguarded")

    def test_list_comprehension(self):
        self.assertEqual(self._st(
            "import os\nxs=[input() for _ in r]\nos.system(xs[0])"), "unguarded")

    def test_string_transform_keeps_taint(self):
        self.assertEqual(self._st("import os\nos.system(input().strip())"),
                         "unguarded")

    # --- must NOT become false positives ---
    def test_for_over_clean_list_safe(self):
        self.assertNotEqual(self._st(
            "import os\nfor a in ['ls','-l']:\n os.system(a)"), "unguarded")

    def test_unpacking_constants_safe(self):
        self.assertNotEqual(self._st("import os\na,b='ls','x'\nos.system(a)"),
                            "unguarded")

    def test_plain_dict_safe(self):
        self.assertNotEqual(self._st("import os\nd={'k':'v'}\nos.system(d['k'])"),
                            "unguarded")

    def test_constant_comprehension_safe(self):
        self.assertNotEqual(self._st(
            "import os\nxs=['ls' for _ in r]\nos.system(xs[0])"), "unguarded")

    def test_strip_on_param_not_fp(self):
        self.assertEqual(self._st(
            "import os\ndef f(p):\n os.system(p.strip())"), "unknown")


class NumericCoercionSanitizes(unittest.TestCase):
    """int()/len()/float() produce numbers that cannot carry injection."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_int_coercion_is_safe(self):
        self.assertEqual(self._st("import os\nos.system(str(int(input())))"), "safe")

    def test_len_is_safe(self):
        self.assertEqual(self._st("import os\nos.system(str(len(input())))"), "safe")

    def test_function_returning_len_is_safe(self):
        self.assertEqual(self._st(
            "import os\ndef sz(x):return len(x)\nos.system(str(sz(input())))"), "safe")

    def test_str_of_source_still_tainted(self):
        self.assertEqual(self._st("import os\nos.system(str(input()))"), "unguarded")

    def test_float_in_sql_fstring_is_safe(self):
        self.assertEqual(self._st(
            "import sqlite3\ncur.execute(f'select {float(input())}')",
            "sqlite3.execute"), "safe")

    def test_sql_fstring_untraceable_stays_unguarded(self):
        # f-string SQL with a non-numeric interpolation is the injection pattern
        self.assertEqual(self._st(
            "import sqlite3\ncur.execute(f'select {y}')", "sqlite3.execute"),
            "unguarded")


class GuardWrapperInference(unittest.TestCase):
    """A function that provably applies a guard to its parameter is a guard
    wrapper — recognised only for sinks whose type the guard fits."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_shell_wrapper_for_shell_sink(self):
        self.assertEqual(self._st(
            "import os, shlex\ndef safe(x):return shlex.quote(x)\n"
            "os.system(safe(input()))"), "guarded")

    def test_shell_wrapper_not_guard_for_eval(self):
        self.assertEqual(self._st(
            "import shlex\ndef safe(x):return shlex.quote(x)\neval(safe(input()))",
            "eval"), "unknown")

    def test_eval_wrapper_for_eval(self):
        self.assertEqual(self._st(
            "import ast\ndef p(x):return ast.literal_eval(x)\neval(p(input()))",
            "eval"), "guarded")

    def test_non_guard_wrapper_not_recognised(self):
        # def bad(x): return str(x) is not a guard wrapper -> never guarded
        self.assertNotEqual(self._st(
            "import os\ndef bad(x):return str(x)\nos.system(bad(input()))"),
            "guarded")

    def test_ambiguous_wrapper_name_not_recognised(self):
        self.assertNotEqual(self._st(
            "import os, shlex\ndef s(x):return shlex.quote(x)\n"
            "def s(x):return x\nos.system(s(input()))"), "guarded")


class IsinstanceNumericNarrowing(unittest.TestCase):
    """isinstance(x, int/float) inside a branch proves x is a number -> safe,
    but only numeric types, only the positive branch, no later reassignment."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_isinstance_int_is_safe(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nif isinstance(x,int):\n os.system(str(x))"), "safe")

    def test_isinstance_int_safe_for_sql(self):
        self.assertEqual(self._st(
            "import sqlite3\nif isinstance(x,int):\n cur.execute(f'select {x}')",
            "sqlite3.execute"), "safe")

    def test_else_branch_not_safe(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nif isinstance(x,int):\n pass\nelse:\n os.system(x)"),
            "unguarded")

    def test_isinstance_str_not_safe(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nif isinstance(x,str):\n os.system(x)"), "unguarded")

    def test_reassignment_after_check_not_safe(self):
        self.assertEqual(self._st(
            "import os\nif isinstance(x,int):\n x=input()\n os.system(x)"), "unguarded")

    def test_none_check_does_not_sanitise(self):
        self.assertEqual(self._st(
            "import os\nx=input()\nif x is not None:\n os.system(x)"), "unguarded")


class LazyAnalysis(unittest.TestCase):
    def test_file_without_sinks_returns_empty(self):
        # a file with no sink calls yields no findings (and skips taint building)
        self.assertEqual(ng.analyze(
            "def f(a, b):\n return [x*2 for x in range(b)] + [a]"), [])

    def test_file_with_sink_still_analysed(self):
        self.assertTrue(ng.analyze("import os\nos.system(input())"))


class AdvancedConfig(unittest.TestCase):
    """Optional .veritascore.json tunes perf/scope/strictness; absent or bad -> defaults,
    and it can never weaken what counts as a guard."""

    def _write(self, body):
        import tempfile, os
        d = tempfile.mkdtemp(prefix="nxcfg_")
        with open(os.path.join(d, ".veritascore.json"), "w") as fh:
            fh.write(body)
        ng._CONFIG_CACHE.clear()
        return d

    def test_absent_config_uses_defaults(self):
        ng._CONFIG_CACHE.clear()
        c = ng.load_config("/tmp/does_not_exist_nx")
        self.assertEqual(c["max_file_bytes"], ng._MAX_FILE_BYTES)
        self.assertFalse(c["cross_file"])

    def test_config_applies(self):
        d = self._write('{"max_file_bytes": 500000, "cross_file": true}')
        c = ng.load_config(d)
        self.assertEqual(c["max_file_bytes"], 500000)
        self.assertTrue(c["cross_file"])

    def test_bad_values_rejected(self):
        d = self._write('{"min_confidence": 5, "max_file_bytes": -1, "junk": 1}')
        c = ng.load_config(d)
        self.assertEqual(c["min_confidence"], 0.0)          # out of 0..1 -> default
        self.assertEqual(c["max_file_bytes"], ng._MAX_FILE_BYTES)  # <=0 -> default
        self.assertNotIn("junk", c)                          # unknown key dropped

    def test_broken_json_falls_back(self):
        d = self._write("{ not valid json")
        self.assertEqual(ng.load_config(d)["max_file_bytes"], ng._MAX_FILE_BYTES)


class ContainerMutationTaint(unittest.TestCase):
    """Taint added to a container after construction must not be lost
    (xs=[]; xs.append(input()) -> xs is tainted)."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_append_taint(self):
        self.assertEqual(self._st(
            "import os\nxs=[]\nxs.append(input())\nos.system(xs[0])"), "unguarded")

    def test_set_add_taint(self):
        self.assertEqual(self._st(
            "import os\ns=set()\ns.add(input())\nos.system(list(s)[0])"), "unguarded")

    def test_extend_with_source(self):
        self.assertEqual(self._st(
            "import os\nxs=[]\nxs.extend(request.args.values())\n"
            "os.system(xs[0])"), "unguarded")

    def test_clean_append_no_false_positive(self):
        self.assertEqual(self._st(
            "import os\nxs=[]\nxs.append('ls')\nos.system(xs[0])"), "safe")


class ConditionalGuardSoundness(unittest.TestCase):
    """A guard in one branch of a ternary/boolean must not clear the whole value
    (the other branch may be raw) — a previously-found false-clear."""

    def _st(self, src, sink="os.system"):
        return next((s.status for s in ng.analyze(src) if s.name == sink), "no-sink")

    def test_ternary_guard_else_raw_is_unguarded(self):
        self.assertEqual(self._st(
            "import os, shlex\nx=shlex.quote(input()) if c else input()\n"
            "os.system(x)"), "unguarded")

    def test_ternary_both_guarded(self):
        self.assertEqual(self._st(
            "import os, shlex\nx=shlex.quote(a) if c else shlex.quote(b)\n"
            "os.system(x)"), "guarded")

    def test_guard_wrapping_ternary(self):
        self.assertEqual(self._st(
            "import os, shlex\nos.system(shlex.quote(a if c else b))"), "guarded")

    def test_boolop_with_source_is_unguarded(self):
        self.assertEqual(self._st(
            "import os\nx=d or input()\nos.system(x)"), "unguarded")

    def test_mutation_then_reassign_is_clean(self):
        # a clean unconditional reassignment after a tainting mutation clears it
        self.assertEqual(self._st(
            "import os\nxs=[]\nxs.append(input())\nxs=['safe']\n"
            "os.system(xs[0])"), "safe")


class GitIncrementalMode(unittest.TestCase):
    """Team/CI incremental scan: only files changed vs git are analysed."""

    def _repo(self):
        import subprocess, tempfile
        d = tempfile.mkdtemp(prefix="nxgit_")
        run = lambda *a: subprocess.run(["git", *a], cwd=d,
                                        capture_output=True, text=True)
        run("init"); run("config", "user.email", "t@t.t")
        run("config", "user.name", "t")
        with open(os.path.join(d, "base.py"), "w") as f:
            f.write("import os\ndef a():\n os.system('ls')\n")
        run("add", "-A"); run("commit", "-m", "base")
        return d, run

    def test_changed_file_is_scanned(self):
        d, run = self._repo()
        with open(os.path.join(d, "vuln.py"), "w") as f:
            f.write("import os\ndef b():\n os.system(input())\n")
        run("add", "-A"); run("commit", "-m", "vuln")
        res = ng.audit_changed(d, "HEAD~1")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["sink"], "os.system")

    def test_unchanged_files_skipped(self):
        d, run = self._repo()
        # base.py is committed and unchanged -> not in the incremental scan
        with open(os.path.join(d, "note.txt"), "w") as f:
            f.write("x")
        run("add", "-A")
        res = ng.audit_changed(d, None)
        self.assertEqual(res["changed_files"], 0)

    def test_non_git_dir_reports_error(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="nxnogit_")
        res = ng.audit_changed(d, None)
        self.assertIn("error", res)


class CrossFileParallelEquivalence(unittest.TestCase):
    """Cross-file analysis must give identical results whether run serially or in
    parallel — parallelism is a speed-up, never a change in verdicts."""

    def _repo(self):
        import tempfile, os
        d = tempfile.mkdtemp(prefix="nxxfpar_")
        with open(os.path.join(d, "utils.py"), "w") as f:
            f.write("import shlex\ndef safe(x):\n return shlex.quote(x)\n")
        for i in range(12):
            with open(os.path.join(d, f"h{i}.py"), "w") as f:
                f.write("import os\nfrom utils import safe\n"
                        f"def h{i}():\n os.system(safe(input()))\n")
        return d

    def test_serial_equals_parallel(self):
        import json, os
        d = self._repo()
        # force the parallel branch with a low threshold
        with open(os.path.join(d, ".veritascore.json"), "w") as f:
            json.dump({"parallel_min_files": 2, "parallel_min_bytes": 100}, f)
        ng._CONFIG_CACHE.clear()
        par = ng.audit(d, cross_file=True, jobs=2)["totals"]
        os.remove(os.path.join(d, ".veritascore.json"))
        ng._CONFIG_CACHE.clear()
        ser = ng.audit(d, cross_file=True, jobs=1)["totals"]
        self.assertEqual(dict(par), dict(ser))


class SkipDirectiveInAudit(unittest.TestCase):
    """`# veritas-core: skip <reason>` suppresses a finding in the audit report too, not
    only in the gate — consistently honoring the human review override."""

    def test_skip_with_reason_suppresses_finding(self):
        import tempfile, os
        d = tempfile.mkdtemp(prefix="nxskip_")
        with open(os.path.join(d, "s.py"), "w") as f:
            f.write("import os\ndef h():\n"
                    " os.system(input())  # veritas-core: skip reviewed\n")
        rep = ng.audit(d)
        self.assertEqual(len(rep["findings"]), 0)
        self.assertEqual(rep["skipped"], 1)

    def test_skip_without_reason_still_reported(self):
        import tempfile, os
        d = tempfile.mkdtemp(prefix="nxskip2_")
        with open(os.path.join(d, "s.py"), "w") as f:
            f.write("import os\ndef h():\n os.system(input())  # veritas-core: skip\n")
        rep = ng.audit(d)
        self.assertEqual(len(rep["findings"]), 1)   # bare skip is not honored


if __name__ == "__main__":
    unittest.main(verbosity=2)
