#!/usr/bin/env python3
"""benchmark.py — measurable accuracy benchmark (Principle Zero).

A four-state engine can ABSTAIN (`unknown`); abstention is NOT a false positive.
Reported by CWE so "low false-positive rate" is a measured fact, not a slogan.
"""
import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import veritas_core as ng


def C(src, sink, label, cwe, advisory_ok=False):
    return {"src": src, "sink": sink, "label": label, "cwe": cwe,
            "advisory_ok": advisory_ok}


CORPUS = [
    # CWE-78 OS Command Injection
    C("import os\nos.system(input())", "os.system", "vuln", "CWE-78"),
    C("import os\nos.system(request.args.get('c'))", "os.system", "vuln", "CWE-78"),
    C("import os\ncmd=input()\nos.system(cmd)", "os.system", "vuln", "CWE-78"),
    C("import os\nos.system('echo ' + input())", "os.system", "vuln", "CWE-78"),
    C("import os\nos.system(f'echo {input()}')", "os.system", "vuln", "CWE-78"),
    C("import subprocess\nsubprocess.run(input(), shell=True)", "subprocess.run", "vuln", "CWE-78"),
    C("import subprocess\nsubprocess.call(request.form.get('x'), shell=True)", "subprocess.call", "vuln", "CWE-78"),
    C("import os\ndef get():\n return input()\nos.system(get())", "os.system", "vuln", "CWE-78"),
    C("import os, sys\nos.system(sys.argv[1])", "os.system", "vuln", "CWE-78", advisory_ok=True),
    C("import os\nos.system(os.environ['CMD'])", "os.system", "vuln", "CWE-78", advisory_ok=True),
    C("import os, shlex\nos.system(shlex.quote(x))", "os.system", "safe", "CWE-78"),
    C("import subprocess\nsubprocess.run(['ls', '-la', path])", "subprocess.run", "safe", "CWE-78"),
    C("import subprocess, shlex\nsubprocess.run(shlex.split(cmd))", "subprocess.run", "safe", "CWE-78"),
    C("import os\nos.system('ls -la')", "os.system", "safe", "CWE-78"),
    C("import os\nos.system('git status')", "os.system", "safe", "CWE-78"),
    C("import subprocess\nsubprocess.run(['git', 'commit', '-m', msg])", "subprocess.run", "safe", "CWE-78"),
    C("import os, shlex\nos.system('echo ' + shlex.quote(x))", "os.system", "safe", "CWE-78"),
    C("import os\ndef run(cmd):\n os.system(cmd)", "os.system", "amb", "CWE-78"),
    C("import os\nos.system(config.value)", "os.system", "amb", "CWE-78"),
    C("import subprocess\ndef r(c):\n subprocess.run(c)", "subprocess.run", "amb", "CWE-78"),
    # CWE-89 SQL Injection
    C("import sqlite3\ncur.execute(f'select * from t where id={input()}')", "sqlite3.execute", "vuln", "CWE-89"),
    C("import sqlite3\ncur.execute('select * from t where n=' + name)", "sqlite3.execute", "vuln", "CWE-89"),
    C("import sqlite3\ncur.execute('select * from t where n=%s' % name)", "sqlite3.execute", "vuln", "CWE-89"),
    C("import sqlite3\ncur.execute('select * from t where n={}'.format(n))", "sqlite3.execute", "vuln", "CWE-89"),
    C("import sqlite3\ncur.execute('select * from t where id=?', (i,))", "sqlite3.execute", "safe", "CWE-89"),
    C("import sqlite3\ncur.execute('select * from t where n=:n', {'n': n})", "sqlite3.execute", "safe", "CWE-89"),
    C("import sqlite3\ncur.execute('select 1')", "sqlite3.execute", "safe", "CWE-89"),
    C("import sqlite3\ncur.execute('insert into t values (?, ?)', (a, b))", "sqlite3.execute", "safe", "CWE-89"),
    C("import sqlite3\ncur.execute(delete(User).where(c))", "sqlite3.execute", "amb", "CWE-89"),
    C("import sqlite3\ncur.execute(query)", "sqlite3.execute", "amb", "CWE-89"),
    # CWE-94 Code Injection
    C("eval(input())", "eval", "vuln", "CWE-94"),
    C("eval(request.args.get('x'))", "eval", "vuln", "CWE-94"),
    C("exec(input())", "exec", "vuln", "CWE-94"),
    C("eval('1+' + input())", "eval", "vuln", "CWE-94"),
    C("import ast\neval(ast.literal_eval(x))", "eval", "safe", "CWE-94"),
    C("eval('1+1')", "eval", "safe", "CWE-94"),
    C("exec('x = 1')", "exec", "safe", "CWE-94"),
    C("eval(expr)", "eval", "amb", "CWE-94", advisory_ok=True),
    # CWE-502 Deserialization
    C("import pickle\npickle.loads(request.data)", "pickle.loads", "vuln", "CWE-502", advisory_ok=True),
    C("import pickle\npickle.loads(pickle.dumps(x))", "pickle.loads", "safe", "CWE-502"),
    C("import pickle\npickle.loads(b'abc')", "pickle.loads", "safe", "CWE-502"),
    C("import pickle\npickle.loads(data)", "pickle.loads", "amb", "CWE-502"),
    # CWE-22 Path Traversal
    C("open(input())", "open", "vuln", "CWE-22"),
    C("open(request.args.get('f'))", "open", "vuln", "CWE-22"),
    C("open('/etc/config.txt')", "open", "safe", "CWE-22"),
    C("from werkzeug.utils import secure_filename\nopen(secure_filename(n))", "open", "safe", "CWE-22"),
    C("import os\nopen(os.path.join(base, name))", "open", "amb", "CWE-22"),
    C("open(path)", "open", "amb", "CWE-22"),
    # CWE-918 SSRF
    C("import requests\nrequests.get(input())", "requests.get", "vuln", "CWE-918"),
    C("import requests\nrequests.get(request.args.get('u'))", "requests.get", "vuln", "CWE-918"),
    C("import urllib.request\nurllib.request.urlopen(input())", "urllib.request.urlopen", "vuln", "CWE-918"),
    C("import requests\nrequests.get('https://api.example.com/v1')", "requests.get", "safe", "CWE-918"),
    C("import requests\nrequests.post('https://api.example.com', data=input())", "requests.post", "safe", "CWE-918"),
    C("import requests\nrequests.get(url)", "requests.get", "amb", "CWE-918"),
    # CWE-94 SSTI
    C("from flask import render_template_string\nrender_template_string(input())", "render_template_string", "vuln", "CWE-94"),
    C("from flask import render_template_string\nrender_template_string('<h1>hi</h1>')", "render_template_string", "safe", "CWE-94"),
    # CWE-611 XXE
    C("import lxml.etree\nlxml.etree.parse(input())", "lxml.etree.parse", "vuln", "CWE-611"),
    C("import lxml.etree\nlxml.etree.fromstring(request.data)", "lxml.etree.fromstring", "vuln", "CWE-611"),
    C("import lxml.etree\nlxml.etree.parse('config.xml')", "lxml.etree.parse", "safe", "CWE-611"),
    # CWE-502 more deserialization
    C("import yaml\nyaml.unsafe_load(data)", "yaml.unsafe_load", "vuln", "CWE-502", advisory_ok=True),
    C("import marshal\nmarshal.loads(data)", "marshal.loads", "vuln", "CWE-502", advisory_ok=True),
    # guard wrappers + numeric coercion (depth, must stay precise)
    C("import os, shlex\ndef safe(x):return shlex.quote(x)\nos.system(safe(input()))", "os.system", "safe", "CWE-78"),
    C("import os\nos.system(str(int(input())))", "os.system", "safe", "CWE-78"),
    C("import os\nos.system(str(len(input())))", "os.system", "safe", "CWE-78"),
    C("import sqlite3\ncur.execute(f'select {int(input())}')", "sqlite3.execute", "safe", "CWE-89"),
]


def status_of(src, sink):
    for s in ng.analyze(src):
        if s.name == sink:
            return s.status, getattr(s, "risk", "")
    return "no-sink", ""


def run(verbose=True):
    agg = defaultdict(lambda: defaultdict(int))
    fails = []
    for case in CORPUS:
        st, risk = status_of(case["src"], case["sink"])
        flag = st == "unguarded"
        clear = st in ("safe", "guarded")
        label, cwe = case["label"], case["cwe"]
        detected = flag or (case["advisory_ok"] and risk == "high")
        if label == "vuln":
            if detected:
                agg[cwe]["TP"] += 1
            elif clear:
                agg[cwe]["FN"] += 1; fails.append((case, st, "FALSE-CLEAR"))
            else:
                agg[cwe]["miss"] += 1; fails.append((case, st, "MISSED"))
        elif label == "safe":
            if flag:
                agg[cwe]["FP"] += 1; fails.append((case, st, "CRIED-WOLF"))
            elif clear:
                agg[cwe]["TN"] += 1
            else:
                agg[cwe]["abst"] += 1
        else:
            if flag:
                agg[cwe]["FP"] += 1; fails.append((case, st, "CRIED-WOLF"))
            elif clear:
                agg[cwe]["over"] += 1; fails.append((case, st, "OVER-CLAIM"))
            else:
                agg[cwe]["abst"] += 1

    tot = defaultdict(int)
    for cwe in agg:
        for k, v in agg[cwe].items():
            tot[k] += v
    n_vuln = sum(1 for c in CORPUS if c["label"] == "vuln")
    n_safe = sum(1 for c in CORPUS if c["label"] in ("safe", "amb"))
    fp_rate = tot["FP"] / n_safe if n_safe else 0
    detect = tot["TP"] / n_vuln if n_vuln else 0

    print("Nexus accuracy benchmark  (%d cases)" % len(CORPUS))
    print("=" * 64)
    print(f"{'CWE':10} {'TP':>3} {'FN':>3} {'miss':>4} {'FP':>3} {'TN':>3} {'over':>4} {'abst':>4}")
    for cwe in sorted(agg):
        a = agg[cwe]
        print(f"{cwe:10} {a['TP']:>3} {a['FN']:>3} {a['miss']:>4} {a['FP']:>3} {a['TN']:>3} {a['over']:>4} {a['abst']:>4}")
    print("-" * 64)
    print(f"FALSE-POSITIVE RATE : {fp_rate*100:5.1f}%   (FP={tot['FP']} on {n_safe} safe/amb)")
    print(f"FALSE-CLEAR (FN)    : {tot['FN']:5}    (said safe when vulnerable)")
    print(f"detection           : {detect*100:5.1f}%   (TP={tot['TP']} of {n_vuln}; miss={tot['miss']})")
    print(f"over-claim          : {tot['over']:5}    (claimed safe without proof)")
    print(f"abstentions         : {tot['abst']:5}    (honest unknown — not an FP)")
    if fails and verbose:
        print("-" * 64)
        print("cases needing attention (shown, not hidden):")
        for case, st, why in fails:
            print(f"  [{why}] {case['cwe']} {case['sink']}: {st}  ::  {case['src'][:56].replace(chr(10),' | ')}")
    return tot["FP"], tot["FN"], tot["over"], tot["miss"]


if __name__ == "__main__":
    fp, fn, over, miss = run()
    sys.exit(0 if (fp == 0 and fn == 0 and over == 0) else 1)
