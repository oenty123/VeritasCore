#!/usr/bin/env python3
"""Конвертирует JSON Nexus в формат RealVuln для score.py."""
import json
import sys
import os

def convert_nexus_to_realvuln(nexus_json_path):
    with open(nexus_json_path) as f:
        data = json.load(f)
    
    results = []
    for v in data.get("violations", []):
        # Определяем CWE по имени sink'а
        cwe_map = {
            "os.system": "CWE-78",
            "os.popen": "CWE-78",
            "subprocess.run": "CWE-78",
            "subprocess.call": "CWE-78",
            "subprocess.Popen": "CWE-78",
            "sqlite3.execute": "CWE-89",
            "sqlite3.executescript": "CWE-89",
            "eval": "CWE-94",
            "exec": "CWE-94",
            "open": "CWE-22",
            "pickle.loads": "CWE-502",
            "yaml.load": "CWE-502",
            "yaml.unsafe_load": "CWE-502",
            "yaml.full_load": "CWE-502",
            "marshal.loads": "CWE-502",
            "requests.get": "CWE-918",
            "requests.post": "CWE-918",
            "urllib.request.urlopen": "CWE-918",
            "render_template_string": "CWE-94",
            "flask.render_template_string": "CWE-94",
            "lxml.etree.parse": "CWE-611",
            "lxml.etree.fromstring": "CWE-611",
            "xml.etree.ElementTree.parse": "CWE-611",
            "xml.etree.ElementTree.fromstring": "CWE-611",
        }
        cwe = cwe_map.get(v.get("sink"), "CWE-unknown")
        results.append({
            "file": v.get("file"),
            "line": v.get("line"),
            "vulnerability_type": cwe,
            "confidence": "high" if v.get("severity") in ("high", "critical") else "medium"
        })
    
    # Формат RealVuln: {"scanner": "nexus", "findings": [...]}
    output = {"scanner": "nexus", "findings": results}
    with open("nexus_realvuln.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"Converted {len(results)} findings to RealVuln format.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 realvuln_parser.py <nexus_output.json>")
        sys.exit(1)
    convert_nexus_to_realvuln(sys.argv[1])