#!/usr/bin/env python3
"""
scan_realvuln.py — сканирует все подпроекты RealVuln и собирает результаты.
"""
import os
import subprocess
import json
from pathlib import Path

BENCHMARK_ROOT = "./Real-Vuln-Benchmark"
OUTPUT_FILE = "realvuln_aggregated.json"

def main():
    results = {}
    benchmark_path = Path(BENCHMARK_ROOT)
    if not benchmark_path.exists():
        print(f"❌ Папка {BENCHMARK_ROOT} не найдена")
        return

    # Ищем все подпапки, начинающиеся с realvuln-
    repos = [p for p in benchmark_path.iterdir() if p.is_dir() and p.name.startswith("realvuln-")]
    if not repos:
        print("❌ Не найдено ни одного репозитория realvuln-*")
        return

    print(f"🔍 Найдено {len(repos)} репозиториев для сканирования")

    for repo in repos:
        print(f"📂 Сканируем {repo.name}...")
        cmd = ["python3", "veritas_core.py", str(repo), "--audit", "--json", "--aggressive"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                print(f"⚠️  Ошибка при сканировании {repo.name}: {proc.stderr}")
                results[repo.name] = {"error": proc.stderr}
                continue
            # Парсим JSON
            try:
                data = json.loads(proc.stdout)
                results[repo.name] = data
                print(f"✅ {repo.name}: найдено {len(data.get('violations', []))} нарушений")
            except json.JSONDecodeError as e:
                print(f"⚠️  Некорректный JSON от {repo.name}: {e}")
                results[repo.name] = {"error": "invalid JSON", "raw": proc.stdout}
        except subprocess.TimeoutExpired:
            print(f"⏰ Тайм-аут при сканировании {repo.name}")
            results[repo.name] = {"error": "timeout"}

    # Сохраняем агрегированный результат
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"📄 Агрегированный результат сохранён в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()