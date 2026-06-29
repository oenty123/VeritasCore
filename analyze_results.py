#!/usr/bin/env python3
"""Анализирует результаты сканирования RealVuln и выводит сводку."""
import json
import glob
from collections import defaultdict

def main():
    totals = defaultdict(int)
    by_sink = defaultdict(lambda: {"guarded": 0, "unguarded": 0, "unknown": 0, "safe": 0})
    files_total = 0
    sinks_total = 0

    for f in glob.glob("realvuln_results_all/*.json"):
        try:
            with open(f) as fp:
                data = json.load(fp)
        except Exception as e:
            print(f"Ошибка чтения {f}: {e}")
            continue

        files_total += data.get("files_scanned", 0)
        sinks_total += data.get("sinks_total", 0)
        t = data.get("totals", {})
        for k, v in t.items():
            totals[k] += v

        for sink, stats in data.get("by_sink", {}).items():
            for status in ("guarded", "unguarded", "unknown", "safe"):
                by_sink[sink][status] += stats.get(status, 0)

    print("=" * 60)
    print("📊 СВОДКА ПО ВСЕМ РЕПОЗИТОРИЯМ")
    print("=" * 60)
    print(f"Всего файлов: {files_total}")
    print(f"Всего sink'ов: {sinks_total}")
    print("\nСтатусы (по всем sink'ам):")
    for status in ["guarded", "unguarded", "unknown", "safe"]:
        print(f"  {status:10}: {totals[status]:5}")

    # Покрытие
    determinable = totals["guarded"] + totals["unguarded"]
    coverage = round(totals["guarded"] / determinable * 100, 1) if determinable else 0
    print(f"\nПокрытие (guarded / determinable): {coverage}%")

    # Топ-10 sink'ов по unknown
    print("\n🔝 Топ-10 sink'ов по количеству unknown (и общие статусы):")
    sorted_by_unknown = sorted(by_sink.items(), key=lambda x: x[1]["unknown"], reverse=True)
    for sink, stats in sorted_by_unknown[:10]:
        u = stats["unguarded"]
        uk = stats["unknown"]
        g = stats["guarded"]
        s = stats["safe"]
        print(f"  {sink:30} | U={u:3} | ?={uk:3} | G={g:3} | S={s:3}")

    # Топ-10 sink'ов по unguarded (самые опасные)
    print("\n🔥 Топ-10 sink'ов с наибольшим числом unguarded:")
    sorted_by_unguarded = sorted(by_sink.items(), key=lambda x: x[1]["unguarded"], reverse=True)
    for sink, stats in sorted_by_unguarded[:10]:
        u = stats["unguarded"]
        uk = stats["unknown"]
        g = stats["guarded"]
        s = stats["safe"]
        print(f"  {sink:30} | U={u:3} | ?={uk:3} | G={g:3} | S={s:3}")

if __name__ == "__main__":
    main()