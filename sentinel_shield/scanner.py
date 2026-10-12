"""Batch Directory Scanner for Sentinel Shield.

Scans an entire repository of Python code using sub-millisecond AST parsing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from sentinel_shield.core.ast_visitor import scan_source_code as audit_python_source
from sentinel_shield.core.cwe_rules import Severity


def scan_directory(target_dir: str | Path, max_files: int = 500) -> dict:
    """Scan all Python files in a directory recursively."""
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    start_scan = time.perf_counter()
    scanned_files = 0
    total_findings = 0
    results = []

    # Directories to ignore
    ignored_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", "dist", "build"}

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for f in files:
            if f.endswith(".py"):
                file_path = Path(root) / f
                scanned_files += 1
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                    
                    rel_path = str(file_path.relative_to(target_path))
                    audit = audit_python_source(content, filename=rel_path)
                    if audit.findings_count > 0:
                        total_findings += audit.findings_count
                        results.append(audit)
                except Exception as ex:
                    pass

                if scanned_files >= max_files:
                    break
        if scanned_files >= max_files:
            break

    total_time = (time.perf_counter() - start_scan) * 1000.0

    return {
        "target_directory": str(target_path),
        "total_files_scanned": scanned_files,
        "vulnerable_files_count": len(results),
        "total_findings": total_findings,
        "scan_time_ms": round(total_time, 2),
        "findings_by_file": [r.model_dump() for r in results],
    }


def main():
    parser = argparse.ArgumentParser(description="Sentinel Shield Batch Scanner")
    parser.add_argument("target", help="Path to directory or project to audit")
    parser.add_argument("--max-files", type=int, default=500, help="Max files to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    data = scan_directory(args.target, max_files=args.max_files)

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print("=" * 70)
    print("🛡️  SENTINEL SHIELD: RESUMEN DE AUDITORÍA FORENSE M2M")
    print("=" * 70)
    print(f"📁 Directorio Objetivo: {data['target_directory']}")
    print(f"📄 Archivos Analizados: {data['total_files_scanned']}")
    print(f"🚨 Archivos Vulnerables: {data['vulnerable_files_count']}")
    print(f"💥 Total de Vulnerabilidades: {data['total_findings']}")
    print(f"⚡ Tiempo Total de Análisis: {data['scan_time_ms']} ms ({data['scan_time_ms']/1000:.3f} s)")
    print("=" * 70)

    for item in data["findings_by_file"]:
        print(f"\n📂 Archivo: {item['target']}")
        for f in item["findings"]:
            sev_badge = f"[{f['severity']}]"
            print(f"   🔴 {sev_badge} {f['cwe_id']} - {f['title']}")
            print(f"      Línea: {f['line_number']}")
            print(f"      Código: {f['snippet']}")
            print(f"      Riesgo: {f['description']}")
            print(f"      Solución: {f['remediation']}")
            print("-" * 65)


if __name__ == "__main__":
    main()
