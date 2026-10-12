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
from sentinel_shield.core.symbolic_engine import SymbolicAnalyzer


def scan_directory(target_dir: str | Path, max_files: int = 500, include_symbolic: bool = False) -> dict:
    """Scan all Python files in a directory recursively."""
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    start_scan = time.perf_counter()
    scanned_files = 0
    total_findings = 0
    results = []
    symbolic_violations = []

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

                    if include_symbolic:
                        sym_results = SymbolicAnalyzer.audit_all_invariants(content)
                        for sym in sym_results:
                            symbolic_violations.append({
                                "file": rel_path,
                                "function": sym.target_function,
                                "invariant": sym.invariant_tested,
                                "summary": sym.summary,
                                "counterexample": (
                                    {
                                        "input_assignments": sym.counterexample.input_assignments,
                                        "resulting_state": sym.counterexample.resulting_state,
                                        "violated_property": sym.counterexample.violated_property,
                                        "explanation": sym.counterexample.explanation,
                                    }
                                    if sym.counterexample
                                    else None
                                ),
                            })
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
        "symbolic_violations_count": len(symbolic_violations),
        "symbolic_violations": symbolic_violations,
        "scan_time_ms": round(total_time, 2),
        "findings_by_file": [r.model_dump() for r in results],
    }


def main():
    parser = argparse.ArgumentParser(description="Sentinel Shield Batch Scanner")
    parser.add_argument("target", help="Path to directory or project to audit")
    parser.add_argument("--max-files", type=int, default=500, help="Max files to scan")
    parser.add_argument("--symbolic", action="store_true", help="Run deep M2M formal invariant verification")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    data = scan_directory(args.target, max_files=args.max_files, include_symbolic=args.symbolic)

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print("=" * 70)
    print("🛡️  SENTINEL SHIELD: RESUMEN DE AUDITORÍA FORENSE M2M")
    print("=" * 70)
    print(f"📁 Directorio Objetivo: {data['target_directory']}")
    print(f"📄 Archivos Analizados: {data['total_files_scanned']}")
    print(f"🚨 Archivos con Hallazgos CWE: {data['vulnerable_files_count']}")
    print(f"💥 Total de Hallazgos CWE: {data['total_findings']}")
    if args.symbolic:
        print(f"🔬 Violaciones Invariantes Simbólicas (M2M): {data['symbolic_violations_count']}")
    print(f"⚡ Tiempo Total de Análisis: {data['scan_time_ms']} ms ({data['scan_time_ms']/1000:.3f} s)")
    print("=" * 70)

    if args.symbolic and data["symbolic_violations"]:
        print("\n🧮 VIOLACIONES FORMALES DE INVARIANTES FINANCIEROS (CON CONTRAEJEMPLOS):")
        for sym in data["symbolic_violations"]:
            print(f"   🛑 Archivo: {sym['file']} | Función: {sym['function']}()")
            print(f"      Invariante Violado: {sym['invariant']}")
            print(f"      Detalle: {sym['summary']}")
            if sym.get("counterexample"):
                cex = sym["counterexample"]
                print(f"      Entradas: {cex['input_assignments']}")
                print(f"      Estado Resultante: {cex['resulting_state']}")
                print(f"      Prueba Matemática: {cex['explanation']}")
            print("-" * 65)

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
