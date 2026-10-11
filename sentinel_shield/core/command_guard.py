"""Command sandbox and destructive bash pattern analyzer for AI agent runtimes."""

from __future__ import annotations

import re
import time
from sentinel_shield.core.cwe_rules import AuditResult, Finding, Severity

# Patterns that indicate high-risk or destructive terminal operations
DANGEROUS_COMMAND_RULES = [
    (re.compile(r"""\brm\s+-[a-zA-Z]*(?:r[fF]|f[rR]|r|f)[a-zA-Z]*\s+(?:/|\*|~|\$HOME|\.\.|/var|/\w+)""", re.IGNORECASE), "CWE-78", "Destructive recursive removal targeting root, home or wildcards", Severity.CRITICAL),
    (re.compile(r"""\b(?:mkfs|fdisk|parted|dd\s+if=)\b"""), "CWE-78", "Direct storage block formatting or overwriting", Severity.CRITICAL),
    (re.compile(r"""\bcat\s+.*(?:id_rsa|id_ed25519|\.env|credentials|\.pgpass|shadow)\b"""), "CWE-200", "Attempt to dump private keys or credential files to stdout", Severity.HIGH),
    (re.compile(r"""\bcurl\s+.*\|\s*(?:bash|sh|zsh)\b"""), "CWE-78", "Unverified remote script piping directly into shell interpreter", Severity.HIGH),
    (re.compile(r"""\b(?:nc\s+.*-e|bash\s+-i\s+>&|python.*socket.*connect)\b"""), "CWE-78", "Interactive reverse shell network socket payload", Severity.CRITICAL),
    (re.compile(r"""\bchmod\s+(?:-R\s+)?777\b"""), "CWE-732", "Insecure file permission modification (world-writable 777)", Severity.MEDIUM),
]


def audit_shell_command(command: str) -> AuditResult:
    """Analyze a proposed terminal command before execution in an agent runtime."""
    start_time = time.perf_counter()
    findings: list[Finding] = []
    cmd_clean = command.strip()

    for pattern, cwe_id, desc, severity in DANGEROUS_COMMAND_RULES:
        if pattern.search(cmd_clean):
            findings.append(
                Finding(
                    cwe_id=cwe_id,
                    rule_name="dangerous_command_pattern",
                    title=f"Disallowed Command Pattern ({cwe_id})",
                    severity=severity,
                    snippet=cmd_clean[:120],
                    description=desc,
                    remediation="Refactor command to target specific unprivileged paths without destructive flags or network pipes.",
                )
            )

    elapsed = (time.perf_counter() - start_time) * 1000.0
    passed = len(findings) == 0
    return AuditResult(
        target=f"command: {cmd_clean[:40]}...",
        passed=passed,
        findings_count=len(findings),
        findings=findings,
        summary="Command validated as safe." if passed else f"Command BLOCKED: Detected {len(findings)} high-risk operational patterns.",
        execution_time_ms=round(elapsed, 3),
    )
