"""Static AST (Abstract Syntax Tree) analyzer for Python code.

Inspects source code at the parser level without executing it.
Identifies CWE-209 exception reflection, CWE-78 command injection,
and hardcoded credentials with sub-millisecond latency.
"""

from __future__ import annotations

import ast
import re
import time
from typing import Optional

from sentinel_shield.core.cwe_rules import AuditResult, Finding, Severity

# Regex patterns for high-entropy secrets and credential tokens
SECRET_PATTERNS = [
    (re.compile(r"""(?:api_key|apikey|secret|token|password|auth_token)\s*=\s*['"][a-zA-Z0-9_\-]{20,}['"]""", re.IGNORECASE), "Generic API Secret"),
    (re.compile(r"""['"]AIza[0-9A-Za-z-_]{35}['"]"""), "Google Cloud API Key"),
    (re.compile(r"""['"]ghp_[0-9a-zA-Z]{36}['"]"""), "GitHub Personal Access Token"),
    (re.compile(r"""['"]sk_live_[0-9a-zA-Z]{24,}['"]"""), "Stripe Live Secret Key"),
    (re.compile(r"""-----BEGIN (?:RSA )?PRIVATE KEY-----"""), "Embedded Private Key Header"),
]


class CodeSecurityVisitor(ast.NodeVisitor):
    """AST Node Visitor that traverses Python code to detect common AI-agent security bugs."""

    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        self._current_except_var: Optional[str] = None

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Inspect except blocks for raw exception string reflection (CWE-209)."""
        prev_var = self._current_except_var
        if node.name:
            self._current_except_var = node.name

        # Recurse through statements inside except block
        self.generic_visit(node)
        self._current_except_var = prev_var

    def visit_Raise(self, node: ast.Raise) -> None:
        """Detect: raise HTTPException(status_code=..., detail=str(e))"""
        if self._current_except_var and node.exc:
            # Check if raising an exception that uses the caught exception variable
            self._check_raw_exception_leak(node.exc, node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        """Detect: return {'error': str(e)} or JSONResponse(content={'error': str(e)})"""
        if self._current_except_var and node.value:
            self._check_raw_exception_leak(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function calls for dangerous invocations (CWE-78 shell=True, os.system)."""
        func_name = self._get_call_name(node.func)

        # 1. os.system call
        if func_name in ("os.system", "system"):
            self.findings.append(
                Finding(
                    cwe_id="CWE-78",
                    rule_name="os_system_invocation",
                    title="Improper Neutralization of OS Command (CWE-78)",
                    severity=Severity.HIGH,
                    line_number=node.lineno,
                    snippet=self._get_snippet(node.lineno),
                    description="Invocation of os.system() is vulnerable to command injection.",
                    remediation="Use subprocess.run(['cmd', 'arg1'], shell=False) with an argument list instead of raw string shell execution.",
                )
            )

        # 2. subprocess calls with shell=True
        if func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        Finding(
                            cwe_id="CWE-78",
                            rule_name="subprocess_shell_true",
                            title="Subprocess Executed with shell=True (CWE-78)",
                            severity=Severity.HIGH,
                            line_number=node.lineno,
                            snippet=self._get_snippet(node.lineno),
                            description="subprocess invoked with shell=True allows shell metacharacter execution if any argument includes external input.",
                            remediation="Set shell=False and pass arguments as a list of strings: subprocess.run(['executable', arg1, arg2], shell=False).",
                        )
                    )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_call_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""

    def _check_raw_exception_leak(self, node: ast.AST, lineno: int) -> None:
        """Check whether an AST sub-expression reflects self._current_except_var into user responses."""
        if not self._current_except_var:
            return

        leak_detected = False

        # Look for str(e) or repr(e) calls
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in ("str", "repr", "format"):
                if any(isinstance(a, ast.Name) and a.id == self._current_except_var for a in sub.args):
                    leak_detected = True
                    break
            # Look for f"...{e}..." formatted values
            elif isinstance(sub, ast.FormattedValue) and isinstance(sub.value, ast.Name) and sub.value.id == self._current_except_var:
                leak_detected = True
                break

        if leak_detected:
            self.findings.append(
                Finding(
                    cwe_id="CWE-209",
                    rule_name="raw_exception_reflection",
                    title="Information Exposure Through Raw Exception Message (CWE-209)",
                    severity=Severity.HIGH,
                    line_number=lineno,
                    snippet=self._get_snippet(lineno),
                    description=(
                        f"Caught exception variable '{self._current_except_var}' is reflected directly in an outbound response or HTTPException. "
                        "This leaks internal stack traces, database schema details, file paths, and environment internals to callers."
                    ),
                    remediation=(
                        f"Log the full exception server-side with logger.error('Operation failed: %s', {self._current_except_var}, exc_info=True) "
                        "and return a generic error message (e.g. 'An internal error occurred. Please contact support.') to external clients."
                    ),
                )
            )

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""


def scan_source_code(source: str, filename: str = "source.py") -> AuditResult:
    """Analyze Python source code and return an AuditResult."""
    start_time = time.perf_counter()
    source_lines = source.splitlines()

    # 1. Parse AST
    try:
        tree = ast.parse(source, filename=filename)
        visitor = CodeSecurityVisitor(source_lines)
        visitor.visit(tree)
        findings = visitor.findings
    except SyntaxError as e:
        elapsed = (time.perf_counter() - start_time) * 1000.0
        return AuditResult(
            target=filename,
            passed=False,
            findings_count=1,
            findings=[
                Finding(
                    cwe_id="CWE-1173",
                    rule_name="syntax_error",
                    title="Python Syntax Error in Target File",
                    severity=Severity.HIGH,
                    line_number=e.lineno,
                    snippet=source_lines[e.lineno - 1] if e.lineno and e.lineno <= len(source_lines) else "",
                    description=f"Source failed to parse: {e.msg}",
                    remediation="Fix syntax error before executing security validation.",
                )
            ],
            summary=f"Analysis aborted due to SyntaxError at line {e.lineno}.",
            execution_time_ms=round(elapsed, 3),
        )

    # 2. Check for hardcoded secrets
    for lineno, line in enumerate(source_lines, 1):
        for pattern, secret_type in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        cwe_id="CWE-798",
                        rule_name="hardcoded_secret",
                        title=f"Hard-coded Credential Detected: {secret_type} (CWE-798)",
                        severity=Severity.CRITICAL,
                        line_number=lineno,
                        snippet=line.strip()[:60] + "...",
                        description="Hardcoded cryptographic key or API token committed directly in source code.",
                        remediation="Move credential to an environment variable loaded via os.environ or Pydantic SecretStr.",
                    )
                )
                break

    elapsed = (time.perf_counter() - start_time) * 1000.0
    critical_or_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    passed = not critical_or_high

    summary = (
        f"Audit passed cleanly with 0 vulnerabilities."
        if passed
        else f"Audit FAILED: Detected {len(findings)} vulnerability finding(s)."
    )

    return AuditResult(
        target=filename,
        passed=passed,
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        execution_time_ms=round(elapsed, 3),
    )
