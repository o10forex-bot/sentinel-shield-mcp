"""Cryptographic authentication audit engine for Web3 and Agentic AI sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional
from sentinel_shield.core.cwe_rules import AuditResult, Finding, Severity


def audit_session_token_security(token: str, secret_key: str) -> AuditResult:
    """Audit an HMAC session token for tampering, replay vulnerability, and expiration."""
    start_time = time.perf_counter()
    findings: list[Finding] = []

    parts = token.strip().split(".")
    if len(parts) != 2:
        findings.append(
            Finding(
                cwe_id="CWE-345",
                rule_name="malformed_session_token",
                title="Insufficient Verification of Data Authenticity (CWE-345)",
                severity=Severity.HIGH,
                description="Session token does not conform to '<payload>.<signature>' structure.",
                remediation="Structure session tokens with strict URL-safe base64 payload and HMAC signature components.",
            )
        )
    else:
        payload_b64, sig_b64 = parts

        # Verify HMAC signature in constant time
        expected_sig = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            findings.append(
                Finding(
                    cwe_id="CWE-347",
                    rule_name="invalid_token_signature",
                    title="Improper Verification of Cryptographic Signature (CWE-347)",
                    severity=Severity.CRITICAL,
                    description="Token signature verification failed: token has been forged or tampered.",
                    remediation="Reject unverified session tokens immediately with HTTP 401 Unauthorized.",
                )
            )

        # Decode payload and check expiration
        rem = len(payload_b64) % 4
        padded_b64 = payload_b64 + ("=" * ((4 - rem) % 4))
        try:
            payload_json = base64.urlsafe_b64decode(padded_b64).decode("utf-8")
            payload = json.loads(payload_json)

            if "exp" not in payload:
                findings.append(
                    Finding(
                        cwe_id="CWE-613",
                        rule_name="missing_token_expiration",
                        title="Insufficient Session Expiration (CWE-613)",
                        severity=Severity.HIGH,
                        description="Session token has no expiration ('exp') claim, allowing permanent replay.",
                        remediation="Always include an explicit 'exp' Unix epoch timestamp (maximum 24h lifetime recommended).",
                    )
                )
            elif time.time() > payload["exp"]:
                findings.append(
                    Finding(
                        cwe_id="CWE-613",
                        rule_name="expired_token_used",
                        title="Expired Session Token Used (CWE-613)",
                        severity=Severity.HIGH,
                        description=f"Session token expired at {payload['exp']} (current time: {int(time.time())}).",
                        remediation="Reject expired session tokens and require a new challenge signature.",
                    )
                )

            if "sub" not in payload or not payload["sub"]:
                findings.append(
                    Finding(
                        cwe_id="CWE-287",
                        rule_name="missing_subject_identity",
                        title="Improper Authentication: Missing Subject Claim (CWE-287)",
                        severity=Severity.HIGH,
                        description="Session token has no 'sub' wallet address claim.",
                        remediation="Bind verified wallet address to the 'sub' field.",
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    cwe_id="CWE-345",
                    rule_name="corrupted_token_payload",
                    title="Corrupted Token Payload",
                    severity=Severity.HIGH,
                    description=f"Unable to parse token payload: {e}",
                    remediation="Ensure payload is valid JSON encoded with URL-safe Base64.",
                )
            )

    elapsed = (time.perf_counter() - start_time) * 1000.0
    passed = len(findings) == 0
    return AuditResult(
        target="session_token",
        passed=passed,
        findings_count=len(findings),
        findings=findings,
        summary="Token validation passed." if passed else f"Identified {len(findings)} security flaws in session token.",
        execution_time_ms=round(elapsed, 3),
    )
