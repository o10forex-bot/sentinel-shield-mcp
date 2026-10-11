"""Hermetic tests for AST Code Security Visitor (CWE-209, CWE-78, CWE-798)."""

import unittest
from sentinel_shield.core.ast_visitor import scan_source_code
from sentinel_shield.core.cwe_rules import Severity


class TestCWEAuditor(unittest.TestCase):
    """Test suite for static code vulnerability detection."""

    def test_detect_cwe_209_raw_exception_reflection(self):
        """Must detect when a caught exception str(e) is reflected directly into an HTTPException detail."""
        vulnerable_code = """
from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.get("/appcast.xml")
async def get_appcast():
    try:
        data = generate_desktop_appcast()
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
"""
        result = scan_source_code(vulnerable_code, "updates.py")
        self.assertFalse(result.passed)
        self.assertEqual(result.findings_count, 1)
        finding = result.findings[0]
        self.assertEqual(finding.cwe_id, "CWE-209")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("detail=str(e)", finding.snippet)

    def test_clean_sanitized_code_passes(self):
        """Sanitized code logging exc_info server-side and returning generic message must pass cleanly."""
        clean_code = """
import logging
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/appcast.xml")
async def get_appcast():
    try:
        data = generate_desktop_appcast()
        return data
    except Exception as e:
        logger.error("Failed to generate desktop appcast: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate desktop appcast.")
"""
        result = scan_source_code(clean_code, "updates_fixed.py")
        self.assertTrue(result.passed)
        self.assertEqual(result.findings_count, 0)

    def test_detect_cwe_78_shell_true(self):
        """Must detect subprocess.Popen or run with shell=True."""
        vulnerable_code = """
import subprocess

def run_user_script(script_name):
    cmd = f"bash /scripts/{script_name}"
    subprocess.run(cmd, shell=True)
"""
        result = scan_source_code(vulnerable_code, "runner.py")
        self.assertFalse(result.passed)
        cwe_78_findings = [f for f in result.findings if f.cwe_id == "CWE-78"]
        self.assertEqual(len(cwe_78_findings), 1)

    def test_detect_cwe_798_hardcoded_secrets(self):
        """Must detect hardcoded API keys and tokens in source code."""
        # Construct synthetic token values dynamically to avoid triggering static git hooks
        sample_google = "AIza" + "SyD" + "0123456789abcdef0123456789abcdef0"
        sample_stripe = "sk_" + "live_" + "0123456789abcdef01234567"
        leaky_code = f'GOOGLE_API_KEY = "{sample_google}"\nSTRIPE_KEY = "{sample_stripe}"\n'
        result = scan_source_code(leaky_code, "config.py")
        self.assertFalse(result.passed)
        cwe_798_findings = [f for f in result.findings if f.cwe_id == "CWE-798"]
        self.assertEqual(len(cwe_798_findings), 2)
        self.assertEqual(cwe_798_findings[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
