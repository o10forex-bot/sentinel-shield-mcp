"""Formal vulnerability models and rule definitions for Sentinel Shield."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Represents a security finding detected during static or dynamic analysis."""

    cwe_id: str = Field(..., description="Common Weakness Enumeration ID (e.g. CWE-209)")
    rule_name: str = Field(..., description="Internal rule identifier")
    title: str = Field(..., description="Human-readable title of the vulnerability")
    severity: Severity = Field(..., description="Impact severity classification")
    line_number: Optional[int] = Field(default=None, description="Source line number where defect occurs")
    snippet: Optional[str] = Field(default=None, description="Relevant source snippet")
    description: str = Field(..., description="Detailed explanation of the flaw and exploitability")
    remediation: str = Field(..., description="Concrete code fix instructions")


class AuditResult(BaseModel):
    """Structured report returned by Sentinel Shield audit tools."""

    target: str = Field(..., description="Name or identifier of the audited resource")
    passed: bool = Field(..., description="True if no CRITICAL or HIGH findings were identified")
    findings_count: int = Field(default=0, description="Total number of findings")
    findings: list[Finding] = Field(default_factory=list, description="List of detected vulnerabilities")
    summary: str = Field(..., description="Executive summary of the security audit")
    execution_time_ms: float = Field(..., description="Wall clock analysis time in milliseconds")
