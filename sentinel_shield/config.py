"""Configuration settings for Sentinel Shield MCP server."""

from __future__ import annotations

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelConfig(BaseSettings):
    """Runtime configuration for Sentinel Shield MCP."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        extra="ignore",
    )

    server_name: str = Field(default="sentinel-shield-mcp", description="Server identifier")
    server_version: str = Field(default="0.1.0", description="Server version")

    # M2M Payment Rail (USDC on Polygon / Base)
    payout_wallet: str = Field(
        default="0x2821d6003ceE245C4997Ff908029aa0116177b69",
        description="Designated EVM payout address for x402 micropayments",
    )
    payout_network: str = Field(default="polygon", description="Target blockchain network for settlement")
    price_per_audit_usdc: float = Field(default=0.10, description="Cost in USDC per audit invocation")
    enforce_x402: bool = Field(default=False, description="Whether to require live x402 payment validation (false for dev/local)")

    # Detection Sensitivity
    strict_ast_mode: bool = Field(default=True, description="Strict AST inspection of all exception handlers")
    max_source_file_bytes: int = Field(default=1_000_000, description="Max file size to audit (1MB)")


config = SentinelConfig()
