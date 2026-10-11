"""HTTP / SSE Remote Server for Sentinel Shield MCP.

Allows remote AI agents across the internet to invoke security tools
and settle micropayments via x402 without local installations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sentinel_shield.config import config
from sentinel_shield.payments.x402_middleware import evaluate_x402_payment
from sentinel_shield.server import TOOLS_REGISTRY, handle_tool_call

logger = logging.getLogger("sentinel_shield.remote")

app = FastAPI(
    title="Sentinel Shield MCP Remote Gateway",
    description="Autonomous M2M Cybersecurity Engine for AI Agents with x402 Protocol",
    version=config.server_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any = None
    method: str
    params: Dict[str, Any] = {}


@app.get("/")
async def root():
    """Service discovery endpoint for AI agents."""
    return {
        "service": config.server_name,
        "version": config.server_version,
        "protocol": "Model Context Protocol (MCP) + x402 Micropayments",
        "payout_wallet": config.payout_wallet,
        "payout_network": config.payout_network,
        "price_per_audit_usdc": config.price_per_audit_usdc,
        "tools_available": [t["name"] for t in TOOLS_REGISTRY],
        "docs_url": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": config.server_name}


@app.post("/mcp/rpc")
async def mcp_rpc_handler(
    req: JsonRpcRequest,
    x_payment_proof: str | None = Header(default=None, alias="X-Payment-Proof"),
):
    """Handle remote JSON-RPC 2.0 tool requests from autonomous internet agents."""
    method = req.method
    params = req.params

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": config.server_name,
                    "version": config.server_version,
                },
                "capabilities": {"tools": {}},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {"tools": TOOLS_REGISTRY},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        if x_payment_proof and "payment_proof" not in args:
            args["payment_proof"] = x_payment_proof

        call_res = handle_tool_call(tool_name, args)
        if call_res.get("isError"):
            # Check if this was an x402 payment challenge
            first_text = call_res["content"][0]["text"]
            if '"status": 402' in first_text:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=first_text,
                )

        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "result": call_res,
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Method not found: {method}",
    )
