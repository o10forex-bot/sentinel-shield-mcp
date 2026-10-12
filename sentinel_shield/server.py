"""Model Context Protocol (MCP) Standard Server for Sentinel Shield.

Provides machine-to-machine security auditing tools via JSON-RPC 2.0 stdio protocol,
compatible with Claude Desktop, Cursor, and autonomous agent runtimes.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from sentinel_shield.config import config
from sentinel_shield.core.ast_visitor import scan_source_code
from sentinel_shield.core.bytecode_engine import BytecodeConcolicEngine
from sentinel_shield.core.command_guard import audit_shell_command
from sentinel_shield.core.crypto_guard import audit_session_token_security
from sentinel_shield.core.symbolic_engine import SymbolicAnalyzer, InvariantType
from sentinel_shield.payments.x402_middleware import evaluate_x402_payment

# Specification of Tools exposed to other AI Agents
TOOLS_REGISTRY = [
    {
        "name": "audit_cwe_leakage",
        "description": (
            "Audits Python backend source code for information leakage flaws (CWE-209, CWE-78, CWE-798). "
            "Detects raw exception string reflection into HTTP responses and hardcoded API tokens."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Python source code content to inspect",
                },
                "filename": {
                    "type": "string",
                    "description": "Optional name of the target file",
                    "default": "module.py",
                },
                "payment_proof": {
                    "type": "string",
                    "description": "Optional x402 payment proof or transaction hash",
                },
            },
            "required": ["source_code"],
        },
    },
    {
        "name": "verify_crypto_auth",
        "description": (
            "Audits Web3 session tokens and wallet authentication schemes. "
            "Detects replay attack vulnerabilities, missing expiration, and forged HMAC signatures."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_token": {
                    "type": "string",
                    "description": "Bearer token to verify (format: payload.signature)",
                },
                "secret_key": {
                    "type": "string",
                    "description": "Server signing secret key",
                },
                "payment_proof": {
                    "type": "string",
                    "description": "Optional x402 payment proof",
                },
            },
            "required": ["session_token", "secret_key"],
        },
    },
    {
        "name": "sandbox_command_guard",
        "description": (
            "Pre-tool-use security guard for terminal commands. "
            "Analyzes proposed shell commands and blocks destructive actions (rm -rf, disk wiping, credential dumping)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Terminal command string proposed for execution",
                },
                "payment_proof": {
                    "type": "string",
                    "description": "Optional x402 payment proof",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "symbolic_audit_invariant",
        "description": (
            "Formal verification and symbolic constraint solver for financial state machines and smart contracts. "
            "Mathematically proves invariant satisfaction (non_negative_balance, fee_non_zero, strict_auth_binding, "
            "balance_conservation) and returns concrete counterexample assignments on violation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Python source code of the contract or financial module to audit",
                },
                "invariant": {
                    "type": "string",
                    "description": (
                        "Invariant property to formally verify. One of: "
                        "'non_negative_balance', 'fee_non_zero', 'strict_auth_binding', 'balance_conservation'"
                    ),
                    "default": "non_negative_balance",
                },
                "function_name": {
                    "type": "string",
                    "description": "Optional name of the target function to verify",
                },
                "payment_proof": {
                    "type": "string",
                    "description": "Optional x402 payment proof",
                },
            },
            "required": ["source_code"],
        },
    },
    {
        "name": "bytecode_concolic_audit",
        "description": (
            "Low-level virtual machine bytecode disassembler and algebraic interval constraint solver. "
            "Reconstructs the Control Flow Graph (CFG) at opcode level, simulates stack mutations, "
            "and discovers exact branch counterexamples using interval algebra ([a, b] ⊖ [c, d])."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Python source code of functions to compile and analyze at bytecode opcode level",
                },
                "payment_proof": {
                    "type": "string",
                    "description": "Optional x402 payment proof",
                },
            },
            "required": ["source_code"],
        },
    },
]


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the requested security tool and return structured tool result."""
    payment_proof = arguments.get("payment_proof")
    payment_verif = evaluate_x402_payment(resource_name=name, payment_proof=payment_proof)

    if not payment_verif.authorized and payment_verif.challenge:
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payment_verif.challenge.model_dump(), indent=2),
                }
            ],
        }

    if name == "audit_cwe_leakage":
        code = arguments.get("source_code", "")
        filename = arguments.get("filename", "module.py")
        result = scan_source_code(code, filename)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result.model_dump(), indent=2),
                }
            ]
        }

    elif name == "verify_crypto_auth":
        token = arguments.get("session_token", "")
        secret = arguments.get("secret_key", "")
        result = audit_session_token_security(token, secret)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result.model_dump(), indent=2),
                }
            ]
        }

    elif name == "sandbox_command_guard":
        cmd = arguments.get("command", "")
        result = audit_shell_command(cmd)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result.model_dump(), indent=2),
                }
            ]
        }

    elif name == "symbolic_audit_invariant":
        code = arguments.get("source_code", "")
        invariant = arguments.get("invariant", InvariantType.NON_NEGATIVE_BALANCE.value)
        func_name = arguments.get("function_name")
        result = SymbolicAnalyzer.audit_invariant(code, invariant, func_name)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result.to_dict(), indent=2),
                }
            ]
        }

    elif name == "bytecode_concolic_audit":
        code = arguments.get("source_code", "")
        results = BytecodeConcolicEngine.audit_source_code(code)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps([r.to_dict() for r in results], indent=2),
                }
            ]
        }

    else:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
        }


def run_stdio_server() -> None:
    """Run the standard JSON-RPC 2.0 stdio loop for MCP clients."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": config.server_name,
                            "version": config.server_version,
                        },
                        "capabilities": {
                            "tools": {},
                        },
                    },
                }
            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS_REGISTRY,
                    },
                }
            elif method == "tools/call":
                tool_name = params.get("name", "")
                args = params.get("arguments", {})
                call_res = handle_tool_call(tool_name, args)
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": call_res,
                }
            else:
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}",
                    },
                }
        except Exception as exc:
            res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {exc}",
                },
            }

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()


def main() -> None:
    """Main CLI entrypoint."""
    run_stdio_server()


if __name__ == "__main__":
    main()
