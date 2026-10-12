# 🛡️ Sentinel Shield MCP

[![Smithery](https://smithery.ai/badge/@o10forex/sentinel-shield)](https://smithery.ai/servers/o10forex/sentinel-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Autonomous Machine-to-Machine Cybersecurity Auditor & Pre-Tool Runtime Guard for AI Agents**

> 📦 **Smithery Marketplace Listing**: [smithery.ai/servers/o10forex/sentinel-shield](https://smithery.ai/servers/o10forex/sentinel-shield)  
> Install instantly with: `npx -y @smithery/cli install @o10forex/sentinel-shield --client claude`


Sentinel Shield is an open-source Model Context Protocol (MCP) server designed to protect AI agent runtimes, CI/CD pipelines, and LLM code generation workflows from high-risk security flaws. Built with sub-millisecond AST static analysis and native **x402 (HTTP 402 Payment Required)** autonomous micropayments.

---

## ⚡ Core Security Tools

1. **`audit_cwe_leakage`**
   - Inspects Python backend code using Abstract Syntax Tree (AST) analysis.
   - Detects **CWE-209** (Information Exposure Through an Error Message): caught exceptions reflected in user HTTP responses or `HTTPException(detail=str(e))`.
   - Detects **CWE-78** (Command Injection): `shell=True` subprocess invocations and `os.system`.
   - Detects **CWE-798** (Hardcoded Credentials): GCP keys, GitHub tokens, Stripe secrets, and private key headers.

2. **`verify_crypto_auth`**
   - Audits Web3 session bearer tokens and authentication workflows.
   - Verifies constant-time HMAC-SHA256 signatures, preventing token forgery (**CWE-347**).
   - Enforces explicit `exp` expiration deadlines to eliminate permanent replay vulnerabilities (**CWE-613**).

3. **`sandbox_command_guard`**
   - Intercepts proposed terminal shell commands before execution by autonomous agents.
   - Blocks destructive recursive file deletion (`rm -rf /`, wildcards).
   - Blocks credential dumps (`cat .env`, `cat ~/.ssh/id_rsa`).
   - Blocks unverified remote script piping (`curl ... | bash`) and interactive reverse shells.

---

## 💳 Autonomous M2M Payments (Protocol x402)

Sentinel Shield supports autonomous machine-to-machine micropayments governed under the **x402 Protocol**:
- **Settlement Asset**: USDC on Polygon / Base
- **Designated Payout Rail**: `0x2821d6003ceE245C4997Ff908029aa0116177b69`
- **Pricing**: $0.10 USDC per audit invocation (configurable).

In permissive mode (`SENTINEL_ENFORCE_X402=false`), local development and hermetic unit testing run with zero external payment friction.

---

## 🌐 Live Cloud MCP Gateway (Zero Local Installation)

Sentinel Shield is deployed and running live 24/7 in the cloud:
- **Public Gateway**: `https://sentinel-shield-mcp.onrender.com`
- **Health Check**: `https://sentinel-shield-mcp.onrender.com/health`
- **MCP RPC Endpoint**: `https://sentinel-shield-mcp.onrender.com/mcp/rpc`
- **Interactive OpenAPI Docs**: `https://sentinel-shield-mcp.onrender.com/docs`

### Connect Claude Desktop / Cursor Directly to the Cloud
Any external AI agent can connect to Sentinel Shield over the internet with zero local dependencies:

```json
{
  "mcpServers": {
    "sentinel-shield-cloud": {
      "url": "https://sentinel-shield-mcp.onrender.com/mcp/rpc"
    }
  }
}
```

Or via direct HTTP JSON-RPC 2.0:
```bash
curl -X POST https://sentinel-shield-mcp.onrender.com/mcp/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}'
```

---

## 🚀 Local Installation & Development

### 1. Installation
```bash
cd sentinel_shield_mcp
pip install -e .
```

### 2. Connect via Stdio
```json
{
  "mcpServers": {
    "sentinel-shield": {
      "command": "python3",
      "args": ["-m", "sentinel_shield.server"],
      "env": {
        "SENTINEL_ENFORCE_X402": "false"
      }
    }
  }
}
```

### 3. Run Test Suite
```bash
pytest -v
# 16/16 hermetic unit tests passing in <0.3s
```

---

## 📜 License
MIT License. Created for the decentralized, autonomous AI agent economy.
