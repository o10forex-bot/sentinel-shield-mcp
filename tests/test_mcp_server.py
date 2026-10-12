"""Hermetic tests for MCP JSON-RPC protocol and tool execution dispatch."""

import json
import unittest
from sentinel_shield.config import config
from sentinel_shield.server import TOOLS_REGISTRY, handle_tool_call


class TestMCPServer(unittest.TestCase):
    """Test suite for MCP server handlers and tool registry."""

    def test_tools_registry_structure(self):
        """All registered tools must conform to MCP tool specification with inputSchema."""
        self.assertEqual(len(TOOLS_REGISTRY), 5)
        tool_names = [t["name"] for t in TOOLS_REGISTRY]
        self.assertIn("audit_cwe_leakage", tool_names)
        self.assertIn("verify_crypto_auth", tool_names)
        self.assertIn("sandbox_command_guard", tool_names)
        self.assertIn("symbolic_audit_invariant", tool_names)
        self.assertIn("bytecode_concolic_audit", tool_names)

        for tool in TOOLS_REGISTRY:
            self.assertIn("description", tool)
            self.assertIn("inputSchema", tool)
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_call_bytecode_concolic_audit_tool(self):
        """Executing bytecode_concolic_audit returns low-level opcode audit."""
        args = {"source_code": "def drain(b, a):\n    return b - a"}
        res = handle_tool_call("bytecode_concolic_audit", args)
        self.assertNotIn("isError", res)
        data = json.loads(res["content"][0]["text"])
        self.assertEqual(len(data), 1)
        self.assertFalse(data[0]["passed"])
        self.assertTrue(data[0]["total_opcodes"] > 0)

    def test_call_symbolic_audit_invariant_tool(self):
        """Executing symbolic_audit_invariant returns formal verification result."""
        args = {
            "source_code": "def withdraw(amount):\n    balance -= amount",
            "invariant": "non_negative_balance",
        }
        res = handle_tool_call("symbolic_audit_invariant", args)
        self.assertNotIn("isError", res)
        data = json.loads(res["content"][0]["text"])
        self.assertFalse(data["passed"])
        self.assertIn("counterexample", data)

    def test_call_audit_cwe_tool(self):
        """Executing audit_cwe_leakage tool returns structured JSON audit result."""
        args = {
            "source_code": "def hello():\n    return 'clean'",
            "filename": "hello.py",
        }
        res = handle_tool_call("audit_cwe_leakage", args)
        self.assertNotIn("isError", res)
        self.assertEqual(len(res["content"]), 1)
        data = json.loads(res["content"][0]["text"])
        self.assertTrue(data["passed"])
        self.assertEqual(data["findings_count"], 0)

    def test_call_sandbox_command_guard_tool(self):
        """Executing sandbox_command_guard tool returns blocking finding on dangerous command."""
        args = {"command": "rm -rf /"}
        res = handle_tool_call("sandbox_command_guard", args)
        self.assertNotIn("isError", res)
        data = json.loads(res["content"][0]["text"])
        self.assertFalse(data["passed"])
        self.assertTrue(data["findings_count"] >= 1)

    def test_x402_payment_challenge_issued_when_enforced(self):
        """When enforce_x402 is enabled and no payment proof is provided, must issue 402 challenge."""
        original_enforce = config.enforce_x402
        try:
            config.enforce_x402 = True
            res = handle_tool_call("audit_cwe_leakage", {"source_code": "x = 1"})
            self.assertTrue(res.get("isError"))
            data = json.loads(res["content"][0]["text"])
            self.assertEqual(data["status"], 402)
            self.assertEqual(data["recipient_wallet"], config.payout_wallet)
            self.assertEqual(data["price_usdc"], config.price_per_audit_usdc)
        finally:
            config.enforce_x402 = original_enforce


if __name__ == "__main__":
    unittest.main()
