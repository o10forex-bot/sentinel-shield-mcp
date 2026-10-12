"""Hermetic tests for HTTP/RPC Remote Server Gateway."""

import json
import unittest
from fastapi.testclient import TestClient
from sentinel_shield.remote_server import app


class TestRemoteServer(unittest.TestCase):
    """Test suite for remote HTTP JSON-RPC gateway."""

    def setUp(self):
        self.client = TestClient(app)

    def test_root_discovery_endpoint(self):
        """Root endpoint returns protocol metadata and payout wallet."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["service"], "sentinel-shield-mcp")
        self.assertEqual(data["payout_wallet"], "0x2821d6003ceE245C4997Ff908029aa0116177b69")
        self.assertIn("audit_cwe_leakage", data["tools_available"])
        self.assertIn("symbolic_audit_invariant", data["tools_available"])

    def test_json_rpc_tools_list(self):
        """JSON-RPC method tools/list returns tools array."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }
        res = self.client.post("/mcp/rpc", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], 1)
        self.assertEqual(len(data["result"]["tools"]), 4)

    def test_json_rpc_tools_call(self):
        """Remote agent calling audit_cwe_leakage via HTTP receives audit result."""
        payload = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "audit_cwe_leakage",
                "arguments": {
                    "source_code": "def ping(): return 'pong'",
                },
            },
        }
        res = self.client.post("/mcp/rpc", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], 42)
        audit_json = json.loads(data["result"]["content"][0]["text"])
        self.assertTrue(audit_json["passed"])

    def test_json_rpc_symbolic_audit_call(self):
        """Remote agent calling symbolic_audit_invariant via HTTP receives mathematical proof."""
        payload = {
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "symbolic_audit_invariant",
                "arguments": {
                    "source_code": "def withdraw(amount):\n    balance -= amount",
                    "invariant": "non_negative_balance",
                },
            },
        }
        res = self.client.post("/mcp/rpc", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], 43)
        res_json = json.loads(data["result"]["content"][0]["text"])
        self.assertFalse(res_json["passed"])
        self.assertIsNotNone(res_json["counterexample"])

    def test_server_card_discovery_endpoint(self):
        """Standardized /.well-known/mcp/server-card.json returns valid card."""
        res = self.client.get("/.well-known/mcp/server-card.json")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["serverInfo"]["name"], "sentinel-shield-mcp")
        self.assertEqual(len(data["tools"]), 4)

    def test_json_rpc_alias_mcp(self):
        """Endpoint /mcp works as alias for /mcp/rpc."""
        payload = {"jsonrpc": "2.0", "id": 99, "method": "tools/list"}
        res = self.client.post("/mcp", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()["result"]["tools"]), 4)


if __name__ == "__main__":
    unittest.main()
