"""Hermetic unit tests for Symbolic Invariant Engine (Formal Verification M2M)."""

import unittest
from sentinel_shield.core.symbolic_engine import (
    SymbolicAnalyzer,
    InvariantType,
    SymbolicAuditResult,
)


class TestSymbolicEngine(unittest.TestCase):
    """Test suite for mathematical symbolic verification engine."""

    def test_non_negative_balance_vulnerable(self):
        vulnerable_code = """
def withdraw(user_id: str, amount: int):
    wallet = get_wallet(user_id)
    wallet.balance -= amount
    commit(wallet)
"""
        result = SymbolicAnalyzer.audit_invariant(
            vulnerable_code,
            InvariantType.NON_NEGATIVE_BALANCE,
            function_name="withdraw",
        )
        self.assertFalse(result.passed)
        self.assertIsNotNone(result.counterexample)
        self.assertIn("Unbounded subtraction", result.summary)
        self.assertIn("amount", result.counterexample.input_assignments)
        self.assertEqual(result.counterexample.resulting_state["final_balance"], -50)

    def test_non_negative_balance_safe(self):
        safe_code = """
def withdraw(user_id: str, amount: int):
    wallet = get_wallet(user_id)
    if amount > wallet.balance:
        raise ValueError("Insufficient balance")
    wallet.balance -= amount
    commit(wallet)
"""
        result = SymbolicAnalyzer.audit_invariant(
            safe_code,
            InvariantType.NON_NEGATIVE_BALANCE,
            function_name="withdraw",
        )
        self.assertTrue(result.passed)
        self.assertIsNone(result.counterexample)
        self.assertIn("provably enforced", result.summary)

    def test_fee_non_zero_truncation_vulnerable(self):
        vulnerable_code = """
def calculate_protocol_fee(amount: int, basis_points: int) -> int:
    fee = (basis_points // 10000) * amount
    return fee
"""
        result = SymbolicAnalyzer.audit_invariant(
            vulnerable_code,
            InvariantType.FEE_NON_ZERO,
            function_name="calculate_protocol_fee",
        )
        self.assertFalse(result.passed)
        self.assertIsNotNone(result.counterexample)
        self.assertEqual(result.counterexample.resulting_state["calculated_fee"], 0)
        self.assertIn("Integer truncation collapses non-zero fee to 0", result.summary)

    def test_fee_non_zero_safe(self):
        safe_code = """
def calculate_protocol_fee(amount: int, basis_points: int) -> int:
    fee = (basis_points * amount) // 10000
    return fee
"""
        result = SymbolicAnalyzer.audit_invariant(
            safe_code,
            InvariantType.FEE_NON_ZERO,
            function_name="calculate_protocol_fee",
        )
        self.assertTrue(result.passed)
        self.assertIsNone(result.counterexample)

    def test_strict_auth_binding_vulnerable(self):
        vulnerable_code = """
def authorize_action(caller: str, allow_fallback: bool) -> bool:
    if caller == "admin" or allow_fallback:
        return True
    return False
"""
        result = SymbolicAnalyzer.audit_invariant(
            vulnerable_code,
            InvariantType.STRICT_AUTH_BINDING,
            function_name="authorize_action",
        )
        self.assertFalse(result.passed)
        self.assertIsNotNone(result.counterexample)
        self.assertTrue(result.counterexample.resulting_state["authorized"])
        self.assertIn("Permissive fallback path", result.summary)

    def test_strict_auth_binding_safe(self):
        safe_code = """
def authorize_action(caller: str) -> bool:
    if caller == "admin":
        return True
    return False
"""
        result = SymbolicAnalyzer.audit_invariant(
            safe_code,
            InvariantType.STRICT_AUTH_BINDING,
            function_name="authorize_action",
        )
        self.assertTrue(result.passed)
        self.assertIsNone(result.counterexample)

    def test_to_dict_serialization(self):
        code = "def f(): pass"
        result = SymbolicAnalyzer.audit_invariant(code, InvariantType.BALANCE_CONSERVATION)
        d = result.to_dict()
        self.assertIn("target_function", d)
        self.assertIn("invariant_tested", d)
        self.assertIn("passed", d)
        self.assertIn("execution_time_ms", d)

    def test_syntax_error_handling(self):
        malformed = "def broken(:"
        result = SymbolicAnalyzer.audit_invariant(malformed, InvariantType.NON_NEGATIVE_BALANCE)
        self.assertFalse(result.passed)
        self.assertIn("Parsing error", result.summary)

    def test_missing_function(self):
        code = "def other(): pass"
        result = SymbolicAnalyzer.audit_invariant(
            code,
            InvariantType.NON_NEGATIVE_BALANCE,
            function_name="withdraw",
        )
        self.assertFalse(result.passed)
        self.assertIn("No matching function definition found", result.summary)

    def test_audit_all_invariants_multiple_functions(self):
        multi_code = """
def bad_withdraw(amount):
    balance -= amount

def bad_fee(amount, rate):
    return (rate // 10000) * amount

def safe_func(x):
    return x * 2
"""
        violations = SymbolicAnalyzer.audit_all_invariants(multi_code)
        self.assertEqual(len(violations), 2)
        func_names = [v.target_function for v in violations]
        self.assertIn("bad_withdraw", func_names)
        self.assertIn("bad_fee", func_names)


if __name__ == "__main__":
    unittest.main()
