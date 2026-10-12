"""Hermetic unit tests for BytecodeConcolicEngine and Algebraic Interval Algebra."""

import unittest
from sentinel_shield.core.bytecode_engine import (
    Interval,
    BytecodeConcolicEngine,
    OpcodeCategory,
    BytecodeInstruction,
)


class TestBytecodeEngine(unittest.TestCase):
    """Test suite for bytecode-level formal verification and interval algebra."""

    def test_interval_algebra_subtraction(self):
        # [10, 50] - [5, 20] = [10 - 20, 50 - 5] = [-10, 45]
        i1 = Interval(10, 50)
        i2 = Interval(5, 20)
        res = i1.subtract(i2)
        self.assertEqual(res.low, -10)
        self.assertEqual(res.high, 45)
        self.assertTrue(res.contains_negative())
        self.assertFalse(res.is_strictly_non_negative())

    def test_interval_algebra_strictly_positive(self):
        # [100, 200] - [10, 20] = [100 - 20, 200 - 10] = [80, 190]
        i1 = Interval(100, 200)
        i2 = Interval(10, 20)
        res = i1.subtract(i2)
        self.assertTrue(res.is_strictly_non_negative())
        self.assertFalse(res.contains_negative())

    def test_interval_multiplication_and_division(self):
        i1 = Interval(10, 20)
        i2 = Interval(2, 4)
        mult = i1.multiply(i2)
        self.assertEqual(mult.low, 20)
        self.assertEqual(mult.high, 80)

        div = i1.floor_divide(i2)
        self.assertEqual(div.low, 2)
        self.assertEqual(div.high, 10)

    def test_bytecode_audit_vulnerable_unshielded_subtraction(self):
        source = """
def unprotected_drain(balance, amount):
    return balance - amount
"""
        results = BytecodeConcolicEngine.audit_source_code(source)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.function_name, "unprotected_drain")
        self.assertFalse(res.passed)
        self.assertEqual(len(res.counterexamples), 1)
        cex = res.counterexamples[0]
        self.assertIn("BINARY_SUBTRACT", cex.opname)
        self.assertEqual(cex.resulting_interval, "(-∞, +∞)")
        self.assertIn("preceding branch guard", cex.first_person_verdict)

    def test_bytecode_audit_safe_guarded_subtraction(self):
        source = """
def safe_payment(balance, amount):
    if amount > balance:
        return 0
    return balance - amount
"""
        results = BytecodeConcolicEngine.audit_source_code(source)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.function_name, "safe_payment")
        self.assertTrue(res.passed)
        self.assertEqual(len(res.counterexamples), 0)

    def test_bytecode_audit_multiple_functions(self):
        source = """
def f1(x, y):
    return x - y

def f2(a, b):
    return a + b
"""
        results = BytecodeConcolicEngine.audit_source_code(source)
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0].passed)
        self.assertTrue(results[1].passed)


if __name__ == "__main__":
    unittest.main()
