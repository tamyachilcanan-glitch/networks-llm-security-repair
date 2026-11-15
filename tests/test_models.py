import unittest

from models import VerificationResult


class TestVerificationResult(unittest.TestCase):

    def test_patch_rejected(self):
        result = VerificationResult("TEST", False, None, None)
        self.assertEqual(result.verified_repair, 0)
        self.assertFalse(result.functional_test_executed)
        self.assertFalse(result.security_test_executed)

    def test_verified_repair(self):
        result = VerificationResult("TEST", True, 0, 0)
        self.assertEqual(result.verified_repair, 1)
        self.assertTrue(result.functional_test_executed)
        self.assertTrue(result.security_test_executed)

    def test_functional_failure(self):
        result = VerificationResult("TEST", True, 1, 0)
        self.assertEqual(result.verified_repair, 0)

    def test_security_failure(self):
        result = VerificationResult("TEST", True, 0, 1)
        self.assertEqual(result.verified_repair, 0)

    def test_missing_functional_test(self):
        result = VerificationResult("TEST", True, None, 0)
        self.assertEqual(result.verified_repair, 0)

    def test_missing_security_test(self):
        result = VerificationResult("TEST", True, 0, None)
        self.assertEqual(result.verified_repair, 0)

    def test_invalid_application_status(self):
        with self.assertRaises(ValueError):
            VerificationResult("TEST", 0, None, None)

    def test_tests_without_applied_patch(self):
        with self.assertRaises(ValueError):
            VerificationResult("TEST", False, 0, 0)


if __name__ == "__main__":
    unittest.main()
