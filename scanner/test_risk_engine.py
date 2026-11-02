import unittest

try:
    from .risk_engine import assess_result, assess_scan
except ImportError:
    from risk_engine import assess_result, assess_scan


class RiskEngineTests(unittest.TestCase):
    def test_cvss_and_telnet_penalty_are_transparent_and_capped(self):
        result = assess_result(
            {
                "port": 23,
                "state": "open",
                "service": "telnet",
                "product": "Telnet",
                "version": "1.0",
                "vulnerabilities": [{"cvss_score": 8.5}],
            }
        )

        self.assertEqual(result.risk_score, 10.0)
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.highest_cvss, 8.5)
        self.assertIn("Highest CVSS score is 8.5.", result.reasons)
        self.assertIn("TELNET is exposed (+2.0).", result.reasons)

    def test_incomplete_fingerprint_gets_low_risk_warning(self):
        result = assess_result(
            {
                "port": 8080,
                "state": "open",
                "service": "http",
                "product": None,
                "version": None,
                "vulnerabilities": [],
            }
        )

        self.assertEqual(result.risk_score, 1.5)
        self.assertEqual(result.severity, "low")
        self.assertEqual(result.vulnerability_count, 0)

    def test_internet_facing_penalty_is_optional(self):
        result = {
            "port": 22,
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.6",
            "vulnerabilities": [{"cvss_score": 5.0}],
        }

        local = assess_result(result)
        exposed = assess_result(result, internet_facing=True)

        self.assertEqual(local.risk_score, 5.0)
        self.assertEqual(exposed.risk_score, 6.0)

    def test_overall_score_uses_highest_open_service_score(self):
        output = assess_scan(
            {
                "target": "127.0.0.1",
                "results": [
                    {
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.24.0",
                        "vulnerabilities": [{"cvss_score": 4.0}],
                    },
                    {
                        "port": 22,
                        "state": "closed",
                        "service": "ssh",
                        "vulnerabilities": [{"cvss_score": 10.0}],
                    },
                ],
            }
        )

        self.assertEqual(output["overall_risk_score"], 4.0)
        self.assertEqual(len(output["results"]), 1)

    def test_invalid_cvss_score_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_result(
                {
                    "port": 80,
                    "state": "open",
                    "service": "http",
                    "vulnerabilities": [{"cvss_score": 11}],
                }
            )

    def test_invalid_scan_result_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_scan({"results": ["not an object"]})


if __name__ == "__main__":
    unittest.main()
