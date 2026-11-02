import unittest

from fastapi.testclient import TestClient

from .main import create_app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(create_app("sqlite+pysqlite:///:memory:"))
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_create_and_get_scan(self):
        payload = {
            "target": "127.0.0.1",
            "results": [
                {
                    "port": 912,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "vmware-auth",
                    "product": "VMware Authentication Daemon",
                    "version": "1.0",
                    "confidence": 0.95,
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2009-3707",
                            "description": "Example",
                            "cvss_score": 5.0,
                            "severity": "MEDIUM",
                            "vector": "AV:N/AC:L",
                        }
                    ],
                }
            ],
        }

        created = self.client.post("/scans", json=payload)

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["overall_risk_score"], 5.0)
        scan_id = created.json()["id"]
        fetched = self.client.get(f"/scans/{scan_id}")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["results"][0]["vulnerability_count"], 1)

    def test_missing_scan_returns_not_found(self):
        response = self.client.get("/scans/999")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
