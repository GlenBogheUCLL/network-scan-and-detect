import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from .main import create_app
from scanner.tcp_scan import ScanResult


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

    def test_run_scan_rejects_invalid_target(self):
        response = self.client.post(
            "/scan",
            json={
                "target": "invalid.invalid",
                "start_port": 80,
                "end_port": 80,
            },
        )
        self.assertEqual(response.status_code, 422)

    @patch("backend.main.NvdClient")
    @patch("backend.main.scan_ports")
    def test_run_scan_orchestrates_and_stores_results(
        self,
        scan_ports_mock,
        nvd_client_mock,
    ):
        scan_ports_mock.return_value = [
            ScanResult(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="nginx",
                version="1.24.0",
                confidence=0.95,
            )
        ]
        nvd_client_mock.return_value.lookup_scan_results.return_value = {
            "target": "127.0.0.1",
            "results": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.24.0",
                    "confidence": 0.95,
                    "vulnerabilities": [],
                }
            ],
        }["results"]

        response = self.client.post(
            "/scan",
            json={
                "target": "127.0.0.1",
                "start_port": 80,
                "end_port": 80,
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["results"][0]["port"], 80)
        scan_ports_mock.assert_called_once_with("127.0.0.1", 80, 80)
        nvd_client_mock.return_value.lookup_scan_results.assert_called_once()


if __name__ == "__main__":
    unittest.main()
