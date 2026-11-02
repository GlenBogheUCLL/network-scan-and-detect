import json
import unittest
from urllib.parse import parse_qs, urlparse

try:
    from .nvd_client import NvdClient, NvdClientError
except ImportError:
    from nvd_client import NvdClient, NvdClientError


NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Example vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N",
                            }
                        }
                    ]
                },
            }
        }
    ]
}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class NvdClientTests(unittest.TestCase):
    def test_search_parses_cve_and_cvss(self):
        requests = []

        def requester(request, timeout):
            requests.append(request)
            return FakeResponse(NVD_RESPONSE)

        client = NvdClient(request_delay=0, requester=requester)

        result = client.search("OpenSSH", "9.6")

        self.assertEqual(result[0].cve_id, "CVE-2024-1234")
        self.assertEqual(result[0].cvss_score, 8.1)
        self.assertEqual(result[0].severity, "HIGH")
        query = parse_qs(urlparse(requests[0].full_url).query)
        self.assertEqual(query["keywordSearch"], ["OpenSSH 9.6"])

    def test_lookup_only_queries_open_results_with_complete_fingerprint(self):
        requester = lambda request, timeout: FakeResponse(NVD_RESPONSE)
        client = NvdClient(request_delay=0, requester=requester)
        scan_data = {
            "target": "127.0.0.1",
            "results": [
                {
                    "port": 22,
                    "state": "open",
                    "product": "OpenSSH",
                    "version": "9.6",
                },
                {"port": 80, "state": "open", "product": None, "version": None},
                {
                    "port": 443,
                    "state": "closed",
                    "product": "nginx",
                    "version": "1.24.0",
                },
            ],
        }

        results = client.lookup_scan_results(scan_data)

        self.assertEqual(len(results[0]["vulnerabilities"]), 1)
        self.assertEqual(results[1]["vulnerabilities"], [])
        self.assertEqual(results[2]["vulnerabilities"], [])

    def test_invalid_nvd_payload_raises_explicit_error(self):
        requester = lambda request, timeout: FakeResponse({})
        client = NvdClient(request_delay=0, requester=requester)

        with self.assertRaises(NvdClientError):
            client.search("OpenSSH", "9.6")


if __name__ == "__main__":
    unittest.main()
