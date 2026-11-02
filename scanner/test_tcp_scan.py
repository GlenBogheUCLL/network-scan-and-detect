import unittest

try:
    from .tcp_scan import fingerprint_service
except ImportError:
    from tcp_scan import fingerprint_service


class FingerprintingTests(unittest.TestCase):
    def test_http_server_banner_extracts_product_and_version(self):
        result = fingerprint_service(
            443,
            "HTTP/1.1 200 OK | Server: nginx/1.24.0",
        )

        self.assertEqual(result, ("http", "nginx", "1.24.0", 0.95))

    def test_smb_port_is_identified_without_guessing_version(self):
        service, product, version, confidence = fingerprint_service(445, None)

        self.assertEqual(service, "smb")
        self.assertEqual(product, "Microsoft SMB")
        self.assertIsNone(version)
        self.assertEqual(confidence, 0.7)

    def test_vmware_banner_extracts_product_and_version(self):
        result = fingerprint_service(
            902,
            "220 VMware Authentication Daemon Version 1.10: SSL Required",
        )

        self.assertEqual(result, ("vmware-auth", "VMware Authentication Daemon", "1.10", 0.95))

    def test_unknown_service_has_low_confidence(self):
        self.assertEqual(fingerprint_service(9999, None), ("unknown", None, None, 0.1))


if __name__ == "__main__":
    unittest.main()
