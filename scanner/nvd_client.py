import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClientError(RuntimeError):
    """Raised when the NVD API cannot be queried or its response is invalid."""


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    vector: Optional[str]

    def to_dict(self):
        return asdict(self)


class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        request_timeout: int = 15,
        request_delay: float = 0.6,
        requester: Callable[..., Any] = urlopen,
    ):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.request_timeout = request_timeout
        self.request_delay = request_delay
        self.requester = requester

    def search(self, product: str, version: str) -> List[Vulnerability]:
        if not product or not version:
            raise ValueError("Both product and version are required for an NVD search.")

        query = urlencode({"keywordSearch": f"{product} {version}"})
        request = Request(
            f"{NVD_CVES_URL}?{query}",
            headers=self._headers(),
        )
        try:
            with self.requester(request, timeout=self.request_timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as error:
            raise NvdClientError(f"NVD request failed: {error}") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NvdClientError("NVD returned an invalid JSON response.") from error

        if not isinstance(payload, dict) or not isinstance(
            payload.get("vulnerabilities"), list
        ):
            raise NvdClientError("NVD response is missing the vulnerabilities list.")

        vulnerabilities = []
        for item in payload["vulnerabilities"]:
            vulnerability = self._parse_vulnerability(item)
            if vulnerability:
                vulnerabilities.append(vulnerability)

        if self.request_delay > 0:
            time.sleep(self.request_delay)
        return vulnerabilities

    def lookup_scan_results(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = scan_data.get("results")
        if not isinstance(results, list):
            raise ValueError("Scan JSON must contain a results list.")

        matches = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Each scan result must be a JSON object.")

            match = dict(result)
            product = result.get("product")
            version = result.get("version")
            if product and version and result.get("state") == "open":
                match["vulnerabilities"] = [
                    vulnerability.to_dict()
                    for vulnerability in self.search(product, version)
                ]
            else:
                match["vulnerabilities"] = []
            matches.append(match)
        return matches

    def _headers(self):
        headers = {"User-Agent": "network-scan-and-detect/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    @staticmethod
    def _parse_vulnerability(item):
        if not isinstance(item, dict):
            return None
        cve = item.get("cve")
        if not isinstance(cve, dict) or not cve.get("id"):
            return None

        descriptions = cve.get("descriptions", [])
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if entry.get("lang") == "en"
            ),
            "",
        )
        metric = NvdClient._preferred_metric(cve.get("metrics", {}))
        return Vulnerability(
            cve_id=cve["id"],
            description=description,
            cvss_score=metric.get("baseScore") if metric else None,
            severity=metric.get("baseSeverity") if metric else None,
            vector=metric.get("vectorString") if metric else None,
        )

    @staticmethod
    def _preferred_metric(metrics):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key, [])
            if values:
                data = values[0].get("cvssData", {})
                return {
                    "baseScore": data.get("baseScore"),
                    "baseSeverity": data.get("baseSeverity")
                    or values[0].get("baseSeverity"),
                    "vectorString": data.get("vectorString"),
                }
        return {}


def load_scan_file(path):
    try:
        with open(path, encoding="utf-8") as scan_file:
            data = json.load(scan_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read scan file '{path}': {error}") from error
    if not isinstance(data, dict):
        raise ValueError("Scan JSON must contain an object at the top level.")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Look up detected products and versions in the NVD."
    )
    parser.add_argument("scan_file", help="JSON file produced by tcp_scan.py")
    parser.add_argument("--output", help="Write vulnerability matches to JSON")
    args = parser.parse_args()

    try:
        scan_data = load_scan_file(args.scan_file)
        matches = NvdClient().lookup_scan_results(scan_data)
    except (ValueError, NvdClientError) as error:
        parser.error(str(error))

    output = {"target": scan_data.get("target"), "results": matches}
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as output_file:
                json.dump(output, output_file, indent=2)
        except OSError as error:
            parser.error(f"Unable to write output file: {error}")
        print(f"Vulnerability results written to {args.output}")
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
