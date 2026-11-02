import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

try:
    from .nvd_client import load_scan_file
except ImportError:
    from nvd_client import load_scan_file


MAX_RISK_SCORE = 10.0
UNKNOWN_FINGERPRINT_PENALTY = 1.5
UNKNOWN_SERVICE_PENALTY = 1.0
INTERNET_FACING_PENALTY = 1.0
SERVICE_PENALTIES = {
    "ftp": 1.0,
    "telnet": 2.0,
    "rlogin": 2.0,
    "redis": 1.0,
}


@dataclass
class RiskAssessment:
    port: int
    service: str
    risk_score: float
    severity: str
    highest_cvss: float
    vulnerability_count: int
    reasons: List[str]

    def to_dict(self):
        return asdict(self)


def _severity_for_score(score):
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _cvss_scores(result):
    vulnerabilities = result.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("The vulnerabilities field must be a list.")

    scores = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise ValueError("Each vulnerability must be a JSON object.")
        score = vulnerability.get("cvss_score")
        if score is None:
            continue
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError("CVSS scores must be numbers between 0 and 10.")
        if not math.isfinite(score) or not 0 <= score <= 10:
            raise ValueError("CVSS scores must be numbers between 0 and 10.")
        scores.append(float(score))
    return scores


def assess_result(result: Dict[str, Any], internet_facing=False):
    if not isinstance(result, dict):
        raise ValueError("Each scan result must be a JSON object.")
    if result.get("state") != "open":
        raise ValueError("Risk assessment only supports open scan results.")

    service = str(result.get("service") or "unknown").lower()
    score = max(_cvss_scores(result), default=0.0)
    reasons = []

    if score:
        reasons.append(f"Highest CVSS score is {score:.1f}.")
    if not result.get("product") or not result.get("version"):
        score += UNKNOWN_FINGERPRINT_PENALTY
        reasons.append(
            f"Incomplete product/version fingerprint (+{UNKNOWN_FINGERPRINT_PENALTY:.1f})."
        )
    if service == "unknown":
        score += UNKNOWN_SERVICE_PENALTY
        reasons.append(f"Unknown service (+{UNKNOWN_SERVICE_PENALTY:.1f}).")
    if service in SERVICE_PENALTIES:
        penalty = SERVICE_PENALTIES[service]
        score += penalty
        reasons.append(f"{service.upper()} is exposed (+{penalty:.1f}).")
    if internet_facing:
        score += INTERNET_FACING_PENALTY
        reasons.append(f"Marked as internet-facing (+{INTERNET_FACING_PENALTY:.1f}).")

    score = min(round(score, 1), MAX_RISK_SCORE)
    if not reasons:
        reasons.append("No CVEs or exposure penalties were identified.")
    return RiskAssessment(
        port=result["port"],
        service=service,
        risk_score=score,
        severity=_severity_for_score(score),
        highest_cvss=round(max(_cvss_scores(result), default=0.0), 1),
        vulnerability_count=len(result.get("vulnerabilities", [])),
        reasons=reasons,
    )


def assess_scan(scan_data: Dict[str, Any], internet_facing=False):
    results = scan_data.get("results")
    if not isinstance(results, list):
        raise ValueError("Scan JSON must contain a results list.")

    assessments = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Each scan result must be a JSON object.")
        if result.get("state") == "open":
            assessments.append(
                assess_result(result, internet_facing=internet_facing)
            )
    overall_score = max(
        (assessment.risk_score for assessment in assessments),
        default=0.0,
    )
    return {
        "target": scan_data.get("target"),
        "internet_facing": internet_facing,
        "overall_risk_score": overall_score,
        "overall_severity": _severity_for_score(overall_score),
        "results": [assessment.to_dict() for assessment in assessments],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Calculate transparent risk scores for vulnerability scan results."
    )
    parser.add_argument("vulnerability_file", help="JSON file produced by nvd_client.py")
    parser.add_argument("--output", help="Write risk assessment to JSON")
    parser.add_argument(
        "--internet-facing",
        action="store_true",
        help="Add the internet-facing exposure penalty to open services",
    )
    args = parser.parse_args()

    try:
        scan_data = load_scan_file(args.vulnerability_file)
        output = assess_scan(scan_data, internet_facing=args.internet_facing)
    except (ValueError, KeyError) as error:
        parser.error(str(error))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as output_file:
                json.dump(output, output_file, indent=2)
        except OSError as error:
            parser.error(f"Unable to write output file: {error}")
        print(f"Risk assessment written to {args.output}")
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
