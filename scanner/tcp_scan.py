import argparse
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Optional


KNOWN_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    135: "msrpc",
    445: "smb",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http",
    8443: "https",
    902: "vmware-auth",
    912: "vmware-auth",
}


@dataclass
class ScanResult:
    port: int
    protocol: str
    state: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self):
        return asdict(self)


def validate_target(target_ip):
    try:
        socket.gethostbyname(target_ip)
    except socket.gaierror:
        print("Invalid IP address or hostname.")
        sys.exit(1)


def validate_ports(start_port, end_port):
    if start_port > end_port or start_port < 1 or end_port > 65535:
        print("Invalid port range. Please enter a valid range (1-65535).")
        sys.exit(1)


def grab_banner(sock, port):
    try:
        if port in [80, 8000, 8080, 8443]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        if not banner:
            return None

        lines = banner.splitlines()
        status_line = lines[0]
        server_line = next(
            (line for line in lines if line.lower().startswith("server:")),
            None,
        )
        return f"{status_line} | {server_line}" if server_line else status_line
    except (OSError, UnicodeError):
        return None


def _extract_product_and_version(service, banner):
    if not banner:
        return None, None

    source = banner
    if " | " in banner:
        source = banner.split(" | ", 1)[1].split(":", 1)[-1].strip()

    patterns = [
        r"(?P<product>VMware Authentication Daemon)[ :]+Version[ /](?P<version>\d+(?:\.\d+)+)",
        r"(?P<product>[A-Za-z][\w.-]*)/(?P<version>\d+(?:\.\d+)+)",
        r"(?P<product>OpenSSH)[_ /](?P<version>\d+(?:\.\d+)+)",
        r"(?P<product>nginx)[/ ](?P<version>\d+(?:\.\d+)+)",
        r"(?P<product>Apache)[/ ](?P<version>\d+(?:\.\d+)+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, source, re.IGNORECASE)
        if match:
            return match.group("product"), match.group("version")
    return None, None


def fingerprint_service(port, banner):
    service = KNOWN_SERVICES.get(port, "unknown")
    product, version = _extract_product_and_version(service, banner)
    confidence = 0.1 if service == "unknown" else 0.55

    if port == 135:
        product = "Microsoft RPC"
        confidence = 0.65
    elif port == 445:
        product = "Microsoft SMB"
        confidence = 0.65
    elif port in [902, 912]:
        product = product or "VMware Authentication Daemon"
        confidence = 0.8

    if banner:
        lower_banner = banner.lower()
        banner_service = next(
            (
                name
                for name in KNOWN_SERVICES.values()
                if name in lower_banner and name != "https"
            ),
            None,
        )
        if banner_service:
            service = banner_service
            confidence = 0.8

    if product and version:
        confidence = 0.95
    elif product:
        confidence = max(confidence, 0.7)

    return service, product, version, confidence


def scan_single_port(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            if sock.connect_ex((target_ip, port)) != 0:
                return None

            banner = grab_banner(sock, port)
            service, product, version, confidence = fingerprint_service(port, banner)
            return ScanResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                product=product,
                version=version,
                banner=banner,
                confidence=confidence,
            )
    except OSError:
        return None


def scan_ports(target_ip, start_port, end_port):
    print(f"\nScanning {target_ip} ({start_port}-{end_port})...")
    start_time = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(scan_single_port, target_ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda result: result.port)
    for result in open_ports:
        fingerprint = result.service
        if result.product:
            fingerprint += f" ({result.product}"
            if result.version:
                fingerprint += f" {result.version}"
            fingerprint += ")"
        print(f"OPEN PORT: {result.port} - {fingerprint} - Banner: {result.banner or 'None'}")

    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
    if not open_ports:
        print("No open ports found.")
    else:
        print(f"{len(open_ports)} open port(s) found.")
    return open_ports


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Scan a target for open TCP ports and fingerprint services."
    )
    parser.add_argument("target_ip", help="IP address or hostname to scan")
    parser.add_argument("start_port", type=int, help="First port to scan")
    parser.add_argument("end_port", type=int, help="Last port to scan")
    parser.add_argument(
        "--output",
        help="Write structured scan results to a JSON file",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    validate_target(args.target_ip)
    validate_ports(args.start_port, args.end_port)

    results = scan_ports(args.target_ip, args.start_port, args.end_port)
    if args.output:
        output = {
            "target": args.target_ip,
            "port_range": {"start": args.start_port, "end": args.end_port},
            "results": [result.to_dict() for result in results],
        }
        with open(args.output, "w", encoding="utf-8") as output_file:
            json.dump(output, output_file, indent=2)
        print(f"Structured results written to {args.output}")


if __name__ == "__main__":
    main()
