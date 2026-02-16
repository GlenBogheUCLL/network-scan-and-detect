import sys
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def validate_target(target_ip):
    try:
        socket.gethostbyname(target_ip)
    except socket.error:
        print("Invalid IP address or hostname.")
        sys.exit(1)


def validate_ports(start_port, end_port):
    if start_port > end_port or start_port < 1 or end_port > 65535:
        print("Invalid port range. Please enter a valid range (1-65535).")
        sys.exit(1)


def grab_banner(sock, port):
    try:
        # Trigger HTTP response if needed
        if port in [80, 8000]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore')

        if not banner:
            return "No banner received"

        # Clean HTTP banners
        lines = banner.split("\r\n")
        status_line = lines[0] if len(lines) > 0 else ""

        server_line = ""
        for line in lines:
            if line.lower().startswith("server:"):
                server_line = line
                break

        if server_line:
            return f"{status_line} | {server_line}"
        else:
            return status_line

    except Exception:
        return "Error retrieving banner"
    
def scan_single_port(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                banner = grab_banner(sock, port)
                return port, banner
    except Exception:
        pass

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
                port, banner = result
                open_ports.append(port)
                print(f"OPEN PORT: {port} - Banner: {banner}")

    end_time = time.time()

    print(f"\nScan completed in {end_time - start_time:.2f} seconds")

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"{len(open_ports)} open port(s) found.")


def main():
    if len(sys.argv) != 4:
        print("Usage: python tcp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]

    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("Port numbers must be integers.")
        sys.exit(1)

    validate_target(target_ip)
    validate_ports(start_port, end_port)

    scan_ports(target_ip, start_port, end_port)


if __name__ == "__main__":
    main()