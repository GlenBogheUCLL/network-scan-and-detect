import sys
import socket
import time

def main():
    if len(sys.argv) != 4:
        print("Usage: python tcp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]

    try:
        socket.gethostbyname(target_ip)
    except socket.error:
        print("Invalid IP address or hostname.")
        sys.exit(1)

    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("Port numbers must be integers.")
        sys.exit(1)

    if start_port > end_port or start_port < 1 or end_port > 65535:
        print("Invalid port range. Please enter a valid range (1-65535).")
        sys.exit(1)

    print(f"\nScanning {target_ip} ({start_port}-{end_port})...")
    
    start_time = time.time()
    open_ports = 0

    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)  # Set a timeout for the connection attempt

                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    print(f"OPEN PORT: {port}")
                    open_ports += 1

        except Exception:
            pass #continue scanning even if an error occurs
    
    end_time = time.time()
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    if open_ports == 0:
        print("No open ports found.")
    else:
        print(f"{open_ports} open port(s) found.")

if __name__ == "__main__":
    main()