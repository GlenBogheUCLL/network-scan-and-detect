import sys
import socket
import time

def main():
    if len(sys.argv) != 4:
        print("Usage: python tcp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Set a timeout for the connection attempt

            result = sock.connect_ex((target_ip, port))

            if result == 0:
                print(f"OPEN PORT: {port}")

            sock.close()
            
        except Exception:
            pass #continue scanning even if an error occurs
    
    end_time = time.time()
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()