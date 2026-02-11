import sys
import socket

def main():
    if len(sys.argv) != 4:
        print("Usage: python tcp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Set a timeout for the connection attempt

        result = sock.connect_ex((target_ip, start_port))

        if result == 0:
            print(f"Port {start_port} is open.")
        else:
            print(f"Port {start_port} is closed or filtered.")
        
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()