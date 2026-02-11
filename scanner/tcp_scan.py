import sys

def main():
    if len(sys.argv) != 4:
        print("Usage: python tcp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")

if __name__ == "__main__":
    main()