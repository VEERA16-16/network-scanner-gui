import socket
import threading
import queue
import sys

# Thread-safe print function lock
print_lock = threading.Lock()

def scan_port(target, port, results_queue, timeout_ms):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_ms / 1000.0)  # Convert ms to seconds
            result = s.connect_ex((target, port))
            with print_lock:
                if result == 0:
                    print(f"[+] Port {port} is open")
                else:
                    print(f"[-] Port {port} is closed or filtered")
            if result == 0:
                results_queue.put(port)
    except Exception as e:
        with print_lock:
            print(f"[!] Error scanning port {port}: {e}")

def worker(target, task_queue, results_queue, timeout_ms):
    while not task_queue.empty():
        port = task_queue.get()
        scan_port(target, port, results_queue, timeout_ms)
        task_queue.task_done()

def main(target, port_range, threads, timeout_ms):
    try:
        port_start, port_end = map(int, port_range.split('-'))
    except Exception as e:
        print(f"Invalid port range format: {e}")
        return

    task_queue = queue.Queue()
    results_queue = queue.Queue()

    for port in range(port_start, port_end + 1):
        task_queue.put(port)

    print(f"[*] Starting scan on {target} from port {port_start} to {port_end} with {threads} threads")

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target, task_queue, results_queue, timeout_ms))
        t.daemon = True
        t.start()
        thread_list.append(t)

    task_queue.join()

    print("[*] Scan complete. Open ports:")
    open_ports = []
    while not results_queue.empty():
        open_ports.append(results_queue.get())

    if open_ports:
        for port in sorted(open_ports):
            print(f" - Port {port}")
    else:
        print(" - No open ports found.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simple threaded port scanner with live output")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g. 1-65535)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=500, help="Timeout per port in milliseconds")
    args = parser.parse_args()

    try:
        main(args.target, args.ports, args.threads, args.timeout)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit()
