from scapy.all import IP, ICMP, sr1
import ipaddress
import socket
import threading
import argparse
import logging
import sys
import os
import json
import datetime
import nmap
from report import save_results_csv, save_results_json, save_results_html
from plotter import plot_open_ports_tkinter
from plyer import notification

logging.basicConfig(
    filename='network_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_desktop_notification(title, message):
    """Send desktop notification, safely ignoring errors."""
    try:
        notification.notify(title=title, message=message, timeout=10)
    except Exception:
        pass

def resource_path(relative_path):
    """Get absolute path to resource, works for PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def detect_os_by_ttl(ttl):
    """Guess operating system based on TTL value."""
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    else:
        return "Unknown"

def validate_target(target):
    """Resolve hostname/IP to IP string, supports IPv4 and IPv6."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        try:
            ipaddress.IPv6Address(target)
            return target
        except Exception:
            return None

def grab_banner(ip, port, timeout=2):
    """Attempt to grab banner from an open port."""
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return s.recv(1024).decode(errors='ignore').strip()
    except Exception:
        return None

def scan_port_with_banner(target, port, timeout=0.5, source_ip=None):
    """Scan a port, optionally bind source IP, and try to grab banner."""
    try:
        family = socket.AF_INET6 if ':' in target else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)

        if source_ip:
            try:
                if family == socket.AF_INET6:
                    sock.bind((source_ip, 0, 0, 0))
                else:
                    sock.bind((source_ip, 0))
            except Exception as e:
                logging.warning(f"Failed to bind source IP {source_ip}: {e}")

        sock.settimeout(timeout)

        if family == socket.AF_INET6:
            result = sock.connect_ex((target, port, 0, 0))
        else:
            result = sock.connect_ex((target, port))

        is_open = (result == 0)
        banner = grab_banner(target, port, timeout) if is_open else None

        sock.close()
        return port, is_open, banner
    except Exception as e:
        logging.error(f"Error scanning port {port} on {target}: {e}")
        return port, False, None

def scan_ports_multithreaded(target, ports, max_threads=200, timeout=0.2, source_ip=None):
    """Scan ports using multithreading, with banner grabbing."""

    open_ports = []
    lock = threading.Lock()

    def worker(port):
        port, is_open, banner = scan_port_with_banner(target, port, timeout, source_ip)
        if is_open:
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = 'unknown'
            with lock:
                open_ports.append((port, service, banner))

    threads = []
    for port in ports:
        thread = threading.Thread(target=worker, args=(port,))
        thread.start()
        threads.append(thread)
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads.clear()
    for t in threads:
        t.join()

    return sorted(open_ports, key=lambda x: x[0])

def advanced_nmap_scan(target, ports='1-1024', timing='-T4', source_ip=None):
    """Perform nmap scan with optional source IP and timing."""
    nm = nmap.PortScanner()
    scan_args = timing
    if source_ip:
        scan_args += f' -S {source_ip}'
    try:
        nm.scan(target, ports, arguments=scan_args)
    except Exception as e:
        logging.error(f"Error during nmap scan: {e}")
        return []

    results = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            lports = nm[target][proto].keys()
            for port in sorted(lports):
                state = nm[target][proto][port]['state']
                service = nm[target][proto][port].get('name', 'unknown')
                version = nm[target][proto][port].get('version', '')
                product = nm[target][proto][port].get('product', '')
                info = f"{service} {product} {version}".strip()
                if state == 'open':
                    results.append((port, info, None))
    return results

def ping_host(ip, timeout=1):
    """Ping host and return alive status, TTL, and OS guess."""
    packet = IP(dst=str(ip)) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=0)
    if reply:
        ttl = reply.ttl
        os_guess = detect_os_by_ttl(ttl)
        return True, ttl, os_guess
    return False, None, None

def ping_sweep(subnet):
    """Scan subnet with ICMP ping sweep, returning list of active hosts."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except Exception:
        return []
    active_hosts = []
    print(f"Starting ping sweep on subnet: {subnet}")
    for ip in network.hosts():
        alive, ttl, os_guess = ping_host(ip)
        if alive:
            print(f"Host {ip} active - TTL: {ttl}, OS guess: {os_guess}")
            active_hosts.append(str(ip))
    print(f"Ping sweep complete. Active hosts: {active_hosts}")
    return active_hosts

def run_all_scans(target, port_range, use_nmap=False, threads=200, timeout=0.2,
                  nmap_timing='-T4', gui_callback=None, source_ip=None,
                  scan_profile=None, notify_enabled=False):
    """Run full scan including port scanning and reporting. Supports CLI and GUI callbacks."""

    resolved_ip = validate_target(target)
    if not resolved_ip:
        err_msg = f"Error: Unable to resolve hostname '{target}'."
        if gui_callback:
            gui_callback(err_msg)
        else:
            print(err_msg)
        return []

    try:
        start_port, end_port = map(int, port_range.split('-'))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError
    except ValueError:
        err_msg = "Invalid port range. Use format start-end within 1-65535."
        if gui_callback:
            gui_callback(err_msg)
        else:
            print(err_msg)
        return []

    ports = range(start_port, end_port + 1)

    if use_nmap:
        results = advanced_nmap_scan(resolved_ip, f"{start_port}-{end_port}", timing=nmap_timing, source_ip=source_ip)
    else:
        results = scan_ports_multithreaded(resolved_ip, ports, max_threads=threads, timeout=timeout, source_ip=source_ip)

    save_dir = "scan_results"
    os.makedirs(save_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{target.replace('/', '_')}_{timestamp}"

    json_path = os.path.join(save_dir, f"{base_filename}.json")
    csv_path = os.path.join(save_dir, f"{base_filename}.csv")
    html_path = os.path.join(save_dir, f"{base_filename}.html")

    save_results_json(target, results, source_ip=source_ip)
    save_results_csv(target, results, source_ip=source_ip)
    save_results_html(target, results, source_ip=source_ip)

    if notify_enabled:
        if results:
            send_desktop_notification(
                "Network Scan Complete",
                f"Scan complete for {target}. {len(results)} ports open."
            )
            critical_ports = {22: "SSH", 80: "HTTP", 445: "SMB"}
            open_critical = [p for p, s, b in results if p in critical_ports]
            if open_critical:
                ports_str = ", ".join(f"{p} ({critical_ports[p]})" for p in open_critical)
                send_desktop_notification(
                    "Critical Ports Open",
                    f"On {target}: {ports_str}"
                )
        else:
            send_desktop_notification(
                "Network Scan Complete",
                f"No open ports found on {target}."
            )

    msg = []
    if results:
        msg.append(f"Scan complete for {target} ({resolved_ip})")
        for port, service, banner in results:
            banner_info = f" - Banner: {banner}" if banner else ""
            msg.append(f"Port {port}: {service}{banner_info}")
        msg.append(f"Results saved: {save_dir}")
    else:
        msg.append(f"No open ports found on {target}")

    result_str = "\n".join(msg)
    if gui_callback:
        gui_callback(result_str)
    else:
        print(result_str)

    return results

def cli_main():
    parser = argparse.ArgumentParser(description='Advanced Network Scanner with Multithreaded TCP, Nmap, and GUI')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range to scan, e.g. 1-1024')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Max number of threads (default 200)')
    parser.add_argument('--timeout', type=float, default=0.2, help='Socket timeout in seconds (default 0.2)')
    parser.add_argument('--use-nmap', action='store_true', help='Use Nmap for advanced scanning')
    parser.add_argument('--gui', action='store_true', help='Launch GUI application')
    parser.add_argument('--source-ip', help='Source IP for scanning (optional)', default=None)
    args = parser.parse_args()

    if args.gui:
        launch_gui()
    else:
        run_all_scans(args.target, args.ports, use_nmap=args.use_nmap, threads=args.threads,
                      timeout=args.timeout, source_ip=args.source_ip)

def launch_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox
    import threading

    def load_previous_scan():
        file_path = filedialog.askopenfilename(
            title="Select Scan Result JSON",
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            target = data.get("target", "Unknown")
            results = data.get("results", [])
            for widget in plot_frame.winfo_children():
                widget.destroy()
            plot_results = [(r["port"], r["service"]) for r in results]
            plot_open_ports_tkinter(target, plot_results, plot_frame)
            result_text.insert(tk.END, f"Loaded scan results from {file_path}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load scan file:\n{e}")

    def start_scan():
        target = entry_target.get().strip()
        if not target:
            result_text.insert(tk.END, "Please enter a target subnet or IP.\n")
            return
        ports = entry_ports.get().strip()
        if not ports:
            result_text.insert(tk.END, "Please enter ports range (e.g., 1-1024).\n")
            return
        use_nmap = var_nmap.get()
        source_ip = entry_sourceip.get().strip() or None
        try:
            threads = int(entry_threads.get() or "200")
            timeout = float(entry_timeout.get() or "0.2")
        except ValueError:
            result_text.insert(tk.END, "Invalid threads or timeout value.\n")
            return
        btn_scan.config(state='disabled')
        result_text.delete("1.0", tk.END)
        for widget in plot_frame.winfo_children():
            widget.destroy()

        def update(text):
            result_text.insert(tk.END, text + "\n")
            result_text.see(tk.END)

        def scan_and_plot():
            update(f"Starting ping sweep on subnet: {target}")
            try:
                active_hosts = ping_sweep(target)
                update(f"Found {len(active_hosts)} active hosts.")
                host_threads = []
                lock = threading.Lock()

                def scan_host(host):
                    update(f"Scanning ports on {host}...")
                    results = run_all_scans(host, ports, use_nmap, threads, timeout,
                                            gui_callback=update, source_ip=source_ip)
                    if results:
                        with lock:
                            plot_open_ports_tkinter(host, [(port, service) for port, service, _ in results], plot_frame)

                for host in active_hosts:
                    t = threading.Thread(target=scan_host, args=(host,))
                    t.start()
                    host_threads.append(t)
                    if len(host_threads) >= 10:
                        for ht in host_threads:
                            ht.join()
                        host_threads.clear()
                for ht in host_threads:
                    ht.join()
                update("Scan complete.")
            except Exception as e:
                update(f"Error during scanning: {str(e)}")
            btn_scan.config(state='normal')

        threading.Thread(target=scan_and_plot).start()

    root = tk.Tk()
    root.title("Network Scanner")

    tk.Label(root, text="Target (domain/IP or subnet for ping sweep):").pack()
    entry_target = tk.Entry(root)
    entry_target.pack()

    tk.Label(root, text="Source IP (Optional, for outgoing scans):").pack()
    entry_sourceip = tk.Entry(root)
    entry_sourceip.pack()

    tk.Label(root, text="Ports (start-end):").pack()
    entry_ports = tk.Entry(root)
    entry_ports.insert(0, "1-1024")
    entry_ports.pack()

    tk.Label(root, text="Threads:").pack()
    entry_threads = tk.Entry(root)
    entry_threads.insert(0, "200")
    entry_threads.pack()

    tk.Label(root, text="Timeout (in seconds):").pack()
    entry_timeout = tk.Entry(root)
    entry_timeout.insert(0, "0.2")
    entry_timeout.pack()

    var_nmap = tk.BooleanVar()
    chk_nmap = tk.Checkbutton(root, text="Use Nmap (advanced scan)", variable=var_nmap)
    chk_nmap.pack()

    btn_scan = tk.Button(root, text="Start Scan", command=start_scan)
    btn_scan.pack()

    btn_load = tk.Button(root, text="Load Previous Scan...", command=load_previous_scan)
    btn_load.pack()

    result_text = tk.Text(root, height=10, width=80)
    result_text.pack()

    plot_frame = tk.Frame(root)
    plot_frame.pack(fill='both', expand=True)

    root.mainloop()

if __name__ == '__main__':
    cli_main()
