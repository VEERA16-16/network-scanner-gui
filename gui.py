import socket
import threading
import psutil
import time
import logging
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import concurrent.futures
import queue
from scanner import validate_target, scan_ports_multithreaded, advanced_nmap_scan
from plotter import plot_open_ports_tkinter
from report import save_results_csv, save_results_json, save_results_html
from network_scanner import ping_sweep, run_all_scans
from system_health import SystemHealthMonitor
from datetime import datetime
import ipaddress
from encryption_utils import load_results_json_encrypted
import json
import os

logging.basicConfig(
    filename="network_scanner.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

def launch_gui():
    root = tk.Tk()
    root.title("Network Scanner")

    health_monitor = SystemHealthMonitor(cpu_threshold=75, mem_threshold=75)
    health_monitor.start()

    SCAN_PROFILES = {
        "Quick": {"threads": 20, "ports": "1-1024", "timeout": 0.2},
        "Standard": {"threads": 50, "ports": "1-2048", "timeout": 0.3},
        "Deep": {"threads": 100, "ports": "1-65535", "timeout": 0.5},
    }

    gui_queue = queue.Queue()

    tk.Label(root, text="Select Network Interface (IPv4 & IPv6):").pack()
    interface_ips = get_interface_ips()
    interface_display_list = []
    iplookup = {}
    for ifname, ips in interface_ips.items():
        for ip in ips:
            display = f"{ifname} - {ip}"
            interface_display_list.append(display)
            iplookup[display] = ip
    interface_var = tk.StringVar(value=interface_display_list[0] if interface_display_list else "")
    interface_menu = tk.OptionMenu(root, interface_var, *interface_display_list)
    interface_menu.pack()
    btn_refresh = tk.Button(root, text="Refresh Interfaces",
                            command=lambda: refresh_interfaces(interface_var, interface_menu, interface_display_list, iplookup))
    btn_refresh.pack()

    tk.Label(root, text="Target (domain/IP or subnet for ping sweep):").pack()
    entry_target = tk.Entry(root)
    entry_target.pack()

    tk.Label(root, text="Ports (start-end):").pack()
    entry_ports = tk.Entry(root)
    entry_ports.insert(0, "1-1024")
    entry_ports.pack()

    tk.Label(root, text="Threads:").pack()
    entry_threads = tk.Entry(root)
    entry_threads.insert(0, "50")
    entry_threads.pack()

    tk.Label(root, text="Timeout (seconds):").pack()
    entry_timeout = tk.Entry(root)
    entry_timeout.insert(0, "0.3")
    entry_timeout.pack()

    tk.Label(root, text="Scan Profile:").pack()
    profile_var = tk.StringVar(value="Standard")
    profile_menu = tk.OptionMenu(root, profile_var, *SCAN_PROFILES.keys())
    profile_menu.pack()

    var_nmap = tk.BooleanVar()
    chk_nmap = tk.Checkbutton(root, text="Use Nmap (advanced scan)", variable=var_nmap)
    chk_nmap.pack()

    var_notify = tk.BooleanVar(value=True)
    chk_notify = tk.Checkbutton(root, text="Enable Desktop Notifications", variable=var_notify)
    chk_notify.pack()

    tk.Label(root, text="Scan History:").pack()
    history_listbox = tk.Listbox(root, height=8)
    history_listbox.pack(fill="x", padx=5)

    result_text = tk.Text(root, height=10, width=80)
    result_text.pack()

    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(root, maximum=100, variable=progress_var)
    progress_bar.pack(fill='x', padx=5, pady=5)

    status_var = tk.StringVar(value="System status: Normal")
    status_label = tk.Label(root, textvariable=status_var)
    status_label.pack()

    plot_frame = tk.Frame(root)
    plot_frame.pack(fill='both', expand=True)

    def refresh_interfaces(interface_var, interface_menu, interface_display_list, iplookup):
        interface_ips = get_interface_ips()
        interface_display_list.clear()
        iplookup.clear()
        for ifname, ips in interface_ips.items():
            for ip in ips:
                display = f"{ifname} - {ip}"
                interface_display_list.append(display)
                iplookup[display] = ip
        interface_var.set(interface_display_list[0] if interface_display_list else "")
        interface_menu['menu'].delete(0, 'end')
        for item in interface_display_list:
            interface_menu['menu'].add_command(label=item, command=tk._setit(interface_var, item))

    def refresh_history_list():
        scans = load_scan_history()
        history_listbox.delete(0, tk.END)
        for entry in reversed(scans):
            display = f"{entry['timestamp']} - {entry['target']} - Profile: {entry.get('scan_profile', '')} - Open ports: {entry.get('open_ports_count', 0)}"
            history_listbox.insert(tk.END, display)

    def on_history_select(evt):
        if not history_listbox.curselection():
            return
        index = history_listbox.curselection()[0]
        scans = load_scan_history()
        if index >= len(scans):
            return
        entry = scans[::-1][index]
        messagebox.showinfo("Scan History",
                            f"Scan for {entry['target']} at {entry['timestamp']} with profile {entry.get('scan_profile')}.\n"
                            f"Open ports: {entry.get('open_ports_count')}")

    history_listbox.bind("<<ListboxSelect>>", on_history_select)
    refresh_history_list()

    def update_system_status():
        try:
            if health_monitor.overloaded:
                status_var.set("System status: High load, scanning paused")
            else:
                status_var.set("System status: Normal")
        except Exception as e:
            logging.error(f"System status update failure: {e}")
        root.after(2000, update_system_status)
    update_system_status()

    def update_gui():
        while True:
            try:
                item = gui_queue.get_nowait()
            except queue.Empty:
                break
            else:
                if isinstance(item, dict):
                    if item.get("type") == "progress":
                        progress_var.set(item.get("value", 0))
                    elif item.get("type") == "status":
                        status_var.set(item.get("value", "Unknown Status"))
                else:
                    result_text.insert(tk.END, item + "\n")
                    result_text.see(tk.END)
        root.after(100, update_gui)

    def apply_profile_settings():
        profile = profile_var.get()
        if profile in SCAN_PROFILES:
            settings = SCAN_PROFILES[profile]
            entry_threads.delete(0, tk.END)
            entry_threads.insert(0, str(settings["threads"]))
            entry_ports.delete(0, tk.END)
            entry_ports.insert(0, settings["ports"])
            entry_timeout.delete(0, tk.END)
            entry_timeout.insert(0, str(settings["timeout"]))
    profile_var.trace('w', lambda *args: apply_profile_settings())

    def start_scan():
        apply_profile_settings()
        target = entry_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target subnet or IP.")
            gui_queue.put("No target entered by user.")
            return
        if not is_valid_ip_or_subnet(target):
            messagebox.showerror("Input Error", "Target must be a valid IP address or subnet in CIDR notation.")
            gui_queue.put("Invalid target IP or subnet.")
            return

        ports = entry_ports.get().strip()
        if not ports:
            messagebox.showerror("Input Error", "Please enter ports range (e.g., 1-1024).")
            gui_queue.put("No ports entered by user.")
            return

        if '-' not in ports:
            messagebox.showerror("Input Error", "Port range must be in format start-end (e.g., 1-1024).")
            gui_queue.put("Invalid port range format.")
            return

        try:
            start_port, end_port = map(int, ports.split('-'))
            if not (1 <= start_port <= end_port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Port range values must be integers between 1 and 65535.")
            gui_queue.put("Invalid port range values.")
            return

        use_nmap = var_nmap.get()

        try:
            threads = int(entry_threads.get())
            if threads <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Threads value should be a positive integer.")
            gui_queue.put("Invalid threads value.")
            return

        try:
            timeout = float(entry_timeout.get())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Timeout should be a positive number (seconds).")
            gui_queue.put("Invalid timeout value.")
            return

        selected_display = interface_var.get()
        source_ip = iplookup.get(selected_display, None)

        notify_enabled = var_notify.get()

        btn_scan.config(state='disabled')
        result_text.delete("1.0", tk.END)
        for widget in plot_frame.winfo_children():
            widget.destroy()

        def scan_and_plot():
            gui_queue.put(f"Starting ping sweep on subnet: {target}")
            try:
                active_hosts = ping_sweep(target)
                gui_queue.put(f"Found {len(active_hosts)} active hosts on {target}.")
                logging.info(f"Found {len(active_hosts)} active hosts for {target}")

                results_dict = {}
                total_hosts = len(active_hosts)
                scanned_hosts = 0

                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {
                        executor.submit(run_all_scans, host, ports, use_nmap, threads, timeout,
                                        gui_callback=gui_queue.put,
                                        source_ip=source_ip,
                                        scan_profile=profile_var.get(),
                                        notify_enabled=notify_enabled
                                        ): host for host in active_hosts
                    }
                    for future in concurrent.futures.as_completed(futures):
                        host = futures[future]
                        try:
                            results = future.result()
                        except Exception as exc:
                            gui_queue.put(f"Scan failed for {host}: {exc}")
                            logging.error(f"Scan failed for {host}: {exc}")
                            results = []
                        scanned_hosts += 1
                        progress = (scanned_hosts / total_hosts) * 100 if total_hosts > 0 else 100
                        gui_queue.put({'type': 'progress', 'value': progress})
                        gui_queue.put(f"Completed scan on {host} ({scanned_hosts}/{total_hosts})")
                        results_dict[host] = results

                for host, results in results_dict.items():
                    if results:
                        plot_open_ports_tkinter(host, results, plot_frame)

                gui_queue.put("Scan complete.")
                logging.info("Scan complete for all hosts.")
                refresh_history_list()

            except Exception as e:
                gui_queue.put(f"Error during scanning: {str(e)}")
                logging.exception(e)
            btn_scan.config(state='normal')

        threading.Thread(target=scan_and_plot, daemon=True).start()

    btn_scan = tk.Button(root, text="Start Scan", command=start_scan)
    btn_scan.pack()

    root.after(100, update_gui)
    root.mainloop()

def get_interface_ips():
    import netifaces
    interfaces = {}
    for iface in netifaces.interfaces():
        addresses = []
        addrs = netifaces.ifaddresses(iface)
        for family in (netifaces.AF_INET, netifaces.AF_INET6):
            for link in addrs.get(family, []):
                addr = link.get('addr')
                if addr:
                    if '%' in addr:
                        addr = addr.split('%')[0]
                    addresses.append(addr)
        if addresses:
            interfaces[iface] = addresses
    return interfaces

def is_valid_ip_or_subnet(value):
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def load_scan_history():
    fname = 'scan_history.json'
    if not os.path.isfile(fname):
        return []
    try:
        with open(fname, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

if __name__ == "__main__":
    launch_gui()
