import socket
import threading
import logging
import nmap
import time
import ipaddress
from report import save_results_csv, save_results_json, save_results_html


def validate_target(target):
    try:
        # Try resolve as IPv4/hostname
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        try:
            # Try parsing as IPv6 literal
            ipaddress.IPv6Address(target)
            return target
        except Exception:
            return None


def scan_port(target, port, timeout=0.5, source_ip=None):
    try:
        # Select socket family by IP format
        family = socket.AF_INET6 if ':' in target else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        if source_ip:
            # Only bind if source_ip matches family format, else ignore
            try:
                sock.bind((source_ip, 0))
            except Exception as e:
                logging.warning(f"Failed to bind socket to source IP {source_ip}: {e}")
        sock.settimeout(timeout)
        # IPv6 connect requires 4-tuple
        if family is socket.AF_INET6:
            result = sock.connect_ex((target, port, 0, 0))
        else:
            result = sock.connect_ex((target, port))
        sock.close()
        return port, result == 0
    except Exception as e:
        logging.error(f"Error scanning port {port} on {target}: {e}")
        return port, False


def scan_ports_multithreaded(target, ports, max_threads=200, timeout=0.2, health_monitor=None, source_ip=None):
    open_ports = []
    lock = threading.Lock()

    def worker(port):
        while health_monitor and health_monitor.overloaded:
            time.sleep(2)
        port_num, is_open = scan_port(target, port, timeout, source_ip=source_ip)
        if is_open:
            try:
                service = socket.getservbyport(port_num, 'tcp')
            except OSError:
                service = 'unknown'
            with lock:
                open_ports.append((port_num, service))
            logging.info(f"Port {port_num} open on {target}, service: {service}")

    threads = []
    for port in ports:
        thread = threading.Thread(target=worker, args=(port,))
        thread.start()
        threads.append(thread)
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()
    return sorted(open_ports, key=lambda x: x[0])


def advanced_nmap_scan(target, ports='1-1024', timing='-T4', health_monitor=None, source_ip=None):
    nm = nmap.PortScanner()
    while health_monitor and health_monitor.overloaded:
        time.sleep(2)
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
            lport = nm[target][proto].keys()
            for port in sorted(lport):
                state = nm[target][proto][port]['state']
                service = nm[target][proto][port].get('name', 'unknown')
                version = nm[target][proto][port].get('version', '')
                product = nm[target][proto][port].get('product', '')
                info = f"{service} {product} {version}".strip()
                if state == 'open':
                    results.append((port, info))
    return results


def run_all_scans(target, port_range, use_nmap=False, threads=50, timeout=0.3, nmap_timing='-T4',
                  gui_callback=None, health_monitor=None, scan_profile=None):
    # Removed source_ip param because it's unsupported by caller and scan functions
    resolved_ip = validate_target(target)
    if not resolved_ip:
        err_msg = f"Error: Unable to resolve hostname '{target}'."
        logging.error(err_msg)
        if gui_callback:
            gui_callback(err_msg)
        return []

    try:
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        err_msg = 'Invalid port range. Use format start-end within 1-65535.'
        logging.error(err_msg)
        if gui_callback:
            gui_callback(err_msg)
        return []

    ports = range(start_port, end_port + 1)

    if health_monitor and health_monitor.overloaded:
        if gui_callback:
            gui_callback("[Scan paused] System overloaded, waiting...")
        logging.warning(f"System overloaded, pausing scan for {target}")
        while health_monitor.overloaded:
            time.sleep(2)
        if gui_callback:
            gui_callback("[Scan resumed] System load normalized.")

    results = []
    try:
        if use_nmap:
            results = advanced_nmap_scan(
                resolved_ip, port_range, timing=nmap_timing,
                health_monitor=health_monitor
            )
        else:
            results = scan_ports_multithreaded(
                resolved_ip, ports, max_threads=threads,
                timeout=timeout, health_monitor=health_monitor,
            )
        logging.info(f"Successfully scanned {target} ports {port_range}.")
    except Exception as scan_error:
        err_msg = f"Error scanning {target} ports {port_range}: {scan_error}"
        logging.exception(err_msg)
        if gui_callback:
            gui_callback(err_msg)
        results = []

    try:
        save_results_csv(target, results, scan_profile=scan_profile)
        save_results_json(target, results, scan_profile=scan_profile)  # encrypted save
        save_results_html(target, results, scan_profile=scan_profile)
        logging.info(f"Results saved for {target}")
    except Exception as report_error:
        logging.error(f"Failed to save results for {target}: {report_error}")

    msg = []
    if results:
        msg.append(f"Scan complete for {target} ({resolved_ip})\n")
        for port, service in results:
            msg.append(f"Port {port}: {service}")
        msg.append("\nScan results saved to files.")
    else:
        msg.append(f"No open ports found on {target} ({resolved_ip}) in range {port_range}")
    result_str = "\n".join(msg)
    if gui_callback:
        try:
            gui_callback(result_str)
        except Exception as e:
            logging.error(f"Failed to update GUI: {e}")
    else:
        print(result_str)

    return results
