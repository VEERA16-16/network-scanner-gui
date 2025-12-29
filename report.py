import csv
import json
from datetime import datetime
import xml.etree.ElementTree as ET
from encryption_utils import save_results_json_encrypted

def save_results_csv(target, results, source_ip=None, scan_profile=None):
    filename = f"{target}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        # Write metadata header
        writer.writerow(["Scan Report"])
        writer.writerow([f"Target: {target}"])
        if source_ip:
            writer.writerow([f"Source IP: {source_ip}"])
        if scan_profile:
            writer.writerow([f"Scan Profile: {scan_profile}"])
        writer.writerow([f"Timestamp: {datetime.now().isoformat()}"])
        writer.writerow([])  # Empty line
        # Write column headers
        writer.writerow(["Port", "Service"])
        # Write port results
        for port, service in results:
            writer.writerow([port, service])

def save_results_json(target, results, source_ip=None, scan_profile=None):
    filename = f"{target}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.enc"
    report = {
        "target": target,
        "source_ip": source_ip,
        "scan_profile": scan_profile,
        "timestamp": datetime.now().isoformat(),
        "results": [{"port": port, "service": service} for port, service in results]
    }
    save_results_json_encrypted(filename, report)
    print(f"Encrypted JSON scan results saved to {filename}")

def save_results_html(target, results, source_ip=None, scan_profile=None):
    filename = f"{target}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, mode='w', encoding='utf-8') as html_file:
        html_file.write(f"<html><head><title>Scan Report for {target}</title></head><body>")
        html_file.write(f"<h1>Scan Report</h1>")
        html_file.write(f"<p><strong>Target:</strong> {target}</p>")
        if source_ip:
            html_file.write(f"<p><strong>Source IP:</strong> {source_ip}</p>")
        if scan_profile:
            html_file.write(f"<p><strong>Scan Profile:</strong> {scan_profile}</p>")
        html_file.write(f"<p><strong>Timestamp:</strong> {datetime.now().isoformat()}</p>")
        html_file.write("<table border='1'><tr><th>Port</th><th>Service</th></tr>")
        for port, service in results:
            html_file.write(f"<tr><td>{port}</td><td>{service}</td></tr>")
        html_file.write("</table></body></html>")

def save_results_xml(target, results, source_ip=None, scan_profile=None):
    root = ET.Element("ScanResults")
    ET.SubElement(root, "Target").text = target
    if source_ip:
        ET.SubElement(root, "SourceIP").text = source_ip
    if scan_profile:
        ET.SubElement(root, "ScanProfile").text = scan_profile

    ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
    ports_elem = ET.SubElement(root, "OpenPorts")
    for port, service in results:
        port_elem = ET.SubElement(ports_elem, "Port")
        ET.SubElement(port_elem, "Number").text = str(port)
        ET.SubElement(port_elem, "Service").text = service

    tree = ET.ElementTree(root)
    filename = f"{target}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    tree.write(filename, encoding='utf-8', xml_declaration=True)
