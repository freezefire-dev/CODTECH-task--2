import socket
import requests

# Function to scan open ports
def scan_ports(target, ports):
    print(f"Scanning ports on {target}...")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to check for outdated software (simple example using HTTP headers)
def check_outdated_software(url):
    print(f"Checking for outdated software on {url}...")
    try:
        response = requests.get(url)
        headers = response.headers
        if 'Server' in headers:
            server_info = headers['Server']
            # Basic check for outdated software (this should be expanded with a real database of versions)
            if "Apache/2.4.1" in server_info:
                return "Outdated Apache version detected"
        return "Software seems up-to-date"
    except requests.RequestException as e:
        return f"Error checking software: {e}"

# Function to check for misconfigurations (simple example using HTTP headers)
def check_misconfigurations(url):
    print(f"Checking for misconfigurations on {url}...")
    try:
        response = requests.get(url)
        headers = response.headers
        misconfigurations = []
        if 'X-Frame-Options' not in headers:
            misconfigurations.append("X-Frame-Options header missing")
        if 'X-XSS-Protection' not in headers:
            misconfigurations.append("X-XSS-Protection header missing")
        return misconfigurations
    except requests.RequestException as e:
        return [f"Error checking misconfigurations: {e}"]

# Main function
def vulnerability_scan(target, ports, url):
    open_ports = scan_ports(target, ports)
    software_status = check_outdated_software(url)
    misconfigurations = check_misconfigurations(url)

    print("\nScan Results:")
    print(f"Open Ports: {open_ports}")
    print(f"Software Status: {software_status}")
    print(f"Misconfigurations: {misconfigurations}")

# Example usage
target_ip = "192.168.1.1"
target_ports = [22, 80, 443]
target_url = "http://example.com"

vulnerability_scan(target_ip, target_ports, target_url)
