import nmap
import os

def scan_target(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-O -sV")

    total_ports = len(nm[target_ip]['tcp'])
    scanned_ports = 0

    print(f"Target: {target_ip}")
    print(f"Host: {nm[target_ip].hostname()}")
    print(f"State: {nm[target_ip].state()}")
    print(f"OS: {nm[target_ip]['osmatch'][0]['name']}")

    for port in nm[target_ip]['tcp']:
        scanned_ports += 1
        progress = (scanned_ports / total_ports) * 100
        print(f"\rScanning ports... {progress:.2f}%", end="")
        print(f"\rPort: {port} - State: {nm[target_ip]['tcp'][port]['state']} - Service: {nm[target_ip]['tcp'][port]['name']}", end="")
    print("\nPorts scanning completed.")

    print("\nRetrieving whois information...")
    print(os.popen(f"whois {target_ip}").read())
    print("Whois information retrieved.")

    print("\nRetrieving DNS information...")
    print(os.popen(f"dig {target_ip}").read())
    print("DNS information retrieved.")

    print("\nDiscovering subdomains...")
    print(os.popen(f"sublist3r -d {target_ip}").read())
    print("Subdomain discovery completed.")

    print("\nRetrieving server headers...")
    print(os.popen(f"curl -I {target_ip}").read())
    print("Server headers retrieved.")

    print("\nRetrieving robots.txt...")
    print(os.popen(f"curl {target_ip}/robots.txt").read())
    print("Robots.txt retrieved.")

# Get target IP address from user input
target_ip = input("Enter the target IP address: ")

# Start scanning
scan_target(target_ip)
