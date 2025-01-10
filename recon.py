import nmap

# Target IP address
target_ip = "192.168.1.10"

# Create a PortScanner object
nm = nmap.PortScanner()

# Scan for open ports and services
nm.scan(target_ip, arguments="-sV")

# Print scan results
print(f"Target: {target_ip}")
print(f"Host: {nm[target_ip].hostname()}")
print(f"State: {nm[target_ip].state()}")

# Print open ports and services
for port in nm[target_ip]['tcp']:
    print(f"Port: {port} - State: {nm[target_ip]['tcp'][port]['state']} - Service: {nm[target_ip]['tcp'][port]['name']}")
