import nmap
import os

# Get target IP address from user input
target_ip = input("Enter the target IP address: ")

# Create a PortScanner object
nm = nmap.PortScanner()

# Scan for open ports and services
nm.scan(target_ip, arguments="-O -sV")

# Print scan results
print(f"Target: {target_ip}")
print(f"Host: {nm[target_ip].hostname()}")
print(f"State: {nm[target_ip].state()}")
print(f"OS: {nm[target_ip]['osmatch'][0]['name']}")

# Print open ports and services
for port in nm[target_ip]['tcp']:
    print(f"Port: {port} - State: {nm[target_ip]['tcp'][port]['state']} - Service: {nm[target_ip]['tcp'][port]['name']}")

# Run whois command
whois_output = os.popen(f"whois {target_ip}").read()
print("\nWhois Information:")
print(whois_output)

# Run dig command
dig_output = os.popen(f"dig {target_ip}").read()
print("\nDNS Information:")
print(dig_output)

# Run sublist3r command
sublist3r_output = os.popen(f"sublist3r -d {target_ip}").read()
print("\nSubdomains:")
print(sublist3r_output)

# Run curl command to get server headers
curl_output = os.popen(f"curl -I {target_ip}").read()
print("\nServer Headers:")
print(curl_output)

# Check robots.txt
robots_output = os.popen(f"curl {target_ip}/robots.txt").read()
print("\nRobots.txt:")
print(robots_output)
