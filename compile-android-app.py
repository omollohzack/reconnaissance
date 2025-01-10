# Android app code (in Python)

import android
import nmap
import os

# Initialize Android app
droid = android.Android()

# Function to scan target IP
def scan_target(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-O -sV")

    output = f"Target: {target_ip}\n"
    output += f"Host: {nm[target_ip].hostname()}\n"
    output += f"State: {nm[target_ip].state()}\n"
    output += f"OS: {nm[target_ip]['osmatch'][0]['name']}\n\n"

    for port in nm[target_ip]['tcp']:
        output += f"Port: {port} - State: {nm[target_ip]['tcp'][port]['state']} - Service: {nm[target_ip]['tcp'][port]['name']}\n"

    output += "\nWhois Information:\n"
    output += os.popen(f"whois {target_ip}").read()

    output += "\nDNS Information:\n"
    output += os.popen(f"dig {target_ip}").read()

    output += "\nSubdomains:\n"
    output += os.popen(f"sublist3r -d {target_ip}").read()

    output += "\nServer Headers:\n"
    output += os.popen(f"curl -I {target_ip}").read()

    output += "\nRobots.txt:\n"
    output += os.popen(f"curl {target_ip}/robots.txt").read()

    return output

# Main function
def main():
    # Prompt user for target IP
    target_ip = droid.dialogGetInput("Target IP", "Enter the target IP address:").result

    # Start scanning
    droid.dialogCreateAlert("Scanning...")
    droid.dialogShow()
    output = scan_target(target_ip)
    droid.dialogDismiss()

    # Display scan results
    droid.dialogCreateAlert("Scan Results", output)
    droid.dialogShow()

# Start the app
main()
