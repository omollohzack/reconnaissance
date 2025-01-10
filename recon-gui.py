import tkinter as tk
import nmap
import os

def scan_target():
    target_ip = entry_ip.get()

    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-O -sV")

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Target: {target_ip}\n")
    output_text.insert(tk.END, f"Host: {nm[target_ip].hostname()}\n")
    output_text.insert(tk.END, f"State: {nm[target_ip].state()}\n")
    output_text.insert(tk.END, f"OS: {nm[target_ip]['osmatch'][0]['name']}\n\n")

    for port in nm[target_ip]['tcp']:
        output_text.insert(tk.END, f"Port: {port} - State: {nm[target_ip]['tcp'][port]['state']} - Service: {nm[target_ip]['tcp'][port]['name']}\n")

    whois_output = os.popen(f"whois {target_ip}").read()
    output_text.insert(tk.END, "\nWhois Information:\n")
    output_text.insert(tk.END, whois_output)

    dig_output = os.popen(f"dig {target_ip}").read()
    output_text.insert(tk.END, "\nDNS Information:\n")
    output_text.insert(tk.END, dig_output)

    sublist3r_output = os.popen(f"sublist3r -d {target_ip}").read()
    output_text.insert(tk.END, "\nSubdomains:\n")
    output_text.insert(tk.END, sublist3r_output)

    curl_output = os.popen(f"curl -I {target_ip}").read()
    output_text.insert(tk.END, "\nServer Headers:\n")
    output_text.insert(tk.END, curl_output)

    robots_output = os.popen(f"curl {target_ip}/robots.txt").read()
    output_text.insert(tk.END, "\nRobots.txt:\n")
    output_text.insert(tk.END, robots_output)

root = tk.Tk()
root.title("Target Scanner")

label_ip = tk.Label(root, text="Target IP:")
label_ip.pack()

entry_ip = tk.Entry(root)
entry_ip.pack()

button_scan = tk.Button(root, text="Scan", command=scan_target)
button_scan.pack()

output_text = tk.Text(root, height=20, width=50)
output_text.pack()

root.mainloop()
