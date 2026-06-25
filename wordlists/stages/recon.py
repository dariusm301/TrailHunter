from unittest import result

import nmap
import subprocess

class Recon:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.web_wordlist = None

    def scan_ports(self):
        print(f"Scanning {self.target} for open ports...")
        self.nm.scan(self.target, arguments='-sS -T4 -Pn')
        return self.nm[self.target]

    def scan_pages(self, web_wordlist):
        self.web_wordlist = web_wordlist
        if self.web_wordlist is None:
            raise ValueError("Web wordlist must be set before scanning for pages.")
        print(f"Scanning {self.target} for web pages using gobuster...")
        self.result = subprocess.run(['gobuster', 'dir', '-u', f'http://{self.target}', 
                                 '-w', self.web_wordlist], 
                                 capture_output=True, text=True)
        print("Scan pages completed.")
        return True

    def display_ports(self):
        if self.target not in self.nm.all_hosts():
            print(f"No information found for {self.target}.")
            return
        print(f"Open ports on {self.target}:")
        for proto in self.nm[self.target].all_protocols():
            lport = self.nm[self.target][proto].keys()
            for port in lport:
                state = self.nm[self.target][proto][port]['state']
                print(f"Port {port}/{proto} is {state}")
    
    def display_pages(self):
        print(self.result.stderr)