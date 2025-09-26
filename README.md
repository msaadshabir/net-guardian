# net-guardian

An automated network health and security auditor built with Python. Scans your local network, identifies devices, checks for open ports, and flags potential risks all from the terminal.

## Features

- Auto-detects your home network (Wi-Fi/Ethernet)
- Discovers live devices using ARP scanning
- Scans open ports on discovered devices (top 100 ports)
- Flags IoT devices and insecure services (common security risks)
- Beautiful terminal dashboard with Rich

## Built With

- Python 3
- Scapy (packet crafting)
- netifaces (network interface detection)
- Rich (terminal UI)
- Nmap (port scanning)

## Setup (macOS)

1. brew install python nmap
2. pip3 install -r requirements.txt
3. sudo python3 main.py
