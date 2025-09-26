# NetGuardian

An automated network health and security auditor built with Python. Scans your local network, identifies devices, and flags potential risks — all from the terminal.

## Features
- Auto-detects your home network (Wi-Fi/Ethernet)
- Discovers live devices using ARP scanning
- Flags IoT devices (common security risk)
- Beautiful terminal dashboard with Rich

## Built With
- Python 3
- Scapy (packet crafting)
- netifaces (network interface detection)
- Rich (terminal UI)
- Nmap (for future port scanning)

## Setup (macOS)
1. brew install python nmap
2. pip3 install -r requirements.txt
3. sudo python3 main.py
