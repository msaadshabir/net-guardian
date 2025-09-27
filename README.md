# net-guardian

An automated network health and security auditor built with Python. Scans your local network, identifies devices, checks for open ports, and flags potential risks all from the terminal.

## Features

- Auto-detects your home network (Wi-Fi/Ethernet)
- Discovers live devices using ARP scanning
- Scans open ports on discovered devices (top 100 ports)
- Identifies device vendors and categorizes device types
- Performs service fingerprinting and OS detection
- Fast scan mode for quick network overview
- Configurable risk assessment rules
- Detects network anomalies over time
- JSON export for scan results
- Terminal dashboard with Rich

## Built With

- Python 3
- Scapy (packet crafting)
- netifaces (network interface detection)
- Rich (terminal UI)
- Nmap (port scanning & service fingerprinting)
- mac-vendor-lookup (device vendor identification)
- pandas & scikit-learn (anomaly detection)
- configparser (configuration management)

## Setup (macOS)

1. brew install python nmap
2. pip3 install virtualenv
3. python3 -m venv .venv
4. source .venv/bin/activate
5. pip install -r requirements.txt
6. cp config.example.ini config.ini # Optional: customize settings
7. sudo .venv/bin/python main.py

## Usage

```bash
# Full detailed scan (default)
sudo .venv/bin/python main.py

# Fast scan (skips service fingerprinting)
sudo .venv/bin/python main.py --fast

# Skip OS detection for faster scanning
sudo .venv/bin/python main.py --no-os

# Skip vendor lookup (fastest, no device identification)
sudo .venv/bin/python main.py --no-vendor

# Combine options
sudo .venv/bin/python main.py --fast --no-os --no-vendor

# Export results to JSON
sudo .venv/bin/python main.py --export
```
