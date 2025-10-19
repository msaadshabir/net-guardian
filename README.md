# NetGuardian

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)
![Nmap](https://img.shields.io/badge/requires-nmap-red.svg)

An automated network health and security auditor built with Python. Scans your local network, identifies devices, checks for open ports, and flags potential security risks from the terminal.

## Quick Start

```bash
# Install dependencies
brew install nmap  # macOS
sudo apt install nmap  # Linux

# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run scan
sudo python main.py
```

## Features

- Device discovery via ARP scanning
- Port and service fingerprinting
- Vendor identification and device categorization
- Risk assessment for IoT devices and insecure services
- Anomaly detection with machine learning
- JSON export

## Usage

```bash
# Basic scan
sudo python main.py

# Fast scan (no service fingerprinting)
sudo python main.py --fast

# Export results
sudo python main.py --export

# Skip OS detection or vendor lookup
sudo python main.py --no-os --no-vendor
```

## Configuration

Customize behavior in `config.ini`:

```ini
[SCANNING]
fast_mode = false
os_detection = true

[RISK_ASSESSMENT]
risky_ports = 21,23,135,139,445,3389,5900
```

## Requirements

- Python 3.7+
- Nmap
- Root/administrator privileges

## License

MIT
