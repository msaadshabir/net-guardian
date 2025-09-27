# NetGuardian

An automated network health and security auditor built with Python. Scans your local network, identifies devices, checks for open ports, and flags potential security risks from the terminal.

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

## Requirements

- Python 3.7+
- Nmap
- macOS (tested) / Linux / Windows (may require adjustments)

## Installation

### macOS Setup

```bash
# Install system dependencies
brew install python nmap

# Create virtual environment
pip3 install virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Optional: Configure settings
cp config.example.ini config.ini
```

### Linux Setup

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip nmap

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Optional: Configure settings
cp config.example.ini config.ini
```

## Usage

### Basic Scanning

```bash
# Activate virtual environment
source .venv/bin/activate

# Full detailed scan (default)
sudo python main.py

# Fast scan (skips service fingerprinting)
sudo python main.py --fast

# Skip OS detection for faster scanning
sudo python main.py --no-os

# Skip vendor lookup (fastest, no device identification)
sudo python main.py --no-vendor
```

### Advanced Options

```bash
# Combine multiple options
sudo python main.py --fast --no-os --no-vendor

# Export results to JSON file
sudo python main.py --export

# Export with custom scan settings
sudo python main.py --fast --export
```

### Configuration

Edit `config.ini` to customize scanning behavior:

```ini
[SCANNING]
fast_mode = false
os_detection = true
vendor_lookup = true

[RISK_ASSESSMENT]
risky_ports = 21,23,135,139,445,3389,5900
iot_ouis = B827EB,A4C138,CC50E3,D831CF,E06290,F0FE6B

[ANOMALY_DETECTION]
contamination = 0.1
model_file = anomaly_model.pkl
```

## Dependencies

- **Python 3.7+**
- **Scapy** - Network packet manipulation
- **netifaces** - Network interface detection
- **Rich** - Terminal UI and formatting
- **Nmap** - Port scanning and service detection
- **mac-vendor-lookup** - Device vendor identification
- **pandas & scikit-learn** - Anomaly detection
- **configparser** - Configuration file parsing (built-in)

## Output

The tool provides a comprehensive terminal-based report including:

- Device inventory with IP, MAC, hostname, and vendor
- Operating system detection
- Open ports and service identification
- Security risk assessment
- Network anomaly detection
- Scan summary statistics

Results can be exported to JSON for further analysis or integration with other tools.

## Security Notes

- Requires root/administrator privileges for raw packet operations
- Network scanning may be detected by security monitoring systems
- Use responsibly and only on networks you own or have permission to scan
- Exported scan data contains network topology information
