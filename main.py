#!/usr/bin/env python3
"""
net-guardian: Automated Network Health & Security Auditor
Run with: sudo python3 main.py
"""

from scanner import scan_network
from reporter import generate_report

if __name__ == "__main__":
    try:
        devices = scan_network()
        generate_report(devices)
    except PermissionError:
        print("❌ Permission denied. Run with 'sudo':")
        print("   sudo python3 main.py")
    except Exception as e:
        print(f"❌ Error: {e}")
