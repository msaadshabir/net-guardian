#!/usr/bin/env python3
"""
net-guardian: Automated Network Health & Security Auditor
Run with: sudo python3 main.py [--fast] [--no-os] [--no-vendor] [--export]
"""

from anomaly_detector import NetworkAnomalyDetector
import sys
import os
import configparser

from scanner import scan_network
from reporter import generate_report

def load_config():
    """Load configuration from config.ini file"""
    config = configparser.ConfigParser()
    config_path = 'config.ini'
    
    if os.path.exists(config_path):
        config.read(config_path)
    else:
        # Create default config if it doesn't exist
        config.add_section('SCANNING')
        config.set('SCANNING', 'fast_mode', 'false')
        config.set('SCANNING', 'os_detection', 'true')
        config.set('SCANNING', 'vendor_lookup', 'true')
        
        config.add_section('RISK_ASSESSMENT')
        config.set('RISK_ASSESSMENT', 'risky_ports', '21,23,135,139,445,3389,5900')
        config.set('RISK_ASSESSMENT', 'iot_ouis', 'B827EB,A4C138,CC50E3,D831CF,E06290,F0FE6B')
        
        config.add_section('ANOMALY_DETECTION')
        config.set('ANOMALY_DETECTION', 'contamination', '0.1')
        config.set('ANOMALY_DETECTION', 'model_file', 'anomaly_model.pkl')
    
    return config

if __name__ == "__main__":
    # Load configuration
    config = load_config()
    
    # Parse command line arguments (override config)
    fast_mode = '--fast' in sys.argv or config.getboolean('SCANNING', 'fast_mode', fallback=False)
    skip_os = '--no-os' in sys.argv or not config.getboolean('SCANNING', 'os_detection', fallback=True)
    skip_vendor = '--no-vendor' in sys.argv or not config.getboolean('SCANNING', 'vendor_lookup', fallback=True)
    
    try:
        devices = scan_network(fast_mode=fast_mode, skip_os=skip_os, skip_vendor=skip_vendor)
        
        # Anomaly detection
        detector = NetworkAnomalyDetector()
        
        if not detector.is_trained:
            # First run: train the model
            detector.train(devices)
            print("Initialized anomaly detection. Run again after collecting more data for best results!")
        else:
            # Later runs: detect anomalies
            anomalies = detector.find_anomalies(devices)
            if anomalies:
                print(f"\n🚨 ANOMALY ALERT! Check these devices: {', '.join(anomalies)}")
            else:
                print("\n✅ No anomalies detected.")
        
        generate_report(devices, config)
        
        # Optional: Export results to JSON
        if '--export' in sys.argv:
            import json
            from datetime import datetime
            
            export_data = {
                'scan_time': datetime.now().isoformat(),
                'scan_config': {
                    'fast_mode': fast_mode,
                    'skip_os': skip_os,
                    'skip_vendor': skip_vendor
                },
                'devices': devices
            }
            
            with open('scan_results.json', 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print("📄 Results exported to scan_results.json")
    except PermissionError:
        print("❌ Permission denied. Run with 'sudo':")
        print("   sudo python3 main.py")
    except Exception as e:
        print(f"❌ Error: {e}")
