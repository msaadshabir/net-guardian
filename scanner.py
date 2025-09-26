import netifaces
from scapy.all import ARP, Ether, srp
import socket

import nmap

def check_open_ports(ip):
    """
    Perform a FAST scan of common ports on a device.
    Returns a list of open port numbers (e.g., [22, 80, 443]).
    """
    try:
        nm = nmap.PortScanner()
        # -F = fast scan (top 100 ports), --open = show only open ports
        nm.scan(ip, arguments='-F --open')
        if ip in nm.all_hosts():
            return sorted([int(port) for port in nm[ip].all_tcp() if nm[ip]['tcp'][port]['state'] == 'open'])
        else:
            return []
    except Exception as e:
        print(f"   ⚠️  Port scan failed for {ip}: {e}")
        return []

def get_local_network():
    """Auto-detect home network (192.168.x.0/24, 10.x.x.0/24, etc.)"""
    for iface in netifaces.interfaces():
        if iface.startswith(('lo', 'utun', 'llw', 'awdl', 'bridge')):
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                             '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                             '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                             '172.30.', '172.31.')):
                network = ".".join(ip.split(".")[:-1]) + ".0/24"
                return network
    raise RuntimeError("No valid private network found. Are you connected to Wi-Fi/Ethernet?")

def scan_network():
    """Discover live devices and scan their open ports"""
    network = get_local_network()
    print(f"🔍 Scanning {network}...")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        print(f"   Scanning ports on {ip}...")  # Optional: show progress
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, UnicodeDecodeError):
            hostname = "Unknown"

        open_ports = check_open_ports(ip)  # ← NEW: scan ports

        devices.append({
            'ip': ip,
            'mac': received.hwsrc.upper(),
            'hostname': hostname,
            'open_ports': open_ports  # ← NEW field
        })
    return devices