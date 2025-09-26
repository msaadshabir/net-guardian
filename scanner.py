import netifaces
from scapy.all import ARP, Ether, srp
import socket

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
    """Discover live devices on the local network using ARP"""
    network = get_local_network()
    print(f"🔍 Scanning {network}...")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except (socket.herror, UnicodeDecodeError):
            hostname = "Unknown"
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc.upper(),
            'hostname': hostname
        })
    return devices
