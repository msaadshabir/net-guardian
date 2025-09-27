import netifaces
from scapy.all import ARP, Ether, srp
import socket
from mac_vendor_lookup import MacLookup

import nmap

def check_open_ports(ip, fast_mode=False, os_detection=True):
    """
    Perform comprehensive scan with service fingerprinting and optional OS detection.
    Returns a dict with ports info, services, and OS details.
    """
    try:
        nm = nmap.PortScanner()
        
        # Build scan arguments based on options
        args = '-F --open'  # Fast scan, open ports only
        
        if not fast_mode:
            args += ' -sV --version-intensity=3'  # Service detection with lower intensity for speed
            args += ' --script=banner'  # Banner grabbing
        
        if os_detection:
            args += ' -O'  # OS detection
        
        nm.scan(ip, arguments=args)
        
        result = {
            'ports': [],
            'os': 'Unknown',
            'services': {}
        }
        
        if ip in nm.all_hosts():
            # Get OS information
            if os_detection and 'osmatch' in nm[ip] and nm[ip]['osmatch']:
                result['os'] = nm[ip]['osmatch'][0]['name']
            
            # Get port and service information
            for port in nm[ip].all_tcp():
                if nm[ip]['tcp'][port]['state'] == 'open':
                    if fast_mode:
                        # Simple port info for fast mode
                        port_info = {
                            'port': int(port),
                            'service': nm[ip]['tcp'][port]['name'],
                            'version': 'N/A',
                            'product': 'N/A'
                        }
                    else:
                        # Detailed service info
                        port_info = {
                            'port': int(port),
                            'service': nm[ip]['tcp'][port]['name'],
                            'version': nm[ip]['tcp'][port]['version'] or 'Unknown',
                            'product': nm[ip]['tcp'][port]['product'] or 'Unknown'
                        }
                    result['ports'].append(int(port))
                    result['services'][int(port)] = port_info
        
        return result
    except Exception as e:
        print(f"   ⚠️  Port scan failed for {ip}: {e}")
        return {'ports': [], 'os': 'Unknown', 'services': {}}

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

def scan_network(fast_mode=False, skip_os=False, skip_vendor=False):
    """Discover live devices and scan their open ports"""
    network = get_local_network()
    scan_type = "FAST" if fast_mode else "DETAILED"
    os_status = " (OS detection disabled)" if skip_os else ""
    print(f"🔍 Scanning {network} in {scan_type} mode{os_status}...")
    
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    total_devices = len(result)
    print(f"📡 Found {total_devices} devices, scanning ports...")
    
    for i, (sent, received) in enumerate(result, 1):
        ip = received.psrc
        print(f"   [{i}/{total_devices}] Scanning {ip}...")  # Progress indicator
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, UnicodeDecodeError):
            hostname = "Unknown"

        port_info = check_open_ports(ip, fast_mode=fast_mode, os_detection=not skip_os)

        # Get vendor from MAC (quiet operation)
        if skip_vendor:
            vendor = "Unknown"
        else:
            vendor = "Unknown"
            try:
                # Format MAC address properly for lookup
                mac_raw = received.hwsrc
                if isinstance(mac_raw, bytes):
                    mac_raw = mac_raw.decode('utf-8')
                mac_clean = mac_raw.replace(':', '').upper()
                mac_formatted = ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])
                
                mac_lookup = MacLookup()
                vendor = mac_lookup.lookup(mac_formatted)
            except:
                # Silently handle any vendor lookup issues
                pass

        # Categorize device
        category = get_device_category(vendor, port_info['ports'], port_info['services'])

        devices.append({
            'ip': ip,
            'mac': received.hwsrc.upper(),
            'hostname': hostname,
            'open_ports': port_info['ports'],
            'os': port_info['os'],
            'services': port_info['services'],
            'vendor': vendor,
            'category': category
        })
    
    print(f"✅ Completed scanning {len(devices)} devices")
    return devices

def get_device_category(vendor, open_ports, services=None):
    """
    Categorize device based on vendor, open ports, and services.
    Returns: 'router', 'iot', 'server', 'workstation', or 'unknown'
    """
    if services is None:
        services = {}
    
    # Router vendors
    router_vendors = ['cisco', 'tp-link', 'netgear', 'd-link', 'asus', 'linksys', 'ubiquiti', 'mikrotik']
    
    # Check for router services
    router_ports = {80, 443, 53, 67, 68}  # HTTP, DNS, DHCP
    has_router_services = any(port in router_ports for port in open_ports)
    
    # Server indicators
    server_services = ['http', 'https', 'ssh', 'ftp', 'smtp', 'pop3', 'imap', 'rdp', 'vnc']
    has_server_services = any(any(svc in service.get('service', '').lower() for svc in server_services) for service in services.values())
    
    vendor_lower = vendor.lower() if vendor else ""
    
    # Router detection
    if any(rv in vendor_lower for rv in router_vendors) or (has_router_services and len(open_ports) <= 10):
        return 'router'
    
    # Server detection
    if has_server_services or len(open_ports) > 5:
        return 'server'
    
    # Default to workstation
    return 'workstation'