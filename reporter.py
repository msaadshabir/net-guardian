from rich.console import Console
from rich.table import Table

def generate_report(devices, config=None):
    console = Console()
    console.print("[bold green]🛡️  net-guardian Network Audit Report[/bold green]\n")

    if not devices:
        console.print("[red]No devices found. Check your network connection.[/red]")
        return

    # Load risk configuration
    if config:
        risky_ports_list = [int(p.strip()) for p in config.get('RISK_ASSESSMENT', 'risky_ports', fallback='21,23,135,139,445,3389,5900').split(',')]
        iot_ouis_list = [oui.strip() for oui in config.get('RISK_ASSESSMENT', 'iot_ouis', fallback='B827EB,A4C138,CC50E3,D831CF,E06290,F0FE6B').split(',')]
    else:
        risky_ports_list = [21, 23, 135, 139, 445, 3389, 5900]
        iot_ouis_list = ['B827EB', 'A4C138', 'CC50E3', 'D831CF', 'E06290', 'F0FE6B']
    
    # Convert to sets for faster lookup
    RISKY_PORTS = set(risky_ports_list)
    IOT_OUIS = set(iot_ouis_list)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Hostname", style="magenta")
    table.add_column("Vendor", style="cyan")
    table.add_column("OS", style="purple")
    table.add_column("Category", style="blue")
    table.add_column("Services", style="white")
    table.add_column("Risk Level", justify="center")

    for device in devices:
        # Format services with port, service name, and version
        services_info = device.get('services', {})
        if services_info:
            services_str = "\n".join([f"{port}/{info['service']} ({info['product']} {info['version']})" 
                                     for port, info in services_info.items()])
        else:
            services_str = "None"
        
        # Risk logic: IoT + risky ports = High
        mac_prefix = device['mac'].replace(':', '')[:6]
        is_iot = mac_prefix in IOT_OUIS
        
        risk = "[green]✅ Low[/green]"
        if is_iot:
            risk = "[yellow]⚠️  Medium (IoT)[/yellow]"
        if any(port in RISKY_PORTS for port in device['open_ports']):
            risk = "[red]🚨 High (Risky Service!)[/red]"

        vendor = device.get('vendor', 'Unknown')
        category = device.get('category', 'Unknown')
        os_info = device.get('os', 'Unknown')

        table.add_row(device['ip'], device['mac'], device['hostname'], vendor, os_info, category, services_str, risk)

    console.print(table)
    console.print(f"\n[bold]✅ Total Devices Found: {len(devices)}[/bold]")
    
    # Scan Summary
    console.print("\n[bold]📊 Scan Summary:[/bold]")
    
    # Count devices by risk
    low_count = 0
    medium_count = 0
    high_count = 0
    total_ports = 0
    
    # Count devices by category
    category_counts = {}
    
    for device in devices:
        mac_prefix = device['mac'].replace(':', '')[:6]
        is_iot = mac_prefix in IOT_OUIS
        has_risky_port = any(port in RISKY_PORTS for port in device['open_ports'])
        
        if has_risky_port:
            high_count += 1
        elif is_iot:
            medium_count += 1
        else:
            low_count += 1
        
        total_ports += len(device['open_ports'])
        
        category = device.get('category', 'unknown')
        category_counts[category] = category_counts.get(category, 0) + 1
    
    console.print(f"   Low Risk Devices: {low_count}")
    console.print(f"   Medium Risk Devices: {medium_count}")
    console.print(f"   High Risk Devices: {high_count}")
    console.print(f"   Total Open Ports Detected: {total_ports}")
    
    console.print("\n   Device Categories:")
    for cat, count in category_counts.items():
        console.print(f"     {cat.title()}: {count}")
    
    # Add risk legend
    console.print("\n[bold]Risk Legend:[/bold]")
    console.print("✅ Low: Standard device, no risky ports")
    console.print("⚠️  Medium: IoT device (often unpatched)")
    console.print("🚨 High: Exposed insecure service (e.g., Telnet, SMB)")