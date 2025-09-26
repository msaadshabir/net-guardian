from rich.console import Console
from rich.table import Table

def generate_report(devices):
    console = Console()
    console.print("[bold green]🛡️  net-guardian Network Audit Report[/bold green]\n")

    if not devices:
        console.print("[red]No devices found. Check your network connection.[/red]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Hostname", style="magenta")
    table.add_column("Open Ports", style="blue")
    table.add_column("Risk Level", justify="center")

    # Known risky ports
    RISKY_PORTS = {
        21: "FTP (insecure)",
        23: "Telnet (plaintext!)",
        135: "Windows RPC",
        139: "NetBIOS",
        445: "SMB (ransomware risk)",
        3389: "RDP (brute-force target)",
        5900: "VNC (unsecured remote access)"
    }

    for device in devices:
        # Format ports as comma-separated string
        ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "None"
        
        # Risk logic: IoT + risky ports = High
        mac_prefix = device['mac'].replace(':', '')[:6]
        IOT_OUIS = {'B827EB', 'A4C138', 'CC50E3', 'D831CF', 'E06290', 'F0FE6B'}
        is_iot = mac_prefix in IOT_OUIS
        
        risk = "[green]✅ Low[/green]"
        if is_iot:
            risk = "[yellow]⚠️  Medium (IoT)[/yellow]"
        if any(port in RISKY_PORTS for port in device['open_ports']):
            risk = "[red]🚨 High (Risky Service!)[/red]"

        table.add_row(device['ip'], device['mac'], device['hostname'], ports_str, risk)

    console.print(table)
    console.print(f"\n[bold]✅ Total Devices Found: {len(devices)}[/bold]")
    
    # Scan Summary
    console.print("\n[bold]📊 Scan Summary:[/bold]")
    
    # Count devices by risk
    low_count = 0
    medium_count = 0
    high_count = 0
    total_ports = 0
    
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
    
    console.print(f"   Low Risk Devices: {low_count}")
    console.print(f"   Medium Risk Devices: {medium_count}")
    console.print(f"   High Risk Devices: {high_count}")
    console.print(f"   Total Open Ports Detected: {total_ports}")
    
    # Add risk legend
    console.print("\n[bold]Risk Legend:[/bold]")
    console.print("✅ Low: Standard device, no risky ports")
    console.print("⚠️  Medium: IoT device (often unpatched)")
    console.print("🚨 High: Exposed insecure service (e.g., Telnet, SMB)")