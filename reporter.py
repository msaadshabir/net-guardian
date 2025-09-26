from rich.console import Console
from rich.table import Table

def generate_report(devices):
    console = Console()
    console.print("[bold green]🛡️  NetGuardian Network Audit Report[/bold green]\n")

    if not devices:
        console.print("[red]No devices found. Check your network connection.[/red]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Hostname", style="magenta")
    table.add_column("Risk Level", justify="center")

    # Common IoT OUI prefixes (first 3 bytes of MAC)
    IOT_OUIS = {
        'B827EB', 'A4C138', 'CC50E3', 'D831CF', 'E06290', 'F0FE6B',
        'AC0BFB', 'B4E62D', 'C44F33', 'DC4F22'
    }

    for device in devices:
        mac_prefix = device['mac'].replace(':', '')[:6]
        if mac_prefix in IOT_OUIS:
            risk = "[red]⚠️  High (IoT)[/red]"
        else:
            risk = "[green]✅ Low[/green]"
        table.add_row(device['ip'], device['mac'], device['hostname'], risk)

    console.print(table)
    console.print(f"\n[bold]✅ Total Devices Found: {len(devices)}[/bold]")
