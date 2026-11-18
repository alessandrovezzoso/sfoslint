"""sfoslint - security linter for Sophos Firewall (SFOS) configurations.

Reads an Entities.xml export and flags risky firewall rules.
"""

# defusedxml instead of the standard library because it blocks malicious XML
from defusedxml.ElementTree import parse
#
from rich.console import Console
from rich.markup import escape

console = Console()

# Services that should never be reachable from the Internet.
RISKY_SERVICES = {
    "RDP": 3389,
    "SMB": 445,
    "Telnet": 23,
    "FTP": 21,
    "VNC": 5900,
    "MSSQL": 1433,
    "MySQL": 3306,
    "PostgreSQL": 5432,
}

root = parse("examples/entities.example.xml").getroot()
#root = parse("private/Entities.xml").getroot()

for rule in root.findall("FirewallRule"):
    name = rule.findtext("Name")
    status = rule.findtext("Status")
    action = rule.findtext("NetworkPolicy/Action")
    # TODO: a rule can have several source zones; only the first one is checked
    zone = rule.findtext("NetworkPolicy/SourceZones/Zone")
    # In SFOS a missing <SourceNetworks> element means the source is "Any"
    source_any = rule.find("NetworkPolicy/SourceNetworks") is None

    # Collect every risky service
    risky_services = []
    for s in rule.findall("NetworkPolicy/Services/Service"):
        if s.text in RISKY_SERVICES:
            risky_services.append(s.text)

    # Active rule that lets anyone on the Internet in
    exposed = status == "Enable" and zone == "WAN" and source_any and action == "Accept"

    # Report each rule only once, with its most severe finding
    if exposed and risky_services:
        risky_services_text = ", ".join(risky_services)
        console.print(f"[bold red][CRITICAL][/] {escape(name)}: exposes {risky_services_text} to anyone on the Internet")
    elif exposed:
        console.print(f"[bold orange1][HIGH][/] {escape(name)}: accepts traffic from anyone on the Internet")