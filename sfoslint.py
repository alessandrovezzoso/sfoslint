"""sfoslint - security linter for Sophos Firewall (SFOS) configurations.

Reads an Entities.xml export and flags risky firewall rules.
"""

import sys

# defusedxml instead of the standard library: it blocks malicious XML (e.g. XXE attacks)
from defusedxml.ElementTree import parse
# rich: colored terminal output, tables and panels
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

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

# Severities from the most to the least serious, with their display style.
# The order matters: findings are reported in this order.
SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "INFO": "bold cyan",
}

# Use the file passed on the command line, or the sample config by default
if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    path = "examples/entities.example.xml"
    console.print(f"[dim]No file given: analyzing the sample configuration ({path}).[/]")
    console.print("[dim]Usage: python sfoslint.py <path/to/Entities.xml>[/]")

root = parse(path).getroot()
rules = root.findall("FirewallRule")

# Some SFOS versions export rules under a different tag (e.g. <SecurityPolicy>).
# If nothing is found, stop here: an empty report must never look like a clean one.
if not rules:
    console.print("[yellow]WARNING: no firewall rules found. Is this an Entities.xml export?[/]")
    sys.exit(1)

# Each finding is a tuple: (severity, rule name, message)
findings = []

# Check every firewall rule
for rule in rules:
    name = rule.findtext("Name")
    status = rule.findtext("Status")
    action = rule.findtext("NetworkPolicy/Action")
    zones = [z.text for z in rule.findall("NetworkPolicy/SourceZones/Zone")]
    # Sophos docs: unset source zones apply the rule to any source.
    # "Any" can also be written explicitly as a zone.
    zones_any = rule.find("NetworkPolicy/SourceZones") is None or "Any" in zones
    from_wan = "WAN" in zones or zones_any
    # In SFOS a missing <SourceNetworks> element means the source is "Any"
    source_any = rule.find("NetworkPolicy/SourceNetworks") is None

    # Collect every risky service
    risky_services = []
    for s in rule.findall("NetworkPolicy/Services/Service"):
        if s.text in RISKY_SERVICES:
            risky_services.append(s.text)

    # Active rule that lets anyone on the Internet in
    exposed = status == "Enable" and from_wan and source_any and action == "Accept"

    # Keep only the most severe exposure finding for each rule
    if exposed and risky_services:
        risky_services_text = ", ".join(risky_services)
        findings.append(("CRITICAL", name, f"exposes {risky_services_text} to anyone on the Internet"))
    elif exposed:
        findings.append(("HIGH", name, "accepts traffic from anyone on the Internet"))

    # Disabled rules are harmless today, but can be re-enabled by mistake
    # and make the rule base harder to review
    if status == "Disable":
        findings.append(("INFO", name, "rule is disabled, consider deleting it"))

# Header: which file was analyzed and how many rules were checked
console.print(Panel.fit(
    f"[bold]sfoslint[/] · analyzing [cyan]{escape(path)}[/] · {len(rules)} rules checked",
    border_style="dim",
))

if not findings:
    console.print("[bold green]No issues found.[/]")
    sys.exit(0)

table = Table(header_style="bold", border_style="dim")
table.add_column("Severity")
table.add_column("Rule", style="bold")
table.add_column("Finding")

# Add the rows grouped by severity, from the most serious, and count them
summary = []
for severity, style in SEVERITY_STYLES.items():
    count = 0
    for finding_severity, rule_name, message in findings:
        if finding_severity == severity:
            table.add_row(f"[{style}]{severity}[/]", escape(rule_name), message)
            count += 1
    if count > 0:
        summary.append(f"[{style}]{count} {severity.lower()}[/]")

console.print(table)
console.print(f"[bold]{len(findings)} findings:[/] " + " · ".join(summary))
