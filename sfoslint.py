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
from rich import box

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
    "MEDIUM": "bold yellow",
    "INFO": "bold cyan",
}

# Before SFOS v18, firewall rules used a different format (<SecurityPolicy>)
MIN_SUPPORTED_MAJOR = 18

SAMPLE_CONFIG = "examples/entities.example.xml"


# --- Input -------------------------------------------------------------------------------------------------------

def get_config_path():
    """Return the file passed on the command line, or the sample config by default."""
    if len(sys.argv) > 1:
        return sys.argv[1]

    console.print(f"[dim]No file given: analyzing the sample configuration ({SAMPLE_CONFIG}).[/]")
    console.print("[dim]Usage: python sfoslint.py <path/to/Entities.xml>[/]")
    return SAMPLE_CONFIG


def load_rules(path):
    """Parse the export and return (api_version, rules). Exit if it can't be analyzed."""
    root = parse(path).getroot()
    api_version = root.get("APIVersion", "unknown")

    # APIVersion starts with the firmware major version: "1905.1" is SFOS 19.5
    try:
        major = int(api_version[:2])
    except ValueError:
        major = None

    # Stop only when we know the format is unsupported; otherwise warn and go on
    if major is None:
        console.print(f"[yellow]WARNING: unknown API version ({escape(api_version)}), results may be incomplete.[/]")
    elif major < MIN_SUPPORTED_MAJOR:
        console.print(f"[bold red]ERROR: this export comes from SFOS v{major}, which uses an older format. "
                    f"sfoslint supports SFOS v{MIN_SUPPORTED_MAJOR} and later.[/]")
        sys.exit(1)

    rules = root.findall("FirewallRule")

    # Some SFOS versions export rules under a different tag (e.g. <SecurityPolicy>).
    # If nothing is found, stop here: an empty report must never look like a clean one.
    if not rules:
        console.print("[yellow]WARNING: no firewall rules found. Is this an Entities.xml export?[/]")
        sys.exit(1)

    return api_version, rules


def read_rules(rule):
    """Extract from a <FirewallRule> element the fields the checks need."""
    zones = [z.text for z in rule.findall("NetworkPolicy/SourceZones/Zone")]
    # Sophos docs: unset source zones apply the rule to any source.
    # "Any" can also be written explicitly as a zone.
    zones_any = rule.find("NetworkPolicy/SourceZones") is None or "Any" in zones

    return {
        "name": rule.findtext("Name"),
        "status": rule.findtext("Status"),
        "action": rule.findtext("NetworkPolicy/Action"),
        "from_wan": "WAN" in zones or zones_any,
        # In SFOS a missing <SourceNetworks> element means the source is "Any"
        "source_any": rule.find("NetworkPolicy/SourceNetworks") is None,
        "services": [s.text for s in rule.findall("NetworkPolicy/Services/Service")],
        "log": rule.findtext("NetworkPolicy/LogTraffic"),
    }


# --- Checks ------------------------------------------------------------------------------------------------------
# Each check receives a rule (the dict from read_rule) and returns a list of findings. 
# A finding is a tuple: (severity, rule name, message). An empty list means "nothing to report".

def check_exposure(r):
    """Active rules that let anyone on the Internet in."""
    exposed = r["status"] == "Enable" and r["from_wan"] and r["source_any"] and r["action"] == "Accept"
    if not exposed:
        return[]

    # Keep only the most severe exposure finding for each rule
    risky_services = [s for s in r["services"] if s in RISKY_SERVICES]
    if risky_services:
        risky_services_text = ", ".join(risky_services)
        return [("CRITICAL", r["name"], f"exposes {risky_services_text} to anyone on the Internet")]
    return [("HIGH", r["name"], "accepts traffic from anyone on the Internet")]


def check_disabled(r):
    """Disabled rules: harmless today, but can be re-enabled by mistake and make the rule base harder to review."""
    if r["status"] == "Disable":
        return [("INFO", r["name"], "rule is disabled, consider deleting it")]
    return []


def check_logging(r):
    """Active rules that accept traffic without logging it: nobody can see what passes."""
    if r["status"] == "Enable" and r["action"] == "Accept" and r["log"] == "Disable":
        return [("MEDIUM", r["name"], "accepts traffic without logging it")]
    return []


# Every check that runs on each rule. To add a check: write the function, add it here.
CHECKS = [
    check_exposure,
    check_disabled,
    check_logging,
]


def analyze(rules):
    """Run every check on every rule and return all the findings."""
    findings = []
    for rule in rules:
        r = read_rules(rule)
        for check in CHECKS:
            findings.extend(check(r))
    return findings


# --- Output ------------------------------------------------------------------------------------------------------

def print_report(path, api_version, rule_count, findings):
    """Print the header, the findings table sorted by severity and a summary."""
    # Header: which file was analyzed and how many rules were checked
    console.print(Panel.fit(
        f"[bold]sfoslint[/] · analyzing [cyan]{escape(path)}[/] · "
        f"SFOS API {escape(api_version)} · {rule_count} rules checked",
        border_style="dim",
    ))

    if not findings:
        console.print("[bold green]No issues found.[/]")
        return

    table = Table(header_style="bold", border_style="dim", box=box.ROUNDED)
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


# --- Main --------------------------------------------------------------------------------------------------------

def main():
    path = get_config_path()
    api_version, rules = load_rules(path)
    findings = analyze(rules)
    print_report(path, api_version, len(rules), findings)


# Run main() only when the file is executed directly, not when it's imported
# (for example by the tests)
if __name__ == "__main__":
    main()