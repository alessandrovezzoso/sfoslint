from defusedxml.ElementTree import parse

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
    # Ottieni i dati dal file
    name = rule.findtext("Name")
    status = rule.findtext("Status")
    action = rule.findtext("NetworkPolicy/Action")
    zone = rule.findtext("NetworkPolicy/SourceZones/Zone")
    source_any = rule.find("NetworkPolicy/SourceNetworks") is None

    risky_services = []
    for s in rule.findall("NetworkPolicy/Services/Service"):
        if s.text in RISKY_SERVICES:
            risky_services.append(s.text)

    # Decide se una regola e' rischiosa
    exposed = status == "Enable" and zone == "WAN" and source_any and action == "Accept"
    if exposed and risky_services:
        risky_service_text = ", ".join(risky_services)
        print(f"[CRITICO] {name}: espone {risky_service_text} a chiunque su Internet")
    elif exposed:
        print(f"[ALTO] {name}: accetta traffico da chiunque su Internet")