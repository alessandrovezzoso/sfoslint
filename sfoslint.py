from defusedxml.ElementTree import parse
root = parse("examples/entities.example.xml").getroot()

for rule in root.findall("FirewallRule"):
    name = rule.findtext("Name")
    status = rule.findtext("Status")
    action = rule.findtext("NetworkPolicy/Action")
    zone = rule.findtext("NetworkPolicy/SourceZones/Zone")
    source_any = rule.find("NetworkPolicy/SourceNetworks") is None

    if status == "Enable" and zone == "WAN" and source_any and action == "Accept":
        print(f"[ALTA] {name}: accetta traffico da chiunque su Internet")