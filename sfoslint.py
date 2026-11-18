from defusedxml.ElementTree import parse
root = parse("examples/entities.example.xml").getroot()

for rule in root.findall("FirewallRule"):
    name = rule.findtext("Name")
    status = rule.findtext("Status")
    print(f"{name} ({status})") 