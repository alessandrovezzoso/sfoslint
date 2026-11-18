# sfoslint

**Unofficial security linter for Sophos Firewall (SFOS) configurations.**

sfoslint reads a configuration export (`Entities.xml`) and flags firewall rules that expose your network to risk, such as remote desktop open to the whole Internet.

> [!WARNING]
> **Status:** early development.
> (see [Roadmap](#roadmap)).

## Why

Firewall rule bases grow over time: temporary rules become permanent, "Any" sources slip in, and nobody remembers why a port is open. sfoslint reviews the rules for you and points out the ones worth a second look.

It works **offline** on an exported file:

- no credentials needed
- no network access to the firewall
- the configuration never leaves your machine

## Current checks

| Severity | Finding |
|---|---|
| **CRITICAL** | Active rule that accepts traffic from anyone on the Internet to a risky service (RDP, SMB, Telnet, FTP, VNC, MSSQL, MySQL, PostgreSQL) |
| **HIGH** | Active rule that accepts traffic from anyone on the Internet |

"Anyone on the Internet" means: the source zones include `WAN` or `Any` (or are not set), the source network is `Any` (not set), and the action is `Accept`.

Each rule is reported once, with its most severe finding.

## Requirements

- Python 3.9 or later
- A Sophos Firewall configuration export (`Entities.xml`)

## Installation

```bash
git clone https://github.com/alessandrovezzoso/sfoslint.git
cd sfoslint
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Getting the configuration

1. On the firewall, go to **Backup & firmware > Import export**.
2. Export the full configuration and download the `.tar` file.
3. Extract it and copy `Entities.xml` into the `private/` folder of this project.

> [!NOTE]
> The `private/` folder and any file named `Entities.xml` or `entities.xml` are excluded by `.gitignore`.

> [!CAUTION]
> `Entities.xml` contains sensitive information about your network, users and VPNs. Never commit it, share it, or upload it anywhere.

## Usage

```bash
python sfoslint.py
```

By default sfoslint analyzes the sample configuration in `examples/entities.example.xml`. To analyze your own export, change the path at the top of `sfoslint.py` to `private/Entities.xml`. Passing the path as a command-line argument is on the roadmap.

## Example output

Running sfoslint on the sample configuration:

```
[CRITICAL] Accesso NAS da fuori: exposes SMB to anyone on the Internet
[CRITICAL] RDP per assistenza: exposes RDP to anyone on the Internet
[HIGH] Webcam da fuori: accepts traffic from anyone on the Internet
[HIGH] Accesso misto: accepts traffic from anyone on the Internet
[HIGH] Regola senza zona: accepts traffic from anyone on the Internet
```

In the terminal, CRITICAL findings are shown in red and HIGH findings in orange.

## Sample configuration

`examples/entities.example.xml` is an **invented** configuration that follows the structure of the Sophos Firewall XML API. It contains both risky and safe rules, and works as a test case: every check has rules that must be flagged and rules that must not.

## Security notes

- XML is parsed with [defusedxml](https://pypi.org/project/defusedxml/), which protects against malicious XML (e.g. XXE attacks).
- Rule names come from the configuration file and are escaped before being printed.

## Known limitations

- Risky services are matched by **name**, not by port. A custom service called "Remote-Desktop" on port 3389 is not detected yet.
- Service groups are not resolved.
- Rule exclusions are ignored.
- Only firewall rules are analyzed (not NAT, VPN or system settings).

## Roadmap

- [x] Flag WAN rules accepting traffic from any source
- [x] Flag risky services exposed to the Internet
- [x] Handle multiple, missing and explicit "Any" source zones
- [ ] Refactor checks into functions, report multiple findings per rule
- [ ] Check: Accept rules without logging
- [ ] Check: disabled rules
- [ ] Check: WAN rules with Any service
- [ ] Take the config file path as a command-line argument
- [ ] Add pytest tests
- [ ] Handle rule exclusions
- [ ] Resolve service groups and match risky services by port

## Disclaimer

sfoslint is an independent project. It is not affiliated with, endorsed by, or supported by Sophos. Sophos and Sophos Firewall are trademarks of their respective owners.

The findings are suggestions for review, not a security guarantee: always evaluate them in the context of your network.

## License

[MIT](LICENSE)
