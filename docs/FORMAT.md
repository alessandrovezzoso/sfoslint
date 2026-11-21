# Entities.xml format notes

This document records what sfoslint knows about the `Entities.xml` export format: which fields it reads, what they mean, and **how sure we are**.

Sophos documents the format only partially. The XML API reference describes each field, but often doesn't say what an omitted field means. This file keeps track of what is documented, what is inferred, and what still needs to be checked on a real export.

## Status legend

| Status | Meaning |
|---|---|
| ✅ Verified | Documented by Sophos, or confirmed on a real export |
| 🔎 Inferred | Deduced from examples, not stated explicitly anywhere |
| ⚠️ Unverified | Assumption used by the code that still needs confirmation |
| ❌ Not handled | Exists in the format, but sfoslint ignores it for now |

## How to update this document

- When you confirm something on a real export, change its status, and add an entry to the [verification log](#verification-log) with the date and the SFOS version.
- When you find a new field or behavior, add it to the right table with its source.
- **Never paste real configuration values here** (IP addresses, names, keys). Describe the structure only.

## Getting the file

**Backup & firmware > Import export** → export the full configuration → extract `Entities.xml` from the downloaded `.tar`. The same format is used by the XML API. ✅

## File structure

```xml
<Configuration APIVersion="2105.1" IPS_CAT_VER="1">
  <IPHost>...</IPHost>
  <FirewallRule>...</FirewallRule>
  ...
</Configuration>
```

The root element `<Configuration>` contains one child element per configuration object (hosts, services, rules, NAT, VPN, users...).

| Attribute | Meaning | Status | Source |
|---|---|---|---|
| `APIVersion` | API version of the firmware that produced the export | ✅ Verified | [1], [2] |
| First two digits of `APIVersion` | Firmware major version (`1702.1` → v17, `1905.1` → v19.5, `2000.2` → v20.0) | 🔎 Inferred | [1], [2], [3] |
| `IPS_CAT_VER` | Not used by sfoslint | — | — |

Exports from different versions are not interchangeable: importing a v19 export into v18.5 can fail. [4]

## Differences between SFOS versions

| Version | Change | Status | Source |
|---|---|---|---|
| v17 and earlier | Firewall rules use the `<SecurityPolicy>` tag | ✅ Verified | [5], [6] |
| v18 and later | Firewall rules use the `<FirewallRule>` tag | ✅ Verified | [5], [7] |
| v22 | Rules have a `<Section>` field (`Central_TOP` / `Local` / `Central_Bottom`) | ✅ Verified | [8] |

sfoslint supports v18 and later. It stops with an error on older exports, and warns when the version can't be read.

## `<FirewallRule>`

### Fields used by sfoslint

| Field | Meaning | Used by | Status | Source |
|---|---|---|---|---|
| `Name` | Rule name | all checks | ✅ Verified | [8] |
| `Status` | `Enable` / `Disable` | exposure, disabled, logging | ✅ Verified | [8] |
| `NetworkPolicy/Action` | `Accept` / `Reject` / `Drop` | exposure, logging | ✅ Verified | [7] |
| `NetworkPolicy/LogTraffic` | `Enable` / `Disable` | logging | ✅ Verified | [7] |
| `NetworkPolicy/SourceZones/Zone` | Source zones, multiple values allowed | exposure | ✅ Verified | [8] |
| `<Zone>Any</Zone>` | "Any" can be written explicitly as a zone | exposure | ✅ Verified | [7], [8] |
| `SourceZones` missing | Rule applies to any source zone | exposure | ✅ Verified | [9] |
| `NetworkPolicy/SourceNetworks/Network` | Source networks, multiple values allowed | exposure | ✅ Verified | [8] |
| `SourceNetworks` missing | Rule applies to any source network | exposure | ✅ Verified | [9] |
| `NetworkPolicy/Services/Service` | Services **or service groups**, multiple values allowed | exposure | ✅ Verified | [8] |
| `Services` missing | Rule applies to every service (any port) | exposure | ⚠️ Unverified | — |

### Fields not handled yet

| Field | Meaning | Status | Source |
|---|---|---|---|
| `PolicyType` | Rule type: `User` / `Network` / `HTTPBased` | ❌ Not handled | [10] |
| `UserPolicy` | Block used by user-based rules instead of `NetworkPolicy` (contains `Action`, `LogTraffic`, `SourceZones`...). **These rules are currently skipped.** | ❌ Not handled | [10] |
| `HTTPBasedPolicy` | Block used by WAF rules | ❌ Not handled | [7] |
| `NetworkPolicy/Exclusions` | Source zones, networks and services the rule does **not** apply to | ❌ Not handled | [8] |
| `NetworkPolicy/DestinationZones/Zone` | Destination zones | ❌ Not handled | [8] |
| `NetworkPolicy/DestinationNetworks/Network` | Destination networks | ❌ Not handled | [8] |
| `Position`, `After`, `Before` | Rule position in the list (needed to detect shadowed rules) | ❌ Not handled | [8], [10] |
| `Section` | Central / local section of the rule list (v22) | ❌ Not handled | [8] |

## Other entities

| Entity | Fields seen | Status | Notes |
|---|---|---|---|
| `IPHost` | `Name`, `IPFamily`, `HostType`, `IPAddress`, `Subnet` | 🔎 Inferred | Seen in examples. Needed to resolve network names into IP addresses. |
| Service objects | — | ⚠️ Unverified | Needed to match risky services by **port** instead of by name. Structure still to be studied. |
| Service groups | — | ⚠️ Unverified | Needed to find risky services inside groups. Structure still to be studied. |

## Open questions

To check on a real export:

- [ ] Does a missing `<Services>` element mean "any service"?
- [ ] Can `Any` be written explicitly as a service or a network?
- [ ] Does the `APIVersion` → firmware version rule hold for every version?
- [ ] How are service objects and service groups defined (protocol, ports)?
- [ ] How are `UserPolicy` rules exported, and do they ever accept traffic from the WAN?

## Verification log

| Date | SFOS version | What was checked | Result |
|---|---|---|---|
| — | — | — | — |

## Sources

1. [Sophos Firewall API: request format and `APIVersion`, with the `"2000.2"` example (v20.0)](https://docs.sophos.com/nsg/sophos-firewall/20.0/api/apiContentPage.html)
2. [Sophos Community: UTM to SFOS migration scripts (`APIVersion="1905.1"` for v19.5)](https://community.sophos.com/sophos-xg-firewall/f/recommended-reads/138675/sophos-firewall-powershell-script-library-for-migrating-sophos-utm-to-sophos-firewall/521151)
3. [Sophos Community: changing HTTPS certificate with the API (`APIVersion="1702.1"`)](https://community.sophos.com/sophos-xg-firewall/f/discussions/118434/changing-https-certificate-with-api)
4. [Sophos Community: export from v19 EAP, import to v18.5.2](https://community.sophos.com/sophos-xg-firewall/sfos-v19-early-access-program/f/discussions/131954/export-from-v19eap-import-to-v18-5-2)
5. [ManageEngine: Sophos XG API troubleshooting (`SecurityPolicy` for v17 and older)](https://pitstop.manageengine.com/portal/en/kb/articles/sophos-xg-api-troubleshoot-dcoument)
6. [Sophos Community: export showing rules as `<SecurityPolicy>`](https://community.sophos.com/sophos-xg-firewall/f/recommended-reads/122450/sophos-firewall-creating-xml-objects-with-notepad-for-mass-import/479591)
7. [Sophos Firewall API v18.5: Add / Edit firewall rule](https://docs.sophos.com/nsg/sophos-firewall/18.5/api/protect/firewall/securitypolicy/operations/Addfirewallrule&Editfirewallrule.html)
8. [Sophos Firewall API v22.0: Add / Edit firewall rule](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/protect/firewall/securitypolicy/operations/Addfirewallrule&Editfirewallrule.html)
9. [Sophos: firewall rules through the XML API ("leaving source zones, networks, and users unset applies the rule to any source")](https://rtadocs.srt.sophos.com/troubleshooting/firewalls/sophos/cli/)
10. [Sophos Firewall API v19.0: Add / Edit firewall rule (`PolicyType`, `UserPolicy`)](https://docs.sophos.com/nsg/sophos-firewall/19.0/api/protect/firewall/securitypolicy/operations/Addfirewallrule&Editfirewallrule.html)
