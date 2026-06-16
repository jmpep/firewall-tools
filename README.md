# Firewall Policy Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Multi-vendor toolkit (Checkpoint, Palo Alto, Fortinet) to convert, fetch, and search firewall policies with a Tkinter GUI and CLI converter.

```
firewall-tools/
├── examples/                      # example policies & CSVs
├── outputs/                       # saved policies & CSVs (auto-created)
├── .gitignore
├── LICENSE                        # MIT
├── README.md                      # root docs
├── checkpoint_toolkit/
│   ├── fetch_policy.py            # multi-vendor API fetcher (paginated)
│   ├── search_gui.py              # Tkinter GUI with multi-language
│   ├── utils.py                   # settings persistence + logging
│   ├── lang.py                    # translations (EN/FR/DE/IT/SK)
│   ├── images/                    # flag PNGs (gb, fr, de, it, sk)
│   ├── JMPEP-logo.png
│   ├── PROMPT.md                  # project prompt
│   └── settings.yaml              # persisted settings (auto-created)
├── firewall-import/
│   ├── convert_checkpoint.py      # latest converter
│   └── history/                   # archived versions
```

## Quick start

```bash
# CSV conversion (latest version) — prompts for save path
python firewall-import\convert_checkpoint.py examples\example_checkpoint_policy.json "rule-number,status,name,source,action"

# NAT rules
python firewall-import\convert_checkpoint.py --nat examples\example_checkpoint_policy.json "rule-number,name,original-source,translated-source"

# Browse GUI (any vendor JSON or Checkpoint JSON)
python checkpoint_toolkit\search_gui.py examples\example_checkpoint_policy.json

# Download policy from live Checkpoint server
python checkpoint_toolkit\fetch_policy.py --server 192.168.1.1 --username admin
```

## What is NOT imported per vendor

The fetcher intentionally skips API endpoints and object types not needed for the search GUI's core use case (policy rule browsing). Below is the full gap list.

### Checkpoint — skipped

| API endpoint / object type | Reason skipped |
|---|---|
| `show-threat-exception-rulebase` | Threat exception rules; only the main threat-rulebase is fetched |
| `show-https-inspection-layer` (with uid) | Only the global HTTPS rulebase is fetched, not per-layer |
| `show-service-groups-*` (tcp/udp/icmp/other) | Service-group members are resolved inline by the Checkpoint API when `details-level=full` is used on rules |
| `show-security-zones` | Zone information is embedded in rule entries |
| `show-time-groups` | Time groups; individual `<time>` entries are sufficient for rule lookup |
| `show-dns-domains`, `show-opsec-applications`, `show-trusted-clients` | Rarely referenced in access rules |
| `show-simple-gateways`, `show-simple-clusters`, `show-checkpoint-hosts` | Topology objects not used in rule search |
| `show-access-roles`, `show-data-center-objects` | Access-role / data-center objects are uncommon |
| `show-*` (all remaining `show-*` endpoints ~40+) | Not referenced by access / HTTPS / threat rule fields |

### Palo Alto — skipped

| API endpoint / XPath | Reason skipped |
|---|---|
| `/application` (predefined + custom apps) | Hundreds of built-in apps; rules reference them by name, no object detail needed |
| Security profiles (antivirus, spyware, vulnerability, url-filtering, file-blocking, data-filtering, wildfire-analysis) | Rule search only needs the profile name (already extracted from `profile-setting/group`) |
| `/log-settings/profiles` | Log forwarding profiles; name is extracted from `log-setting` on each rule |
| `/authentication-profile` | Not referenced in security/NAT rules |
| `/hip-object`, `/hip-profile` | PAN-OS 10.0+ host-integrity checks; rarely used |
| `/dynamic-user-group` | User-group filters; group names already resolved inline |
| `/region` | Geolocation regions; not used in standard rule search |
| `/predefined` (all predefined objects) | Read-only system objects |
| Individual users (`/local-user-database-user`) | User names referenced in rules are extracted from `source-user` |
| Rule audit comments & hit counts | Operational state, not configuration |

### Fortinet — skipped

| API endpoint | Reason skipped |
|---|---|
| `GET /api/v2/cmdb/firewall.interface/` | Interface config; zone/interface names are extracted inline from rules |
| `GET /api/v2/cmdb/firewall/security-policy` | NGFW security policies (FortiOS 7.x); not fetched |
| `GET /api/v2/cmdb/system/` (all system endpoints) | System configuration not relevant to policy search |
| `GET /api/v2/cmdb/user/` (local, ldap, radius, etc.) | User/group names are extracted from `users` field in policies |
| Application control, web filter, ips, ssl-ssh inspection profiles | Profile names are extracted inline; full config not needed |

## Documentation

See `checkpoint_toolkit/PROMPT.md` for full feature docs, design decisions, and version history.

## License

[MIT](LICENSE) — feel free to use, modify, and distribute.

CRLF should be replaced by LF the next time Git touches it
