# Checkpoint Firewall Policy Toolkit

Tools to export, convert, and search Checkpoint firewall policies.

## Components

| Tool | Description |
|---|---|
| `../firewall-import/convert_checkpoint.py` | Convert JSON policy → CSV with field selection, split modes, NAT (older versions in `history/`) |
| `fetch_policy.py` | Fetch live policy from Checkpoint Management API → JSON (pagination for 5000+ objects) |
| `search_gui.py` | Tkinter GUI to browse and search exported JSON policies with export |

## Quick start

```bash
# 1. Fetch a live policy (or use the sample checkpoint_policy.json)
python fetch_policy.py --server 192.168.1.1 --username admin --output my_policy.json

# 2. Convert to CSV (latest version)
python ..\firewall-import\convert_checkpoint.py my_policy.json "rule-number,status,name,source,source-ips,destination,destination-ips,service,service-ports,action"

# 3. Browse in GUI
python search_gui.py my_policy.json
```

## Conversion usage

```bash
python ..\firewall-import\convert_checkpoint.py [--split] [--split-groups] [--nat] <policy.json> "field1,field2,..."
```

Older versions are kept in `..\firewall-import\history\`. Run them the same way
(e.g. `python ..\firewall-import\history\convert_checkpoint_v4.py ...`).

### Available fields

**Access rules:**
```
rule-number    name           rule-type      policy-name    status
enabled        source         source-ips     destination    destination-ips
service        service-ports  action         track          comments
content        inline-layer   time           user           install-on
threat-name    threat-category site-category certificate    uid
hits           creation-time  last-modified  _layer
```

**NAT rules (--nat):**
```
rule-number    name           status         method         action
install-on     comments
original-source          original-source-ips
original-destination     original-destination-ips
original-service         original-service-ports
translated-source        translated-source-ips
translated-destination   translated-destination-ips
translated-service       translated-service-ports
uid            hits           creation-time  last-modified
```

### Flags

| Flag | Effect |
|---|---|
| `--split` | One row per (source, destination) pair |
| `--split-groups` | Expand groups into individual member refs (composes with `--split`) |
| `--nat` | Extract NAT rules instead of access/HTTPS/threat rules |

### Examples

```bash
# Standard export
python ..\firewall-import\convert_checkpoint.py policy.json "rule-number,status,name,source,destination,action"

# Expanded rows with IP sub-columns
python ..\firewall-import\convert_checkpoint.py --split policy.json "rule-number,name,source,source-ips,destination,destination-ips"

# Groups expanded into members and split
python ..\firewall-import\convert_checkpoint.py --split-groups --split policy.json "rule-number,name,source,destination,action"

# NAT rules
python ..\firewall-import\convert_checkpoint.py --nat policy.json "rule-number,name,original-source,original-source-ips,translated-source,translated-source-ips"
```

## Fetching a live policy

```bash
python fetch_policy.py --server 10.0.0.1 --username api_user
```

The script authenticates against the Checkpoint Management Web API and fetches:
- All access layers (with inline layers) — paginated
- HTTPS inspection policy — paginated
- Threat prevention policy — paginated
- All object types — each paginated separately

### Pagination

All API calls use the `_paginate` helper which automatically handles
Checkpoint's `limit`/`offset` pagination (default 500 items/page).
Every endpoint — layers, rulebases, hosts, networks, groups, services
(TCP/UDP/ICMP/other), application-sites, time, user-groups — is paginated.

The loop handles both APIs that return `total` and those that don't,
using `result_key` passed explicitly (since Checkpoint uses inconsistent
response key names: `show-services-tcp` returns `tcp-services`, not `services_tcp`).

Supports policies with **5000+ objects** and **1000+ rules** per layer.

### Options

| Flag | Description |
|---|---|
| `--server` | Management server IP/hostname (required) |
| `--username` | API user (required) |
| `--password` | Password (omit for prompt) |
| `--port` | API port (default 443) |
| `--output` | Output JSON file path |
| `--ssl-verify` | Verify SSL certificate |

## Search GUI

```bash
python search_gui.py [policy.json]
```

Tkinter GUI with three tabs.  All treeviews include **horizontal scrollbars**
so wide column sets (IP sub-columns, ports, timestamps) are reachable.

### Objects tab
- Space-separated multi-term search (AND)
- `*` matches any string, `.` matches any single character
- Searches across name, IP address, subnet, comments, category
- Double-click for full object detail

### Rules tab
- `AND` / `OR` between `field:value` pairs
- Fields: `layer`, `rule-number`, `name`, `status`, `source`, **`source-ips`**, `destination`, **`destination-ips`**, `service`, **`service-ports`**, `action`, `track`, `comments`, `uid`, `hits`, `creation-time`, `last-modified`
- Inline layer rules show hierarchical numbering (`8.1`, `8.2`)
- **Split** checkbox: expand multi-source/multi-destination rules into one row per pair (affects display + CSV export)
- **Split Groups** checkbox: recursively expand group objects into individual members before splitting
- **Export All to CSV** / **Export Searched to CSV** (respect Split/Split Groups)

### NAT Rules tab
- Original/translated source, destination, service with IP/port sub-columns
- Same AND/OR search syntax
- **Export All to CSV** / **Export Searched to CSV**

### Download from Live Server
- **Download** button in toolbar (requires `fetch_policy.py` in toolkit directory)
- Credential dialog → Connect & Fetch Layers → checkboxes per layer → Download & Load
- Fetches selected layers + HTTPS inspection + threat prevention + all objects
- Saves to tempfile, loads into GUI

## Version history

- **v1** — Basic name-based resolution
- **v2** — IP/CIDR resolution for hosts, networks, gateways
- **v3** — Name [IP/CIDR] display, service port/protocol, `;` separator
- **v4** — Hierarchical inline numbering (8.1, 8.2), `--split` flag
- **v5** — `status`, `policy-name`, `rule-type` fields
- **v6** — `--split-groups` flag for expanding group members
- **v7** — NAT rule support (`--nat`), IP resolution in GUI
- **v8** — `hits`, `creation-time`, `last-modified`, `uid` columns
- **v9** — IP/port sub-columns in converter + GUI; Split/Split Groups checkboxes in GUI
- **v10** — Fixed column alignment (IP/port sub-columns now show correct data); hierarchical rule numbering for inline rules in GUI
- **v11** — Full pagination in `fetch_policy.py` for all rulebases and object types (5000+ objects, 1000+ rules)

## License

[MIT](../LICENSE) — permissive, free to use, modify, and distribute.
