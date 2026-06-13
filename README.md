# Checkpoint Firewall Policy Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Multi-tool suite to convert, fetch, and search Checkpoint firewall policies.

```
convert_Checkpoint_json/
├── checkpoint_policy.json        # example policy
├── .gitignore
├── LICENSE                       # MIT
├── README.md                     # root docs
├── checkpoint_toolkit/
│   ├── fetch_policy.py           # live API fetcher (paginated)
│   ├── search_gui.py             # Tkinter GUI
│   ├── JMPEP-logo.png
│   ├── PROMPT.md                 # project prompt
│   └── README.md                 # toolkit docs
└── firewall-import/
    ├── convert_checkpoint.py     # latest (v6)
    └── history/
        ├── convert_checkpoint_v1.py
        ├── convert_checkpoint_v2.py
        ├── convert_checkpoint_v3.py
        ├── convert_checkpoint_v4.py
        ├── convert_checkpoint_v5.py
        └── convert_checkpoint_v6.py
```

```

## Quick start

```bash
# CSV conversion (latest version)
python firewall-import\convert_checkpoint.py checkpoint_policy.json "rule-number,status,name,source,source-ips,destination,destination-ips,service,service-ports,action"

# NAT rules
python firewall-import\convert_checkpoint.py --nat checkpoint_policy.json "rule-number,name,original-source,translated-source"

# Browse GUI
python checkpoint_toolkit\search_gui.py checkpoint_policy.json
```

## Documentation

See `checkpoint_toolkit/README.md` for full usage with all flags, GUI features,
and live server fetching.  `checkpoint_toolkit/PROMPT.md` contains the project
prompt and design decisions.

## License

[MIT](LICENSE) — feel free to use, modify, and distribute.
