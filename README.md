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

## Documentation

See `checkpoint_toolkit/PROMPT.md` for full feature docs, design decisions, and version history.

## License

[MIT](LICENSE) — feel free to use, modify, and distribute.
