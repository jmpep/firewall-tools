"""GUI to search Checkpoint policy JSON — objects, rules, NAT.  Export to CSV."""

import json
import re
import sys
import os
import csv
import time
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from fetch_policy import CheckpointAPIClient
    HAS_FETCH = True
except ImportError:
    HAS_FETCH = False


# ==================================================================== pattern

def _glob_to_regex(pattern):
    """Convert simplified pattern (* = any, . = single char) to regex."""
    parts = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            parts.append('.*')
        elif c == '.':
            parts.append('.')
        else:
            parts.append(re.escape(c))
        i += 1
    return '(?i)' + ''.join(parts)


def match_pattern(value, pattern):
    """Return True if value matches the simplified pattern (substring)."""
    if not isinstance(value, str):
        value = str(value)
    return bool(re.search(_glob_to_regex(pattern.strip()), value.strip()))


def _resolve_ip(objects_lookup, name):
    """Resolve a name to IP/CIDR string, or None."""
    if name == 'Any':
        return None
    entry = objects_lookup.get(name)
    if not entry:
        return None
    ip = entry.get('ip-address', '')
    if ip:
        return f"{ip}/32"
    subnet = entry.get('subnet', '')
    mask = entry.get('mask-length')
    if subnet and mask is not None:
        return f"{subnet}/{mask}"
    return None


def _sanitize(obj):
    """Recursively replace non-breaking spaces with normal space and remove backslashes."""
    if isinstance(obj, str):
        return obj.replace('\u00a0', ' ').replace('\\', '')
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    return obj


def _build_object_lookup(objects_list):
    """Build name->dict lookup from flat object list."""
    return {o['name']: o for o in objects_list if o.get('name')}


# ================================================================ data loader

def load_policy(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_rules(data):
    """Yield (layer_path, rule_dict) for access/inline/https/threat layers
    with hierarchical rule-number for inline sub-rules."""
    try:
        layers = data['policy-package']['access-control-policy']['layers']
    except (KeyError, TypeError):
        layers = []

    for layer in layers:
        lname = layer.get('name', '?')
        inline_by_name = {inline['name']: inline for inline in layer.get('inline-layers', [])
                          if inline.get('name')}
        used_inline = set()

        for r in layer.get('rules', []):
            r = dict(r)
            rule_num = r.get('rule-number', '')
            r['_layer_path'] = f"Access / {lname}"
            yield (f"Access / {lname}", r)

            inline_ref = r.get('inline-layer', {})
            inline_name = inline_ref.get('name', '') if isinstance(inline_ref, dict) else ''
            if inline_name and inline_name in inline_by_name:
                used_inline.add(inline_name)
                inline = inline_by_name[inline_name]
                for i, irule in enumerate(inline.get('rules', []), 1):
                    irule = dict(irule)
                    irule['_layer_path'] = f"Access / {lname} / Inline: {inline_name}"
                    irule['_parent_rule'] = rule_num
                    irule['_inline_index'] = i
                    yield (f"Access / {lname} / Inline: {inline_name}", irule)

        for inline_name, inline in inline_by_name.items():
            if inline_name not in used_inline:
                for irule in inline.get('rules', []):
                    irule = dict(irule)
                    irule['_layer_path'] = f"Access / {lname} / Inline: {inline_name} (unlinked)"
                    yield (f"Access / {lname} / Inline: {inline_name} (unlinked)", irule)

    for r in data.get('policy-package', {}).get('https-inspection-policy', {}).get('rules', []):
        r = dict(r) if isinstance(r, dict) else r
        yield ("HTTPS Inspection", r)
    for r in data.get('policy-package', {}).get('threat-prevention-policy', {}).get('rulebase', []):
        r = dict(r) if isinstance(r, dict) else r
        yield ("Threat Prevention", r)


def extract_nat_rules(data):
    """Yield NAT rules with original/translated fields."""
    for r in data.get('policy-package', {}).get('nat-policy', {}).get('rules', []):
        yield r


def _names_ips(arr, lookup):
    """Join object names with inline IP resolution."""
    if not isinstance(arr, list):
        return str(arr)
    parts = []
    for o in arr:
        if not isinstance(o, dict):
            parts.append(str(o))
            continue
        name = o.get('name', '')
        ip = _resolve_ip(lookup, name)
        if ip:
            parts.append(f"{name} [{ip}]")
        else:
            parts.append(name)
    return '; '.join(parts)


def _extract_ips(arr, lookup):
    """Extract just IP/CIDR strings from object refs (no names)."""
    if not isinstance(arr, list):
        return ''
    ips = []
    for o in arr:
        if not isinstance(o, dict):
            continue
        name = o.get('name', '')
        if name == 'Any':
            ips.append('Any')
            continue
        ip = _resolve_ip(lookup, name)
        if ip:
            ips.append(ip)
    return '; '.join(ips)


def _extract_ports(arr, lookup):
    """Extract protocol/port strings from service refs."""
    if not isinstance(arr, list):
        return ''
    ports = []
    for o in arr:
        if not isinstance(o, dict):
            continue
        name = o.get('name', '')
        if name == 'Any':
            ports.append('Any')
            continue
        entry = lookup.get(name)
        if entry:
            proto = entry.get('protocol', '')
            port = entry.get('port', '')
            if proto and port:
                ports.append(f"{proto}/{port}")
            elif port:
                ports.append(str(port))
            elif proto == 'icmp':
                icmp_type = entry.get('icmp-type', '')
                icmp_code = entry.get('icmp-code', '')
                ports.append(f"icmp type={icmp_type} code={icmp_code}")
            else:
                ports.append(name)
        else:
            ports.append(name)
    return '; '.join(ports)


def flatten_rule_for_display(layer, rule, lookup):
    """Return a dict with string values for treeview columns (IPs resolved)."""
    action = rule.get('action', {})
    if isinstance(action, dict):
        action = action.get('name', '')
    track = rule.get('track', {})
    if isinstance(track, dict):
        track = track.get('type', '')

    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}

    parent = rule.get('_parent_rule', '')
    idx = rule.get('_inline_index', '')
    rule_num = f"{parent}.{idx}" if parent and idx else rule.get('rule-number', '')

    return {
        "layer": layer,
        "rule-number": rule_num,
        "name": rule.get('name', ''),
        "status": "Disabled" if rule.get('enabled') is False else "Enabled",
        "source": _names_ips(rule.get('source', []), lookup),
        "source-ips": _extract_ips(rule.get('source', []), lookup),
        "destination": _names_ips(rule.get('destination', []), lookup),
        "destination-ips": _extract_ips(rule.get('destination', []), lookup),
        "service": _names_ips(rule.get('service', []), lookup),
        "service-ports": _extract_ports(rule.get('service', []), lookup),
        "action": action,
        "track": track,
        "comments": rule.get('comments', ''),
        "uid": rule.get('uid', ''),
        "hits": hm.get('hits', '') if isinstance(hm, dict) else '',
        "creation-time": meta.get('creation-time', {}).get('iso', '') if isinstance(meta.get('creation-time'), dict) else '',
        "last-modified": meta.get('last-modified', {}).get('iso', '') if isinstance(meta.get('last-modified'), dict) else '',
    }


def flatten_nat_for_display(rule, lookup):
    def _names(arr):
        if not isinstance(arr, list):
            return str(arr)
        parts = []
        for o in arr:
            if not isinstance(o, dict):
                parts.append(str(o))
                continue
            name = o.get('name', '')
            ip = _resolve_ip(lookup, name)
            if ip:
                parts.append(f"{name} [{ip}]")
            else:
                parts.append(name)
        return '; '.join(parts)

    action = rule.get('action', {})
    if isinstance(action, dict):
        action = action.get('name', '')
    install = rule.get('install-on', {})
    if isinstance(install, dict):
        install = install.get('name', '')

    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}

    return {
        "rule-number": rule.get('rule-number', ''),
        "name": rule.get('name', ''),
        "status": "Disabled" if rule.get('enabled') is False else "Enabled",
        "original-source": _names(rule.get('original-source', [])),
        "original-source-ips": _extract_ips(rule.get('original-source', []), lookup),
        "original-destination": _names(rule.get('original-destination', [])),
        "original-destination-ips": _extract_ips(rule.get('original-destination', []), lookup),
        "original-service": _names(rule.get('original-service', [])),
        "original-service-ports": _extract_ports(rule.get('original-service', []), lookup),
        "translated-source": _names(rule.get('translated-source', [])),
        "translated-source-ips": _extract_ips(rule.get('translated-source', []), lookup),
        "translated-destination": _names(rule.get('translated-destination', [])),
        "translated-destination-ips": _extract_ips(rule.get('translated-destination', []), lookup),
        "translated-service": _names(rule.get('translated-service', [])),
        "translated-service-ports": _extract_ports(rule.get('translated-service', []), lookup),
        "method": rule.get('method', ''),
        "action": action,
        "install-on": install,
        "comments": rule.get('comments', ''),
        "uid": rule.get('uid', ''),
        "hits": hm.get('hits', '') if isinstance(hm, dict) else '',
        "creation-time": meta.get('creation-time', {}).get('iso', '') if isinstance(meta.get('creation-time'), dict) else '',
        "last-modified": meta.get('last-modified', {}).get('iso', '') if isinstance(meta.get('last-modified'), dict) else '',
    }


def collect_objects(data):
    """Return a flat list of object dicts."""
    objs = []
    objects = data.get('objects', {})
    for otype, items in objects.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                item['_objtype'] = otype
                objs.append(item)
    return objs


# ================================================================ GUI

class SearchGUI:
    NAT_COLS = ("rule-number", "name", "status",
                "original-source", "original-source-ips",
                "original-destination", "original-destination-ips",
                "original-service", "original-service-ports",
                "translated-source", "translated-source-ips",
                "translated-destination", "translated-destination-ips",
                "translated-service", "translated-service-ports",
                "method", "action", "install-on", "comments",
                "uid", "hits", "creation-time", "last-modified")
    RULE_COLS = ("layer", "rule-number", "name", "status",
                 "source", "source-ips",
                 "destination", "destination-ips",
                 "service", "service-ports",
                 "action", "track", "comments",
                 "uid", "hits", "creation-time", "last-modified")
    OBJ_COLS = ("name", "ip-address", "subnet", "mask-length", "type",
                "comments", "category", "risk", "_objtype")

    def __init__(self, root, initial_file=None):
        self.root = root
        root.title("Checkpoint Policy Search")
        root.geometry("1300x800")

        self.data = None
        self.all_objects = []
        self.lookup = {}
        self._groups = {}
        self.all_rules = []
        self.all_nat_rules = []

        # ---- menu
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open JSON ...", command=self.open_file)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # ---- toolbar
        toolbar = ttk.Frame(root)
        toolbar.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(toolbar, text="File:").pack(side=tk.LEFT)
        self.file_label = ttk.Label(toolbar, text="(none)", foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Open", command=self.open_file).pack(side=tk.LEFT, padx=2)
        if HAS_FETCH:
            ttk.Button(toolbar, text="Download", command=self._download_dialog).pack(side=tk.LEFT, padx=2)

        # ---- banner
        banner = tk.Frame(root, bg="#1a3a5c", height=56)
        banner.pack(fill=tk.X, padx=0, pady=(2, 0))
        banner.pack_propagate(False)

        logo_frame = tk.Frame(banner, bg="#1a3a5c")
        logo_frame.pack(side=tk.LEFT, padx=(12, 6), pady=6)
        logo_path = os.path.join(os.path.dirname(__file__), "JMPEP-logo.png")
        if os.path.exists(logo_path):
            self._logo_img = tk.PhotoImage(file=logo_path)
            # subsample to fit banner height (56px): 96→48 at factor 2
            self._logo_img = self._logo_img.subsample(2)
            tk.Label(logo_frame, image=self._logo_img,
                     bg="#1a3a5c").pack()
        else:
            logo_canvas = tk.Canvas(logo_frame, width=36, height=36,
                                    bg="#2a5a8c", highlightthickness=0)
            logo_canvas.pack()
            logo_canvas.create_rectangle(2, 2, 34, 34, fill="#3a7abd", outline="")
            logo_canvas.create_text(18, 18, text="PEPJ", fill="white",
                                    font=("Helvetica", 10, "bold"))

        info_frame = tk.Frame(banner, bg="#1a3a5c")
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=4)
        tk.Label(info_frame, text="Checkpoint Policy Toolkit",
                 bg="#1a3a5c", fg="white",
                 font=("Helvetica", 13, "bold")).pack(anchor=tk.W)
        tk.Label(info_frame,
                 text="v12  •  5000+ objects  •  1000+ rules  •  enjoy and give me feedback. Your friend Jean-Michel",
                 bg="#1a3a5c", fg="#8ab4d6",
                 font=("Helvetica", 8)).pack(anchor=tk.W)

        # ---- notebook
        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # -- object search tab
        obj_frame = ttk.Frame(nb)
        nb.add(obj_frame, text="Objects")
        self._build_object_tab(obj_frame)

        # -- rule search tab
        rule_frame = ttk.Frame(nb)
        nb.add(rule_frame, text="Rules")
        self._build_rule_tab(rule_frame)

        # -- NAT tab
        nat_frame = ttk.Frame(nb)
        nb.add(nat_frame, text="NAT Rules")
        self._build_nat_tab(nat_frame)

        # -- load file if given
        if initial_file and os.path.exists(initial_file):
            self._load(initial_file)

    # ============================================================ object tab

    def _build_object_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.obj_search_var = tk.StringVar()
        self.obj_search_var.trace_add('write', lambda *a: self._do_obj_search())
        e = ttk.Entry(top, textvariable=self.obj_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Label(top, text="  Space = AND,  * = any,  . = single char").pack(side=tk.LEFT)
        self.obj_count_label = ttk.Label(top, text="")
        self.obj_count_label.pack(side=tk.RIGHT, padx=5)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.OBJ_COLS
        self.obj_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                     selectmode='extended')
        for col in c:
            self.obj_tree.heading(col, text=col, command=lambda _c=col: self._sort(self.obj_tree, _c, False))
            self.obj_tree.column(col, width=120, minwidth=60)
        self.obj_tree.column("name", width=180)
        self.obj_tree.column("comments", width=200)
        self.obj_tree.column("_objtype", width=100)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.obj_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.obj_tree.xview)
        self.obj_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.obj_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.obj_tree.bind("<Double-1>", self._obj_detail)

    def _do_obj_search(self):
        self.obj_tree.delete(*self.obj_tree.get_children())
        raw = self.obj_search_var.get().strip()
        if not raw or not self.all_objects:
            self.obj_count_label.config(text=f"{len(self.all_objects)} objects")
            if self.all_objects:
                for o in self.all_objects:
                    self.obj_tree.insert('', tk.END, values=self._obj_vals(o))
            return

        terms = [t.strip() for t in raw.split() if t.strip()]
        matched = []
        for o in self.all_objects:
            if all(self._obj_matches(o, t) for t in terms):
                matched.append(o)

        for o in matched:
            self.obj_tree.insert('', tk.END, values=self._obj_vals(o))
        self.obj_count_label.config(text=f"{len(matched)} / {len(self.all_objects)}")

    def _obj_vals(self, o):
        return tuple(o.get(c, '') for c in self.OBJ_COLS)

    def _obj_matches(self, o, term):
        fields = [str(o.get(k, '')) for k in ('name', 'ip-address', 'subnet', 'comments',
                                               'category', '_objtype')]
        return any(match_pattern(f, term) for f in fields)

    def _obj_detail(self, event):
        sel = self.obj_tree.selection()
        if not sel:
            return
        item = self.obj_tree.item(sel[0])
        vals = {c: v for c, v in zip(self.OBJ_COLS, item['values'])}
        msg = json.dumps(vals, indent=2, ensure_ascii=False)
        messagebox.showinfo("Object detail", msg)

    # ============================================================ rule tab

    def _build_rule_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.rule_search_var = tk.StringVar()
        self.rule_search_var.trace_add('write', lambda *a: self._do_rule_search())
        e = ttk.Entry(top, textvariable=self.rule_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Label(top, text="  field:value AND / OR   (* = any, . = single char)").pack(side=tk.LEFT)
        self.rule_count_label = ttk.Label(top, text="")
        self.rule_count_label.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(btn_frame, text="Export All to CSV",
                   command=self._export_rule_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export Searched to CSV",
                   command=self._export_rule_searched).pack(side=tk.LEFT, padx=2)
        self.split_var = tk.BooleanVar()
        self.split_groups_var = tk.BooleanVar()
        ttk.Checkbutton(btn_frame, text="Split", variable=self.split_var,
                        command=self._do_rule_search).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(btn_frame, text="Split Groups", variable=self.split_groups_var,
                        command=self._do_rule_search).pack(side=tk.LEFT, padx=2)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.RULE_COLS
        self.rule_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                      selectmode='extended')
        for col in c:
            self.rule_tree.heading(col, text=col, command=lambda _c=col: self._sort(self.rule_tree, _c, False))
            self.rule_tree.column(col, width=110, minwidth=60)
        self.rule_tree.column("name", width=220)
        self.rule_tree.column("source", width=220)
        self.rule_tree.column("destination", width=220)
        self.rule_tree.column("source-ips", width=180)
        self.rule_tree.column("destination-ips", width=180)
        self.rule_tree.column("service-ports", width=150)
        self.rule_tree.column("comments", width=200)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.rule_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.rule_tree.xview)
        self.rule_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.rule_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.rule_tree.bind("<Double-1>", self._rule_detail)

    def _do_rule_search(self):
        self.rule_tree.delete(*self.rule_tree.get_children())
        all_flat = self._get_rule_display_rows()
        raw = self.rule_search_var.get().strip()
        if not raw:
            children = [(f, None) for f in all_flat]
        else:
            children = [(f, f) for f in all_flat if self._rule_flat_matches(f, raw)]
        for f, _ in children:
            self.rule_tree.insert('', tk.END, values=tuple(f.values()))
        count = len(children)
        total = len(all_flat)
        self.rule_count_label.config(text=f"{count} / {total}" if raw else str(total))

    def _get_rule_display_rows(self):
        """Return flat dicts for display, respecting split/split-groups."""
        result = []
        for layer, rule in self.all_rules:
            if self.split_groups_var.get():
                rule = self._expand_groups_in_rule(rule)
            if self.split_var.get():
                sources = rule.get('source', [])
                if not isinstance(sources, list):
                    sources = [sources] if sources else []
                destinations = rule.get('destination', [])
                if not isinstance(destinations, list):
                    destinations = [destinations] if destinations else []
                for s in sources:
                    for d in destinations:
                        sr = dict(rule)
                        sr['source'] = [s] if isinstance(s, dict) else [s]
                        sr['destination'] = [d] if isinstance(d, dict) else [d]
                        result.append(flatten_rule_for_display(layer, sr, self.lookup))
            else:
                result.append(flatten_rule_for_display(layer, rule, self.lookup))
        return result

    def _rule_flat_matches(self, flat, raw):
        """Check flat dict against AND/OR query."""
        def _clause_matches(clause):
            clause = clause.strip()
            if ':' not in clause:
                return match_pattern(flat.get("name", ""), clause) or \
                       match_pattern(flat.get("source", ""), clause) or \
                       match_pattern(flat.get("destination", ""), clause) or \
                       match_pattern(flat.get("service", ""), clause)
            field, _, pat = clause.partition(':')
            field = field.strip().lower()
            pat = pat.strip()
            return match_pattern(flat.get(field, ''), pat)

        or_parts = re.split(r'\s+OR\s+', raw, flags=re.IGNORECASE)
        for or_part in or_parts:
            and_parts = re.split(r'\s+AND\s+', or_part, flags=re.IGNORECASE)
            if all(_clause_matches(c) for c in and_parts):
                return True
        return False

    def _get_matching_rules(self):
        """Return (all_rules_flat, searched_rules_flat) lists of dicts."""
        all_flat = self._get_rule_display_rows()
        raw = self.rule_search_var.get().strip()
        if not raw:
            return all_flat, all_flat
        searched = [f for f in all_flat if self._rule_flat_matches(f, raw)]
        return all_flat, searched

    def _export_rule_all(self):
        all_flat, _ = self._get_matching_rules()
        self._export_to_csv(all_flat, "rules_all.csv")

    def _export_rule_searched(self):
        _, searched = self._get_matching_rules()
        self._export_to_csv(searched, "rules_searched.csv")

    def _export_to_csv(self, rows, default_name):
        if not rows:
            messagebox.showinfo("Export", "No data to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export to CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Exported {len(rows)} rows to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def _build_group_lookup(self):
        """Populate self._groups with group-type objects for expand_groups."""
        self._groups = {}
        for name, obj in self.lookup.items():
            otype = obj.get('_objtype', '')
            if otype in ('group', 'group-with-exclusion', 'access-group', 'security-zone'):
                members = obj.get('members', [])
                if isinstance(members, list):
                    self._groups[name] = obj

    def _expand_groups_in_rule(self, rule):
        """Recursively replace group references with individual members."""
        sources = rule.get('source', [])
        destinations = rule.get('destination', [])
        expanded_any = [False]

        def _walk(refs, visited):
            out = []
            for ref in refs:
                name = ref.get('name', '') if isinstance(ref, dict) else str(ref)
                if name and name != 'Any' and name in self._groups and name not in visited:
                    visited.add(name)
                    members = self._groups[name].get('members', [])
                    out.extend(_walk(members, visited))
                    expanded_any[0] = True
                else:
                    out.append(ref)
            return out

        new_src = _walk(sources, set())
        new_dst = _walk(destinations, set())
        if not expanded_any[0]:
            return rule
        r = dict(rule)
        r['source'] = new_src
        r['destination'] = new_dst
        return r

    def _rule_detail(self, event):
        sel = self.rule_tree.selection()
        if not sel:
            return
        item = self.rule_tree.item(sel[0])
        vals = {c: v for c, v in zip(self.RULE_COLS, item['values'])}
        msg = json.dumps(vals, indent=2, ensure_ascii=False)
        messagebox.showinfo("Rule detail", msg)

    # ============================================================ NAT tab

    def _build_nat_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.nat_search_var = tk.StringVar()
        self.nat_search_var.trace_add('write', lambda *a: self._do_nat_search())
        e = ttk.Entry(top, textvariable=self.nat_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Label(top, text="  field:value AND / OR   (* = any, . = single char)").pack(side=tk.LEFT)
        self.nat_count_label = ttk.Label(top, text="")
        self.nat_count_label.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(btn_frame, text="Export All to CSV",
                   command=self._export_nat_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export Searched to CSV",
                   command=self._export_nat_searched).pack(side=tk.LEFT, padx=2)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.NAT_COLS
        self.nat_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                     selectmode='extended')
        for col in c:
            self.nat_tree.heading(col, text=col, command=lambda _c=col: self._sort(self.nat_tree, _c, False))
            self.nat_tree.column(col, width=120, minwidth=60)
        self.nat_tree.column("name", width=200)
        self.nat_tree.column("original-source", width=180)
        self.nat_tree.column("original-destination", width=180)
        self.nat_tree.column("original-source-ips", width=150)
        self.nat_tree.column("original-destination-ips", width=150)
        self.nat_tree.column("original-service-ports", width=130)
        self.nat_tree.column("translated-source", width=180)
        self.nat_tree.column("translated-destination", width=180)
        self.nat_tree.column("translated-source-ips", width=150)
        self.nat_tree.column("translated-destination-ips", width=150)
        self.nat_tree.column("translated-service-ports", width=130)
        self.nat_tree.column("comments", width=200)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.nat_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.nat_tree.xview)
        self.nat_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.nat_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.nat_tree.bind("<Double-1>", self._nat_detail)

    def _do_nat_search(self):
        self.nat_tree.delete(*self.nat_tree.get_children())
        raw = self.nat_search_var.get().strip()
        if not raw or not self.all_nat_rules:
            self.nat_count_label.config(text=f"{len(self.all_nat_rules)} NAT rules")
            for r in self.all_nat_rules:
                self.nat_tree.insert('', tk.END,
                                     values=tuple(flatten_nat_for_display(r, self.lookup).values()))
            return

        matched = self._eval_nat_query(raw)
        for r in matched:
            self.nat_tree.insert('', tk.END,
                                 values=tuple(flatten_nat_for_display(r, self.lookup).values()))
        self.nat_count_label.config(text=f"{len(matched)} / {len(self.all_nat_rules)}")

    def _eval_nat_query(self, raw):
        def _clause_matches(rule, clause):
            clause = clause.strip()
            flat = flatten_nat_for_display(rule, self.lookup)
            if ':' not in clause:
                for field in ('name', 'original-source', 'original-destination',
                              'translated-source', 'translated-destination', 'comments'):
                    if match_pattern(flat.get(field, ''), clause):
                        return True
                return False
            field, _, pat = clause.partition(':')
            field = field.strip().lower()
            pat = pat.strip()
            if field in flat:
                return match_pattern(flat[field], pat)
            return False

        or_parts = re.split(r'\s+OR\s+', raw, flags=re.IGNORECASE)
        results = []
        for or_part in or_parts:
            and_parts = re.split(r'\s+AND\s+', or_part, flags=re.IGNORECASE)
            for rule in self.all_nat_rules:
                if all(_clause_matches(rule, c) for c in and_parts):
                    results.append(rule)
        return results

    def _get_matching_nat(self):
        all_flat = [flatten_nat_for_display(r, self.lookup) for r in self.all_nat_rules]
        raw = self.nat_search_var.get().strip()
        if not raw:
            return all_flat, all_flat
        matched = self._eval_nat_query(raw)
        matched_set = set(id(r) for r in matched)
        searched = [flatten_nat_for_display(r, self.lookup)
                    for r in self.all_nat_rules if id(r) in matched_set]
        return all_flat, searched

    def _export_nat_all(self):
        all_flat, _ = self._get_matching_nat()
        self._export_to_csv(all_flat, "nat_all.csv")

    def _export_nat_searched(self):
        _, searched = self._get_matching_nat()
        self._export_to_csv(searched, "nat_searched.csv")

    def _nat_detail(self, event):
        sel = self.nat_tree.selection()
        if not sel:
            return
        item = self.nat_tree.item(sel[0])
        vals = {c: v for c, v in zip(self.NAT_COLS, item['values'])}
        msg = json.dumps(vals, indent=2, ensure_ascii=False)
        messagebox.showinfo("NAT rule detail", msg)

    # ============================================================ download dialog

    def _download_dialog(self):
        """Open a dialog to download policy from a live Checkpoint management server."""
        if not HAS_FETCH:
            messagebox.showerror("Error", "fetch_policy.py not found in toolkit directory.")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Download Policy from Management Server")
        dlg.geometry("620x580")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(True, True)

        row = 0

        # -- connection frame
        cf = ttk.LabelFrame(dlg, text="Connection", padding=10)
        cf.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cf, text="Server:").grid(row=0, column=0, sticky=tk.W, pady=2)
        server_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(cf, textvariable=server_var, width=40).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(cf, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=2)
        user_var = tk.StringVar(value="admin")
        ttk.Entry(cf, textvariable=user_var, width=40).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(cf, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        pass_var = tk.StringVar()
        ttk.Entry(cf, textvariable=pass_var, width=40, show="*").grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(cf, text="Port:").grid(row=3, column=0, sticky=tk.W, pady=2)
        port_var = tk.StringVar(value="443")
        ttk.Entry(cf, textvariable=port_var, width=10).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

        ssl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cf, text="Verify SSL", variable=ssl_var).grid(row=3, column=1, padx=80, pady=2, sticky=tk.W)

        connect_btn = ttk.Button(cf, text="Connect & Fetch Layers")
        connect_btn.grid(row=4, column=0, columnspan=2, pady=6)

        # -- layers frame
        lf = ttk.LabelFrame(dlg, text="Access Layers (select to include)", padding=10)
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        layer_frame = ttk.Frame(lf)
        layer_frame.pack(fill=tk.BOTH, expand=True)
        layer_canvas = tk.Canvas(layer_frame, borderwidth=0, highlightthickness=0)
        layer_scroll = ttk.Scrollbar(layer_frame, orient=tk.VERTICAL, command=layer_canvas.yview)
        layer_inner = ttk.Frame(layer_canvas)
        layer_inner.bind("<Configure>", lambda e: layer_canvas.configure(scrollregion=layer_canvas.bbox("all")))
        layer_canvas.create_window((0, 0), window=layer_inner, anchor=tk.NW)
        layer_canvas.configure(yscrollcommand=layer_scroll.set)
        layer_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        layer_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # -- bottom buttons
        bf = ttk.Frame(dlg)
        bf.pack(fill=tk.X, padx=10, pady=5)

        def _select_all():
            for cb in layer_checkboxes:
                cb[1].set(True)
        def _clear_all():
            for cb in layer_checkboxes:
                cb[1].set(False)

        ttk.Button(bf, text="Select All", command=_select_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(bf, text="Clear All", command=_clear_all).pack(side=tk.LEFT, padx=2)

        ttk.Label(bf, text="Policy name:").pack(side=tk.LEFT, padx=(20, 2))
        pkg_var = tk.StringVar(value="fetched_policy")
        ttk.Entry(bf, textvariable=pkg_var, width=20).pack(side=tk.LEFT, padx=2)

        download_btn = ttk.Button(bf, text="Download & Load", state=tk.DISABLED)
        download_btn.pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=2)

        status_var = tk.StringVar(value="Enter credentials and click Connect")
        status_bar = ttk.Label(dlg, textvariable=status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=(0, 5))

        layer_checkboxes = []
        _client_ref = [None]

        def _do_connect():
            connect_btn.config(state=tk.DISABLED)
            status_var.set("Connecting ...")
            dlg.update()

            server = server_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get()
            try:
                port = int(port_var.get().strip())
            except ValueError:
                status_var.set("Invalid port number.")
                connect_btn.config(state=tk.NORMAL)
                return

            if not server or not username:
                status_var.set("Server and username required.")
                connect_btn.config(state=tk.NORMAL)
                return

            try:
                client = CheckpointAPIClient(server, username, password,
                                              port=port, verify=ssl_var.get())
                _client_ref[0] = client
                status_var.set("Connected. Fetching access layers ...")
                dlg.update()
                layer_names = client.fetch_layers()
            except (SystemExit, Exception) as e:
                msg = str(e).strip() or "Connection failed"
                status_var.set(f"Error: {msg}")
                connect_btn.config(state=tk.NORMAL)
                return

            # Populate layer checkboxes
            for cb in layer_checkboxes:
                cb[0].destroy()
            layer_checkboxes.clear()
            if not layer_names:
                status_var.set("No access layers found on the server.")
                connect_btn.config(state=tk.NORMAL)
                return
            for ln in layer_names:
                var = tk.BooleanVar(value=True)
                cb = ttk.Checkbutton(layer_inner, text=ln, variable=var)
                cb.pack(anchor=tk.W, padx=5, pady=1)
                layer_checkboxes.append((cb, var))
            download_btn.config(state=tk.NORMAL)
            status_var.set(f"Connected. {len(layer_names)} layer(s) found. Select layers and click Download.")
            connect_btn.config(state=tk.NORMAL)

        def _do_download():
            selected = [ln for (_, var), ln in zip(layer_checkboxes,
                         [cb[0].cget("text") for cb in layer_checkboxes]) if var.get()]
            if not selected:
                status_var.set("Select at least one layer to download.")
                return

            download_btn.config(state=tk.DISABLED)
            connect_btn.config(state=tk.DISABLED)
            client = _client_ref[0]
            if not client:
                status_var.set("Not connected.")
                return

            pkg_name = pkg_var.get().strip() or "fetched_policy"

            try:
                status_var.set("Fetching rulebases ...")
                dlg.update()
                layers_data = []
                for i, ln in enumerate(selected):
                    status_var.set(f"Fetching layer {i+1}/{len(selected)}: {ln}")
                    dlg.update()
                    rb = client.fetch_rulebase(ln)
                    layer = {"name": ln, "uid": rb.get("uid", ""),
                             "rules": [], "inline-layers": []}
                    seen = set()
                    for item in rb.get("rulebase", []):
                        t = item.get("type", "")
                        uid = item.get("uid", "")
                        if uid in seen:
                            continue
                        seen.add(uid)
                        if t == "access-rule":
                            layer["rules"].append(item)
                        elif t == "inline-layer":
                            layer["inline-layers"].append(item)
                        elif t == "access-section":
                            pass
                        else:
                            layer["rules"].append(item)
                    layers_data.append(layer)

                status_var.set("Fetching HTTPS inspection ...")
                dlg.update()
                try:
                    https_rules = client.fetch_https_inspection()
                except Exception:
                    https_rules = []

                status_var.set("Fetching threat prevention ...")
                dlg.update()
                try:
                    threat_rules = client.fetch_threat_rulebase()
                except Exception:
                    threat_rules = []

                status_var.set("Fetching objects ...")
                dlg.update()
                objects = client.fetch_all_objects()

                data = {
                    "policy-package": {
                        "name": pkg_name,
                        "meta-info": {
                            "fetched-at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        },
                        "access-control-policy": {"layers": layers_data},
                        "https-inspection-policy": {"rules": https_rules},
                        "threat-prevention-policy": {"rulebase": threat_rules},
                    },
                    "objects": objects,
                }

                status_var.set("Sanitizing data ...")
                dlg.update()
                data = _sanitize(data)
                status_var.set("Saving ...")
                dlg.update()
                fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="checkpoint_")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)

            except (SystemExit, Exception) as e:
                msg = str(e).strip() or "Download failed"
                status_var.set(f"Error: {msg}")
                download_btn.config(state=tk.NORMAL)
                connect_btn.config(state=tk.NORMAL)
                return

            try:
                client.logout()
            except Exception:
                pass

            status_var.set("Loading into GUI ...")
            dlg.update()
            dlg.destroy()
            self._load(tmp_path)

        connect_btn.config(command=_do_connect)
        download_btn.config(command=_do_download)
        dlg.wait_window()

    def open_file(self):
        path = filedialog.askopenfilename(
            title="Open Checkpoint policy JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            self._load(path)

    def _load(self, path):
        try:
            self.data = load_policy(path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load:\n{e}")
            return

        self.all_objects = collect_objects(self.data)
        self.lookup = _build_object_lookup(self.all_objects)
        self._build_group_lookup()
        self.all_rules = list(extract_rules(self.data))
        self.all_nat_rules = list(extract_nat_rules(self.data))
        self.file_label.config(text=os.path.basename(path))
        self.root.title(f"Checkpoint Policy Search — {os.path.basename(path)}")
        self._do_obj_search()
        self._do_rule_search()
        self._do_nat_search()

    # ============================================================ sort

    def _sort(self, tree, col, reverse):
        data = [(tree.set(k, col), k) for k in tree.get_children('')]
        data.sort(key=lambda x: (x[0] or '').lower(), reverse=reverse)
        for idx, (_, k) in enumerate(data):
            tree.move(k, '', idx)
        tree.heading(col, command=lambda: self._sort(tree, col, not reverse))


# ==================================================================== main

def main():
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    SearchGUI(root, initial)
    root.mainloop()


if __name__ == "__main__":
    main()
