"""GUI to search Checkpoint policy JSON — objects, rules, NAT.  Export to CSV."""

import json
import re
import sys
import os
import csv
import time
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from fetch_policy import fetch_policy, VENDORS, CheckpointAPIClient
    HAS_FETCH = True
except ImportError:
    HAS_FETCH = False

from utils import load_settings, save_settings, update_settings, setup_logging, reset_log, DEFAULT_LOG_LEVEL
from lang import L, set_language

logger = logging.getLogger(__name__)


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
    ip = entry.get('ip-address') or entry.get('ipv4-address', '')
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
    track = rule.get('track', '')
    if isinstance(track, dict):
        track = track.get('type', '') or ''

    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}

    parent = rule.get('_parent_rule', '')
    idx = rule.get('_inline_index', '')
    rule_num = f"{parent}.{idx}" if parent and idx else rule.get('rule-number', '')

    uid = rule.get('uid', '')
    return {
        "layer": layer,
        "rule-number": rule_num,
        "rule-id": uid,
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

    uid = rule.get('uid', '')
    return {
        "rule-number": rule.get('rule-number', ''),
        "rule-id": uid,
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
        "hits": hm.get('hits', '') if isinstance(hm, dict) else '',
        "creation-time": meta.get('creation-time', {}).get('iso', '') if isinstance(meta.get('creation-time'), dict) else '',
        "last-modified": meta.get('last-modified', {}).get('iso', '') if isinstance(meta.get('last-modified'), dict) else '',
    }


def extract_proxy_rules(data):
    """Yield proxy policy rules."""
    for r in data.get('policy-package', {}).get('proxy-policy', {}).get('rules', []):
        yield r


def flatten_proxy_for_display(rule, lookup):
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

    extra = rule.get('extra', {}) or {}
    uid = rule.get('uid', '')
    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}

    return {
        "rule-number": rule.get('rule-number', ''),
        "rule-id": uid,
        "name": rule.get('name', ''),
        "status": "Disabled" if rule.get('enabled') is False else "Enabled",
        "proxy-type": extra.get('proxy-type', ''),
        "source": _names(rule.get('source', [])),
        "destination": _names(rule.get('destination', [])),
        "service": _names(rule.get('service', [])),
        "source-interface": extra.get('source-interface', ''),
        "destination-interface": extra.get('destination-interface', ''),
        "action": action,
        "schedule": extra.get('schedule', ''),
        "transparent": "Yes" if extra.get('transparent') else "",
        "webcache": "Yes" if extra.get('webcache') else "",
        "disclaimer": extra.get('disclaimer', ''),
        "redirect-url": extra.get('redirect-url', ''),
        "webproxy-profile": extra.get('webproxy-profile', ''),
        "http-tunnel-auth": "Yes" if extra.get('http-tunnel-auth') else "",
        "profile-group": extra.get('profile-group', ''),
        "comments": rule.get('comments', ''),
        "track": rule.get('track', ''),
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
    NAT_COLS = ("rule-number", "rule-id", "name", "status",
                "original-source", "original-source-ips",
                "original-destination", "original-destination-ips",
                "original-service", "original-service-ports",
                "translated-source", "translated-source-ips",
                "translated-destination", "translated-destination-ips",
                "translated-service", "translated-service-ports",
                "method", "action", "install-on", "comments",
                "hits", "creation-time", "last-modified")
    PROXY_COLS = ("rule-number", "rule-id", "name", "status", "proxy-type",
                  "source", "destination", "service",
                  "source-interface", "destination-interface",
                  "action", "schedule",
                  "transparent", "webcache", "disclaimer",
                  "redirect-url", "webproxy-profile", "http-tunnel-auth",
                   "profile-group", "comments", "track")
    RULE_COLS = ("layer", "rule-number", "rule-id", "name", "status",
                 "source", "source-ips",
                 "destination", "destination-ips",
                 "service", "service-ports",
                  "action", "track", "comments",
                  "hits", "creation-time", "last-modified")
    OBJ_COLS = ("name", "ip-address", "subnet", "mask-length", "type",
                "comments", "category", "risk", "_objtype")

    def __init__(self, root, initial_file=None):
        self.root = root
        root.title(L("app.title"))
        root.geometry("1300x800")

        self.data = None
        self.all_objects = []
        self.lookup = {}
        self._groups = {}
        self.all_rules = []
        self.all_nat_rules = []
        self.all_proxy_rules = []

        settings = load_settings()
        self.page_size = settings.get("page_size", 200)
        self.timeout = settings.get("timeout", 300)
        self.log_level_name = settings.get("log_level", DEFAULT_LOG_LEVEL)
        self.download_dir = settings.get("download_dir", "examples")
        lang_code = settings.get("language", "en")
        set_language(lang_code)

        setup_logging(self.log_level_name)
        logging.info("GUI started (lang=%s)", lang_code)

        # ---- menu
        self.menubar = tk.Menu(root)
        self.filemenu = tk.Menu(self.menubar, tearoff=0)
        self.filemenu.add_command(label=L("menu.open"), command=self.open_file)
        self.filemenu.add_separator()
        self.filemenu.add_command(label=L("menu.exit"), command=self._on_quit)
        self.menubar.add_cascade(label=L("menu.file"), menu=self.filemenu)
        root.config(menu=self.menubar)
        root.protocol("WM_DELETE_WINDOW", self._on_quit)

        # ---- toolbar
        self._lang_widgets = []
        toolbar = ttk.Frame(root)
        toolbar.pack(fill=tk.X, padx=5, pady=3)
        w = ttk.Label(toolbar, text=L("tb.file_label")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "tb.file_label"))
        self.file_label = ttk.Label(toolbar, text=L("group.none"), foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=5)
        w = ttk.Button(toolbar, text=L("tb.open"), command=self.open_file); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "tb.open"))
        if HAS_FETCH:
            self.dl_btn = ttk.Button(toolbar, text=L("tb.download"), command=self._download_dialog)
            self.dl_btn.pack(side=tk.LEFT, padx=2)
            self._lang_widgets.append((self.dl_btn, "tb.download"))
        self.settings_btn = ttk.Button(toolbar, text=L("tb.settings"), command=self._settings_dialog)
        self.settings_btn.pack(side=tk.RIGHT, padx=2)
        self._lang_widgets.append((self.settings_btn, "tb.settings"))
        w = ttk.Label(toolbar, text=L("tb.lang")); w.pack(side=tk.RIGHT, padx=(2, 0))
        self._lang_widgets.append((w, "tb.lang"))
        self._lang_btns = {}
        img_dir = os.path.join(os.path.dirname(__file__), "images")
        self._flag_images = {}
        for code in ("en", "fr", "de", "it", "sk"):
            btn = tk.Button(toolbar, text=code.upper(), width=4,
                            command=lambda c=code: self._select_language(c), padx=0, pady=0)
            btn.pack(side=tk.RIGHT, padx=1)
            img_path = os.path.join(img_dir, f"{code}.png")
            if os.path.exists(img_path):
                try:
                    img = tk.PhotoImage(file=img_path)
                    self._flag_images[code] = img
                    btn.config(image=img, text="", width=28, height=18)
                except tk.TclError:
                    pass
            self._lang_btns[code] = btn
        self._highlight_lang(L.code)

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
        self.banner_title = tk.Label(info_frame, text=L("banner.title"),
                 bg="#1a3a5c", fg="white",
                 font=("Helvetica", 13, "bold"))
        self.banner_title.pack(anchor=tk.W)
        self.banner_sub = tk.Label(info_frame, text=L("banner.subtitle"),
                 bg="#1a3a5c", fg="#8ab4d6",
                 font=("Helvetica", 8))
        self.banner_sub.pack(anchor=tk.W)

        # ---- notebook
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # -- object search tab
        obj_frame = ttk.Frame(self.nb)
        self.nb.add(obj_frame, text=L("tab.objects"))
        self._build_object_tab(obj_frame)

        # -- rule search tab
        rule_frame = ttk.Frame(self.nb)
        self.nb.add(rule_frame, text=L("tab.rules"))
        self._build_rule_tab(rule_frame)

        # -- nat search tab
        nat_frame = ttk.Frame(self.nb)
        self.nb.add(nat_frame, text=L("tab.nat"))
        self._build_nat_tab(nat_frame)

        # -- proxy search tab
        proxy_frame = ttk.Frame(self.nb)
        self.nb.add(proxy_frame, text=L("tab.proxy"))
        self._build_proxy_tab(proxy_frame)

        # ---- status bar
        status_frame = ttk.Frame(root)
        status_frame.pack(fill=tk.X, padx=5, pady=(0, 3))
        self.status_label = ttk.Label(status_frame, text="", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate', length=120)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

        # -- load file if given
        if initial_file and os.path.exists(initial_file):
            self._load(initial_file)

    # ============================================================ object tab

    def _build_object_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        w = ttk.Label(top, text=L("search.placeholder")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.placeholder"))
        self.obj_search_var = tk.StringVar()
        self.obj_search_var.trace_add('write', lambda *a: self._do_obj_search())
        e = ttk.Entry(top, textvariable=self.obj_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        w = ttk.Label(top, text=L("search.hint_objects")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.hint_objects"))
        self.obj_count_label = ttk.Label(top, text="")
        self.obj_count_label.pack(side=tk.RIGHT, padx=5)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.OBJ_COLS
        self.obj_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                     selectmode='extended')
        for col in c:
            self.obj_tree.heading(col, text=L("col." + col), command=lambda _c=col: self._sort(self.obj_tree, _c, False))
            self.obj_tree.column(col, width=120, minwidth=60)
        self.obj_tree.column("name", width=180)
        self.obj_tree.column("comments", width=200)
        self.obj_tree.column("_objtype", width=100)
        self.obj_tree._col_lang_key = "col."  # marker for language refresh

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
            self.obj_count_label.config(text=L("search.count_objects", n=len(self.all_objects)))
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
        self.obj_count_label.config(text=L("search.count_matched", n=len(matched), total=len(self.all_objects)))

    def _obj_vals(self, o):
        def _fmt(v):
            if isinstance(v, dict):
                return v.get('name', '') or str(v)
            if isinstance(v, (int, float)):
                return str(v)
            return v if v else ''
        return tuple(_fmt(o.get(c)) for c in self.OBJ_COLS)

    def _obj_matches(self, o, term):
        def _fmt(v):
            if isinstance(v, dict):
                return v.get('name', '') or str(v)
            if isinstance(v, (int, float)):
                return str(v)
            return v if v else ''
        fields = [_fmt(o.get(k)) for k in ('name', 'ip-address', 'subnet', 'comments',
                                            'category', '_objtype')]
        return any(match_pattern(f, term) for f in fields)

    def _obj_detail(self, event):
        sel = self.obj_tree.selection()
        if not sel:
            return
        item = self.obj_tree.item(sel[0])
        vals = {c: v for c, v in zip(self.OBJ_COLS, item['values'])}
        msg = json.dumps(vals, indent=2, ensure_ascii=False)
        messagebox.showinfo(L("detail.object"), msg)

    # ============================================================ rule tab

    def _build_rule_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        w = ttk.Label(top, text=L("search.placeholder")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.placeholder"))
        self.rule_search_var = tk.StringVar()
        self.rule_search_var.trace_add('write', lambda *a: self._do_rule_search())
        e = ttk.Entry(top, textvariable=self.rule_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        w = ttk.Label(top, text=L("search.hint_rules")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.hint_rules"))
        self.rule_count_label = ttk.Label(top, text="")
        self.rule_count_label.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        w = ttk.Button(btn_frame, text=L("export.all_csv"),
                   command=self._export_rule_all); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.all_csv"))
        w = ttk.Button(btn_frame, text=L("export.searched_csv"),
                   command=self._export_rule_searched); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.searched_csv"))
        self.split_var = tk.BooleanVar()
        self.split_groups_var = tk.BooleanVar()
        w = ttk.Checkbutton(btn_frame, text=L("split.split"), variable=self.split_var,
                        command=self._do_rule_search); w.pack(side=tk.LEFT, padx=5)
        self._lang_widgets.append((w, "split.split"))
        w = ttk.Checkbutton(btn_frame, text=L("split.groups"), variable=self.split_groups_var,
                        command=self._do_rule_search); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "split.groups"))

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.RULE_COLS
        self.rule_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                      selectmode='extended')
        for col in c:
            self.rule_tree.heading(col, text=L("col." + col), command=lambda _c=col: self._sort(self.rule_tree, _c, False))
            self.rule_tree.column(col, width=110, minwidth=60)
        self.rule_tree.column("rule-id", width=160)
        self.rule_tree.column("name", width=220)
        self.rule_tree.column("source", width=220)
        self.rule_tree.column("destination", width=220)
        self.rule_tree.column("source-ips", width=180)
        self.rule_tree.column("destination-ips", width=180)
        self.rule_tree.column("service-ports", width=150)
        self.rule_tree.column("comments", width=200)
        self.rule_tree._col_lang_key = "col."

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
        self.rule_count_label.config(text=L("search.count_rules", n=count, total=total) if raw else L("search.count_total_rules", n=total))

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
            messagebox.showinfo(L("export.title"), L("export.no_data"))
            return
        path = filedialog.asksaveasfilename(
            title=L("export.save_title"),
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[(L("export.filter_csv"), "*.csv"), (L("export.filter_all"), "*.*")])
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            messagebox.showinfo(L("export.title"), L("export.exported", count=len(rows), path=os.path.basename(path)))
        except Exception as e:
            messagebox.showerror(L("export.error"), str(e))

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
        messagebox.showinfo(L("detail.rule"), msg)

    # ============================================================ NAT tab

    def _build_nat_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        w = ttk.Label(top, text=L("search.placeholder")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.placeholder"))
        self.nat_search_var = tk.StringVar()
        self.nat_search_var.trace_add('write', lambda *a: self._do_nat_search())
        e = ttk.Entry(top, textvariable=self.nat_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        w = ttk.Label(top, text=L("search.hint_rules")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.hint_rules"))
        self.nat_count_label = ttk.Label(top, text="")
        self.nat_count_label.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        w = ttk.Button(btn_frame, text=L("export.all_csv"),
                   command=self._export_nat_all); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.all_csv"))
        w = ttk.Button(btn_frame, text=L("export.searched_csv"),
                   command=self._export_nat_searched); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.searched_csv"))

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.NAT_COLS
        self.nat_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                     selectmode='extended')
        for col in c:
            self.nat_tree.heading(col, text=L("col." + col), command=lambda _c=col: self._sort(self.nat_tree, _c, False))
            self.nat_tree.column(col, width=120, minwidth=60)
        self.nat_tree.column("rule-id", width=160)
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
        self.nat_tree._col_lang_key = "col."
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
            self.nat_count_label.config(text=L("search.count_nat", n=len(self.all_nat_rules)))
            for r in self.all_nat_rules:
                self.nat_tree.insert('', tk.END,
                                     values=tuple(flatten_nat_for_display(r, self.lookup).values()))
            return

        matched = self._eval_nat_query(raw)
        for r in matched:
            self.nat_tree.insert('', tk.END,
                                 values=tuple(flatten_nat_for_display(r, self.lookup).values()))
        self.nat_count_label.config(text=L("search.count_matched", n=len(matched), total=len(self.all_nat_rules)))

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
        messagebox.showinfo(L("detail.nat"), msg)

    # ============================================================ proxy tab

    def _build_proxy_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, padx=5, pady=5)
        w = ttk.Label(top, text=L("search.placeholder")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.placeholder"))
        self.proxy_search_var = tk.StringVar()
        self.proxy_search_var.trace_add('write', lambda *a: self._do_proxy_search())
        e = ttk.Entry(top, textvariable=self.proxy_search_var, width=60)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        w = ttk.Label(top, text=L("search.hint_rules")); w.pack(side=tk.LEFT)
        self._lang_widgets.append((w, "search.hint_rules"))
        self.proxy_count_label = ttk.Label(top, text="")
        self.proxy_count_label.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        w = ttk.Button(btn_frame, text=L("export.all_csv"),
                   command=self._export_proxy_all); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.all_csv"))
        w = ttk.Button(btn_frame, text=L("export.searched_csv"),
                   command=self._export_proxy_searched); w.pack(side=tk.LEFT, padx=2)
        self._lang_widgets.append((w, "export.searched_csv"))

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        c = self.PROXY_COLS
        self.proxy_tree = ttk.Treeview(tree_frame, columns=c, show='headings',
                                       selectmode='extended')
        for col in c:
            self.proxy_tree.heading(col, text=L("col." + col), command=lambda _c=col: self._sort(self.proxy_tree, _c, False))
            self.proxy_tree.column(col, width=120, minwidth=60)
        self.proxy_tree.column("rule-id", width=160)
        self.proxy_tree.column("name", width=200)
        self.proxy_tree.column("source", width=180)
        self.proxy_tree.column("destination", width=180)
        self.proxy_tree.column("redirect-url", width=200)
        self.proxy_tree.column("comments", width=200)
        self.proxy_tree._col_lang_key = "col."

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.proxy_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.proxy_tree.xview)
        self.proxy_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.proxy_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.proxy_tree.bind("<Double-1>", self._proxy_detail)

    def _do_proxy_search(self):
        self.proxy_tree.delete(*self.proxy_tree.get_children())
        raw = self.proxy_search_var.get().strip()
        if not raw or not self.all_proxy_rules:
            self.proxy_count_label.config(text=L("search.count_proxy", n=len(self.all_proxy_rules)))
            for r in self.all_proxy_rules:
                self.proxy_tree.insert('', tk.END,
                                       values=tuple(flatten_proxy_for_display(r, self.lookup).values()))
            return

        matched = self._eval_proxy_query(raw)
        for r in matched:
            self.proxy_tree.insert('', tk.END,
                                   values=tuple(flatten_proxy_for_display(r, self.lookup).values()))
        self.proxy_count_label.config(text=L("search.count_matched", n=len(matched), total=len(self.all_proxy_rules)))

    def _eval_proxy_query(self, raw):
        def _clause_matches(rule, clause):
            clause = clause.strip()
            flat = flatten_proxy_for_display(rule, self.lookup)
            if ':' not in clause:
                for field in ('name', 'proxy-type', 'source', 'destination',
                              'webproxy-profile', 'redirect-url', 'comments'):
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
            for rule in self.all_proxy_rules:
                if all(_clause_matches(rule, c) for c in and_parts):
                    results.append(rule)
        return results

    def _get_matching_proxy(self):
        all_flat = [flatten_proxy_for_display(r, self.lookup) for r in self.all_proxy_rules]
        raw = self.proxy_search_var.get().strip()
        if not raw:
            return all_flat, all_flat
        matched = self._eval_proxy_query(raw)
        matched_set = set(id(r) for r in matched)
        searched = [flatten_proxy_for_display(r, self.lookup)
                    for r in self.all_proxy_rules if id(r) in matched_set]
        return all_flat, searched

    def _export_proxy_all(self):
        all_flat, _ = self._get_matching_proxy()
        self._export_to_csv(all_flat, "proxy_all.csv")

    def _export_proxy_searched(self):
        _, searched = self._get_matching_proxy()
        self._export_to_csv(searched, "proxy_searched.csv")

    def _proxy_detail(self, event):
        sel = self.proxy_tree.selection()
        if not sel:
            return
        item = self.proxy_tree.item(sel[0])
        vals = {c: v for c, v in zip(self.PROXY_COLS, item['values'])}
        msg = json.dumps(vals, indent=2, ensure_ascii=False)
        messagebox.showinfo(L("detail.proxy"), msg)

    # ============================================================ status / progress

    def _set_status(self, text):
        self.status_label.config(text=text)
        self.root.update_idletasks()

    def _show_progress(self, visible=True):
        if visible:
            self.progress_bar.pack(side=tk.RIGHT, padx=5)
            self.progress_bar.start(10)
        else:
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
        self.root.update_idletasks()

    # ============================================================ language

    def _highlight_lang(self, code):
        for c, btn in self._lang_btns.items():
            btn.config(relief=tk.SUNKEN if c == code else tk.RAISED)

    def _select_language(self, code):
        if not self.root.winfo_exists():
            return
        if code == L.code:
            return
        set_language(code)
        self._highlight_lang(code)
        self._apply_language()
        update_settings({"language": code})

    def _apply_language(self):
        def _u(w, key=None, **kwargs):
            try:
                if key:
                    w.config(text=L(key, **kwargs))
                elif kwargs:
                    w.config(**kwargs)
            except tk.TclError:
                pass

        _u(self.root, title=L("app.title"))
        _u(self.banner_title, "banner.title")
        _u(self.banner_sub, "banner.subtitle")
        for w, key in self._lang_widgets:
            _u(w, key)
        try:
            self.filemenu.entryconfig(0, label=L("menu.open"))
            self.filemenu.entryconfig(2, label=L("menu.exit"))
            self.menubar.entryconfig(0, label=L("menu.file"))
        except tk.TclError:
            pass
        try:
            self.nb.tab(0, text=L("tab.objects"))
            self.nb.tab(1, text=L("tab.rules"))
            self.nb.tab(2, text=L("tab.nat"))
            self.nb.tab(3, text=L("tab.proxy"))
        except tk.TclError:
            pass
        self._do_obj_search()
        self._do_rule_search()
        self._do_nat_search()
        self._do_proxy_search()
        for tree in (self.obj_tree, self.rule_tree, self.nat_tree, self.proxy_tree):
            try:
                prefix = getattr(tree, '_col_lang_key', '')
                if prefix:
                    for cid in tree['columns']:
                        tree.heading(cid, text=L(prefix + cid))
            except tk.TclError:
                pass

    # ============================================================ quit / persist

    def _on_quit(self):
        update_settings({
            "timeout": self.timeout,
            "page_size": self.page_size,
            "download_dir": self.download_dir,
            "log_level": self.log_level_name,
            "language": L.code,
        })
        logging.info("GUI shutting down")
        self.root.quit()
        self.root.destroy()

    # ============================================================ settings dialog

    def _settings_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title(L("settings.title"))
        dlg.geometry("500x390")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        cf = ttk.LabelFrame(dlg, text=L("settings.api"), padding=10)
        cf.pack(fill=tk.X, padx=10, pady=(10, 0))

        ttk.Label(cf, text=L("settings.page_size")).grid(row=0, column=0, sticky=tk.W, pady=4)
        ps_var = tk.IntVar(value=self.page_size)
        ttk.Scale(cf, from_=50, to=1000, variable=ps_var, orient=tk.HORIZONTAL).grid(row=0, column=1, padx=8, pady=4, sticky=tk.EW)
        ttk.Label(cf, textvariable=ps_var, width=4).grid(row=0, column=2, padx=2, pady=4)

        ttk.Label(cf, text=L("settings.timeout")).grid(row=1, column=0, sticky=tk.W, pady=4)
        to_var = tk.IntVar(value=self.timeout)
        ttk.Scale(cf, from_=30, to=600, variable=to_var, orient=tk.HORIZONTAL).grid(row=1, column=1, padx=8, pady=4, sticky=tk.EW)
        ttk.Label(cf, textvariable=to_var, width=4).grid(row=1, column=2, padx=2, pady=4)

        cf.columnconfigure(1, weight=1)

        # -- log settings
        lf = ttk.LabelFrame(dlg, text=L("settings.logging"), padding=10)
        lf.pack(fill=tk.X, padx=10, pady=(10, 0))

        ttk.Label(lf, text=L("settings.log_level")).grid(row=0, column=0, sticky=tk.W, pady=4)
        lvl_var = tk.StringVar(value=self.log_level_name)
        lvl_combo = ttk.Combobox(lf, textvariable=lvl_var,
                                  values=["DEBUG", "INFO", "WARNING", "ERROR"],
                                  state="readonly", width=16)
        lvl_combo.grid(row=0, column=1, sticky=tk.W, padx=8, pady=4)

        ttk.Label(lf, text=L("settings.download_dir")).grid(row=1, column=0, sticky=tk.W, pady=4)
        dd_var = tk.StringVar(value=self.download_dir)
        ttk.Entry(lf, textvariable=dd_var, width=50).grid(row=1, column=1, padx=8, pady=4, sticky=tk.EW)
        lf.columnconfigure(1, weight=1)

        reset_log_btn = ttk.Button(lf, text=L("settings.reset_log"))
        reset_log_btn.grid(row=3, column=0, columnspan=2, pady=6)

        def _do_reset_log():
            reset_log()
            messagebox.showinfo(L("settings.log_reset_title"), L("settings.log_reset_ok"), parent=dlg)

        reset_log_btn.config(command=_do_reset_log)

        def _apply():
            self.page_size = ps_var.get()
            self.timeout = to_var.get()
            old_level = self.log_level_name
            self.log_level_name = lvl_var.get()
            self.download_dir = dd_var.get().strip() or "examples"
            if self.log_level_name != old_level:
                setup_logging(self.log_level_name)
                logging.info("Log level changed to %s", self.log_level_name)
            settings = {
                "timeout": self.timeout,
                "page_size": self.page_size,
                "download_dir": self.download_dir,
                "log_level": self.log_level_name,
                "language": L.code,
            }
            update_settings(settings)
            dlg.destroy()

        bf = ttk.Frame(dlg)
        bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text=L("settings.apply"), command=_apply).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text=L("settings.cancel"), command=dlg.destroy).pack(side=tk.RIGHT, padx=2)

    # ============================================================ download dialog

    def _download_dialog(self):
        """Open a dialog to download policy from a live firewall."""
        if not HAS_FETCH:
            messagebox.showerror(L("export.error"), L("open.no_fetch"))
            return

        settings = load_settings()

        dlg = tk.Toplevel(self.root)
        dlg.title(L("dlg.title"))
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(True, True)
        dlg.geometry("1000x700")

        # ================================================================= top half: fields (left) + progress (right)
        top_frame = ttk.Frame(dlg)
        top_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        top_group = ttk.LabelFrame(top_frame, text=L("dlg.connection"), padding=5)
        top_group.pack(fill=tk.BOTH, expand=True)
        top_group.columnconfigure(0, weight=0)
        top_group.columnconfigure(1, weight=1)
        top_group.rowconfigure(0, weight=1)

        # -- left: connection fields
        cf = ttk.Frame(top_group)
        cf.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 8))
        cf.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(cf, text=L("dlg.server")).grid(row=row, column=0, sticky=tk.W, pady=1)
        server_var = tk.StringVar(value=settings.get("last_server") or "192.168.1.1")
        ttk.Entry(cf, textvariable=server_var, width=30).grid(row=row, column=1, padx=4, pady=1, sticky=tk.EW)
        row += 1

        ttk.Label(cf, text=L("dlg.username")).grid(row=row, column=0, sticky=tk.W, pady=1)
        user_var = tk.StringVar(value=settings.get("last_username") or "admin")
        ttk.Entry(cf, textvariable=user_var, width=30).grid(row=row, column=1, padx=4, pady=1, sticky=tk.EW)
        row += 1

        ttk.Label(cf, text=L("dlg.password")).grid(row=row, column=0, sticky=tk.W, pady=1)
        pass_var = tk.StringVar()
        ttk.Entry(cf, textvariable=pass_var, width=30, show="*").grid(row=row, column=1, padx=4, pady=1, sticky=tk.EW)
        row += 1

        ttk.Label(cf, text=L("dlg.port")).grid(row=row, column=0, sticky=tk.W, pady=1)
        pf = ttk.Frame(cf); pf.grid(row=row, column=1, sticky=tk.W, padx=4, pady=1)
        port_var = tk.StringVar(value=str(settings.get("last_port", 443)))
        ttk.Entry(pf, textvariable=port_var, width=8).pack(side=tk.LEFT)
        ssl_var = tk.BooleanVar(value=settings.get("last_verify_ssl", False))
        ttk.Checkbutton(pf, text=L("dlg.verify_ssl"), variable=ssl_var).pack(side=tk.LEFT, padx=8)
        row += 1

        ttk.Label(cf, text=L("dlg.timeout")).grid(row=row, column=0, sticky=tk.W, pady=1)
        timeout_var = tk.StringVar(value=str(self.timeout))
        ttk.Entry(cf, textvariable=timeout_var, width=8).grid(row=row, column=1, sticky=tk.W, padx=4, pady=1)
        row += 1

        ttk.Label(cf, text=L("dlg.page_size")).grid(row=row, column=0, sticky=tk.W, pady=1)
        page_size_var = tk.StringVar(value=str(self.page_size))
        ttk.Entry(cf, textvariable=page_size_var, width=8).grid(row=row, column=1, sticky=tk.W, padx=4, pady=1)
        row += 1

        ttk.Label(cf, text=L("dlg.vendor")).grid(row=row, column=0, sticky=tk.W, pady=1)
        vendor_var = tk.StringVar(value=settings.get("last_vendor", "auto"))
        vendor_combo = ttk.Combobox(cf, textvariable=vendor_var,
                                    values=["auto", "checkpoint", "paloalto", "fortinet"],
                                    state="readonly", width=18)
        vendor_combo.grid(row=row, column=1, sticky=tk.W, padx=4, pady=1)
        row += 1

        ttk.Label(cf, text=L("dlg.output_dir")).grid(row=row, column=0, sticky=tk.W, pady=1)
        out_dir_var = tk.StringVar(value=settings.get("last_output_dir", self.download_dir))
        ttk.Entry(cf, textvariable=out_dir_var).grid(row=row, column=1, padx=4, pady=1, sticky=tk.EW)
        row += 1

        # policy name + action buttons row
        br = ttk.Frame(cf); br.grid(row=row, column=0, columnspan=2, pady=4, sticky=tk.EW)
        ttk.Button(br, text=L("dlg.select_all"), command=lambda: [cb[1].set(True) for cb in layer_checkboxes]).pack(side=tk.LEFT, padx=1)
        ttk.Button(br, text=L("dlg.clear_all"), command=lambda: [cb[1].set(False) for cb in layer_checkboxes]).pack(side=tk.LEFT, padx=1)
        ttk.Label(br, text=L("dlg.policy_name")).pack(side=tk.LEFT, padx=(10, 2))
        pkg_var = tk.StringVar(value=settings.get("last_policy_name", "fetched_policy"))
        ttk.Entry(br, textvariable=pkg_var, width=15).pack(side=tk.LEFT, padx=1)
        ttk.Label(br, text="").pack(side=tk.LEFT, fill=tk.X, expand=True)
        connect_btn = ttk.Button(br, text=L("dlg.connect"))
        connect_btn.pack(side=tk.LEFT, padx=1)
        download_btn = ttk.Button(br, text=L("dlg.download_btn"), state=tk.DISABLED)
        download_btn.pack(side=tk.LEFT, padx=1)
        ttk.Button(br, text=L("dlg.cancel"), command=dlg.destroy).pack(side=tk.LEFT, padx=1)

        # -- right: progress panel
        pf_outer = ttk.LabelFrame(top_group, text=L("dlg.progress"), padding=5)
        pf_outer.grid(row=0, column=1, sticky=tk.NSEW)
        pf_outer.rowconfigure(0, weight=1)
        pf_outer.columnconfigure(0, weight=1)

        progress_text = tk.Text(pf_outer, width=48, height=14, wrap=tk.WORD,
                                state=tk.DISABLED, font=("Consolas", 9))
        progress_text.grid(row=0, column=0, sticky=tk.NSEW)

        progress_bar = ttk.Progressbar(pf_outer, mode='indeterminate', length=120)
        progress_bar.grid(row=1, column=0, sticky=tk.EW, pady=(2, 0))

        def _start_spinner():
            progress_bar.start(10)

        def _stop_spinner():
            progress_bar.stop()

        def _log_progress(msg):
            progress_text.config(state=tk.NORMAL)
            progress_text.insert(tk.END, f"  {msg}\n")
            progress_text.see(tk.END)
            progress_text.config(state=tk.DISABLED)
            dlg.update()

        # -- middle: layers frame
        lf = ttk.LabelFrame(dlg, text=L("dlg.layers_frame"), padding=10)
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=2)

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

        # -- bottom: big status bar with log
        status_frame = ttk.LabelFrame(dlg, text=L("dlg.status"), padding=2)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

        status_var = tk.StringVar(value=L("dlg.status_connect"))
        status_label = ttk.Label(status_frame, textvariable=status_var, relief=tk.SUNKEN, anchor=tk.W, font=("", 10))
        status_label.pack(fill=tk.X)
        log_label = ttk.Label(status_frame, text="", anchor=tk.W, font=("Consolas", 8), foreground="gray")
        log_label.pack(fill=tk.X)

        layer_checkboxes = []
        _client_ref = [None]

        def _save_last_connection():
            update_settings({
                "last_server": server_var.get().strip(),
                "last_username": user_var.get().strip(),
                "last_port": int(port_var.get().strip() or 443),
                "last_vendor": vendor_var.get().strip().lower(),
                "last_verify_ssl": ssl_var.get(),
                "last_policy_name": pkg_var.get().strip() or "fetched_policy",
                "last_output_dir": out_dir_var.get().strip() or "examples",
            })

        def _update_status(msg, log=None):
            status_var.set(msg)
            if log:
                log_label.config(text=log)
            dlg.update()

        def _do_connect():
            connect_btn.config(state=tk.DISABLED)
            _start_spinner()
            _update_status(L("dlg.connecting"))

            server = server_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get()
            try:
                port = int(port_var.get().strip())
            except ValueError:
                _stop_spinner()
                _update_status(L("dlg.invalid_port"))
                connect_btn.config(state=tk.NORMAL)
                return

            try:
                timeout = int(timeout_var.get().strip())
            except ValueError:
                _stop_spinner()
                _update_status(L("dlg.invalid_timeout"))
                connect_btn.config(state=tk.NORMAL)
                return

            try:
                page_size = int(page_size_var.get().strip())
            except ValueError:
                _stop_spinner()
                _update_status(L("dlg.invalid_pagesize"))
                connect_btn.config(state=tk.NORMAL)
                return

            if not server or not username:
                _stop_spinner()
                _update_status(L("dlg.need_credentials"))
                connect_btn.config(state=tk.NORMAL)
                return

            vendor = vendor_var.get().strip().lower()
            if vendor == "auto":
                vendor = None

            is_checkpoint = (vendor is None or vendor == "checkpoint")

            _save_last_connection()

            try:
                if is_checkpoint:
                    _log_progress(L("dlg.progress.connecting", server=server, port=port, username=username))
                    _update_status(L("dlg.connecting"))
                    client = CheckpointAPIClient(server, username, password,
                                                  port=port, verify=ssl_var.get(),
                                                  timeout=timeout, page_size=page_size)
                    _client_ref[0] = client
                    logging.info("Connected to %s as %s (Checkpoint)", server, username)
                    _log_progress(L("dlg.progress.connected_layers"))
                    _update_status(L("dlg.fetching_layers"))
                    dlg.update()
                    layer_names = client.fetch_layers()
                    _log_progress(L("dlg.progress.layers_found", count=len(layer_names)))
                    for cb in layer_checkboxes:
                        cb[0].destroy()
                    layer_checkboxes.clear()
                    if not layer_names:
                        _update_status(L("dlg.no_layers"))
                        connect_btn.config(state=tk.NORMAL)
                        return
                    for ln in layer_names:
                        var = tk.BooleanVar(value=True)
                        cb = ttk.Checkbutton(layer_inner, text=ln, variable=var)
                        cb.pack(anchor=tk.W, padx=5, pady=1)
                        layer_checkboxes.append((cb, var))
                    download_btn.config(state=tk.NORMAL)
                    _update_status(L("dlg.layers_found", count=len(layer_names)))
                else:
                    # PA / FortiGate: fetch all directly
                    from fetch_policy import fetch_policy as _fp
                    _log_progress(L("dlg.progress.fetching_policy", server=server, vendor=vendor or "auto"))
                    logging.info("Fetching policy from %s (%s)", server, vendor or "auto")
                    data = _fp(server, port, username, password, vendor=vendor, verify=ssl_var.get(), timeout=timeout, page_size=page_size, package=pkg_var.get().strip() or None)
                    _log_progress(L("dlg.progress.fetched_saving"))
                    _stop_spinner()
                    ok = _save_and_load_download(data, dlg, status_var)
                    if not ok:
                        connect_btn.config(state=tk.NORMAL)
                    return

            except (SystemExit, Exception) as e:
                _stop_spinner()
                msg = str(e).strip() or L("dlg.error_connection")
                logging.error("Connection error: %s", msg)
                _log_progress(L("dlg.progress.error", msg=msg))
                _update_status(L("dlg.error_prefix", msg=msg))
                connect_btn.config(state=tk.NORMAL)
                return

            _stop_spinner()
            connect_btn.config(state=tk.NORMAL)

        def _make_default_filename(server, pkg_name):
            safe_server = server.replace(":", "_").replace("/", "_").replace(" ", "_")
            safe_pkg = pkg_name.replace(" ", "_").replace("/", "_")
            date_str = time.strftime("%Y%m%d-%H%M%S")
            return f"{safe_server}_{safe_pkg}_{date_str}.json"

        def _save_and_load_download(data, original_dlg, status_var):
            status_var.set(L("dlg.sanitizing"))
            original_dlg.update()
            data = _sanitize(data)
            default_name = _make_default_filename(server_var.get().strip(), pkg_var.get().strip() or "fetched_policy")
            out_dir = out_dir_var.get().strip() or self.download_dir
            if not os.path.exists(out_dir):
                os.makedirs(out_dir, exist_ok=True)
            status_var.set(L("dlg.saving"))
            original_dlg.update()
            save_path = filedialog.asksaveasfilename(
                title=L("dlg.save_title"),
                initialdir=os.path.abspath(out_dir),
                initialfile=default_name,
                defaultextension=".json",
                filetypes=[(L("export.filter_json"), "*.json"), (L("export.filter_all"), "*.*")])
            if not save_path:
                status_var.set(L("dlg.save_cancelled"))
                return False
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logging.info("Policy saved to %s", save_path)
            status_var.set(L("dlg.loading"))
            original_dlg.update()
            original_dlg.destroy()
            self._load(save_path)
            return True

        def _do_download():
            selected = [ln for (_, var), ln in zip(layer_checkboxes,
                         [cb[0].cget("text") for cb in layer_checkboxes]) if var.get()]
            pkg_name = pkg_var.get().strip() or "fetched_policy"

            if not selected:
                if pkg_name and _client_ref[0]:
                    selected = [pkg_name]
                else:
                    _update_status(L("dlg.need_layer"))
                    return

            download_btn.config(state=tk.DISABLED)
            connect_btn.config(state=tk.DISABLED)
            _start_spinner()
            client = _client_ref[0]
            if not client:
                _update_status(L("dlg.not_connected"))
                return

            try:
                _update_status(L("dlg.fetch_rules"))
                layers_data = []
                for i, ln in enumerate(selected):
                    _log_progress(L("dlg.progress.layer", n=i+1, total=len(selected), name=ln))
                    _update_status(L("dlg.fetch_layer_n", n=i+1, total=len(selected), name=ln))
                    logging.info("Fetching rulebase: %s", ln)
                    rb = client.fetch_rulebase(ln)
                    layer = {"name": ln, "uid": rb.get("uid", ""),
                             "rules": [], "inline-layers": []}
                    seen = set()
                    def _extract(items):
                        for item in items:
                            t = item.get("type", "")
                            uid = item.get("uid", "")
                            if uid in seen:
                                continue
                            seen.add(uid)
                            if t == "access-rule":
                                layer["rules"].append(item)
                            elif t == "inline-layer":
                                _extract(item.get("rulebase", []))
                                layer["inline-layers"].append(item)
                            elif t == "access-section":
                                _extract(item.get("rulebase", []))
                            else:
                                layer["rules"].append(item)
                    _extract(rb.get("rulebase", []))
                    layers_data.append(layer)

                _log_progress(L("dlg.progress.fetching_https"))
                _update_status(L("dlg.fetch_https"))
                try:
                    https_rules = client.fetch_https_inspection()
                    logging.info("HTTPS rules: %d", len(https_rules))
                except Exception as e:
                    logging.warning("HTTPS fetch failed: %s", e)
                    https_rules = []

                _log_progress(L("dlg.progress.fetching_threat"))
                _update_status(L("dlg.fetch_threat"))
                try:
                    threat_rules = client.fetch_threat_rulebase()
                    logging.info("Threat rules: %d", len(threat_rules))
                except Exception as e:
                    logging.warning("Threat fetch failed: %s", e)
                    threat_rules = []

                _log_progress(L("dlg.progress.fetching_objects"))
                _update_status(L("dlg.fetch_objects"))
                objects = client.fetch_all_objects()
                total_objs = sum(len(v) for v in objects.values())
                logging.info("Objects fetched: %d total across %d types", total_objs, len(objects))
                _log_progress(L("dlg.progress.objects_total", count=total_objs))

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

                _log_progress(L("dlg.progress.saving_loading"))
                _stop_spinner()
                ok = _save_and_load_download(data, dlg, status_var)
                if not ok:
                    download_btn.config(state=tk.NORMAL)
                    connect_btn.config(state=tk.NORMAL)
                    return
                try:
                    client.logout()
                    _log_progress(L("dlg.progress.logged_out"))
                    logging.info("Logged out from %s", server_var.get().strip())
                except Exception:
                    pass
                return

            except (SystemExit, Exception) as e:
                _stop_spinner()
                msg = str(e).strip() or L("dlg.error_download")
                logging.error("Download error: %s", msg)
                _log_progress(L("dlg.progress.error", msg=msg))
                _update_status(L("dlg.error_prefix", msg=msg))
                download_btn.config(state=tk.NORMAL)
                connect_btn.config(state=tk.NORMAL)
                return

        connect_btn.config(command=_do_connect)
        download_btn.config(command=_do_download)
        dlg.wait_window()

    def open_file(self):
        path = filedialog.askopenfilename(
            title=L("open.title"),
            filetypes=[(L("export.filter_json"), "*.json"), (L("export.filter_all"), "*.*")])
        if path:
            self._load(path)

    def _load(self, path):
        self._show_progress(True)
        self._set_status(os.path.basename(path))
        try:
            self.data = load_policy(path)
        except Exception as e:
            self._show_progress(False)
            messagebox.showerror(L("export.error"), L("open.load_error", e=e))
            return

        self.all_objects = collect_objects(self.data)
        self.lookup = _build_object_lookup(self.all_objects)
        self._build_group_lookup()
        self.all_rules = list(extract_rules(self.data))
        self.all_nat_rules = list(extract_nat_rules(self.data))
        self.all_proxy_rules = list(extract_proxy_rules(self.data))
        self.file_label.config(text=os.path.basename(path))
        self.root.title(L("app.title_file", name=os.path.basename(path)))
        self._do_obj_search()
        self._do_rule_search()
        self._do_nat_search()
        self._do_proxy_search()
        self._show_progress(False)
        self._set_status("")

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
