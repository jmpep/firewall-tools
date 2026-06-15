import json
import csv
import sys
import os
import argparse

class ObjectResolver:
    def __init__(self, objects_data):
        self._hosts = {}
        self._networks = {}
        self._groups = {}
        self._services = {}
        self._gateway_interfaces = {}
        self._load(objects_data)

    def _load(self, objects_data):
        if not objects_data:
            return
        for h in objects_data.get('hosts', []):
            self._hosts[h['name']] = h
            if h.get('type') == 'gateway' and 'interfaces' in h:
                self._gateway_interfaces[h['name']] = [
                    iface['ip-address'] for iface in h.get('interfaces', [])
                ]
        for n in objects_data.get('networks', []):
            self._networks[n['name']] = n
        for g in objects_data.get('groups', []):
            self._groups[g['name']] = g
        for s in objects_data.get('services', []):
            self._services[s['name']] = s

    def _resolve_ip(self, name):
        if name in self._hosts:
            h = self._hosts[name]
            ip = h.get('ip-address', '')
            if name in self._gateway_interfaces:
                return ', '.join(f"{ip}/32" for ip in self._gateway_interfaces[name])
            if ip:
                return f"{ip}/32"
        if name in self._networks:
            n = self._networks[name]
            subnet = n.get('subnet', '')
            mask = n.get('mask-length')
            if subnet and mask is not None:
                return f"{subnet}/{mask}"
        return None

    def resolve_with_name(self, obj_ref, _visited=None):
        name = obj_ref.get('name', '') if isinstance(obj_ref, dict) else str(obj_ref)
        if not name or name == 'Any':
            return name or 'Any'
        if _visited is None:
            _visited = set()
        if name in _visited:
            return f"<circular:{name}>"
        _visited.add(name)
        ip_str = self._resolve_ip(name)
        if ip_str:
            return f"{name} [{ip_str}]"
        if name in self._groups:
            members = self._groups[name].get('members', [])
            parts = [self.resolve_with_name(m, _visited) for m in members]
            return f"{name} [{' | '.join(parts)}]"
        return name

    def resolve_service(self, svc_ref):
        name = svc_ref.get('name', '') if isinstance(svc_ref, dict) else str(svc_ref)
        if not name or name == 'Any':
            return name or 'Any'
        if name in self._services:
            s = self._services[name]
            proto = s.get('protocol', '')
            if proto == 'tcp':
                return f"{name} [tcp/{s.get('port', '?')}]"
            elif proto == 'udp':
                return f"{name} [udp/{s.get('port', '?')}]"
            elif proto == 'icmp':
                return f"{name} [icmp type={s.get('icmp-type', '?')} code={s.get('icmp-code', '?')}]"
            return f"{name} [{proto}]"
        return name

    def resolve_ip_only(self, obj_ref):
        """Resolve to just the IP/CIDR string, or empty string."""
        name = obj_ref.get('name', '') if isinstance(obj_ref, dict) else str(obj_ref)
        if not name or name == 'Any':
            return name or 'Any'
        ip = self._resolve_ip(name)
        if ip:
            return ip
        if name in self._groups:
            members = self._groups[name].get('members', [])
            parts = [self.resolve_ip_only(m) for m in members]
            return ' | '.join(parts)
        return ''

    def resolve_port_only(self, svc_ref):
        """Resolve service to protocol/port string, or empty string."""
        name = svc_ref.get('name', '') if isinstance(svc_ref, dict) else str(svc_ref)
        if not name or name == 'Any':
            return name or 'Any'
        if name in self._services:
            s = self._services[name]
            proto = s.get('protocol', '')
            port = s.get('port', '')
            if proto and port:
                return f"{proto}/{port}"
            elif port:
                return str(port)
            elif proto == 'icmp':
                return f"icmp type={s.get('icmp-type', '?')} code={s.get('icmp-code', '?')}"
            return proto or ''
        return ''

    def expand_groups(self, rule):
        """Recursively replace group references with their individual members."""
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


def flatten_rule(rule, resolver):
    flat = {}
    flat['rule-number'] = rule.get('_rule-number') or rule.get('rule-number', '')
    flat['rule-id'] = rule.get('uid', '')
    flat['policy-name'] = rule.get('_policy-name', '')
    flat['rule-type'] = rule.get('_rule-type', '')
    enabled = rule.get('enabled', True)
    flat['enabled'] = enabled if isinstance(enabled, bool) else str(enabled)
    flat['status'] = 'Enabled' if enabled else 'Disabled'
    for key in ['name', 'comments', 'threat-name']:
        flat[key] = rule.get(key, '')
    action = rule.get('action', {})
    flat['action'] = action.get('name', '') if isinstance(action, dict) else str(action)
    track = rule.get('track', {})
    flat['track'] = track.get('type', '') if isinstance(track, dict) else str(track)
    for array_field in ('source', 'destination'):
        vals = rule.get(array_field, [])
        if isinstance(vals, list):
            flat[array_field] = '; '.join(resolver.resolve_with_name(v) for v in vals)
        else:
            flat[array_field] = str(vals)
    flat['source-ips'] = '; '.join(resolver.resolve_ip_only(v) for v in rule.get('source', []) if isinstance(v, dict)) if isinstance(rule.get('source'), list) else ''
    flat['destination-ips'] = '; '.join(resolver.resolve_ip_only(v) for v in rule.get('destination', []) if isinstance(v, dict)) if isinstance(rule.get('destination'), list) else ''
    services = rule.get('service', [])
    if isinstance(services, list):
        flat['service'] = '; '.join(resolver.resolve_service(s) for s in services)
        flat['service-ports'] = '; '.join(resolver.resolve_port_only(s) for s in services)
    else:
        flat['service'] = str(services)
        flat['service-ports'] = ''
    content = rule.get('content', [])
    flat['content'] = ', '.join(c.get('name', '') for c in content) if isinstance(content, list) else str(content)
    time_obj = rule.get('time', {})
    flat['time'] = time_obj.get('name', '') if isinstance(time_obj, dict) else str(time_obj)
    user_obj = rule.get('user', {})
    flat['user'] = user_obj.get('name', '') if isinstance(user_obj, dict) else str(user_obj)
    install = rule.get('install-on', {})
    flat['install-on'] = install.get('name', '') if isinstance(install, dict) else str(install)
    inline = rule.get('inline-layer', {})
    flat['inline-layer'] = inline.get('name', '') if isinstance(inline, dict) else str(inline)
    threat_cat = rule.get('threat-category', [])
    flat['threat-category'] = ', '.join(threat_cat) if isinstance(threat_cat, list) else str(threat_cat)
    site_cat = rule.get('site-category', [])
    flat['site-category'] = ', '.join(site_cat) if isinstance(site_cat, list) else str(site_cat)
    cert = rule.get('certificate', {})
    flat['certificate'] = cert.get('name', '') if isinstance(cert, dict) else str(cert)
    flat['uid'] = rule.get('uid', '')
    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}
    flat['hits'] = hm.get('hits', '') if isinstance(hm, dict) else ''
    flat['creation-time'] = meta.get('creation-time', {}).get('iso', '') if isinstance(meta.get('creation-time'), dict) else ''
    flat['last-modified'] = meta.get('last-modified', {}).get('iso', '') if isinstance(meta.get('last-modified'), dict) else ''
    flat['_layer'] = rule.get('_layer', '')
    return flat


def flatten_nat_rule(rule, resolver):
    flat = {}
    flat['rule-number'] = rule.get('rule-number', '')
    flat['rule-id'] = rule.get('uid', '')
    flat['name'] = rule.get('name', '')
    flat['status'] = 'Enabled' if rule.get('enabled') is not False else 'Disabled'
    flat['method'] = rule.get('method', '')
    action = rule.get('action', {})
    flat['action'] = action.get('name', '') if isinstance(action, dict) else str(action)
    install = rule.get('install-on', {})
    flat['install-on'] = install.get('name', '') if isinstance(install, dict) else str(install)
    flat['comments'] = rule.get('comments', '')
    _SVC_FIELDS = {'original-service', 'translated-service'}
    _HOST_FIELDS = {'original-source', 'original-destination', 'translated-source', 'translated-destination'}
    for nf in ('original-source', 'original-destination', 'original-service',
               'translated-source', 'translated-destination', 'translated-service'):
        vals = rule.get(nf, [])
        if isinstance(vals, list):
            resolved = []
            for v in vals:
                name = v.get('name', '') if isinstance(v, dict) else str(v)
                if name in ('Original', 'Any'):
                    resolved.append(name)
                else:
                    ip = resolver.resolve_with_name(v)
                    resolved.append(ip)
            flat[nf] = '; '.join(resolved)
        else:
            flat[nf] = str(vals)

    # IP and port sub-columns for NAT
    for nf in _HOST_FIELDS:
        vals = rule.get(nf, [])
        if isinstance(vals, list):
            flat[f'{nf}-ips'] = '; '.join(
                resolver.resolve_ip_only(v) for v in vals if isinstance(v, dict)
                and v.get('name', '') not in ('Original', 'Any'))
        else:
            flat[f'{nf}-ips'] = ''
    for nf in _SVC_FIELDS:
        vals = rule.get(nf, [])
        if isinstance(vals, list):
            flat[f'{nf}-ports'] = '; '.join(
                resolver.resolve_port_only(v) for v in vals if isinstance(v, dict)
                and v.get('name', '') not in ('Original', 'Any'))
        else:
            flat[f'{nf}-ports'] = ''
    flat['uid'] = rule.get('uid', '')
    meta = rule.get('meta-info', {}) or {}
    hm = rule.get('hits', {}) or {}
    flat['hits'] = hm.get('hits', '') if isinstance(hm, dict) else ''
    flat['creation-time'] = meta.get('creation-time', {}).get('iso', '') if isinstance(meta.get('creation-time'), dict) else ''
    flat['last-modified'] = meta.get('last-modified', {}).get('iso', '') if isinstance(meta.get('last-modified'), dict) else ''
    return flat


def _layer_type(layer_name):
    name_lower = layer_name.lower()
    if 'threat' in name_lower:
        return 'threat-prevention'
    if 'application' in name_lower or 'url filtering' in name_lower or 'appctrl' in name_lower:
        return 'app-control'
    if 'content filtering' in name_lower or 'content' in name_lower:
        return 'inline'
    return 'access'


def extract_rules(data):
    entries = []
    try:
        layers = data['policy-package']['access-control-policy']['layers']
        policy_name = data['policy-package']['name']
    except (KeyError, TypeError):
        print("Error: JSON path 'policy-package > access-control-policy > layers' not found.")
        sys.exit(1)

    for layer in layers:
        layer_name = layer.get('name', 'Unknown Layer')
        base_type = _layer_type(layer_name)

        # Build inline layer lookup
        inline_by_name = {}
        for inline in layer.get('inline-layers', []):
            inline_by_name[inline['name']] = inline
        used_inline = set()

        # Iterate over rules; inject inline children under their parent
        for rule in layer.get('rules', []):
            rule_num = rule.get('rule-number', '')
            rule['_layer'] = layer_name
            rule['_rule-type'] = base_type
            rule['_policy-name'] = policy_name
            entries.append(rule)

            # Check for referenced inline layer
            inline_ref = rule.get('inline-layer', {})
            inline_name = inline_ref.get('name', '') if isinstance(inline_ref, dict) else ''
            if inline_name and inline_name in inline_by_name:
                used_inline.add(inline_name)
                inline = inline_by_name[inline_name]
                inline_type = _layer_type(inline_name)
                for i, irule in enumerate(inline.get('rules', []), 1):
                    irule['_layer'] = f"{layer_name} > {inline_name}"
                    irule['_rule-number'] = f"{rule_num}.{i}"
                    irule['_rule-type'] = inline_type
                    irule['_policy-name'] = policy_name
                    entries.append(irule)

        # Append any inline layers not referenced by any rule
        for inline_name, inline in inline_by_name.items():
            if inline_name not in used_inline:
                inline_type = _layer_type(inline_name)
                for irule in inline.get('rules', []):
                    irule['_layer'] = f"{layer_name} > {inline_name} (unlinked)"
                    irule['_rule-type'] = inline_type
                    irule['_policy-name'] = policy_name
                    entries.append(irule)

    # HTTPS inspection rules
    https = data.get('policy-package', {}).get('https-inspection-policy', {}).get('rules', [])
    for r in https:
        r['_layer'] = 'HTTPS Inspection'
        r['_rule-type'] = 'https-inspection'
        r['_policy-name'] = policy_name
        entries.append(r)

    return entries


def _split_rows(flat_rules, fields_wanted):
    """Expand rules with multiple sources/destinations into one row per pair."""
    expanded = []
    for rule in flat_rules:
        src_raw = rule.get('source', '')
        dst_raw = rule.get('destination', '')
        src_list = [s.strip() for s in src_raw.split(';')] if src_raw and src_raw != 'Any' else [src_raw]
        dst_list = [d.strip() for d in dst_raw.split(';')] if dst_raw and dst_raw != 'Any' else [dst_raw]

        if len(src_list) == 1 and len(dst_list) == 1:
            expanded.append(rule)
        else:
            for src in src_list:
                for dst in dst_list:
                    r = dict(rule)
                    r['source'] = src
                    r['destination'] = dst
                    expanded.append(r)
    return expanded


def main():
    parser = argparse.ArgumentParser(
        description="Convert Checkpoint policy JSON to CSV.")
    parser.add_argument("--split", action="store_true",
                        help="Expand multi-source/multi-destination access rules into one row per pair")
    parser.add_argument("--split-groups", action="store_true",
                        help="Expand group objects into individual members before resolving IPs")
    parser.add_argument("--nat", action="store_true",
                        help="Extract NAT rules instead of access/HTTPS/threat rules")
    parser.add_argument("--output", default=None,
                        help="Output CSV file (default: outputs/<json_file>_v6.csv or _nat.csv)")
    parser.add_argument("json_file", help="Input JSON policy file")
    parser.add_argument("fields", help="Comma-separated list of fields to include")
    args = parser.parse_args()

    split_mode = args.split
    split_groups = args.split_groups
    nat_mode = args.nat

    json_file = args.json_file
    fields = [f.strip() for f in args.fields.split(',')]

    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)

    suffix = '_nat.csv' if nat_mode else '_v6.csv'
    default_name = os.path.splitext(os.path.basename(json_file))[0] + suffix
    output = args.output
    if output is None:
        default_path = os.path.join("outputs", default_name)
        user_path = input(f"Save path [{default_path}]: ").strip()
        output = user_path or default_path

    out_dir = os.path.dirname(output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    resolver = ObjectResolver(data.get('objects'))

    if nat_mode:
        all_rules = data.get('policy-package', {}).get('nat-policy', {}).get('rules', [])
        flat_rules = [flatten_nat_rule(r, resolver) for r in all_rules]
        labels = []
        label_suffix = ''
        known = flatten_nat_rule({}, resolver)
    else:
        all_rules = extract_rules(data)
        if split_groups:
            all_rules = [resolver.expand_groups(r) for r in all_rules]
        flat_rules = [flatten_rule(r, resolver) for r in all_rules]
        labels = []
        if split_groups:
            labels.append('groups-split')
        if split_mode:
            flat_rules = _split_rows(flat_rules, fields)
            labels.append('split')
        label_suffix = ' (' + ', '.join(labels) + ')' if labels else ''
        known = flatten_rule({}, resolver)

    for f in fields:
        if f not in known:
            print(f"Warning: '{f}' is not a recognized field.")

    with open(output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flat_rules)

    print(f"OK  {len(flat_rules)} rules written to '{output}'{label_suffix}")
    print(f"    Fields: {', '.join(fields)}")


if __name__ == '__main__':
    main()
