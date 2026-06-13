import json
import csv
import sys
import os


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
    services = rule.get('service', [])
    if isinstance(services, list):
        flat['service'] = '; '.join(resolver.resolve_service(s) for s in services)
    else:
        flat['service'] = str(services)
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
    flat['uid'] = rule.get('uid', '')
    flat['_layer'] = rule.get('_layer', '')
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
    split_mode = False
    args = [a for a in sys.argv[1:] if a != '--split']
    if len(sys.argv) > 1 and '--split' in sys.argv:
        split_mode = True

    if len(args) != 2:
        print("Usage: python convert_checkpoint_v5.py [--split] <json_file> <field1,field2,...>")
        print()
        print("Available fields:")
        print("  rule-number, name, rule-type, policy-name, status, enabled,")
        print("  source, destination, service, action, track, comments,")
        print("  content, inline-layer, time, user, install-on,")
        print("  threat-name, threat-category, uid, _layer")
        print()
        print("  rule-type: access | inline | app-control | threat-prevention")
        print("  status:    Enabled | Disabled")
        print()
        print("Options:")
        print("  --split    Expand multi-source/multi-destination rules into")
        print("             one row per source-destination pair")
        print()
        print("Examples:")
        print('  python convert_checkpoint_v5.py checkpoint_policy.json "rule-number,status,name,source,destination,action"')
        print('  python convert_checkpoint_v5.py --split checkpoint_policy.json "rule-number,status,name,source,destination,action"')
        sys.exit(1)

    json_file = args[0]
    fields = [f.strip() for f in args[1].split(',')]

    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    resolver = ObjectResolver(data.get('objects'))
    all_rules = extract_rules(data)
    flat_rules = [flatten_rule(r, resolver) for r in all_rules]

    if split_mode:
        flat_rules = _split_rows(flat_rules, fields)
        label_suffix = ' (split)'
    else:
        label_suffix = ''

    known = flatten_rule({}, resolver)
    for f in fields:
        if f not in known:
            print(f"Warning: '{f}' is not a recognized field.")

    output = os.path.splitext(json_file)[0] + '_v5.csv'

    with open(output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flat_rules)

    print(f"OK  {len(flat_rules)} rules written to '{output}'{label_suffix}")
    print(f"    Fields: {', '.join(fields)}")


if __name__ == '__main__':
    main()
