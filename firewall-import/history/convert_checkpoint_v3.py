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
        """Resolve a single object name to its IP/CIDR string."""
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
        """Resolve to 'Name [IP/CIDR]' format. Multiple objects joined with ';'."""
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

        # Group — recursively resolve members
        if name in self._groups:
            members = self._groups[name].get('members', [])
            parts = [self.resolve_with_name(m, _visited) for m in members]
            return f"{name} [{'; '.join(parts)}]"

        return name

    def resolve_service(self, svc_ref):
        """Resolve a service reference to 'Name [protocol/port]' format."""
        name = svc_ref.get('name', '') if isinstance(svc_ref, dict) else str(svc_ref)
        if not name or name == 'Any':
            return name or 'Any'

        if name in self._services:
            s = self._services[name]
            proto = s.get('protocol', '')
            if proto == 'tcp':
                port = s.get('port', '?')
                return f"{name} [tcp/{port}]"
            elif proto == 'udp':
                port = s.get('port', '?')
                return f"{name} [udp/{port}]"
            elif proto == 'icmp':
                icmp_type = s.get('icmp-type', '?')
                icmp_code = s.get('icmp-code', '?')
                return f"{name} [icmp type={icmp_type} code={icmp_code}]"
            return f"{name} [{proto}]"

        return name


def flatten_rule(rule, resolver):
    flat = {}

    for key in ['rule-number', 'name', 'enabled', 'comments', 'threat-name']:
        flat[key] = rule.get(key, '')

    action = rule.get('action', {})
    flat['action'] = action.get('name', '') if isinstance(action, dict) else str(action)

    track = rule.get('track', {})
    flat['track'] = track.get('type', '') if isinstance(track, dict) else str(track)

    # Source / Destination — resolve with names, separator = "; "
    for array_field in ('source', 'destination'):
        vals = rule.get(array_field, [])
        if isinstance(vals, list):
            flat[array_field] = '; '.join(
                resolver.resolve_with_name(v) for v in vals
            )
        else:
            flat[array_field] = str(vals)

    # Service — resolve to name + port/protocol
    services = rule.get('service', [])
    if isinstance(services, list):
        flat['service'] = '; '.join(
            resolver.resolve_service(s) for s in services
        )
    else:
        flat['service'] = str(services)

    # Content / application sites
    content = rule.get('content', [])
    flat['content'] = ', '.join(
        c.get('name', '') for c in content
    ) if isinstance(content, list) else str(content)

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


def extract_rules(data):
    all_rules = []
    try:
        layers = data['policy-package']['access-control-policy']['layers']
    except (KeyError, TypeError):
        print("Error: JSON path 'policy-package > access-control-policy > layers' not found.")
        sys.exit(1)

    for layer in layers:
        layer_name = layer.get('name', 'Unknown Layer')
        for rule in layer.get('rules', []):
            rule['_layer'] = layer_name
            all_rules.append(rule)
        for inline in layer.get('inline-layers', []):
            inline_name = inline.get('name', 'Unknown Inline Layer')
            for rule in inline.get('rules', []):
                rule['_layer'] = f"{layer_name} > {inline_name}"
                all_rules.append(rule)

    return all_rules


def main():
    if len(sys.argv) != 3:
        print("Usage: python convert_checkpoint_v3.py <json_file> <field1,field2,...>")
        print()
        print("Available fields:")
        print("  rule-number, name, enabled, source, destination, service,")
        print("  action, track, comments, content, inline-layer, time, user,")
        print("  install-on, threat-name, threat-category, uid, _layer")
        print()
        print("Differences from v2:")
        print("  - source/destination show: Name [IP/CIDR]")
        print("  - Multiple objects separated by ';'")
        print("  - Services resolved to: Name [protocol/port]")
        print()
        print("Example:")
        print('  python convert_checkpoint_v3.py checkpoint_policy.json "rule-number,name,source,destination,service,action"')
        sys.exit(1)

    json_file = sys.argv[1]
    fields = [f.strip() for f in sys.argv[2].split(',')]

    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    resolver = ObjectResolver(data.get('objects'))

    all_rules = extract_rules(data)
    flat_rules = [flatten_rule(r, resolver) for r in all_rules]

    known = flatten_rule({}, resolver)
    for f in fields:
        if f not in known:
            print(f"Warning: '{f}' is not a recognized field.")

    output = os.path.splitext(json_file)[0] + '_v3.csv'

    with open(output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flat_rules)

    print(f"OK  {len(flat_rules)} rules written to '{output}'")
    print(f"    Fields: {', '.join(fields)}")


if __name__ == '__main__':
    main()
