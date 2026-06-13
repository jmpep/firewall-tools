import json
import csv
import sys
import os


class ObjectResolver:
    def __init__(self, objects_data):
        self._hosts = {}
        self._networks = {}
        self._groups = {}
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

    def resolve(self, obj_ref, _visited=None):
        """Resolve an object reference to its IP/CIDR representation."""
        name = obj_ref.get('name', '') if isinstance(obj_ref, dict) else str(obj_ref)
        if not name or name == 'Any':
            return name or 'Any'

        if _visited is None:
            _visited = set()
        if name in _visited:
            return f"<circular:{name}>"
        _visited.add(name)

        # Host
        if name in self._hosts:
            h = self._hosts[name]
            ip = h.get('ip-address', '')
            if name in self._gateway_interfaces:
                ips = self._gateway_interfaces[name]
                return ', '.join(f"{ip}/32" for ip in ips)
            if ip:
                return f"{ip}/32"
            return name

        # Network
        if name in self._networks:
            n = self._networks[name]
            subnet = n.get('subnet', '')
            mask = n.get('mask-length')
            if subnet and mask is not None:
                return f"{subnet}/{mask}"
            return name

        # Group — recursively resolve members
        if name in self._groups:
            members = self._groups[name].get('members', [])
            parts = [self.resolve(m, _visited) for m in members]
            return ', '.join(parts)

        return name


def flatten_rule(rule, resolver):
    flat = {}

    for key in ['rule-number', 'name', 'enabled', 'comments', 'threat-name']:
        flat[key] = rule.get(key, '')

    action = rule.get('action', {})
    flat['action'] = action.get('name', '') if isinstance(action, dict) else str(action)

    track = rule.get('track', {})
    flat['track'] = track.get('type', '') if isinstance(track, dict) else str(track)

    # Resolve source/destination to IPs/CIDRs
    for array_field in ('source', 'destination'):
        vals = rule.get(array_field, [])
        if isinstance(vals, list):
            flat[array_field] = ', '.join(
                resolver.resolve(v) for v in vals
            )
        else:
            flat[array_field] = str(vals)

    # Service stays as name-based (services map to ports, but keep simple)
    services = rule.get('service', [])
    flat['service'] = ', '.join(
        s.get('name', '') for s in services
    ) if isinstance(services, list) else str(services)

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
        print("Usage: python convert_checkpoint_v2.py <json_file> <field1,field2,...>")
        print()
        print("Available fields:")
        print("  rule-number, name, enabled, source, destination, service,")
        print("  action, track, comments, content, inline-layer, time, user,")
        print("  install-on, threat-name, threat-category, uid, _layer")
        print()
        print("Note: source and destination are resolved to IP/CIDR notation.")
        print("  Hosts: 10.1.1.10/32    Networks: 10.1.0.0/16")
        print("  Gateways: resolves all interface IPs")
        print("  Groups: recursively resolves all members")
        print()
        print("Example:")
        print('  python convert_checkpoint_v2.py checkpoint_policy.json "rule-number,name,source,destination,action"')
        sys.exit(1)

    json_file = sys.argv[1]
    fields = [f.strip() for f in sys.argv[2].split(',')]

    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Build resolver from the objects section
    resolver = ObjectResolver(data.get('objects'))

    all_rules = extract_rules(data)
    flat_rules = [flatten_rule(r, resolver) for r in all_rules]

    known = flatten_rule({}, resolver)
    for f in fields:
        if f not in known:
            print(f"Warning: '{f}' is not a recognized field.")

    output = os.path.splitext(json_file)[0] + '_resolved.csv'

    with open(output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flat_rules)

    print(f"OK  {len(flat_rules)} rules written to '{output}'")
    print(f"    Fields: {', '.join(fields)}")


if __name__ == '__main__':
    main()
