import json
import csv
import sys
import os


def flatten_rule(rule):
    flat = {}

    for key in ['rule-number', 'name', 'enabled', 'comments', 'threat-name']:
        flat[key] = rule.get(key, '')

    # Action: {name: "Accept"} -> "Accept"
    action = rule.get('action', {})
    flat['action'] = action.get('name', '') if isinstance(action, dict) else str(action)

    # Track: {type: "Log"} -> "Log"
    track = rule.get('track', {})
    flat['track'] = track.get('type', '') if isinstance(track, dict) else str(track)

    # Source/Destination/Service: [{name: "X"}, {name: "Y"}] -> "X, Y"
    for array_field in ('source', 'destination', 'service', 'content'):
        vals = rule.get(array_field, [])
        flat[array_field] = ', '.join(
            v.get('name', '') for v in vals
        ) if isinstance(vals, list) else str(vals)

    # Time: {name: "Business_Hours"} -> "Business_Hours"
    time_obj = rule.get('time', {})
    flat['time'] = time_obj.get('name', '') if isinstance(time_obj, dict) else str(time_obj)

    # User: {name: "IT_Admins"} -> "IT_Admins"
    user_obj = rule.get('user', {})
    flat['user'] = user_obj.get('name', '') if isinstance(user_obj, dict) else str(user_obj)

    # Install-on: {name: "Policy Targets"} -> "Policy Targets"
    install = rule.get('install-on', {})
    flat['install-on'] = install.get('name', '') if isinstance(install, dict) else str(install)

    # Inline layer: {name: "Content Filtering"} -> "Content Filtering"
    inline = rule.get('inline-layer', {})
    flat['inline-layer'] = inline.get('name', '') if isinstance(inline, dict) else str(inline)

    # Threat categories: ["Critical", "High"] -> "Critical, High"
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
        print("Error: JSON missing 'policy-package > access-control-policy > layers'")
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
        print("Usage: python convert_checkpoint.py <json_file> <field1,field2,...>")
        print()
        print("Available fields:")
        print("  rule-number, name, enabled, source, destination, service,")
        print("  action, track, comments, content, inline-layer, time, user,")
        print("  install-on, threat-name, threat-category, uid, _layer")
        print()
        print("Example:")
        print("  python convert_checkpoint.py checkpoint_policy.json \"rule-number,name,source,destination,service,action,track,comments\"")
        sys.exit(1)

    json_file = sys.argv[1]
    fields = [f.strip() for f in sys.argv[2].split(',')]

    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    all_rules = extract_rules(data)
    flat_rules = [flatten_rule(r) for r in all_rules]

    # Warn about unknown fields
    known = flatten_rule({})
    for f in fields:
        if f not in known:
            print(f"Warning: '{f}' is not a recognized field. It will be empty for all rows.")

    output = os.path.splitext(json_file)[0] + '.csv'

    with open(output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flat_rules)

    print(f"OK  {len(flat_rules)} rules written to '{output}'")
    print(f"    Fields: {', '.join(fields)}")


if __name__ == '__main__':
    main()
