"""Fetch Checkpoint firewall policy from Management API and save as JSON."""

import json
import sys
import os
import argparse
import time
import ssl
import urllib.request
import urllib.error


class CheckpointAPIClient:
    """Client for Checkpoint R81.x Management Web API (no external deps)."""

    def __init__(self, server, username, password, port=443, verify=False):
        self.base_url = f"https://{server}:{port}/web_api"
        self.verify = verify
        self.sid = None
        self._login(username, password)

    # ------------------------------------------------------------------ helpers

    def _ctx(self):
        if self.verify:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _post(self, endpoint, payload):
        url = f"{self.base_url}/{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self._ctx(), timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            print(f"  API error {endpoint}: {e.code} {body[:300]}")
            sys.exit(1)
        except urllib.error.URLError as e:
            print(f"  Connection error {endpoint}: {e.reason}")
            sys.exit(1)

    # ------------------------------------------------------------------ auth

    def _login(self, username, password):
        res = self._post("login", {"user": username, "password": password})
        self.sid = res["sid"]
        print(f"  Login OK  sid={self.sid[:8]}...")

    def logout(self):
        if self.sid:
            self._post("logout", {})
            print("  Logged out")

    # ------------------------------------------------------------------ pagination

    def _paginate(self, endpoint, payload, limit=500, result_key=None):
        """Fetch all pages from a paginated API endpoint.

        Parameters
        ----------
        endpoint : str
            API endpoint name (e.g. "show-hosts", "show-access-rulebase").
        payload : dict
            Base payload; limit/offset are added automatically.
        limit : int
            Items per page (default 500, Checkpoint max).
        result_key : str or None
            Key in the response dict that holds the item list.
            If None, derived from endpoint name (fragile — pass explicitly).
        """
        all_data = []
        payload = dict(payload)
        payload["limit"] = limit
        payload["offset"] = 0
        while True:
            res = self._post(endpoint, payload)
            if result_key is not None:
                key = result_key
            else:
                key = endpoint.replace("show-", "").replace("-", "_")
            items = res.get(key) or res.get("objects") or res.get("rulebase") or []
            if not items:
                break
            all_data.extend(items)
            total = res.get("total")
            if total is not None:
                if payload["offset"] + len(items) >= total:
                    break
            elif len(items) < limit:
                break
            payload["offset"] += limit
        return all_data

    # ------------------------------------------------------------------ layers & rules

    def fetch_layers(self):
        items = self._paginate("show-access-layers", {}, result_key="access-layers")
        return [l["name"] for l in items]

    def fetch_rulebase(self, layer_name):
        items = self._paginate("show-access-rulebase", {
            "name": layer_name,
            "details-level": "full",
            "use-object-dictionary": False,
        }, result_key="rulebase")
        # Re-assemble a response-like dict (used by fetch_all)
        return {"rulebase": items, "uid": items[0].get("uid", "") if items else ""}

    def fetch_https_inspection(self):
        try:
            return self._paginate("show-https-inspection-rulebase", {
                "details-level": "full",
            }, result_key="rulebase")
        except Exception as e:
            print(f"  Warning: HTTPS inspection not available ({e})")
            return []

    def fetch_threat_rulebase(self):
        try:
            return self._paginate("show-threat-rulebase", {
                "details-level": "full",
            }, result_key="rulebase")
        except Exception as e:
            print(f"  Warning: Threat rulebase not available ({e})")
            return []

    # ------------------------------------------------------------------ objects

    def _fetch_objects(self, show_cmd, result_key=None):
        try:
            return self._paginate(show_cmd, {"details-level": "full"},
                                  result_key=result_key)
        except Exception as e:
            print(f"  Warning: {show_cmd} failed ({e})")
            return []

    def fetch_all_objects(self):
        objects = {}
        objects["hosts"] = self._fetch_objects("show-hosts", result_key="hosts")
        objects["networks"] = self._fetch_objects("show-networks", result_key="networks")
        objects["groups"] = self._fetch_objects("show-groups", result_key="groups")
        # Service API endpoints return different key names than the endpoint:
        # show-services-tcp  → "tcp-services"
        # show-services-udp  → "udp-services"
        # show-services-icmp → "icmp-services"
        # show-services-other → "other-services"
        objects["services-tcp"] = self._fetch_objects("show-services-tcp", result_key="tcp-services")
        objects["services-udp"] = self._fetch_objects("show-services-udp", result_key="udp-services")
        objects["services-icmp"] = self._fetch_objects("show-services-icmp", result_key="icmp-services")
        objects["services-other"] = self._fetch_objects("show-services-other", result_key="other-services")
        objects["application-sites"] = self._fetch_objects("show-application-sites", result_key="application-sites")
        objects["time"] = self._fetch_objects("show-time", result_key="time")
        objects["users"] = self._fetch_objects("show-user-groups", result_key="user-groups")
        return objects

    # ------------------------------------------------------------------ assemble

    def fetch_all(self):
        print("Fetching access layers ...")
        layer_names = self.fetch_layers()
        print(f"  Found layers: {layer_names}")

        access_policy = {"layers": []}
        for name in layer_names:
            print(f"  Fetching rulebase for '{name}' ...")
            rb = self.fetch_rulebase(name)
            layer = {"name": name, "uid": rb.get("uid", ""),
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
            access_policy["layers"].append(layer)

        print("  Fetching HTTPS inspection policy ...")
        https_rules = self.fetch_https_inspection()

        print("  Fetching threat prevention policy ...")
        threat_rules = self.fetch_threat_rulebase()

        print("  Fetching objects ...")
        objects = self.fetch_all_objects()

        data = {
            "policy-package": {
                "name": "fetched_policy",
                "meta-info": {
                    "fetched-at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                "access-control-policy": access_policy,
                "https-inspection-policy": {"rules": https_rules},
                "threat-prevention-policy": {"rulebase": threat_rules},
            },
            "objects": objects,
        }
        return data


# ====================================================================== CLI

def main():
    parser = argparse.ArgumentParser(
        description="Fetch Checkpoint firewall policy from Management API to JSON."
    )
    parser.add_argument("--server", required=True,
                        help="Management server IP/hostname")
    parser.add_argument("--username", required=True, help="API user")
    parser.add_argument("--password", help="Password (omit for prompt)")
    parser.add_argument("--port", type=int, default=443,
                        help="API port (default 443)")
    parser.add_argument("--output", default=None,
                        help="Output JSON file (default: outputs/<policy_name>.json)")
    parser.add_argument("--ssl-verify", action="store_true",
                        help="Verify SSL certificate")
    args = parser.parse_args()

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    output = args.output
    if output is None:
        default = "outputs/checkpoint_policy.json"
        user_path = input(f"Save path [{default}]: ").strip()
        output = user_path or default

    out_dir = os.path.dirname(output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    print(f"Connecting to {args.server}:{args.port} as {args.username} ...")
    client = CheckpointAPIClient(args.server, args.username, password,
                                 port=args.port, verify=args.ssl_verify)
    data = client.fetch_all()
    client.logout()

    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    total_rules = sum(
        len(l.get("rules", []))
        for l in data["policy-package"]["access-control-policy"]["layers"]
    )
    obj_count = sum(len(v) for v in data.get("objects", {}).values())

    print(f"\nSaved to '{output}'")
    print(f"  Access layers : {len(data['policy-package']['access-control-policy']['layers'])}")
    print(f"  Access rules  : {total_rules}")
    print(f"  HTTPS rules   : {len(data['policy-package']['https-inspection-policy']['rules'])}")
    print(f"  Threat rules  : {len(data['policy-package']['threat-prevention-policy']['rulebase'])}")
    print(f"  Objects       : {obj_count}")


if __name__ == "__main__":
    main()
