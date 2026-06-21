"""Collect routing tables from Checkpoint GAIA, Checkpoint VSX, FortiGate,
Palo Alto firewalls via their respective APIs. No external dependencies."""

import json
import sys
import os
import argparse
import time
import ssl
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET

VENDORS = ("checkpoint", "paloalto", "fortinet")


# ============================================================ helpers (same as fetch_policy)

def _create_ctx(verify):
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url, headers=None, verify=False, timeout=300):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, context=_create_ctx(verify), timeout=timeout) as resp:
        return resp.read()


def _http_post(url, data, headers=None, verify=False, timeout=300):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, context=_create_ctx(verify), timeout=timeout) as resp:
        return resp.read()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ============================================================ vendor detection

def detect_vendor(server, port=443, verify=False):
    base = f"https://{server}:{port}"
    try:
        url = f"{base}/web_api/login"
        data = json.dumps({"user": "_probe_"}).encode()
        _http_post(url, data, {"Content-Type": "application/json"}, verify)
    except urllib.error.HTTPError as e:
        if e.code == 400:
            body = e.read().decode("utf-8", errors="replace")
            if '"sid"' in body or '"message"' in body:
                return "checkpoint"
    except Exception:
        pass
    try:
        url = f"{base}/api/?type=keygen&user=_probe_&password=_probe_"
        resp = _http_get(url, verify=verify)
        if b"<response" in resp and (b"key" in resp or b"result" in resp):
            return "paloalto"
    except Exception:
        pass
    try:
        url = f"{base}/api/v2/cmdb/router/static/"
        resp = _http_get(url, verify=verify)
        if b"results" in resp or b"http_status" in resp:
            return "fortinet"
    except Exception:
        pass
    return None


# ============================================================ Checkpoint

class CheckpointRoutingClient:
    """Collect routes from Checkpoint R81+ Management API (including VSX)."""

    def __init__(self, server, username, password, port=443, verify=False, timeout=300, page_size=200):
        self.base_url = f"https://{server}:{port}/web_api"
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size
        self.sid = None
        self._login(username, password)

    def _ctx(self):
        return _create_ctx(self.verify)

    def _post(self, endpoint, payload):
        url = f"{self.base_url}/{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self._ctx(), timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Checkpoint API error {endpoint}: {e.code} {body[:300]}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Checkpoint connection error {endpoint}: {e.reason}")

    def _login(self, username, password):
        res = self._post("login", {"user": username, "password": password})
        self.sid = res["sid"]
        print(f"  Login OK  sid={self.sid[:8]}...")

    def logout(self):
        if self.sid:
            try:
                self._post("logout", {})
                print("  Logged out")
            except Exception:
                pass

    def _paginate(self, endpoint, payload, limit=None, result_key=None):
        items = []
        payload = dict(payload)
        payload["limit"] = limit if limit is not None else self.page_size
        payload["offset"] = 0
        while True:
            res = self._post(endpoint, payload)
            if result_key is not None:
                key = result_key
            else:
                key = endpoint.replace("show-", "").replace("-", "_")
            batch = res.get(key) or []
            if not batch:
                break
            items.extend(batch)
            total = res.get("total")
            if total is not None:
                if payload["offset"] + len(batch) >= total:
                    break
            elif len(batch) < payload["limit"]:
                break
            payload["offset"] += payload["limit"]
        return items

    def get_virtual_systems(self):
        """Return list of Virtual System names (empty list for non-VSX)."""
        try:
            gw = self._post("show-simple-gateways", {"details-level": "full"})
            vs_list = []
            for obj in gw.get("objects", []):
                if obj.get("type") in ("CpmiVsxNetwkVirtualGW", "CpmiVsxClusterNetwkVirtualGW",
                                       "CpmiVsxClusterVirtualGW", "virtual-system"):
                    name = obj.get("name")
                    if name:
                        vs_list.append({"name": name, "uid": obj.get("uid", "")})
            return vs_list
        except Exception as e:
            print(f"  Warning: could not list VSs ({e})")
            return []

    def _fetch_routes(self, endpoint, vs_name=None):
        """Generic route fetcher supporting VSX context."""
        if vs_name:
            result_key = f"routes-{vs_name}"
            payload = {"details-level": "full", "vs-name": vs_name}
        else:
            result_key = None
            payload = {"details-level": "full"}
        try:
            return self._paginate(endpoint, payload, result_key=result_key)
        except Exception as e:
            print(f"  Warning: {endpoint} failed ({e})")
            return []

    def get_static_routes(self, vs_name=None):
        return self._fetch_routes("show-static-routes", vs_name)

    def get_routes(self, vs_name=None):
        """Return all routes (including dynamic) for a given VS or GAIA."""
        return self._fetch_routes("show-routes", vs_name)

    def get_ospf_routes(self, vs_name=None):
        return self._fetch_routes("show-route-ospf", vs_name)

    def get_bgp_routes(self, vs_name=None):
        return self._fetch_routes("show-route-bgp", vs_name)

    def fetch_all(self):
        """Gather all routing data for all Virtual Systems (or gateway itself)."""
        result = {
            "_vendor": "checkpoint",
            "fetched-at": _now(),
            "virtual-systems": [],
        }

        vs_list = self.get_virtual_systems()
        if vs_list:
            result["virtual-systems"] = vs_list
            for vs in vs_list:
                vs_name = vs["name"]
                print(f"  VS: {vs_name}")
                vs_entry = {"name": vs_name}
                vs_entry["static-routes"] = self.get_static_routes(vs_name)
                vs_entry["routes"] = self.get_routes(vs_name)
                vs_entry["ospf-routes"] = self.get_ospf_routes(vs_name)
                vs_entry["bgp-routes"] = self.get_bgp_routes(vs_name)
                print(f"    static={len(vs_entry['static-routes'])} ospf={len(vs_entry['ospf-routes'])} bgp={len(vs_entry['bgp-routes'])} all={len(vs_entry['routes'])}")
                result.setdefault("vs-routes", []).append(vs_entry)
        else:
            print("  GAIA gateway (no VSX)")
            result["static-routes"] = self.get_static_routes()
            result["routes"] = self.get_routes()
            result["ospf-routes"] = self.get_ospf_routes()
            result["bgp-routes"] = self.get_bgp_routes()
            print(f"    static={len(result['static-routes'])} ospf={len(result['ospf-routes'])} bgp={len(result['bgp-routes'])} all={len(result['routes'])}")

        return result


# ============================================================ FortiGate

class FortinetRoutingClient:
    """Collect routes from FortiGate REST API (CMDB + monitor endpoints)."""

    def __init__(self, server, username, password, port=443, verify=False, timeout=300, page_size=200):
        self.base_url = f"https://{server}:{port}"
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size
        self.session = None
        self._login(username, password)

    def _get(self, path):
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json"}
        if self.session:
            headers["Cookie"] = f"ccsrftoken={self.session}; APSCOOKIE={self.session}"
        resp = _http_get(url, headers, self.verify, timeout=self.timeout)
        return json.loads(resp.decode("utf-8"))

    def _post(self, path, data_dict):
        url = f"{self.base_url}{path}"
        data = json.dumps(data_dict).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.session:
            headers["Cookie"] = f"ccsrftoken={self.session}; APSCOOKIE={self.session}"
        resp = _http_post(url, data, headers, self.verify, timeout=self.timeout)
        return json.loads(resp.decode("utf-8"))

    def _login(self, username, password):
        try:
            resp = self._post("/api/v2/authentication", {
                "username": username,
                "password": password,
            })
            if "session" in resp:
                self.session = resp["session"]
                print(f"  Login OK  session={self.session[:8]}...")
                return
        except Exception:
            pass
        print("  Fortinet login: trying /logincheck ...")
        try:
            data = urllib.parse.urlencode({"username": username, "secretkey": password}).encode()
            url = f"{self.base_url}/logincheck"
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, context=_create_ctx(self.verify), timeout=self.timeout) as resp:
                for c in resp.headers.get_all("Set-Cookie") or []:
                    if "ccsrftoken" in c:
                        self.session = c.split("=")[1].split(";")[0].strip()
                        break
            if self.session:
                print(f"  Login OK  session={self.session[:8]}...")
            else:
                raise RuntimeError("Fortinet login failed: no session cookie")
        except Exception as e:
            raise RuntimeError(f"Fortinet login failed: {e}")

    def logout(self):
        try:
            self._post("/api/v2/authentication/logout", {})
        except Exception:
            pass
        self.session = None

    def _fetch_all_pages(self, path):
        items = []
        skip = 0
        while True:
            url = f"{path}?skip={skip}&limit=100"
            resp = self._get(url)
            results = resp.get("results", [])
            if not results:
                break
            items.extend(results)
            if len(results) < 100:
                break
            skip += 100
        return items

    def get_static_routes(self):
        return self._fetch_all_pages("/api/v2/cmdb/router/static")

    def get_policy_routes(self):
        return self._fetch_all_pages("/api/v2/cmdb/router/policy")

    def get_ospf_config(self):
        try:
            return self._get("/api/v2/cmdb/router/ospf")
        except Exception as e:
            print(f"  Warning: OSPF config fetch failed ({e})")
            return {}

    def get_bgp_config(self):
        try:
            return self._get("/api/v2/cmdb/router/bgp")
        except Exception as e:
            print(f"  Warning: BGP config fetch failed ({e})")
            return {}

    def get_routes(self):
        """Fetch live IPv4 routing table from monitor endpoint."""
        try:
            return self._fetch_all_pages("/api/v2/monitor/router/ipv4")
        except Exception as e:
            print(f"  Warning: live routing table fetch failed ({e})")
            return []

    def fetch_all(self):
        result = {
            "_vendor": "fortinet",
            "fetched-at": _now(),
        }
        print("  Static routes...")
        result["static-routes"] = self.get_static_routes()
        print(f"    {len(result['static-routes'])} entries")
        print("  Policy routes...")
        result["policy-routes"] = self.get_policy_routes()
        print(f"    {len(result['policy-routes'])} entries")
        print("  OSPF config...")
        result["ospf"] = self.get_ospf_config()
        print("  BGP config...")
        result["bgp"] = self.get_bgp_config()
        print("  Live routing table...")
        result["routes"] = self.get_routes()
        print(f"    {len(result['routes'])} entries")
        return result


# ============================================================ Palo Alto

class PaloAltoRoutingClient:
    """Collect routes from Palo Alto PAN-OS XML API."""

    def __init__(self, server, username, password, port=443, verify=False, timeout=300, page_size=200):
        self.base_url = f"https://{server}:{port}"
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size
        self.api_key = None
        self._login(username, password)

    def _api_get(self, params):
        url = f"{self.base_url}/api/?{urllib.parse.urlencode(params)}"
        if self.api_key:
            url += f"&key={self.api_key}"
        resp = _http_get(url, verify=self.verify, timeout=self.timeout)
        return ET.fromstring(resp)

    def _api_post(self, params):
        url = f"{self.base_url}/api/"
        data = urllib.parse.urlencode(params).encode()
        resp = _http_post(url, data, verify=self.verify, timeout=self.timeout)
        return ET.fromstring(resp)

    def _login(self, username, password):
        params = {"type": "keygen", "user": username, "password": password}
        root = self._api_post(params)
        key_el = root.find(".//key")
        if key_el is None or not key_el.text:
            error = root.find(".//msg")
            msg = error.text if error is not None else "Unknown error"
            raise RuntimeError(f"Palo Alto login failed: {msg}")
        self.api_key = key_el.text
        print(f"  Login OK  key={self.api_key[:8]}...")

    def logout(self):
        self.api_key = None

    def _xpath_get(self, xpath):
        params = {"type": "config", "action": "show", "xpath": xpath}
        root = self._api_get(params)
        if root.get("status") != "success":
            error = root.find(".//msg")
            msg = error.text if error is not None else "Unknown error"
            print(f"  API error for {xpath}: {msg}")
            return ET.Element("dummy")
        result = root.find("result")
        return result if result is not None else ET.Element("dummy")

    def _op_cmd(self, cmd_xml):
        """Send operational command and return XML result."""
        params = {"type": "op", "cmd": f"<{cmd_xml}></{cmd_xml.split()[0]}>"}
        root = self._api_get(params)
        if root.get("status") != "success":
            error = root.find(".//msg")
            msg = error.text if error is not None else "Unknown error"
            print(f"  Op cmd error '{cmd_xml}': {msg}")
            return ET.Element("dummy")
        result = root.find("result")
        return result if result is not None else ET.Element("dummy")

    def _extract_entries(self, parent, tag="entry"):
        """Extract list of entry dicts from XML."""
        entries = []
        for entry in parent.findall(tag):
            d = {"name": entry.get("name", "")}
            for child in entry:
                if child.tag == "member":
                    d.setdefault("members", []).append(child.text.strip() if child.text else "")
                elif len(child) == 0:
                    d[child.tag] = child.text.strip() if child.text else ""
                else:
                    sub = {}
                    for subchild in child:
                        if subchild.tag == "member":
                            sub.setdefault("members", []).append(subchild.text.strip() if subchild.text else "")
                        else:
                            sub[subchild.tag] = subchild.text.strip() if subchild.text else ""
                    d[child.tag] = sub
            entries.append(d)
        return entries

    def get_virtual_routers(self):
        """Return list of virtual router names."""
        result = self._xpath_get("/config/devices/entry/network/virtual-router/entry")
        return [e.get("name") for e in result.findall("entry") if e.get("name")]

    def get_static_routes(self, vr_name="default"):
        xpath = f"/config/devices/entry/vsys/entry/protocol/static/route/entry"
        if vr_name != "default":
            xpath = f"/config/devices/entry/network/virtual-router/entry[@name='{vr_name}']/protocol/static/route/entry"
        result = self._xpath_get(xpath)
        return self._extract_entries(result)

    def get_live_routes(self, vr_name=None):
        """Fetch live routing table via operational command."""
        cmd = "show route"
        if vr_name:
            cmd += f" virtual-router {vr_name}"
        result = self._op_cmd(cmd)
        routes = []
        for entry in result.findall(".//entry"):
            r = {"destination": entry.get("name", "")}
            for child in entry:
                if child.tag == "member":
                    r.setdefault("members", []).append(child.text.strip() if child.text else "")
                elif child.text:
                    r[child.tag] = child.text.strip()
            routes.append(r)
        return routes

    def fetch_all(self):
        result = {
            "_vendor": "paloalto",
            "fetched-at": _now(),
            "virtual-routers": [],
        }
        vrs = self.get_virtual_routers()
        if not vrs:
            vrs = ["default"]
        result["virtual-routers"] = vrs
        print(f"  Virtual routers: {', '.join(vrs)}")
        print("  Static routes per VR...")
        for vr in vrs:
            print(f"    {vr}:", end="")
            static = self.get_static_routes(vr)
            print(f" {len(static)} static route(s)")
            vr_entry = {"name": vr, "static-routes": static}
            try:
                routes = self.get_live_routes(vr)
                vr_entry["routes"] = routes
                print(f"      {len(routes)} live route(s)")
            except Exception as e:
                print(f"      live routes: {e}")
            result["virtual-routers"][result["virtual-routers"].index(vr)] = vr_entry
        return result


# ============================================================ factory

VENDOR_CLIENTS = {
    "checkpoint": CheckpointRoutingClient,
    "fortinet": FortinetRoutingClient,
    "paloalto": PaloAltoRoutingClient,
}


def fetch_routing(server, port, username, password, vendor=None, verify=False, timeout=300, page_size=200):
    """Auto-detect vendor, instantiate client, collect all routing data."""
    if vendor is None:
        print("  Auto-detecting vendor...")
        detected = detect_vendor(server, port, verify)
        if detected is None:
            print("  Could not auto-detect vendor.")
            sys.exit(1)
        vendor = detected
        print(f"  Detected: {vendor}")

    if vendor not in VENDOR_CLIENTS:
        print(f"  Unknown vendor: {vendor}")
        sys.exit(1)

    print(f"Connecting to {server}:{port} as {username} ({vendor})")
    client = VENDOR_CLIENTS[vendor](server, username, password, port=port, verify=verify, timeout=timeout, page_size=page_size)

    try:
        data = client.fetch_all()
        data["_vendor"] = vendor
        return data
    finally:
        client.logout()


# ============================================================ CLI

def main():
    parser = argparse.ArgumentParser(
        description="Collect routing tables from Checkpoint (GAIA/VSX), FortiGate, or Palo Alto."
    )
    parser.add_argument("--server", required=True, help="Management IP/hostname")
    parser.add_argument("--username", required=True, help="API/SSH username")
    parser.add_argument("--password", help="Password (omit for prompt)")
    parser.add_argument("--port", type=int, default=443, help="API port (default 443)")
    parser.add_argument("--vendor", choices=VENDORS, default=None,
                        help="Firewall vendor (auto-detect if omitted)")
    parser.add_argument("--output", default=None, help="Output JSON file (default: stdout)")
    parser.add_argument("--ssl-verify", action="store_true", help="Verify SSL certificate")
    args = parser.parse_args()

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass(f"Password for {args.username}@{args.server}: ")

    data = fetch_routing(
        args.server, args.port, args.username, password,
        vendor=args.vendor, verify=args.ssl_verify
    )

    output = json.dumps(data, indent=2, ensure_ascii=False)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\nWrote {args.output}")
    else:
        print()
        print(output)


if __name__ == "__main__":
    main()
