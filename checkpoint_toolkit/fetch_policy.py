"""Fetch firewall policy from Checkpoint, Palo Alto, or Fortinet API and save as JSON."""

import json
import sys
import os
import argparse
import time
import ssl
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

VENDORS = ("checkpoint", "paloalto", "fortinet")


# ============================================================ SSL helper

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


# ============================================================ vendor detection

def detect_vendor(server, port=443, verify=False):
    """Probe well-known endpoints to identify the firewall vendor."""
    base = f"https://{server}:{port}"

    # Checkpoint
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

    # Palo Alto
    try:
        url = f"{base}/api/?type=keygen&user=_probe_&password=_probe_"
        resp = _http_get(url, verify=verify)
        if b"<response" in resp and (b"key" in resp or b"result" in resp):
            return "paloalto"
    except Exception:
        pass

    # Fortinet
    try:
        url = f"{base}/api/v2/cmdb/firewall/policy/"
        resp = _http_get(url, verify=verify)
        if b"results" in resp or b"http_status" in resp or b"fortinet" in resp.lower():
            return "fortinet"
    except Exception:
        pass

    return None


# ============================================================ normalize helpers

def _normalize_time():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _common_package(name, access_layers, nat_rules=None):
    pkg = {
        "name": name,
        "meta-info": {"fetched-at": _normalize_time()},
        "access-control-policy": {"layers": access_layers},
        "https-inspection-policy": {"rules": []},
        "threat-prevention-policy": {"rulebase": []},
    }
    if nat_rules:
        pkg["nat-policy"] = {"rules": nat_rules}
    return pkg


def _common_rule(rule_num, name, uid, enabled, source, dest, service,
                 action, track="Log", comments="", install_on=None,
                 time_obj=None, user=None, extra=None):
    r = {
        "rule-number": str(rule_num),
        "name": name,
        "uid": uid,
        "enabled": enabled,
        "source": [{"name": s} for s in (source if isinstance(source, list) else [source])],
        "destination": [{"name": d} for d in (dest if isinstance(dest, list) else [dest])],
        "service": [{"name": sv} for sv in (service if isinstance(service, list) else [service])],
        "action": {"name": action},
        "track": {"type": track},
        "comments": comments,
        "install-on": {"name": install_on or ""},
        "time": {"name": time_obj or "Any"},
        "user": {"name": user or "Any"},
    }
    if extra:
        r.update(extra)
    return r


# ============================================================ Checkpoint

class CheckpointAPIClient:
    """Client for Checkpoint R81.x Management Web API (no external deps)."""

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
            with urllib.request.urlopen(req, context=_create_ctx(self.verify), timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Checkpoint API error {endpoint}: {e.code} {body[:300]}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Checkpoint connection error {endpoint}: {e.reason}")

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

    def _paginate(self, endpoint, payload, limit=None, result_key=None):
        all_data = []
        payload = dict(payload)
        payload["limit"] = limit if limit is not None else self.page_size
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
            elif len(items) < payload["limit"]:
                break
            payload["offset"] += payload["limit"]
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
                    "fetched-at": _normalize_time(),
                },
                "access-control-policy": access_policy,
                "https-inspection-policy": {"rules": https_rules},
                "threat-prevention-policy": {"rulebase": threat_rules},
            },
            "objects": objects,
            "_vendor": "checkpoint",
        }
        return data


# ============================================================ Palo Alto

class PaloAltoAPIClient:
    """Client for Palo Alto Networks PAN-OS XML API."""

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
        import urllib.parse
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

    # ------------------------------------------------------------------ fetch

    def _xpath_get(self, xpath):
        import urllib.parse
        params = {"type": "config", "action": "show",
                  "xpath": xpath}
        root = self._api_get(params)
        if root.get("status") != "success":
            error = root.find(".//msg")
            msg = error.text if error is not None else "Unknown error"
            print(f"  API error for {xpath}: {msg}")
            return ET.Element("dummy")
        result = root.find("result")
        return result if result is not None else ET.Element("dummy")

    def _parse_members(self, parent, tag="member"):
        members = []
        for m in parent.findall(tag):
            if m.text:
                members.append(m.text.strip())
        return members

    def _parse_rules(self, entries):
        rules = []
        for i, entry in enumerate(entries, 1):
            name = entry.get("name", f"rule-{i:04d}")
            enabled = entry.get("disabled", None) != "yes"
            sources = self._parse_members(entry.find("source"))
            destinations = self._parse_members(entry.find("destination"))
            services = self._parse_members(entry.find("service"))
            action_el = entry.find("action")
            action = action_el.text.strip() if action_el is not None else "allow"
            log_el = entry.find("log-start") or entry.find("log-end")
            track = "Log"
            if log_el is not None:
                track = f"Log at {'Start' if log_el.tag == 'log-start' else 'Session End'}"
            comment_el = entry.find("description")
            comments = comment_el.text.strip() if comment_el is not None else ""
            src_zone = self._parse_members(entry.find("from"), tag="member")
            dst_zone = self._parse_members(entry.find("to"), tag="member")
            apps = self._parse_members(entry.find("application"))
            users = self._parse_members(entry.find("source-user"))
            profile_el = entry.find("profile-setting/group")
            profiles = [profile_el.text.strip()] if profile_el is not None and profile_el.text else []

            extra = {}
            if src_zone:
                extra["source-zone"] = ", ".join(src_zone)
            if dst_zone:
                extra["destination-zone"] = ", ".join(dst_zone)
            if apps:
                extra["application"] = [{"name": a} for a in apps]
            if users:
                extra["user"] = [{"name": u} for u in users]
            if profiles:
                extra["profile"] = profiles

            uid = entry.get("uuid", f"pa-rule-{i:04d}")
            rules.append(_common_rule(
                i, name, uid, enabled,
                sources or ["Any"], destinations or ["Any"], services or ["Any"],
                action.capitalize(), track, comments,
                install_on=None, extra=extra,
            ))
        return rules

    def fetch_security_rules(self):
        print("  Fetching security rules ...")
        result = self._xpath_get("/config/devices/entry/vsys/entry/rulebase/security/rules")
        entries = []
        for rules_el in result.findall("rules"):
            entries.extend(rules_el.findall("entry"))
        if not entries:
            entries = result.findall(".//entry")
        return self._parse_rules(entries)

    def fetch_nat_rules(self):
        print("  Fetching NAT rules ...")
        result = self._xpath_get("/config/devices/entry/vsys/entry/rulebase/nat/rules")
        nat_rules = []
        entries = []
        for rules_el in result.findall("rules"):
            entries.extend(rules_el.findall("entry"))
        if not entries:
            entries = result.findall(".//entry")
        for i, entry in enumerate(entries, 1):
            name = entry.get("name", f"nat-{i:04d}")
            enabled = entry.get("disabled", None) != "yes"
            src = self._parse_members(entry.find("source"))
            dst = self._parse_members(entry.find("destination"))
            svc = self._parse_members(entry.find("service"))
            src_trans = self._parse_members(entry.find("source-translation"))
            dst_trans = self._parse_members(entry.find("destination-translation"))

            nat_rules.append({
                "rule-number": str(i),
                "name": name,
                "uid": entry.get("uuid", f"pa-nat-{i:04d}"),
                "enabled": enabled,
                "method": "static",
                "original-source": [{"name": s} for s in (src or ["Any"])],
                "original-destination": [{"name": d} for d in (dst or ["Any"])],
                "original-service": [{"name": s} for s in (svc or ["Any"])],
                "translated-source": [{"name": s} for s in (src_trans or ["Original"])],
                "translated-destination": [{"name": d} for d in (dst_trans or ["Original"])],
                "translated-service": [{"name": "Original"}],
                "action": {"name": "translate"},
                "install-on": {"name": ""},
                "comments": "",
            })
        return nat_rules

    def _fetch_addresses(self):
        hosts = []
        networks = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/address")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            ip_netmask = entry.find("ip-netmask")
            ip_range = entry.find("ip-range")
            fqdn = entry.find("fqdn")
            if ip_netmask is not None and ip_netmask.text:
                val = ip_netmask.text.strip()
                if "/" in val:
                    ip, mask = val.split("/", 1)
                    networks.append({"name": name, "subnet": ip, "mask-length": int(mask)})
                else:
                    hosts.append({"name": name, "ip-address": val, "type": "ip-netmask"})
            elif ip_range is not None and ip_range.text:
                hosts.append({"name": name, "ip-address": ip_range.text.strip(), "type": "ip-range"})
            elif fqdn is not None and fqdn.text:
                hosts.append({"name": name, "ip-address": fqdn.text.strip(), "type": "fqdn"})
        return hosts, networks

    def _fetch_address_groups(self):
        groups = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/address-group")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            members = [{"name": m.text.strip()} for m in entry.findall(".//member") if m.text]
            if members:
                groups.append({"name": name, "members": members})
        return groups

    def _fetch_services(self):
        services = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/service")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            protocol = entry.find("protocol")
            if protocol is not None:
                tcp_el = protocol.find("tcp")
                udp_el = protocol.find("udp")
                port = None
                proto_name = None
                if tcp_el is not None:
                    port_el = tcp_el.find("port")
                    if port_el is not None:
                        port = port_el.text.strip()
                    proto_name = "tcp"
                elif udp_el is not None:
                    port_el = udp_el.find("port")
                    if port_el is not None:
                        port = port_el.text.strip()
                    proto_name = "udp"
                if proto_name:
                    svc = {"name": name, "protocol": proto_name}
                    if port:
                        svc["port"] = port
                    services.append(svc)
        return services

    def fetch_all_objects(self):
        print("  Fetching objects ...")
        hosts, networks = self._fetch_addresses()
        groups = self._fetch_address_groups()
        services = self._fetch_services()
        return {
            "hosts": hosts,
            "networks": networks,
            "groups": groups,
            "services": services,
            "services-tcp": [s for s in services if s.get("protocol") == "tcp"],
            "services-udp": [s for s in services if s.get("protocol") == "udp"],
            "services-icmp": [],
            "services-other": [],
            "application-sites": [],
            "time": [],
            "users": [],
        }

    def fetch_all(self):
        rules = self.fetch_security_rules()
        nat_rules = self.fetch_nat_rules()
        objects = self.fetch_all_objects()

        layer = {
            "name": "Security Policy",
            "uid": "pa-layer-001",
            "rules": rules,
            "inline-layers": [],
        }
        data = {
            "policy-package": _common_package("fetched_policy", [layer], nat_rules),
            "objects": objects,
            "_vendor": "paloalto",
        }
        print(f"  Security rules : {len(rules)}")
        print(f"  NAT rules      : {len(nat_rules)}")
        return data


# ============================================================ Fortinet

class FortinetAPIClient:
    """Client for Fortinet FortiGate REST API."""

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

    # ------------------------------------------------------------------ fetch

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

    def _parse_policy(self, p, i):
        name = p.get("name", "") or p.get("policyid", str(i))
        enabled = p.get("status", "enable") == "enable"
        action = p.get("action", "deny")
        track = "Log All" if p.get("logtraffic", "disable") == "all" else "Log"
        comments = p.get("comments", "") or p.get("comment", "")
        srcintf = [z.get("name", "") for z in p.get("srcintf", []) if isinstance(z, dict)]
        dstintf = [z.get("name", "") for z in p.get("dstintf", []) if isinstance(z, dict)]
        schedule = p.get("schedule", "")
        profile = p.get("profile-protocol-options", "") or p.get("profile_group", "")

        sources = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
        destinations = [m.get("name", "") for m in p.get("dstaddr", []) if isinstance(m, dict)]
        services = [m.get("name", "") for m in p.get("service", []) if isinstance(m, dict)]
        users = [m.get("name", "") for m in p.get("users", []) if isinstance(m, dict)]

        extra = {}
        if srcintf:
            extra["source-interface"] = ", ".join(srcintf)
        if dstintf:
            extra["destination-interface"] = ", ".join(dstintf)
        if schedule:
            extra["schedule"] = schedule
        if profile:
            extra["profile"] = [profile]

        nat_el = p.get("nat", "disable")
        if nat_el == "enable":
            extra["nat"] = True

        uid = p.get("policyid", str(i))
        return _common_rule(
            uid, name, f"fg-rule-{i:04d}", enabled,
            sources or ["Any"], destinations or ["Any"], services or ["Any"],
            action.capitalize(), track, comments,
            install_on=None, extra=extra,
        )

    def fetch_policies(self):
        print("  Fetching firewall policies ...")
        raw = self._fetch_all_pages("/api/v2/cmdb/firewall/policy")
        return [self._parse_policy(p, i + 1) for i, p in enumerate(raw)]

    def fetch_nat_rules(self):
        print("  Fetching NAT policies ...")
        try:
            raw = self._fetch_all_pages("/api/v2/cmdb/firewall/central-snat-map")
            nat_rules = []
            for i, p in enumerate(raw, 1):
                name = p.get("name", f"nat-{i:04d}")
                enabled = p.get("status", "enable") == "enable"
                src = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
                dst = [m.get("name", "") for m in p.get("dstaddr", []) if isinstance(m, dict)]
                orig_src = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
                nat_rules.append({
                    "rule-number": str(i),
                    "name": name,
                    "uid": p.get("policyid", f"fg-nat-{i:04d}"),
                    "enabled": enabled,
                    "method": "dynamic-ip-and-port",
                    "original-source": [{"name": s} for s in (orig_src or ["Any"])],
                    "original-destination": [{"name": d} for d in (dst or ["Any"])],
                    "original-service": [{"name": "Any"}],
                    "translated-source": [{"name": s} for s in src or ["Original"]],
                    "translated-destination": [{"name": "Original"}],
                    "translated-service": [{"name": "Original"}],
                    "action": {"name": "snat"},
                    "install-on": {"name": ""},
                    "comments": "",
                })
            return nat_rules
        except Exception as e:
            print(f"  Warning: NAT rules not available ({e})")
            return []

    def _fetch_addresses(self):
        hosts = []
        networks = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall/address")
            for a in items:
                name = a.get("name", "")
                subnet = a.get("subnet", [])
                if isinstance(subnet, list) and len(subnet) == 2:
                    networks.append({
                        "name": name,
                        "subnet": subnet[0],
                        "mask-length": int(subnet[1]),
                    })
                else:
                    ip = a.get("start-ip", "") or a.get("fqdn", "")
                    if ip:
                        hosts.append({"name": name, "ip-address": ip, "type": "ipmask"})
        except Exception as e:
            print(f"  Warning: addresses not available ({e})")
        return hosts, networks

    def _fetch_addr_groups(self):
        groups = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall/addrgrp")
            for g in items:
                name = g.get("name", "")
                members = []
                for m in g.get("member", []):
                    if isinstance(m, dict) and m.get("name"):
                        members.append({"name": m["name"]})
                if members:
                    groups.append({"name": name, "members": members})
        except Exception as e:
            print(f"  Warning: address groups not available ({e})")
        return groups

    def _fetch_services(self):
        services = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall.service/custom")
            for s in items:
                name = s.get("name", "")
                protocol = s.get("protocol", "")
                port = ""
                tcp_range = s.get("tcp-portrange", "")
                udp_range = s.get("udp-portrange", "")
                if tcp_range:
                    port = tcp_range.split("-")[0].split(",")[0].strip()
                    protocol = "tcp"
                elif udp_range:
                    port = udp_range.split("-")[0].split(",")[0].strip()
                    protocol = "udp"
                svc = {"name": name, "protocol": protocol or "tcp"}
                if port:
                    svc["port"] = port
                services.append(svc)
        except Exception as e:
            print(f"  Warning: services not available ({e})")
        return services

    def fetch_all_objects(self):
        print("  Fetching objects ...")
        hosts, networks = self._fetch_addresses()
        groups = self._fetch_addr_groups()
        services = self._fetch_services()
        return {
            "hosts": hosts,
            "networks": networks,
            "groups": groups,
            "services": services,
            "services-tcp": [s for s in services if s.get("protocol") == "tcp"],
            "services-udp": [s for s in services if s.get("protocol") == "udp"],
            "services-icmp": [],
            "services-other": [],
            "application-sites": [],
            "time": [],
            "users": [],
        }

    def fetch_all(self):
        rules = self.fetch_policies()
        nat_rules = self.fetch_nat_rules()
        objects = self.fetch_all_objects()

        layer = {
            "name": "IPv4 Policy",
            "uid": "fg-layer-v4-001",
            "rules": rules,
            "inline-layers": [],
        }
        data = {
            "policy-package": _common_package("fetched_policy", [layer], nat_rules),
            "objects": objects,
            "_vendor": "fortinet",
        }
        print(f"  Firewall rules : {len(rules)}")
        print(f"  NAT rules      : {len(nat_rules)}")
        return data


# ============================================================ factory

VENDOR_CLIENTS = {
    "checkpoint": CheckpointAPIClient,
    "paloalto": PaloAltoAPIClient,
    "fortinet": FortinetAPIClient,
}


def fetch_policy(server, port, username, password, vendor=None, verify=False,
                 timeout=300, page_size=200):
    """Detect vendor (if not given) and fetch policy data."""
    if vendor and vendor not in VENDORS:
        raise ValueError(f"Unknown vendor '{vendor}'. Choose from: {', '.join(VENDORS)}")

    if vendor is None:
        print("Detecting firewall vendor ...")
        detected = detect_vendor(server, port, verify)
        if detected:
            print(f"  Detected: {detected}")
            vendor = detected
        else:
            print("  Could not auto-detect vendor.")
            vendor = input(f"Enter vendor ({', '.join(VENDORS)}): ").strip().lower()
            while vendor not in VENDORS:
                vendor = input(f"Must be one of {', '.join(VENDORS)}: ").strip().lower()

    cls = VENDOR_CLIENTS[vendor]
    print(f"Connecting to {server}:{port} as {username} ({vendor}) ...")
    client = cls(server, username, password, port=port, verify=verify,
                 timeout=timeout, page_size=page_size)
    data = client.fetch_all()
    client.logout()
    return data


# ====================================================================== CLI

def main():
    parser = argparse.ArgumentParser(
        description="Fetch firewall policy from Checkpoint, Palo Alto, or Fortinet API to JSON."
    )
    parser.add_argument("--server", required=True,
                        help="Management server IP/hostname")
    parser.add_argument("--username", required=True, help="API user")
    parser.add_argument("--password", help="Password (omit for prompt)")
    parser.add_argument("--port", type=int, default=443,
                        help="API port (default 443)")
    parser.add_argument("--vendor", choices=VENDORS, default=None,
                        help="Firewall vendor (auto-detect if omitted)")
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
        default = "outputs/fetched_policy.json"
        user_path = input(f"Save path [{default}]: ").strip()
        output = user_path or default

    out_dir = os.path.dirname(output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    data = fetch_policy(args.server, args.port, args.username, password,
                        vendor=args.vendor, verify=args.ssl_verify)

    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    total_rules = sum(
        len(l.get("rules", []))
        for l in data["policy-package"]["access-control-policy"]["layers"]
    )
    obj_count = sum(len(v) for v in data.get("objects", {}).values())

    print(f"\nSaved to '{output}'")
    print(f"  Vendor        : {data.get('_vendor', 'unknown')}")
    print(f"  Access layers : {len(data['policy-package']['access-control-policy']['layers'])}")
    print(f"  Access rules  : {total_rules}")
    nat_rules = data.get('policy-package', {}).get('nat-policy', {}).get('rules', [])
    if nat_rules:
        print(f"  NAT rules     : {len(nat_rules)}")
    print(f"  Objects       : {obj_count}")


if __name__ == "__main__":
    main()
