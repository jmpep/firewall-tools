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
        self._cached_objects = {}
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
            # Cache objects-dictionary from rulebase/object endpoints
            for obj in res.get("objects-dictionary") or []:
                uid = obj.get("uid")
                if uid:
                    self._cached_objects[uid] = obj
            if result_key is not None:
                key = result_key
            else:
                key = "objects"
                # try both hyphenated and underscored forms
                candidate = endpoint.replace("show-", "")
                for k in (candidate, candidate.replace("-", "_")):
                    if k in res:
                        key = k
                        break
            items = res.get(key) or []
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

    # ------------------------------------------------------------------ packages, layers & rules

    def fetch_packages(self):
        """Return list of policy package names."""
        try:
            items = self._paginate("show-packages", {}, result_key="packages")
            return [p["name"] for p in items]
        except Exception as e:
            print(f"  Warning: show-packages failed ({e})")
            return []

    def fetch_layers(self):
        items = self._paginate("show-access-layers", {}, result_key="access-layers")
        return [l["name"] for l in items]

    def fetch_rulebase(self, layer_name, package=None):
        def _try(pkg):
            p = {
                "name": layer_name,
                "details-level": "full",
                "use-object-dictionary": True,
            }
            if pkg:
                p["package"] = pkg
            return self._paginate("show-access-rulebase", p, result_key="rulebase")

        # try explicit package, then auto-discovered packages, then no package
        candidates = []
        if package:
            candidates.append(package)
        else:
            pkgs = self.fetch_packages()
            candidates.extend(pkgs)
            candidates.append(None)  # fallback: no package context

        items = []
        used_pkg = None
        for pkg in candidates:
            try:
                result = _try(pkg)
                if result:
                    items = result
                    used_pkg = pkg
                    break
            except Exception:
                continue

        uid = ""
        if items:
            uid = items[0].get("uid", "")
        else:
            try:
                single = self._post("show-access-rulebase", {"name": layer_name, "limit": 1, "details-level": "uid"})
                uid = single.get("uid", "")
            except Exception:
                pass
        return {"rulebase": items, "uid": uid, "_package": used_pkg}

    def fetch_https_inspection(self):
        try:
            return self._paginate("show-https-inspection-rulebase", {
                "details-level": "full",
                "use-object-dictionary": True,
            }, result_key="rulebase")
        except Exception as e:
            print(f"  Warning: HTTPS inspection not available ({e})")
            return []

    def fetch_threat_rulebase(self):
        try:
            return self._paginate("show-threat-rulebase", {
                "details-level": "full",
                "use-object-dictionary": True,
            }, result_key="rulebase")
        except Exception as e:
            print(f"  Warning: Threat rulebase not available ({e})")
            return []

    def fetch_nat_rulebase(self, package=None):
        try:
            p = {"details-level": "full", "use-object-dictionary": True}
            if package:
                p["package"] = package
            result = self._paginate("show-nat-rulebase", p, result_key="rulebase")
            if result:
                return result
        except Exception:
            pass
        # auto-discover package
        if not package:
            try:
                pkgs = self.fetch_packages()
                for pkg in pkgs:
                    try:
                        result = self._paginate("show-nat-rulebase",
                                                {"details-level": "full", "use-object-dictionary": True, "package": pkg},
                                                result_key="rulebase")
                        if result:
                            return result
                    except Exception:
                        continue
            except Exception:
                pass
        return []

    # ------------------------------------------------------------------ objects

    SINGULAR_TO_PLURAL = {
        "host": "hosts",
        "network": "networks",
        "group": "groups",
        "address-range": "address-ranges",
        "service-tcp": "services-tcp",
        "service-udp": "services-udp",
        "service-icmp": "services-icmp",
        "service-other": "services-other",
        "service-dce-rpc": "services-dce-rpc",
        "service-rpc": "services-rpc",
        "service-sctp": "services-sctp",
        "service-icmp6": "services-icmp6",
        "multicast-address-range": "multicast-address-ranges",
        "service-group": "service-groups",
        "application-site": "application-sites",
        "application-site-category": "application-site-categories",
        "application-site-group": "application-site-groups",
        "time": "times",
        "user-group": "users",
        "security-zone": "security-zones",
        "dynamic-object": "dynamic-objects",
        "dns-domain": "dns-domains",
        "group-with-exclusion": "groups-with-exclusion",
        "time-group": "time-groups",
        "application-group": "application-groups",
        "exception-group": "exception-groups",
        "tag": "tags",
        "simple-gateway": "simple-gateways",
        "simple-cluster": "simple-clusters",
        "trusted-client": "trusted-clients",
        "opsec-application": "opsec-applications",
        "data-center": "data-centers",
        "data-center-object": "data-center-objects",
        "cpmi-gateway": "cpmi-gateways",
        "cpmi-gateway-cluster": "cpmi-gateway-clusters",
        "vsx-net-object": "vsx-net-objects",
        "vsx-objects": "vsx-objects",
        "wildcard": "wildcards",
        "updatable-object": "updatable-objects",
        "access-role": "access-roles",
        "threat-profile": "threat-profiles",
    }

    def _fetch_objects(self, show_cmd, result_key=None):
        try:
            return self._paginate(show_cmd, {"details-level": "full"},
                                  result_key=result_key)
        except Exception as e:
            print(f"  Warning: {show_cmd} failed ({e})")
            return []

    def resolve_uids(self, obj):
        """Recursively replace UID-only references with names from cached objects-dictionary."""
        if isinstance(obj, dict):
            if "uid" in obj and "name" not in obj:
                cached = self._cached_objects.get(obj["uid"])
                if cached:
                    obj["name"] = cached.get("name", "")
            for key in list(obj.keys()):
                obj[key] = self.resolve_uids(obj[key])
        elif isinstance(obj, list):
            for i in range(len(obj)):
                obj[i] = self.resolve_uids(obj[i])
        return obj

    def fetch_all_objects(self):
        objects = {}
        for obj in self._cached_objects.values():
            otype = obj.get("type", "")
            pkey = self.SINGULAR_TO_PLURAL.get(otype)
            if pkey is None:
                continue
            if pkey not in objects:
                objects[pkey] = []
            objects[pkey].append(obj)
        if objects:
            total = sum(len(v) for v in objects.values())
            print(f"  Collected {total} objects from rulebase objects-dictionary ({len(objects)} types)")
            return objects
        # Fallback: individual show-* calls with auto-detected result keys
        print("  No objects-dictionary found, falling back to individual show-* calls")
        okeys = [
            ("show-hosts", "hosts"), ("show-networks", "networks"),
            ("show-groups", "groups"), ("show-address-ranges", "address-ranges"),
            ("show-services-tcp", "services-tcp"), ("show-services-udp", "services-udp"),
            ("show-services-icmp", "services-icmp"), ("show-services-other", "services-other"),
            ("show-service-groups", "service-groups"),
            ("show-application-sites", "application-sites"),
            ("show-application-site-categories", "application-site-categories"),
            ("show-time", "time"), ("show-user-groups", "users"),
            ("show-security-zones", "security-zones"),
            ("show-dynamic-objects", "dynamic-objects"),
            ("show-dns-domains", "dns-domains"),
        ]
        for cmd, key in okeys:
            objects[key] = self._fetch_objects(cmd)
        return objects

    # ------------------------------------------------------------------ assemble

    def fetch_all(self, package=None):
        print("Fetching access layers ...")
        layer_names = self.fetch_layers()
        print(f"  Found layers: {layer_names}")

        # auto-discover packages if not specified
        if not package:
            pkgs = self.fetch_packages()
            if pkgs:
                package = pkgs[0]
                print(f"  Auto-selected package: {package}")

        access_policy = {"layers": []}
        for name in layer_names:
            print(f"  Fetching rulebase for '{name}' ...")
            rb = self.fetch_rulebase(name, package=package)
            layer = {"name": name, "uid": rb.get("uid", ""),
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
            access_policy["layers"].append(layer)

        print("  Fetching HTTPS inspection policy ...")
        https_rules = self.fetch_https_inspection()

        print("  Fetching threat prevention policy ...")
        threat_rules = self.fetch_threat_rulebase()

        print("  Fetching NAT policy ...")
        nat_rules = self.fetch_nat_rulebase(package=package)

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
                "nat-policy": {"rules": nat_rules},
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
            comment_el = entry.find("description")
            comments = comment_el.text.strip() if comment_el is not None else ""
            src_zone = self._parse_members(entry.find("from"), tag="member")
            dst_zone = self._parse_members(entry.find("to"), tag="member")
            apps = self._parse_members(entry.find("application"))
            users = self._parse_members(entry.find("source-user"))
            categories = self._parse_members(entry.find("category"))

            extra = {}
            if src_zone:
                extra["source-zone"] = ", ".join(src_zone)
            if dst_zone:
                extra["destination-zone"] = ", ".join(dst_zone)
            if apps:
                extra["application"] = [{"name": a} for a in apps]
            if users:
                extra["user"] = [{"name": u} for u in users]
            if categories:
                extra["category"] = [{"name": c} for c in categories]

            log_start_el = entry.find("log-start")
            log_end_el = entry.find("log-end")
            track = "Log"
            if log_start_el is not None and log_start_el.text == "yes":
                track = "Log at Start"
            if log_end_el is not None and log_end_el.text == "yes":
                track = "Log at Session End" if track == "Log" else "Log at Start & End"

            log_setting_el = entry.find("log-setting")
            if log_setting_el is not None and log_setting_el.text:
                extra["log-setting"] = log_setting_el.text.strip()

            schedule_el = entry.find("schedule")
            schedule = schedule_el.text.strip() if schedule_el is not None and schedule_el.text else ""

            profile_el = entry.find("profile-setting/group")
            if profile_el is not None and profile_el.text:
                extra["group"] = profile_el.text.strip()

            neg_src = entry.find("negate-source")
            if neg_src is not None and neg_src.text == "yes":
                extra["negate-source"] = True
            neg_dst = entry.find("negate-destination")
            if neg_dst is not None and neg_dst.text == "yes":
                extra["negate-destination"] = True

            icmp_el = entry.find("icmp-unreachable")
            if icmp_el is not None and icmp_el.text == "yes":
                extra["icmp-unreachable"] = True

            uid = entry.get("uuid", f"pa-rule-{i:04d}")
            rules.append(_common_rule(
                i, name, uid, enabled,
                sources or ["Any"], destinations or ["Any"], services or ["Any"],
                action.capitalize(), track, comments,
                install_on=None, time_obj=schedule or None, extra=extra,
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
            src_trans_el = entry.find("source-translation")
            dst_trans_el = entry.find("destination-translation")
            nat_type_el = entry.find("nat-type")
            nat_type = nat_type_el.text.strip() if nat_type_el is not None else "ipv4"

            src_trans_type = "static"
            src_trans_addrs = ["Original"]
            dst_trans_addr = ""
            dst_trans_port = ""
            bi_directional = False
            method = "static"

            if src_trans_el is not None:
                static_ip = src_trans_el.find("static-ip")
                dynamic_ip = src_trans_el.find("dynamic-ip")
                dyn_ip_port = src_trans_el.find("dynamic-ip-and-port")
                if static_ip is not None:
                    ta = static_ip.find("translated-address")
                    if ta is not None:
                        src_trans_addrs = [ta.text.strip()] if ta.text else ["Original"]
                    bd = static_ip.find("bi-directional")
                    if bd is not None and bd.text == "yes":
                        bi_directional = True
                elif dynamic_ip is not None:
                    src_trans_type = "dynamic-ip"
                    method = "dynamic-ip"
                    ta = dynamic_ip.find("translated-address")
                    if ta is not None:
                        src_trans_addrs = [m.text.strip() for m in ta.findall("member") if m.text]
                    if not src_trans_addrs:
                        interface = dynamic_ip.find("interface")
                        if interface is not None and interface.text:
                            src_trans_addrs = [f"interface:{interface.text.strip()}"]
                elif dyn_ip_port is not None:
                    src_trans_type = "dynamic-ip-and-port"
                    method = "dynamic-ip-and-port"
                    ta = dyn_ip_port.find("translated-address")
                    if ta is not None:
                        src_trans_addrs = [m.text.strip() for m in ta.findall("member") if m.text]
                    if not src_trans_addrs:
                        interface = dyn_ip_port.find("interface")
                        if interface is not None and interface.text:
                            src_trans_addrs = [f"interface:{interface.text.strip()}"]

            if dst_trans_el is not None:
                ta = dst_trans_el.find("translated-address")
                if ta is not None and ta.text:
                    dst_trans_addr = ta.text.strip()
                tp = dst_trans_el.find("translated-port")
                if tp is not None and tp.text:
                    dst_trans_port = tp.text.strip()

            nat_rules.append({
                "rule-number": str(i),
                "name": name,
                "uid": entry.get("uuid", f"pa-nat-{i:04d}"),
                "enabled": enabled,
                "method": method,
                "nat-type": nat_type,
                "original-source": [{"name": s} for s in (src or ["Any"])],
                "original-destination": [{"name": d} for d in (dst or ["Any"])],
                "original-service": [{"name": s} for s in (svc or ["Any"])],
                "translated-source": [{"name": s} for s in src_trans_addrs],
                "translated-destination": [{"name": d} for d in ([dst_trans_addr] if dst_trans_addr else ["Original"])],
                "translated-service": [{"name": "Original"}],
                "action": {"name": "translate"},
                "install-on": {"name": ""},
                "comments": entry.findtext("description", ""),
            })
            if bi_directional:
                nat_rules[-1]["bi-directional"] = True
            if dst_trans_port:
                nat_rules[-1]["translated-port"] = dst_trans_port
        return nat_rules

    def _fetch_addresses(self):
        hosts = []
        networks = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/address")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            ip_netmask = entry.find("ip-netmask")
            ip_range = entry.find("ip-range")
            ip_wildcard = entry.find("ip-wildcard")
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
            elif ip_wildcard is not None and ip_wildcard.text:
                hosts.append({"name": name, "ip-address": ip_wildcard.text.strip(), "type": "ip-wildcard"})
            elif fqdn is not None and fqdn.text:
                hosts.append({"name": name, "ip-address": fqdn.text.strip(), "type": "fqdn"})
        return hosts, networks

    def _fetch_service_groups(self):
        groups = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/service-group")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            members = [{"name": m.text.strip()} for m in entry.findall(".//member") if m.text]
            if members:
                groups.append({"name": name, "members": members})
        return groups

    def _fetch_application_groups(self):
        groups = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/application-group")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            members = [{"name": m.text.strip()} for m in entry.findall(".//member") if m.text]
            if members:
                groups.append({"name": name, "members": members})
        return groups

    def _fetch_tags(self):
        tags = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/tag")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            color = entry.findtext("color", "")
            comments = entry.findtext("comments", "")
            tag = {"name": name}
            if color:
                tag["color"] = color
            if comments:
                tag["comments"] = comments
            tags.append(tag)
        return tags

    def _fetch_security_profile_groups(self):
        groups = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/profile-group")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            g = {"name": name}
            for field in ("virus", "spyware", "vulnerability", "url-filtering",
                          "file-blocking", "data-filtering", "wildfire-analysis"):
                val = entry.findtext(field, "")
                if val:
                    g[field] = val
            groups.append(g)
        return groups

    def _fetch_schedules(self):
        schedules = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/schedule")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            sched = {"name": name}
            disable = entry.find("disable-override")
            if disable is not None and disable.text == "yes":
                sched["disable-override"] = True
            sched_type = entry.find("schedule-type")
            if sched_type is not None:
                non_rec = sched_type.find("non-recurring")
                rec = sched_type.find("recurring")
                if non_rec is not None:
                    sched["type"] = "non-recurring"
                    dates = [m.text.strip() for m in non_rec.findall("member") if m.text]
                    if dates:
                        sched["date-time"] = dates
                elif rec is not None:
                    sched["type"] = "recurring"
                    daily = rec.find("daily")
                    weekly = rec.find("weekly")
                    if daily is not None:
                        sched["recurrence"] = "daily"
                        sched["time"] = [m.text.strip() for m in daily.findall("member") if m.text]
                    elif weekly is not None:
                        sched["recurrence"] = "weekly"
                        for day in ("sunday", "monday", "tuesday", "wednesday",
                                    "thursday", "friday", "saturday"):
                            day_el = weekly.find(day)
                            if day_el is not None:
                                times = [m.text.strip() for m in day_el.findall("member") if m.text]
                                if times:
                                    sched[day] = times
            schedules.append(sched)
        return schedules

    def _fetch_edls(self):
        edls = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/external-list")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            edl = {"name": name}
            type_el = entry.find("type")
            if type_el is not None:
                for t in ("ip", "domain", "url", "predefined-ip", "predefined-url"):
                    sub = type_el.find(t)
                    if sub is not None:
                        edl["list-type"] = t
                        url = sub.findtext("url", "")
                        if url:
                            edl["source"] = url
                        recurring = sub.find("recurring")
                        if recurring is not None:
                            for r in ("five-minute", "hourly", "daily", "weekly", "monthly"):
                                r_el = recurring.find(r)
                                if r_el is not None:
                                    edl["repeat"] = r
                                    at = r_el.findtext("at", "")
                                    if at:
                                        edl["repeat-at"] = at
                                    dow = r_el.findtext("day-of-week", "")
                                    if dow:
                                        edl["repeat-day"] = dow
                        break
            edls.append(edl)
        return edls

    def _fetch_custom_url_categories(self):
        categories = []
        result = self._xpath_get("/config/devices/entry/vsys/entry/profiles/custom-url-category")
        for entry in result.findall(".//entry"):
            name = entry.get("name", "")
            cat = {"name": name}
            members = [m.text.strip() for m in entry.findall(".//member") if m.text]
            if members:
                cat["members"] = members
            desc = entry.findtext("description", "")
            if desc:
                cat["description"] = desc
            categories.append(cat)
        return categories

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
        svc_groups = self._fetch_service_groups()
        app_groups = self._fetch_application_groups()
        tags = self._fetch_tags()
        profile_groups = self._fetch_security_profile_groups()
        schedules = self._fetch_schedules()
        edls = self._fetch_edls()
        url_categories = self._fetch_custom_url_categories()
        return {
            "hosts": hosts,
            "networks": networks,
            "groups": groups,
            "service-groups": svc_groups,
            "application-groups": app_groups,
            "services": services,
            "services-tcp": [s for s in services if s.get("protocol") == "tcp"],
            "services-udp": [s for s in services if s.get("protocol") == "udp"],
            "services-icmp": [],
            "services-other": [],
            "application-sites": [],
            "time": [],
            "users": [],
            "tags": tags,
            "security-profile-groups": profile_groups,
            "schedules": schedules,
            "edls": edls,
            "custom-url-categories": url_categories,
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
        print(f"  Security rules         : {len(rules)}")
        print(f"  NAT rules              : {len(nat_rules)}")
        print(f"  Hosts                  : {len(objects.get('hosts', []))}")
        print(f"  Networks               : {len(objects.get('networks', []))}")
        print(f"  Groups                 : {len(objects.get('groups', []))}")
        print(f"  Services               : {len(objects.get('services', []))}")
        print(f"  Service groups         : {len(objects.get('service-groups', []))}")
        print(f"  Application groups     : {len(objects.get('application-groups', []))}")
        print(f"  Tags                   : {len(objects.get('tags', []))}")
        print(f"  Security profile groups: {len(objects.get('security-profile-groups', []))}")
        print(f"  Schedules              : {len(objects.get('schedules', []))}")
        print(f"  EDLs                   : {len(objects.get('edls', []))}")
        print(f"  Custom URL categories  : {len(objects.get('custom-url-categories', []))}")
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
        logtraffic = p.get("logtraffic", "disable")
        logstart = p.get("logtraffic-start", "disable")
        if logstart == "enable":
            track = "Log at Session Start"
        elif logtraffic == "all":
            track = "Log All"
        elif logtraffic == "utm":
            track = "Log UTM"
        else:
            track = "Log" if logtraffic == "enable" else ""
        comments = p.get("comments", "") or p.get("comment", "")
        srcintf = [z.get("name", "") for z in p.get("srcintf", []) if isinstance(z, dict)]
        dstintf = [z.get("name", "") for z in p.get("dstintf", []) if isinstance(z, dict)]
        schedule = p.get("schedule", "")
        profile_group = p.get("profile-group", "")

        sources = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
        destinations = [m.get("name", "") for m in p.get("dstaddr", []) if isinstance(m, dict)]
        services = [m.get("name", "") for m in p.get("service", []) if isinstance(m, dict)]
        users = [m.get("name", "") for m in p.get("users", []) if isinstance(m, dict)]
        groups = [m.get("name", "") for m in p.get("groups", []) if isinstance(m, dict)]

        extra = {}
        if srcintf:
            extra["source-interface"] = ", ".join(srcintf)
        if dstintf:
            extra["destination-interface"] = ", ".join(dstintf)
        if schedule:
            extra["schedule"] = schedule
        if profile_group:
            extra["profile-group"] = profile_group

        sec_profiles = {}
        for sp in ["av-profile", "webfilter-profile", "ips-sensor",
                    "application-list", "dlp-sensor", "dnsfilter-profile",
                    "ssl-ssh-profile", "sctp-filter-profile", "file-filter-profile",
                    "cifs-profile", "voip-profile", "waf-profile",
                    "ssh-filter-profile", "videofilter-profile",
                    "profile-protocol-options"]:
            val = p.get(sp, "")
            if val and val != "default":
                sec_profiles[sp] = val
        if sec_profiles:
            extra["security-profiles"] = sec_profiles

        if p.get("srcaddr-negate", "disable") == "enable":
            extra["source-negate"] = True
        if p.get("dstaddr-negate", "disable") == "enable":
            extra["destination-negate"] = True
        if p.get("service-negate", "disable") == "enable":
            extra["service-negate"] = True

        nat_el = p.get("nat", "disable")
        if nat_el == "enable":
            extra["nat"] = True
        poolname = p.get("poolname", [])
        if isinstance(poolname, list) and any(
            isinstance(m, dict) and m.get("name") for m in poolname
        ):
            extra["nat-pool"] = ", ".join(m["name"] for m in poolname if isinstance(m, dict) and m.get("name"))

        shaper = p.get("traffic-shaper", "")
        shaper_rev = p.get("traffic-shaper-reverse", "")
        if shaper:
            extra["traffic-shaper"] = shaper
        if shaper_rev:
            extra["traffic-shaper-reverse"] = shaper_rev

        if p.get("send-deny-packet", "disable") == "enable":
            extra["send-deny-packet"] = True
        if p.get("capture-packet", "disable") == "enable":
            extra["capture-packet"] = True

        uuid = p.get("uuid", "")
        if uuid:
            extra["uuid"] = uuid

        if users:
            extra["users"] = [{"name": u} for u in users]
        if groups:
            extra["groups"] = [{"name": g} for g in groups]

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

    def _parse_proxy_policy(self, p, i):
        name = p.get("name", "") or p.get("policyid", str(i))
        enabled = p.get("status", "enable") == "enable"
        action = p.get("action", "deny")
        logtraffic = p.get("logtraffic", "disable")
        logstart = p.get("logtraffic-start", "disable")
        if logstart == "enable":
            track = "Log at Session Start"
        elif logtraffic == "all":
            track = "Log All"
        elif logtraffic == "utm":
            track = "Log UTM"
        else:
            track = ""
        comments = p.get("comments", "") or p.get("comment", "")
        proxy_type = p.get("proxy", "")
        srcintf = [z.get("name", "") for z in p.get("srcintf", []) if isinstance(z, dict)]
        dstintf = [z.get("name", "") for z in p.get("dstintf", []) if isinstance(z, dict)]
        schedule = p.get("schedule", "")
        profile_group = p.get("profile-group", "")

        sources = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
        destinations = [m.get("name", "") for m in p.get("dstaddr", []) if isinstance(m, dict)]
        services = [m.get("name", "") for m in p.get("service", []) if isinstance(m, dict)]
        users = [m.get("name", "") for m in p.get("users", []) if isinstance(m, dict)]
        groups = [m.get("name", "") for m in p.get("groups", []) if isinstance(m, dict)]

        extra = {}
        if proxy_type:
            extra["proxy-type"] = proxy_type
        if srcintf:
            extra["source-interface"] = ", ".join(srcintf)
        if dstintf:
            extra["destination-interface"] = ", ".join(dstintf)
        if schedule:
            extra["schedule"] = schedule
        if profile_group:
            extra["profile-group"] = profile_group

        if p.get("transparent", "disable") == "enable":
            extra["transparent"] = True
        if p.get("webcache", "disable") == "enable":
            extra["webcache"] = True
        if p.get("webcache-https", "disable") == "enable":
            extra["webcache-https"] = True
        disclaimer = p.get("disclaimer", "disable")
        if disclaimer != "disable":
            extra["disclaimer"] = disclaimer
        redirect_url = p.get("redirect-url", "")
        if redirect_url:
            extra["redirect-url"] = redirect_url
        webproxy_forward = p.get("webproxy-forward-server", "")
        if webproxy_forward:
            extra["webproxy-forward-server"] = webproxy_forward
        webproxy_profile = p.get("webproxy-profile", "")
        if webproxy_profile:
            extra["webproxy-profile"] = webproxy_profile
        if p.get("http-tunnel-auth", "disable") == "enable":
            extra["http-tunnel-auth"] = True
        if p.get("ssh-policy-redirect", "disable") == "enable":
            extra["ssh-policy-redirect"] = True
        decrypted = p.get("decrypted-traffic-mirror", "")
        if decrypted:
            extra["decrypted-traffic-mirror"] = decrypted

        sec_profiles = {}
        for sp in ["av-profile", "webfilter-profile", "ips-sensor",
                    "application-list", "dlp-sensor", "file-filter-profile",
                    "emailfilter-profile", "icap-profile", "cifs-profile",
                    "waf-profile", "ssh-filter-profile", "ssl-ssh-profile",
                    "profile-protocol-options"]:
            val = p.get(sp, "")
            if val and val != "default":
                sec_profiles[sp] = val
        if sec_profiles:
            extra["security-profiles"] = sec_profiles

        if p.get("srcaddr-negate", "disable") == "enable":
            extra["source-negate"] = True
        if p.get("dstaddr-negate", "disable") == "enable":
            extra["destination-negate"] = True
        if p.get("service-negate", "disable") == "enable":
            extra["service-negate"] = True

        internet_svc = p.get("internet-service", "disable")
        if internet_svc == "enable":
            extra["internet-service"] = True
            for is_key in ["internet-service-name", "internet-service-group",
                           "internet-service-custom", "internet-service-custom-group"]:
                val = p.get(is_key, [])
                if isinstance(val, list):
                    names = [m.get("name", "") for m in val if isinstance(m, dict) and m.get("name")]
                    if names:
                        extra[is_key] = ", ".join(names)

        if users:
            extra["users"] = [{"name": u} for u in users]
        if groups:
            extra["groups"] = [{"name": g} for g in groups]

        uuid = p.get("uuid", "")
        if uuid:
            extra["uuid"] = uuid
        if p.get("utm-status", "disable") == "enable":
            extra["utm-status"] = True

        uid = p.get("policyid", str(i))
        rule = _common_rule(
            uid, name, f"fg-proxy-{i:04d}", enabled,
            sources or ["Any"], destinations or ["Any"], services or ["Any"],
            action.capitalize(), track, comments,
            install_on=None, extra=extra,
        )
        rule["proxy-type"] = proxy_type
        return rule

    def fetch_proxy_policies(self):
        print("  Fetching proxy policies ...")
        try:
            raw = self._fetch_all_pages("/api/v2/cmdb/firewall/proxy-policy")
            return [self._parse_proxy_policy(p, i + 1) for i, p in enumerate(raw)]
        except Exception as e:
            print(f"  Warning: proxy policies not available ({e})")
            return []

    def fetch_nat_rules(self):
        print("  Fetching NAT policies ...")
        nat_rules = []
        try:
            raw = self._fetch_all_pages("/api/v2/cmdb/firewall/central-snat-map")
            for i, p in enumerate(raw, 1):
                name = p.get("name", f"central-snat-{i:04d}")
                enabled = p.get("status", "enable") == "enable"
                nat_type = p.get("type", "")
                src = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
                dst = [m.get("name", "") for m in p.get("dstaddr", []) if isinstance(m, dict)]
                service = [m.get("name", "") for m in p.get("service", []) if isinstance(m, dict)]
                orig_src = [m.get("name", "") for m in p.get("srcaddr", []) if isinstance(m, dict)]
                nat_rules.append({
                    "rule-number": str(i),
                    "name": name,
                    "uid": p.get("policyid", f"fg-nat-{i:04d}"),
                    "enabled": enabled,
                    "method": nat_type or "dynamic-ip-and-port",
                    "original-source": [{"name": s} for s in (orig_src or ["Any"])],
                    "original-destination": [{"name": d} for d in (dst or ["Any"])],
                    "original-service": [{"name": s} for s in (service or ["Any"])],
                    "translated-source": [{"name": s} for s in src or ["Original"]],
                    "translated-destination": [{"name": "Original"}],
                    "translated-service": [{"name": "Original"}],
                    "action": {"name": "snat"},
                    "install-on": {"name": ""},
                    "comments": p.get("comments", "") or p.get("comment", ""),
                })
        except Exception as e:
            print(f"  Warning: Central SNAT not available ({e})")

        try:
            vip_raw = self._fetch_all_pages("/api/v2/cmdb/firewall/vip")
            offset = len(nat_rules)
            for i, v in enumerate(vip_raw, offset + 1):
                name = v.get("name", f"vip-{i:04d}")
                enabled = v.get("status", "enable") == "enable"
                mappedip = v.get("mappedip", [])
                if isinstance(mappedip, list) and mappedip:
                    dst = mappedip[0].get("range", "") if isinstance(mappedip[0], dict) else str(mappedip[0])
                else:
                    dst = ""
                extip = v.get("extip", "")
                port_fwd = v.get("portforward", "") == "enable"
                extport = v.get("extport", "") if port_fwd else ""
                mappedport = v.get("mappedport", "") if port_fwd else ""
                proto = v.get("protocol", "")
                nat_rules.append({
                    "rule-number": str(i),
                    "name": name,
                    "uid": f"fg-vip-{i:04d}",
                    "enabled": enabled,
                    "method": "static-nat",
                    "original-source": [{"name": "Any"}],
                    "original-destination": [{"name": extip}] if extip else [{"name": "Any"}],
                    "original-service": [{"name": extport}] if extport else [{"name": "Any"}],
                    "translated-source": [{"name": "Original"}],
                    "translated-destination": [{"name": dst}] if dst else [{"name": "Original"}],
                    "translated-service": [{"name": mappedport}] if mappedport else [{"name": "Original"}],
                    "action": {"name": "dnat"},
                    "install-on": {"name": ""},
                    "comments": v.get("comment", "") or v.get("comments", ""),
                })
        except Exception as e:
            print(f"  Warning: VIPs not available for NAT ({e})")
        return nat_rules

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

    def _fetch_service_groups(self):
        groups = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall.service/group")
            for g in items:
                name = g.get("name", "")
                members = []
                for m in g.get("member", []):
                    if isinstance(m, dict) and m.get("name"):
                        members.append({"name": m["name"]})
                if members:
                    groups.append({"name": name, "members": members})
        except Exception as e:
            print(f"  Warning: service groups not available ({e})")
        return groups

    def _fetch_schedules(self):
        schedules = []
        for path, stype in [
            ("/api/v2/cmdb/firewall.schedule/recurring", "recurring"),
            ("/api/v2/cmdb/firewall.schedule/onetime", "onetime"),
            ("/api/v2/cmdb/firewall.schedule/group", "group"),
        ]:
            try:
                items = self._fetch_all_pages(path)
                for s in items:
                    name = s.get("name", "")
                    entry = {"name": name, "type": stype}
                    if stype == "recurring":
                        entry.update({
                            "day": s.get("day", ""),
                            "start": s.get("start", ""),
                            "end": s.get("end", ""),
                        })
                    elif stype == "onetime":
                        entry.update({
                            "start": s.get("start", ""),
                            "end": s.get("end", ""),
                        })
                    elif stype == "group":
                        members = []
                        for m in s.get("member", []):
                            if isinstance(m, dict) and m.get("name"):
                                members.append({"name": m["name"]})
                        entry["members"] = members
                    schedules.append(entry)
            except Exception as e:
                print(f"  Warning: schedules ({stype}) not available ({e})")
        return schedules

    def _fetch_vips(self):
        vips = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall/vip")
            for v in items:
                name = v.get("name", "")
                entry = {"name": name}
                mappedip = v.get("mappedip", [])
                if isinstance(mappedip, list) and len(mappedip) > 0:
                    entry["mapped-ip"] = mappedip[0].get("range", "") if isinstance(mappedip[0], dict) else str(mappedip[0])
                extip = v.get("extip", "")
                if extip:
                    entry["ext-ip"] = extip
                port_fwd = v.get("portforward", "")
                if port_fwd == "enable":
                    entry["port-forward"] = True
                    entry["extport"] = v.get("extport", "")
                    entry["mappedport"] = v.get("mappedport", "")
                vips.append(entry)
        except Exception as e:
            print(f"  Warning: VIPs not available ({e})")
        return vips

    def _fetch_ippools(self):
        pools = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall/ippool")
            for p in items:
                name = p.get("name", "")
                entry = {"name": name}
                startip = p.get("startip", "")
                endip = p.get("endip", "")
                if startip:
                    entry["start-ip"] = startip
                if endip:
                    entry["end-ip"] = endip
                pools.append(entry)
        except Exception as e:
            print(f"  Warning: IP pools not available ({e})")
        return pools

    def _fetch_profile_groups(self):
        groups = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/firewall/profile-group")
            for g in items:
                name = g.get("name", "")
                groups.append({
                    "name": name,
                    "av-profile": g.get("av-profile", ""),
                    "webfilter-profile": g.get("webfilter-profile", ""),
                    "ips-sensor": g.get("ips-sensor", ""),
                    "application-list": g.get("application-list", ""),
                    "dlp-sensor": g.get("dlp-sensor", ""),
                    "dnsfilter-profile": g.get("dnsfilter-profile", ""),
                    "ssl-ssh-profile": g.get("ssl-ssh-profile", ""),
                })
        except Exception as e:
            print(f"  Warning: profile groups not available ({e})")
        return groups

    def _fetch_tags(self):
        tags = []
        try:
            items = self._fetch_all_pages("/api/v2/cmdb/system/object-tagging")
            for t in items:
                name = t.get("name", "")
                tags.append({"name": name})
        except Exception as e:
            print(f"  Warning: tags not available ({e})")
        return tags

    def fetch_all_objects(self):
        print("  Fetching objects ...")
        hosts, networks = self._fetch_addresses()
        groups = self._fetch_addr_groups()
        services = self._fetch_services()
        svc_groups = self._fetch_service_groups()
        schedules = self._fetch_schedules()
        vips = self._fetch_vips()
        ippools = self._fetch_ippools()
        profile_groups = self._fetch_profile_groups()
        tags = self._fetch_tags()
        return {
            "hosts": hosts,
            "networks": networks,
            "groups": groups,
            "service-groups": svc_groups,
            "services": services,
            "services-tcp": [s for s in services if s.get("protocol") == "tcp"],
            "services-udp": [s for s in services if s.get("protocol") == "udp"],
            "services-icmp": [],
            "services-other": [],
            "application-sites": [],
            "time": [],
            "users": [],
            "schedules": schedules,
            "vips": vips,
            "ip-pools": ippools,
            "security-profile-groups": profile_groups,
            "tags": tags,
        }

    def fetch_all(self):
        rules = self.fetch_policies()
        proxy_rules = self.fetch_proxy_policies()
        nat_rules = self.fetch_nat_rules()
        objects = self.fetch_all_objects()

        layer = {
            "name": "IPv4 Policy",
            "uid": "fg-layer-v4-001",
            "rules": rules,
            "inline-layers": [],
        }
        pkg = _common_package("fetched_policy", [layer], nat_rules)
        pkg["proxy-policy"] = {"rules": proxy_rules}
        data = {
            "policy-package": pkg,
            "objects": objects,
            "_vendor": "fortinet",
        }
        print(f"  Firewall rules          : {len(rules)}")
        print(f"  Proxy rules             : {len(proxy_rules)}")
        print(f"  NAT rules               : {len(nat_rules)}")
        print(f"  Hosts                   : {len(objects.get('hosts', []))}")
        print(f"  Networks                : {len(objects.get('networks', []))}")
        print(f"  Groups                  : {len(objects.get('groups', []))}")
        print(f"  Services                : {len(objects.get('services', []))}")
        print(f"  Service groups          : {len(objects.get('service-groups', []))}")
        print(f"  Schedules               : {len(objects.get('schedules', []))}")
        print(f"  VIPs                    : {len(objects.get('vips', []))}")
        print(f"  IP pools                : {len(objects.get('ip-pools', []))}")
        print(f"  Profile groups          : {len(objects.get('security-profile-groups', []))}")
        print(f"  Tags                    : {len(objects.get('tags', []))}")
        return data


# ============================================================ factory

VENDOR_CLIENTS = {
    "checkpoint": CheckpointAPIClient,
    "paloalto": PaloAltoAPIClient,
    "fortinet": FortinetAPIClient,
}


def fetch_policy(server, port, username, password, vendor=None, verify=False,
                 timeout=300, page_size=200, package=None):
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
    if vendor == "checkpoint" and package:
        data = client.fetch_all(package=package)
    else:
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
    parser.add_argument("--package", default=None,
                        help="Policy package name (Checkpoint only; auto-detected if omitted)")
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
                        vendor=args.vendor, verify=args.ssl_verify,
                        package=args.package)

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
