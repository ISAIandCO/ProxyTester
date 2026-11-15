"""Subscriptions are data, never complete executable core configurations."""
import base64
import json
import re
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx
import yaml

from .util import error_kind, identifier, safe_name


@dataclass
class Node:
    name: str
    protocol: str = "unknown"
    host: str = ""
    port: int = 0
    core: str = ""
    outbound: dict = field(default_factory=dict, repr=False)
    issue: str = ""
    source: str = ""
    country: str = "?"
    id: str = ""

    def __post_init__(self):
        self.name = safe_name(self.name)
        self.id = identifier([self.name, self.protocol, self.host, self.port, self.outbound, self.issue])
        flag = re.search(r"[\U0001f1e6-\U0001f1ff]{2}", self.name)
        code = re.search(r"(?:^|[\s\[(_-])(DE|NL|US|GB|FR|FI|SE|CH|PL|RU|TR|JP|SG|CA|AU|NO|RS|IT|MK|GE|DK)(?:$|[\s\])_-])", self.name, re.I)
        if flag:
            self.country = "".join(chr(ord(c) - 0x1f1e6 + 65) for c in flag[0])
        elif code:
            self.country = code[1].upper()

    def public(self):
        return {k: getattr(self, k) for k in ("id", "name", "protocol", "country", "source", "issue")}


def boolean(value):
    if str(value).lower() not in ("true", "false", "1", "0", ""):
        raise ValueError("Invalid boolean option")
    return str(value).lower() in ("true", "1")


def no_routing(value):
    if isinstance(value, dict):
        forbidden = {"dialerProxy", "proxySettings", "detour", "downloadSettingsFromFile", "certificate_path",
                     "key_path", "certificates", "pinnedPeerCertificateChainSha256", "acceptProxyProtocol", "sockopt"}
        if forbidden.intersection(value):
            raise ValueError("Unsupported imported routing, socket or file option; export a single standalone node")
        for v in value.values():
            no_routing(v)
    elif isinstance(value, list):
        for v in value:
            no_routing(v)


def valid(node):
    if not node.host or not 1 <= int(node.port) <= 65535:
        raise ValueError("Missing host or invalid port")
    no_routing(node.outbound)
    if node.protocol == "vless":
        settings = node.outbound["settings"]
        if len(settings.get("vnext", [])) != 1 or len(settings["vnext"][0].get("users", [])) != 1:
            raise ValueError("Exactly one VLESS endpoint/user required")
        user = settings["vnext"][0]["users"][0]
        uuid.UUID(user["id"])
        stream = node.outbound.get("streamSettings", {})
        network = stream.get("network", "tcp")
        if network not in ("tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "h2", "http"):
            raise ValueError("Unsupported VLESS transport")
        if user.get("flow") and network in ("xhttp", "splithttp", "ws", "grpc", "httpupgrade", "http", "h2"):
            raise ValueError("VLESS flow is incompatible with this transport")
        if stream.get("security") == "reality":
            reality = stream.get("realitySettings", {})
            if not (reality.get("publicKey") or reality.get("password")) or not reality.get("serverName"):
                raise ValueError("REALITY requires public key and SNI")
    elif node.protocol == "hysteria2":
        if not node.outbound.get("password") or not node.outbound.get("tls", {}).get("enabled"):
            raise ValueError("Hysteria2 requires password and TLS")
    return node


def from_uri(line):
    p = urlsplit(line)
    protocol = {"hy2": "hysteria2"}.get(p.scheme, p.scheme)
    name = unquote(p.fragment) or p.hostname or "Unnamed"
    if protocol not in ("vless", "hysteria2"):
        return Node(name, protocol, issue="Unsupported protocol")
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("Duplicate URI parameter")
    q = dict(pairs)
    host, port = p.hostname, p.port or 443
    if protocol == "vless":
        allowed = {"encryption", "flow", "security", "type", "sni", "serverName", "fp", "pbk", "sid", "spx",
                   "alpn", "allowInsecure", "insecure", "host", "path", "mode", "extra", "serviceName", "authority",
                   "headerType", "ed", "eh", "packetEncoding", "remarks", "group", "pqv"}
        if set(q) - allowed:
            raise ValueError("Unsupported VLESS URI parameter: " + ", ".join(sorted(set(q) - allowed)))
        network = q.get("type", "tcp")
        if q.get("headerType", "none") != "none":
            raise ValueError("Unsupported TCP headerType")
        user = {"id": unquote(p.username or ""), "encryption": q.get("encryption", "none")}
        if q.get("flow"):
            user["flow"] = q["flow"]
        if q.get("packetEncoding"):
            if q["packetEncoding"] != "xudp":
                raise ValueError("Unsupported packetEncoding")
        security = q.get("security", "none")
        if security not in ("none", "tls", "reality"):
            raise ValueError("Unsupported VLESS security")
        stream = {"network": network, "security": security}
        sni = q.get("sni", q.get("serverName", host))
        if security == "reality":
            stream["realitySettings"] = {"serverName": sni, "fingerprint": q.get("fp", "chrome"),
                                         "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
                                         "spiderX": q.get("spx", "/")}
            if q.get("pqv"):
                stream["realitySettings"]["mldsa65Verify"] = q["pqv"]
        elif security == "tls":
            tls = {"serverName": sni, "fingerprint": q.get("fp", "chrome"),
                   "allowInsecure": boolean(q.get("allowInsecure", q.get("insecure", "0")))}
            if q.get("alpn"):
                tls["alpn"] = q["alpn"].split(",")
            stream["tlsSettings"] = tls
        if network in ("xhttp", "splithttp"):
            opts = {"host": q.get("host", ""), "path": q.get("path", "/"), "mode": q.get("mode", "auto")}
            if "extra" in q:
                opts["extra"] = json.loads(q["extra"])
                if not isinstance(opts["extra"], dict):
                    raise ValueError("XHTTP extra must be an object")
            stream["xhttpSettings"] = opts
            stream["network"] = "xhttp"
        elif network == "ws":
            stream["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
            if q.get("ed"):
                stream["wsSettings"]["maxEarlyData"] = int(q["ed"])
                stream["wsSettings"]["earlyDataHeaderName"] = q.get("eh", "Sec-WebSocket-Protocol")
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": q.get("serviceName", ""), "authority": q.get("authority", ""),
                                       "multiMode": q.get("mode") == "multi"}
        elif network == "httpupgrade":
            stream["httpupgradeSettings"] = {"host": q.get("host", host), "path": q.get("path", "/")}
        elif network in ("http", "h2"):
            stream["httpSettings"] = {"host": q.get("host", host).split(","), "path": q.get("path", "/")}
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                    "streamSettings": stream}
        return valid(Node(name, protocol, host, port, "xray", outbound))
    allowed = {"sni", "peer", "insecure", "allowInsecure", "obfs", "obfs-password", "alpn", "mport",
               "upmbps", "downmbps", "up", "down", "hop-interval", "remarks", "group"}
    if set(q) - allowed:
        raise ValueError("Unsupported Hysteria2 URI parameter: " + ", ".join(sorted(set(q) - allowed)))
    outbound = {"type": "hysteria2", "server": host, "server_port": port,
                "password": unquote(p.netloc.rsplit("@", 1)[0]),
                "tls": {"enabled": True, "server_name": q.get("sni", q.get("peer", host)),
                        "insecure": boolean(q.get("insecure", q.get("allowInsecure", "0")))}}
    if q.get("alpn"):
        outbound["tls"]["alpn"] = q["alpn"].split(",")
    if q.get("obfs"):
        if q["obfs"] != "salamander" or not q.get("obfs-password"):
            raise ValueError("Unsupported or incomplete Hysteria2 obfuscation")
        outbound["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
    if q.get("mport"):
        outbound.pop("server_port")
        outbound["server_ports"] = q["mport"].replace("-", ":").split(",")
    if q.get("hop-interval"):
        outbound["hop_interval"] = q["hop-interval"]
    for a, b, key in (("upmbps", "up", "up_mbps"), ("downmbps", "down", "down_mbps")):
        if q.get(a, q.get(b)):
            outbound[key] = int(q.get(a, q.get(b)))
    return valid(Node(name, protocol, host, port, "sing-box", outbound))


def from_native(obj):
    obj = deepcopy(obj)
    name = obj.pop("tag", obj.pop("name", "Unnamed"))
    protocol = obj.get("protocol", obj.get("type", "unknown"))
    if protocol == "vless" and "protocol" in obj:
        endpoint = obj["settings"]["vnext"][0]
        # Only the outbound is retained; imported DNS/rules/fallback outbounds never execute.
        return valid(Node(name, protocol, endpoint["address"], endpoint["port"], "xray", obj))
    if protocol == "vless":
        allowed = {"type", "server", "server_port", "uuid", "flow", "tls", "transport", "packet_encoding", "network"}
        if set(obj) - allowed:
            raise ValueError("Unsupported sing-box VLESS option")
        tls, transport = obj.get("tls", {}), obj.get("transport", {})
        if set(tls) - {"enabled", "server_name", "insecure", "alpn", "utls", "reality"}:
            raise ValueError("Unsupported sing-box TLS option")
        q = {"type": transport.get("type", "tcp"), "security": "none", "flow": obj.get("flow", "")}
        if tls.get("enabled"):
            q.update(security="tls", sni=tls.get("server_name", obj["server"]), insecure=str(tls.get("insecure", False)))
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            q["fp"] = tls.get("utls", {}).get("fingerprint", "chrome")
            if tls.get("reality", {}).get("enabled"):
                q.update(security="reality", pbk=tls["reality"]["public_key"], sid=tls["reality"].get("short_id", ""))
        if set(transport) - {"type", "path", "headers", "service_name", "host", "max_early_data", "early_data_header_name"}:
            raise ValueError("Unsupported sing-box VLESS transport option")
        q.update(path=transport.get("path", "/"), host=transport.get("headers", {}).get("Host", ""),
                 serviceName=transport.get("service_name", ""))
        if transport.get("max_early_data"):
            q.update(ed=transport["max_early_data"], eh=transport.get("early_data_header_name", "Sec-WebSocket-Protocol"))
        from urllib.parse import urlencode, quote
        host = obj["server"]
        host = f"[{host}]" if ":" in host else host
        return from_uri(f"vless://{obj['uuid']}@{host}:{obj['server_port']}?{urlencode(q)}#{quote(name)}")
    if protocol == "hysteria2":
        allowed = {"type", "server", "server_port", "server_ports", "hop_interval", "password", "up_mbps", "down_mbps",
                   "obfs", "tls", "network", "brutal_debug", "udp_fragment", "connect_timeout"}
        if set(obj) - allowed:
            raise ValueError("Unsupported sing-box Hysteria2 option")
        return valid(Node(name, protocol, obj["server"], obj.get("server_port", 443), "sing-box", obj))
    return Node(name, protocol, issue="Unsupported protocol")


def from_clash(obj):
    typ = obj.get("type")
    allowed = {"name", "type", "server", "port", "uuid", "password", "flow", "tls", "servername", "sni",
               "skip-cert-verify", "client-fingerprint", "fingerprint", "reality-opts", "network", "ws-opts", "grpc-opts",
               "xhttp-opts", "alpn", "obfs", "obfs-password", "up", "down", "ports", "hop-interval", "udp", "packet-encoding"}
    if set(obj) - allowed:
        raise ValueError("Unsupported Clash option: " + ", ".join(sorted(set(obj) - allowed)))
    if obj.get("fingerprint"):
        raise ValueError("Unsupported Clash certificate fingerprint pin; use client-fingerprint for uTLS")
    from urllib.parse import urlencode, quote
    q = {"sni": obj.get("servername", obj.get("sni", obj.get("server"))),
         "insecure": str(obj.get("skip-cert-verify", False))}
    if obj.get("alpn"):
        q["alpn"] = ",".join(obj["alpn"])
    if typ == "vless":
        q.update(type=obj.get("network", "tcp"), security="tls" if obj.get("tls") else "none",
                 flow=obj.get("flow", ""), fp=obj.get("client-fingerprint", "chrome"))
        if obj.get("reality-opts"):
            q.update(security="reality", pbk=obj["reality-opts"]["public-key"], sid=obj["reality-opts"].get("short-id", ""))
        opts = obj.get("xhttp-opts", obj.get("ws-opts", {}))
        if set(opts) - {"path", "host", "headers", "mode", "extra", "max-early-data", "early-data-header-name"}:
            raise ValueError("Unsupported Clash transport option")
        if set(opts.get("headers", {})) - {"Host"}:
            raise ValueError("Unsupported Clash transport header; use native Xray JSON")
        q.update(path=opts.get("path", "/"), host=opts.get("host", opts.get("headers", {}).get("Host", "")))
        if opts.get("max-early-data"):
            q.update(ed=opts["max-early-data"], eh=opts.get("early-data-header-name", "Sec-WebSocket-Protocol"))
        if obj.get("packet-encoding"):
            q["packetEncoding"] = obj["packet-encoding"]
        if "extra" in opts:
            q["extra"] = json.dumps(opts["extra"])
        if "mode" in opts:
            q["mode"] = opts["mode"]
        if "grpc-opts" in obj:
            q["serviceName"] = obj["grpc-opts"].get("grpc-service-name", "")
        auth = obj["uuid"]
    elif typ == "hysteria2":
        auth = obj["password"]
        for k in ("obfs", "obfs-password", "up", "down", "hop-interval"):
            if k in obj:
                q[k] = obj[k]
        if "ports" in obj:
            q["mport"] = obj["ports"]
    else:
        return Node(obj.get("name", "Unnamed"), typ or "unknown", issue="Unsupported protocol")
    host = obj["server"]
    host = f"[{host}]" if ":" in host else host
    return from_uri(f"{typ}://{quote(str(auth), safe='')}@{host}:{obj['port']}?{urlencode(q)}#{quote(obj.get('name', 'Unnamed'))}")


def parse(text, source="local"):
    text = text.lstrip("\ufeff").strip()
    if not text:
        return [Node(source, issue="Empty subscription", source=source)]
    if "://" not in text and not text.startswith(("{", "[", "proxies:")):
        try:
            decoded = base64.urlsafe_b64decode(re.sub(r"\s", "", text) + "=" * (-len(re.sub(r"\s", "", text)) % 4)).decode()
            if "://" in decoded or decoded.lstrip().startswith(("{", "[", "proxies:")):
                text = decoded
        except (ValueError, UnicodeError):
            pass
    nodes = []

    def add(value, mode):
        try:
            node = from_uri(value) if mode == "uri" else from_clash(value) if mode == "clash" else from_native(value)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
            # Never echo the original input; exceptions like invalid port embed it.
            message = str(e) if isinstance(e, ValueError) and str(e).startswith(("Unsupported", "Missing", "REALITY", "VLESS", "Exactly", "Hysteria2", "Duplicate", "XHTTP", "Invalid boolean")) else "Invalid configuration (" + type(e).__name__ + ")"
            name = value.get("name", value.get("tag", "Invalid entry")) if isinstance(value, dict) else "Invalid entry"
            node = Node(name, issue=safe_name(message))
        node.source = source
        node.id = identifier([source, node.id, value])
        nodes.append(node)

    if text.startswith(("{", "[")) or re.search(r"(?m)^proxies\s*:", text):
        try:
            data = json.loads(text) if text.startswith(("{", "[")) else yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                for item in data["proxies"]:
                    add(item, "clash")
            else:
                configs = data if isinstance(data, list) else [data]
                for config in configs:
                    if isinstance(config, str):
                        add(config, "uri")
                    else:
                        outbounds = config.get("outbounds", [config])
                        for item in outbounds:
                            if item.get("type", item.get("protocol")) in ("direct", "block", "dns", "freedom", "blackhole", "selector", "urltest"):
                                continue
                            add(item, "native")
        except (ValueError, TypeError, AttributeError, yaml.YAMLError):
            nodes.append(Node(source, issue="Malformed JSON/YAML subscription", source=source))
    else:
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                add(line.strip(), "uri")
    return nodes or [Node(source, issue="No supported proxy entries", source=source)]


async def collect(config):
    nodes = []
    # Subscription requests intentionally use the host network (there is no node yet).
    async with httpx.AsyncClient(trust_env=False, timeout=config["timeout"], follow_redirects=True) as client:
        for index, source in enumerate(config["subscriptions"], 1):
            label = f"subscription-{index}"
            headers = {"User-Agent": "ProxyTester/1.0", **source.get("headers", {})}
            params = dict(source.get("query", {}))
            if source.get("hwid"):
                mode, name = source.get("hwid_mode", "header"), source.get("hwid_name", "x-hwid")
                if mode == "header":
                    headers[name] = source["hwid"]
                elif mode == "query":
                    params[name] = source["hwid"]
                else:
                    headers["Authorization"] = "Bearer " + source["hwid"]
            try:
                async with client.stream("GET", source["url"], headers=headers, params=params) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 16000000:
                            raise ValueError("Subscription exceeds 16 MB")
                nodes.extend(parse(body.decode("utf-8-sig"), label))
            except (httpx.HTTPError, ValueError, UnicodeError) as e:
                status = f"HTTP {e.response.status_code}" if isinstance(e, httpx.HTTPStatusError) else error_kind(e)
                nodes.append(Node(label, issue="Subscription failed: " + status, source=label))
    for index, filename in enumerate(config["files"], 1):
        label = f"file-{index}"
        try:
            nodes.extend(parse(Path(filename).read_text(encoding="utf-8-sig"), label))
        except (OSError, UnicodeError) as e:
            nodes.append(Node(label, issue="File failed: " + error_kind(e), source=label))
    return list({n.id: n for n in nodes}.values())
