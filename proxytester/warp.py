import asyncio
import base64
import ipaddress
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .network import client, bounded_get
from .util import atomic_json


class WarpError(RuntimeError):
    pass


def decode_registration(data, private_key):
    try:
        cfg = data["config"]
        peer = cfg["peers"][0]
        endpoint = peer["endpoint"].get("v4") or peer["endpoint"].get("host") or "engage.cloudflareclient.com:2408"
        p = urlsplit("//" + endpoint)
        addresses = []
        for key, prefix in (("v4", 32), ("v6", 128)):
            address = cfg["interface"]["addresses"].get(key)
            if address:
                addresses.append(str(ipaddress.ip_interface(address if "/" in address else f"{address}/{prefix}")))
        reserved = list(base64.b64decode(cfg["client_id"], validate=True))
        if len(reserved) != 3 or len(base64.b64decode(peer["public_key"], validate=True)) != 32 or not addresses or not p.hostname:
            raise ValueError("Invalid WireGuard fields")
        return {"private_key": private_key, "peer_key": peer["public_key"], "addresses": addresses,
                "endpoint_host": p.hostname, "endpoint_port": p.port or 2408, "reserved": reserved,
                "created": time.time(), "device_id": data.get("id", "")}
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise WarpError("WARP API returned invalid WireGuard configuration") from e


class WarpCache:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = asyncio.Lock()
        self.last_registration = 0
        self.rate_limited = False

    async def get(self, node, proxy, identity, config):
        if not identity.get("verified"):
            raise WarpError("WARP registration requires verified VPN")
        path = self.directory / (node.id + ".json")
        async with self.lock:
            if path.exists():
                try:
                    cached = json.loads(path.read_text())
                    if time.time() - cached["created"] < config["warp_cache_days"] * 86400:
                        return cached, "cache"
                except (ValueError, KeyError, TypeError):
                    pass
            if self.rate_limited:
                raise WarpError("Registration paused after Cloudflare HTTP 429; retry in a later run")
            await asyncio.sleep(max(0, 3 - (time.monotonic() - self.last_registration)))
            key = X25519PrivateKey.generate()
            private = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
            public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            payload = {"key": public, "install_id": "", "fcm_token": "", "tos": datetime.now(timezone.utc).isoformat(),
                       "model": "PC", "serial_number": secrets.token_hex(8), "key_type": "curve25519",
                       "tunnel_type": "wireguard", "locale": "en_US"}
            # POST is intentionally never retried: ambiguous failures may already have registered a device.
            async with client(proxy, config["timeout"]) as session:
                self.last_registration = time.monotonic()
                async with session.stream("POST", config["warp_api"].rstrip("/") + "/reg", json=payload,
                                          follow_redirects=False,
                                          headers={"User-Agent": "WARP for Android", "CF-Client-Version": "a-6.35-4471"}) as response:
                    if response.status_code == 429:
                        self.rate_limited = True
                        raise WarpError("WARP registration rate limited (HTTP 429)")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise WarpError(f"WARP registration HTTP {response.status_code}")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 1000000:
                            raise WarpError("WARP registration response too large")
                try:
                    value = decode_registration(json.loads(body), private)
                except ValueError as e:
                    raise WarpError("WARP API returned invalid JSON") from e
                # DNS for an API-provided hostname also goes through this VPN, never socket.getaddrinfo.
                try:
                    ipaddress.ip_address(value["endpoint_host"])
                except ValueError:
                    response, text = await bounded_get(session, "https://cloudflare-dns.com/dns-query?name=" + value["endpoint_host"] + "&type=A", 100000,
                                                       headers={"Accept": "application/dns-json"})
                    if response.status_code != 200:
                        raise WarpError("WARP endpoint remote DNS failed")
                    try:
                        value["endpoint_host"] = next(str(ipaddress.ip_address(x["data"])) for x in json.loads(text)["Answer"] if x["type"] == 1)
                    except (ValueError, KeyError, StopIteration) as e:
                        raise WarpError("WARP endpoint remote DNS returned no IPv4") from e
            value["registration_exit_ip"] = identity["ip"]
            atomic_json(path, value)
            return value, "registered_through_vpn"
