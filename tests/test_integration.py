"""Real loopback transports, not mocked VPN measurements. No paid subscription needed.

The local registration API and trace IPs are fixtures; they are NOT Cloudflare WARP.
The cascade tests really encrypt WireGuard datagrams and relay them through VLESS/HY2.
"""
import asyncio
import base64
import json
import os
import ssl
import tempfile
import unittest
from contextlib import AsyncExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from proxytester.config import DEFAULT
from proxytester.cores import CoreProcess, Route, binary, free_port
from proxytester.network import client, latency, speed, verify
from proxytester.runner import Runner
from proxytester.services import http_check, browser_checks
from proxytester.subscriptions import parse
from proxytester.warp import WarpCache, WarpError

CORES = Path(os.environ.get("PROXYTESTER_CORES", "cores")).resolve()
UUID = "11111111-1111-4111-8111-111111111111"


def keypair():
    key = X25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return private, public


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(key, hashes.SHA256())
    certfile, keyfile = Path(directory) / "cert.pem", Path(directory) / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(certfile), str(keyfile)


@unittest.skipUnless(binary(CORES, "xray").exists() and binary(CORES, "sing-box").exists(), "Install pinned cores first: proxytester setup --no-browser")
class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.stack = AsyncExitStack()
        await self.stack.__aenter__()
        self.requests = []
        self.reg_status = 200
        self.reg_body = {}
        self.origin = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.origin.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.cfg = deepcopy(DEFAULT)
        self.cfg.update(timeout=3, retries=0, latency_samples=2, latency_url=self.url + "/ok", download_url=self.url + "/data?bytes={bytes}",
                        download_bytes=40000, upload_bytes=10000, upload_url=self.url + "/up", browser=False, warp=False,
                        services=[{"name": "Fixture", "url": self.url + "/ok", "success_regex": "WORKING_APP"}], cloudflare_urls=[])

    async def asyncTearDown(self):
        await self.stack.__aexit__(None, None, None)
        self.origin.close()
        await self.origin.wait_closed()
        self.temp.cleanup()

    async def handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            lines = head.decode().split("\r\n")
            method, path, _ = lines[0].split(" ")
            headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            body = await reader.readexactly(int(headers.get("Content-Length", "0")))
            self.requests.append((method, path, body))
            status, content_type = 200, "text/html"
            if path.startswith("/data"):
                from urllib.parse import parse_qs, urlsplit
                payload = b"x" * int(parse_qs(urlsplit(path).query)["bytes"][0])
            elif path.startswith("/reg"):
                status, payload, content_type = self.reg_status, json.dumps(self.reg_body).encode(), "application/json"
            elif path == "/trace":
                payload = b"ip=203.0.113.9\nwarp=off\nloc=DE\ncolo=LOCAL\n"
            elif path == "/ip":
                payload = b"203.0.113.9"
            elif path == "/js":
                payload = b"<html><body>loading<script>setTimeout(()=>{location.href='/blocked?location=unsupported'},50)</script></body></html>"
            elif path == "/ready":
                payload = b"<html><body><script>setTimeout(()=>{document.body.innerHTML='<button id=ready>New notebook</button>'},50)</script></body></html>"
            elif path.startswith("/blocked"):
                payload = b"Unsupported location"
            else:
                payload = b"WORKING_APP"
            writer.write(f"HTTP/1.1 {status} OK\r\nContent-Length: {len(payload)}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n".encode() + payload)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def vless(self, transport="tcp", reality=False):
        port = free_port()
        stream = {"network": transport, "security": "none"}
        query = "security=none&type=" + transport
        if transport == "xhttp":
            stream["xhttpSettings"] = {"path": "/test"}
            query += "&path=/test&mode=packet-up"
        if reality:
            certfile, keyfile = certificate(self.temp.name)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            async def target(reader, writer):
                writer.close()
            target_server = await asyncio.start_server(target, "127.0.0.1", 0, ssl=ctx)
            self.stack.callback(target_server.close)
            private, public = keypair()
            private = private.replace("+", "-").replace("/", "_").rstrip("=")
            public = public.replace("+", "-").replace("/", "_").rstrip("=")
            stream.update(security="reality", realitySettings={"target": f"127.0.0.1:{target_server.sockets[0].getsockname()[1]}", "serverNames": ["localhost"], "privateKey": private, "shortIds": ["aabb"]})
            query = f"security=reality&type={transport}&sni=localhost&pbk={public}&sid=aabb&fp=chrome"
            if transport == "xhttp":
                query += "&path=/test&mode=auto"
        config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                  "settings": {"clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": stream}],
                  "outbounds": [{"protocol": "freedom"}]}
        server = await self.stack.enter_async_context(CoreProcess(binary(CORES, "xray"), "xray", config, port, 3))
        node = parse(f"vless://{UUID}@127.0.0.1:{port}?{query}#Local_{transport}")[0]
        self.assertFalse(node.issue)
        return node, server

    async def hysteria(self):
        port = free_port()
        certfile, keyfile = certificate(self.temp.name)
        config = {"log": {"disabled": True}, "inbounds": [{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
                  "users": [{"password": "local-secret"}], "obfs": {"type": "salamander", "password": "local-obfs"},
                  "tls": {"enabled": True, "certificate_path": certfile, "key_path": keyfile}}], "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
        server = await self.stack.enter_async_context(CoreProcess(binary(CORES, "sing-box"), "sing-box", config, None, 3))
        node = parse(f"hysteria2://local-secret@127.0.0.1:{port}?insecure=1&sni=localhost&obfs=salamander&obfs-password=local-obfs#Local_HY2")[0]
        return node, server

    async def wireguard(self):
        server_private, server_public = keypair()
        client_private, client_public = keypair()
        port = free_port()
        config = {"log": {"disabled": True}, "endpoints": [{"type": "wireguard", "tag": "wg", "system": False,
                  "listen_port": port, "address": ["10.88.0.1/32"], "private_key": server_private,
                  "peers": [{"public_key": client_public, "allowed_ips": ["10.88.0.2/32"]}]}],
                  "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
        server = await self.stack.enter_async_context(CoreProcess(binary(CORES, "sing-box"), "sing-box", config, None, 3))
        return {"private_key": client_private, "peer_key": server_public, "addresses": ["10.88.0.2/32"],
                "endpoint_host": "127.0.0.1", "endpoint_port": port, "reserved": [0, 0, 0]}, server

    async def assert_transfer(self, node, cascade=False):
        route = Route(CORES, node, 3)
        async with route.base() as proxy:
            if cascade:
                wg, _ = await self.wireguard()
                proxy = await self.stack.enter_async_context(route.cascade(wg))
            async with client(proxy, 5) as session:
                response = await session.get(self.url + "/ok")
                self.assertEqual(response.text, "WORKING_APP")
            result = await speed(proxy, self.cfg)
            self.assertFalse(result["errors"], result)
            self.assertGreater(result["download_mbps"]["median"], 0)
            self.assertGreater(result["upload_mbps"]["median"], 0)

    async def test_vless_tcp_real_transfer(self):
        node, _ = await self.vless()
        await self.assert_transfer(node)

    async def test_vless_xhttp_real_transfer(self):
        node, _ = await self.vless("xhttp")
        await self.assert_transfer(node)

    async def test_vless_reality_real_transfer(self):
        node, _ = await self.vless(reality=True)
        await self.assert_transfer(node)

    async def test_vless_xhttp_reality_real_transfer(self):
        node, _ = await self.vless("xhttp", reality=True)
        await self.assert_transfer(node)

    async def test_hysteria_salamander_real_transfer(self):
        node, _ = await self.hysteria()
        await self.assert_transfer(node)

    async def test_wireguard_over_vless_udp(self):
        node, _ = await self.vless()
        await self.assert_transfer(node, cascade=True)

    async def test_wireguard_over_xhttp_udp(self):
        node, _ = await self.vless("xhttp")
        await self.assert_transfer(node, cascade=True)

    async def test_wireguard_over_hysteria_udp(self):
        node, _ = await self.hysteria()
        await self.assert_transfer(node, cascade=True)

    async def test_no_direct_fallback_after_server_stops(self):
        node, server = await self.vless()
        async with Route(CORES, node, 3).base() as proxy:
            async with client(proxy, 2) as session:
                self.assertEqual((await session.get(self.url + "/ok")).status_code, 200)
            before = len(self.requests)
            await server.__aexit__(None, None, None)
            with patch.dict(os.environ, {"HTTP_PROXY": self.url, "HTTPS_PROXY": self.url, "NO_PROXY": "*"}):
                async with client(proxy, 1) as session:
                    with self.assertRaises(httpx.HTTPError):
                        await session.get(self.url + "/forbidden-direct")
            self.assertEqual(before, len(self.requests))

    async def test_registration_through_vpn_cache_and_no_fallback(self):
        node, server = await self.vless("xhttp")
        wg, _ = await self.wireguard()
        self.reg_body = {"id": "local-fixture", "config": {"client_id": "AAAA", "interface": {"addresses": {"v4": "10.88.0.2"}},
                         "peers": [{"public_key": wg["peer_key"], "endpoint": {"v4": "127.0.0.1:" + str(wg["endpoint_port"])}}]}}
        cache = WarpCache(Path(self.temp.name) / "cache")
        self.cfg["warp_api"] = self.url
        async with Route(CORES, node, 3).base() as proxy:
            value, origin = await cache.get(node, proxy, {"verified": True, "ip": "203.0.113.9"}, self.cfg)
            self.assertEqual(origin, "registered_through_vpn")
            request = next(r for r in self.requests if r[1] == "/reg")
            self.assertEqual(json.loads(request[2])["tunnel_type"], "wireguard")
            self.assertNotIn(value["private_key"].encode(), request[2])
            _, source = await cache.get(node, proxy, {"verified": True, "ip": "203.0.113.9"}, self.cfg)
            self.assertEqual(source, "cache")
            self.assertEqual(sum(r[1] == "/reg" for r in self.requests), 1)
            await server.__aexit__(None, None, None)
            with self.assertRaises(httpx.HTTPError):
                await WarpCache(Path(self.temp.name) / "another-cache").get(node, proxy, {"verified": True, "ip": "203.0.113.9"}, self.cfg)
            self.assertEqual(sum(r[1] == "/reg" for r in self.requests), 1)

    async def test_warp_429_stops_further_registrations(self):
        node, _ = await self.vless()
        self.reg_status = 429
        self.cfg["warp_api"] = self.url
        async with Route(CORES, node, 3).base() as proxy:
            cache = WarpCache(Path(self.temp.name) / "cache")
            for _ in range(2):
                with self.assertRaises(WarpError):
                    await cache.get(node, proxy, {"verified": True, "ip": "203.0.113.9"}, self.cfg)
            self.assertEqual(sum(r[1] == "/reg" for r in self.requests), 1)

    async def test_measurements_and_identity(self):
        node, _ = await self.vless()
        async with Route(CORES, node, 3).base() as proxy:
            with patch("proxytester.network.TRACE_URL", self.url + "/trace"), patch("proxytester.network.IP_URL", self.url + "/ip"):
                identity = await verify(proxy, 3)
                self.assertTrue(identity["verified"])
                self.assertFalse((await verify(proxy, 3, identity))["verified"])
            value = await latency(proxy, self.cfg)
            self.assertEqual(value["failure_percent"], 0)
            self.assertEqual(len(value["samples_ms"]), 2)
            value = await http_check(proxy, self.cfg["services"][0], self.cfg)
            self.assertEqual(value["status"], "available")

    async def test_runner_checkpoint_and_resume(self):
        node, _ = await self.vless()
        file = Path(self.temp.name) / "subscription.json"
        file.write_text(json.dumps(node.outbound))
        self.cfg["files"] = [str(file)]
        runner = Runner(self.cfg, CORES, Path(self.temp.name) / "data", Path(self.temp.name) / "report.html")
        with patch("proxytester.network.TRACE_URL", self.url + "/trace"), patch("proxytester.network.IP_URL", self.url + "/ip"):
            await runner.run()
            self.assertEqual(runner.report["results"][0]["status"], "ok")
            count = len(self.requests)
            await runner.run(resume=True)
            self.assertEqual(count, len(self.requests))
        self.assertTrue((Path(self.temp.name) / "report.csv").exists())

    async def test_cancel_releases_processes_and_saves(self):
        node, _ = await self.vless()
        route = Route(CORES, node, 3)
        port = None
        async def task():
            nonlocal port
            async with route.base() as proxy:
                port = int(proxy.rsplit(":", 1)[1])
                await asyncio.Event().wait()
        job = asyncio.create_task(task())
        for _ in range(100):
            if port:
                break
            if job.done():
                await job
            await asyncio.sleep(.05)
        self.assertIsNotNone(port)
        job.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await job
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", port)

    @unittest.skipUnless(os.environ.get("PROXYTESTER_BROWSER_TESTS") == "1", "Set PROXYTESTER_BROWSER_TESTS=1 with installed Chromium")
    async def test_chromium_javascript_and_readiness(self):
        node, _ = await self.vless()
        self.cfg.update(browser=True, browser_settle_ms=300)
        services = [{"name": "JSRegion", "url": self.url + "/js"}, {"name": "JSReady", "url": self.url + "/ready", "success_selector": "#ready"}]
        async with Route(CORES, node, 3).base() as proxy:
            with patch("proxytester.services.TRACE_URL", self.url + "/trace"):
                result = await browser_checks(proxy, services, self.cfg, {"ip": "203.0.113.9", "warp": "off"})
        self.assertEqual(result["JSRegion"]["status"], "regional_block", result)
        self.assertEqual(result["JSReady"]["status"], "available", result)


if __name__ == "__main__":
    unittest.main()
