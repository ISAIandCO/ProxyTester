"""Real loopback transports, not mocked VPN measurements. No paid subscription needed.

The local registration API and trace IPs are fixtures; they are NOT Cloudflare WARP.
The cascade tests really encrypt WireGuard datagrams and relay them through VLESS/HY2.
"""
import asyncio
import base64
import json
import hashlib
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
from proxytester.subscriptions import collect, parse
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
        self.logfile = None
        if os.environ.get("PROXYTESTER_TEST_LOGS") == "1":
            # Only synthetic local credentials are used by this suite. Production logs stay off.
            self.logfile = open(Path(self.temp.name) / "cores.log", "w+", encoding="utf-8")
            original_exec = asyncio.create_subprocess_exec
            async def logged_exec(*args, **kwargs):
                if Path(str(args[0])).stem in ("xray", "sing-box") and "-c" in args:
                    path = Path(args[args.index("-c") + 1])
                    cfg = json.loads(path.read_text(encoding="utf-8"))
                    cfg["log"] = {"loglevel": "debug"} if Path(str(args[0])).stem == "xray" else {"level": "debug"}
                    path.write_text(json.dumps(cfg), encoding="utf-8")
                    kwargs.update(stdout=self.logfile, stderr=asyncio.subprocess.STDOUT)
                return await original_exec(*args, **kwargs)
            patcher = patch("asyncio.create_subprocess_exec", logged_exec)
            patcher.start()
            self.stack.callback(patcher.stop)
        self.requests = []
        self.received_headers = []
        self.subscription_status = 200
        self.subscription = f"vless://{UUID}@example.com:443?security=none#Test".encode()
        self.reg_status = 200
        self.reg_body = {}
        self.registration_hook = None
        self.origin = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.origin.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.cfg = deepcopy(DEFAULT)
        self.cfg.update(timeout=3, retries=0, latency_samples=2, latency_url=self.url + "/ok", download_url=self.url + "/data?bytes={bytes}",
                        download_bytes=40000, upload_bytes=10000, upload_url=self.url + "/up", browser=False, warp=False,
                        services=[{"name": "Fixture", "url": self.url + "/ok", "success_regex": "WORKING_APP"}], cloudflare_urls=[])

    async def asyncTearDown(self):
        await self.stack.__aexit__(None, None, None)
        if self.logfile:
            self.logfile.flush()
            self.logfile.seek(0)
            result = self._outcome.result
            if any(test is self for test, _ in result.errors + result.failures):
                print("\nLOCAL FIXTURE CORE LOGS:\n" + self.logfile.read()[-14000:])
            self.logfile.close()
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
            self.received_headers.append({k.lower(): v for k, v in headers.items()})
            status, content_type = 200, "text/html"
            if path.startswith("/data"):
                from urllib.parse import parse_qs, urlsplit
                payload = b"x" * int(parse_qs(urlsplit(path).query)["bytes"][0])
            elif path.startswith("/reg"):
                if self.registration_hook:
                    self.reg_body = await self.registration_hook(json.loads(body))
                status, payload, content_type = self.reg_status, json.dumps(self.reg_body).encode(), "application/json"
            elif path.startswith("/subscription"):
                status, payload = self.subscription_status, self.subscription
            elif path == "/trace":
                content_type = "text/plain"
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

    async def vless(self, transport="tcp", reality=False, redirect=None):
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
                  "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]}
        if redirect:
            config["outbounds"][0]["settings"]["redirect"] = redirect
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

    async def wireguard(self, enrolled_public=None):
        server_private, server_public = keypair()
        client_private, client_public = keypair()
        client_public = enrolled_public or client_public
        port = free_port()
        config = {"log": {"disabled": True}, "endpoints": [{"type": "wireguard", "tag": "wg", "system": False,
                  "listen_port": port, "address": ["10.88.0.1/32"], "private_key": server_private,
                  "peers": [{"public_key": client_public, "allowed_ips": ["10.88.0.2/32"]}]}],
                  "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct",
                    "rules": [{"inbound": ["wg"], "action": "route", "outbound": "direct", "override_address": "127.0.0.1"}]}}
        server = await self.stack.enter_async_context(CoreProcess(binary(CORES, "sing-box"), "sing-box", config, None, 3))
        return {"private_key": client_private, "peer_key": server_public, "addresses": ["10.88.0.2/32"],
                "endpoint_host": "127.0.0.1", "endpoint_port": port, "reserved": [0, 0, 0]}, server

    async def assert_transfer(self, node, cascade=False):
        route = Route(CORES, node, 3)
        target_url = self.url
        cfg = deepcopy(self.cfg)
        async with route.base() as proxy:
            if cascade:
                wg, _ = await self.wireguard()
                proxy = await self.stack.enter_async_context(route.cascade(wg))
                # Loopback destinations stay inside gVisor's own stack. Use a routed test IP;
                # the fixture WireGuard server alone rewrites it to our HTTP origin.
                target_url = self.url.replace("127.0.0.1", "198.18.0.99")
                cfg["download_url"] = cfg["download_url"].replace("127.0.0.1", "198.18.0.99")
                cfg["upload_url"] = cfg["upload_url"].replace("127.0.0.1", "198.18.0.99")
            async with client(proxy, 5) as session:
                response = await session.get(target_url + "/ok")
                self.assertEqual(response.text, "WORKING_APP")
            result = await speed(proxy, cfg)
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

    async def test_generated_warp_identity_drives_real_wireguard_cascade(self):
        node, _ = await self.vless("xhttp")
        async def enroll(payload):
            wg, _ = await self.wireguard(payload["key"])
            return {"id": "enrolled-fixture", "config": {"client_id": "AAAA", "interface": {"addresses": {"v4": "10.88.0.2"}},
                    "peers": [{"public_key": wg["peer_key"], "endpoint": {"v4": "127.0.0.1:" + str(wg["endpoint_port"])}}]}}
        self.registration_hook = enroll
        self.cfg["warp_api"] = self.url
        route = Route(CORES, node, 3)
        async with route.base() as proxy:
            cache = WarpCache(Path(self.temp.name) / "cache")
            identity, _ = await cache.get(node, proxy, {"verified": True, "ip": "203.0.113.9"}, self.cfg)
            async with route.cascade(identity) as cascade:
                async with client(cascade, 5) as session:
                    url = self.url.replace("127.0.0.1", "198.18.0.99") + "/ok"
                    self.assertEqual((await session.get(url)).text, "WORKING_APP")

    async def test_subscription_hwid_header_query_bearer_and_http_error(self):
        for mode in ("header", "query", "bearer"):
            self.cfg["subscriptions"] = [{"url": self.url + "/subscription", "hwid": "FIXTURE-HWID", "hwid_mode": mode, "hwid_name": "x-hwid"}]
            nodes = await collect(self.cfg)
            self.assertEqual(nodes[0].protocol, "vless")
            if mode == "header":
                self.assertEqual(self.received_headers[-1]["x-hwid"], "FIXTURE-HWID")
            elif mode == "query":
                self.assertIn("x-hwid=FIXTURE-HWID", self.requests[-1][1])
            else:
                self.assertEqual(self.received_headers[-1]["authorization"], "Bearer FIXTURE-HWID")
            self.assertNotIn("FIXTURE-HWID", json.dumps(nodes[0].public()))
        self.subscription_status = 403
        nodes = await collect(self.cfg)
        self.assertIn("HTTP 403", nodes[0].issue)

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

    async def test_parallel_routes_are_isolated(self):
        first, first_server = await self.vless()
        second, _ = await self.vless("xhttp")
        async with Route(CORES, first, 3).base() as a, Route(CORES, second, 3).base() as b:
            self.assertNotEqual(a, b)
            await first_server.__aexit__(None, None, None)
            async with client(a, 1) as session:
                with self.assertRaises(httpx.HTTPError):
                    await session.get(self.url + "/ok")
            async with client(b, 3) as session:
                self.assertEqual((await session.get(self.url + "/ok")).text, "WORKING_APP")

    async def test_cascade_has_no_direct_fallback(self):
        node, server = await self.vless()
        wg, _ = await self.wireguard()
        route = Route(CORES, node, 3)
        url = self.url.replace("127.0.0.1", "198.18.0.99")
        async with route.base(), route.cascade(wg) as proxy:
            async with client(proxy, 3) as session:
                self.assertEqual((await session.get(url + "/ok")).text, "WORKING_APP")
            count = len(self.requests)
            await server.__aexit__(None, None, None)
            async with client(proxy, 1) as session:
                with self.assertRaises(httpx.HTTPError):
                    await session.get(url + "/must-not-go-direct")
            self.assertEqual(count, len(self.requests))

    async def test_runner_interruption_saves_partial_report(self):
        node, _ = await self.vless()
        file = Path(self.temp.name) / "subscription.json"
        file.write_text(json.dumps(node.outbound), encoding="utf-8")
        self.cfg["files"] = [str(file)]
        runner = Runner(self.cfg, CORES, Path(self.temp.name) / "data", Path(self.temp.name) / "report.html")
        job = asyncio.create_task(runner.run())
        for _ in range(100):
            if runner.report and runner.report["results"][0]["status"] == "running":
                break
            await asyncio.sleep(.02)
        job.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await job
        saved = json.loads((Path(self.temp.name) / "data" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["results"][0]["status"], "cancelled")
        self.assertFalse(saved["completed"])
        self.assertTrue((Path(self.temp.name) / "report.html").exists())

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
        services = [{"name": "JSRegion", "url": self.url + "/js"}, {"name": "JSReady", "url": self.url + "/ready", "success_selector": "#ready"},
                    {"name": "InvalidCSS", "url": self.url + "/ready", "success_selector": "button["}]
        async with Route(CORES, node, 3).base() as proxy:
            with patch("proxytester.services.TRACE_URL", self.url + "/trace"):
                with patch("proxytester.services.error_kind", lambda e: str(e)):
                    result = await browser_checks(proxy, services, self.cfg, {"ip": "203.0.113.9", "warp": "off"})
        self.assertEqual(result["JSRegion"]["status"], "regional_block", result)
        self.assertEqual(result["JSReady"]["status"], "available", result)
        self.assertEqual(result["InvalidCSS"]["status"], "check_error", result)
        self.assertEqual(result["InvalidCSS"]["stage"], "readiness", result)

    @unittest.skipUnless(os.environ.get("PROXYTESTER_BROWSER_TESTS") == "1", "Requires Chromium")
    async def test_chromium_https_domain_through_authenticated_proxy(self):
        from proxytester.services import browser_options, verify_browser_route
        from playwright.async_api import async_playwright
        certfile, keyfile = certificate(self.temp.name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        origin = await asyncio.start_server(self.handle, "127.0.0.1", 0, ssl=context)
        self.stack.callback(origin.close)
        port = origin.sockets[0].getsockname()[1]
        cert = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
        node, _ = await self.vless(redirect=f"127.0.0.1:{port}")
        url = f"https://service.proxytester.invalid:{port}"
        async with Route(CORES, node, 5).base() as proxy:
            for headless in (True, False):
                options = browser_options(proxy, headless=headless)
                # Trust only this ephemeral test certificate; production TLS validation stays on.
                options["args"].append("--ignore-certificate-errors-spki-list=" + pin)
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(**options)
                    try:
                        page = await browser.new_page()
                        with patch("proxytester.services.TRACE_URL", url + "/trace"):
                            await verify_browser_route(page, {"ip": "203.0.113.9", "warp": "off"}, 10)
                        response = await page.goto(url + "/ready", wait_until="domcontentloaded", timeout=10000)
                        self.assertEqual(response.status, 200)
                        await page.wait_for_selector("#ready")
                        self.assertGreater(await page.locator(DEFAULT["services"][0]["success_selector"]).count(), 0)
                        self.assertEqual(await page.locator(DEFAULT["services"][1]["success_selector"]).count(), 0)
                    finally:
                        await browser.close()
        self.assertTrue(any(r[1] == "/ready" for r in self.requests))

    @unittest.skipUnless(os.environ.get("PROXYTESTER_LIVE_SMOKE") == "1", "Optional public HTTPS diagnostics")
    async def test_public_google_browser_diagnostics(self):
        from proxytester.services import browser_options
        from proxytester.network import bounded_get
        from playwright.async_api import async_playwright, Error
        from urllib.parse import urlsplit
        node, _ = await self.vless()
        self.cfg.update(timeout=20, browser_settle_ms=1000)
        async with Route(CORES, node, 5).base() as proxy:
            identity = await verify(proxy, 20)
            print("PUBLIC HTTPS identity:", identity)
            if identity["verified"]:
                async with client(proxy, 12) as session:
                    for url in ("https://notebooklm.google.com/", "https://gemini.google.com/app"):
                        try:
                            response, text = await bounded_get(session, url)
                            print("PUBLIC HTTP probe:", response.status_code, str(response.url).split("?")[0], len(text))
                        except Exception as exc:
                            print("PUBLIC HTTP probe error:", type(exc).__name__)
                services = [{"name": "NotebookLM", "url": "https://notebooklm.google.com/"}, {"name": "Gemini", "url": "https://gemini.google.com/app"}]
                with patch("proxytester.services.error_kind", lambda e: str(e)):
                    result = await browser_checks(proxy, services, self.cfg, identity)
                print("PUBLIC HTTPS browser:", json.dumps(result, ensure_ascii=False))
                for mode in ("original", "no_resolver_rule", "default_args"):
                    options = browser_options(proxy)
                    if mode == "no_resolver_rule":
                        options["args"] = [arg for arg in options["args"] if not arg.startswith("--host-resolver-rules=")]
                    elif mode == "default_args":
                        options["args"] = []
                    async with async_playwright() as pw:
                        browser = await pw.chromium.launch(**options)
                        try:
                            page = await browser.new_page()
                            failures, responses = [], []
                            page.on("requestfailed", lambda req: failures.append([urlsplit(req.url).hostname, req.failure]))
                            page.on("response", lambda resp: responses.append([urlsplit(resp.url).hostname, resp.status]))
                            try:
                                await page.goto("https://notebooklm.google.com/", timeout=12000, wait_until="domcontentloaded")
                                error = "none"
                            except Error as exc:
                                error = str(exc).split("Call log:")[0]
                            try:
                                state = await asyncio.wait_for(page.evaluate("document.readyState"), 3)
                            except (asyncio.TimeoutError, Error):
                                state = "execution_context_unavailable"
                            print("PUBLIC CHROME mode:", mode, "error:", error, "url:", page.url.split("?")[0], "state:", state, "failures:", failures[-10:], "responses:", responses[-10:], flush=True)
                        finally:
                            await browser.close()
                if self.logfile:
                    self.logfile.flush()
                    self.logfile.seek(0)
                    lines = self.logfile.read().splitlines()
                    print("PUBLIC CORE:", "\n".join(line for line in lines if any(s in line.lower() for s in ("google", "failed", "error", "blackhol")))[-15000:])


if __name__ == "__main__":
    unittest.main()
