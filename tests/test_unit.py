import asyncio
import base64
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from proxytester.config import DEFAULT, load
from proxytester.cores import sing_config, xray_config
from proxytester.network import client, parse_trace
from proxytester.report import write_report
from proxytester.runner import failed
from proxytester.services import browser_options, classify, cloudflare
from proxytester.subscriptions import parse
from proxytester.util import error_kind, public_url
from proxytester.warp import decode_registration, valid_identity, WarpError

UUID = "11111111-1111-4111-8111-111111111111"
URI = f"vless://{UUID}@example.com:443?security=reality&sni=example.org&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab&type=tcp&flow=xtls-rprx-vision#🇩🇪%20VPN"
HY2 = "hysteria2://secret%3Apassword@example.com:443?sni=example.org&obfs=salamander&obfs-password=test&mport=443,5000-5010#NL_test"


class SubscriptionTests(unittest.TestCase):
    def test_reality_and_country(self):
        n = parse(URI)[0]
        self.assertFalse(n.issue)
        self.assertEqual(n.country, "DE")
        self.assertEqual(n.outbound["streamSettings"]["realitySettings"]["shortId"], "ab")

    def test_base64_unpadded_and_bom(self):
        text = base64.urlsafe_b64encode((URI + "\n" + HY2).encode()).decode().rstrip("=")
        self.assertEqual([n.protocol for n in parse("\ufeff" + text)], ["vless", "hysteria2"])

    def test_hy2_password_hopping_and_obfs(self):
        n = parse(HY2)[0]
        self.assertFalse(n.issue)
        self.assertEqual(n.outbound["password"], "secret:password")
        self.assertEqual(n.outbound["server_ports"], ["443", "5000:5010"])
        self.assertEqual(n.outbound["obfs"]["type"], "salamander")

    def test_xhttp_extra(self):
        from urllib.parse import quote
        n = parse(f"vless://{UUID}@[::1]:443?security=tls&type=xhttp&mode=packet-up&extra=" + quote(json.dumps({"noGRPCHeader": True, "scMaxEachPostBytes": 100000})))[0]
        self.assertFalse(n.issue)
        self.assertEqual(n.outbound["streamSettings"]["xhttpSettings"]["extra"]["scMaxEachPostBytes"], 100000)

    def test_flow_xhttp_explicit_error(self):
        self.assertIn("incompatible", parse(URI.replace("type=tcp", "type=xhttp"))[0].issue)

    def test_unknown_parameters_visible(self):
        nodes = parse(URI + "&unused=1\n" + URI.replace("#", "&unsupported=1#"))
        self.assertEqual(len(nodes), 2)
        self.assertIn("Unsupported", nodes[1].issue)

    def test_unsupported_protocol_visible(self):
        self.assertEqual(parse("ss://abc@server:443#SS")[0].issue, "Unsupported protocol")

    def test_invalid_port_no_secret(self):
        n = parse(f"vless://{UUID}@example.com:SECRET?security=none")[0]
        self.assertTrue(n.issue)
        self.assertNotIn("SECRET", json.dumps(n.public()))

    def test_duplicate_parameter(self):
        self.assertIn("Duplicate", parse(URI.replace("#", "&sni=again#"))[0].issue)

    def test_malformed_json_visible(self):
        self.assertIn("Malformed", parse('{"outbounds":[')[0].issue)

    def test_native_xray_preserves_xhttp(self):
        native = parse(URI.replace("type=tcp&flow=xtls-rprx-vision", "type=xhttp"))[0].outbound
        native["tag"] = "XHTTP"
        nodes = parse(json.dumps([{"outbounds": [native, {"protocol": "freedom"}]}]))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].outbound["streamSettings"]["network"], "xhttp")

    def test_native_routing_rejected(self):
        native = parse(URI)[0].outbound
        native["streamSettings"]["sockopt"] = {"dialerProxy": "direct"}
        self.assertIn("Unsupported", parse(json.dumps(native))[0].issue)

    def test_benign_native_socket_options_preserved(self):
        native = parse(URI)[0].outbound
        native["streamSettings"]["sockopt"] = {"domainStrategy": "UseIPv4", "tcpKeepAliveIdle": 30}
        node = parse(json.dumps(native))[0]
        self.assertFalse(node.issue)
        self.assertEqual(node.outbound["streamSettings"]["sockopt"]["tcpKeepAliveIdle"], 30)

    def test_singbox_reality(self):
        n = parse(json.dumps({"outbounds": [{"type": "vless", "tag": "US_test", "server": "example.com", "server_port": 443,
            "uuid": UUID, "tls": {"enabled": True, "server_name": "example.org", "reality": {"enabled": True, "public_key": "AAA", "short_id": "ab"}}}]}))[0]
        self.assertFalse(n.issue)
        self.assertEqual(n.outbound["streamSettings"]["security"], "reality")

    def test_clash_yaml(self):
        text = f"proxies:\n  - name: FR_test\n    type: vless\n    server: example.com\n    port: 443\n    uuid: {UUID}\n    tls: true\n    network: ws\n    ws-opts:\n      path: /vpn\n      headers:\n        Host: www.example.com\n"
        n = parse(text)[0]
        self.assertFalse(n.issue)
        self.assertEqual(n.outbound["streamSettings"]["wsSettings"]["headers"]["Host"], "www.example.com")

    def test_invalid_entries_not_deduplicated(self):
        nodes = parse("ss://aaa@server:443#One\nss://bbb@server:443#Two")
        self.assertNotEqual(nodes[0].id, nodes[1].id)

    def test_same_node_across_sources_has_same_cache_key(self):
        self.assertEqual(parse(URI, "source-1")[0].id, parse(URI, "source-2")[0].id)

    def test_missing_hy2_password_and_zero_port(self):
        self.assertTrue(parse("hy2://example.com:443")[0].issue)
        self.assertTrue(parse(f"vless://{UUID}@example.com:0")[0].issue)

    def test_malformed_entry_does_not_stop_later_json_nodes(self):
        nodes = parse(json.dumps([URI, 42, HY2]))
        self.assertEqual(len(nodes), 3)
        self.assertEqual(nodes[-1].protocol, "hysteria2")

    def test_no_config_secret_in_public(self):
        public = json.dumps(parse(HY2)[0].public())
        self.assertNotIn("password", public)
        self.assertNotIn("example.com", public)


class RoutingTests(unittest.TestCase):
    def test_no_direct_outbound_in_any_route(self):
        node = parse(URI)[0]
        warp = {"private_key": "SECRET", "addresses": ["172.16.0.2/32"], "peer_key": "PUBLIC", "endpoint_host": "162.159.192.1", "endpoint_port": 2408, "reserved": [1, 2, 3]}
        cfg = sing_config(node, 10001, 10002, warp)
        self.assertEqual(cfg["route"]["final"], "warp")
        self.assertEqual(cfg["endpoints"][0]["detour"], "vpn")
        self.assertFalse(cfg["endpoints"][0]["system"])
        self.assertEqual(cfg["dns"]["servers"][0]["detour"], "warp")
        self.assertEqual([o["type"] for o in cfg["outbounds"]], ["socks"])
        self.assertEqual(xray_config(node, 10002)["routing"]["domainStrategy"], "AsIs")

    def test_trace_validation(self):
        self.assertEqual(parse_trace("ip=203.0.113.1\nwarp=on\nloc=DE")["warp"], "on")
        for text in ("ip=not-an-ip\nwarp=on", "ip=127.0.0.1\nwarp=unknown", "<html>error</html>"):
            with self.assertRaises(ValueError):
                parse_trace(text)

    def test_explicit_loopback_proxy_only(self):
        for value in ("", "http://example.com:1", "socks5://127.0.0.1:1"):
            with self.assertRaises(ValueError):
                client(value, 1)

    def test_route_auth_is_present_on_both_local_hops(self):
        n = parse(URI)[0]
        c = sing_config(n, 10001, 10002, auth=("front", "secret"), backhaul_auth=("back", "other"))
        self.assertEqual(c["inbounds"][0]["users"][0]["username"], "front")
        self.assertEqual(c["outbounds"][0]["username"], "back")
        self.assertEqual(xray_config(n, 10002, ("back", "other"))["inbounds"][0]["settings"]["auth"], "password")
        options = browser_options("http://front:secret@127.0.0.1:10001")
        self.assertEqual(options["proxy"]["server"], "http://127.0.0.1:10001")
        self.assertEqual(options["proxy"]["password"], "secret")


class ClassificationTests(unittest.TestCase):
    def test_notebook_redirect_anywhere_in_history(self):
        value = classify(200, ["https://notebooklm.google/?location=unsupported", "https://accounts.google.com/"], "Sign in")
        self.assertEqual(value["status"], "regional_block")

    def test_login_never_available(self):
        self.assertEqual(classify(200, ["https://accounts.google.com/ServiceLogin"], "Sign in", success=True)["status"], "unconfirmed")

    def test_http_200_not_proof(self):
        self.assertEqual(classify(200, ["https://notebooklm.google.com"], "Welcome")["status"], "unconfirmed")

    def test_application_readiness(self):
        self.assertEqual(classify(200, ["https://notebooklm.google.com"], "New notebook", success=True)["status"], "available")

    def test_cf_challenge_header(self):
        self.assertEqual(cloudflare(403, {"CF-Mitigated": "challenge"}, ""), "challenge")

    def test_cf_block(self):
        self.assertEqual(cloudflare(403, {"server": "cloudflare"}, "Sorry, you have been blocked"), "block")

    def test_turnstile_is_not_automatically_challenge(self):
        self.assertEqual(cloudflare(200, {}, '<div class="cf-turnstile"></div>'), "not_observed")
        self.assertEqual(cloudflare(403, {}, '<div class="cf-turnstile">Verify you are human</div>'), "captcha")

    def test_no_cf_no_generalization(self):
        self.assertEqual(cloudflare(200, {}, "ok"), "not_observed")
        self.assertEqual(cloudflare(200, {"cf-ray": "x"}, "ok"), "clear_observed")

    def test_translations_in_javascript_not_a_region_block(self):
        self.assertEqual(classify(200, ["https://example.com"], '<script>"not available in your country"</script>Welcome')["status"], "unconfirmed")


class WarpTests(unittest.TestCase):
    def fixture(self):
        return {"id": "device", "token": "NOT_FOR_REPORT", "config": {"client_id": "AQID", "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110::2"}}, "peers": [{"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "endpoint": {"v4": "162.159.192.1:2408"}}]}}

    def test_decode(self):
        v = decode_registration(self.fixture(), "private")
        self.assertEqual(v["reserved"], [1, 2, 3])
        self.assertEqual(v["endpoint_port"], 2408)
        self.assertEqual(v["addresses"][0], "172.16.0.2/32")
        self.assertNotIn("token", v)

    def test_bad_reserved(self):
        v = self.fixture()
        v["config"]["client_id"] = "AQI="
        with self.assertRaises(WarpError):
            decode_registration(v, "private")

    def test_cache_corruption_detected_before_core_launch(self):
        value = decode_registration(self.fixture(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        self.assertTrue(valid_identity(value))
        value["reserved"] = [999, 0, 0]
        with self.assertRaises(ValueError):
            valid_identity(value)


class OutputTests(unittest.TestCase):
    def test_chromium_error_code_is_preserved_without_secret_url(self):
        exc = RuntimeError("Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://example.com/?token=SECRET")
        self.assertEqual(error_kind(exc), "ERR_TUNNEL_CONNECTION_FAILED")

    def test_invalid_selector_is_not_reported_as_network_failure(self):
        exc = RuntimeError('Locator.count: Unexpected token while parsing css selector "button["')
        self.assertEqual(error_kind(exc), "invalid_selector")

    def test_html_script_injection_and_csv_formula(self):
        r = {"services": ["NotebookLM"], "results": [{"name": '=HYPERLINK("evil")</script><script>alert(1)</script>', "id": "one", "country": "DE", "protocol": "vless", "status": "invalid"}]}
        with tempfile.TemporaryDirectory() as d:
            path = write_report(Path(d) / "report.html", r)
            text = path.read_text(encoding="utf-8")
            self.assertNotIn('</script><script>alert(1)', text)
            self.assertIn("\\u003c/script", text)
            self.assertIn("'=HYPERLINK", path.with_suffix(".csv").read_text(encoding="utf-8-sig"))
            self.assertEqual(json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))["results"][0]["id"], "one")

    def test_url_query_removed(self):
        self.assertEqual(public_url("https://user:password@example.com/app?token=secret#s"), "https://example.com/app")

    def test_config_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.json"
            p.write_text('{"parallel": 99}')
            with self.assertRaises(ValueError):
                load(p)

    def test_retry_failed_covers_warp(self):
        self.assertTrue(failed({"status": "ok", "warp": {"error": "rate limited"}}))
        self.assertFalse(failed({"status": "ok", "vpn": {"identity": {"verified": True}}}))


if __name__ == "__main__":
    unittest.main()
