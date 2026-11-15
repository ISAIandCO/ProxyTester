import json
import os
import tempfile
import unittest
from pathlib import Path

from proxytester.report import write_report


@unittest.skipUnless(os.environ.get("PROXYTESTER_BROWSER_TESTS") == "1", "Requires installed Chromium")
class ReportBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_filters_sort_details_and_exports(self):
        from playwright.async_api import async_playwright
        report = {"version": "test fixture", "created": "2026-11-15T12:00:00Z", "updated": "2026-11-15T12:00:01Z",
                  "completed": True, "services": ["NotebookLM"], "parameters": {}, "resources": {}, "cores": {},
                  "results": []}
        for index, country in enumerate(("DE", "NL", "FR")):
            report["results"].append({"id": str(index), "name": country + " VPN", "country": country, "protocol": "vless", "status": "ok",
                "vpn": {"identity": {"verified": True}, "latency": {"rtt_ms": {"median": 50 - 10 * index}},
                        "services": {"NotebookLM": {"status": "available" if index == 0 else "regional_block", "cloudflare": "not_observed"}}},
                "warp": {"identity": {"verified": True}, "services": {"NotebookLM": {"status": "available", "cloudflare": "clear_observed"}}}})
        with tempfile.TemporaryDirectory() as d:
            path = write_report(Path(d) / "report.html", report)
            async with async_playwright() as pw:
                browser = await pw.chromium.launch()
                try:
                    page = await browser.new_page(viewport={"width": 1400, "height": 1000})
                    errors = []
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    await page.goto(path.as_uri())
                    self.assertEqual(await page.locator("#rows > tr").count(), 3)
                    await page.select_option("#availability", "warp-only")
                    self.assertEqual(await page.locator("#rows > tr").count(), 2)
                    await page.select_option("#country", "NL")
                    self.assertEqual(await page.locator("#rows > tr").count(), 1)
                    async with page.expect_download() as pending:
                        await page.click("#json")
                    download = await pending.value
                    exported = json.loads(Path(await download.path()).read_text(encoding="utf-8"))
                    self.assertEqual(len(exported["results"]), 1)
                    await page.click("#reset")
                    await page.locator("#columns button").filter(has_text="VPN RTT").click()
                    self.assertEqual(await page.locator("#rows button").first.inner_text(), "FR VPN")
                    await page.locator("#rows button").first.click()
                    self.assertEqual(await page.locator(".details").count(), 1)
                    await page.set_viewport_size({"width": 390, "height": 844})
                    self.assertTrue(await page.locator("#search").is_visible())
                    self.assertFalse(errors, errors)
                finally:
                    await browser.close()
