import re
from urllib.parse import parse_qs, urlsplit

import httpx

from .network import TRACE_URL, bounded_get, client, parse_trace
from .util import error_kind, public_url

REGION = ("not available in your country", "not available in your region", "unsupported country",
          "unsupported region", "isn't available in your country", "is not supported in your country",
          "isn't currently available in your country", "недоступен в вашей стране", "недоступно в вашей стране",
          "недоступен в вашем регионе", "недоступно в вашем регионе")


def cloudflare(status, headers, body):
    h = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    text = body.lower()
    cf = "cf-ray" in h or "cloudflare" in h.get("server", "") or "cdn-cgi/challenge-platform" in text
    # An embedded Turnstile widget alone is not a challenge: many successful pages include one.
    if ("cf-turnstile" in text or "challenges.cloudflare.com/turnstile" in text) and (status in (403, 429, 503) or any(x in text for x in ("verify you are human", "verification required", "complete the security check"))):
        return "captcha"
    if h.get("cf-mitigated") == "challenge" or (cf and ("cf-chl-" in text or "just a moment..." in text or "checking your browser" in text)):
        return "challenge"
    if cf and ("sorry, you have been blocked" in text or "error code: 1020" in text or "error 1020" in text or (status == 403 and "access denied" in text)):
        return "block"
    if "g-recaptcha" in text and (status >= 400 or "unusual traffic" in text):
        return "other_captcha"
    if status >= 400:
        return "http_error"
    return "clear_observed" if cf else "not_observed"


def classify(status, urls, body, headers=None, success=False, protection_body=None):
    cf = cloudflare(status, headers or {}, protection_body if protection_body is not None else body)
    lower = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", body, flags=re.I | re.S)).lower()
    region_url = any(parse_qs(urlsplit(url).query).get("location") == ["unsupported"] for url in urls)
    if region_url or any(marker in lower for marker in REGION):
        state, reason = "regional_block", "Regional restriction / location=unsupported"
    elif cf in ("challenge", "captcha", "block", "other_captcha"):
        state, reason = "blocked", "Protection observed: " + cf
    elif status in (401, 407):
        state, reason = "unconfirmed", "Authentication required"
    elif status >= 400:
        state, reason = "http_error", f"HTTP {status}"
    elif any(urlsplit(url).hostname in ("accounts.google.com", "login.microsoftonline.com") for url in urls[-1:]):
        state, reason = "unconfirmed", "Sign-in page is not proof of availability"
    elif success:
        state, reason = "available", "Configured application readiness check passed"
    else:
        state, reason = "unconfirmed", "No application readiness evidence; login or a custom check may be needed"
    return {"status": state, "reason": reason, "http_status": status, "cloudflare": cf,
            "final_url": public_url(urls[-1]) if urls else "", "redirects": [public_url(url) for url in urls[:-1]]}


async def http_check(proxy, service, config):
    try:
        async with client(proxy, config["timeout"]) as session:
            response, text = await bounded_get(session, service["url"])
            urls = [str(r.url) for r in response.history] + [str(response.url)]
            # Arbitrary services need an explicit readiness assertion; HTTP 200 is never enough.
            success = bool(service.get("success_regex") and re.search(service["success_regex"], text, re.I))
            value = classify(response.status_code, urls, text, response.headers, success)
            value["method"] = "http"
            return value
    except (httpx.HTTPError, ValueError, re.error) as e:
        return {"status": "network_error", "reason": error_kind(e), "cloudflare": "unknown", "method": "http"}


def browser_options(proxy, headless=True):
    return {"headless": headless, "proxy": {"server": proxy, "bypass": "<-loopback>"},
            "args": ["--disable-quic", "--disable-background-networking", "--disable-component-update",
                     "--disable-sync", "--no-first-run", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                     "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost"]}


async def browser_checks(proxy, services, config, identity):
    from playwright.async_api import async_playwright, Error
    results = {}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**browser_options(proxy))
            try:
                state = config.get("storage_state")
                context = await browser.new_context(storage_state=state, service_workers="block", locale="en-US")
                page = await context.new_page()
                page.set_default_timeout(config["timeout"] * 1000)
                # Same browser instance/proxy as the service checks, before reading an authenticated session.
                response = await page.goto(TRACE_URL, wait_until="domcontentloaded")
                trace = parse_trace(await page.locator("body").inner_text())
                if not response or response.status != 200 or trace["ip"] != identity["ip"] or trace["warp"] != identity["warp"]:
                    raise ValueError("Browser exit identity mismatch")
                for service in services:
                    redirects, blocked_responses = [], []

                    def on_response(resp):
                        if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                            redirects.append(resp.url)
                            if "location=unsupported" in resp.url:
                                blocked_responses.append(resp.url)

                    page.on("response", on_response)
                    try:
                        response = await page.goto(service["url"], wait_until="domcontentloaded", timeout=config["timeout"] * 1000)
                        await page.wait_for_timeout(config["browser_settle_ms"])
                        body = (await page.locator("body").inner_text())[:2000000]
                        html = (await page.content())[:2000000]
                        success = False
                        if service.get("success_selector"):
                            matches = page.locator(service["success_selector"])
                            for i in range(min(await matches.count(), 20)):
                                if await matches.nth(i).is_visible():
                                    success = True
                                    break
                        if service.get("success_regex"):
                            success = success or bool(re.search(service["success_regex"], body, re.I))
                        urls = blocked_responses + redirects + [page.url]
                        value = classify(response.status if response else 0, urls, body,
                                         await response.all_headers() if response else {}, success, html)
                        value["method"] = "chromium"
                        value["browser_identity_verified"] = True
                        results[service["name"]] = value
                    except (Error, ValueError, re.error) as e:
                        results[service["name"]] = {"status": "network_error", "reason": error_kind(e),
                                                    "cloudflare": "unknown", "method": "chromium"}
                    finally:
                        page.remove_listener("response", on_response)
                await context.close()
            finally:
                await browser.close()
    except (Error, OSError, ValueError) as e:
        for service in services:
            results.setdefault(service["name"], {"status": "unconfirmed", "reason": "Browser unavailable or identity unverified: " + error_kind(e),
                                                 "cloudflare": "unknown", "method": "chromium"})
    return results


async def check_all(proxy, config, identity):
    results = {}
    for service in config["services"]:
        results[service["name"]] = await http_check(proxy, service, config)
    if config["browser"]:
        # Always execute JavaScript: HTTP and browser responses can differ even for apparent blocks.
        browser = await browser_checks(proxy, config["services"], config, identity)
        for name, value in browser.items():
            value["http_evidence"] = results[name]
            results[name] = value
    cf = []
    for index, url in enumerate(config["cloudflare_urls"], 1):
        value = await http_check(proxy, {"name": str(index), "url": url}, config)
        cf.append({"resource": public_url(url), **value})
    return {"services": results, "cloudflare_checks": cf}
