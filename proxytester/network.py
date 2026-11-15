import asyncio
import ipaddress
import os
import statistics
import time
from urllib.parse import urlsplit

import httpx

from .util import error_kind, public_url

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
IP_URL = "https://api4.ipify.org/"


def client(proxy, timeout):
    p = urlsplit(proxy)
    if p.scheme != "http" or p.hostname != "127.0.0.1" or not p.port:
        raise ValueError("A loopback test proxy is mandatory")
    # Explicit proxy, no environment, no retries that could change the route.
    return httpx.AsyncClient(proxy=proxy, trust_env=False, timeout=timeout, follow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 ProxyTester/1.0", "Accept-Encoding": "identity"})


async def bounded_get(session, url, limit=2000000, **kwargs):
    async with session.stream("GET", url, **kwargs) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk[:max(0, limit - len(body))])
            if len(body) >= limit:
                break
        return response, body.decode("utf-8", errors="replace")


def parse_trace(text):
    data = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    ip = str(ipaddress.ip_address(data.get("ip", "")))
    if data.get("warp") not in ("off", "on", "plus"):
        raise ValueError("Invalid Cloudflare trace")
    return {"ip": ip, "warp": data["warp"], "location": data.get("loc", "?"), "colo": data.get("colo", "?")}


async def verify(proxy, timeout, base=None, retries=0):
    attempts = []
    for attempt in range(retries + 1):
        try:
            async with client(proxy, timeout) as session:
                response, text = await bounded_get(session, TRACE_URL, 10000)
                response.raise_for_status()
                identity = parse_trace(text)
                # Independent HTTPS endpoint, same route, same IPv4 family.
                response, text = await bounded_get(session, IP_URL, 1000)
                response.raise_for_status()
                second = str(ipaddress.ip_address(text.strip()))
                identity["second_ip"] = second
                identity["consistent_ipv4"] = identity["ip"] == second
                if base is not None:
                    if identity["warp"] not in ("on", "plus"):
                        raise ValueError("Cascade trace did not confirm WARP")
                    if identity["ip"] == base["ip"] or identity["second_ip"] == base.get("second_ip"):
                        raise ValueError("Cascade exit IP did not change")
                identity.update(verified=True, attempts=attempts)
                return identity
        except (httpx.HTTPError, ValueError) as e:
            reason = str(e) if isinstance(e, ValueError) and str(e).startswith("Cascade") else error_kind(e)
            attempts.append(reason)
            if attempt < retries:
                await asyncio.sleep(.3)
    return {"verified": False, "error": attempts[-1], "attempts": attempts}


def distribution(samples):
    if not samples:
        return {"median": None, "min": None, "max": None, "stdev": None}
    return {"median": round(statistics.median(samples), 2), "min": round(min(samples), 2),
            "max": round(max(samples), 2), "stdev": round(statistics.pstdev(samples), 2)}


async def latency(proxy, config):
    rtts, connects, errors = [], [], []
    for _ in range(config["latency_samples"]):
        begin = time.perf_counter()
        tls_connected = None

        async def trace(event, info):
            nonlocal tls_connected
            if event.endswith("start_tls.complete"):
                tls_connected = (time.perf_counter() - begin) * 1000

        try:
            async with client(proxy, config["timeout"]) as session:
                async with session.stream("GET", config["latency_url"], extensions={"trace": trace}) as response:
                    response.raise_for_status()
                    rtts.append((time.perf_counter() - begin) * 1000)
                    if tls_connected is not None:
                        connects.append(tls_connected)
        except httpx.HTTPError as e:
            errors.append(error_kind(e))
    return {"rtt_ms": distribution(rtts), "connect_tls_ms": distribution(connects), "samples_ms": rtts,
            "failure_percent": round(len(errors) * 100 / config["latency_samples"], 1), "errors": errors,
            "method": "Fresh HTTPS connections through proxy; RTT is time to response headers, not ICMP"}


async def speed(proxy, config):
    down, up, errors, measurements = [], [], [], []
    for _ in range(config["speed_repeats"]):
        try:
            async with client(proxy, config["timeout"]) as session:
                size = config["download_bytes"]
                start, received = time.perf_counter(), 0
                async with session.stream("GET", config["download_url"].replace("{bytes}", str(size)),
                                          headers={"Cache-Control": "no-cache"}) as response:
                    response.raise_for_status()
                    async for chunk in response.aiter_raw():
                        received += len(chunk)
                        if received >= size:
                            break
                seconds = time.perf_counter() - start
                if received < size:
                    raise ValueError("Download returned less than requested bytes")
                down.append(received * 8 / seconds / 1000000)
                measurements.append({"direction": "download", "bytes": received, "seconds": round(seconds, 3)})
        except (httpx.HTTPError, ValueError) as e:
            errors.append("download: " + (str(e) if isinstance(e, ValueError) else error_kind(e)))
        if config["upload_bytes"]:
            try:
                payload = os.urandom(config["upload_bytes"])
                async with client(proxy, config["timeout"]) as session:
                    start = time.perf_counter()
                    async with session.stream("POST", config["upload_url"], content=payload,
                                              headers={"Content-Type": "application/octet-stream"}) as response:
                        response.raise_for_status()
                    seconds = time.perf_counter() - start
                up.append(len(payload) * 8 / seconds / 1000000)
                measurements.append({"direction": "upload", "bytes": len(payload), "seconds": round(seconds, 3)})
            except httpx.HTTPError as e:
                errors.append("upload: " + error_kind(e))
    return {"download_mbps": distribution(down), "upload_mbps": distribution(up), "measurements": measurements,
            "errors": errors, "method": "Single stream, includes connection/TLS overhead; parallel tests share bandwidth"}
