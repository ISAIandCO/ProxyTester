import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import __version__
from .cores import LOCK, CoreError, Route
from .network import latency, speed, verify
from .report import write_report
from .services import check_all
from .subscriptions import collect
from .util import atomic_json, error_kind, identifier, public_url, safe_name
from .warp import WarpCache, WarpError


def now():
    return datetime.now(timezone.utc).isoformat()


def failed(row):
    if row.get("status") != "ok":
        return True
    for route in ("vpn", "warp"):
        data = row.get(route, {})
        if data.get("error") or data.get("identity", {}).get("verified") is False:
            return True
        if any(v.get("status") in ("network_error", "http_error") for v in data.get("services", {}).values()):
            return True
    return False


class Runner:
    def __init__(self, config, cores, data, output, on_update=None):
        self.config, self.cores, self.data, self.output = config, cores, Path(data), output
        self.cache = WarpCache(self.data / "warp")
        self.report = {}
        self.tasks = []
        self.save_lock = asyncio.Lock()
        self.completed = 0
        self.on_update = on_update

    async def measurements(self, proxy, result, base=None):
        cfg = self.config
        result["identity"] = await verify(proxy, cfg["timeout"], base, cfg["retries"])
        await self.save()
        if not result["identity"]["verified"]:
            return False
        result["latency"] = await latency(proxy, cfg)
        result.update(await check_all(proxy, cfg, result["identity"]))
        await self.save()
        if cfg["speed"]:
            result["speed"] = await speed(proxy, cfg)
        return True

    async def test(self, node, result):
        if node.issue:
            result.update(status="invalid", error=node.issue)
            return
        result.update(status="running", started=now(), vpn={}, warp={})
        await self.save()
        route = Route(self.cores, node, self.config["timeout"])
        try:
            async with route.base() as proxy:
                if not await self.measurements(proxy, result["vpn"]):
                    result.update(status="failed", error="VPN identity could not be verified")
                    return
                result["status"] = "ok"
                if self.config["warp"]:
                    try:
                        warp, origin = await self.cache.get(node, proxy, result["vpn"]["identity"], self.config)
                        result["warp"]["configuration_source"] = origin
                        result["warp"]["registration_exit_ip"] = warp.get("registration_exit_ip")
                        async with route.cascade(warp) as cascade:
                            if not await self.measurements(cascade, result["warp"], result["vpn"]["identity"]):
                                result["warp"]["error"] = "VPN → WARP identity could not be verified"
                    except (WarpError, CoreError, httpx.HTTPError, OSError, ValueError) as e:
                        result["warp"]["error"] = str(e) if isinstance(e, (WarpError, CoreError)) else error_kind(e)
        except (CoreError, httpx.HTTPError, OSError, ValueError) as e:
            result.update(status="failed", error=str(e) if isinstance(e, CoreError) else error_kind(e))

    async def save(self):
        async with self.save_lock:
            self.report["updated"] = now()
            atomic_json(self.data / "run.json", self.report)
            write_report(self.output, self.report)
            if self.on_update:
                self.on_update(self.report)

    async def run(self, resume=False, retry_failed=False, selected=None):
        nodes = await collect(self.config)
        if not nodes:
            raise ValueError("No sources configured; run configure first")
        signature = identifier(self.config)
        checkpoint = self.data / "run.json"
        previous = {}
        if (resume or retry_failed or selected) and checkpoint.exists():
            saved = json.loads(checkpoint.read_text(encoding="utf-8"))
            if saved.get("config_signature") != signature:
                raise ValueError("Settings changed; start a new run without --resume/--retry-failed/--only")
            previous = {r["id"]: r for r in saved["results"]}
        selected = set(selected or [])
        if selected and not selected.issubset({n.id for n in nodes}):
            raise ValueError("--only contains unknown node IDs; use list")
        self.report = {"version": __version__, "created": now(), "config_signature": signature,
                       "services": [s["name"] for s in self.config["services"]], "completed": False,
                       "parameters": {k: self.config[k] for k in ("parallel", "timeout", "node_timeout", "latency_samples", "retries",
                                                                  "speed", "download_bytes", "upload_bytes", "speed_repeats", "warp", "browser")},
                       "resources": {"latency": public_url(self.config["latency_url"]),
                                     "services": [{"name": s["name"], "url": public_url(s["url"])} for s in self.config["services"]]},
                       "cores": {k: v["version"] for k, v in LOCK.items()}, "results": []}
        todo = []
        for node in nodes:
            old = previous.get(node.id)
            skip = (selected and node.id not in selected) or (retry_failed and old and not failed(old)) or (resume and old and old.get("status") not in ("pending", "running", "cancelled"))
            if skip:
                self.report["results"].append(old or {**node.public(), "status": "not_selected"})
            else:
                row = {**node.public(), "status": "pending"}
                self.report["results"].append(row)
                todo.append((node, row))
        sem = asyncio.Semaphore(self.config["parallel"])

        async def worker(node, row):
            async with sem:
                print(f"Проверяется: {node.name}", flush=True)
                try:
                    async with asyncio.timeout(self.config["node_timeout"]):
                        await self.test(node, row)
                except asyncio.TimeoutError:
                    row.update(status="failed", error="Node time budget exceeded")
                except asyncio.CancelledError:
                    row.update(status="cancelled", error="Interrupted by user")
                    raise
                except Exception as e:
                    row.update(status="failed", error="Unexpected test error: " + error_kind(e))
                finally:
                    row["finished"] = now()
                    self.completed += 1
                    print(f"[{self.completed}/{len(todo)}] {row['name']} — {row['status']}", flush=True)
                    await self.save()

        await self.save()
        self.tasks = [asyncio.create_task(worker(node, row)) for node, row in todo]
        try:
            await asyncio.gather(*self.tasks)
            self.report["completed"] = True
        finally:
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            for row in self.report["results"]:
                if row["status"] in ("running", "pending"):
                    row["status"] = "cancelled"
            await self.save()
        return Path(self.output).resolve()
