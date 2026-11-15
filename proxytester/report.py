import csv
import html
import io
import json
from pathlib import Path

from .util import atomic_json


def write_report(destination, report):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = Path(__file__).with_name("report.html").read_text(encoding="utf-8")
    content = template.replace("__REPORT_DATA__", payload)
    tmp = destination.with_suffix(".html.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(destination)
    atomic_json(destination.with_suffix(".json"), report, private=False)
    fields = ["id", "name", "country", "protocol", "status"]
    services = report.get("services", [])
    for route in ("vpn", "warp"):
        fields += [f"{route}.{k}" for k in ("verified", "ip", "rtt_ms", "download_mbps", "upload_mbps")]
        fields += [f"{route}.{s}" for s in services]
    with destination.with_suffix(".csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in report["results"]:
            values = {k: row.get(k, "") for k in fields[:5]}
            for route in ("vpn", "warp"):
                data = row.get(route, {})
                identity = data.get("identity", {})
                values.update({f"{route}.verified": identity.get("verified", False), f"{route}.ip": identity.get("ip", ""),
                               f"{route}.rtt_ms": data.get("latency", {}).get("rtt_ms", {}).get("median", ""),
                               f"{route}.download_mbps": data.get("speed", {}).get("download_mbps", {}).get("median", ""),
                               f"{route}.upload_mbps": data.get("speed", {}).get("upload_mbps", {}).get("median", "")})
                for service in services:
                    values[f"{route}.{service}"] = data.get("services", {}).get(service, {}).get("status", "not_tested")
            # Protect CSV consumers from spreadsheet formula execution in untrusted node names.
            writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r")) else v for k, v in values.items()})
    return destination.resolve()
