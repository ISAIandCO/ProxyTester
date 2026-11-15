import json
from copy import deepcopy
from pathlib import Path

from .util import atomic_json, web_url

DEFAULT = {
    "subscriptions": [],
    "files": [],
    "parallel": 2,
    "timeout": 20,
    "node_timeout": 240,
    "retries": 1,
    "latency_samples": 3,
    "latency_url": "https://www.gstatic.com/generate_204",
    "speed": True,
    "download_bytes": 5000000,
    "upload_bytes": 0,
    "speed_repeats": 1,
    "download_url": "https://speed.cloudflare.com/__down?bytes={bytes}",
    "upload_url": "https://speed.cloudflare.com/__up",
    "warp": True,
    "warp_api": "https://api.cloudflareclient.com/v0a4471",
    "warp_cache_days": 7,
    "browser": True,
    "browser_settle_ms": 3000,
    "storage_state": None,
    "services": [
        {"name": "NotebookLM", "url": "https://notebooklm.google.com/",
         "success_selector": "button:has-text('Create new'), button:has-text('New notebook'), button:has-text('Создать'), button:has-text('Новый блокнот')"},
        {"name": "Gemini", "url": "https://gemini.google.com/app",
         "success_selector": "rich-textarea [contenteditable=true], textarea[aria-label*='prompt' i]"}
    ],
    "cloudflare_urls": ["https://www.cloudflare.com/"],
}


def load(path):
    result = deepcopy(DEFAULT)
    result.update(json.loads(Path(path).read_text(encoding="utf-8")))
    for key, low, high in (("parallel", 1, 8), ("timeout", 1, 180), ("node_timeout", 10, 3600),
                           ("retries", 0, 3), ("latency_samples", 1, 20), ("speed_repeats", 1, 5),
                           ("download_bytes", 1000, 200000000), ("upload_bytes", 0, 50000000),
                           ("browser_settle_ms", 0, 30000), ("warp_cache_days", 1, 90)):
        if not isinstance(result[key], int) or not low <= result[key] <= high:
            raise ValueError(f"Invalid {key}: expected {low}..{high}")
    names = []
    for s in result["services"]:
        web_url(s["url"])
        if not s.get("name") or s["name"] in names:
            raise ValueError("Service names must be nonempty and unique")
        names.append(s["name"])
    for value in [result["latency_url"], result["download_url"].replace("{bytes}", "1000"),
                  result["upload_url"], result["warp_api"], *result["cloudflare_urls"]]:
        web_url(value)
    for source in result["subscriptions"]:
        web_url(source["url"])
        if source.get("hwid_mode", "header") not in ("header", "query", "bearer"):
            raise ValueError("hwid_mode must be header, query or bearer")
    return result


def wizard(path):
    config = deepcopy(DEFAULT)
    print("ProxyTester — настройка. Enter оставляет предложенное значение.")
    while True:
        url = input("URL подписки (пусто — закончить): ").strip()
        if not url:
            break
        web_url(url)
        source = {"url": url}
        hwid = input("HWID (необязательно): ").strip()
        if hwid:
            source.update(hwid=hwid, hwid_mode=input("Способ header/query/bearer [header]: ").strip() or "header",
                          hwid_name=input("Имя заголовка/параметра [x-hwid]: ").strip() or "x-hwid")
        config["subscriptions"].append(source)
    if not config["subscriptions"]:
        file = input("Путь к локальной подписке: ").strip().strip('"')
        if file:
            config["files"] = [str(Path(file).resolve())]
    config["parallel"] = int(input("Параллельных серверов [2]: ") or "2")
    config["speed"] = input("Проверять скорость? [Y/n]: ").lower() != "n"
    config["warp"] = input("Проверять VPN → WARP? [Y/n]: ").lower() != "n"
    extra = input("Дополнительные сервисы URL через запятую (необязательно): ").strip()
    for url in filter(None, map(str.strip, extra.split(","))):
        config["services"].append({"name": urlsplit_name(url), "url": web_url(url)})
    atomic_json(path, config)
    load(path)
    print(f"Сохранено: {path}")
    return config


def urlsplit_name(url):
    from urllib.parse import urlsplit
    return urlsplit(url).hostname
