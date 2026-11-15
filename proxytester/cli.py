import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import load, wizard
from .cores import install, Route
from .network import verify
from .report import write_report
from .runner import Runner
from .services import browser_options
from .subscriptions import collect
from .util import atomic_json, error_kind


def root():
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()


async def login(cfg, args):
    from playwright.async_api import async_playwright
    nodes = await collect(cfg)
    node = next((n for n in nodes if n.id == args.node and not n.issue), None)
    if not node:
        raise ValueError("Unknown/invalid node ID; use list")
    async with Route(args.cores, node, cfg["timeout"]).base() as proxy:
        identity = await verify(proxy, cfg["timeout"], retries=cfg["retries"])
        if not identity["verified"]:
            raise ValueError("VPN identity could not be verified")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**browser_options(proxy, headless=False, executable=cfg.get("browser_executable")))
            try:
                context = await browser.new_context(service_workers="block")
                page = await context.new_page()
                await page.goto(cfg["services"][0]["url"], wait_until="domcontentloaded", timeout=cfg["timeout"] * 1000)
                print("Войдите в сервис в открытом браузере. CAPTCHA проходите вручную.")
                await asyncio.to_thread(input, "Когда вход завершён, нажмите Enter здесь… ")
                atomic_json(args.session, await context.storage_state(indexed_db=True))
            finally:
                await browser.close()
    config_path = Path(args.config)
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    saved["storage_state"] = str(Path(args.session).resolve())
    atomic_json(config_path, saved)
    print("Сессия сохранена и подключена в настройках. Файл содержит секреты — не публикуйте его.")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    base = root()
    os.chdir(base)
    if (base / "browsers").is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(base / "browsers")
    parser = argparse.ArgumentParser(description="ProxyTester — VLESS / Hysteria2 / VPN → WARP")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--cores", default="cores")
    parser.add_argument("--data", default="data")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("configure", help="Интерактивная настройка")
    p = sub.add_parser("setup", help="Загрузка ядер и Chromium")
    p.add_argument("--no-browser", action="store_true")
    sub.add_parser("list", help="Список серверов и ID")
    p = sub.add_parser("run", help="Запуск проверок")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--retry-failed", action="store_true")
    p.add_argument("--only", help="ID серверов через запятую")
    p.add_argument("--output", default="reports/report.html")
    p.add_argument("--open", action="store_true")
    p = sub.add_parser("login", help="Авторизация через выбранный VPN")
    p.add_argument("--node", required=True)
    p.add_argument("--session", default="session.json")
    p = sub.add_parser("report", help="Восстановить отчёт из checkpoint")
    p.add_argument("--output", default="reports/report.html")
    args = parser.parse_args()
    try:
        if not args.command:
            print("ProxyTester " + __version__)
            if not Path(args.config).exists():
                wizard(args.config)
            choice = input("1 — тест; 2 — настройка; 3 — список серверов; 4 — повторить ошибки [1]: ").strip() or "1"
            if choice == "2":
                wizard(args.config)
                return
            args.command = "list" if choice == "3" else "run"
            args.resume, args.retry_failed, args.only = False, choice == "4", None
            args.output, args.open = "reports/report.html", True
        if args.command == "configure":
            wizard(args.config)
            return
        if args.command == "setup":
            install(args.cores)
            if not args.no_browser:
                from playwright._impl._driver import compute_driver_executable
                driver, cli = compute_driver_executable()
                subprocess.run([driver, cli, "install", "chromium"], check=True)
            print("Компоненты готовы.")
            return
        if args.command == "report":
            result = write_report(args.output, json.loads((Path(args.data) / "run.json").read_text(encoding="utf-8")))
            print(result)
            return
        cfg = load(args.config)
        if args.command == "list":
            for n in asyncio.run(collect(cfg)):
                print(f"{n.id}  {n.protocol:10} {n.country:2} {n.name}" + (" — " + n.issue if n.issue else ""))
            return
        install(args.cores)
        if args.command == "login":
            asyncio.run(login(cfg, args))
            return
        if cfg["browser"]:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                available = Path(cfg.get("browser_executable") or pw.chromium.executable_path).exists()
            if not available:
                print("Chromium не найден. Выполните proxytester setup (или отключите browser в настройках).")
                return 2
        runner = Runner(cfg, args.cores, args.data, args.output)
        try:
            result = asyncio.run(runner.run(args.resume, args.retry_failed, args.only.split(",") if args.only else None))
        except KeyboardInterrupt:
            result = Path(args.output).resolve()
            if not runner.report:
                print("Прервано во время загрузки подписок; новый отчёт ещё не создан.")
                return 130
            print("Прервано. Промежуточные результаты сохранены.")
        print("Отчёт: " + str(result))
        if args.open:
            import webbrowser
            webbrowser.open(result.as_uri())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as e:
        # Config errors are controlled messages; network exceptions can contain secrets.
        message = str(e) if type(e) in (ValueError, RuntimeError) and "http" not in str(e).lower() else error_kind(e)
        print("Ошибка: " + message, file=sys.stderr)
        return 1
    return 0
