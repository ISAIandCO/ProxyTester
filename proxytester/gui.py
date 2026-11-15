"""Native Windows UI. Tk stays on the main thread; the existing async runner does the work."""
import asyncio
import json
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from copy import deepcopy
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from types import SimpleNamespace
from urllib.parse import urlsplit

from . import __version__
from .config import DEFAULT, load, validate
from .cores import install
from .runner import Runner
from .services import BrowserConnectionError
from .subscriptions import collect
from .util import atomic_json, error_kind

STATES = {"pending": "Ожидает", "running": "Проверяется", "ok": "VPN работает", "failed": "Ошибка",
          "invalid": "Некорректная запись", "cancelled": "Прервано", "not_selected": "Не выбран"}
MODES = ("Все серверы", "Продолжить прерванный запуск", "Повторить ошибки", "Выбранные серверы")
NUMBERS = (("parallel", "Параллельных серверов", 1), ("timeout", "Сетевой таймаут, с", 1),
           ("node_timeout", "Бюджет на сервер, с", 1), ("retries", "Повторы проверки IP", 1),
           ("latency_samples", "Измерений задержки", 1), ("speed_repeats", "Измерений скорости", 1),
           ("download_bytes", "Download за измерение, MB", 1000000), ("upload_bytes", "Upload, MB (0 — выключить)", 1000000),
           ("warp_cache_days", "Кэш WARP, дней", 1), ("browser_settle_ms", "Ожидание JavaScript, мс", 1))


def describe_error(exc):
    if isinstance(exc, BrowserConnectionError):
        return str(exc)
    if isinstance(exc, json.JSONDecodeError):
        return f"Некорректный JSON: строка {exc.lineno}, столбец {exc.colno}"
    if type(exc) in (ValueError, RuntimeError) and "http" not in str(exc).lower():
        return str(exc)
    return error_kind(exc)


class Worker:
    """One operation at a time; cancellation is delivered to asyncio, never by killing cores."""
    def __init__(self, events):
        self.events = events
        self.thread = self.loop = self.task = None
        self.stop_requested = threading.Event()

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, operation):
        if self.running:
            raise RuntimeError("Дождитесь завершения текущей операции")
        self.stop_requested.clear()

        def work():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop
            self.task = loop.create_task(operation())
            if self.stop_requested.is_set():
                self.task.cancel()
            outcome, value = "done", None
            try:
                value = loop.run_until_complete(self.task)
            except asyncio.CancelledError:
                outcome = "cancelled"
            except Exception as exc:
                outcome, value = "error", describe_error(exc)
            finally:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.run_until_complete(loop.shutdown_default_executor())
                self.loop = self.task = None
                loop.close()
                self.events.put((outcome, value))

        self.thread = threading.Thread(target=work, name="proxytester-worker", daemon=False)
        self.thread.start()

    def stop(self):
        self.stop_requested.set()
        loop, task = self.loop, self.task
        if loop and task and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:  # The operation may have just finished on the worker thread.
                pass


async def prepare_components(config, cores, log):
    log("Проверка и подготовка компонентов…")
    await asyncio.to_thread(install, cores, progress=log)
    if not config["browser"]:
        return
    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        executable = config.get("browser_executable") or pw.chromium.executable_path
    if Path(executable).is_file():
        return
    if config.get("browser_executable"):
        raise ValueError("Указанный файл Chrome/Chromium не найден")
    from playwright._impl._driver import compute_driver_executable
    driver, cli = compute_driver_executable()
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    process = await asyncio.create_subprocess_exec(driver, cli, "install", "chromium", stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.STDOUT, **kwargs)
    try:
        while line := await process.stdout.readline():
            log(re.sub(r"\x1b\[[0-9;]*m", "", line.decode(errors="replace")).strip())
        if await process.wait():
            raise RuntimeError("Не удалось подготовить Chromium. Проверьте подключение и повторите подготовку.")
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 4)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()


class EditDialog(tk.Toplevel):
    def __init__(self, parent, kind, value, apply):
        super().__init__(parent)
        self.kind, self.original, self.apply = kind, deepcopy(value), apply
        self.title("Подписка" if kind == "subscriptions" else "Веб-сервис")
        self.transient(parent)
        self.resizable(True, False)
        self.columnconfigure(1, weight=1)
        self.vars, self.json_fields = {}, {}
        fields = (("url", "URL подписки"), ("hwid", "HWID (необязательно)"), ("hwid_mode", "Передача HWID"),
                  ("hwid_name", "Имя заголовка / параметра")) if kind == "subscriptions" else (
                  ("name", "Название"), ("url", "Адрес сервиса"), ("success_selector", "Признак готовности: CSS / Playwright"),
                  ("success_regex", "Признак готовности: regex текста"))
        for row, (key, label) in enumerate(fields):
            ttk.Label(self, text=label).grid(row=row, column=0, padx=16, pady=8, sticky="w")
            self.vars[key] = tk.StringVar(value=value.get(key, "header" if key == "hwid_mode" else "x-hwid" if key == "hwid_name" else ""))
            widget = ttk.Combobox(self, textvariable=self.vars[key], values=("header", "query", "bearer"), state="readonly") if key == "hwid_mode" else ttk.Entry(self, textvariable=self.vars[key], width=62, show="•" if key == "hwid" else "")
            widget.grid(row=row, column=1, padx=(0, 16), pady=8, sticky="ew")
        row = len(fields)
        if kind == "subscriptions":
            for key, label in (("headers", "Дополнительные заголовки, JSON"), ("query", "Дополнительные query-параметры, JSON")):
                ttk.Label(self, text=label).grid(row=row, column=0, padx=16, pady=8, sticky="nw")
                box = ScrolledText(self, height=3, width=58, font=("Consolas", 10))
                box.insert("1.0", json.dumps(value.get(key, {}), ensure_ascii=False))
                box.grid(row=row, column=1, padx=(0, 16), pady=8, sticky="ew")
                self.json_fields[key] = box
                row += 1
        else:
            ttk.Label(self, text="Укажите видимый элемент рабочего приложения. Страница входа не подтверждает доступность.",
                      wraplength=650, foreground="#52637a").grid(row=row, column=0, columnspan=2, padx=16, pady=8, sticky="w")
            row += 1
        buttons = ttk.Frame(self)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", padx=16, pady=16)
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Сохранить", command=self.save).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())
        self.grab_set()

    def save(self):
        try:
            value = deepcopy(self.original)
            value.update({key: var.get().strip() for key, var in self.vars.items()})
            value.update({key: json.loads(box.get("1.0", "end")) for key, box in self.json_fields.items()})
            if self.kind == "services":
                for key in ("success_selector", "success_regex"):
                    if not value[key]:
                        value.pop(key)
            validate({self.kind: [value]})
            self.apply(value)
            self.destroy()
        except (ValueError, TypeError) as exc:
            messagebox.showerror("Проверьте поля", describe_error(exc), parent=self)


class App:
    def __init__(self, root, config_path="config.json", cores="cores", data="data"):
        self.root, self.path, self.cores, self.data = root, Path(config_path), str(cores), Path(data)
        self.events = queue.Queue()
        self.worker = Worker(self.events)
        self.busy = self.closing = False
        self.auth_event = None
        self.operation = ""
        self.config = load(self.path) if self.path.exists() else deepcopy(DEFAULT)
        self.output = tk.StringVar(value=str(Path("reports/report.html").resolve()))
        self.auto_open = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Добавьте подписку или локальный файл, затем запустите проверку.")
        self.mode = tk.StringVar(value=MODES[0])
        self.vars = {}
        self.last_report = None
        self.root.title(f"ProxyTester {__version__}")
        self.root.geometry("1120x820")
        self.root.minsize(900, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
        style.configure("TNotebook.Tab", padding=(18, 9))
        style.configure("Heading.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Treeview", rowheight=27)
        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        head = ttk.Frame(outer)
        head.pack(fill="x", pady=(0, 12))
        ttk.Label(head, text="ProxyTester", style="Heading.TLabel").pack(side="left")
        ttk.Label(head, text="  VPN → WARP · проверка маршрутов и сервисов", foreground="#52637a").pack(side="left")
        self.config_buttons = []
        for text, command in (("Открыть настройки…", self.open_config), ("Сохранить как…", self.save_as), ("Сохранить", self.save_config)):
            button = ttk.Button(head, text=text, command=command)
            button.pack(side="right", padx=(8, 0))
            self.config_buttons.append(button)
        self.config_label = ttk.Label(outer, text=str(self.path.resolve()), foreground="#52637a")
        self.config_label.pack(anchor="w", pady=(0, 10))
        self.status_label = ttk.Label(outer, textvariable=self.status, wraplength=950)
        self.status_label.pack(side="bottom", fill="x", pady=(12, 0))
        self.book = ttk.Notebook(outer)
        self.book.pack(fill="both", expand=True)
        self.tabs = [ttk.Frame(self.book, padding=14) for _ in range(4)]
        for frame, title in zip(self.tabs, ("Подписки", "Сервисы", "Параметры", "Запуск")):
            self.book.add(frame, text=title)
        self.build_sources()
        self.build_services()
        self.build_settings()
        self.build_run()
        self.fill()
        self.after_id = self.root.after(100, self.poll)
        checkpoint = self.data / "run.json"
        if checkpoint.exists():
            try:
                self.display_report(json.loads(checkpoint.read_text(encoding="utf-8")))
            except (OSError, ValueError, KeyError, TypeError):
                pass

    def table(self, frame, columns, height=8):
        holder = ttk.Frame(frame)
        holder.pack(fill="both", expand=True, pady=(8, 8))
        tree = ttk.Treeview(holder, columns=[key for key, _, _ in columns], show="headings", height=height)
        scrollbar = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=60)
        return tree

    def build_sources(self):
        frame = self.tabs[0]
        ttk.Label(frame, text="Подписки", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(frame, text="URL и HWID сохраняются в настройках. В отчёт они не попадают.").pack(anchor="w")
        self.sources = self.table(frame, (("source", "Источник", 440), ("hwid", "HWID", 140), ("mode", "Передача", 180)))
        self.sources.bind("<Double-1>", lambda e: self.edit_item("subscriptions", True))
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        for title, action in (("Добавить…", lambda: self.edit_item("subscriptions")), ("Изменить…", lambda: self.edit_item("subscriptions", True)),
                              ("Удалить", lambda: self.delete_item("subscriptions"))):
            ttk.Button(bar, text=title, command=action).pack(side="left", padx=(0, 8))
        ttk.Label(frame, text="Локальные подписки (URI, base64, JSON, YAML)", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(20, 5))
        self.files = tk.Listbox(frame, height=5, selectmode="extended", exportselection=False)
        self.files.pack(fill="x", pady=(0, 8))
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Button(bar, text="Добавить файлы…", command=self.add_files).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="Удалить выбранные", command=self.remove_files).pack(side="left")

    def build_services(self):
        frame = self.tabs[1]
        ttk.Label(frame, text="Сервисы для проверки через VPN и VPN → WARP", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.services = self.table(frame, (("name", "Сервис", 180), ("url", "Адрес", 370), ("check", "Проверка готовности", 230)))
        self.services.bind("<Double-1>", lambda e: self.edit_item("services", True))
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        for title, action in (("Добавить…", lambda: self.edit_item("services")), ("Изменить…", lambda: self.edit_item("services", True)),
                              ("Удалить", lambda: self.delete_item("services"))):
            ttk.Button(bar, text=title, command=action).pack(side="left", padx=(0, 8))
        ttk.Label(frame, text="Дополнительные ресурсы Cloudflare — один URL на строку", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(20, 5))
        self.cf_urls = ScrolledText(frame, height=4, font=("Segoe UI", 10))
        self.cf_urls.pack(fill="x")

    def build_settings(self):
        frame = self.tabs[2]
        toggles = ttk.Frame(frame)
        toggles.pack(fill="x", pady=(0, 12))
        for key, title in (("speed", "Измерять скорость"), ("warp", "Проверять VPN → WARP"), ("browser", "Проверять сервисы в Chromium")):
            self.vars[key] = tk.BooleanVar()
            ttk.Checkbutton(toggles, text=title, variable=self.vars[key]).pack(side="left", padx=(0, 20))
        numbers = ttk.Frame(frame)
        numbers.pack(fill="x")
        for i, (key, title, _) in enumerate(NUMBERS):
            column, row = i % 2, i // 2
            numbers.columnconfigure(column * 2 + 1, weight=1)
            ttk.Label(numbers, text=title).grid(row=row, column=column * 2, sticky="w", pady=7, padx=(0, 12))
            self.vars[key] = tk.StringVar()
            ttk.Entry(numbers, textvariable=self.vars[key], width=12).grid(row=row, column=column * 2 + 1, sticky="ew", pady=7, padx=(0, 24))
        advanced = ttk.LabelFrame(frame, text="Ресурсы и сессия", padding=10)
        advanced.pack(fill="x", pady=(18, 0))
        advanced.columnconfigure(1, weight=1)
        for row, (key, label) in enumerate((("latency_url", "Адрес для задержки"), ("download_url", "Download URL ({bytes} — объём)"),
                ("upload_url", "Upload URL"), ("warp_api", "WARP API"), ("browser_executable", "Свой Chrome / Chromium"), ("storage_state", "Файл авторизованной сессии"))):
            self.vars[key] = tk.StringVar()
            ttk.Label(advanced, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
            ttk.Entry(advanced, textvariable=self.vars[key]).grid(row=row, column=1, sticky="ew", pady=5)
            if key in ("browser_executable", "storage_state"):
                ttk.Button(advanced, text="Обзор…", command=lambda k=key: self.choose_file(k)).grid(row=row, column=2, padx=(8, 0))

    def build_run(self):
        frame = self.tabs[3]
        row = ttk.Frame(frame)
        row.pack(fill="x")
        self.run_mode = ttk.Combobox(row, textvariable=self.mode, values=MODES, state="readonly", width=31)
        self.run_mode.pack(side="left", padx=(0, 8))
        self.run_buttons = []
        for title, action in (("Загрузить серверы", self.load_nodes), ("Подготовить компоненты", self.prepare), ("Запустить", self.start_run)):
            b = ttk.Button(row, text=title, command=action)
            b.pack(side="left", padx=(0, 8))
            self.run_buttons.append(b)
        self.stop_button = ttk.Button(row, text="Остановить", command=self.stop, state="disabled")
        self.stop_button.pack(side="right")
        self.progress = ttk.Progressbar(frame, mode="determinate")
        self.progress.pack(fill="x", pady=(14, 4))
        self.progress_text = ttk.Label(frame, text="Серверы ещё не загружены")
        self.progress_text.pack(anchor="w")
        self.results = self.table(frame, (("name", "Сервер", 280), ("protocol", "Протокол", 90), ("status", "Состояние", 180),
                                         ("vpn", "IP VPN", 150), ("warp", "IP WARP", 150)), height=8)
        self.results.bind("<Double-1>", lambda e: self.show_details())
        self.results.bind("<Return>", lambda e: self.show_details())
        row = ttk.Frame(frame)
        row.pack(fill="x")
        self.auth_button = ttk.Button(row, text="Войти через выбранный сервер…", command=self.authorize)
        self.auth_button.pack(side="left")
        self.session_button = ttk.Button(row, text="Сохранить сессию", command=self.finish_auth, state="disabled")
        self.session_button.pack(side="left", padx=8)
        ttk.Button(row, text="Подробности сервера…", command=self.show_details).pack(side="right")
        ttk.Label(frame, text="Отчёт HTML", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(12, 4))
        row = ttk.Frame(frame)
        row.pack(fill="x")
        self.output_entry = ttk.Entry(row, textvariable=self.output)
        self.output_entry.pack(side="left", fill="x", expand=True)
        self.output_button = ttk.Button(row, text="Куда сохранить…", command=self.choose_output)
        self.output_button.pack(side="left", padx=8)
        ttk.Button(row, text="Открыть отчёт", command=self.open_report).pack(side="left")
        ttk.Checkbutton(frame, text="Открывать отчёт после завершения", variable=self.auto_open).pack(anchor="w", pady=8)
        self.log = ScrolledText(frame, height=5, font=("Consolas", 10), state="disabled")
        self.log.pack(fill="both", expand=True)

    def fill(self):
        for key, var in self.vars.items():
            value = self.config.get(key)
            factor = next((scale for name, _, scale in NUMBERS if name == key), 1)
            var.set(format(value / factor, "g") if factor != 1 else "" if value is None else value)
        self.cf_urls.delete("1.0", "end")
        self.cf_urls.insert("1.0", "\n".join(self.config["cloudflare_urls"]))
        self.refresh_models()
        self.config_label.configure(text=str(self.path.resolve()))
        prefs = self.path.with_suffix(".gui.json")
        if prefs.exists():
            try:
                saved = json.loads(prefs.read_text(encoding="utf-8"))
                if isinstance(saved.get("output"), str) and saved["output"]:
                    self.output.set(saved["output"])
                if isinstance(saved.get("auto_open"), bool):
                    self.auto_open.set(saved["auto_open"])
            except (ValueError, OSError, AttributeError):
                pass

    def refresh_models(self):
        for kind, tree in (("subscriptions", self.sources), ("services", self.services)):
            tree.delete(*tree.get_children())
            for index, item in enumerate(self.config[kind]):
                values = (f"{index + 1}. {urlsplit(item['url']).hostname}", "Задан" if item.get("hwid") else "Нет", item.get("hwid_mode", "header")) if kind == "subscriptions" else (
                          item["name"], item["url"], "CSS / Playwright" if item.get("success_selector") else "Regex" if item.get("success_regex") else "Не задана")
                tree.insert("", "end", iid=str(index), values=values)
        self.files.delete(0, "end")
        for file in self.config["files"]:
            self.files.insert("end", file)

    def read_config(self):
        value = deepcopy(self.config)
        for key, var in self.vars.items():
            value[key] = var.get()
        for key, title, scale in NUMBERS:
            try:
                raw = self.vars[key].get().replace(",", ".")
                number = float(raw) * scale
                if not number.is_integer():
                    raise ValueError()
                value[key] = int(number)
            except (ValueError, OverflowError):
                raise ValueError(f"{title}: укажите корректное число") from None
        for key in ("browser_executable", "storage_state"):
            value[key] = value[key].strip() or None
        value["cloudflare_urls"] = [line.strip() for line in self.cf_urls.get("1.0", "end").splitlines() if line.strip()]
        return validate(value)

    def save_config(self):
        try:
            self.config = self.read_config()
            atomic_json(self.path, self.config)
            atomic_json(self.path.with_suffix(".gui.json"), {"output": self.output.get(), "auto_open": self.auto_open.get()})
            self.config_label.configure(text=str(self.path.resolve()))
            self.status.set("Настройки сохранены.")
            return True
        except (ValueError, OSError, TypeError) as exc:
            messagebox.showerror("Не удалось сохранить", describe_error(exc), parent=self.root)
            return False

    def save_as(self):
        file = filedialog.asksaveasfilename(parent=self.root, defaultextension=".json", filetypes=[("Настройки", "*.json")])
        if file:
            old = self.path
            self.path = Path(file)
            if not self.save_config():
                self.path = old

    def open_config(self):
        file = filedialog.askopenfilename(parent=self.root, filetypes=[("Настройки", "*.json")])
        if file:
            try:
                config = load(file)
                self.path, self.config = Path(file), config
                self.fill()
                self.status.set("Настройки загружены.")
            except (ValueError, OSError, TypeError) as exc:
                messagebox.showerror("Не удалось открыть", describe_error(exc), parent=self.root)

    def edit_item(self, kind, editing=False):
        tree = self.sources if kind == "subscriptions" else self.services
        selected = tree.selection()
        if editing and not selected:
            return
        index = int(selected[0]) if editing else None
        def apply(item):
            items = deepcopy(self.config[kind])
            if index is None:
                items.append(item)
            else:
                items[index] = item
            validate({kind: items})
            self.config[kind] = items
            self.refresh_models()
        return EditDialog(self.root, kind, self.config[kind][index] if editing else {}, apply)

    def delete_item(self, kind):
        tree = self.sources if kind == "subscriptions" else self.services
        for index in sorted(map(int, tree.selection()), reverse=True):
            del self.config[kind][index]
        self.refresh_models()

    def add_files(self):
        files = filedialog.askopenfilenames(parent=self.root, title="Локальные подписки")
        self.config["files"] = list(dict.fromkeys(self.config["files"] + list(files)))
        self.refresh_models()

    def remove_files(self):
        for index in reversed(self.files.curselection()):
            del self.config["files"][index]
        self.refresh_models()

    def choose_file(self, key):
        path = filedialog.askopenfilename(parent=self.root)
        if path:
            self.vars[key].set(path)

    def choose_output(self):
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".html", filetypes=[("HTML", "*.html")])
        if path:
            self.output.set(path)

    def set_busy(self, busy):
        self.busy = busy
        for index in range(3):
            self.book.tab(index, state="disabled" if busy else "normal")
        for widget in [*self.config_buttons, *self.run_buttons, self.auth_button, self.output_entry, self.output_button]:
            widget.configure(state="disabled" if busy else "normal")
        self.run_mode.configure(state="disabled" if busy else "readonly")
        self.stop_button.configure(state="normal" if busy else "disabled")
        if not busy:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            if self.operation != "run":
                self.progress.configure(value=0)
            self.session_button.configure(state="disabled")

    def begin(self, kind, operation):
        if self.busy:
            return
        self.operation = kind
        self.book.select(3)
        self.set_busy(True)
        self.progress.configure(mode="indeterminate")
        self.progress.start(15)
        self.status.set("Подготовка…")
        self.worker.start(operation)

    def log_message(self, message):
        self.events.put(("log", message))

    def load_nodes(self):
        if not self.save_config():
            return
        config = deepcopy(self.config)
        async def operation():
            nodes = await collect(config)
            if not nodes:
                raise ValueError("Добавьте хотя бы одну подписку или локальный файл")
            return [n.public() for n in nodes]
        self.begin("nodes", operation)

    def prepare(self):
        if self.save_config():
            config = deepcopy(self.config)
            self.begin("prepare", lambda: prepare_components(config, self.cores, self.log_message))

    def start_run(self):
        if not self.save_config():
            return
        config, output, mode = deepcopy(self.config), self.output.get().strip(), self.mode.get()
        selected = list(self.results.selection()) if mode == MODES[3] else None
        if not config["subscriptions"] and not config["files"]:
            messagebox.showerror("Нет источников", "Добавьте подписку или локальный файл на первой вкладке.", parent=self.root)
            return
        if not output or (selected is not None and not selected):
            messagebox.showerror("Проверьте запуск", "Укажите путь отчёта и выберите серверы для выбранного режима.", parent=self.root)
            return
        async def operation():
            await prepare_components(config, self.cores, self.log_message)
            runner = Runner(config, self.cores, self.data, output, on_update=lambda report: self.events.put(("report", deepcopy(report))))
            return str(await runner.run(resume=mode == MODES[1], retry_failed=mode == MODES[2], selected=selected))
        self.begin("run", operation)

    def authorize(self):
        selected = self.results.selection()
        if len(selected) != 1:
            messagebox.showinfo("Выберите сервер", "Загрузите список серверов и выделите один для входа в сервис.", parent=self.root)
            return
        if not self.save_config():
            return
        config = deepcopy(self.config)
        if not config["services"]:
            messagebox.showerror("Нет сервиса", "Добавьте сервис для авторизации.", parent=self.root)
            return
        session = self.path.resolve().with_suffix(".session.json")
        async def operation():
            from .cli import login
            await prepare_components({**config, "browser": True}, self.cores, self.log_message)
            self.auth_event = asyncio.Event()
            async def confirm():
                self.events.put(("auth_ready", None))
                await self.auth_event.wait()
            await login(config, SimpleNamespace(node=selected[0], cores=self.cores, session=str(session), config=str(self.path)), confirm=confirm, progress=self.log_message)
        self.begin("auth", operation)

    def finish_auth(self):
        if self.worker.loop and self.auth_event:
            self.worker.loop.call_soon_threadsafe(self.auth_event.set)
            self.session_button.configure(state="disabled")

    def stop(self):
        if self.busy:
            self.worker.stop()
            self.stop_button.configure(state="disabled")
            self.status.set("Останавливаем проверку, закрываем соединения и сохраняем результаты…")

    def display_report(self, report):
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.last_report = report
        selected = set(self.results.selection())
        scroll = self.results.yview()[0]
        self.results.delete(*self.results.get_children())
        results = report["results"]
        for item in results:
            state = item.get("status", "pending")
            if state == "ok" and not item.get("finished"):
                label = "Проверяется WARP" if report.get("parameters", {}).get("warp") else "Завершается"
            else:
                label = STATES.get(state, state)
            self.results.insert("", "end", iid=item["id"], values=(item["name"], item["protocol"], label,
                item.get("vpn", {}).get("identity", {}).get("ip", "—"), item.get("warp", {}).get("identity", {}).get("ip", "—")))
            if item["id"] in selected:
                self.results.selection_add(item["id"])
        self.results.yview_moveto(scroll)
        done = sum(bool(r.get("finished")) or r.get("status") in ("invalid", "not_selected", "cancelled") for r in results)
        self.progress.configure(maximum=max(1, len(results)), value=done)
        self.progress_text.configure(text=f"Обработано {done} из {len(results)} · VPN подтверждён: {sum(bool(r.get('vpn', {}).get('identity', {}).get('verified')) for r in results)}")

    def poll(self):
        for _ in range(100):
            try:
                event, value = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "report":
                self.display_report(value)
                self.status.set("Проверяем серверы…" if not self.worker.stop_requested.is_set() else "Останавливаем…")
            elif event == "log":
                self.log.configure(state="normal")
                self.log.insert("end", value + "\n")
                if int(self.log.index("end-1c").split(".")[0]) > 1000:
                    self.log.delete("1.0", "200.0")
                self.log.see("end")
                self.log.configure(state="disabled")
                self.status.set(value)
            elif event == "auth_ready":
                self.session_button.configure(state="normal")
                self.status.set("Войдите в сервис в окне Chromium, затем нажмите «Сохранить сессию».")
            else:
                self.set_busy(False)
                if event == "done":
                    if self.operation == "nodes":
                        self.display_report({"results": [{**n, "status": "invalid" if n["issue"] else "pending"} for n in value]})
                        self.status.set(f"Загружено серверов: {len(value)}. Можно выбрать строки для отдельной проверки.")
                    elif self.operation == "auth":
                        self.config = load(self.path)
                        self.fill()
                        self.status.set("Авторизованная сессия сохранена и подключена к проверкам.")
                    else:
                        self.status.set("Проверка завершена. Отчёт сохранён." if self.operation == "run" else "Компоненты готовы.")
                        if self.operation == "run" and self.auto_open.get() and not self.closing:
                            self.open_report()
                elif event == "cancelled":
                    self.status.set("Остановлено. Полученные результаты сохранены." if self.operation == "run" and self.last_report else "Операция остановлена.")
                else:
                    self.status.set("Ошибка: " + value)
                    if not self.closing:
                        messagebox.showerror("Не удалось завершить операцию", value, parent=self.root)
                if self.closing:
                    self.destroy()
                    return
        self.after_id = self.root.after(100, self.poll)

    def open_report(self):
        path = Path(self.output.get()).resolve()
        if path.is_file():
            webbrowser.open(path.as_uri())
        else:
            self.status.set("Отчёт ещё не создан. Запустите проверку.")

    def show_details(self):
        selected = self.results.selection()
        if not selected or not self.last_report:
            return
        row = next((r for r in self.last_report["results"] if r["id"] == selected[0]), None)
        if row:
            window = tk.Toplevel(self.root)
            window.title("Подробности: " + row["name"])
            window.geometry("850x500")
            text = ScrolledText(window, font=("Consolas", 10), wrap="word")
            text.pack(fill="both", expand=True, padx=12, pady=12)
            text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2))
            text.configure(state="disabled")
            return window

    def close(self):
        if self.busy:
            self.closing = True
            self.stop()
        else:
            if self.save_config():
                self.destroy()

    def destroy(self):
        self.root.after_cancel(self.after_id)
        self.root.destroy()


def launch(config_path="config.json", cores="cores", data="data", smoke_test=False):
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
    os.chdir(base)
    if (base / "browsers").is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(base / "browsers")
    if os.name == "nt":
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    try:
        app = App(root, config_path, cores, data)
    except (ValueError, OSError, TypeError) as exc:
        messagebox.showerror("Настройки не загружены", describe_error(exc), parent=root)
        root.destroy()
        return 1
    if smoke_test:
        root.after(300, app.destroy)
    root.mainloop()
    return 0
