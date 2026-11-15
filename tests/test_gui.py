import asyncio
import gc
import json
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from proxytester.config import DEFAULT, load
from proxytester.gui import App, MODES, Worker


class WorkerTests(unittest.TestCase):
    def test_result_and_loop_cleanup(self):
        events = queue.Queue()
        worker = Worker(events)
        async def operation():
            return "finished"
        worker.start(operation)
        self.assertEqual(events.get(timeout=3), ("done", "finished"))
        worker.thread.join(3)
        self.assertFalse(worker.running)
        self.assertIsNone(worker.loop)

    def test_stop_waits_for_async_cleanup(self):
        events, started, cleaned = queue.Queue(), threading.Event(), threading.Event()
        worker = Worker(events)
        async def operation():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(.03)
                cleaned.set()
        worker.start(operation)
        self.assertTrue(started.wait(2))
        worker.stop()
        self.assertEqual(events.get(timeout=3)[0], "cancelled")
        self.assertTrue(cleaned.is_set())
        worker.thread.join(3)
        self.assertFalse(worker.running)

    def test_error_does_not_echo_secret_url(self):
        events = queue.Queue()
        worker = Worker(events)
        async def operation():
            raise RuntimeError("Failed https://example.com/?token=SECRET")
        worker.start(operation)
        state, message = events.get(timeout=3)
        worker.thread.join(3)
        self.assertEqual(state, "error")
        self.assertNotIn("SECRET", message)


@unittest.skipUnless(sys.platform == "win32" or os.environ.get("DISPLAY"), "Native Tk window requires a desktop")
class NativeGuiTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        self.temp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        self.app = App(self.root, Path(self.temp.name) / "config.json", data=Path(self.temp.name) / "data")
        self.app.output.set(str(Path(self.temp.name) / "report.html"))
        self.app.auto_open.set(False)
        self.root.update()

    def tearDown(self):
        if self.app.worker.running:
            self.app.stop()
            self.pump(lambda: not self.app.worker.running)
        if self.root.winfo_exists():
            self.app.destroy()
        # Destroyed Tcl interpreters must be finalized on their creating thread,
        # before the next test starts an allocating asyncio worker.
        self.app = self.root = None
        gc.collect()
        self.temp.cleanup()

    def pump(self, condition, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.root.update()
            if condition():
                return
            time.sleep(.015)
        self.fail("GUI operation did not finish")

    def test_settings_round_trip_preserves_advanced_fields(self):
        self.app.config["subscriptions"] = [{"url": "https://example.com/sub?token=secret", "hwid": "private", "hwid_mode": "query",
            "hwid_name": "device", "headers": {"X-Client": "custom"}, "query": {"format": "clash"}}]
        self.app.config["custom_extension"] = {"keep": True}
        self.app.fill()
        self.app.vars["parallel"].set("4")
        self.app.vars["download_bytes"].set("0.25")
        self.app.vars["upload_bytes"].set("0.1")
        self.app.vars["warp"].set(False)
        self.assertTrue(self.app.save_config())
        saved = load(self.app.path)
        self.assertEqual(saved["parallel"], 4)
        self.assertEqual(saved["download_bytes"], 250000)
        self.assertEqual(saved["upload_bytes"], 100000)
        self.assertFalse(saved["warp"])
        self.assertEqual(saved["subscriptions"][0]["headers"]["X-Client"], "custom")
        self.assertTrue(saved["custom_extension"]["keep"])
        self.assertNotIn("secret", str(self.app.sources.item("0", "values")))
        prefs = json.loads(self.app.path.with_suffix(".gui.json").read_text(encoding="utf-8"))
        self.assertEqual(prefs["output"], self.app.output.get())

    def test_subscription_and_service_dialogs_edit_models(self):
        dialog = self.app.edit_item("subscriptions")
        dialog.vars["url"].set("https://example.com/subscription")
        dialog.vars["hwid"].set("test-hwid")
        dialog.vars["hwid_mode"].set("header")
        dialog.save()
        self.assertEqual(self.app.config["subscriptions"][0]["hwid"], "test-hwid")
        self.app.sources.selection_set("0")
        dialog = self.app.edit_item("subscriptions", True)
        dialog.vars["hwid_mode"].set("query")
        dialog.save()
        self.assertEqual(self.app.config["subscriptions"][0]["hwid_mode"], "query")
        dialog = self.app.edit_item("services")
        dialog.vars["name"].set("Custom app")
        dialog.vars["url"].set("https://example.com/app")
        dialog.vars["success_selector"].set("#app-ready")
        dialog.save()
        self.assertEqual(self.app.config["services"][-1]["success_selector"], "#app-ready")

    def test_invalid_settings_are_not_written(self):
        self.assertTrue(self.app.save_config())
        original = self.app.path.read_bytes()
        self.app.vars["parallel"].set("100")
        with patch("proxytester.gui.messagebox.showerror") as error:
            self.assertFalse(self.app.save_config())
            self.assertTrue(error.called)
        self.assertEqual(self.app.path.read_bytes(), original)

    def test_load_nodes_start_real_runner_and_render_report(self):
        fixture = Path(self.temp.name) / "nodes.txt"
        fixture.write_text("ss://unsupported@127.0.0.1:443#Unsupported\nnot-a-valid-node", encoding="utf-8")
        self.app.config["files"] = [str(fixture)]
        self.app.load_nodes()
        self.pump(lambda: not self.app.busy)
        self.assertEqual(len(self.app.results.get_children()), 2)
        async def prepared(*args):
            pass
        with patch("proxytester.gui.prepare_components", prepared):
            self.app.start_run()
            self.pump(lambda: not self.app.busy)
        path = Path(self.app.output.get())
        self.assertTrue(path.is_file())
        report = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertTrue(report["completed"])
        self.assertTrue(all(r["status"] == "invalid" for r in report["results"]))
        self.assertEqual(float(self.app.progress["value"]), 2)
        self.assertEqual(str(self.app.stop_button["state"]), "disabled")
        self.app.results.selection_set(report["results"][0]["id"])
        detail = self.app.show_details()
        self.assertIsNotNone(detail)
        self.assertIn("Unsupported", detail.title())
        detail.destroy()

    def test_selected_mode_and_stop_use_existing_runner_contract(self):
        fixture = Path(self.temp.name) / "nodes.txt"
        fixture.write_text("not-a-node", encoding="utf-8")
        self.app.config["files"] = [str(fixture)]
        self.app.display_report({"results": [{"id": "one", "name": "Fixture", "protocol": "vless", "status": "pending"}]})
        self.app.results.selection_set("one")
        self.app.mode.set(MODES[3])
        captured, started, cleaned = {}, threading.Event(), threading.Event()
        class ControlledRunner:
            def __init__(self, *args, **kwargs):
                captured["config"] = args[0]
            async def run(self, **kwargs):
                captured.update(kwargs)
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(.03)
                    cleaned.set()
        async def prepared(*args):
            pass
        with patch("proxytester.gui.prepare_components", prepared), patch("proxytester.gui.Runner", ControlledRunner):
            self.app.start_run()
            self.pump(started.is_set)
            self.assertTrue(self.app.busy)
            self.app.stop()
            self.pump(lambda: not self.app.busy)
        self.assertEqual(captured["selected"], ["one"])
        self.assertTrue(cleaned.is_set())

    def test_authorization_confirmation_is_thread_safe(self):
        self.app.config["files"] = ["fixture.txt"]
        self.app.display_report({"results": [{"id": "one", "name": "Fixture", "protocol": "vless", "status": "pending"}]})
        self.app.results.selection_set("one")
        async def prepared(*args):
            pass
        async def login(config, args, confirm=None):
            await confirm()
            config["storage_state"] = args.session
            from proxytester.util import atomic_json
            atomic_json(args.config, config)
        with patch("proxytester.gui.prepare_components", prepared), patch("proxytester.cli.login", login):
            self.app.authorize()
            self.pump(lambda: str(self.app.session_button["state"]) == "normal")
            self.app.finish_auth()
            self.pump(lambda: not self.app.busy)
        self.assertTrue(self.app.vars["storage_state"].get().endswith(".session.json"))

    def test_layout_and_optional_windows_capture(self):
        for index, name in enumerate(("subscriptions", "services", "settings", "run")):
            self.app.book.select(index)
            self.root.update()
            self.assertTrue(self.app.tabs[index].winfo_viewable())
            if sys.platform == "win32" and os.environ.get("PROXYTESTER_GUI_QA") == "1":
                from gui_capture import capture
                capture(self.root, Path("data/gui-qa") / (name + ".bmp"))


if __name__ == "__main__":
    unittest.main()
