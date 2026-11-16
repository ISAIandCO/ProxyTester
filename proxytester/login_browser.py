"""A separately launched browser for a human sign-in, with an isolated profile."""
import asyncio
import os
import shutil
import sys
import tempfile
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import httpx

from .cores import free_port
from .services import BrowserConnectionError, browser_options


def discover_browsers():
    """Installed stable Chromium browsers, with distinct installations preserved."""
    candidates = []
    names = (("Brave", "brave.exe"), ("Google Chrome", "chrome.exe"), ("Microsoft Edge", "msedge.exe"))
    if sys.platform == "win32":
        import winreg
        for label, executable in names:
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                    try:
                        key_path = r"Software\Microsoft\Windows\CurrentVersion\App Paths" + "\\" + executable
                        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                            candidates.append((label, winreg.QueryValueEx(key, None)[0]))
                    except OSError:
                        pass
    for label, relative in (("Brave", "BraveSoftware/Brave-Browser/Application/brave.exe"),
                            ("Google Chrome", "Google/Chrome/Application/chrome.exe"),
                            ("Microsoft Edge", "Microsoft/Edge/Application/msedge.exe")):
        for name in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            if base := os.environ.get(name):
                candidates.append((label, str(Path(base) / relative)))
    for label, executable in (("Brave", "brave.exe"), ("Google Chrome", "chrome.exe"), ("Microsoft Edge", "msedge.exe"),
                              ("Brave", "brave-browser"), ("Brave", "brave"), ("Google Chrome", "google-chrome"),
                              ("Google Chrome", "google-chrome-stable"), ("Microsoft Edge", "microsoft-edge"),
                              ("Chromium", "chromium"), ("Chromium", "chromium-browser")):
        if path := shutil.which(executable):
            candidates.append((label, path))
    found, seen = [], set()
    for label, value in candidates:
        if not isinstance(value, str):
            continue
        path = Path(os.path.expandvars(value).strip().strip('"')).expanduser()
        if path.is_file():
            resolved = str(path.resolve())
            key = os.path.normcase(resolved)
            if key not in seen:
                found.append((label, resolved))
                seen.add(key)
    return found


def login_executable(configured, bundled):
    if configured:
        path = Path(configured).expanduser()
        if not path.is_file():
            raise BrowserConnectionError("Браузер для входа не найден. Проверьте путь Brave / Chrome / Edge в параметрах.")
        return str(path.resolve())
    found = discover_browsers()
    if found:
        return found[0][1]
    if Path(bundled).is_file():
        return bundled
    raise BrowserConnectionError("Для входа установите Brave / Chrome / Edge либо подготовьте встроенный Chromium.")


@asynccontextmanager
async def manual_browser(pw, proxy, timeout, executable=None, progress=print):
    from playwright.async_api import Error
    executable = login_executable(executable, pw.chromium.executable_path)
    options = browser_options(proxy, headless=False)
    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    process = browser = None
    with tempfile.TemporaryDirectory(prefix="proxytester-login-") as profile:
        try:
            # Launch directly, without Playwright's --enable-automation/default flags.
            # CDP is local to this new profile; the regular browser profile is untouched.
            # The default context also has a proxy, so it cannot fall back to direct access.
            process = await asyncio.create_subprocess_exec(
                executable, *options["args"], f"--user-data-dir={profile}",
                "--remote-debugging-address=127.0.0.1", f"--remote-debugging-port={port}",
                "--proxy-server=" + options["proxy"]["server"], "--proxy-bypass-list=<-loopback>",
                "--no-default-browser-check", "about:blank",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            progress("Браузер для ручного входа: " + Path(executable).name + ". Отдельный временный профиль.")
            deadline = asyncio.get_running_loop().time() + timeout
            async with httpx.AsyncClient(trust_env=False, timeout=1) as session:
                while True:
                    if process.returncode is not None:
                        raise BrowserConnectionError("Браузер для входа завершился до подключения. Проверьте выбранный Brave / Chrome / Edge.")
                    try:
                        response = await session.get(endpoint + "/json/version")
                        if response.status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if asyncio.get_running_loop().time() >= deadline:
                        raise BrowserConnectionError("Браузер для входа не готов: timeout. Проверьте браузер и ограничения удалённой отладки.")
                    await asyncio.sleep(.1)
            browser = await pw.chromium.connect_over_cdp(endpoint, timeout=timeout * 1000)
            # Context-level proxy retains authentication on both local hops.
            context = await browser.new_context(proxy=options["proxy"], service_workers="block", locale="en-US")
            page = await context.new_page()
            for other in browser.contexts:
                if other != context:
                    for blank in other.pages:
                        await blank.close()
            yield context, page
        finally:
            if browser:
                with suppress(Error):
                    control = await browser.new_browser_cdp_session()
                    await control.send("Browser.close")
                with suppress(Error):
                    await browser.close()
            if process and process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except asyncio.TimeoutError:
                    process.terminate()
                    await process.wait()
