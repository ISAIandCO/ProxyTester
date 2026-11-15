import asyncio
import hashlib
import io
import json
import os
import platform
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path

from .util import atomic_json

LOCK = json.loads(Path(__file__).with_name("cores.lock.json").read_text())


def binary(directory, name):
    return Path(directory).resolve() / (name + (".exe" if os.name == "nt" else ""))


def install(directory, target=None):
    target = target or ("windows" if os.name == "nt" else "linux")
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Only x64 is packaged")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, spec in LOCK.items():
        filename = name + (".exe" if target == "windows" else "")
        dest = directory / filename
        receipt = directory / (name + ".receipt.json")
        if dest.exists() and receipt.exists():
            saved = json.loads(receipt.read_text())
            if saved.get("asset_sha256") == spec[target]["sha256"] and saved.get("binary_sha256") == hashlib.sha256(dest.read_bytes()).hexdigest():
                continue
        asset = spec[target]
        url = f"https://github.com/{spec['repository']}/releases/download/v{spec['version']}/{asset['asset']}"
        print(f"Загрузка {name} {spec['version']} ({target})…", flush=True)
        with urllib.request.urlopen(url, timeout=90) as response:
            data = response.read(100000000)
        if hashlib.sha256(data).hexdigest() != asset["sha256"]:
            raise RuntimeError("Core archive checksum mismatch")
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                member = next(n for n in archive.namelist() if Path(n).name == filename)
                content = archive.read(member)
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                member = next(n for n in archive.getmembers() if Path(n.name).name == filename and n.isfile())
                content = archive.extractfile(member).read()
        # Extract a known executable only, never archive paths.
        temp = dest.with_suffix(".tmp")
        temp.write_bytes(content)
        temp.chmod(0o755)
        temp.replace(dest)
        license_url = f"https://raw.githubusercontent.com/{spec['repository']}/v{spec['version']}/LICENSE"
        with urllib.request.urlopen(license_url, timeout=30) as response:
            (directory / (name + ".LICENSE")).write_bytes(response.read(200000))
        atomic_json(receipt, {"version": spec["version"], "asset_sha256": asset["sha256"],
                              "binary_sha256": hashlib.sha256(content).hexdigest()})


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def xray_config(node, port):
    outbound = deepcopy(node.outbound)
    outbound["tag"] = "vpn"
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": "test",
                          "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}],
            "outbounds": [outbound],
            "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["test"], "outboundTag": "vpn"}]}}


def sing_config(node, port, xray_port=None, warp=None):
    if node.core == "xray":
        vpn = {"type": "socks", "tag": "vpn", "server": "127.0.0.1", "server_port": xray_port, "version": "5"}
    else:
        vpn = deepcopy(node.outbound)
        vpn["tag"] = "vpn"
    final = "warp" if warp else "vpn"
    config = {"log": {"disabled": True},
              "dns": {"servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "server_port": 443,
                                     "path": "/dns-query", "detour": final, "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}}],
                      "final": "remote", "strategy": "prefer_ipv4"},
              "inbounds": [{"type": "mixed", "tag": "test", "listen": "127.0.0.1", "listen_port": port}],
              "outbounds": [vpn],
              "route": {"final": final, "default_domain_resolver": "remote"}}
    if warp:
        config["endpoints"] = [{"type": "wireguard", "tag": "warp", "system": False, "mtu": 1280,
                                "address": warp["addresses"], "private_key": warp["private_key"],
                                "detour": "vpn", "workers": 1,
                                "peers": [{"address": warp["endpoint_host"], "port": warp["endpoint_port"],
                                           "public_key": warp["peer_key"], "reserved": warp["reserved"],
                                           "allowed_ips": ["0.0.0.0/0", "::/0"]}]}]
    return config


async def bootstrap(node):
    # Only the physical VPN endpoint uses host DNS. All service/DNS/WARP traffic is proxied.
    node = deepcopy(node)
    try:
        import ipaddress
        ipaddress.ip_address(node.host)
        return node
    except ValueError:
        pass
    infos = await asyncio.get_running_loop().getaddrinfo(node.host, node.port, type=socket.SOCK_STREAM)
    address = next((a[4][0] for a in infos if a[0] == socket.AF_INET), infos[0][4][0])
    if node.core == "xray":
        node.outbound["settings"]["vnext"][0]["address"] = address
        stream = node.outbound.get("streamSettings", {})
        for key in ("tlsSettings", "realitySettings"):
            if key in stream:
                stream[key].setdefault("serverName", node.host)
    else:
        node.outbound["server"] = address
        node.outbound.setdefault("tls", {}).setdefault("server_name", node.host)
    return node


class CoreError(RuntimeError):
    pass


class CoreProcess:
    def __init__(self, executable, kind, config, port, timeout):
        self.executable, self.kind, self.config, self.port, self.timeout = executable, kind, config, port, timeout
        self.process = None
        self.temp = None

    async def __aenter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="proxytester-")
        path = Path(self.temp.name) / "config.json"
        atomic_json(path, self.config)
        args = [str(self.executable), "run", "-c", str(path)]
        check = [str(self.executable), "run", "-test", "-c", str(path)] if self.kind == "xray" else [str(self.executable), "check", "-c", str(path)]
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        try:
            proc = await asyncio.create_subprocess_exec(*check, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, **kwargs)
            try:
                code = await asyncio.wait_for(proc.wait(), self.timeout)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            if code:
                raise CoreError(f"{self.kind}: configuration rejected (exit {code}); check subscription options against pinned core")
            self.process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, **kwargs)
            if self.port is None:  # UDP-only integration servers have no TCP readiness listener.
                await asyncio.sleep(.25)
                if self.process.returncode is not None:
                    raise CoreError(f"{self.kind}: UDP process exited during startup")
                return self
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                if self.process.returncode is not None:
                    raise CoreError(f"{self.kind}: process exited before listener became ready")
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                    writer.close()
                    await writer.wait_closed()
                    return self
                except OSError:
                    await asyncio.sleep(.08)
            raise CoreError(f"{self.kind}: listener startup timeout")
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def __aexit__(self, *args):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 4)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.temp:
            self.temp.cleanup()


class Route:
    def __init__(self, directory, node, timeout):
        self.directory, self.node, self.timeout = directory, node, timeout
        self.xray_port = None

    @asynccontextmanager
    async def base(self):
        from contextlib import AsyncExitStack
        async with AsyncExitStack() as stack:
            self.node = await bootstrap(self.node)
            if self.node.core == "xray":
                self.xray_port = free_port()
                await stack.enter_async_context(CoreProcess(binary(self.directory, "xray"), "xray", xray_config(self.node, self.xray_port), self.xray_port, self.timeout))
            port = free_port()
            await stack.enter_async_context(CoreProcess(binary(self.directory, "sing-box"), "sing-box", sing_config(self.node, port, self.xray_port), port, self.timeout))
            yield f"http://127.0.0.1:{port}"

    @asynccontextmanager
    async def cascade(self, warp):
        port = free_port()
        async with CoreProcess(binary(self.directory, "sing-box"), "sing-box", sing_config(self.node, port, self.xray_port, warp), port, self.timeout):
            yield f"http://127.0.0.1:{port}"
