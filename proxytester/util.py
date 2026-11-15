"""Small shared helpers. Public results never contain core configs or response bodies."""
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def atomic_json(path, value, private=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with open(temp, "w", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)
    if private:
        path.chmod(0o600)


def identifier(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]


def public_url(value):
    try:
        p = urlsplit(str(value))
        return urlunsplit((p.scheme, p.hostname or "", p.path, "", ""))
    except ValueError:
        return "[invalid URL]"


def safe_name(value):
    value = re.sub(r"[\x00-\x1f\x7f]", "", str(value))[:160]
    value = re.sub(r"(?:vless|hy2|hysteria2)://\S+", "[proxy]", value, flags=re.I)
    value = re.sub(r"https?://\S+", "[URL]", value)
    value = re.sub(r"[A-Za-z0-9_+/=-]{40,}", "[redacted]", value)
    return value


def error_kind(exc):
    # Exception strings can include credentials, URL queries, or response payloads.
    name = type(exc).__name__
    lower = (name + " " + str(exc)).lower()
    if "timeout" in lower:
        return "timeout"
    if "executable doesn't exist" in lower:
        return "browser_missing (run setup)"
    if "proxy_connection" in lower or "tunnel_connection" in lower:
        return "proxy_connection_failed"
    if "certificate" in lower or "ssl" in lower or "tls" in lower or "err_cert" in lower:
        return "tls_error"
    if "name resolution" in lower or "getaddrinfo" in lower or "dns" in lower or "name_not_resolved" in lower:
        return "dns_error"
    return safe_name(name)


def web_url(value):
    p = urlsplit(value)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password:
        raise ValueError("Expected HTTP(S) URL without embedded credentials")
    return value
