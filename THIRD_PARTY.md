# Bundled components

ProxyTester source is MIT (LICENSE). The portable distribution contains separate
upstream components; their original licenses continue to apply.

| Component | Pinned version | License / source |
|---|---|---|
| Xray-core | 26.11.9 | MPL-2.0 · https://github.com/XTLS/Xray-core/tree/v26.11.9 |
| sing-box | 1.14.4 | GPL-3.0 · https://github.com/SagerNet/sing-box/tree/v1.14.4 |
| Python | 3.12 | PSF · https://www.python.org/downloads/ |
| HTTPX | 0.28.1 | BSD-3-Clause · https://github.com/encode/httpx |
| cryptography | 50.0.0 | Apache-2.0 / BSD · https://github.com/pyca/cryptography |
| PyYAML | 6.0.3 | MIT · https://github.com/yaml/pyyaml |
| Playwright | 1.62.0 | Apache-2.0 · https://github.com/microsoft/playwright-python |
| Chromium | Playwright revision 1234 | BSD and third-party licenses included in browser distribution |
| PyInstaller bootloader | 6.17.0 | GPL with bootloader exception · https://github.com/pyinstaller/pyinstaller |

The exact upstream core archives and SHA-256 hashes are in
`proxytester/cores.lock.json`. Unmodified corresponding source is available at
the pinned tag URLs above. Preserve these notices and upstream license files
when redistributing. Core executable receipts identify the downloaded versions.

The WARP registration schema was checked against Throne's public implementation
(`core/internal/warp/api.go` and `register.go`, https://github.com/throneproj/Throne)
and independently implemented in Python. No Throne source is bundled.
