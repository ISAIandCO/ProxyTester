$ErrorActionPreference = "Stop"
python -m PyInstaller --noconfirm --clean --onedir --console --name ProxyTester --collect-all playwright --collect-data proxytester scripts/entry.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Copy-Item -Recurse cores dist/ProxyTester/cores
Copy-Item README.md, LICENSE, THIRD_PARTY.md, config.example.json, Start.cmd dist/ProxyTester/
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/dist/ProxyTester/browsers"
python -m playwright install chromium
if ($LASTEXITCODE -ne 0) { throw "Chromium installation failed" }
& dist/ProxyTester/ProxyTester.exe --version
if ($LASTEXITCODE -ne 0) { throw "Portable executable smoke test failed" }
Compress-Archive -Path dist/ProxyTester -DestinationPath dist/ProxyTester-windows-x64.zip -Force
Get-FileHash dist/ProxyTester-windows-x64.zip -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  ProxyTester-windows-x64.zip" } | Set-Content dist/SHA256SUMS.txt
