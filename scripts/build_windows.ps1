$ErrorActionPreference = "Stop"
python -m PyInstaller --noconfirm --clean scripts/windows.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Copy-Item -Recurse cores dist/ProxyTester/cores
Copy-Item README.md, LICENSE, THIRD_PARTY.md, config.example.json, Start.cmd dist/ProxyTester/
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD/dist/ProxyTester/browsers"
python -m playwright install chromium
if ($LASTEXITCODE -ne 0) { throw "Chromium installation failed" }
& dist/ProxyTester/ProxyTesterCLI.exe --version
if ($LASTEXITCODE -ne 0) { throw "Portable executable smoke test failed" }
python -c "import subprocess; r=subprocess.run(['dist/ProxyTester/ProxyTester.exe','--smoke-test'],timeout=30); raise SystemExit(r.returncode)"
if ($LASTEXITCODE -ne 0) { throw "Portable GUI smoke test failed" }
Compress-Archive -Path dist/ProxyTester -DestinationPath dist/ProxyTester-windows-x64.zip -Force
Get-FileHash dist/ProxyTester-windows-x64.zip -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  ProxyTester-windows-x64.zip" } | Set-Content dist/SHA256SUMS.txt
