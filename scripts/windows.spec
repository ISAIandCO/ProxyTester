from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_data_files

repo = Path(SPECPATH).parent
datas, binaries, hidden = collect_all("playwright")
datas += collect_data_files("proxytester")
a = Analysis([str(repo / "scripts/entry.py"), str(repo / "scripts/entry_cli.py")],
             pathex=[str(repo)], binaries=binaries, datas=datas, hiddenimports=hidden)
pyz = PYZ(a.pure)
# Both entry points share one Python/runtime directory; only the bootloaders differ.
gui_scripts = [item for item in a.scripts if item[0] != "entry_cli"]
cli_scripts = [item for item in a.scripts if item[0] != "entry"]
assert any(item[0] == "entry" for item in gui_scripts)
assert any(item[0] == "entry_cli" for item in cli_scripts)
gui = EXE(pyz, gui_scripts, [], exclude_binaries=True, name="ProxyTester", console=False)
cli = EXE(pyz, cli_scripts, [], exclude_binaries=True, name="ProxyTesterCLI", console=True)
COLLECT(gui, cli, a.binaries, a.datas, name="ProxyTester")
