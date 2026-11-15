import sys
from proxytester.gui import launch

if "--smoke-test" in sys.argv:
    raise SystemExit(launch(smoke_test=True))
raise SystemExit(launch())
