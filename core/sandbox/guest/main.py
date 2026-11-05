"""Entry point inside the sandbox. `python -I` drops the script folder from sys.path, so add it."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import worker  # noqa: E402

raise SystemExit(worker.main())
