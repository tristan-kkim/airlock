# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.110", "uvicorn>=0.29"]
# ///
"""Baseline `raw`: pass-through. Records the request exactly as a client would send it upstream.

    uv run eval/baselines/raw.py --port 8801

The upper bound for every leak metric. Declared vault terms are accepted and ignored.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import create_app, serve  # noqa: E402

DESCRIPTION = "pass-through, no masking (upper bound)"


def build():
    return create_app("raw", None, honor_vault_terms=False, description=DESCRIPTION)


if __name__ == "__main__":
    serve(build, 8801, __doc__)
