# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.110", "uvicorn>=0.29"]
# ///
"""Baseline `regex`: the regex rules from eval/mock_airlock.py, with no simulated LLM and no gate.

    uv run eval/baselines/regex_only.py --port 8802

Rules: e-mail, dashed Korean mobile, `(NNN) NNN-NNNN`, dashed RRN and SSN, dashed 16-digit card,
`xx_live_...` keys, `password: ...`, and any 7+ digit number. Unlike the mock, this baseline also
masks tool-call arguments and matches declared terms case-insensitively (see common.py), so it
measures what regular expressions alone catch rather than the mock's deliberate plumbing holes.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parent))
from common import Span, create_app, serve  # noqa: E402
from mock_airlock import REGEX_RULES  # noqa: E402

DESCRIPTION = "regex rules from eval/mock_airlock.py, no LLM, no gate"


class RegexDetector:
    name = "regex"

    def detect(self, text: str, lang: str) -> list[Span]:
        return [
            Span(m.start(), m.end(), type_, "regex")
            for type_, pattern in REGEX_RULES
            for m in pattern.finditer(text)
        ]


def build():
    return create_app("regex", RegexDetector(), description=DESCRIPTION)


if __name__ == "__main__":
    serve(build, 8802, __doc__)
