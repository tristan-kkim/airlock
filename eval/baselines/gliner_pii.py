# /// script
# requires-python = ">=3.11,<3.13"
# dependencies = [
#   "fastapi>=0.110",
#   "uvicorn>=0.29",
#   "gliner>=0.2.16",
#   "torch>=2.4",
# ]
# ///
"""Baseline `gliner_pii`: NVIDIA GLiNER-PII (`nvidia/gliner-PII`, 570M span NER) alone.

    uv run eval/baselines/gliner_pii.py --port 8804

This is the PII backend NeMo Guardrails documents. It was trained on English-only data
(nvidia/Nemotron-PII); we run it unchanged on the Korean cases and report what happens.

Configuration:
* threshold 0.3 (the value used for the model card's evaluation), flat NER
* the model was trained with at most 25 entity types per prompt, so the 50 labels below are sent
  in two groups of 25 and the results are merged
* long texts are split into overlapping windows of at most 120 whitespace words / 600 characters
  (the model's max_len is 384 words including the label prompt, and DeBERTa has 512 positions)
* no language routing: every segment goes to the same model
* labels left out on purpose because they would mask what the answer needs: country, language,
  time, date_time, date, education_level, url

Environment: GLINER_PII_MODEL (default `nvidia/gliner-PII`; a local directory also works),
GLINER_PII_DEVICE (default: mps if available, else cpu), GLINER_PII_THRESHOLD (default 0.3).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Span, create_app, serve  # noqa: E402

DESCRIPTION = "nvidia/gliner-PII span NER, threshold 0.3, 50 labels in two groups of 25"
LABEL_GROUPS = [
    [
        "first_name", "last_name", "company_name", "email", "phone_number", "fax_number",
        "street_address", "city", "county", "state", "postcode", "coordinate", "date_of_birth",
        "age", "gender", "race_ethnicity", "religious_belief", "political_view", "sexuality",
        "occupation", "employment_status", "user_name", "customer_id", "employee_id",
        "license_plate",
    ],
    [
        "ssn", "tax_id", "credit_debit_card", "cvv", "account_number", "bank_routing_number",
        "swift_bic", "pin", "password", "api_key", "http_cookie", "medical_record_number",
        "health_plan_beneficiary_number", "certificate_license_number", "blood_type",
        "biometric_identifier", "device_identifier", "vehicle_identifier", "unique_id",
        "ipv4", "ipv6", "mac_address", "national_id", "passport_number", "bank_account",
    ],
]  # fmt: skip
MAX_WORDS = 120
MAX_CHARS = 600
_WORD = re.compile(r"\S+")


def windows(text: str, max_words: int = MAX_WORDS, max_chars: int = MAX_CHARS):
    """Yield (offset, chunk) windows over text with ~25% word overlap; offsets are exact."""
    words = [(m.start(), m.end()) for m in _WORD.finditer(text)]
    if not words:
        return
    i = 0
    while i < len(words):
        j = i
        while (
            j < len(words)
            and j - i < max_words
            and (j == i or words[j][1] - words[i][0] <= max_chars)
        ):
            j += 1
        start, end = words[i][0], words[j - 1][1]
        yield start, text[start:end]
        if j >= len(words):
            break
        i = max(i + 1, j - max(1, (j - i) // 4))


class GlinerDetector:
    name = "gliner_pii"

    def __init__(self, model_id: str, device: str | None, threshold: float):
        import torch
        from gliner import GLiNER

        if not device:
            device = "mps" if torch.backends.mps.is_available() else "cpu"
        self.model = GLiNER.from_pretrained(model_id)
        self.model.to(device)
        self.model.eval()
        self.device = device
        self.model_id = model_id
        self.threshold = threshold

    def detect(self, text: str, lang: str) -> list[Span]:
        spans: list[Span] = []
        for offset, chunk in windows(text):
            for labels in LABEL_GROUPS:
                for e in self.model.predict_entities(
                    chunk, labels, threshold=self.threshold, flat_ner=True
                ):
                    spans.append(
                        Span(
                            offset + e["start"],
                            offset + e["end"],
                            e["label"].upper(),
                            "gliner",
                            float(e["score"]),
                        )
                    )
        return spans


def build():
    model_id = os.environ.get("GLINER_PII_MODEL", "nvidia/gliner-PII")
    threshold = float(os.environ.get("GLINER_PII_THRESHOLD", "0.3"))
    detector = GlinerDetector(model_id, os.environ.get("GLINER_PII_DEVICE"), threshold)
    info = {
        "model": "nvidia/gliner-PII",
        "model_path_is_local": Path(model_id).is_dir(),
        "device": detector.device,
        "threshold": threshold,
    }
    return create_app("gliner_pii", detector, description=DESCRIPTION, info=info)


if __name__ == "__main__":
    serve(build, 8804, __doc__)
