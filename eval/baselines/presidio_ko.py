# /// script
# requires-python = ">=3.11,<3.13"
# dependencies = [
#   "fastapi>=0.110",
#   "uvicorn>=0.29",
#   "presidio-analyzer==2.2.364",
#   "presidio-anonymizer==2.2.364",
#   "spacy>=3.8,<3.9",
#   "ko_core_news_sm @ https://github.com/explosion/spacy-models/releases/download/ko_core_news_sm-3.8.0/ko_core_news_sm-3.8.0-py3-none-any.whl",
#   "en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl",
# ]
# ///
"""Baseline `presidio_ko`: Microsoft Presidio analyzer + anonymizer, Korean and English pipelines.

    uv run eval/baselines/presidio_ko.py --port 8803

Each text is split into runs of lines by script (common.language_segments): lines with Hangul go
to the Korean analyzer, the rest to the English analyzer. The configuration is deliberately
generous, and fully listed here so a low score cannot be blamed on a hidden setting:

Korean (`ko_core_news_sm`, KLUE labels PS/LC/OG/DT mapped to PERSON/LOCATION/ORGANIZATION/
DATE_TIME, no low-confidence penalty), per nebius/LANDSCAPE.md:
  KrRrn, KrPassport, KrDriverLicense, KrBrn, KrFrn (shipped disabled by default in Presidio),
  Email, Phone (regions KR and US), plus the language-independent pattern recognizers CreditCard,
  IbanCode, IpRecognizer, Crypto, UsSsn and Url, and the spaCy NER recognizer.
English (`en_core_web_sm`): Presidio's full predefined English registry, with the spaCy NER
  recognizer extended to ORGANIZATION (Presidio's default leaves organizations out).
Anonymizer: Presidio's default `replace` operator (`<ENTITY_TYPE>`), score threshold 0 (every
  result is anonymized, which maximizes recall). Declared vault terms are added as results with
  score 1.0 before anonymization.

Environment: PRESIDIO_KO_MODEL / PRESIDIO_EN_MODEL override the spaCy model names (for example
`ko_core_news_lg` / `en_core_web_lg`; install those wheels into the environment yourself). The
small models are the default because the large wheels could not be downloaded in reasonable time
when the published runs were made.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Span, create_app, serve  # noqa: E402

DESCRIPTION = "Presidio 2.2.364 analyzer+anonymizer, spaCy ko/en NER, Korean ID recognizers"
NER_ENTITIES = ["PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME", "NRP"]


def build_analyzers(ko_model: str, en_model: str):
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_analyzer.predefined_recognizers import (
        CreditCardRecognizer,
        CryptoRecognizer,
        EmailRecognizer,
        IbanRecognizer,
        IpRecognizer,
        KrBrnRecognizer,
        KrDriverLicenseRecognizer,
        KrFrnRecognizer,
        KrPassportRecognizer,
        KrRrnRecognizer,
        PhoneRecognizer,
        SpacyRecognizer,
        UrlRecognizer,
        UsSsnRecognizer,
    )

    ko_conf = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "ko", "model_name": ko_model}],
        "ner_model_configuration": {
            "model_to_presidio_entity_mapping": {
                "PS": "PERSON",
                "LC": "LOCATION",
                "OG": "ORGANIZATION",
                "DT": "DATE_TIME",
            },
            "low_confidence_score_multiplier": 1.0,
            "low_score_entity_names": [],
            "labels_to_ignore": ["QT", "TI"],
        },
    }
    ko_nlp = NlpEngineProvider(nlp_configuration=ko_conf).create_engine()
    ko_reg = RecognizerRegistry(supported_languages=["ko"])
    for cls in (
        KrRrnRecognizer,
        KrPassportRecognizer,
        KrDriverLicenseRecognizer,
        KrBrnRecognizer,
        KrFrnRecognizer,
        EmailRecognizer,
        CreditCardRecognizer,
        IbanRecognizer,
        IpRecognizer,
        CryptoRecognizer,
        UsSsnRecognizer,
        UrlRecognizer,
    ):
        ko_reg.add_recognizer(cls(supported_language="ko"))
    ko_reg.add_recognizer(PhoneRecognizer(supported_language="ko", supported_regions=["KR", "US"]))
    ko_reg.add_recognizer(SpacyRecognizer(supported_language="ko", supported_entities=NER_ENTITIES))
    ko = AnalyzerEngine(nlp_engine=ko_nlp, registry=ko_reg, supported_languages=["ko"])

    en_conf = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": en_model}],
        "ner_model_configuration": {
            "model_to_presidio_entity_mapping": {
                "PER": "PERSON",
                "PERSON": "PERSON",
                "NORP": "NRP",
                "FAC": "LOCATION",
                "LOC": "LOCATION",
                "GPE": "LOCATION",
                "LOCATION": "LOCATION",
                "ORG": "ORGANIZATION",
                "ORGANIZATION": "ORGANIZATION",
                "DATE": "DATE_TIME",
                "TIME": "DATE_TIME",
            },
            "low_confidence_score_multiplier": 1.0,
            "low_score_entity_names": [],
        },
    }
    en_nlp = NlpEngineProvider(nlp_configuration=en_conf).create_engine()
    en_reg = RecognizerRegistry(supported_languages=["en"])
    en_reg.load_predefined_recognizers(languages=["en"], nlp_engine=en_nlp)
    en_reg.remove_recognizer("SpacyRecognizer")
    en_reg.add_recognizer(SpacyRecognizer(supported_language="en", supported_entities=NER_ENTITIES))
    en = AnalyzerEngine(nlp_engine=en_nlp, registry=en_reg, supported_languages=["en"])
    return {"ko": ko, "en": en}


class PresidioDetector:
    name = "presidio_ko"

    def __init__(self, ko_model: str, en_model: str):
        from presidio_anonymizer import AnonymizerEngine

        self.analyzers = build_analyzers(ko_model, en_model)
        self.anonymizer = AnonymizerEngine()
        self.models = {"ko": ko_model, "en": en_model}

    def detect(self, text: str, lang: str) -> list[Span]:
        results = self.analyzers[lang].analyze(text=text, language=lang)
        return [
            Span(r.start, r.end, r.entity_type, f"presidio:{lang}", float(r.score)) for r in results
        ]

    def anonymize(self, text: str, spans: list[Span]) -> str:
        from presidio_analyzer import RecognizerResult

        results = [RecognizerResult(s.type, s.start, s.end, s.score or 1.0) for s in spans]
        return self.anonymizer.anonymize(text=text, analyzer_results=results).text


def build():
    ko_model = os.environ.get("PRESIDIO_KO_MODEL", "ko_core_news_sm")
    en_model = os.environ.get("PRESIDIO_EN_MODEL", "en_core_web_sm")
    detector = PresidioDetector(ko_model, en_model)
    import presidio_analyzer

    info = {
        "presidio_analyzer": getattr(presidio_analyzer, "__version__", "2.2.364"),
        "spacy_models": detector.models,
    }
    return create_app("presidio_ko", detector, description=DESCRIPTION, info=info)


if __name__ == "__main__":
    serve(build, 8803, __doc__)
