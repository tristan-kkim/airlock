"""NVIDIA GLiNER-PII as a second local span proposer, merged by an ensemble policy.

On the 243-case eval, `nvidia/gliner-PII` alone leaked far less than regex or Presidio, but it
masked most benign prompts and mislabeled Korean text (an age written as `마흔다섯` became
PASSWORD, a company RELIGIOUS_BELIEF). Airlock uses it for recall and keeps precision with three
steps, applied only to GLiNER's spans:

1. Agreement. A GLiNER span that overlaps a span from another source (regex, entropy, vault,
   rules, Nano) is accepted. If it lies entirely inside that span it adds nothing and is only
   counted.
2. Type consistency. A GLiNER-only span must look like its type: SECRET needs the entropy or a
   password/key pattern, phone/ID/account labels need a digit or code shape, PERSON needs a
   name shape (a common surname plus 3-4 Hangul syllables by default, or capitalized Latin
   words), and age-, date- or money-like text under any other label is dropped as a mislabel.
   Labels in AIRLOCK_GLINER_AGREEMENT_ONLY (default: city, date_of_birth) stop here.
3. Local adjudication. Survivors go to Nemotron-3-Nano-4B in one batched call per request: "is
   each span private to the user in this context?", JSON schema, temperature 0, thinking off.
   Only "yes" is accepted.

Everything runs on this machine. The model is optional (`uv sync --extra gliner`) and off by
default (`AIRLOCK_GLINER=on`). When it is on but the package or weights are missing, Airlock
refuses to start (`GlinerUnavailable`) instead of failing per request; `airlock doctor` reports
the same check.
"""

from __future__ import annotations

import asyncio
import importlib.util
import re
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.config import Settings
from airlock.detect.ko_rules import (
    _COMPOUND_SURNAMES,
    _NAME_STOPWORDS,
    _PUBLIC_FIGURES,
    _SURNAMES,
)
from airlock.detect.ko_rules import (
    _TITLE_WORDS as _TITLE_STEMS,
)
from airlock.detect.llm import LocalModel, LocalModelMalformed, load_prompt
from airlock.detect.patterns import _looks_like_secret, _password_like, detect_patterns
from airlock.detect.spans import (
    MIN_SPAN_CHARS,
    Placement,
    Span,
    contains_placeholder,
    locate,
    normalize,
)
from airlock.textnorm import digit_runs


class GlinerUnavailable(RuntimeError):
    """GLiNER is enabled but its package or weights are missing. Raised at startup."""


# ---- labels -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Label:
    name: str  # GLiNER-PII label (Nemotron-PII taxonomy)
    type: str  # Airlock span type
    shape: str  # type-consistency check applied to GLiNER-only spans
    threshold: float | None = None  # None: AIRLOCK_GLINER_THRESHOLD


# Left out on purpose: labels whose spans the answer usually needs or that GLiNER mislabels most
# in Korean (age, gender, occupation, employment_status, education_level, race_ethnicity,
# religious_belief, political_view, sexuality, blood_type, country, state, county, language,
# date, time, date_time, url, ipv4, ipv6, coordinate). Airlock's rules and Nano cover
# quasi-identifiers with generalization instead of masks.
LABELS: tuple[Label, ...] = (
    Label("first_name", "PERSON", "name"),
    Label("last_name", "PERSON", "name"),
    Label("user_name", "CONTACT", "handle"),
    Label("company_name", "ORG", "org"),
    Label("email", "CONTACT", "email"),
    Label("phone_number", "CONTACT", "phone"),
    Label("fax_number", "CONTACT", "phone"),
    Label("street_address", "LOCATION", "address"),
    Label("city", "LOCATION", "place"),
    Label("postcode", "LOCATION", "postcode"),
    Label("date_of_birth", "QUASI_IDENTIFIER", "birthdate"),
    Label("ssn", "ID_NUMBER", "id"),
    Label("tax_id", "ID_NUMBER", "id"),
    Label("national_id", "ID_NUMBER", "id"),
    Label("passport_number", "ID_NUMBER", "id"),
    Label("customer_id", "ID_NUMBER", "id"),
    Label("employee_id", "ID_NUMBER", "id"),
    Label("medical_record_number", "ID_NUMBER", "id"),
    Label("health_plan_beneficiary_number", "ID_NUMBER", "id"),
    Label("certificate_license_number", "ID_NUMBER", "id"),
    Label("license_plate", "ID_NUMBER", "id"),
    Label("vehicle_identifier", "ID_NUMBER", "id"),
    Label("device_identifier", "ID_NUMBER", "id"),
    Label("unique_id", "ID_NUMBER", "id"),
    Label("mac_address", "ID_NUMBER", "id"),
    Label("credit_debit_card", "FINANCIAL", "account"),
    Label("account_number", "FINANCIAL", "account"),
    Label("bank_routing_number", "FINANCIAL", "account"),
    Label("swift_bic", "FINANCIAL", "swift"),
    Label("cvv", "SECRET", "pin"),
    Label("pin", "SECRET", "pin"),
    Label("password", "SECRET", "secret"),
    Label("api_key", "SECRET", "secret"),
    Label("http_cookie", "SECRET", "secret"),
)
LABELS_BY_NAME = {label.name: label for label in LABELS}
# GLiNER-PII was trained with at most 25 entity types per prompt.
MAX_LABELS_PER_PROMPT = 25
MAX_WORDS = 120
MAX_CHARS = 600
_WORD = re.compile(r"\S+")


def label_groups(labels: Sequence[Label] = LABELS) -> list[list[str]]:
    names = [label.name for label in labels]
    return [
        names[i : i + MAX_LABELS_PER_PROMPT] for i in range(0, len(names), MAX_LABELS_PER_PROMPT)
    ]


def windows(text: str, max_words: int = MAX_WORDS, max_chars: int = MAX_CHARS):
    """(offset, chunk) windows with ~25% word overlap; the model reads at most 384 words."""
    words = [(m.start(), m.end()) for m in _WORD.finditer(text)]
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


def parse_thresholds(raw: str | None) -> dict[str, float]:
    """`first_name=0.6,password=0.8` -> per-label overrides. Unknown labels are an error."""
    out: dict[str, float] = {}
    for item in (raw or "").split(","):
        if not item.strip():
            continue
        name, _, value = item.partition("=")
        name = name.strip()
        if name not in LABELS_BY_NAME:
            raise ValueError(f"AIRLOCK_GLINER_THRESHOLDS: unknown label {name!r}")
        out[name] = float(value)
    return out


def parse_labels(raw: str | None) -> frozenset[str]:
    names = frozenset(n.strip() for n in (raw or "").split(",") if n.strip())
    unknown = sorted(names - LABELS_BY_NAME.keys())
    if unknown:
        raise ValueError(f"AIRLOCK_GLINER_AGREEMENT_ONLY: unknown labels {unknown}")
    return names


# ---- model --------------------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Entity:
    start: int
    end: int
    label: str
    score: float


def availability_problem(settings: Settings) -> str | None:
    """Why GLiNER cannot run with these settings, or None. Cheap: nothing is loaded."""
    for package in ("gliner", "torch"):
        if importlib.util.find_spec(package) is None:
            return f"python package {package!r} not installed (uv sync --extra gliner)"
    path = Path(settings.gliner_model).expanduser()
    if path.is_dir():
        if not (path / "gliner_config.json").is_file():
            return f"{path}: gliner_config.json missing"
        if not any((path / name).is_file() for name in ("pytorch_model.bin", "model.safetensors")):
            return f"{path}: model weights missing"
        return None
    # A Hub id must already be in the local cache: Airlock never downloads at request time.
    try:
        from huggingface_hub import try_to_load_from_cache
    except ImportError:
        return "huggingface_hub not installed"
    for name in ("gliner_config.json",):
        hit = try_to_load_from_cache(settings.gliner_model, name)
        if not isinstance(hit, str):
            return f"{settings.gliner_model}: not a local directory and not in the Hub cache"
    return None


def pick_device(requested: str) -> str:
    if requested and requested != "auto":
        return requested
    import torch

    # M3 Pro, 2 label prompts per text. Alone, mps is faster (30 eval texts: p50 324 ms vs cpu
    # 456 ms). Inside Airlock, GLiNER runs while Nano decodes on Metal, and cpu wins (61 dev
    # requests: mps p50 1165 / p95 1752 ms, cpu p50 467 / p95 649 ms). The default is cpu.
    return "mps" if torch.backends.mps.is_available() else "cpu"


class GlinerModel:
    """Lazy, thread-safe wrapper around `gliner.GLiNER`. Loads once on first use."""

    def __init__(self, settings: Settings, loader: Callable[[], Any] | None = None):
        self.settings = settings
        self.overrides = parse_thresholds(settings.gliner_thresholds)
        self._loader = loader
        self._model: Any = None
        self._lock = threading.Lock()
        self.device: str | None = None
        self.load_s: float | None = None

    def threshold(self, label: str) -> float:
        spec = LABELS_BY_NAME[label]
        if label in self.overrides:
            return self.overrides[label]
        return spec.threshold if spec.threshold is not None else self.settings.gliner_threshold

    def _load(self) -> Any:
        if self._model is None:
            started = time.perf_counter()
            if self._loader is not None:
                self._model = self._loader()
            else:
                from gliner import GLiNER

                self.device = pick_device(self.settings.gliner_device)
                model = GLiNER.from_pretrained(
                    str(Path(self.settings.gliner_model).expanduser()), local_files_only=True
                )
                model.to(self.device)
                model.eval()
                self._model = model
            self.load_s = time.perf_counter() - started
        return self._model

    def predict(self, texts: Sequence[str]) -> list[list[Entity]]:
        """Entities per text, above each label's threshold, with offsets into that text."""
        chunks: list[tuple[int, int, str]] = [
            (i, offset, chunk) for i, text in enumerate(texts) for offset, chunk in windows(text)
        ]
        out: list[dict[tuple[int, int, str], float]] = [{} for _ in texts]
        if not chunks:
            return [[] for _ in texts]
        floor = min(self.threshold(label.name) for label in LABELS)
        with self._lock:
            model = self._load()
            for labels in label_groups():
                results = model.inference(
                    [c[2] for c in chunks], labels, flat_ner=True, threshold=floor, batch_size=8
                )
                for (i, offset, _), entities in zip(chunks, results, strict=True):
                    for e in entities:
                        label = e["label"]
                        score = float(e["score"])
                        if label not in LABELS_BY_NAME or score < self.threshold(label):
                            continue
                        key = (offset + e["start"], offset + e["end"], label)
                        out[i][key] = max(score, out[i].get(key, 0.0))
        return [
            sorted(Entity(s, e, label, score) for (s, e, label), score in found.items())
            for found in out
        ]


# ---- type consistency ---------------------------------------------------------------------------

_HANGUL = re.compile(r"[가-힣]")
_KO_TENS = r"(?:스물|서른|마흔|쉰|예순|일흔|여든|아흔)"
_KO_NUM_AGE = _KO_TENS + r"(?:한|하나|두|둘|세|셋|네|넷|다섯|여섯|일곱|여덟|아홉)?"
_AGE = re.compile(
    rf"^(?:만\s*)?(?:\d{{1,3}}\s*(?:세|살)|{_KO_NUM_AGE}(?:\s*살)?)"
    r"(?:이야|이에요|입니다|이고|이며|인데|이|가|은|는|을|를|의|야|다|에)?$"
    r"|^(?:age[ds]?\s*|turn(?:ed|ing|s)?\s+)?\d{1,3}(?:\s*(?:-?\s*years?(?:\s*|-)old|y/?o|yrs?))?$",
    re.IGNORECASE,
)
_MONTHS = (
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)
_DATE = re.compile(
    r"^\d{4}\s*(?:[-./]|년)\s*\d{1,2}\s*(?:[-./]|월)?\s*(?:\d{1,2}\s*일?)?$"
    r"|^\d{1,2}[-./]\d{1,2}[-./]\d{2,4}$"
    r"|^\d{1,2}\s*월(?:\s*\d{1,2}\s*일)?$"
    r"|^(?:19|20)\d{2}\s*년?$"
    rf"|^(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?(?:\s+\d{{4}})?$"
    rf"|^\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:{_MONTHS})\.?,?(?:\s+\d{{4}})?$",
    re.IGNORECASE,
)
_MONEY = re.compile(
    r"^[$€£₩¥]\s*[\d,.]+\s*[kKmMbB]?$|^[\d,.]+\s*(?:만\s*원|억\s*원?|천\s*원|원|달러|dollars?|"
    r"usd|krw|eur|won)$",
    re.IGNORECASE,
)
_SWIFT = re.compile(r"^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$")
_LATIN_NAME_TOKEN = re.compile(r"^[A-Z][a-zA-Z'’\-]*[a-z][a-zA-Z'’\-]*\.?$|^[A-Z]\.$")
_KO_COPULA = (
    r"입니다|이에요|예요|이라고|이라는|라고|이고|이며|이야|인데|이다|이라|에서는|에게는|에서|에게"
)
_KO_NAME_TAIL = re.compile(
    rf"(?:{_KO_COPULA}|님|씨|께서는|께서|에게서|한테|이랑|랑|은|는|을|를|의|과|와|도|만|께)$"
)
# Particles stripped from other Hangul spans ("도담하늘병원에서"). No 과/와/도: 내과, 새론도.
_KO_TAIL = re.compile(rf"(?:{_KO_COPULA}|께서|한테|은|는|을|를|의)$")
# A Latin/digit value with a Korean particle attached by the tokenizer ("F8YAXXGS이고").
_LATIN_WITH_KO_TAIL = re.compile(r"(?<=[A-Za-z0-9])[가-힣]{1,4}$")
# Opaque codes: order/ticket/record numbers, base64 or random tokens ("AC-8NMD61YGVM").
_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-+/=.]{7,}$|^[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})+$")
_ADDRESS_KO = re.compile(r"(?:로|길|동|읍|면|리|번지|아파트|빌라|호|층|가)(?:\s|\d|$)")
_HANDLE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._\-]{2,39}$")
_COMPOUND = tuple(_COMPOUND_SURNAMES.split("|"))


def _digit_count(text: str) -> int:
    plain = sum(ch.isdigit() for ch in text)
    if plain:
        return plain
    # Digits spelled out (공일공 구일일, zero one zero): only runs of 6+ count.
    return max((len(r.digits) for r in digit_runs(text)), default=0)


def _digit_shape(text: str, min_digits: int, min_ratio: float = 0.3) -> bool:
    n = _digit_count(text)
    if n < min_digits:
        return False
    compact = [ch for ch in text if ch.isalnum()]
    plain = sum(ch.isdigit() for ch in text)
    return plain == 0 or plain / max(1, len(compact)) >= min_ratio


def ko_name(text: str, min_syllables: int = 2) -> str | None:
    """The Korean name inside `text` (particles and honorifics stripped), or None."""
    name = text.strip()
    for _ in range(2):
        stripped = _KO_NAME_TAIL.sub("", name)
        removed = name[len(stripped) :]
        if stripped != name and (stripped in _NAME_STOPWORDS or stripped in _PUBLIC_FIGURES):
            return None  # "이장이" is 이장 + 이, not a name
        # 정다은 ends in 은: a one-syllable particle only goes when a 3+ syllable name remains.
        if len(stripped) >= 3 or (len(stripped) == 2 and (len(removed) >= 2 or removed in "님씨")):
            name = stripped
    if not re.fullmatch(r"[가-힣]{2,4}", name) or len(name) < min_syllables:
        return None
    if not (name.startswith(_COMPOUND) or name[0] in _SURNAMES):
        return None
    if name in _NAME_STOPWORDS or name in _PUBLIC_FIGURES:
        return None
    if name[-1] in "이가은는을를의과와도만" and (
        name[:-1] in _NAME_STOPWORDS or name[:-1] in _TITLE_STEMS
    ):
        return None  # "이장이", "사장님" + particle: a title with a particle, not a name
    return name


def latin_name(text: str) -> bool:
    tokens = text.split()
    return 1 <= len(tokens) <= 4 and all(_LATIN_NAME_TOKEN.match(t) for t in tokens)


def code_token(text: str) -> bool:
    return (
        bool(_CODE.match(text))
        and bool(re.search(r"\d", text))
        and bool(re.search(r"[A-Za-z]", text))
        and len(text) >= 6
    )


def mislabel(text: str, label: Label) -> bool:
    """Age-, date- or money-like text under a label that cannot hold it."""
    t = text.strip()
    if label.shape == "pin" and t.isdigit():
        return False  # a CVV or PIN is a short number by definition
    if _AGE.match(t) or _MONEY.match(t):
        return True
    return label.shape != "birthdate" and bool(_DATE.match(t))


def shape_ok(text: str, label: Label, ko_min_syllables: int = 2) -> bool:
    t = text.strip()
    shape = label.shape
    if shape == "name":
        if _HANGUL.search(t):
            return ko_name(t, ko_min_syllables) is not None
        return latin_name(t)
    if shape == "secret":
        if _HANGUL.search(t) or len(t) < 6:
            return False
        return bool(_looks_like_secret(t) or detect_patterns(t) or _password_like(t))
    if shape == "pin":
        return bool(re.fullmatch(r"\d{3,8}", t)) or _digit_shape(t, 6, 0.5) or code_token(t)
    if shape == "phone":
        return _digit_shape(t, 7, 0.5)
    if shape == "account":
        return _digit_shape(t, 6, 0.5) or code_token(t)
    if shape == "id":
        return (_digit_shape(t, 3) and len(t) >= 4) or code_token(t)
    if shape == "swift":
        return bool(_SWIFT.match(t))
    if shape == "email":
        return "@" in t and " " not in t
    if shape == "handle":
        return bool(_HANDLE.match(t)) and bool(re.search(r"[A-Za-z]", t))
    if shape == "postcode":
        return _digit_shape(t, 4, 0.5) and len(t) <= 10
    if shape == "birthdate":
        return _digit_count(t) >= 2 or bool(re.search(r"[년월일]", t))
    if shape == "address":
        return bool(re.search(r"\d", t) or _ADDRESS_KO.search(t))
    if shape == "place":
        return not re.search(r"\d", t) and (bool(_HANGUL.search(t)) or t[:1].isupper())
    if shape == "org":
        return bool(_HANGUL.search(t)) or any(ch.isupper() for ch in t)
    return False


def remap_person(text: str, label: Label, ko_min_syllables: int = 2) -> bool:
    """A name under a label whose shape it fails (`독고새론` as password): treat it as PERSON."""
    t = text.strip()
    return ko_name(t, ko_min_syllables) is not None or (label.shape == "handle" and latin_name(t))


def trim(text: str, start: int, end: int, label: Label) -> tuple[int, int]:
    """Drop Korean particles, honorifics and copulas the span picked up from its word."""
    raw = text[start:end]
    if not _HANGUL.search(raw):
        return start, end
    if label.type == "PERSON" or ko_name(raw):
        name = ko_name(raw)
        if name and raw.startswith(name):
            return start, start + len(name)
    if m := _LATIN_WITH_KO_TAIL.search(raw):
        return start, start + m.start()
    for _ in range(2):
        stripped = _KO_TAIL.sub("", raw)
        if len(stripped) < 2 or stripped == raw:
            break
        raw = stripped
    return start, start + len(raw)


# ---- merge --------------------------------------------------------------------------------------


@dataclass
class Candidate:
    """A GLiNER span with offsets into its text."""

    text_index: int
    start: int
    end: int
    label: Label
    score: float
    type: str | None = None  # set when a mislabeled name is remapped to PERSON

    def span(self, text: str) -> Span:
        return Span(
            text=text[self.start : self.end],
            type=self.type or self.label.type,
            source="gliner",
            start=self.start,
            end=self.end,
            rule=f"gliner:{self.label.name}",
        )


def to_candidates(text: str, text_index: int, entities: Sequence[Entity]) -> list[Candidate]:
    """Map labels, join adjacent name parts ("Jane" + "Park"), keep the best of overlaps."""
    cands = []
    for e in entities:
        label = LABELS_BY_NAME[e.label]
        start, end = e.start, e.end
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1] in " \t\r\n.,;:!?)\"'“”’":
            end -= 1
        start, end = trim(text, start, end, label)
        if end - start < MIN_SPAN_CHARS or contains_placeholder(text[start:end]):
            continue
        cands.append(Candidate(text_index, start, end, label, e.score))
    cands.sort(key=lambda c: (c.start, c.end))

    joined: list[Candidate] = []
    for c in cands:
        prev = joined[-1] if joined else None
        if (
            prev is not None
            and prev.label.type == c.label.type == "PERSON"
            and prev.end <= c.start
            and not text[prev.end : c.start].strip()
            and "\n" not in text[prev.end : c.start]
        ):
            prev.end = c.end
            prev.score = min(prev.score, c.score)
            continue
        joined.append(c)

    chosen: list[Candidate] = []
    for c in sorted(joined, key=lambda c: (-c.score, c.start)):
        if not any(c.start < o.end and o.start < c.end for o in chosen):
            chosen.append(c)
    return sorted(chosen, key=lambda c: c.start)


def _overlap(a_start: int, a_end: int, b: Placement) -> int:
    return max(0, min(a_end, b.end) - max(a_start, b.start))


@dataclass
class EnsembleResult:
    accepted: list[list[Span]]  # per text, spans to add
    counts: dict[str, float] = field(default_factory=dict)


ADJUDICATOR_PROMPT = load_prompt("adjudicate.md")


def adjudication_schema(ids: Sequence[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {i: {"type": "string", "enum": ["yes", "no"]} for i in ids},
        "required": list(ids),
        "additionalProperties": False,
    }


CONTEXT_CHARS = 110
MAX_PER_CALL = 24


def _context(text: str, start: int, end: int, hidden: Sequence[Placement]) -> str:
    """Text around a candidate, with deterministic spans shown as `<TYPE>` tokens."""
    left = max(0, start - CONTEXT_CHARS)
    right = min(len(text), end + CONTEXT_CHARS)
    pieces: list[tuple[int, int, str]] = [
        (p.start, p.end, f"<{p.span.type}>")
        for p in hidden
        if p.end > left and p.start < right and (p.end <= start or p.start >= end)
    ]
    pieces.append((start, end, "⟦" + text[start:end] + "⟧"))
    out, cursor = [], left
    for s, e, rendered in sorted(pieces):
        s, e = max(s, left), min(e, right)
        if s < cursor:
            continue
        out.append(text[cursor:s])
        out.append(rendered)
        cursor = e
    out.append(text[cursor:right])
    body = re.sub(r"\s+", " ", "".join(out)).strip()
    return ("…" if left else "") + body + ("…" if right < len(text) else "")


class Ensemble:
    def __init__(self, settings: Settings, gliner: GlinerModel, local: LocalModel):
        self.settings = settings
        self.gliner = gliner
        self.local = local
        # Labels whose GLiNER-only spans are never accepted: only agreement can confirm them.
        self.agreement_only = parse_labels(settings.gliner_agreement_only)

    async def propose(self, texts: Sequence[str]) -> tuple[list[list[Entity]], float]:
        started = time.perf_counter()
        entities = await asyncio.to_thread(self.gliner.predict, list(texts))
        return entities, (time.perf_counter() - started) * 1000

    async def merge(
        self,
        texts: Sequence[str],
        spans_by_text: Sequence[Sequence[Span]],
        proposals: tuple[list[list[Entity]], float],
    ) -> EnsembleResult:
        """Agreement, type consistency, then one batched adjudication call for the rest."""
        entities, gliner_ms = proposals
        counts: dict[str, float] = {
            "gliner_texts": len(texts),
            "gliner_spans": 0,
            "gliner_agreed": 0,
            "gliner_rejected_mislabel": 0,
            "gliner_rejected_shape": 0,
            "gliner_rejected_label": 0,
            "gliner_remapped": 0,
            "gliner_candidates": 0,
            "adjudication_calls": 0,
            "adjudicated_yes": 0,
            "adjudicated_no": 0,
            "gliner_ms": round(gliner_ms),
            "adjudication_ms": 0,
        }
        accepted: list[list[Span]] = [[] for _ in texts]
        pending: list[tuple[Candidate, list[Placement]]] = []
        for i, (text, existing, found) in enumerate(
            zip(texts, spans_by_text, entities, strict=True)
        ):
            others = locate(text, list(existing))
            hidden = [p for p in others if p.span.source in ("regex", "entropy", "vault")]
            for cand in to_candidates(text, i, found):
                counts["gliner_spans"] += 1
                if mislabel(text[cand.start : cand.end], cand.label):
                    counts["gliner_rejected_mislabel"] += 1
                    continue
                size = cand.end - cand.start
                partners = [
                    p
                    for p in others
                    if _overlap(cand.start, cand.end, p) * 2 >= min(size, p.end - p.start)
                ]
                if partners:
                    counts["gliner_agreed"] += 1
                    # Inside a partner it adds nothing; next to a generalization, a mask would
                    # override the generalized phrase, so the partner's decision stands.
                    covered = any(p.start <= cand.start and cand.end <= p.end for p in partners)
                    if not covered and all(p.span.action == "mask" for p in partners):
                        accepted[i].append(cand.span(text))
                    continue
                if cand.label.name in self.agreement_only:
                    counts["gliner_rejected_label"] += 1
                    continue
                value = text[cand.start : cand.end]
                ko_min = self.settings.gliner_ko_name_min_syllables
                if not shape_ok(value, cand.label, ko_min):
                    if not remap_person(value, cand.label, ko_min):
                        counts["gliner_rejected_shape"] += 1
                        continue
                    cand.type = "PERSON"
                    counts["gliner_remapped"] += 1
                counts["gliner_candidates"] += 1
                pending.append((cand, hidden))

        if pending and not self.settings.gliner_adjudicate:
            for cand, _ in pending:
                accepted[cand.text_index].append(cand.span(texts[cand.text_index]))
        elif pending:
            started = time.perf_counter()
            verdicts = await self._adjudicate(texts, pending, counts)
            counts["adjudication_ms"] = round((time.perf_counter() - started) * 1000)
            for (cand, _), yes in zip(pending, verdicts, strict=True):
                counts["adjudicated_yes" if yes else "adjudicated_no"] += 1
                if yes:
                    accepted[cand.text_index].append(cand.span(texts[cand.text_index]))
        return EnsembleResult(accepted, counts)

    async def _adjudicate(
        self,
        texts: Sequence[str],
        pending: Sequence[tuple[Candidate, list[Placement]]],
        counts: dict[str, float],
    ) -> list[bool]:
        # The same value with the same type is asked about once.
        keys: dict[tuple[str, str], int] = {}
        items: list[tuple[Candidate, list[Placement]]] = []
        index: list[int] = []
        for cand, hidden in pending:
            key = (normalize(texts[cand.text_index][cand.start : cand.end]), cand.label.type)
            if key not in keys:
                keys[key] = len(items)
                items.append((cand, hidden))
            index.append(keys[key])

        answers: list[bool] = []
        for batch_start in range(0, len(items), MAX_PER_CALL):
            batch = items[batch_start : batch_start + MAX_PER_CALL]
            ids = [f"c{n + 1}" for n in range(len(batch))]
            lines = []
            for cid, (cand, hidden) in zip(ids, batch, strict=True):
                text = texts[cand.text_index]
                value = text[cand.start : cand.end]
                lines.append(
                    f"[{cid}] label={cand.label.name} span={value!r}\n"
                    f"context: {_context(text, cand.start, cand.end, hidden)}"
                )
            data = await self.local.chat_json(
                ADJUDICATOR_PROMPT,
                "<candidates>\n" + "\n\n".join(lines) + "\n</candidates>",
                adjudication_schema(ids),
                "airlock_adjudication",
                max_tokens=16 + 10 * len(ids),
                temperature=0.0,
            )
            counts["adjudication_calls"] += 1
            if not isinstance(data, dict) or any(data.get(i) not in ("yes", "no") for i in ids):
                raise LocalModelMalformed("schema")
            answers += [data[i] == "yes" for i in ids]
        return [answers[i] for i in index]


def build_ensemble(settings: Settings, local: LocalModel) -> Ensemble | None:
    """The ensemble for these settings; None when GLiNER is off. Fails closed when it is on."""
    if not settings.gliner:
        return None
    problem = availability_problem(settings)
    if problem:
        raise GlinerUnavailable(f"AIRLOCK_GLINER=on but GLiNER cannot run: {problem}")
    return Ensemble(settings, GlinerModel(settings), local)


def doctor_checks(settings: Settings) -> Iterator[tuple[str, str, str]]:
    """(status, name, detail) rows for `airlock doctor`. Loads the model and runs a probe."""
    if not settings.gliner:
        yield "ok", "gliner", "off (AIRLOCK_GLINER=on enables the NVIDIA GLiNER-PII ensemble)"
        return
    problem = availability_problem(settings)
    if problem:
        yield "fail", "gliner", problem
        return
    model = GlinerModel(settings)
    try:
        [found] = model.predict(["Please email Jane Doe about the Q3 invoice."])
    except Exception as exc:  # noqa: BLE001 - any load failure means the server must not start
        yield "fail", "gliner", f"load or probe failed ({type(exc).__name__})"
        return
    yield (
        "ok",
        "gliner",
        f"{Path(settings.gliner_model).name} on {model.device}, loaded in "
        f"{model.load_s or 0:.1f}s, {len(found)} span(s) on a synthetic probe, "
        f"threshold {settings.gliner_threshold}, adjudication "
        f"{'on' if settings.gliner_adjudicate else 'off'}",
    )
