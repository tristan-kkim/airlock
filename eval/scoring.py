"""Scanning, per-case scoring and metric aggregation for the Airlock eval harness.

Pure functions only: no network, no file I/O. `run.py` feeds it raw records; `--rescore` feeds it
records read back from disk, so every published number can be recomputed offline.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import re
import statistics
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import unquote

HARNESS_VERSION = "1.0.0"

# --------------------------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------------------------

_ZERO_WIDTH = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_WS = re.compile(r"\s+")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
# A run of digits that may be broken up by spaces, newlines, dashes, dots, slashes or brackets.
_DIGIT_RUN = re.compile(r"\d(?:[\d\s\-.()/+_]*\d)?")
_KO_NUMERALS = {
    "공": "0", "영": "0", "일": "1", "이": "2", "삼": "3", "사": "4",
    "오": "5", "육": "6", "륙": "6", "칠": "7", "팔": "8", "구": "9",
}  # fmt: skip
_KO_CLASS = "".join(_KO_NUMERALS)
_KO_RUN = re.compile(rf"[{_KO_CLASS}\d](?:[{_KO_CLASS}\d\s\-.,]*[{_KO_CLASS}\d])?")
_EN_NUMERALS = {
    "zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}  # fmt: skip
_EN_TOKEN = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine|\d+)"
_EN_RUN = re.compile(rf"\b{_EN_TOKEN}\b(?:[\s,\-]+{_EN_TOKEN}\b)*", re.IGNORECASE)

MIN_DIGITS = 6  # digit-only matching is used only for needles with at least this many digits
MIN_ASCII_COLLAPSED = 8  # whitespace/alnum-collapsed matching guard for Latin-only needles
MIN_NON_ASCII_COLLAPSED = 3  # ... and for needles containing Hangul or other scripts

VARIANTS = ("exact", "casefold", "whitespace", "alnum", "digits", "numeral_words")
KEEP_VARIANTS = ("exact", "casefold", "whitespace")


def nfkc(text: str) -> str:
    return _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))


def only_digits(text: str) -> str:
    return "".join(ch for ch in text if "0" <= ch <= "9")


def alnum_fold(text: str) -> str:
    return "".join(ch for ch in text if ch.isalnum()).casefold()


def strip_ws(text: str) -> str:
    return _WS.sub("", text)


def _collapsed_ok(text: str) -> bool:
    limit = MIN_ASCII_COLLAPSED if text.isascii() else MIN_NON_ASCII_COLLAPSED
    return len(text) >= limit


def _numeral_runs(text: str) -> list[str]:
    out: list[str] = []
    for m in _KO_RUN.finditer(text):
        run = m.group()
        if any(ch in _KO_NUMERALS for ch in run):
            out.append("".join(_KO_NUMERALS.get(ch, ch if ch.isdigit() else "") for ch in run))
    for m in _EN_RUN.finditer(text):
        tokens = re.split(r"[\s,\-]+", m.group())
        if any(t.lower() in _EN_NUMERALS for t in tokens):
            out.append("".join(_EN_NUMERALS.get(t.lower(), only_digits(t)) for t in tokens))
    return [r for r in out if len(r) >= MIN_DIGITS]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Airlock hashes audit values with HMAC-SHA256 under a local key (AIRLOCK_AUDIT_HASH_KEY or
# .airlock/audit_hash.key). run.py loads it; without a key only plain SHA-256 is tried.
_HASH_KEY: bytes | None = None


def set_hash_key(key: bytes | None) -> None:
    global _HASH_KEY
    _HASH_KEY = key or None


def hash_candidates(value: str) -> set[str]:
    """Hashes under which a detector or the gate might have recorded this value."""
    forms = {f for f in {value, value.strip(), nfkc(value).strip()} if f}
    out = {sha256_text(f) for f in forms}
    if _HASH_KEY:
        out |= {hmac.new(_HASH_KEY, f.encode("utf-8"), hashlib.sha256).hexdigest() for f in forms}
    return out


# --------------------------------------------------------------------------------------------
# Haystack: every string in an outbound payload, plus decoded layers
# --------------------------------------------------------------------------------------------


def iter_strings(obj: Any) -> Iterator[str]:
    """Every string leaf (and dict key, and number) in a JSON value."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, bool) or obj is None:
        return
    elif isinstance(obj, int | float):
        yield str(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from iter_strings(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from iter_strings(v)


def _try_b64(token: str) -> str | None:
    core = token.rstrip("=")
    if len(core) < 16:
        return None
    urlsafe = "-" in core or "_" in core
    if urlsafe and ("+" in core or "/" in core):
        return None
    padded = core + "=" * (-len(core) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_" if urlsafe else None, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch.isspace())
    return text if printable / len(text) >= 0.9 else None


def decode_layers(text: str) -> list[str]:
    """One decoding step: embedded JSON strings, percent-encoding and base64 tokens."""
    out: list[str] = []
    stripped = text.strip()
    if stripped[:1] in "{[" and stripped[-1:] in "}]":
        with contextlib.suppress(ValueError):
            out.extend(iter_strings(json.loads(stripped)))
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            out.append(decoded)
    for m in _B64_TOKEN.finditer(text):
        decoded = _try_b64(m.group())
        if decoded:
            out.append(decoded)
    return out


class _Leaf:
    __slots__ = ("text", "cf", "ws", "alnum", "digit_runs", "numeral_runs")

    def __init__(self, text: str):
        self.text = text
        norm = nfkc(text)
        self.cf = norm.casefold()
        self.ws = strip_ws(self.cf)
        self.alnum = alnum_fold(norm)
        self.digit_runs = [only_digits(m.group()) for m in _DIGIT_RUN.finditer(norm)]
        self.numeral_runs = _numeral_runs(norm)


class Needle:
    """A string we look for, precomputed in every normalized form."""

    def __init__(self, value: str):
        self.value = value
        norm = nfkc(value)
        self.cf = norm.casefold()
        self.ws = strip_ws(self.cf)
        self.alnum = alnum_fold(norm)
        self.digits = only_digits(norm)
        alnum_len = max(1, len(self.alnum))
        self.mostly_digits = len(self.digits) >= MIN_DIGITS and len(self.digits) / alnum_len >= 0.6
        self._exact = self._pattern(value, 0)
        self._cf = self._pattern(self.cf, 0)

    @staticmethod
    def _pattern(text: str, flags: int) -> re.Pattern[str] | None:
        # Latin-script needles get word boundaries ("Avery" must not match "bravery").
        # Hangul needles do not: Korean particles attach directly ("김서윤에게").
        if not text:
            return None
        head, tail = text[:1], text[-1:]
        prefix = r"(?<![A-Za-z0-9])" if head.isascii() and head.isalnum() else ""
        suffix = r"(?![A-Za-z0-9])" if tail.isascii() and tail.isalnum() else ""
        return re.compile(prefix + re.escape(text) + suffix, flags)

    def match(self, leaf: _Leaf, variant: str) -> bool:
        if variant == "exact":
            return bool(self._exact and self._exact.search(leaf.text))
        if variant == "casefold":
            return bool(self._cf and self._cf.search(leaf.cf))
        if variant == "whitespace":
            # Length-guarded: collapsing whitespace makes short Latin needles collide
            # ("a very" -> "avery").
            return not self.mostly_digits and _collapsed_ok(self.ws) and self.ws in leaf.ws
        if variant == "alnum":
            return not self.mostly_digits and _collapsed_ok(self.alnum) and self.alnum in leaf.alnum
        if variant == "digits":
            return self.mostly_digits and any(self.digits in run for run in leaf.digit_runs)
        if variant == "numeral_words":
            return self.mostly_digits and any(self.digits in run for run in leaf.numeral_runs)
        raise ValueError(variant)


class Haystack:
    """All strings of one outbound payload, with up to two decoded layers."""

    def __init__(self, payload: Any, decode_depth: int = 2):
        base = list(iter_strings(payload))
        self.leaves = [_Leaf(t) for t in base]
        decoded: list[str] = []
        frontier = base
        for _ in range(decode_depth):
            nxt = [d for t in frontier for d in decode_layers(t)]
            if not nxt:
                break
            decoded.extend(nxt)
            frontier = nxt
        self.decoded = [_Leaf(t) for t in decoded]

    def find(self, needle: Needle | str, variants: Iterable[str] = VARIANTS) -> str | None:
        """Return the strictest variant under which the needle occurs, or None."""
        if isinstance(needle, str):
            needle = Needle(needle)
        variants = tuple(variants)
        for layer, label in ((self.leaves, ""), (self.decoded, "decoded:")):
            if label and variants == KEEP_VARIANTS:
                break
            for variant in variants:
                if any(needle.match(leaf, variant) for leaf in layer):
                    return label + variant
        return None


def scan_text(text: str, needle: str) -> str | None:
    """Convenience: scan a bare string as if it were an outbound payload."""
    return Haystack(text).find(needle)


# --------------------------------------------------------------------------------------------
# Per-case scoring
# --------------------------------------------------------------------------------------------

NON_MASKING_ACTIONS = {"keep", "allow", "none", "pass", ""}


def alternatives(attr: str | list[str]) -> list[str]:
    return [attr] if isinstance(attr, str) else list(attr)


def dedupe(items: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        if item and item not in seen:
            seen[item] = None
    return list(seen)


def overhead_ms(timings: dict[str, Any] | None) -> float | None:
    """Local processing time: total minus time spent waiting on cloud calls."""
    if not timings:
        return None
    nums = {k: float(v) for k, v in timings.items() if isinstance(v, int | float)}
    if not nums:
        return None
    remote = re.compile(r"upstream|tavily|cloud|remote|provider", re.IGNORECASE)
    external = sum(v for k, v in nums.items() if remote.search(k))
    total = nums.get("total", nums.get("total_ms"))
    if total is not None:
        return max(total - external, 0.0)
    return sum(v for k, v in nums.items() if not remote.search(k))


def score_case(case: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Score one request/audit pair against the case's expectations."""
    base = {
        "case_id": case["id"],
        "category": case["category"],
        "lang": case["lang"],
        "task": case["task"],
        "status": record.get("status", "error"),
        "http_status": record.get("http_status"),
        "request_id": record.get("request_id"),
        "client_ms": record.get("client_ms"),
    }
    if base["status"] == "error":
        return {**base, "error": record.get("error")}

    audit = record.get("audit") or {}
    outbound = audit.get("outbound") or []
    detections = audit.get("detections") or []
    gate = audit.get("gate") or {}
    blocked = base["status"] == "blocked" or gate.get("decision") == "block"

    hays: list[tuple[str, Haystack]] = [
        (str(o.get("destination", "unknown")), Haystack(o.get("payload"))) for o in outbound
    ]
    det_hashes = {d.get("text_sha256") for d in detections if d.get("text_sha256")}
    reasons_blob = json.dumps(
        [gate.get("reasons") or [], record.get("block_reasons") or []], ensure_ascii=False
    )

    canaries = set(case.get("canaries") or [])
    needles = dedupe([*(case.get("must_not_leak") or []), *(case.get("canaries") or [])])
    values: list[dict[str, Any]] = []
    for value in needles:
        needle = Needle(value)
        hits = []
        for dest, hay in hays:
            variant = hay.find(needle)
            if variant:
                hits.append({"destination": dest, "variant": variant})
        hashes = hash_candidates(value)
        detected = bool(hashes & det_hashes)
        attributed = any(h[:12] in reasons_blob for h in hashes)
        if hits:
            outcome = "leaked_despite_detection" if detected else "missed_leaked"
        elif detected:
            outcome = "detected_removed"
        elif blocked:
            outcome = "gate_saved"
        else:
            outcome = "removed_unattributed"
        values.append(
            {
                "value": value,
                "is_canary": value in canaries,
                "hits": hits,
                "detected": detected,
                "gate_attributed": attributed,
                "outcome": outcome,
            }
        )

    quasi = None
    group = case.get("quasi_group")
    if group:
        k = int(case.get("quasi_k") or len(group))
        by_dest: dict[str, list[Haystack]] = defaultdict(list)
        for dest, hay in hays:
            by_dest[dest].append(hay)
        per_dest = {}
        for dest, dest_hays in by_dest.items():
            found = [
                i
                for i, attr in enumerate(group)
                if any(h.find(a) for h in dest_hays for a in alternatives(attr))
            ]
            per_dest[dest] = found
        max_found = max((len(v) for v in per_dest.values()), default=0)
        quasi = {
            "k": k,
            "size": len(group),
            "max_found": max_found,
            "per_destination": per_dest,
            "reidentified": max_found >= k,
        }

    must_keep = case.get("must_keep") or []
    if hays:
        missing = [m for m in must_keep if not any(h.find(m, KEEP_VARIANTS) for _, h in hays)]
    else:
        missing = None  # nothing was sent (blocked): over-redaction is not measurable

    masking = [
        d for d in detections if str(d.get("action", "mask")).lower() not in NON_MASKING_ACTIONS
    ]
    value_leaked = any(v["hits"] for v in values)
    return {
        **base,
        "blocked": blocked,
        "gate_decision": gate.get("decision"),
        "n_outbound": len(outbound),
        "n_values": len(values),
        "n_values_leaked": sum(1 for v in values if v["hits"]),
        "value_leaked": value_leaked,
        "exact_leaked": any(h["variant"] == "exact" for v in values for h in v["hits"]),
        "canary_count": len(canaries),
        "canary_leaked": any(v["hits"] for v in values if v["is_canary"]),
        "quasi": quasi,
        "leaked": value_leaked or bool(quasi and quasi["reidentified"]),
        "values": values,
        "must_keep_total": len(must_keep),
        "must_keep_missing": missing,
        "detections": len(detections),
        "masking_detections": len(masking),
        "detection_types": dict(Counter(str(d.get("type")) for d in masking)),
        "overhead_ms": overhead_ms(audit.get("timings_ms")),
        "timings_ms": audit.get("timings_ms"),
    }


# --------------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------------


def _rate(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = (len(ordered) - 1) * q
    lo, hi = int(idx), min(int(idx) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo)


def compute_metrics(scored: list[dict[str, Any]]) -> dict[str, Any]:
    """Rates for one pass over a set of scored cases. Denominators are documented in README."""
    ok = [s for s in scored if s["status"] != "error"]
    benign = [s for s in ok if s["category"] == "benign"]
    sensitive = [s for s in ok if s["category"] != "benign"]
    eligible = [s for s in ok if s["n_values"] or s["quasi"]]
    with_canary = [s for s in ok if s["canary_count"]]
    with_quasi = [s for s in ok if s["quasi"]]
    keep_scored = [s for s in ok if s["must_keep_missing"] is not None and s["must_keep_total"]]

    outcomes = Counter(v["outcome"] for s in ok for v in s["values"])
    attributed = sum(
        1 for s in ok for v in s["values"] if v["outcome"] == "gate_saved" and v["gate_attributed"]
    )
    missed_leaked = outcomes["missed_leaked"]
    gate_saved = outcomes["gate_saved"]
    n_values = sum(s["n_values"] for s in ok)
    overheads = [s["overhead_ms"] for s in ok if s.get("overhead_ms") is not None]
    client = [s["client_ms"] for s in ok if s.get("client_ms") is not None]

    return {
        "cases": len(scored),
        "errors": len(scored) - len(ok),
        "leak_rate": _rate(sum(s["leaked"] for s in eligible), len(eligible)),
        "value_leak_rate": _rate(sum(s["n_values_leaked"] for s in ok), n_values),
        "exact_leak_rate": _rate(sum(s["exact_leaked"] for s in eligible), len(eligible)),
        "canary_leak_rate": _rate(sum(s["canary_leaked"] for s in with_canary), len(with_canary)),
        "quasi_reid_rate": _rate(
            sum(s["quasi"]["reidentified"] for s in with_quasi), len(with_quasi)
        ),
        "block_rate": _rate(sum(s["blocked"] for s in ok), len(ok)),
        "block_rate_sensitive": _rate(sum(s["blocked"] for s in sensitive), len(sensitive)),
        "over_block_benign": _rate(sum(s["blocked"] for s in benign), len(benign)),
        "benign_false_positive_rate": _rate(
            sum(1 for s in benign if s["masking_detections"] > 0), len(benign)
        ),
        "over_redaction_rate": _rate(
            sum(len(s["must_keep_missing"]) for s in keep_scored),
            sum(s["must_keep_total"] for s in keep_scored),
        ),
        "over_redaction_case_rate": _rate(
            sum(1 for s in keep_scored if s["must_keep_missing"]), len(keep_scored)
        ),
        "detector_miss_rate": _rate(missed_leaked + gate_saved, n_values),
        "gate_save_rate": _rate(gate_saved, gate_saved + missed_leaked),
        "gate_save_rate_attributed": _rate(attributed, gate_saved + missed_leaked),
        "overhead_ms_mean": statistics.fmean(overheads) if overheads else None,
        "overhead_ms_p50": _percentile(overheads, 0.5),
        "overhead_ms_p95": _percentile(overheads, 0.95),
        "client_ms_mean": statistics.fmean(client) if client else None,
        "value_outcomes": dict(outcomes),
        "gate_saved_attributed": attributed,
    }


def metrics_by(scored: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in scored:
        groups[s[key]].append(s)
    return {g: compute_metrics(items) for g, items in sorted(groups.items())}


def describe(values: Iterable[float | None]) -> dict[str, Any]:
    """Mean, sample standard deviation (n-1) and range. None values are skipped."""
    xs = [float(v) for v in values if v is not None]
    if not xs:
        return {"n": 0, "mean": None, "std": None, "min": None, "max": None, "values": []}
    return {
        "n": len(xs),
        "mean": statistics.fmean(xs),
        "std": statistics.stdev(xs) if len(xs) >= 2 else 0.0,
        "min": min(xs),
        "max": max(xs),
        "values": xs,
    }


def aggregate(pass_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    keys = (
        [k for k, v in pass_metrics[0].items() if not isinstance(v, dict)] if pass_metrics else []
    )
    return {k: describe(m.get(k) for m in pass_metrics) for k in keys}


def case_failures(scored_passes: list[list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Per-case counts across passes: which cases leaked, how often, and how."""
    table: dict[str, dict[str, Any]] = {}
    for pass_scores in scored_passes:
        for s in pass_scores:
            row = table.setdefault(
                s["case_id"],
                {
                    "case_id": s["case_id"],
                    "category": s["category"],
                    "lang": s["lang"],
                    "passes": 0,
                    "errors": 0,
                    "leaked_passes": 0,
                    "quasi_reid_passes": 0,
                    "blocked_passes": 0,
                    "fp_passes": 0,
                    "over_redaction_passes": 0,
                    "leaked_values": {},
                    "missing_keep": {},
                },
            )
            row["passes"] += 1
            if s["status"] == "error":
                row["errors"] += 1
                continue
            row["leaked_passes"] += int(s["leaked"])
            row["quasi_reid_passes"] += int(bool(s["quasi"] and s["quasi"]["reidentified"]))
            row["blocked_passes"] += int(s["blocked"])
            row["fp_passes"] += int(s["masking_detections"] > 0)
            row["over_redaction_passes"] += int(bool(s["must_keep_missing"]))
            for v in s["values"]:
                if v["hits"]:
                    entry = row["leaked_values"].setdefault(
                        v["value"], {"passes": 0, "variants": [], "destinations": []}
                    )
                    entry["passes"] += 1
                    for h in v["hits"]:
                        if h["variant"] not in entry["variants"]:
                            entry["variants"].append(h["variant"])
                        if h["destination"] not in entry["destinations"]:
                            entry["destinations"].append(h["destination"])
            for m in s["must_keep_missing"] or []:
                row["missing_keep"][m] = row["missing_keep"].get(m, 0) + 1

    rows = list(table.values())
    for r in rows:
        evaluated = r["passes"] - r["errors"]
        r["evaluated_passes"] = evaluated
        r["persistent"] = evaluated > 0 and r["leaked_passes"] == evaluated
    leaks = sorted(
        (r for r in rows if r["leaked_passes"]),
        key=lambda r: (-r["leaked_passes"] / max(r["evaluated_passes"], 1), r["case_id"]),
    )
    benign = sorted(
        (
            r
            for r in rows
            if r["category"] == "benign"
            and (r["blocked_passes"] or r["fp_passes"] or r["over_redaction_passes"])
        ),
        key=lambda r: (-(r["blocked_passes"] + r["fp_passes"]), r["case_id"]),
    )
    over_redaction = sorted(
        (r for r in rows if r["over_redaction_passes"]),
        key=lambda r: (-r["over_redaction_passes"], r["case_id"]),
    )
    return {"leaks": leaks, "benign_issues": benign, "over_redaction": over_redaction}


def summarize(
    cases: list[dict[str, Any]], scored_passes: list[list[dict[str, Any]]], config: dict[str, Any]
) -> dict[str, Any]:
    per_pass = [compute_metrics(p) for p in scored_passes]
    cats = sorted({c["category"] for c in cases})
    langs = sorted({c["lang"] for c in cases})
    by_cat_passes = [metrics_by(p, "category") for p in scored_passes]
    by_lang_passes = [metrics_by(p, "lang") for p in scored_passes]
    failures = case_failures(scored_passes)
    n_passes = len(scored_passes)
    return {
        "harness_version": HARNESS_VERSION,
        "config": config,
        "dataset": {
            "cases": len(cases),
            "by_category": dict(Counter(c["category"] for c in cases)),
            "by_lang": dict(Counter(c["lang"] for c in cases)),
            "by_task": dict(Counter(c["task"] for c in cases)),
        },
        "passes": n_passes,
        "overall": aggregate(per_pass),
        "by_category": {
            cat: aggregate([p[cat] for p in by_cat_passes if cat in p]) for cat in cats
        },
        "by_lang": {
            lang: aggregate([p[lang] for p in by_lang_passes if lang in p]) for lang in langs
        },
        "per_pass": per_pass,
        "persistent_leaks": [r for r in failures["leaks"] if r["persistent"]],
        "flaky_leaks": [r for r in failures["leaks"] if not r["persistent"]],
        "leak_frequency_histogram": dict(Counter(r["leaked_passes"] for r in failures["leaks"])),
        "benign_issues": failures["benign_issues"],
        "over_redaction_cases": failures["over_redaction"],
    }


# --------------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------------

_HEADLINE = [
    ("leak_rate", "Leak rate (cases)", "pct"),
    ("value_leak_rate", "Leak rate (individual values)", "pct"),
    ("exact_leak_rate", "Leak rate (exact-string hits only)", "pct"),
    ("canary_leak_rate", "Canary leak rate", "pct"),
    ("quasi_reid_rate", "Quasi-identifier re-identification rate", "pct"),
    ("gate_save_rate", "Gate save rate (upper bound: request-level)", "pct"),
    ("gate_save_rate_attributed", "Gate save rate (lower bound: hash-attributed)", "pct"),
    ("detector_miss_rate", "Values that got past the detectors", "pct"),
    ("block_rate", "Block rate (all)", "pct"),
    ("block_rate_sensitive", "Block rate (non-benign)", "pct"),
    ("over_block_benign", "Over-block on benign", "pct"),
    ("benign_false_positive_rate", "Benign cases with any masking", "pct"),
    ("over_redaction_rate", "Over-redaction (must_keep strings missing)", "pct"),
    ("over_redaction_case_rate", "Over-redaction (cases with any missing)", "pct"),
    ("overhead_ms_mean", "Local overhead, mean (ms)", "ms"),
    ("overhead_ms_p95", "Local overhead, p95 (ms)", "ms"),
    ("client_ms_mean", "Client wall time, mean (ms)", "ms"),
    ("errors", "Errors per pass", "int"),
]


def _fmt(value: float | None, kind: str) -> str:
    if value is None:
        return "n/a"
    if kind == "pct":
        return f"{value * 100:.1f}%"
    if kind == "ms":
        return f"{value:.0f}"
    return f"{value:.1f}" if value != int(value) else f"{int(value)}"


def _stat_cells(stat: dict[str, Any], kind: str) -> list[str]:
    if not stat or stat.get("n", 0) == 0:
        return ["n/a", "n/a", "n/a"]
    std = stat["std"] * 100 if kind == "pct" else stat["std"]
    std_s = f"{std:.1f}{' pp' if kind == 'pct' else ''}"
    return [
        _fmt(stat["mean"], kind),
        std_s,
        f"{_fmt(stat['min'], kind)} to {_fmt(stat['max'], kind)}",
    ]


def render_markdown(summary: dict[str, Any]) -> str:
    cfg = summary["config"]
    n = summary["passes"]
    lines = [
        "# Airlock eval summary",
        "",
        f"- Target: `{cfg.get('base_url')}` ({cfg.get('target_label', 'airlock')})",
        f"- Passes: {n} · cases per pass: {summary['dataset']['cases']} · "
        f"protection level: `{cfg.get('protection_level') or 'server default'}`",
        f"- Dataset sha256: `{cfg.get('dataset_sha256')}`",
        f"- Harness version: {summary['harness_version']} · started {cfg.get('started_at')}",
        "",
        "All rates are computed per pass, then summarized across passes as mean, sample standard "
        "deviation and range (min to max). Definitions: `eval/README.md`.",
        "",
        "## Headline",
        "",
        "| Metric | Mean | Std | Range |",
        "|---|---:|---:|---:|",
    ]
    for key, label, kind in _HEADLINE:
        lines.append(
            f"| {label} | " + " | ".join(_stat_cells(summary["overall"].get(key), kind)) + " |"
        )

    lines += [
        "",
        "## By category",
        "",
        "| Category | Leak rate | Block rate | Over-redaction | Gate save | Benign FP |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cat, agg in summary["by_category"].items():
        cells = []
        for key in (
            "leak_rate",
            "block_rate",
            "over_redaction_rate",
            "gate_save_rate",
            "benign_false_positive_rate",
        ):
            st = agg.get(key) or {}
            if not st.get("n"):
                cells.append("n/a")
            else:
                cells.append(f"{st['mean'] * 100:.1f}% ± {st['std'] * 100:.1f}")
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## By language",
        "",
        "| Lang | Leak rate | Block rate | Over-redaction |",
        "|---|---:|---:|---:|",
    ]
    for lang, agg in summary["by_lang"].items():
        cells = []
        for key in ("leak_rate", "block_rate", "over_redaction_rate"):
            st = agg.get(key) or {}
            cells.append(
                "n/a" if not st.get("n") else f"{st['mean'] * 100:.1f}% ± {st['std'] * 100:.1f}"
            )
        lines.append(f"| {lang} | " + " | ".join(cells) + " |")

    persistent, flaky = summary["persistent_leaks"], summary["flaky_leaks"]
    lines += [
        "",
        "## Cases that leaked in any pass",
        "",
        f"{len(persistent)} case(s) leaked in every pass; {len(flaky)} leaked in some passes only.",
        "",
        "| Case | Category | Lang | Leaked passes "
        "| What reached the cloud (value: passes, match variants) |",
        "|---|---|---|---:|---|",
    ]
    for r in persistent + flaky:
        parts = [
            f"`{_md_escape(v)}`: {e['passes']}, {'/'.join(e['variants'])}"
            for v, e in sorted(r["leaked_values"].items(), key=lambda kv: -kv[1]["passes"])
        ]
        if r["quasi_reid_passes"]:
            parts.append(f"quasi-identifier group ≥k: {r['quasi_reid_passes']}")
        lines.append(
            f"| {r['case_id']} | {r['category']} | {r['lang']} | "
            f"{r['leaked_passes']}/{r['evaluated_passes']} | {'; '.join(parts)} |"
        )

    lines += [
        "",
        "## Benign cases with over-blocking or masking",
        "",
        "| Case | Lang | Blocked passes | Passes with masking | Missing must_keep |",
        "|---|---|---:|---:|---|",
    ]
    for r in summary["benign_issues"]:
        missing = ", ".join(f"`{_md_escape(k)}` ({c})" for k, c in r["missing_keep"].items())
        lines.append(
            f"| {r['case_id']} | {r['lang']} | {r['blocked_passes']}/{r['evaluated_passes']} | "
            f"{r['fp_passes']}/{r['evaluated_passes']} | {missing or '-'} |"
        )

    o = summary["overall"]
    lines += ["", "## Value outcomes (summed over passes)", ""]
    totals: Counter[str] = Counter()
    for p in summary["per_pass"]:
        totals.update(p["value_outcomes"])
    for key in (
        "detected_removed",
        "removed_unattributed",
        "gate_saved",
        "missed_leaked",
        "leaked_despite_detection",
    ):
        lines.append(f"- `{key}`: {totals.get(key, 0)}")
    lines.append(
        f"- `gate_saved` with hash-attributed reason: "
        f"{sum(p['gate_saved_attributed'] for p in summary['per_pass'])}"
    )
    if o.get("errors", {}).get("mean"):
        lines += [
            "",
            f"Note: mean errors per pass = {o['errors']['mean']:.1f}; errored cases are "
            "excluded from every rate.",
        ]
    if summary.get("judge"):
        j = summary["judge"]
        lines += [
            "",
            "## Answer utility (LLM judge, optional)",
            "",
            "The baseline for this section sent the raw synthetic prompts directly to the "
            "judge endpoint. See README.",
            "",
            f"- Judged cases: {j.get('judged')} (passes judged: {j.get('passes_judged')})",
            f"- Mean score, Airlock answer: {_fmt(j.get('airlock_score_mean'), 'int')} / 5",
            f"- Mean score, direct raw-prompt answer: {_fmt(j.get('baseline_score_mean'), 'int')}"
            " / 5",
            "- Utility retention (mean Airlock / mean baseline): "
            f"{_fmt(j.get('utility_retention'), 'pct')}",
            f"- Airlock judged similar or better: {_fmt(j.get('similar_or_better_rate'), 'pct')}",
        ]
    lines.append("")
    return "\n".join(lines)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "\\n").replace("`", "'")
