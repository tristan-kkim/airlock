# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Judge-model calibration: can a cheaper Token Factory model take a scoring role?

    uv run eval/calibrate_judges.py --dry-run        # sample and token estimate, no calls
    uv run eval/calibrate_judges.py --yes            # run (cached, resumable, hard token cap)
    uv run eval/calibrate_judges.py --report-only    # rebuild the report from cached calls

The eval scores every system with four LLM roles: the attacker (`attack`), the intent and
situation graders (`grader`), the utility judge (`utility`) and the distortion confirmation
(`distortion_confirm`). Nemotron 3 Ultra made every stored score. This script re-runs each role
on a stratified sample of stored (system, case) items with candidate models and measures how far
the numbers the comparison tables report would move. The harness and proxy never run: inputs
are the stored outbound payloads, attacker outputs and answers in eval/results/, and the Ultra
reference is the stored Ultra output (no second payment).

Each role is isolated: a candidate grader grades Ultra's stored attacker output; a candidate
utility judge sees exactly the answer pair and order Ultra saw; a candidate confirmation model
re-checks exactly the distortions Ultra's judge flagged. Two end-to-end checks follow the
pipeline: a candidate attacker's output is graded by the Ultra grader and scored by the
deterministic scorer, and a candidate judge's flags are confirmed by the same candidate. An
Ultra retest re-runs the roles named in --retest-roles (by default the two cheap ones, the
graders and the confirmation) with Ultra itself to show the reference's own noise.

Agreement: Cohen's kappa for binary judgments, Spearman and mean absolute difference for
usefulness scores, and the difference in aggregate rates per system and pooled. A candidate
qualifies for a role when every headline rate of the role stays within the tolerance of Ultra
(pooled, and per system up to one net flipped item) and no clearly separated pair of systems
changes order. The report goes to eval/results/JUDGE_CALIBRATION.md; calls, the sample and the
numbers to eval/results/judge-calibration/.

All data is synthetic. Token Factory calls are capped by --max-tokens (default 2,000,000 across
all calls, retries included); the estimate prints first and the sample shrinks to fit.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import random
import statistics
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR))
import attack  # noqa: E402
import protected  # noqa: E402
import utility  # noqa: E402

RESULTS = EVAL_DIR / "results"
DEFAULT_OUT = RESULTS / "judge-calibration"
DEFAULT_REPORT = RESULTS / "JUDGE_CALIBRATION.md"
SYSTEMS = {
    "raw": "baseline-raw",
    "presidio_ko": "baseline-presidio_ko",
    "gliner_pii": "baseline-gliner_pii",
    "airlock_f0ba569": "baseline-f0ba569",
}
CANDIDATES = [attack.SUPER, attack.LIGHTNING, attack.NANO]
RETEST = "ultra-retest"
ROLES = ("attack", "grader", "utility", "distortion_confirm")
SENSITIVE_CATEGORIES = ("finance", "health", "quasi_identifier", "intent_leak_search")
RATE_TOLERANCE = 0.03
RATIO_TOLERANCE = 0.03
RATIO_SYSTEM_TOLERANCE = 0.05
RANK_GAP = 0.10  # pairs of systems closer than this on Ultra's sample are not ranked
MAX_UNPARSED = 0.05

# Headline numbers per role: (metric key, kind). `rate` metrics are per item (binary),
# `value_rate` per planted value, `ratio` the utility ratio.
HEADLINES: dict[str, list[tuple[str, str]]] = {
    "attack": [
        ("attack_value_recovery_rate", "value_rate"),
        ("attack_quasi_reid_rate", "rate"),
        ("attack_identity_recovery_rate", "rate"),
        ("situation_inference_rate", "rate"),
        ("linkable_disclosure_rate", "rate"),
    ],
    "grader": [("situation_inference_rate", "rate"), ("linkable_disclosure_rate", "rate")],
    "utility": [("utility_ratio_vs_reference", "ratio"), ("distortion_rate", "rate")],
    "distortion_confirm": [("distortion_rate", "rate")],
}
# Informational binary judgments (kappa only, not part of the qualification).
EXTRA_BINARY: dict[str, list[str]] = {
    "attack": ["attack_intent_inference_rate"],
    "grader": ["attack_intent_inference_rate"],
    "utility": ["distortion_flag_system", "distortion_flag_reference"],
    "distortion_confirm": ["confirmed"],
}


# --------------------------------------------------------------------------------------------
# Agreement statistics (tested)
# --------------------------------------------------------------------------------------------


def cohen_kappa(a: Sequence[bool], b: Sequence[bool]) -> float | None:
    """Cohen's kappa for two binary raters; None when undefined (both raters constant, equal)."""
    if len(a) != len(b):
        raise ValueError("raters must rate the same items")
    n = len(a)
    if n == 0:
        return None
    observed = sum(1 for x, y in zip(a, b, strict=True) if bool(x) == bool(y)) / n
    pa, pb = sum(map(bool, a)) / n, sum(map(bool, b)) / n
    expected = pa * pb + (1 - pa) * (1 - pb)
    if expected >= 1.0:
        return None
    return (observed - expected) / (1 - expected)


def average_ranks(xs: Sequence[float]) -> list[float]:
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def spearman(a: Sequence[float], b: Sequence[float]) -> float | None:
    """Spearman's rho with average ranks for ties; None if either side is constant."""
    if len(a) != len(b):
        raise ValueError("series must have the same length")
    if len(a) < 2:
        return None
    ra, rb = average_ranks(a), average_ranks(b)
    ma, mb = statistics.fmean(ra), statistics.fmean(rb)
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb, strict=True))
    va = sum((x - ma) ** 2 for x in ra)
    vb = sum((y - mb) ** 2 for y in rb)
    if va == 0 or vb == 0:
        return None
    return cov / math.sqrt(va * vb)


def mean_abs_diff(a: Sequence[float], b: Sequence[float]) -> float | None:
    if not a:
        return None
    return statistics.fmean(abs(x - y) for x, y in zip(a, b, strict=True))


def rate(values: Iterable[bool]) -> float | None:
    xs = [bool(v) for v in values]
    return sum(xs) / len(xs) if xs else None


def ranking_reversals(
    reference: dict[str, float | None], candidate: dict[str, float | None], gap: float = RANK_GAP
) -> list[tuple[str, str]]:
    """System pairs that the reference separates by at least `gap` and the candidate reverses."""
    out = []
    names = [s for s in reference if reference[s] is not None and candidate.get(s) is not None]
    for i, s in enumerate(names):
        for t in names[i + 1 :]:
            d_ref = reference[s] - reference[t]
            d_cand = candidate[s] - candidate[t]
            if abs(d_ref) >= gap and d_ref * d_cand < 0:
                out.append((s, t))
    return out


def compare_binary(pairs: list[tuple[str, bool, bool]], systems: Sequence[str]) -> dict[str, Any]:
    """Agreement of (system, reference, candidate) binary judgments, pooled and per system."""
    ref = [r for _, r, _ in pairs]
    cand = [c for _, _, c in pairs]
    per_system = {}
    for s in systems:
        rs = [(r, c) for sys_, r, c in pairs if sys_ == s]
        n = len(rs)
        r_rate = rate(r for r, _ in rs)
        c_rate = rate(c for _, c in rs)
        per_system[s] = {
            "n": n,
            "reference": r_rate,
            "candidate": c_rate,
            "delta": None if r_rate is None else c_rate - r_rate,
            "net_flips": sum(int(c) - int(r) for r, c in rs),
        }
    r_all, c_all = rate(ref), rate(cand)
    return {
        "n": len(pairs),
        "kappa": cohen_kappa(ref, cand),
        "agreement": rate(r == c for r, c in zip(ref, cand, strict=True)),
        "reference": r_all,
        "candidate": c_all,
        "delta": None if r_all is None else c_all - r_all,
        "ref_only": sum(1 for r, c in zip(ref, cand, strict=True) if r and not c),
        "cand_only": sum(1 for r, c in zip(ref, cand, strict=True) if c and not r),
        "per_system": per_system,
        "reversals": ranking_reversals(
            {s: v["reference"] for s, v in per_system.items()},
            {s: v["candidate"] for s, v in per_system.items()},
        ),
    }


def compare_ratio(
    items: list[tuple[str, int, int, int, int]], systems: Sequence[str]
) -> dict[str, Any]:
    """Utility agreement from (system, ref_sys, ref_ref, cand_sys, cand_ref) usefulness scores.

    The ratio is mean system usefulness / mean reference usefulness over the same items.
    """

    def ratio(rows: list[tuple[str, int, int, int, int]], sys_i: int, ref_i: int) -> float | None:
        if not rows:
            return None
        den = statistics.fmean(r[ref_i] for r in rows)
        return statistics.fmean(r[sys_i] for r in rows) / den if den else None

    per_system = {}
    for s in systems:
        rows = [r for r in items if r[0] == s]
        r_ratio, c_ratio = ratio(rows, 1, 2), ratio(rows, 3, 4)
        per_system[s] = {
            "n": len(rows),
            "reference": r_ratio,
            "candidate": c_ratio,
            "delta": None if r_ratio is None or c_ratio is None else c_ratio - r_ratio,
        }
    sys_ref = [r[1] for r in items]
    sys_cand = [r[3] for r in items]
    all_ref = sys_ref + [r[2] for r in items]
    all_cand = sys_cand + [r[4] for r in items]
    r_all, c_all = ratio(items, 1, 2), ratio(items, 3, 4)
    return {
        "n": len(items),
        "spearman_system": spearman(sys_ref, sys_cand),
        "mad_system": mean_abs_diff(sys_ref, sys_cand),
        "spearman_all": spearman(all_ref, all_cand),
        "mad_all": mean_abs_diff(all_ref, all_cand),
        "exact_all": rate(a == b for a, b in zip(all_ref, all_cand, strict=True)),
        "reference": r_all,
        "candidate": c_all,
        "delta": None if r_all is None or c_all is None else c_all - r_all,
        "per_system": per_system,
        "reversals": ranking_reversals(
            {s: v["reference"] for s, v in per_system.items()},
            {s: v["candidate"] for s, v in per_system.items()},
        ),
    }


def qualifies(
    cmp: dict[str, Any], kind: str, retest: dict[str, Any] | None = None
) -> tuple[bool, list[str]]:
    """Whether one headline comparison passes; the reasons when it does not.

    Pooled: |delta| <= max(tolerance, |Ultra retest delta|). Per system: |delta| within that
    tolerance, or (rates) at most one net flipped item. Ranking: no reversal of a pair Ultra
    separates by RANK_GAP.
    """
    base = RATIO_TOLERANCE if kind == "ratio" else RATE_TOLERANCE
    noise = abs((retest or {}).get("delta") or 0.0)
    tol = max(base, noise)
    reasons = []
    if not cmp.get("n"):
        return True, []  # the sample has no item for this metric: nothing to disagree on
    if cmp.get("delta") is None:
        return False, ["no comparable items"]
    if abs(cmp["delta"]) > tol + 1e-9:
        reasons.append(f"pooled delta {cmp['delta']:+.3f} beyond ±{tol:.3f}")
    for s, v in cmp["per_system"].items():
        if v.get("delta") is None:
            continue
        if kind == "ratio":
            sys_tol = max(RATIO_SYSTEM_TOLERANCE, noise)
            if abs(v["delta"]) > sys_tol + 1e-9:
                reasons.append(f"{s} delta {v['delta']:+.3f} beyond ±{sys_tol:.3f}")
        elif abs(v["delta"]) > tol + 1e-9 and abs(v["net_flips"]) > 1:
            reasons.append(f"{s} delta {v['delta'] * 100:+.1f}pp ({v['net_flips']:+d} items)")
    for s, t in cmp.get("reversals") or []:
        reasons.append(f"ranking of {s} vs {t} reversed")
    return not reasons, reasons


# --------------------------------------------------------------------------------------------
# Stored inputs
# --------------------------------------------------------------------------------------------


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


@dataclass
class Item:
    system: str
    case: dict[str, Any]
    record: dict[str, Any]
    attack_row: dict[str, Any] | None
    utility_row: dict[str, Any] | None
    system_text: str | None = None
    reference_text: str | None = None

    @property
    def key(self) -> str:
        return f"{self.system}:{self.case['id']}"

    @property
    def sent(self) -> bool:
        return bool((self.record.get("audit") or {}).get("outbound"))

    @property
    def sensitive(self) -> bool:
        return protected.case_protection(self.case)["situation_sensitive"]

    @property
    def judged(self) -> bool:
        u = self.utility_row or {}
        return bool(u.get("system") and u.get("reference") and self.reference_text is not None)


def load_system(name: str, dirname: str) -> dict[str, Item]:
    run_dir = RESULTS / dirname
    cases = {c["id"]: c for c in read_jsonl(run_dir / "cases_snapshot.jsonl")}
    records = {r["record"]["case_id"]: r["record"] for r in read_jsonl(run_dir / "pass_01.jsonl")}
    attacks = {r["case_id"]: r for r in read_jsonl(run_dir / "attack" / "pass_01.jsonl")}
    utilities = {r["case_id"]: r for r in read_jsonl(run_dir / "utility" / "pass_01.jsonl")}
    answers = {a["case_id"]: a for a in read_jsonl(run_dir / "utility" / "answers_pass_01.jsonl")}
    items = {}
    for cid, record in records.items():
        item = Item(name, cases[cid], record, attacks.get(cid), utilities.get(cid))
        u = item.utility_row or {}
        if u.get("system") and u.get("reference"):
            ref_file = utility.REFERENCE_DIR / (u.get("reference_file") or "")
            if ref_file.is_file():
                item.reference_text = json.loads(ref_file.read_text(encoding="utf-8"))["answer"]
            if u.get("answer_source") == "recorded":
                item.system_text = record.get("answer") or ""
            else:
                item.system_text = (answers.get(cid) or {}).get("answer") or ""
        items[cid] = item
    return items


def choose_cases(
    by_system: dict[str, dict[str, Item]], per_stratum: int, sensitive_extra: int, seed: int
) -> list[str]:
    """Case ids stratified by (category, language), usable in every system.

    Chat cases must have a stored utility judgment in every system; every case needs a stored
    attack row. Situation-sensitive categories get `sensitive_extra` more cases per stratum.
    """
    systems = list(by_system)
    first = by_system[systems[0]]
    strata: dict[tuple[str, str], list[str]] = {}
    for cid, item in sorted(first.items()):
        if not all(cid in by_system[s] and by_system[s][cid].attack_row for s in systems):
            continue
        if item.case["task"] == "chat" and not all(by_system[s][cid].judged for s in systems):
            continue
        strata.setdefault((item.case["category"], item.case["lang"]), []).append(cid)
    rng = random.Random(f"calibrate:{seed}")
    chosen = []
    for (category, _lang), ids in sorted(strata.items()):
        # Prefer chat cases in mixed strata (benign): they also exercise the utility judge.
        chat = [c for c in ids if first[c].case["task"] == "chat"]
        pool = chat or ids
        rng.shuffle(pool)
        k = per_stratum + (sensitive_extra if category in SENSITIVE_CATEGORIES else 0)
        chosen += pool[:k]
    return chosen


# --------------------------------------------------------------------------------------------
# Cached, budgeted calls
# --------------------------------------------------------------------------------------------


@dataclass
class Budget:
    cap: int
    used: int = 0
    reserved: int = 0
    skipped: int = 0

    def try_reserve(self, tokens: int) -> bool:
        if self.used + self.reserved + tokens > self.cap:
            self.skipped += 1
            return False
        self.reserved += tokens
        return True


@dataclass
class CallStore:
    """Every Token Factory call of the study, keyed by model and request content (resumable)."""

    path: Path
    budget: Budget
    client: Any = None
    sem: asyncio.Semaphore | None = None
    offline: bool = False
    rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    _llms: dict[str, attack.LLM] = field(default_factory=dict)

    def load(self) -> None:
        for row in read_jsonl(self.path):
            if not row.get("result", {}).get("error"):
                self.rows[row["key"]] = row

    def llm(self, model: str, role: str, subject: str) -> attack.LLM:
        """An attack.LLM for `model`, cached by request; usage tagged with role and subject."""

        async def call(messages, name, schema, reasoning, max_tokens):
            digest = hashlib.sha256(
                json.dumps([messages, name, reasoning, max_tokens], ensure_ascii=False).encode()
            ).hexdigest()[:24]
            key = f"{model}|{name}|{digest}"
            if key in self.rows:
                return self.rows[key]["result"]
            if self.offline:
                return {"content": "", "usage": {}, "error": "not cached", "model": model}
            est = sum(attack.estimate_tokens(m["content"]) for m in messages)
            est += min(max_tokens, 700)
            if not self.budget.try_reserve(est):
                return {"content": "", "usage": {}, "error": "budget", "model": model}
            try:
                if model not in self._llms:
                    self._llms[model] = attack.make_llm(self.client, model)
                async with self.sem:
                    result = await self._llms[model](messages, name, schema, reasoning, max_tokens)
            finally:
                self.budget.reserved -= est
            spent = sum(
                int(u.get("prompt_tokens") or 0) + int(u.get("completion_tokens") or 0)
                for u in attack.iter_usage(result)
            )
            self.budget.used += spent
            row = {
                "key": key,
                "model": model,
                "role": role,
                "subject": subject,
                "name": name,
                "at": datetime.now(UTC).isoformat(),
                "result": result,
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            if not result.get("error"):
                self.rows[key] = row
            return result

        return call


# --------------------------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------------------------

NONE_OPTS = argparse.Namespace(attacker_reasoning="none", grader_reasoning="none")


def tracked(llm: attack.LLM, errors: list[str]) -> attack.LLM:
    """The same LLM, recording every call error (budget, not cached, HTTP) into `errors`."""

    async def call(messages, name, schema, reasoning, max_tokens):
        result = await llm(messages, name, schema, reasoning, max_tokens)
        if result.get("error"):
            errors.append(result["error"])
        return result

    return call


def ultra_attack(item: Item) -> dict[str, Any]:
    raw = (item.attack_row.get("attacker") or {}).get("raw")
    return attack.normalize_attack(attack.parse_json_object(raw))


def attack_item_metrics(item: Item, score: dict[str, Any]) -> dict[str, Any]:
    quasi = score.get("quasi")
    return {
        "values": [v["match"] == "exact" for v in score["values"]],
        "attack_quasi_reid_rate": quasi["reidentified"] if quasi else None,
        "attack_identity_recovery_rate": score.get("identity_recovered"),
        "situation_inference_rate": score.get("situation_inferred"),
        "linkable_disclosure_rate": score.get("linkable"),
        "attack_intent_inference_rate": score.get("intent_inferred"),
    }


def reference_attack_metrics(item: Item) -> dict[str, Any]:
    return attack_item_metrics(item, attack.rescore_row(item.case, item.attack_row))


async def run_attacker(store: CallStore, item: Item, model: str, label: str) -> dict[str, Any]:
    """Candidate attacker, graded by the Ultra grader, scored deterministically."""
    errors: list[str] = []
    llm = tracked(store.llm(model, "attack", label), errors)
    grader = tracked(store.llm(attack.ULTRA, "attack", label), errors)
    row = await attack.attack_one(item.case, item.record, llm, NONE_OPTS, grader)
    metrics = attack_item_metrics(item, row["score"])
    metrics["_missing"] = bool(errors)
    metrics["_unparsed"] = bool(row.get("sent")) and not (row.get("attacker") or {}).get(
        "parsed_ok"
    )
    return metrics


async def run_grader(store: CallStore, item: Item, model: str, label: str) -> dict[str, Any]:
    """Candidate intent and situation graders on Ultra's stored attacker output."""
    errors: list[str] = []
    llm = tracked(store.llm(model, "grader", label), errors)
    base = attack.rescore_row(item.case, item.attack_row)
    if not item.sent:
        return attack_item_metrics(item, base) | {"_missing": False, "_unparsed": False}
    inferred = ultra_attack(item)
    has_inference = bool(inferred["private_situation"].strip() or inferred["person_attributes"])
    row: dict[str, Any] = {}
    intent = None
    unparsed = False
    if item.case.get("category") == "intent_leak_search":
        intent = False
        if has_inference:
            reply = await llm(
                attack.grader_messages(item.case, inferred),
                "grade",
                attack.GRADER_SCHEMA,
                "none",
                attack.GRADER_MAX_TOKENS,
            )
            intent = attack.parse_grade(reply.get("content"))
            unparsed |= intent is None and not reply.get("error")
    situation = None
    if item.sensitive:
        situation = await attack.grade_situation(item.case, inferred, row, llm, "none")
        grader_row = row.get("situation_grader") or {}
        unparsed |= bool(grader_row) and situation is None and not grader_row.get("error")
    score = attack.score_attack(item.case, inferred, intent, situation)
    return attack_item_metrics(item, score) | {"_missing": bool(errors), "_unparsed": unparsed}


def reference_utility(item: Item) -> dict[str, Any]:
    u = item.utility_row
    return {
        "sys_use": u["system"]["usefulness"],
        "ref_use": u["reference"]["usefulness"],
        "distortion_flag_system": bool(u["system"].get("distortion_judge", False))
        or bool(u["system"].get("distortion")),
        "distortion_flag_reference": bool(u["reference"].get("distortion_judge", False))
        or bool(u["reference"].get("distortion")),
        "distortion_rate": bool(u["system"].get("distortion")),
        "system_empty": bool(u.get("system_empty")),
    }


def flagged(item: Item) -> bool:
    return any(item.utility_row[s].get("distortion_judge") for s in ("system", "reference"))


def judge_inputs(item: Item) -> tuple[list[dict[str, str]], bool]:
    system_first = item.utility_row.get("system_shown_as") == "Answer 1"
    sys_text, ref_text = item.system_text or "", item.reference_text or ""
    a1, a2 = (sys_text, ref_text) if system_first else (ref_text, sys_text)
    return utility.judge_messages(item.case, a1, a2), system_first


async def run_judge(
    store: CallStore, item: Item, model: str, confirm_model: str, label: str
) -> dict[str, Any]:
    """Candidate utility judge on the stored pair; its flags confirmed by `confirm_model`."""
    messages, system_first = judge_inputs(item)
    errors: list[str] = []
    reply = await tracked(store.llm(model, "utility", label), errors)(
        messages, "utility_judge", utility.JUDGE_SCHEMA, "none", utility.JUDGE_MAX_TOKENS
    )
    grades = utility.parse_judgment(reply.get("content"))
    out: dict[str, Any] = {"_missing": bool(errors), "_unparsed": False}
    if grades is None:
        out["_unparsed"] = not reply.get("error")
        return out
    sys_grade, ref_grade = (dict(g) for g in utility.assign(grades, system_first))
    empty = not (item.system_text or "").strip()
    out.update(
        {
            "sys_use": 1 if empty else sys_grade["usefulness"],
            "ref_use": ref_grade["usefulness"],
            "distortion_flag_system": (not empty) and sys_grade["distortion"],
            "distortion_flag_reference": ref_grade["distortion"],
        }
    )
    await utility.verify_distortions(
        tracked(store.llm(confirm_model, "utility", label), errors),
        utility.render_request(item.case["messages"]),
        [(sys_grade, item.system_text or ""), (ref_grade, item.reference_text or "")],
    )
    out["_missing"] = bool(errors)
    out["distortion_rate"] = (not empty) and bool(sys_grade["distortion"])
    return out


async def run_confirm(store: CallStore, item: Item, model: str, label: str) -> dict[str, Any]:
    """Candidate confirmation of the distortions Ultra's judge flagged on this item."""
    u = item.utility_row
    request = utility.render_request(item.case["messages"])
    confirmed_pairs = []
    final_system = bool(u["system"].get("distortion"))
    errors: list[str] = []
    llm = tracked(store.llm(model, "distortion_confirm", label), errors)
    unparsed = False
    for side, text in (("system", item.system_text or ""), ("reference", item.reference_text)):
        grade = u[side]
        if not grade.get("distortion_judge"):
            continue
        if u.get("system_empty") and side == "system":
            continue
        reply = await llm(
            utility.verify_messages(request, text or "", grade.get("distortion_detail") or ""),
            "verify_distortion",
            utility.VERIFY_SCHEMA,
            "none",
            utility.VERIFY_MAX_TOKENS,
        )
        ok = utility.parse_verification(reply.get("content"))
        unparsed |= ok is None and not reply.get("error")
        confirmed_pairs.append((bool(grade.get("distortion_verified")), bool(ok)))
        if side == "system":
            final_system = bool(ok)
    return {
        "confirmed": confirmed_pairs,
        "distortion_rate": final_system,
        "_missing": bool(errors),
        "_unparsed": unparsed,
    }


# --------------------------------------------------------------------------------------------
# Estimate
# --------------------------------------------------------------------------------------------


def estimate_item(item: Item, runs_per_role: dict[str, int]) -> dict[str, int]:
    """Token estimate for one item across the models run for each role (retest included).

    Checked against stored Ultra usage: judge prompts estimate 2,597 tokens vs 2,672 measured,
    attacker prompts 622 vs 596.
    """
    tok = attack.estimate_tokens
    out = dict.fromkeys(ROLES, 0)
    if item.sent and item.attack_row:
        outbound = item.record["audit"]["outbound"]
        prompt = sum(tok(m["content"]) for m in attack.attacker_messages(outbound))
        usage = (item.attack_row.get("attacker") or {}).get("usage") or {}
        completion = max(int(usage.get("completion_tokens") or 0), 350)
        grade = attack.situation_prompt_estimate(item.case) + 120
        per_grade = (1 if item.sensitive else 0) + (
            1 if item.case["category"] == "intent_leak_search" else 0
        )
        # 15% of attacks retry with reasoning on (measured on Ultra: 27-41 of 243).
        out["attack"] = runs_per_role["attack"] * int(
            prompt + completion + 0.15 * (prompt + 2500) + per_grade * grade
        )
        out["grader"] = runs_per_role["grader"] * per_grade * grade
    if item.judged:
        messages, _ = judge_inputs(item)
        judge = sum(tok(m["content"]) for m in messages) + 300
        flags = sum(
            1 for g in (item.utility_row["system"], item.utility_row["reference"])
            if g.get("distortion_judge")
        )  # fmt: skip
        verify = tok(utility.VERIFY_SYSTEM) + judge // 2 + 120
        out["utility"] = runs_per_role["utility"] * (judge + max(flags, 1) * verify)
        out["distortion_confirm"] = runs_per_role["distortion_confirm"] * flags * verify
    return out


# --------------------------------------------------------------------------------------------
# Analysis and report
# --------------------------------------------------------------------------------------------


def binary_pairs(
    results: dict[str, dict[str, Any]],
    refs: dict[str, dict[str, Any]],
    items: dict[str, Item],
    metric: str,
) -> list[tuple[str, bool, bool]]:
    pairs = []
    for key, res in results.items():
        if res.get("_missing") or key not in refs:
            continue
        ref, cand = refs[key].get(metric), res.get(metric)
        if metric == "values":
            pairs += [(items[key].system, r, c) for r, c in zip(ref or [], cand or [], strict=True)]
        elif metric == "confirmed":
            pairs += [(items[key].system, r, c) for r, c in cand or []]
        elif ref is not None and cand is not None:
            pairs.append((items[key].system, bool(ref), bool(cand)))
    return pairs


def analyze_role(
    role: str,
    results: dict[str, dict[str, dict[str, Any]]],
    refs: dict[str, dict[str, Any]],
    items: dict[str, Item],
    systems: Sequence[str],
) -> dict[str, Any]:
    """Per model (candidates and retest): headline comparisons, extras, qualification."""
    out: dict[str, Any] = {}
    for label, res in results.items():
        usable = {k: v for k, v in res.items() if not v.get("_missing")}
        entry: dict[str, Any] = {
            "items": len(usable),
            "missing": len(res) - len(usable),
            "unparsed": sum(1 for v in usable.values() if v.get("_unparsed")),
            "headlines": {},
            "extras": {},
        }
        for metric, kind in HEADLINES[role]:
            if kind == "ratio":
                rows = [
                    (items[k].system, refs[k]["sys_use"], refs[k]["ref_use"], v["sys_use"],
                     v["ref_use"])
                    for k, v in usable.items()
                    if k in refs and "sys_use" in v
                ]  # fmt: skip
                entry["headlines"][metric] = compare_ratio(rows, systems)
            else:
                source = "values" if kind == "value_rate" else metric
                pairs = binary_pairs(usable, refs, items, source)
                entry["headlines"][metric] = compare_binary(pairs, systems)
        for metric in EXTRA_BINARY[role]:
            entry["extras"][metric] = compare_binary(
                binary_pairs(usable, refs, items, metric), systems
            )
        out[label] = entry
    retest = out.get(RETEST)
    for label, entry in out.items():
        ok_all, reasons = True, []
        for metric, kind in HEADLINES[role]:
            noise = None if label == RETEST or not retest else retest["headlines"].get(metric)
            ok, why = qualifies(entry["headlines"][metric], kind, noise)
            ok_all &= ok
            reasons += [f"{metric}: {w}" for w in why]
        if entry["items"] and entry["unparsed"] / entry["items"] > MAX_UNPARSED:
            ok_all = False
            reasons.append(f"unparsed replies {entry['unparsed']}/{entry['items']}")
        entry["qualifies"] = ok_all and entry["items"] > 0
        entry["reasons"] = reasons
    return out


def spend(store_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Tokens and USD per (role, subject model, billed model), plus per-call averages."""
    table: dict[tuple[str, str, str], dict[str, float]] = {}
    for row in store_rows:
        t = table.setdefault(
            (row["role"], row["subject"], row["model"]),
            {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "usd": 0.0},
        )
        t["calls"] += 1
        for u in attack.iter_usage(row["result"]):
            t["prompt_tokens"] += int(u.get("prompt_tokens") or 0)
            t["completion_tokens"] += int(u.get("completion_tokens") or 0)
            t["usd"] += attack.usage_cost(row["model"], u) or 0.0
    total = {
        "prompt_tokens": sum(v["prompt_tokens"] for v in table.values()),
        "completion_tokens": sum(v["completion_tokens"] for v in table.values()),
        "usd": sum(v["usd"] for v in table.values()),
    }
    return {
        "rows": [
            {"role": r, "subject": s, "model": m, **v} for (r, s, m), v in sorted(table.items())
        ],
        "total": total,
    }


def effective_analysis(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The main analysis with every extension's entries replacing the same role and model."""
    merged = {role: dict(entries) for role, entries in report["analysis"].items()}
    for ext in report.get("extensions") or []:
        for role, entries in ext["analysis"].items():
            merged.setdefault(role, {}).update(entries)
    return merged


def recommend(analysis: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Cheapest qualifying candidate per role; else Ultra.

    Cheapest by output price, then input price; equal prices go to the model whose headline
    deltas sum closest to Ultra.
    """
    chosen = {}
    for role in ROLES:
        ok = [
            m
            for m, e in analysis.get(role, {}).items()
            if m != RETEST and m in attack.MODEL_PRICES and e["qualifies"]
        ]
        entries = analysis.get(role, {})
        ok.sort(
            key=lambda m: (
                attack.MODEL_PRICES[m][1],
                attack.MODEL_PRICES[m][0],
                sum(abs(h.get("delta") or 0.0) for h in entries[m].get("headlines", {}).values()),
                m,
            )
        )
        chosen[role] = ok[0] if ok else attack.ULTRA
    return chosen


def short(model: str) -> str:
    return {
        attack.ULTRA: "Ultra",
        attack.SUPER: "Super",
        attack.LIGHTNING: "Lightning",
        attack.NANO: "Nano",
        RETEST: "Ultra retest",
    }.get(model, model)


def fmt(v: float | None, kind: str = "num", signed: bool = False) -> str:
    if v is None:
        return "n/a"
    if kind == "pct":
        return f"{v * 100:+.1f}pp" if signed else f"{v * 100:.1f}%"
    return f"{v:+.2f}" if signed else f"{v:.2f}"


ROLE_TITLES = {
    "attack": "Attacker (value recovery, quasi re-identification, identity, situation, linkable)",
    "grader": "Intent and situation grader",
    "utility": "Utility judge (usefulness 1-5 and distortion flag)",
    "distortion_confirm": "Distortion confirmation",
}
METRIC_TITLES = {
    "attack_value_recovery_rate": "values recovered",
    "attack_quasi_reid_rate": "quasi re-id",
    "attack_identity_recovery_rate": "identity recovered",
    "situation_inference_rate": "situation inferred",
    "linkable_disclosure_rate": "linkable disclosure",
    "attack_intent_inference_rate": "intent inferred",
    "utility_ratio_vs_reference": "utility ratio",
    "distortion_rate": "distortion (confirmed)",
    "distortion_flag_system": "distortion flag, system answer",
    "distortion_flag_reference": "distortion flag, reference answer",
    "confirmed": "confirmation verdict",
}


def render_report(report: dict[str, Any]) -> str:
    analysis = report["analysis"]
    lines = [
        "# Judge model calibration",
        "",
        f"Generated by `uv run eval/calibrate_judges.py` on {report['generated_at'][:10]}. "
        "Every score in the comparison tables so far was made by Nemotron 3 Ultra "
        f"(`{attack.ULTRA}`, $1.00 / $3.00 per 1M input / output tokens). This study re-runs "
        "each scoring role on a stratified sample of stored items with cheaper Token Factory "
        "models and asks one question: would any headline number or the ranking of systems "
        "move by more than about 3 percentage points?",
        "",
        "## Recommended assignment",
        "",
        "| Role | Environment variable | Model | Price in / out ($/1M) |",
        "|---|---|---|---:|",
    ]
    for role, model in report["recommendation"].items():
        p = attack.MODEL_PRICES.get(model, (float("nan"), float("nan")))
        lines.append(
            f"| {role} | `{attack.ROLE_ENV[role]}` | `{model}` | {p[0]:.2f} / {p[1]:.2f} |"
        )
    lines += [
        "",
        "Rule: the cheapest candidate whose every headline rate for the role stays within "
        f"±{RATE_TOLERANCE * 100:.0f}pp of Ultra pooled over the sample (±{RATIO_TOLERANCE:.2f} "
        "for the utility ratio), within that tolerance per system or at most one net flipped "
        f"item (utility ratio: ±{RATIO_SYSTEM_TOLERANCE:.2f} per system), with no pair of "
        f"systems that Ultra separates by {RANK_GAP * 100:.0f}pp or more changing order, and "
        f"with at most {MAX_UNPARSED * 100:.0f}% unparsed replies. When Ultra's own retest "
        "moves a number by more than the tolerance, the tolerance widens to that noise. Ultra "
        "stays for a role no candidate passes. Every role can be switched back with its "
        "environment variable or flag (`--attack-model`, `--grader-model`, `--judge-model`, "
        "`--confirm-model`).",
        "",
        *render_outcome(report),
        *render_projection(report["recommendation"]),
        "## Sample",
        "",
        f"Cases are stratified by category and language (seed {report['sample']['seed']}): "
        f"{report['sample']['per_stratum']} per stratum plus "
        f"{report['sample']['sensitive_extra']} more in the situation-sensitive categories "
        f"({', '.join(SENSITIVE_CATEGORIES)}). The graders and the confirmation are cheap and "
        "use every sampled case; the attacker and the utility judge use a subset shrunk to fit "
        "the token cap. The utility roles leave out `raw`: its answer and the reference answer "
        "come from the same prompt.",
        "",
        "| Role | Systems | Cases | Items | Ultra retest |",
        "|---|---|---:|---:|---|",
        *[
            f"| {role} | {', '.join(r['systems'])} | {len(r['cases'])} | {r['items']} | "
            f"{'yes' if RETEST in report['models'][role] else 'no'} |"
            for role, r in report["role_samples"].items()
        ],
        "",
        "- Ultra reference: the stored Ultra outputs in `eval/results/<system>/attack` and "
        "`utility` (pass 1). `Ultra retest` re-runs the same role with Ultra to show its own "
        "noise.",
        f"- Case ids: {', '.join(report['cases'])} (attacker and utility subset: "
        f"{', '.join(report['role_samples']['attack']['cases'])})",
        "- Adapters: every call runs with thinking off (Ultra `reasoning_effort: none`; the "
        "others `chat_template_kwargs.enable_thinking: false`), temperature 0. Super ignores "
        "`json_schema` response formats, so it runs in JSON mode with the schema in the prompt; "
        "every reply is validated locally and retried once if it does not match.",
        "",
        "## Agreement summary",
        "",
        "Kappa: Cohen's kappa against the stored Ultra judgment. Delta: candidate minus Ultra, "
        "pooled over the sample. `ok` means the model qualifies for the role.",
        "",
    ]
    for role in ROLES:
        if role not in analysis:
            continue
        lines += [f"### {ROLE_TITLES[role]}", ""]
        heads = HEADLINES[role]
        header = ["Model", "Items"]
        for metric, kind in heads:
            name = METRIC_TITLES[metric]
            if kind == "ratio":
                header += [f"{name}: Spearman (system / all)", "MAD (system / all)", "delta"]
            else:
                header += [f"{name}: kappa", "delta"]
        header += ["Unparsed", "Qualifies"]
        lines += ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
        for label, e in analysis[role].items():
            cells = [f"{short(label)}", str(e["items"])]
            for metric, kind in heads:
                h = e["headlines"][metric]
                if kind == "ratio":
                    cells += [
                        f"{fmt(h['spearman_system'])} / {fmt(h['spearman_all'])}",
                        f"{fmt(h['mad_system'])} / {fmt(h['mad_all'])}",
                        fmt(h["delta"], signed=True),
                    ]
                else:
                    cells += [fmt(h["kappa"]), fmt(h["delta"], "pct", signed=True)]
            superseded = any(
                label in (ext["analysis"].get(role) or {}) for ext in report.get("extensions") or []
            )
            verdict = "ok" if e["qualifies"] else "no"
            cells += [str(e["unparsed"]), verdict + (" (see follow-up)" if superseded else "")]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
        for label, e in analysis[role].items():
            if e["reasons"] and label != RETEST:
                lines.append(f"- {short(label)} fails: " + "; ".join(e["reasons"][:6]))
        extras = [
            (label, metric, c)
            for label, e in analysis[role].items()
            for metric, c in e["extras"].items()
            if c["n"]
        ]
        if extras:
            lines.append("- informational kappas: " + "; ".join(
                f"{short(label)} {METRIC_TITLES[m]} {fmt(c['kappa'])} (n={c['n']}, "
                f"delta {fmt(c['delta'], 'pct', signed=True)})"
                for label, m, c in extras
            ))  # fmt: skip
        lines.append("")
    lines += [
        "## Aggregate rates per system",
        "",
        "Ultra (stored) vs each model on the same sample items. The comparison tables report "
        "these numbers per system; the question is whether any of them moves.",
        "",
    ]
    for role in ROLES:
        if role not in analysis:
            continue
        for metric, kind in HEADLINES[role]:
            lines += [
                f"### {role}: {METRIC_TITLES[metric]}",
                "",
                "| System | n | Ultra | " + " | ".join(short(m) for m in analysis[role]) + " |",
                "|---|---:|---:|" + "---:|" * len(analysis[role]),
            ]
            first = next(iter(analysis[role].values()))["headlines"][metric]
            for s in report["role_samples"][role]["systems"]:
                ref = first["per_system"][s]["reference"]
                cells = [s, str(first["per_system"][s]["n"])]
                cells.append(fmt(ref, "num" if kind == "ratio" else "pct"))
                for e in analysis[role].values():
                    v = e["headlines"][metric]["per_system"][s]
                    k = "num" if kind == "ratio" else "pct"
                    cells.append(f"{fmt(v['candidate'], k)} ({fmt(v['delta'], k, signed=True)})")
                lines.append("| " + " | ".join(cells) + " |")
            lines.append("")
    sp = report["spend"]
    lines += [
        "## Calibration spend",
        "",
        f"Total: {sp['total']['prompt_tokens']:,} prompt + {sp['total']['completion_tokens']:,} "
        f"completion tokens, ${sp['total']['usd']:.2f} at list prices (cap "
        f"{report['max_tokens']:,} tokens). Adapter probes before the study used about "
        f"{report['probe_tokens']:,} more tokens. `Billed` is the model that made the call; "
        "the Ultra rows under a candidate are the Ultra graders that scored that candidate's "
        "attacks.",
        "",
        "| Role | Model under test | Billed | Calls | Prompt | Completion | Completion / call "
        "| USD |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in sp["rows"]:
        lines.append(
            f"| {r['role']} | {short(r['subject'])} | {short(r['model'])} | {r['calls']:,} | "
            f"{r['prompt_tokens']:,} | {r['completion_tokens']:,} | "
            f"{r['completion_tokens'] / max(r['calls'], 1):.0f} | {r['usd']:.3f} |"
        )
    for ext in report.get("extensions") or []:
        lines += ["", *render_extension(ext)]
    lines += ["", "## Caveats", ""]
    lines += [f"- {c}" for c in report["caveats"]]
    lines.append("")
    return "\n".join(lines)


def render_outcome(report: dict[str, Any]) -> list[str]:
    merged = effective_analysis(report)
    lines = ["### Outcome", ""]
    for role in ROLES:
        entries = {m: e for m, e in merged.get(role, {}).items() if m != RETEST}
        if not entries:
            continue
        passed = [short(m) for m, e in entries.items() if e["qualifies"]]
        deltas = []
        for m, e in entries.items():
            worst = max(
                (
                    (abs(h["delta"]), metric, h["delta"], kind)
                    for (metric, kind) in HEADLINES[role]
                    if (h := e["headlines"][metric]).get("n") and h.get("delta") is not None
                ),
                default=None,
            )
            if worst:
                k = "num" if worst[3] == "ratio" else "pct"
                deltas.append(
                    f"{short(m)} {METRIC_TITLES[worst[1]]} {fmt(worst[2], k, signed=True)}"
                )
        verdict = f"qualifies: {', '.join(passed)}" if passed else "no candidate qualifies"
        lines.append(
            f"- **{role}**: {verdict}. Largest pooled move per candidate: {'; '.join(deltas)}."
        )
    if all(m == attack.ULTRA for m in report["recommendation"].values()):
        lines += [
            "",
            "Every candidate moves at least one headline number of its role beyond the "
            "tolerance, so Nemotron 3 Ultra stays the default for all four roles. The cost has "
            "to come down through the size of the protocol instead (next table).",
        ]
    lines.append("")
    return lines


def render_projection(recommendation: dict[str, str]) -> list[str]:
    """Projected final-protocol tokens and dollars (eval/protocol_estimate.py variants)."""
    import protocol_estimate as pe

    lines = [
        "### Projected final protocol cost",
        "",
        "From `eval/protocol_estimate.py --variants` (typical completion lengths measured on the "
        "stored runs; list prices). Airlock upstream answers are Ultra calls and are included. "
        "Airlock passes are assumed to differ (the local detector samples at temperature 0.6); "
        "the four deterministic baselines are scored once, their identical passes reused by "
        "payload hash (`eval/reuse.py`), or reused entirely from the committed runs.",
        "",
        "| Variant | Airlock upstream | Airlock scoring | Total, baselines scored once | "
        "Total, baselines reused from committed runs | Total without reuse |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    def cell(tokens: float, usd: float) -> str:
        return f"{tokens / 1e6:.1f}M, ${usd:.2f}"

    for r in pe.variant_rows(recommendation):
        up = r["airlock_upstream"]
        up_tokens = up["prompt"] + up["completion_typical"]
        a = r["airlock"]
        lines.append(
            f"| {r['variant']} | {cell(up_tokens, up['usd'])} | "
            f"{cell(a['tokens'] - up_tokens, a['usd'] - up['usd'])} | "
            f"{cell(r['total_once']['tokens'], r['total_once']['usd'])} | "
            f"{cell(r['total_reused']['tokens'], r['total_reused']['usd'])} | "
            f"{cell(r['total_no_reuse']['tokens'], r['total_no_reuse']['usd'])} |"
        )
    lines.append("")
    return lines


def render_extension(ext: dict[str, Any]) -> list[str]:
    lines = [
        f"## Follow-up: {', '.join(ext['analysis'])} on a larger sample (`{ext['tag']}`)",
        "",
        f"Same method, {ext['sample']['per_stratum']} cases per stratum; these results replace "
        "the ones above for the same role and model in the recommendation.",
        "",
        "| Role | Model | Items | Headline | Kappa | Delta | Informational | Qualifies |",
        "|---|---|---:|---|---:|---:|---|---|",
    ]
    for role, entries in ext["analysis"].items():
        for label, e in entries.items():
            for metric, kind in HEADLINES[role]:
                h = e["headlines"][metric]
                k = "num" if kind == "ratio" else "pct"
                info = "; ".join(
                    f"{METRIC_TITLES[m]} kappa {fmt(c['kappa'])} (n={c['n']}, "
                    f"{c['ref_only']} Ultra-only, {c['cand_only']} candidate-only)"
                    for m, c in e["extras"].items()
                    if c["n"]
                )
                lines.append(
                    f"| {role} | {short(label)} | {e['items']} | {METRIC_TITLES[metric]} | "
                    f"{fmt(h.get('kappa'))} | {fmt(h['delta'], k, signed=True)} | {info} | "
                    f"{'ok' if e['qualifies'] else 'no: ' + '; '.join(e['reasons'][:3])} |"
                )
            per = [
                f"{s} {fmt(v['reference'], 'pct')} -> {fmt(v['candidate'], 'pct')} (n={v['n']})"
                for s, v in e["headlines"][HEADLINES[role][0][0]]["per_system"].items()
            ]
            lines.append(f"| | | | per system: {'; '.join(per)} | | | | |")
    lines += ["", "Its calls are included in the calibration spend above."]
    return lines


CAVEATS = [
    "Small sample. Per-system rates rest on a handful of items (see `n`), so a single flipped "
    "item moves a per-system rate by several points. The pooled deltas and kappas are the "
    "stronger evidence; the per-system rule allows one net flip for that reason.",
    "One stored Ultra sample is the reference. Ultra at temperature 0 is not fully "
    "deterministic; the retest rows show how much Ultra disagrees with itself, and the "
    "tolerance widens to that noise.",
    "The attacker sets the privacy numbers' ceiling. A weaker attacker makes every system look "
    "safer, which is why the attacker role is judged on the recovery rates themselves, not only "
    "on agreement.",
    "Isolated roles. The grader is measured on Ultra's attacker outputs and the confirmation on "
    "Ultra's flags. Combining a cheaper attacker with a cheaper grader was not measured "
    "separately; the attacker check already uses the Ultra grader.",
    "Thinking is off for every model, matching how the stored Ultra scores were made. With "
    "thinking on the candidates might agree more, at several times the completion tokens.",
    "Same model family. All candidates are Nemotron 3 variants, so shared biases with Ultra "
    "would not show up as disagreement.",
]


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------


async def run_study(opts: argparse.Namespace) -> None:
    systems = list(opts.systems)
    utility_systems = [s for s in opts.utility_systems if s in systems]
    by_system = {s: load_system(s, SYSTEMS[s]) for s in systems}
    all_cases = opts.case_ids or choose_cases(
        by_system, opts.per_stratum, opts.sensitive_extra, opts.seed
    )
    base_cases = list(all_cases)
    role_models = {
        role: list(opts.candidates) + ([RETEST] if role in opts.retest_roles else [])
        for role in ROLES
    }
    runs_per_role = {role: len(m) for role, m in role_models.items()}
    items = {by_system[s][c].key: by_system[s][c] for c in all_cases for s in systems}

    def role_items(role: str, base: list[str]) -> list[Item]:
        """The items one role scores: its cases, its systems and its eligibility."""
        cases = set(base if role in ("attack", "utility") else all_cases)
        role_systems = utility_systems if role in ("utility", "distortion_confirm") else systems
        eligible: dict[str, Callable[[Item], bool]] = {
            "attack": lambda i: bool(i.attack_row),
            "grader": lambda i: i.sensitive and bool(i.attack_row),
            "utility": lambda i: i.judged,
            "distortion_confirm": lambda i: i.judged,
        }
        return [
            i
            for i in items.values()
            if i.case["id"] in cases and i.system in role_systems and eligible[role](i)
        ]

    def estimate(base: list[str]) -> dict[str, int]:
        return {
            role: sum(estimate_item(i, runs_per_role)[role] for i in role_items(role, base))
            for role in opts.roles
        }

    target = int(opts.max_tokens * opts.estimate_share)
    est = estimate(base_cases)
    while sum(est.values()) > target and len(base_cases) > 8:
        # Drop the last-chosen case of the most-populated (category, language) stratum.
        counts: dict[tuple[str, str], int] = {}
        for cid in base_cases:
            case = items[f"{systems[0]}:{cid}"].case
            k = (case["category"], case["lang"])
            counts[k] = counts.get(k, 0) + 1
        worst = max(counts, key=lambda k: (counts[k], k))
        drop = next(
            cid
            for cid in reversed(base_cases)
            if (items[f"{systems[0]}:{cid}"].case["category"],
                items[f"{systems[0]}:{cid}"].case["lang"]) == worst
        )  # fmt: skip
        base_cases.remove(drop)
        est = estimate(base_cases)
    samples = {role: role_items(role, base_cases) for role in ROLES}
    print(
        f"calibration sample: {len(all_cases)} cases (attacker and utility judge: "
        f"{len(base_cases)}); candidates {', '.join(short(m) for m in opts.candidates)}; "
        f"Ultra retest for {', '.join(opts.retest_roles) or 'no role'}",
        file=sys.stderr,
    )
    for role, v in est.items():
        print(
            f"  estimate {role:20s} {len(samples[role]):3d} items x {runs_per_role[role]} "
            f"models ~{v:,} tokens",
            file=sys.stderr,
        )
    print(
        f"  estimate total ~{sum(est.values()):,} tokens (target {target:,}; hard cap "
        f"{opts.max_tokens:,})",
        file=sys.stderr,
    )
    if opts.dry_run:
        return
    opts.out.mkdir(parents=True, exist_ok=True)
    store = CallStore(opts.out / "calls.jsonl", Budget(opts.max_tokens))
    store.load()
    store.budget.used = sum(
        int(u.get("prompt_tokens") or 0) + int(u.get("completion_tokens") or 0)
        for row in read_jsonl(store.path)
        for u in attack.iter_usage(row["result"])
    )
    if store.budget.used:
        print(f"  already spent {store.budget.used:,} tokens (cached calls)", file=sys.stderr)
    store.offline = opts.report_only
    if not opts.report_only and not opts.yes:
        print(
            "  not running: pass --yes to make these calls (synthetic data only)", file=sys.stderr
        )
        return

    import httpx

    key = attack.read_env_key()
    if not opts.report_only and not key:
        raise SystemExit("NEBIUS_API_KEY is not set (environment or .env)")
    results: dict[str, dict[str, dict[str, dict[str, Any]]]] = {r: {} for r in ROLES}
    async with httpx.AsyncClient(
        base_url=opts.base_url,
        headers={"Authorization": f"Bearer {key or ''}"},
        timeout=httpx.Timeout(opts.timeout, connect=15.0),
    ) as client:
        store.client = client
        store.sem = asyncio.Semaphore(opts.concurrency)

        def subject(label: str) -> str:
            return attack.ULTRA if label == RETEST else label

        runners: dict[str, Callable[[Item, str], Any]] = {
            "grader": lambda i, m: run_grader(store, i, subject(m), m),
            "distortion_confirm": lambda i, m: run_confirm(store, i, subject(m), m),
            "utility": lambda i, m: run_judge(store, i, subject(m), subject(m), m),
            "attack": lambda i, m: run_attacker(store, i, subject(m), m),
        }
        # Cheapest roles first, so the hard cap would cut the expensive ones.
        for role in [
            r for r in ("grader", "distortion_confirm", "utility", "attack") if r in opts.roles
        ]:
            for label in role_models[role]:
                t0 = datetime.now(UTC)
                chosen = samples[role]
                outs = await asyncio.gather(*(runners[role](i, label) for i in chosen))
                results[role][label] = {i.key: o for i, o in zip(chosen, outs, strict=True)}
                secs = (datetime.now(UTC) - t0).total_seconds()
                print(
                    f"  {role} {short(label)}: {len(chosen)} items, spent so far "
                    f"{store.budget.used:,} tokens ({secs:.0f}s)",
                    file=sys.stderr,
                )

    refs: dict[str, dict[str, dict[str, Any]]] = {
        "attack": {k: reference_attack_metrics(i) for k, i in items.items() if i.attack_row},
        "utility": {k: reference_utility(i) for k, i in items.items() if i.judged},
    }
    refs["grader"] = refs["attack"]
    refs["distortion_confirm"] = refs["utility"]
    role_systems = {
        role: utility_systems if role in ("utility", "distortion_confirm") else systems
        for role in ROLES
    }
    analysis = {
        role: analyze_role(role, results[role], refs[role], items, role_systems[role])
        for role in opts.roles
    }
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "cases": all_cases,
        "models": role_models,
        "sample": {
            "per_stratum": opts.per_stratum,
            "sensitive_extra": opts.sensitive_extra,
            "seed": opts.seed,
        },
        "role_samples": {
            role: {
                "systems": role_systems[role],
                "cases": sorted({i.case["id"] for i in samples[role]}),
                "items": len(samples[role]),
            }
            for role in opts.roles
        },
        "tag": opts.tag,
        "estimate": est,
        "max_tokens": opts.max_tokens,
        "probe_tokens": opts.probe_tokens,
        "budget_skipped_calls": store.budget.skipped,
        "missing_items": {
            role: {short(m): e["missing"] for m, e in analysis[role].items()} for role in opts.roles
        },
        "analysis": analysis,
        "recommendation": {},
        "spend": spend(read_jsonl(store.path)),
        "caveats": CAVEATS,
    }
    name = f"report-{opts.tag}.json" if opts.tag else "report.json"
    if not opts.tag:
        # Follow-up studies on a larger sample (--tag) supersede the main result for their
        # roles and models.
        report["extensions"] = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(opts.out.glob("report-*.json"))
        ]
    report["recommendation"] = recommend(effective_analysis(report))
    (opts.out / name).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    if not opts.tag:
        opts.report.write_text(render_report(report), encoding="utf-8")
    total = report["spend"]["total"]
    print(f"  recommendation: {report['recommendation']}", file=sys.stderr)
    print(
        f"  spent {total['prompt_tokens'] + total['completion_tokens']:,} tokens, "
        f"${total['usd']:.2f}; report: {opts.out / name if opts.tag else opts.report}",
        file=sys.stderr,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--systems", nargs="+", default=list(SYSTEMS), choices=list(SYSTEMS))
    ap.add_argument(
        "--utility-systems",
        nargs="+",
        default=[s for s in SYSTEMS if s != "raw"],
        choices=list(SYSTEMS),
        help="systems for the utility judge and confirmation (raw answers match the reference)",
    )
    ap.add_argument("--candidates", nargs="+", default=CANDIDATES)
    ap.add_argument("--per-stratum", type=int, default=1)
    ap.add_argument("--sensitive-extra", type=int, default=1)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--case-ids", nargs="+", default=None, help="explicit cases (smoke tests)")
    ap.add_argument(
        "--retest-roles",
        nargs="*",
        default=["grader", "distortion_confirm"],
        choices=ROLES,
        help="roles Ultra re-runs to measure its own noise (default: the two cheap roles)",
    )
    ap.add_argument("--max-tokens", type=int, default=2_000_000, help="hard cap, all calls")
    ap.add_argument(
        "--estimate-share",
        type=float,
        default=0.9,
        help="shrink the sample until the estimate fits this share of the cap",
    )
    ap.add_argument("--probe-tokens", type=int, default=8_400, help="spent on adapter probes")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    ap.add_argument("--base-url", default=attack.DEFAULT_BASE_URL)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--roles", nargs="+", default=list(ROLES), choices=ROLES)
    ap.add_argument(
        "--tag",
        default=None,
        help="follow-up study: writes report-<tag>.json, which the main report merges (its "
        "results replace the main ones for the same role and model)",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--report-only", action="store_true", help="cached calls only, no network")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    asyncio.run(run_study(parse_args(argv)))


if __name__ == "__main__":
    main()
