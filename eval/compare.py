# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Build eval/results/COMPARISON.md from every baseline-* results directory present.

    uv run eval/compare.py
    uv run eval/compare.py --results eval/results --out eval/results/COMPARISON.md
    uv run eval/compare.py --agent eval/agent/results/demo/reframe

Rows come from `baseline-<name>/summary.json` (run.py), `attack/summary.json` (attack.py),
`utility/summary.json` (utility.py) and `reframe.json` (reframe.py, which gathers the
unlinkability and utility columns). Known local baselines are listed first; any other
`baseline-<name>` directory is a live Airlock run at commit <name> (a suffix after the commit,
as in `baseline-1a2b3c4-gliner`, is shown as a variant). Until one exists, the table carries a
placeholder row for Airlock. The agent-mode section comes from `reframe.py agent`. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
BASELINES = ["raw", "regex", "presidio_ko", "gliner_pii"]
AIRLOCK_PLACEHOLDER = "f0ba569"
DEFAULT_AGENT = EVAL_DIR / "agent" / "results" / "demo" / "reframe"
LABELS = {
    "raw": "raw (pass-through)",
    "regex": "regex only",
    "presidio_ko": "Presidio + ko/en spaCy + KR recognizers",
    "gliner_pii": "NVIDIA GLiNER-PII",
}
KOREAN_SUPPORT = {
    "raw": "n/a (no masking)",
    "regex": "Korean RRN and dashed mobile patterns only; no names",
    "presidio_ko": "Korean NER from spaCy ko_core_news (KLUE labels) plus Presidio's 5 KR ID "
    "recognizers (disabled by default upstream); no Korean bank/card/address patterns",
    "gliner_pii": "none officially: trained on English-only Nemotron-PII, run unchanged. It still "
    "flags many Korean spans, often under unrelated labels (in qid-ko-01 the age became PASSWORD "
    "and the company RELIGIOUS_BELIEF), so its Korean leak rate is low but benign masking and "
    "over-redaction are high; see the by-language table",
}
COLUMNS = [
    ("leak_rate", "Leak rate"),
    ("canary_leak_rate", "Canary leak"),
    ("quasi_reid_rate", "Quasi re-id"),
    ("over_block_benign", "Over-block benign"),
    ("benign_false_positive_rate", "Benign masked"),
    ("over_redaction_rate", "Over-redaction"),
]
ATTACK_COLUMNS = [
    ("attack_value_recovery_rate", "Values recovered"),
    ("attack_value_partial_rate", "Values full or partial"),
    ("attack_quasi_reid_rate", "Quasi re-id (attacker)"),
    ("attack_intent_inference_rate", "Intent inferred"),
]
# (key in reframe.json, header, kind)
HEADLINE = [
    ("identity_leak_rate", "Identity leak", "pct"),
    ("linkable_disclosure_rate", "**Linkable disclosure**", "pct"),
    ("attack_identity_recovery_rate", "Identity recovered (attacker)", "pct"),
    ("situation_inference_rate", "Situation inferred", "pct"),
    ("utility_ratio_vs_reference", "Utility ratio", "ratio"),
    ("distortion_rate", "Distortion", "pct"),
    ("over_redaction_rate", "Over-redaction", "pct"),
    ("benign_false_positive_rate", "Benign masked", "pct"),
]
BY_LANG = [
    ("identity_leak_rate", "Identity leak", "pct"),
    ("linkable_disclosure_rate", "Linkable", "pct"),
    ("utility_ratio_vs_reference", "Utility ratio", "ratio"),
    ("distortion_rate", "Distortion", "pct"),
    ("over_redaction_rate", "Over-redaction", "pct"),
]


def pct(stat: dict[str, Any] | None) -> str:
    if not stat or not stat.get("n") or stat.get("mean") is None:
        return "n/a"
    if stat["n"] < 2:
        return f"{stat['mean'] * 100:.1f}%"
    return f"{stat['mean'] * 100:.1f}% ± {stat['std'] * 100:.1f}"


def ratio(stat: dict[str, Any] | None) -> str:
    if not stat or not stat.get("n") or stat.get("mean") is None:
        return "n/a"
    if stat["n"] < 2:
        return f"{stat['mean']:.2f}"
    return f"{stat['mean']:.2f} ± {stat['std']:.2f}"


def ms(stat: dict[str, Any] | None) -> str:
    if not stat or not stat.get("n") or stat.get("mean") is None:
        return "n/a"
    return f"{stat['mean']:,.0f}"


def fmt(stat: dict[str, Any] | None, kind: str) -> str:
    return ratio(stat) if kind == "ratio" else pct(stat)


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def discover(results: Path, extra: list[Path] | None = None) -> list[tuple[str, Path]]:
    dirs = [*sorted(results.glob("baseline-*")), *(extra or [])]
    found = {
        p.name.removeprefix("baseline-"): p
        for p in dirs
        if p.is_dir() and (p / "summary.json").exists()
    }
    ordered = [(n, found.pop(n)) for n in BASELINES if n in found]
    return ordered + sorted(found.items())


REUSE_NOTE = "scored once; outputs identical across passes, verified by payload hash"


def reuse_info(path: Path) -> dict[str, dict[str, Any]]:
    """Attack and utility `reuse` blocks (eval/reuse.py) that actually reused rows."""
    found = {}
    attack_cfg = (load_json(path / "attack" / "summary.json") or {}).get("config") or {}
    utility_cfg = load_json(path / "utility" / "config.json") or {}
    for part, cfg in (("attack", attack_cfg), ("utility", utility_cfg)):
        info = cfg.get("reuse") or {}
        if info.get("rows_reused"):
            found[part] = info
    return found


def reuse_mark(path: Path, part: str) -> str:
    return "*" if part in reuse_info(path) else ""


def reuse_notes(runs: list[tuple[str, Path]]) -> list[str]:
    """One footnote naming, per system, how many attack and utility rows were reused."""
    parts = []
    for name, path in runs:
        for part, info in reuse_info(path).items():
            origin = f", pass 1 from `{info['from']}`" if info.get("from") else ""
            parts.append(
                f"{label_for(name)} {part} {info['rows_reused']} of {info['rows']} rows{origin}"
            )
    if not parts:
        return []
    return ["", f"\\* {REUSE_NOTE}: " + "; ".join(parts) + ". Other rows were scored normally."]


NOT_INDEPENDENT_MARK = "†"
NOT_INDEPENDENT_NOTE = (
    "passes not independent (detector cache: the server was reset only before pass 1, so later "
    "passes reused pass-1 detections); treat sd as not measured"
)
# Live Airlock runs whose passes shared server state; filled by build().
_not_independent: set[str] = set()


def passes_not_independent(name: str, path: Path) -> bool:
    """A multi-pass live Airlock run made before run.py reset the server before every pass."""
    if name in BASELINES:
        return False
    s = load_json(path / "summary.json") or {}
    return (s.get("passes") or 0) > 1 and (s.get("config") or {}).get("reset_scope") != "every pass"


def label_for(name: str) -> str:
    if name in LABELS:
        return LABELS[name]
    commit, _, variant = name.partition("-")
    mark = f" {NOT_INDEPENDENT_MARK}" if name in _not_independent else ""
    return f"airlock (live, {commit}{', ' + variant if variant else ''}){mark}"


def independence_notes(runs: list[tuple[str, Path]]) -> list[str]:
    marked = [
        label_for(n).removesuffix(f" {NOT_INDEPENDENT_MARK}")
        for n, _ in runs
        if n in _not_independent
    ]
    if not marked:
        return []
    return ["", f"{NOT_INDEPENDENT_MARK} {NOT_INDEPENDENT_NOTE}: " + "; ".join(marked) + "."]


def headline_section(runs: list[tuple[str, Path]], has_airlock: bool) -> list[str]:
    lines = [
        "## Headline: who has what, and what it costs",
        "",
        "Airlock's claim is unlinkability: the cloud may learn the problem, but not who has it. "
        "**Linkable disclosure** is the share of situation-sensitive cases (health, finance, "
        "quasi-identifier, intent search) where an LLM attacker reading only the outbound "
        "payloads recovers at least one identity item AND infers the private situation, so it "
        "could say who has what. Identity items and situations are classified per case in "
        "`eval/protected.py`. Utility ratio and distortion come from a blind judge comparing each "
        "system's answer with a raw-prompt reference answer (`eval/utility.py`). Lower is better "
        "except utility ratio.",
        "",
        "| System | Passes (run / attack / judge) | "
        + " | ".join(h for _, h, _ in HEADLINE)
        + " | Local overhead p50 / p95 (ms) |",
        "|---|---:|" + "---:|" * (len(HEADLINE) + 1),
    ]
    for name, path in runs:
        r = load_json(path / "reframe.json")
        s = load_json(path / "summary.json") or {}
        o = (r or {}).get("overall") or {}
        so = s.get("overall") or {}
        if r is None:
            # no reframe.json yet: fill what summary.json has
            o = {k: so.get(k) for k in ("over_redaction_rate", "benign_false_positive_rate")}
        passes = (
            f"{s.get('passes', '?')} / {(r or {}).get('attacked_passes', 0)}"
            f"{reuse_mark(path, 'attack')} / {(r or {}).get('judged_passes', 0)}"
            f"{reuse_mark(path, 'utility')}"
        )
        cells = [label_for(name), passes, *(fmt(o.get(k), kind) for k, _, kind in HEADLINE)]
        cells.append(f"{ms(so.get('overhead_ms_p50'))} / {ms(so.get('overhead_ms_p95'))}")
        lines.append("| " + " | ".join(cells) + " |")
    if not has_airlock:
        lines.append(
            f"| airlock (live, {AIRLOCK_PLACEHOLDER}) | pending |" + " |" * (len(HEADLINE) + 1)
        )
    lines += reuse_notes(runs)
    lines += independence_notes(runs)
    lines += [
        "",
        "### By language",
        "",
        "| System | "
        + " | ".join(f"{h} {lang}" for _, h, _ in BY_LANG for lang in ("ko", "en"))
        + " |",
        "|---|" + "---:|" * (2 * len(BY_LANG)),
    ]
    for name, path in runs:
        r = load_json(path / "reframe.json") or {}
        s = load_json(path / "summary.json") or {}
        cells = []
        for key, _, kind in BY_LANG:
            for lang in ("ko", "en"):
                stat = ((r.get("by_lang") or {}).get(lang) or {}).get(key)
                if stat is None:
                    stat = ((s.get("by_lang") or {}).get(lang) or {}).get(key)
                cells.append(fmt(stat, kind))
        lines.append(f"| {label_for(name)} | " + " | ".join(cells) + " |")
    return lines


def agent_section(agent_dir: Path | None) -> list[str]:
    summary = load_json(agent_dir / "summary.json") if agent_dir else None
    if not summary:
        return []
    modes = summary.get("modes") or {}
    rows = [
        ("identity_leak_rate", "Identity leak (scanner)", "pct"),
        ("linkable_disclosure_rate", "**Linkable disclosure**", "pct"),
        ("attack_identity_recovery_rate", "Identity recovered (attacker)", "pct"),
        ("identity_fact_recovery", "Identity facts recovered (share)", "pct"),
        ("situation_fact_recovery", "Situation facts recovered (share)", "pct"),
        ("situation_inference_rate", "Situation inferred (no anchor needed)", "pct"),
        ("pairwise_utility_mean", "Utility, blind pairwise judge (1-5)", "ratio"),
        ("distortion_rate", "Distortion", "pct"),
    ]
    ratio_stat = summary.get("utility_ratio_vs_unguarded")
    lines = [
        "",
        "## Agent mode (`eval/agent`, reframed by `eval/reframe.py agent`)",
        "",
        f"{summary.get('passes')} passes over 16 research-agent scenarios. The same attacker reads "
        "every outbound hop of a run. A run is a linkable disclosure when the attacker names at "
        "least one identity fact (classified in each `scenario.json` `fact_classes`) and infers "
        "the situation. Utility is judged blind and pairwise, with the unguarded answer as the "
        f"reference: utility ratio airlock / unguarded = {ratio(ratio_stat)}.",
        "",
        "| Metric | unguarded | airlock |",
        "|---|---:|---:|",
    ]
    for key, label, kind in rows:
        cells = [
            fmt(((modes.get(m) or {}).get("overall") or {}).get(key), kind)
            for m in ("unguarded", "airlock")
        ]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return lines


def build(results: Path, extra: list[Path] | None = None, agent: Path | None = None) -> str:
    runs = discover(results, extra)
    _not_independent.clear()
    _not_independent.update(n for n, p in runs if passes_not_independent(n, p))
    has_airlock = any(name not in BASELINES for name, _ in runs)
    lines = [
        "# Comparison: Airlock vs local baselines",
        "",
        "Generated by `uv run eval/compare.py` from the `baseline-*` directories in "
        "`eval/results/`. Every system gets the same 243 cases and the same scanner; baselines "
        "record what they would send and make no cloud calls. Cells are mean ± sample sd across "
        "passes; a cell without ± comes from one pass. Definitions: `eval/README.md`; framing and "
        "caveats: `eval/results/REFRAME.md`.",
        "",
    ]
    lines += headline_section(runs, has_airlock)
    lines += agent_section(agent)
    lines += [
        "",
        "## String-matching leak rates",
        "",
        "Every planted value counts, including situation details the answer does not need. "
        "Lower is better for every column.",
        "",
        "| System | Passes | "
        + " | ".join(label for _, label in COLUMNS)
        + " | Leak ko | Leak en | Errors/pass |",
        "|---|---:|" + "---:|" * (len(COLUMNS) + 3),
    ]
    summaries: dict[str, dict[str, Any]] = {}
    for name, path in runs:
        s = load_json(path / "summary.json") or {}
        summaries[name] = s
        o = s.get("overall", {})
        by_lang = s.get("by_lang", {})
        errors = (o.get("errors") or {}).get("mean")
        cells = [
            label_for(name),
            str(s.get("passes", "?")),
            *(pct(o.get(key)) for key, _ in COLUMNS),
            pct(by_lang.get("ko", {}).get("leak_rate")),
            pct(by_lang.get("en", {}).get("leak_rate")),
            "n/a" if errors is None else f"{errors:.1f}",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    if not has_airlock:
        pending = f"pending: `eval/results/baseline-{AIRLOCK_PLACEHOLDER}/`"
        lines.append(
            f"| airlock (live, {AIRLOCK_PLACEHOLDER}) | {pending} |" + " |" * (len(COLUMNS) + 3)
        )

    lines += [
        "",
        "### By language",
        "",
        "| System | Leak ko | Leak en | Quasi re-id ko | Quasi re-id en | Benign masked ko "
        "| Benign masked en | Over-redaction ko | Over-redaction en |",
        "|---|" + "---:|" * 8,
    ]
    for name, _ in runs:
        by_lang = summaries[name].get("by_lang", {})
        keys = ("leak_rate", "quasi_reid_rate", "benign_false_positive_rate", "over_redaction_rate")
        cells = [pct(by_lang.get(lang, {}).get(k)) for k in keys for lang in ("ko", "en")]
        lines.append(f"| {label_for(name)} | " + " | ".join(cells) + " |")

    cats = sorted({c for s in summaries.values() for c in s.get("by_category", {})})
    if cats:
        lines += [
            "",
            "### Leak rate by category",
            "",
            "| System | " + " | ".join(cats) + " |",
            "|---|" + "---:|" * len(cats),
        ]
        for name, _ in runs:
            by_cat = summaries[name].get("by_category", {})
            cells = [pct(by_cat.get(c, {}).get("leak_rate")) for c in cats]
            lines.append(f"| {label_for(name)} | " + " | ".join(cells) + " |")

    attack_rows = []
    for name, path in runs:
        a = load_json(path / "attack" / "summary.json")
        if a:
            attack_rows.append((name, a))
    lines += ["", "## Adversary inference (`eval/attack.py`)", ""]
    if attack_rows:
        lines += [
            "An LLM attacker sees only the outbound payloads of each request and tries to recover "
            "the planted values, the quasi-identifier attributes and the private situation. Cells "
            "are mean ± sd over attacked passes; with one pass, the mean only.",
            "",
            "| System | Attacked passes | "
            + " | ".join(label for _, label in ATTACK_COLUMNS)
            + " | Values recovered ko | Values recovered en | Attacker |",
            "|---|---:|" + "---:|" * (len(ATTACK_COLUMNS) + 2) + "---|",
        ]
        for name, a in attack_rows:
            o, by_lang, cfg = a.get("overall", {}), a.get("by_lang", {}), a.get("config", {})
            cells = [
                label_for(name),
                str(a.get("passes", "?"))
                + ("*" if (cfg.get("reuse") or {}).get("rows_reused") else ""),
                *(pct(o.get(key)) for key, _ in ATTACK_COLUMNS),
                pct(by_lang.get("ko", {}).get("attack_value_recovery_rate")),
                pct(by_lang.get("en", {}).get("attack_value_recovery_rate")),
                f"`{cfg.get('model', '?')}` reasoning `{cfg.get('attacker_reasoning', '?')}`",
            ]
            lines.append("| " + " | ".join(cells) + " |")
        lines += reuse_notes([(n, p) for n, p in runs if "attack" in reuse_info(p)])
    else:
        lines.append("No attack results yet. Run `uv run eval/attack.py --rescore <results dir>`.")

    lines += ["", "## Korean support in each baseline", ""]
    for name, _ in runs:
        if name in KOREAN_SUPPORT:
            health = (summaries[name].get("config") or {}).get("server_health") or {}
            extra_note = ""
            if health.get("spacy_models"):
                extra_note = f" Models: `{json.dumps(health['spacy_models'])}`."
            if health.get("device"):
                extra_note = f" Device: `{health['device']}`, threshold {health.get('threshold')}."
            lines.append(f"- **{label_for(name)}**: {KOREAN_SUPPORT[name]}.{extra_note}")
    lines += [
        "",
        "## Reading this table",
        "",
        "- Baselines mask chat `content` and tool-call arguments and honor declared vault terms "
        "(case-insensitive). They have no gate, no generalization, no rehydration and no review "
        "step, so a detector miss is always a leak. See `eval/baselines/common.py`.",
        "- Baseline utility: baselines only return stub answers, so `eval/utility.py` sends each "
        "one's recorded outbound payload to the upstream model once and judges that answer. "
        "Their placeholders are never restored. Airlock is judged on the answer it returned "
        "(rehydrated). The raw row is the noise floor of sampling plus judging: it sends the same "
        "prompt as the reference.",
        "- Search: only the (masked) query is recorded as outbound, as in Airlock; the private "
        "context never leaves. Utility is judged on chat cases only.",
        "- Over-block is 0 for every baseline by construction (they never block). Compare it "
        "with Airlock's block rate, not in isolation.",
        "- Latency is local overhead (total minus cloud calls). Runs made while other models "
        "shared the GPU are contaminated; `eval/final_protocol.sh` runs each system alone.",
        "- The dataset's identifiers are invalid on purpose (SSN area 666, Luhn-failing cards, "
        "bad RRN and IBAN check digits; see README). Presidio's SSN, card, IBAN and KR ID "
        "recognizers validate checksums, so they reject many of these values even when the "
        "format is recognized. On real data they would catch more; the NER and Korean gaps are "
        "unaffected.",
        "- The attacker and judge columns use Token Factory on synthetic data only. See README, "
        "*Adversary inference* and *Answer utility*, for their limitations.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, default=EVAL_DIR / "results")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=None,
        help="another baseline-<name> run directory to include (for example from a worktree)",
    )
    ap.add_argument(
        "--agent",
        type=Path,
        default=DEFAULT_AGENT,
        help="agent-mode reframe directory (reframe.py agent --out); 'none' to skip",
    )
    args = ap.parse_args(argv)
    out = args.out or args.results / "COMPARISON.md"
    agent = None if str(args.agent) == "none" else args.agent
    out.write_text(build(args.results, args.extra, agent), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
