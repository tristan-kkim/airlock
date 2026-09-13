"""Identity vs situation: what each protected item in the dataset is. Stdlib only.

Airlock's claim is unlinkability: the cloud may learn the problem, but not who has it. To measure
that, every protected item of a case gets one of two classes:

* identity: direct identifiers and linkable handles. Names, phone numbers, e-mail addresses,
  national and account numbers, exact addresses, patient, ticket and case codes, credentials, the
  user's declared vault terms, private employer and client names, and the attributes of a
  quasi-identifier group that single a person out in combination (employer, site, team, role,
  age, small town, rare personal facts).
* situation: the private circumstance itself. A diagnosis or health condition, a legal,
  financial or employment circumstance (a layoff, a pregnancy during probation, a DUI record,
  an unannounced deal's target), or an intent.

Rules, in order:

1. Every `must_not_leak` value and canary is `identity`. In this dataset those lists only hold
   identifiers, credentials, codes and organization names (diagnoses and amounts the answer
   needs are `must_keep`, not protected). `kind` is a coarse label for reports.
2. Quasi-identifier attributes are classified by hand in `QUASI_CLASSES`, per case id, keyed by the
   attribute's first surface form. Every attribute must be listed; `classify_case` raises
   otherwise, and the generator refuses to write a dataset with an unclassified item.
3. A quasi group singles a person out when its identity attributes reach `identity_k`: the case's
   `quasi_k` minus the number of situation attributes in the group, and never less than 2 (one
   generic attribute alone does not identify anyone). When a group has fewer identity attributes
   than that, it cannot identify anyone by itself.
4. `situation_sensitive` marks the cases whose request is itself a private circumstance:
   categories `health`, `finance`, `quasi_identifier` and `intent_leak_search`. Linkable
   disclosure is measured on these cases only; secrets, direct-PII chores, vault-term chores and
   the obfuscation probes carry identity items but no private situation worth inferring.

The generator writes the result into each case as `protected`. Result directories made before the
field existed are classified on the fly by the same function (`case_protection`).
"""

from __future__ import annotations

import re
from typing import Any

IDENTITY = "identity"
SITUATION = "situation"
CLASSES = (IDENTITY, SITUATION)
SITUATION_CATEGORIES = frozenset({"health", "finance", "quasi_identifier", "intent_leak_search"})

_I, _S = IDENTITY, SITUATION

# case id -> {first surface form of each quasi attribute: class}
QUASI_CLASSES: dict[str, dict[str, str]] = {
    # intent_leak_search, Korean
    "int-ko-01": {"다올빛화학": _I, "설계팀": _I, "희망퇴직": _S},
    # IR team member: the acquirer is the employer, the target is the deal
    "int-ko-02": {"새길모빌리티": _I, "해온정밀": _S},
    "int-ko-03": {"별찬게임즈": _I, "부당 전보": _S, "육아휴직": _S},
    "int-ko-04": {"공황장애": _S, "윤슬반도체": _I},
    "int-ko-05": {"달빛동": _I, "누리내경찰서": _I, "가정폭력": _S},
    "int-ko-06": {"미래기반처": _I, "음주운전": _S, "2회": _S},
    "int-ko-07": {"물빛누리대학교": _I, "연구비 횡령": _S},
    "int-ko-08": {"라온벨시스템즈": _I, "개인회생": _S},
    "int-ko-09": {"청람로지스": _I, "네팔": _I, "임금체불": _S, "안산": _I},
    "int-ko-11": {"미르솔금융": _I, "난임": _S},
    "int-ko-12": {"다올빛화학": _I, "적자 전환": _S, "재무팀": _I},
    "int-ko-13": {"HIV": _S, "새길모빌리티": _I, "은행나무구": _I},
    "int-ko-14": {"해온정밀": _I, "영업2팀": _I, "상간": _S},
    # intent_leak_search, English
    "int-en-01": {"Tessaline Foods": _I, "firmware": _I, "layoffs": _S},
    "int-en-02": {"Pellucid Grid": _I, "pregnant": _S, "probation": _S},
    # corporate development at the acquirer: the target is the deal
    "int-en-03": {"Fernhollow Outfitters": _S, "Corvenna Systems": _I},
    "int-en-04": {"Brasswick Logistics": _I, "expense fraud": _S},
    "int-en-05": {"Voskuil Robotics": _I, "H-1B": _S, "laid off": _S},
    "int-en-07": {"Fabry": _S, "Merrow Falls": _I, "9 year old": _I},
    "int-en-08": {"Port Aldine": _I, "Tessaline Foods": _I, "hiding assets": _S},
    "int-en-09": {"Pellucid Grid": _I, "miss guidance": _S, "12%": _S},
    "int-en-10": {"gambling": _S, "Fernhollow Outfitters": _I},
    "int-en-11": {"Corvenna Systems": _I, "felony": _S},
    # quasi_identifier, Korean
    "qid-ko-01": {
        "청람로지스": _I,
        "판교 본사": _I,
        "보안팀": _I,
        "유일한 여성 팀장": _I,
        "마흔다섯": _I,
    },  # fmt: skip
    "qid-ko-02": {"구름내면": _I, "72세": _I, "참전용사": _I, "다리를 절단": _S},
    "qid-ko-03": {"별바위마을": _I, "한의원 원장": _I, "58세": _I, "의료분쟁": _S},
    "qid-ko-04": {"누리온전자": _I, "2019년 공채": _I, "반도체 설계": _I, "육아휴직 복직": _S},
    "qid-ko-05": {"느티숲초등학교": _I, "3학년 2반": _I, "쌍둥이": _I, "ADHD": _S},
    "qid-ko-06": {"물빛누리대학교": _I, "천문우주학과": _I, "몽골 출신": _I, "박사과정": _I},
    "qid-ko-07": {"달무리도": _I, "산부인과 전문의": _I, "41세": _I},
    "qid-ko-08": {"미래기반처": _I, "5급 사무관": _I, "2022년 행정고시": _I, "수석": _I},
    "qid-ko-09": {"해온정밀": _I, "CTO": _I, "06학번": _I, "직원 12명": _I},
    "qid-ko-10": {"새벽별리버뷰": _I, "관리사무소장": _I, "연수구": _I, "입주자대표 회장": _I},
    "qid-ko-11": {"누리솔배": _I, "75kg급": _I, "체육교사": _I, "가온시": _I},
    "qid-ko-12": {"빛솔교회": _I, "청각장애인 전도사": _I, "사하구": _I},
    "qid-ko-13": {"누리별함": _I, "유일한 여군 부사관": _I, "함장": _I},
    "qid-ko-14": {"새내군": _I, "사과 농사": _I, "귀농 부부": _I, "전직 변호사": _I},
    # quasi_identifier, English
    "qid-en-01": {
        "Nettlefield Pharmacy Group": _I,
        "reactor-controls": _I,
        "Tulsa": _I,
        "turned 52": _I,
        "only woman": _I,
    },  # fmt: skip
    "qid-en-02": {"34-year-old": _I, "00041": _I, "leap day": _I, "man with Fabry": _S},
    "qid-en-03": {
        "Birchwick Elementary": _I,
        "East Tamsworth": _I,
        "cochlear implant": _S,
        "fourth-grader": _I,
    },  # fmt: skip
    "qid-en-04": {
        "planning commission": _I,
        "Quenby Township": _I,
        "only one who voted against": _I,
        "Corvenna Systems warehouse": _I,
    },  # fmt: skip
    "qid-en-05": {"ER nurse": _I, "Port Aldine": _I, "2:51": _I, "three-legged greyhound": _I},
    "qid-en-06": {
        "former CFO": _I,
        "craft brewery": _I,
        "Cobalt Springs": _I,
        "January 2025": _I,
        "founder's DUI": _S,
    },  # fmt: skip
    "qid-en-07": {
        "Halvorsen Maritime": _I,
        "Portuguese-speaking": _I,
        "Singapore office": _I,
        "Recife": _I,
        "joined last May": _I,
    },  # fmt: skip
    "qid-en-08": {
        "dad, 61": _I,
        "Korean-speaking": _I,
        "pediatric cardiologist": _I,
        "Merrow Falls": _I,
        "2023 surgery": _S,
    },  # fmt: skip
    "qid-en-09": {
        "helicopter mechanic": _I,
        "412th Aviation Maintenance Company": _I,
        "Camp Harlan": _I,
        "only woman": _I,
        "left-handed": _I,
    },  # fmt: skip
    "qid-en-10": {
        "quantum optics": _I,
        "Aldermoor University": _I,
        "Valparaíso": _I,
        "tenure-track": _I,
    },  # fmt: skip
    "qid-en-11": {"Tillbrook High": _I, "AP chemistry": _I, "goalkeeper": _I, "water polo": _I},
    "qid-en-12": {
        "night-shift pharmacist": _I,
        "Juniper Flats": _I,
        "24-hour pharmacy": _I,
        "a twin": _I,
        "I'm 29": _I,
    },  # fmt: skip
    "qid-en-13": {
        "only female airline captain": _I,
        "Anchorage": _I,
        "she's 47": _I,
        "Nettlefield Pharmacy Group Air": _I,
    },  # fmt: skip
}

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_PHONE = re.compile(r"^(?:\(\d{3}\) ?\d{3}-\d{4}|\d{3}-\d{3,4}-\d{4})$")
_ADDRESS = re.compile(
    r"\d+동 \d+호|\b\d+ [A-Z][a-z]+(?: [A-Z][a-z]+)* (?:Street|Road|Lane|Drive|Court|Avenue)\b"
)


def value_kind(value: str, case: dict[str, Any]) -> str:
    """Coarse label for reports only; classification does not depend on it."""
    if value in (case.get("vault_terms") or []):
        return "vault_term"
    if any(c and c in value for c in case.get("canaries") or []):
        return "credential_or_code"
    if _EMAIL.search(value):
        return "email"
    if _PHONE.match(value.strip()):
        return "phone"
    if _ADDRESS.search(value):
        return "address"
    letters_digits = [ch for ch in value if ch.isalnum()]
    if letters_digits and sum(ch.isdigit() for ch in letters_digits) >= 0.6 * len(letters_digits):
        return "number"
    return "name_org_or_code"


def _first_form(attr: str | list[str]) -> str:
    return attr if isinstance(attr, str) else attr[0]


def classify_case(case: dict[str, Any], strict: bool = True) -> dict[str, Any]:
    """The `protected` field for one case.

    strict (the generator and tests): an unclassified quasi attribute raises KeyError. Non-strict
    (scoring a case that is not from this dataset, such as a unit-test fixture): unclassified
    attributes count as identity attributes.
    """
    items: list[dict[str, Any]] = []
    canaries = set(case.get("canaries") or [])
    seen: set[str] = set()
    for value in [*(case.get("must_not_leak") or []), *(case.get("canaries") or [])]:
        if not value or value in seen:
            continue
        seen.add(value)
        items.append(
            {
                "source": "canary" if value in canaries else "must_not_leak",
                "value": value,
                "class": IDENTITY,
                "kind": value_kind(value, case),
            }
        )
    identity_k = None
    group = case.get("quasi_group") or []
    if group:
        table = QUASI_CLASSES.get(case.get("id", ""), {})
        forms = [_first_form(a) for a in group]
        unknown = [f for f in forms if f not in table]
        extra = [f for f in table if f not in forms]
        if strict and (unknown or extra):
            raise KeyError(f"{case.get('id')}: unclassified quasi {unknown}, stale {extra}")
        n_situation = 0
        for index, attr in enumerate(group):
            cls = table.get(forms[index], IDENTITY)
            n_situation += cls == SITUATION
            items.append(
                {
                    "source": "quasi",
                    "index": index,
                    "value": [attr] if isinstance(attr, str) else list(attr),
                    "class": cls,
                    "kind": "quasi_attribute",
                }
            )
        k = int(case.get("quasi_k") or len(group))
        identity_k = max(2, k - n_situation)
    return {
        "situation_sensitive": case.get("category") in SITUATION_CATEGORIES,
        "identity_k": identity_k,
        "items": items,
    }


def case_protection(case: dict[str, Any]) -> dict[str, Any]:
    """The stored `protected` field, or the same classification computed for an older snapshot."""
    stored = case.get("protected")
    if isinstance(stored, dict) and "items" in stored:
        return stored
    return classify_case(case, strict=False)


def identity_values(case: dict[str, Any]) -> list[str]:
    """Individually identifying values (every non-quasi identity item)."""
    return [
        i["value"]
        for i in case_protection(case)["items"]
        if i["class"] == IDENTITY and i["source"] != "quasi"
    ]


def identity_quasi_indices(case: dict[str, Any]) -> list[int]:
    return [
        i["index"]
        for i in case_protection(case)["items"]
        if i["class"] == IDENTITY and i["source"] == "quasi"
    ]


def has_identity(case: dict[str, Any]) -> bool:
    prot = case_protection(case)
    quasi_ok = (
        prot["identity_k"] is not None and len(identity_quasi_indices(case)) >= prot["identity_k"]
    )
    return bool(identity_values(case)) or quasi_ok


def quasi_identifies(case: dict[str, Any], found_indices: set[int] | list[int]) -> bool:
    """True when the identity attributes among `found_indices` reach the case's identity_k."""
    prot = case_protection(case)
    if prot["identity_k"] is None:
        return False
    hits = set(found_indices) & set(identity_quasi_indices(case))
    return len(hits) >= prot["identity_k"]


def linkable_eligible(case: dict[str, Any]) -> bool:
    return case_protection(case)["situation_sensitive"] and has_identity(case)


# --------------------------------------------------------------------------------------------
# Agent-mode scenarios: `fact_classes` in scenario.json
# --------------------------------------------------------------------------------------------


def scenario_fact_classes(scenario: dict[str, Any]) -> dict[str, str]:
    """{private fact: class}. Raises ValueError if a fact is unclassified or a class is unknown."""
    classes = scenario.get("fact_classes") or {}
    facts = scenario.get("private_facts") or []
    missing = [f for f in facts if f not in classes]
    stale = [f for f in classes if f not in facts]
    bad = [f for f, c in classes.items() if c not in CLASSES]
    if missing or stale or bad:
        raise ValueError(
            f"{scenario.get('id')}: unclassified {missing}, stale {stale}, bad class {bad}"
        )
    return dict(classes)
