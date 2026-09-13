"""The placeholder type of a declared vault term when the client did not give one.

`POST /vault/terms` used to store every term as PERSON. In the S6 test runs that sent a company
and a project codename as `<PERSON_1>` and `<PERSON_5>`, and the cloud model wrote about "the
two people" behind `<PERSON_1> and <LOCATION_1>`, two companies. The type is part of what the
cloud sees, so a wrong one distorts the answer while a right one reveals nothing extra.

Order: a company suffix is ORG, `프로젝트 X` / `Project X` is PROJECT, the leading words of a
declared organization are ORG (`Sableridge` next to `Sableridge Media`), a name shape is PERSON,
and anything else is TERM ("a private name the user declared").
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from airlock.detect.gliner import ko_name, latin_name
from airlock.detect.ko_rules import detect_rules
from airlock.detect.org_rules import en_orgs

_PROJECT = re.compile(r"^(?:프로젝트|project|operation|codename|코드명)\s+\S", re.IGNORECASE)
# Suffixes the detectors do not treat as organizations on their own but a declared term with them
# is one ("누리결파트너스", "Harrowgate Biosystems").
_EXTRA_KO_ORG = re.compile(
    r"[가-힣A-Za-z0-9]{2,}(?:파트너스|컴퍼니|코리아|랩스|랩|스튜디오|엔터테인먼트|홀딩스|벤처스|"
    r"인베스트먼트|커머스|푸드|팜|클리닉|치과|한의원|약국|법률사무소|회계법인|세무법인|학원|어린이집)$"
)
_EXTRA_EN_ORG = re.compile(
    r"^(?:[A-Z][\w&'’\-]*\s+){1,3}(?:Biosystems|Bio|Biosciences|Works|Collective|Agency|Studio|"
    r"Firm|Foundation|Trust|Fund|Clinic|Center|Centre|Cooperative|Co-op|Society|Press)$"
)


def _is_org(text: str) -> bool:
    spans = [s for s in detect_rules(text) + en_orgs(text) if s.type == "ORG"]
    if any(s.text.strip() == text for s in spans):
        return True
    return bool(_EXTRA_KO_ORG.match(text) or _EXTRA_EN_ORG.match(text))


def infer_term_type(text: str, others: Iterable[str] = ()) -> str:
    """ORG, PROJECT, PERSON or TERM for a declared term. `others`: the other declared terms."""
    t = text.strip()
    if _PROJECT.match(t):
        return "PROJECT"
    if _is_org(t):
        return "ORG"
    folded = t.casefold()
    for other in others:
        o = other.strip()
        if o == t or not o.casefold().startswith(folded + " "):
            continue
        if _is_org(o):
            return "ORG"
    if ko_name(t) == t or (latin_name(t) and len(t.split()) >= 2):
        return "PERSON"
    return "TERM"
