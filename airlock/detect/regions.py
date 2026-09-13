"""Place containment for fact-preserving generalization: which region holds a city or district.

A generalization of a place must be *entailed* by the original: `성남시` may become `경기도`, never
`서울`. The table is deliberately small: Korean metropolitan cities and provinces, their 시/군/구
and a few well-known neighbourhoods, plus major foreign cities with their state or country.
Anything not in the table is generalized by its administrative suffix alone (`새내군` ->
`한 군 지역`), which is always true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Top-level Korean regions: canonical name -> aliases (the canonical name is what a
# generalization says).
KO_TOP: dict[str, tuple[str, ...]] = {
    "서울": ("서울특별시", "서울시", "서울"),
    "부산": ("부산광역시", "부산시", "부산"),
    "대구": ("대구광역시", "대구시", "대구"),
    "인천": ("인천광역시", "인천시", "인천"),
    "광주광역시": ("광주광역시",),
    "대전": ("대전광역시", "대전시", "대전"),
    "울산": ("울산광역시", "울산시", "울산"),
    "세종": ("세종특별자치시", "세종시", "세종"),
    "경기도": ("경기도", "경기"),
    "강원도": ("강원특별자치도", "강원도", "강원"),
    "충청북도": ("충청북도", "충북"),
    "충청남도": ("충청남도", "충남"),
    "전라북도": ("전북특별자치도", "전라북도", "전북"),
    "전라남도": ("전라남도", "전남"),
    "경상북도": ("경상북도", "경북"),
    "경상남도": ("경상남도", "경남"),
    "제주도": ("제주특별자치도", "제주도", "제주"),
}

_KO_CHILDREN = """
서울: 종로구 용산구 성동구 광진구 동대문구 중랑구 성북구 강북구 도봉구 노원구 은평구 서대문구 마포구
    양천구 구로구 금천구 영등포구 동작구 관악구 서초구 강남구 송파구 강동구
    여의도 잠실 대치동 역삼동 삼성동 성수동 신촌 홍대 목동 상암동 압구정동 청담동 이태원 한남동
부산: 영도구 부산진구 동래구 금정구 사하구 연제구 수영구 사상구 기장군 서면 해안동
대구: 수성구 달서구 달성군 군위군
인천: 미추홀구 연수구 남동구 부평구 계양구 강화군 옹진군 송도
광주광역시: 광산구
대전: 유성구 대덕구 둔산동
울산: 울주군
경기도: 수원시 성남시 의정부시 안양시 부천시 광명시 평택시 동두천시 안산시 고양시 과천시 구리시
    남양주시 오산시 시흥시 군포시 의왕시 하남시 용인시 파주시 이천시 안성시 김포시 화성시 양주시
    포천시 여주시 연천군 가평군 양평군 분당구 수정구 중원구 일산동구 일산서구 덕양구 영통구 권선구
    장안구 팔달구 기흥구 수지구 처인구 동안구 만안구 단원구 상록구 판교 분당 일산 평촌 평촌동 동탄
    광교 산본 위례 수원 성남 안양 용인 고양 부천 화성 평택 파주 김포 의정부
강원도: 춘천시 원주시 강릉시 동해시 태백시 속초시 삼척시 홍천군 횡성군 영월군 평창군 정선군 철원군
    화천군 양구군 인제군 양양군 춘천 원주 강릉 속초
충청북도: 청주시 충주시 제천시 보은군 옥천군 영동군 증평군 진천군 괴산군 음성군 단양군 청주 충주
충청남도: 천안시 공주시 보령시 아산시 서산시 논산시 계룡시 당진시 금산군 부여군 서천군 청양군 홍성군
    예산군 태안군 천안 아산
전라북도: 전주시 군산시 익산시 정읍시 남원시 김제시 완주군 진안군 무주군 장수군 임실군 순창군 고창군
    부안군 전주 군산 익산
전라남도: 목포시 여수시 순천시 나주시 광양시 담양군 곡성군 구례군 고흥군 보성군 화순군 장흥군 강진군
    해남군 영암군 무안군 함평군 영광군 장성군 완도군 진도군 신안군 목포 여수 순천
경상북도: 포항시 경주시 김천시 안동시 구미시 영주시 영천시 상주시 문경시 경산시 의성군 청송군 영양군
    영덕군 청도군 고령군 성주군 칠곡군 예천군 봉화군 울진군 울릉군 포항 경주 구미 안동
경상남도: 창원시 진주시 통영시 사천시 김해시 밀양시 거제시 양산시 의령군 함안군 창녕군 남해군 하동군
    산청군 함양군 거창군 합천군 창원 김해 거제 양산 진주
제주도: 제주시 서귀포시 서귀포
"""


def _words(block: str) -> list[str]:
    return block.split()


def _parse_children(block: str) -> dict[str, str]:
    out: dict[str, str] = {}
    key = ""
    for line in block.splitlines():
        if not line.strip():
            continue
        if ":" in line:
            key, _, line = line.partition(":")
            key = key.strip()
        for name in line.split():
            out[name] = key
    return out


KO_PARENT: dict[str, str] = _parse_children(_KO_CHILDREN)
_KO_ALIAS: dict[str, str] = {alias: top for top, aliases in KO_TOP.items() for alias in aliases}

_US_STATES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire",
    "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York", "NC": "North Carolina",
    "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania",
    "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee",
    "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming", "DC": "the District of Columbia",
    "PR": "Puerto Rico",
}  # fmt: skip

_EN_CITIES = """
Alabama: Birmingham Montgomery Huntsville Mobile
Arizona: Phoenix Tucson Mesa Scottsdale Tempe Flagstaff
California: Los_Angeles San_Francisco San_Diego San_Jose Sacramento Oakland Fresno Irvine Berkeley
    Palo_Alto Pasadena Long_Beach Santa_Monica Mountain_View Sunnyvale
Colorado: Denver Boulder Aurora Colorado_Springs Fort_Collins
Florida: Miami Orlando Tampa Jacksonville Tallahassee Fort_Lauderdale
Georgia: Atlanta Savannah Augusta
Illinois: Chicago Springfield Naperville Evanston
Indiana: Indianapolis Fort_Wayne Bloomington
Kentucky: Louisville Lexington
Louisiana: New_Orleans Baton_Rouge
Maryland: Baltimore Annapolis Bethesda
Massachusetts: Boston Cambridge Worcester Somerville
Michigan: Detroit Ann_Arbor Grand_Rapids Lansing
Minnesota: Minneapolis Saint_Paul St._Paul Duluth Rochester
Missouri: Kansas_City St._Louis Saint_Louis
Nevada: Las_Vegas Reno Henderson
New_York: New_York_City Brooklyn Manhattan Queens Buffalo Albany Syracuse
North_Carolina: Charlotte Raleigh Durham Asheville
Ohio: Columbus Cleveland Cincinnati Dayton Toledo Akron
Oklahoma: Tulsa Oklahoma_City Norman
Oregon: Portland Eugene Salem Bend
Pennsylvania: Philadelphia Pittsburgh Harrisburg Allentown
Tennessee: Nashville Memphis Knoxville Chattanooga
Texas: Houston Dallas Austin San_Antonio Fort_Worth El_Paso Plano
Utah: Salt_Lake_City Provo
Virginia: Richmond Arlington Norfolk Virginia_Beach Alexandria
Washington: Seattle Spokane Tacoma Bellevue Redmond
Wisconsin: Milwaukee Madison
Ontario: Toronto Ottawa Mississauga Hamilton Waterloo
British_Columbia: Vancouver Victoria Burnaby Surrey
Quebec: Montreal Quebec_City
Alberta: Calgary Edmonton
England: London Manchester Birmingham_UK Liverpool Leeds Bristol Oxford Sheffield
Scotland: Edinburgh Glasgow Aberdeen
Japan: Tokyo Osaka Kyoto Yokohama Nagoya Sapporo Fukuoka
China: Beijing Shanghai Shenzhen Guangzhou Chengdu Hangzhou
France: Paris Lyon Marseille Toulouse Nice
Germany: Berlin Munich Hamburg Frankfurt Cologne Stuttgart
Australia: Sydney Melbourne Brisbane Perth Adelaide
India: Mumbai Delhi Bangalore Bengaluru Chennai Hyderabad Pune
Ghana: Accra Kumasi Tema
Nigeria: Lagos Abuja
Kenya: Nairobi Mombasa
Brazil: Sao_Paulo São_Paulo Rio_de_Janeiro
Mexico: Mexico_City Guadalajara Monterrey
Philippines: Manila Cebu
Vietnam: Hanoi Ho_Chi_Minh_City
Singapore: Singapore
"""

EN_PARENT: dict[str, str] = {
    name.replace("_", " "): region.replace("_", " ")
    for name, region in _parse_children(_EN_CITIES).items()
}
_EN_COUNTRIES = frozenset(
    _words(
        """
        Japan China France Germany Australia India Ghana Nigeria Kenya Brazil Mexico
        Philippines Vietnam Singapore England Scotland
        """
    )
)
_CA_PROVINCES = frozenset({"Ontario", "British Columbia", "Quebec", "Alberta"})
EN_REGIONS = frozenset(EN_PARENT.values()) | frozenset(_US_STATES.values())

KO_SUFFIX_GENERIC = {
    "특별시": "한 대도시",
    "광역시": "한 광역시",
    "도": "한 지역",
    "시": "한 도시",
    "군": "한 군 지역",
    "구": "한 자치구",
    "읍": "한 읍 지역",
    "면": "한 면 지역",
    "동": "한 동네",
    "리": "한 마을",
}
_KO_PLACE = re.compile(
    r"[가-힣]{1,8}?(?:특별자치시|특별자치도|특별시|광역시|도|시|군|구|읍|면|동|리)(?![가-힣])"
)
_KO_PLACE_TAIL = re.compile(
    r"(?:에서는|에서|에는|에도|에|의|은|는|이|가|을|를|과|와|으로|로|도|만|까지|부터|소재|쪽)$"
)


@dataclass(frozen=True)
class Place:
    name: str  # as written, particles stripped
    top: str | None  # containing top-level region (Korean) or state/country (English)
    lang: str  # "ko" | "en"
    suffix: str = ""  # Korean administrative suffix, "" if none


def _ko_top(name: str) -> str | None:
    if name in _KO_ALIAS:
        return _KO_ALIAS[name]
    parent = KO_PARENT.get(name)
    if parent is None and name.endswith(("시", "군", "구", "동")) and name[:-1] in KO_PARENT:
        parent = KO_PARENT[name[:-1]]
    if parent is None:
        parent = KO_PARENT.get(name + "시") or KO_PARENT.get(name + "군")
    return parent


def ko_places(text: str) -> list[Place]:
    """Korean place tokens in `text`, most general first, with their top-level region."""
    out: list[Place] = []
    for raw in re.findall(r"[가-힣]+", text):
        token = _KO_PLACE_TAIL.sub("", raw) if len(raw) > 2 else raw
        top = _ko_top(token)
        suffix = next(
            (s for s in sorted(KO_SUFFIX_GENERIC, key=len, reverse=True) if token.endswith(s)), ""
        )
        if top is not None or (suffix and _KO_PLACE.fullmatch(token) and len(token) >= 2):
            out.append(Place(token, top, "ko", suffix))
    return out


def en_places(text: str) -> list[Place]:
    out: list[Place] = []
    for m in re.finditer(r"\b([A-Z][a-zA-Z.]+(?:\s+[A-Z][a-zA-Z.]+){0,3}),\s*([A-Z]{2})\b", text):
        state = _US_STATES.get(m.group(2))
        if state:
            out.append(Place(m.group(1), state, "en"))
    for name in sorted(EN_PARENT, key=len, reverse=True):
        found = re.search(rf"(?<![A-Za-z]){re.escape(name)}(?![A-Za-z])", text)
        if found and not any(name in p.name or p.name in name for p in out):
            out.append(Place(name, EN_PARENT[name], "en"))
    return out


def ko_container(text: str) -> str | None:
    """The top-level Korean region that contains every known place in `text`, if unique."""
    tops = {p.top for p in ko_places(text) if p.top}
    return tops.pop() if len(tops) == 1 else None


def en_container(text: str) -> str | None:
    tops = {p.top for p in en_places(text) if p.top}
    return tops.pop() if len(tops) == 1 else None


def en_region_phrase(region: str, noun: str = "a city") -> str:
    if region in _EN_COUNTRIES or region in _CA_PROVINCES or region in _US_STATES.values():
        return f"{noun} in {region}"
    return f"{noun} in {region}"


def contains(region: str, place_text: str) -> bool:
    """True when `region` (as a generalization would say it) contains the places in the text."""
    region = region.strip()
    ko_top = _KO_ALIAS.get(region, region if region in KO_TOP else None)
    if ko_top:
        places = [p for p in ko_places(place_text) if p.top]
        return bool(places) and all(p.top == ko_top for p in places)
    places = [p for p in en_places(place_text) if p.top]
    return bool(places) and all(p.top == region for p in places)


def named_regions(text: str) -> list[str]:
    """Region names a generalization mentions (Korean top-level or English state/country)."""
    found = [top for alias, top in _KO_ALIAS.items() if alias in text]
    found += [
        r
        for r in EN_REGIONS | {"Korea", "South Korea", "North Korea", "Seoul", "United States"}
        if re.search(rf"(?<![A-Za-z]){re.escape(r)}(?![A-Za-z])", text)
    ]
    found += [KO_PARENT[k] for k in KO_PARENT if len(k) >= 2 and k in text]
    return found
