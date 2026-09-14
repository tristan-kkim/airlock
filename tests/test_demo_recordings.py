"""The committed "recorded run" fallbacks never show a declared private value leaving the server."""

from __future__ import annotations

import pytest

from airlock.demo.presets import PRESETS, PRESETS_BY_ID, load_recorded
from tests.fixtures.demo_private_values import (
    ANSWER_KEYWORDS,
    PRIVATE_VALUES,
    answer_problems,
    find_private_values,
    recording_outbound,
)

RECORDED = load_recorded()


def test_every_preset_declares_private_values_and_keywords():
    assert set(PRIVATE_VALUES) == set(ANSWER_KEYWORDS) == {p.id for p in PRESETS}


@pytest.mark.parametrize("preset_id", sorted(PRESETS_BY_ID))
def test_declared_values_are_found_in_the_preset_input(preset_id):
    # Guards the matcher itself: a check that finds nothing in the raw input proves nothing.
    preset = PRESETS_BY_ID[preset_id]
    raw = [preset.message, preset.query, preset.context, preset.question, *preset.docs]
    text = " ".join(s for item in raw for s in (item if isinstance(item, tuple) else (item,)))
    literal = {v for v in PRIVATE_VALUES[preset_id] if v.casefold() in text.casefold()}
    assert literal
    assert literal <= set(find_private_values(raw, preset_id))


@pytest.mark.parametrize("preset_id", sorted(RECORDED))
def test_recording_outbound_has_no_private_value(preset_id):
    recording = RECORDED[preset_id]
    assert recording["cloud_saw"], "a recording must show what the cloud saw"
    leaked = find_private_values([recording_outbound(recording)], preset_id)
    assert leaked == [], f"{preset_id} recording sent private values to the cloud: {leaked}"


@pytest.mark.parametrize("preset_id", sorted(RECORDED))
def test_recording_answer_is_on_topic(preset_id):
    assert answer_problems(RECORDED[preset_id]) == []


def test_matcher_normalizes_separators_case_and_word_edges():
    payload = {"messages": [{"content": "call 01055550142, HANBIT clinic, customer tomorrow"}]}
    found = find_private_values([payload], "chat-medical-en")
    assert "010-5555-0142" in found and "Hanbit Clinic" in found
    assert "Tom" not in found  # "customer", "tomorrow"
    assert find_private_values([{"q": "박성훈은 서명했다"}], "agent-resignation-ko") == ["박성훈"]
