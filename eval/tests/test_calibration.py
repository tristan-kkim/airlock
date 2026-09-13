"""Agreement statistics and qualification rules of eval/calibrate_judges.py."""

import pytest

import attack
import calibrate_judges as cj


def test_cohen_kappa():
    assert cj.cohen_kappa([1, 1, 0, 0], [1, 0, 0, 0]) == pytest.approx(0.5)
    assert cj.cohen_kappa([True, False] * 5, [True, False] * 5) == pytest.approx(1.0)
    assert cj.cohen_kappa([1, 0, 1, 0], [0, 1, 0, 1]) == pytest.approx(-1.0)
    # 20 items: 7 both yes, 8 both no, 5 disagreements -> po .75, pe .5 -> kappa .5
    a = [1] * 7 + [0] * 8 + [1] * 3 + [0] * 2
    b = [1] * 7 + [0] * 8 + [0] * 3 + [1] * 2
    assert cj.cohen_kappa(a, b) == pytest.approx(0.5)
    assert cj.cohen_kappa([1, 1, 1], [1, 1, 1]) is None
    assert cj.cohen_kappa([], []) is None
    with pytest.raises(ValueError):
        cj.cohen_kappa([1], [1, 0])


def test_spearman_and_mad():
    assert cj.spearman([1, 2, 3, 4], [1, 3, 2, 4]) == pytest.approx(0.8)
    assert cj.spearman([1, 2, 3], [3, 2, 1]) == pytest.approx(-1.0)
    assert cj.average_ranks([5, 3, 5, 1]) == [3.5, 2.0, 3.5, 1.0]
    # ties: Pearson on average ranks
    assert cj.spearman([1, 2, 2, 3], [1, 2, 3, 3]) == pytest.approx(5 / 6)
    assert cj.spearman([4, 4, 4], [1, 2, 3]) is None
    assert cj.mean_abs_diff([5, 4, 3], [4, 4, 1]) == pytest.approx(1.0)
    assert cj.mean_abs_diff([], []) is None


def test_compare_binary_rates_flips_and_reversals():
    pairs = [("a", True, True)] * 8 + [("a", False, False)] * 2
    pairs += [("b", False, False)] * 8 + [("b", True, False), ("b", True, True)]
    cmp = cj.compare_binary(pairs, ["a", "b"])
    assert cmp["n"] == 20 and cmp["ref_only"] == 1 and cmp["cand_only"] == 0
    assert cmp["reference"] == pytest.approx(0.5) and cmp["delta"] == pytest.approx(-0.05)
    assert cmp["per_system"]["b"]["delta"] == pytest.approx(-0.1)
    assert cmp["per_system"]["b"]["net_flips"] == -1 and cmp["reversals"] == []
    assert cj.ranking_reversals({"a": 0.8, "b": 0.2}, {"a": 0.3, "b": 0.4}) == [("a", "b")]
    assert cj.ranking_reversals({"a": 0.45, "b": 0.4}, {"a": 0.3, "b": 0.4}) == []  # too close


def test_compare_ratio():
    items = [("s", 4, 5, 4, 5), ("s", 2, 5, 3, 4), ("t", 5, 5, 5, 5)]
    cmp = cj.compare_ratio(items, ["s", "t"])
    assert cmp["per_system"]["s"]["reference"] == pytest.approx(0.6)
    assert cmp["per_system"]["s"]["candidate"] == pytest.approx(3.5 / 4.5)
    assert cmp["mad_system"] == pytest.approx(1 / 3)
    assert cmp["mad_all"] == pytest.approx(2 / 6)
    assert cmp["delta"] == pytest.approx(12 / 14 - 11 / 15)


def test_qualification_rules():
    def binary(delta, per_system, reversals=()):
        return {"n": 40, "delta": delta, "per_system": per_system, "reversals": list(reversals)}

    one_flip = {"a": {"delta": 0.1, "net_flips": 1}}
    assert cj.qualifies(binary(0.02, one_flip), "rate") == (True, [])
    ok, why = cj.qualifies(binary(0.05, {"a": {"delta": 0.2, "net_flips": 2}}), "rate")
    assert not ok and len(why) == 2
    assert cj.qualifies(binary(0.05, one_flip), "rate", {"delta": -0.06})[0]  # retest noise
    assert not cj.qualifies(binary(0.0, one_flip, [("a", "b")]), "rate")[0]
    assert cj.qualifies({"n": 0, "delta": None, "per_system": {}}, "rate") == (True, [])
    ratio = {"n": 30, "delta": 0.02, "per_system": {"a": {"delta": 0.06}}, "reversals": []}
    assert not cj.qualifies(ratio, "ratio")[0]


def test_recommend_cheapest_qualifying_or_ultra():
    def entry(ok, delta=0.0):
        return {"qualifies": ok, "headlines": {"m": {"delta": delta}}}

    analysis = {
        "attack": {attack.SUPER: entry(False), cj.RETEST: entry(True)},
        "grader": {
            attack.SUPER: entry(True),
            attack.NANO: entry(True, -0.02),
            attack.LIGHTNING: entry(True, 0.01),
        },
        "utility": {attack.SUPER: entry(True), attack.NANO: entry(False)},
        "distortion_confirm": {},
    }
    rec = cj.recommend(analysis)
    assert rec["attack"] == attack.ULTRA and rec["distortion_confirm"] == attack.ULTRA
    assert rec["grader"] == attack.LIGHTNING  # same price as Nano, closer to Ultra
    assert rec["utility"] == attack.SUPER
