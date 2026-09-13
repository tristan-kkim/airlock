"""Judge models: per-model request adapters, JSON validation and retry, role plumbing."""

import asyncio
import json

import httpx
import pytest

import attack
import reframe
import utility

GRADE_OK = '{"match": true, "reason": "same circumstance"}'
MESSAGES = [{"role": "system", "content": "rubric"}, {"role": "user", "content": "grade this"}]


# --------------------------------------------------------------------------------------------
# Request adapter
# --------------------------------------------------------------------------------------------


def test_ultra_keeps_json_schema_and_reasoning_effort():
    body = attack.build_request(attack.ULTRA, MESSAGES, "grade", attack.GRADER_SCHEMA, "none", 200)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["reasoning_effort"] == "none" and "chat_template_kwargs" not in body
    assert body["messages"] == MESSAGES and body["temperature"] == 0 and body["max_tokens"] == 200
    assert "reasoning_effort" not in attack.build_request(
        attack.ULTRA, MESSAGES, "grade", attack.GRADER_SCHEMA, "", 200
    )


@pytest.mark.parametrize("reasoning, thinking", [("none", False), ("", False), ("low", True)])
def test_super_never_sends_reasoning_effort_and_uses_json_mode(reasoning, thinking):
    body = attack.build_request(
        attack.SUPER, MESSAGES, "grade", attack.GRADER_SCHEMA, reasoning, 200
    )
    assert "reasoning_effort" not in body
    assert body["chat_template_kwargs"] == {"enable_thinking": thinking}
    assert body["response_format"] == {"type": "json_object"}
    last = body["messages"][-1]["content"]
    assert last.startswith("grade this") and '"required":["match","reason"]' in last
    assert MESSAGES[-1]["content"] == "grade this"  # the caller's messages are not mutated


def test_lightning_and_nano_keep_json_schema_with_thinking_kwarg():
    for model in (attack.LIGHTNING, attack.NANO, attack.NANO.lower()):
        body = attack.build_request(model, MESSAGES, "grade", attack.GRADER_SCHEMA, "none", 50)
        assert body["response_format"]["type"] == "json_schema"
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert "reasoning_effort" not in body and body["messages"] == MESSAGES


def test_unknown_model_gets_the_default_adapter():
    body = attack.build_request("acme/model", MESSAGES, "grade", attack.GRADER_SCHEMA, "low", 50)
    assert body["reasoning_effort"] == "low" and body["response_format"]["type"] == "json_schema"


def test_clean_content_drops_reasoning():
    msg = {"content": "\n\n" + GRADE_OK, "reasoning_content": "We need to decide {not json}"}
    assert attack.clean_content(msg) == GRADE_OK
    assert attack.clean_content({"content": "<think>hmm {x}</think>\n" + GRADE_OK}) == GRADE_OK
    assert attack.clean_content({"content": "stray reasoning</think>" + GRADE_OK}) == GRADE_OK
    assert attack.clean_content({"content": None, "reasoning_content": GRADE_OK}) == ""


def test_schema_errors():
    assert (
        attack.schema_errors({"match": True, "reason": "x", "extra": 1}, attack.GRADER_SCHEMA) == []
    )
    assert attack.schema_errors({"match": "true", "reason": "x"}, attack.GRADER_SCHEMA) == [
        "$.match: expected boolean"
    ]
    assert attack.schema_errors({"reason": "x"}, attack.GRADER_SCHEMA) == ["$.match: missing"]
    bad_attack = {"extracted_values": [{"kind": "name"}], "person_attributes": "Tulsa"}
    assert attack.schema_errors(bad_attack, attack.ATTACKER_SCHEMA) == [
        "$.private_situation: missing",
        "$.extracted_values[0].value: missing",
        "$.person_attributes: expected array",
    ]
    grade = {"answer_1": {"usefulness": True, "distortion_detail": "", "distortion": False}}
    errors = attack.schema_errors(grade, utility.JUDGE_SCHEMA)
    assert "$.answer_1.usefulness: expected integer" in errors and "$.answer_2: missing" in errors
    assert attack.reply_errors("match=true", attack.GRADER_SCHEMA) == ["reply is not a JSON object"]


def _mock_llm(model, replies):
    """make_llm over a mock transport; returns (llm, list of request bodies)."""
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        message = replies[len(bodies) - 1]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": message, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
            },
        )

    async def run():
        async with httpx.AsyncClient(
            base_url="https://tf.test/v1", transport=httpx.MockTransport(handler)
        ) as client:
            llm = attack.make_llm(client, model)
            return await llm(MESSAGES, "grade", attack.GRADER_SCHEMA, "none", 200)

    return run, bodies


def test_make_llm_retries_invalid_json_once_and_strips_reasoning():
    run, bodies = _mock_llm(
        attack.SUPER,
        [
            {"content": "\n\nmatch=true", "reasoning_content": "thinking"},
            {"content": "\n\n" + GRADE_OK, "reasoning_content": "thinking again"},
        ],
    )
    result = asyncio.run(run())
    assert len(bodies) == 2
    assert result["content"] == GRADE_OK and result["model"] == attack.SUPER
    assert result["retried_after"]["errors"] == ["reply is not a JSON object"]
    assert all("reasoning_effort" not in b for b in bodies)
    assert bodies[1]["response_format"] == {"type": "json_object"}
    assert "not valid for this schema" in bodies[1]["messages"][-1]["content"]
    assert [u["prompt_tokens"] for u in attack.iter_usage(result)] == [10, 10]


def test_make_llm_retries_schema_violation_and_accepts_valid_first_reply():
    run, bodies = _mock_llm(
        attack.ULTRA, [{"content": '{"match": "maybe"}'}, {"content": GRADE_OK}]
    )
    result = asyncio.run(run())
    assert len(bodies) == 2 and bodies[0]["response_format"]["type"] == "json_schema"
    assert "$.match: expected boolean" in result["retried_after"]["errors"]
    assert "$.reason: missing" in bodies[1]["messages"][-1]["content"]

    run, bodies = _mock_llm(attack.ULTRA, [{"content": GRADE_OK}])
    result = asyncio.run(run())
    assert len(bodies) == 1 and "retried_after" not in result and result["model"] == attack.ULTRA


def test_usage_cost():
    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 500_000}
    assert attack.usage_cost(attack.ULTRA, usage) == pytest.approx(2.5)
    assert attack.usage_cost(attack.SUPER.upper(), usage) == pytest.approx(0.75)
    assert attack.usage_cost(attack.NANO, usage) == pytest.approx(0.18)
    assert attack.usage_cost("acme/model", usage) is None


# --------------------------------------------------------------------------------------------
# Role plumbing
# --------------------------------------------------------------------------------------------


ROLE_VARS = list(attack.ROLE_ENV.values())


@pytest.fixture
def clean_env(monkeypatch):
    for var in ROLE_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_role_model_env_overrides_default(clean_env):
    for role in attack.ROLE_ENV:
        assert attack.role_model(role) == attack.DEFAULT_ROLE_MODELS[role]
    assert attack.role_model("grader", {"AIRLOCK_GRADER_MODEL": "x/y"}) == "x/y"
    clean_env.setenv("AIRLOCK_UTILITY_MODEL", attack.NANO)
    assert attack.role_model("utility") == attack.NANO


def test_attack_cli_models(clean_env):
    opts = attack.parse_args(["--rescore", "r"])
    assert opts.attack_model == attack.DEFAULT_ROLE_MODELS["attack"]
    assert opts.grader_model == attack.DEFAULT_ROLE_MODELS["grader"]
    clean_env.setenv("AIRLOCK_GRADER_MODEL", attack.NANO)
    opts = attack.parse_args(["--rescore", "r", "--attack-model", attack.SUPER])
    assert (opts.attack_model, opts.grader_model) == (attack.SUPER, attack.NANO)
    opts = attack.parse_args(["--rescore", "r", "--model", attack.ULTRA])
    assert (opts.attack_model, opts.grader_model) == (attack.ULTRA, attack.ULTRA)


def test_utility_and_reframe_cli_models(clean_env):
    clean_env.setenv("AIRLOCK_DISTORTION_CONFIRM_MODEL", attack.LIGHTNING)
    opts = utility.parse_args(["--results", "r", "--judge-model", attack.SUPER])
    assert (opts.judge_model, opts.confirm_model) == (attack.SUPER, attack.LIGHTNING)
    assert opts.model == attack.ULTRA  # the upstream answer model is not a judge role
    opts = reframe.parse_args(["agent", "run", "--out", "o", "--model", attack.ULTRA])
    assert {opts.grader_model, opts.judge_model, opts.confirm_model} == {attack.ULTRA}
    opts = reframe.parse_args(["agent", "run", "--out", "o"])
    assert opts.confirm_model == attack.LIGHTNING
    assert opts.grader_model == attack.DEFAULT_ROLE_MODELS["grader"]


def test_run_attack_records_role_models_in_config(tmp_path, clean_env, monkeypatch):
    case = {
        "id": "hlt-x",
        "category": "health",
        "lang": "en",
        "task": "chat",
        "messages": [{"role": "user", "content": "I have bipolar II; draft a note to HR."}],
        "must_not_leak": ["Avery Thornbury"],
        "canaries": [],
    }
    record = {
        "case_id": "hlt-x",
        "status": "ok",
        "audit": {"outbound": [{"destination": "upstream", "payload": {"messages": []}}]},
    }
    (tmp_path / "cases_snapshot.jsonl").write_text(json.dumps(case) + "\n")
    (tmp_path / "pass_01.jsonl").write_text(json.dumps({"record": record}) + "\n")
    seen = []

    def fake_make_llm(client, model):
        async def llm(messages, name, schema, reasoning, max_tokens):
            seen.append((model, name))
            content = GRADE_OK
            if name == "attack":
                content = json.dumps(
                    {"extracted_values": [], "person_attributes": [],
                     "private_situation": "has bipolar II and asks HR for accommodation"}
                )  # fmt: skip
            return {
                "content": content,
                "model": model,
                "usage": {"prompt_tokens": 1000, "completion_tokens": 100},
            }

        return llm

    monkeypatch.setattr(attack, "make_llm", fake_make_llm)
    monkeypatch.setattr(attack, "read_env_key", lambda name="NEBIUS_API_KEY": "test")
    opts = attack.parse_args(
        ["--rescore", str(tmp_path), "--attack-model", attack.SUPER, "--grader-model", attack.NANO]
    )
    out = asyncio.run(attack.run_attack(opts))
    assert seen == [(attack.SUPER, "attack"), (attack.NANO, "situation")]
    config = json.loads((out / "config.json").read_text())
    assert config["attack_model"] == config["model"] == attack.SUPER
    assert config["grader_model"] == attack.NANO
    assert config["usage_by_role"]["grader"] == {
        "model": attack.NANO, "prompt_tokens": 1000, "completion_tokens": 100
    }  # fmt: skip
    assert config["cost_usd"] == pytest.approx((300 + 90 + 60 + 24) / 1_000_000)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["config"]["grader_model"] == attack.NANO
    md = (out / "summary.md").read_text()
    assert f"attacker: `{attack.SUPER}`" in md and f"graders: `{attack.NANO}`" in md
    row = json.loads((out / "pass_01.jsonl").read_text())
    assert row["attacker"]["model"] == attack.SUPER
    assert row["situation_grader"]["model"] == attack.NANO


def test_utility_reuses_judgments_only_from_the_same_models():
    class Opts:
        judge_model = attack.ULTRA
        confirm_model = attack.ULTRA

    legacy = {
        "judge": {"raw": "{}"},
        "system": {"usefulness": 2, "distortion": True, "distortion_judge": True},
        "reference": {"usefulness": 5, "distortion": False},
    }
    assert utility.same_models(legacy, Opts)
    Opts.confirm_model = attack.NANO
    assert not utility.same_models(legacy, Opts)
    unflagged = {**legacy, "system": {"usefulness": 4, "distortion": False}}
    assert utility.same_models(unflagged, Opts)  # no confirmation call was made
    Opts.judge_model = attack.SUPER
    assert not utility.same_models(unflagged, Opts)


def test_verify_distortions_uses_the_confirmation_model():
    calls = []

    async def confirm(messages, name, schema, reasoning, max_tokens):
        calls.append(name)
        return {"content": '{"quote": "age 30", "confirmed": false}', "model": attack.NANO}

    grade = {"usefulness": 2, "distortion": True, "distortion_detail": "age"}
    checks = asyncio.run(utility.verify_distortions(confirm, "req", [(grade, "answer")]))
    assert calls == ["verify_distortion"] and len(checks) == 1
    assert grade["distortion"] is False and grade["distortion_judge"] is True
    assert grade["verify_model"] == attack.NANO
