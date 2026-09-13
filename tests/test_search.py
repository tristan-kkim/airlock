import json


def test_search_rewrites_query_and_reranks_locally(client, harness) -> None:
    harness.entities = {
        "Minji Lee": ("PERSON", "mask", ""),
        "Seoul Mirae Bank": ("ORG", "mask", ""),
    }
    harness.rewrite = lambda q, c: "severance pay rules after layoff South Korea"
    r = client.post(
        "/v1/search",
        json={
            "query": "Can Seoul Mirae Bank fire Minji Lee without severance?",
            "context": "Minji Lee, employee ID 900101-1234567, was told on Friday.",
            "max_results": 2,
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data) == {"request_id", "outbound_query", "results", "answer"}
    assert data["outbound_query"] == "severance pay rules after layoff South Korea"
    assert harness.tavily_requests == [
        {
            "query": "severance pay rules after layoff South Korea",
            "max_results": 2,
            "search_depth": "basic",
            "include_answer": True,
        }
    ]
    # The fake ranker reverses the order.
    assert [x["title"] for x in data["results"]] == ["Result B", "Result A"]
    assert [x["local_rank"] for x in data["results"]] == [1, 2]
    assert data["answer"] == "tavily answer"
    assert r.headers["x-airlock-request-id"] == data["request_id"]

    audit = client.get(f"/audit/{data['request_id']}").json()
    assert audit["kind"] == "search"
    assert audit["outbound"] == [{"destination": "tavily", "payload": harness.tavily_requests[0]}]
    assert audit["gate"]["decision"] == "allow"
    blob = json.dumps(audit, ensure_ascii=False)
    for original in ("Minji Lee", "Seoul Mirae Bank", "900101-1234567"):
        assert original not in blob
    assert {d["source"] for d in audit["detections"]} >= {"llm", "regex"}


def test_search_blocks_rewrite_that_leaks_identity(client, harness) -> None:
    harness.entities = {"Minji Lee": ("PERSON", "mask", "")}
    harness.rewrite = lambda q, c: "Minji Lee severance"
    r = client.post("/v1/search", json={"query": "severance for Minji Lee", "max_results": 3})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["type"] == "airlock_blocked"
    assert err["reasons"][0].startswith("vault_original:PERSON:")
    assert harness.tavily_requests == []
    audit = client.get(f"/audit/{err['request_id']}").json()
    assert audit["outbound"] == [] and "Minji Lee" not in json.dumps(audit)


def test_search_allows_generalized_topic(client, harness) -> None:
    harness.entities = {"type 1 diabetes": ("HEALTH", "generalize", "a chronic condition")}
    harness.rewrite = lambda q, c: "type 1 diabetes travel insulin tips"
    r = client.post(
        "/v1/search",
        json={"query": "travel tips for my son with type 1 diabetes", "max_results": 2},
    )
    assert r.status_code == 200, r.text


def test_search_fails_closed_without_local_model(client, harness) -> None:
    harness.local_down = True
    r = client.post("/v1/search", json={"query": "anything", "max_results": 1})
    assert r.status_code == 422
    assert r.json()["error"]["reasons"] == ["local_detector_unavailable:LocalModelUnavailable"]
    assert harness.tavily_requests == []
