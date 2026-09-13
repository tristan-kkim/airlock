# Airlock

**A local privacy airlock between your apps and cloud AI.**

Point any OpenAI-compatible app at `http://127.0.0.1:8787/v1`. Before a request leaves your machine, deterministic detectors and a small local model find what is private, the vault swaps it for placeholders, and a deterministic gate checks the exact outbound bytes. The large cloud model does the reasoning on the sanitized text. The answer is restored locally, and every request leaves an audit record of exactly what the cloud saw.

> The small local model does not solve the task. It only decides what is private. The big cloud model does the reasoning.

## Why

People and companies avoid cloud AI mainly because of leakage: names, customer data, health details, credentials pasted into a prompt. Local-only models avoid the leak, but they are much weaker than frontier models. Airlock splits the job:

- **On device:** regex and entropy detectors mask secrets and identifiers first. NVIDIA Nemotron-3-Nano-4B then proposes semantic spans (names, organizations, health details, quasi-identifiers) on the partially masked text, and deterministic Korean rules back it up where the small model is weak. Optionally, you confirm the redactions before anything is sent.
- **In the cloud:** Nemotron 3 Ultra on Nebius Token Factory answers the sanitized request.
- **Between them:** a gate written in plain code, not a prompt. A model never gets to say "this is fine."

It works with tools you already use (scripts, notebooks, editors, agents) by changing one `base_url`.

## Architecture

```mermaid
flowchart LR
    App["Any app<br/>(OpenAI SDK, base_url = localhost)"] -->|request| Detect

    subgraph Local["Your machine"]
        Detect["Detect<br/>1. regex / entropy / vault terms<br/>2. mask them, then Nemotron-3-Nano-4B<br/>3. Korean rules + span verification"]
        Review{{"Review (optional)<br/>HTTP 409 → POST /review/id"}}
        Vault[("Vault<br/>original ↔ #60;PERSON_1#62;<br/>SQLite, local only")]
        Gate{"Deterministic gate<br/>originals, declared terms,<br/>canaries, secret patterns"}
        Rehydrate["Rehydrate<br/>#60;PERSON_1#62; → original"]
        Audit[("Audit log<br/>exact outbound payload,<br/>hashes only")]
        Detect --> Review --> Vault --> Gate
        Gate -. record .-> Audit
    end

    Gate -->|"BLOCK: HTTP 422"| App
    Gate -->|"ALLOW: sanitized JSON"| TF["Nebius Token Factory<br/>Nemotron 3 Ultra"]
    TF -->|"answer with placeholders"| Rehydrate
    Rehydrate -->|"answer with originals"| App

    subgraph Search["Private search"]
        Rewrite["Local rewrite<br/>(no identity, no intent)"] --> Gate2{"Gate"} --> Tavily["Tavily /search"]
        Tavily --> Rerank["Local re-rank<br/>against private context"]
    end
```

Request flow for `POST /v1/chat/completions`:

1. **Detect.** Every text slot (message content, text parts, tool-call arguments) goes through these steps, in order:
   1. **Deterministic spans first:** regex and entropy detectors, exact and variant matching against the vault (your declared terms and this conversation's earlier originals), and base64 blobs that hide a known value.
   2. **Mask before the model:** those spans are replaced by local tokens (`<SECRET_1>`) in the copy the local model reads. The model never receives raw secrets, cannot echo them, and has less to copy.
   3. **Korean semantic rules** ([`airlock/detect/ko_rules.py`](airlock/detect/ko_rules.py)) propose spans the small model often misses in Korean: uniqueness cues (`유일한 여성 부사장`, `the only male nurse`), health terms in a sentence about a person (`공황장애 진단을 받았`), company and institution suffixes (`새론다움물류`, `㈜누리소프트`, `한빛병원`), and names before titles (`박지훈 고객`, `문태오 대리`). Each rule has negative lists (public figures, famous companies, generic words like `유일한 방법`, `초등학교`, `국회의원`) and never fires inside a placeholder.
   4. **Local model:** Nemotron-3-Nano-4B reads the masked draft with a JSON-schema-constrained output (temperature 0.6, top_p 0.95, thinking off, output cap sized to the input). The prompt lives in [`airlock/prompts/detector.md`](airlock/prompts/detector.md).
   5. **Verify:** a model span whose text does not occur in the original (after the vault's normalization) is discarded, so hallucinated IDs never become redactions. Discard counts are recorded in the audit record.
2. **Resolve and substitute.** Overlapping spans are resolved with a longest-span-wins rule. Each original gets a typed placeholder (`<PERSON_1>`, `<SECRET_1>`, ...) or, for health details and quasi-identifiers, a generalization ("in their 30s"). A generalization is rejected, and the span masked instead, when it still contains the original, a digit run or rare word from it, a proper noun, text in another language, or junk. Within a conversation, the same original always maps to the same placeholder.
3. **Gate.** The final outbound JSON is walked string by string, keys and numbers included. If any vault original, declared term, canary, or high-confidence secret or ID pattern is still present, or if the request contains content Airlock cannot inspect (images), the request is blocked with HTTP 422. "Present" covers variants, not only exact text:
   - letter case, full-width characters, and zero-width or other invisible format characters
   - inserted spaces or punctuation (`새론 다움물류` matches `새론다움물류`)
   - numbers written with separators, spaced-out digits, or Korean, Hanja or English numerals (`공일공 이삼사오 …`)
   - values hidden inside JSON strings (tool-call arguments), percent-encoding, or base64/base64url, up to two layers deep

   The vault matcher uses the same normalized views, so a variant is usually masked rather than blocked. If the local model is down, times out, or malfunctions (prose instead of JSON, invalid JSON, output cut off at the token cap, a repetition loop), the request is also blocked after at most one resample of a short malformed answer. Airlock fails closed.
4. **Upstream.** The exact bytes that passed the gate go to Token Factory. When placeholders are present, a one-line system note says: "Tokens like <PERSON_1> are placeholders for private values; copy them exactly." If the primary model returns 5xx or reports itself unavailable, Airlock retries once on the fallback model. That attempt is also audited.
5. **Rehydrate.** Placeholders in the answer, including tool-call arguments and streamed deltas, are mapped back to the originals on your machine. Matching is lenient about what a model may do to the brackets (`< PERSON_1 >`, `&lt;PERSON_1&gt;`, `[[PERSON_1]]`, `⟨PERSON_1⟩`, full-width brackets, lower case) but only replaces keys that exist in the conversation, so `List<T>` or HTML is left alone. The older `[[PERSON_1]]` syntax is still accepted in client histories and old vault files.
6. **Audit.** One record per request stores the outbound payloads verbatim, detections as SHA-256 hashes, the gate decision, and timings.

### Optional: NVIDIA GLiNER-PII ensemble

`AIRLOCK_GLINER=on` adds [`nvidia/gliner-PII`](https://huggingface.co/nvidia/gliner-PII) (570M span NER, the NeMo Guardrails PII backend) as a second local proposer. Install it with `uv sync --extra gliner` and point `AIRLOCK_GLINER_MODEL` at the downloaded weights.

```mermaid
flowchart LR
    T["Text slots of one request"] --> D["regex / entropy / vault<br/>→ mask → Nano-4B spans<br/>+ Korean rules"]
    T --> G["GLiNER-PII<br/>34 labels, threshold 0.4<br/>(runs in parallel, CPU)"]
    D --> A{"Agreement?<br/>overlaps a span from<br/>another source"}
    G --> A
    A -->|yes| Accept["accept"]
    A -->|"GLiNER only"| F{"Type consistency<br/>SECRET: entropy/pattern<br/>phone/ID/account: digit or code shape<br/>PERSON: surname + 3-4 Hangul syllables<br/>or capitalized Latin words<br/>age/date/money text: drop<br/>city, birth date: agreement only"}
    F -->|fails| Drop["drop (counted)"]
    F -->|passes| J{"Nano-4B adjudication<br/>one batched call per request<br/>JSON schema, temp 0, thinking off<br/>'private to the user here?'"}
    J -->|yes| Accept
    J -->|no| Drop
    Accept --> R["overlap resolution → vault → gate"]
```

Why three steps instead of trusting GLiNER:

- **GLiNER has the recall.** Alone on the 243-case eval it leaks 19.0% of cases, against 76.9% for Presidio and 94.0% for regex ([`eval/results/COMPARISON.md`](eval/results/COMPARISON.md)).
- **It over-masks, most of all in Korean.** It masks 59.3% of benign prompts and loses 14.1% of the strings answers need. It was trained on English only: in `qid-ko-01` the age `마흔다섯` became PASSWORD and the company RELIGIOUS_BELIEF. Airlock drops the labels that drove that (religion, gender, occupation, age, dates, URLs, IPs), and Nano and the Korean rules handle quasi-identifiers with generalizations instead.
- **Agreement is free precision.** When regex, the rules or Nano already flagged an overlapping span, the second opinion costs nothing and can only widen a mask. A GLiNER span next to a generalization never overrides it.
- **Type consistency is deterministic and explainable.** A span labeled PASSWORD with no Latin letters and digits, or a phone number with no digits, is a mislabel no matter the score. Korean particles the tokenizer attached (`조유나입니다`, `F8YAXXGS이고`) are trimmed first, and a Korean name under a wrong label (`독고새론` as password) is kept as PERSON.
- **Local adjudication settles context.** Whether `Tucson` or `Corvenna Systems` is private depends on the sentence. Only GLiNER-only spans that passed the shape check are asked, all in one call with `<TYPE>` tokens in place of pattern values, so requests without such candidates pay nothing. A malformed answer blocks the request, like any local detector failure.

If the package or weights are missing while `AIRLOCK_GLINER=on`, `airlock serve` refuses to start and `airlock doctor` reports it; nothing fails per request. Per-request counters go to `meta.detector` (`gliner_spans`, `gliner_agreed`, `gliner_rejected_mislabel`, `gliner_rejected_shape`, `gliner_remapped`, `gliner_candidates`, `adjudication_calls`, `adjudicated_yes`, `adjudicated_no`, `gliner_ms`, `adjudication_ms`). With GLiNER off these keys are absent and behavior is unchanged.

**Measured** ([`eval/results/ENSEMBLE.md`](eval/results/ENSEMBLE.md)), 1 pass per config on the 171-case test split. Thresholds, shape rules, the adjudication prompt and the variant were chosen on a separate 72-case dev split.

| Test split (70%) | Leak | Canary leak | Quasi re-id | Benign masked | Over-block benign | Over-redaction | Leak ko / en |
|---|---:|---:|---:|---:|---:|---:|---:|
| GLiNER off (HEAD detector) | 26.3% | 14.1% | 38.9% | 0.0% | 0.0% | 14.1% | 26.0% / 26.7% |
| GLiNER ensemble (default) | 11.2% | 1.0% | 27.8% | 21.1% | 10.5% | 15.5% | 13.0% / 9.3% |

Over all 243 cases, an LLM attacker reading only the outbound payloads recovers 1.0% of planted values with the ensemble, against 9.9% without it. The cost is real: 4 of 19 benign test prompts get a mask, and 2 benign searches are blocked because the local rewrite kept an organization GLiNER flagged. GLiNER adds p50 457 ms / p95 635 ms of CPU inference, run in parallel with Nano. The adjudication call is needed in 28% of chat requests and then takes p50 1.7 s / p95 2.2 s. Local latency across runs was contaminated by other models sharing the laptop.

## Quickstart

Requirements: macOS or Linux, Python 3.12, [uv](https://docs.astral.sh/uv/), [llama.cpp](https://github.com/ggml-org/llama.cpp) (`llama-server`).

```bash
git clone https://github.com/tristan-kkim/airlock && cd airlock
uv sync

# 1. Local detector model (Nemotron-3-Nano-4B GGUF via llama-server on 127.0.0.1:8081)
scripts/local_model/serve.sh

# 2. Keys
cp .env.example .env   # set NEBIUS_API_KEY and TAVILY_API_KEY

# 3. Check everything (never prints secrets), then run
uv run airlock doctor
uv run airlock serve   # http://127.0.0.1:8787
```

See [`scripts/local_model/serve.sh`](scripts/local_model/serve.sh) for downloading the model and serving it.

Open <http://127.0.0.1:8787/> for the demo UI. It has three panes: **What you typed**, **What the cloud saw**, and **Answer (rehydrated)**, plus the gate decision and detections. With **Review redactions before sending** on, it first lists every proposed redaction with a before/after preview; uncheck the ones you want sent as written, add anything that was missed, then **Send**.

Use it from any OpenAI client:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="unused-locally")
reply = client.chat.completions.create(
    model="any",  # Airlock always uses AIRLOCK_UPSTREAM_MODEL
    messages=[{"role": "user", "content": "I'm Jane Park, 010-2345-6789. Draft a note to my landlord."}],
)
print(reply.choices[0].message.content)  # contains your real name and number again
```

Run the tests (fully offline, all services mocked):

```bash
uv run pytest -q
uv run ruff check
uv run pytest -m live   # opt-in: real local model / Token Factory / Tavily using .env
```

## How Airlock uses NVIDIA Nemotron and Nebius Token Factory

Airlock is built around a division of labour between two NVIDIA open models.

| Role | Model | Where it runs | Why this model |
|---|---|---|---|
| Privacy detector, search rewriter, result re-ranker | **NVIDIA Nemotron-3-Nano-4B** (`nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF`, Q4_K_M) | On your machine via llama.cpp | Small enough to run on a laptop, and it follows a JSON schema reliably. It sees private text (with pattern-detected secrets already masked), so it must never leave the device. Reasoning is disabled per request (`chat_template_kwargs.enable_thinking=false`) to keep latency low. |
| Optional second PII proposer | **NVIDIA GLiNER-PII** (`nvidia/gliner-PII`) | On your machine (PyTorch, CPU by default) | High recall on names, IDs and secrets, including many Korean spans. Its over-masking is filtered by agreement, type checks and a Nano adjudication call (see the ensemble section). |
| Reasoning over the sanitized request | **NVIDIA Nemotron 3 Ultra** (`nvidia/Nemotron-3-Ultra-550b-a55b`) | **Nebius Token Factory** (OpenAI-compatible API) | A frontier-class open model for the real task. It only ever receives placeholders and generalizations, and it keeps `<PERSON_1>`-style placeholders intact, including in Korean output. |
| Fallback | **NVIDIA Nemotron 3 Super** (`nvidia/nemotron-3-super-120b-a12b`) | Nebius Token Factory | Used once, automatically, when Ultra returns 5xx or is unavailable. `reasoning_effort` is dropped for this model because it rejects that field. Its `reasoning_content` is hidden from clients unless they opt in. |

Token Factory is on the execution path of every allowed chat request: `POST https://api.tokenfactory.nebius.com/v1/chat/completions` with `Authorization: Bearer $NEBIUS_API_KEY`. Airlock forwards `tools`, `tool_choice`, `reasoning_effort` and `stream` unchanged. It does not rely on upstream `response_format: json_schema`.

**Data retention.** By default, Token Factory may store prompts and outputs unless Zero Data Retention (ZDR) is enabled for your account or project. We recommend enabling ZDR. Airlock's guarantee does not depend on it: whatever the provider keeps is the sanitized payload shown in the audit log, never your originals.

Web search uses [Tavily](https://tavily.com) (`POST /search`, basic depth). Nemotron-3-Nano rewrites the query locally before it is sent, and re-ranks the results locally afterwards.

## Configuration

All settings are environment variables. Airlock also reads `.env`; see [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `AIRLOCK_LOCAL_BASE_URL` | `http://127.0.0.1:8081/v1` | Local OpenAI-compatible server (llama.cpp) |
| `AIRLOCK_LOCAL_MODEL` | `nemotron-3-nano-4b` | Model name sent to the local server |
| `AIRLOCK_LOCAL_DISABLE_THINKING` | `true` | Send `chat_template_kwargs.enable_thinking=false` |
| `NEBIUS_API_KEY` | none | Token Factory key |
| `AIRLOCK_UPSTREAM_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Upstream API |
| `AIRLOCK_UPSTREAM_MODEL` | `nvidia/Nemotron-3-Ultra-550b-a55b` | Primary cloud model |
| `AIRLOCK_UPSTREAM_FALLBACK_MODEL` | `nvidia/nemotron-3-super-120b-a12b` | Retried once on 5xx or model unavailable; empty disables it |
| `TAVILY_API_KEY` | none | Tavily key for `/v1/search` |
| `AIRLOCK_VAULT_PATH` | `./.airlock/vault.sqlite3` | Vault (holds originals; `:memory:` for none on disk) |
| `AIRLOCK_AUDIT_DB` | `./.airlock/audit.sqlite3` | Audit log |
| `AIRLOCK_AUDIT_HASH_KEY` | none | HMAC key for audit hashes; if unset, one is generated at the key file |
| `AIRLOCK_AUDIT_HASH_KEY_FILE` | `./.airlock/audit_hash.key` | Where the generated key is stored (mode 600) |
| `AIRLOCK_PROTECTION_LEVEL` | `balanced` | `strict`, `balanced` or `minimal` (see below) |
| `AIRLOCK_REVIEW` | `never` | `always`, `uncertain` or `never`: when to stop and ask for confirmation (see review mode) |
| `AIRLOCK_LOCAL_TIMEOUT_S` | `30` | Local detector timeout; a timeout blocks the request |
| `AIRLOCK_CANARIES` | none | Comma-separated tripwire strings that must never leave |
| `AIRLOCK_GLINER` | `off` | `on` adds the NVIDIA GLiNER-PII ensemble (needs `uv sync --extra gliner`) |
| `AIRLOCK_GLINER_MODEL` | `nvidia/gliner-PII` | Local weights directory or an already-cached Hub id (falls back to `GLINER_PII_MODEL`); never downloaded at runtime |
| `AIRLOCK_GLINER_THRESHOLD` | `0.4` | Score threshold for every label |
| `AIRLOCK_GLINER_THRESHOLDS` | none | Per-label overrides, e.g. `city=0.6,first_name=0.5` |
| `AIRLOCK_GLINER_DEVICE` | `cpu` | `cpu`, `mps` or `cuda`. On an M3 Pro, `mps` is faster alone but slower while Nano decodes on Metal |
| `AIRLOCK_GLINER_ADJUDICATE` | `on` | Ask the local model about GLiNER-only spans; `off` accepts every span that passes the shape check |
| `AIRLOCK_GLINER_AGREEMENT_ONLY` | `city,date_of_birth` | Labels whose GLiNER-only spans are dropped; only agreement with another source confirms them. Empty adjudicates every label |
| `AIRLOCK_GLINER_KO_NAME_MIN_SYLLABLES` | `3` | Shortest Hangul name GLiNER may add on its own |
| `AIRLOCK_HOST` / `AIRLOCK_PORT` | `127.0.0.1` / `8787` | Bind address |
| `AIRLOCK_ALLOWED_HOSTS` | `127.0.0.1,localhost,::1` | Accepted `Host` headers (DNS-rebinding protection); `*` disables |

Protection levels:

| Level | Direct identifiers and secrets | Quasi-identifiers, health, precise location |
|---|---|---|
| `strict` | masked | always masked with placeholders; the detector is told to flag aggressively |
| `balanced` | masked | generalized as the detector suggests ("34" → "in their 30s") |
| `minimal` | masked | `QUASI_IDENTIFIER` spans are left as-is; health and location are still generalized |

## API

### `POST /v1/chat/completions`

OpenAI-compatible request and response, streaming included. Airlock-specific headers:

- Response `x-airlock-request-id`: key for `GET /audit/{id}`.
- Request/response `x-airlock-conversation-id`: scopes placeholder numbering. If omitted, it is derived from the first user message.
- Request `x-airlock-include-reasoning: 1`: forward the model's `reasoning_content` (rehydrated). Off by default.

Forwarded fields: `messages`, `tools`, `tool_choice`, `parallel_tool_calls`, `reasoning_effort`, `stream`, `stream_options`, `temperature`, `top_p`, `max_tokens`, `max_completion_tokens`, `n`, `stop`, `seed`, `presence_penalty`, `frequency_penalty`, `response_format`, `logprobs`, `top_logprobs`. Everything else (`user`, `metadata`, ...) is dropped. `model` is always replaced by `AIRLOCK_UPSTREAM_MODEL`.

- Request `x-airlock-review: required`: return proposed redactions for confirmation instead of sending (see below).

Blocked requests return HTTP 422:

```json
{"error": {"type": "airlock_blocked", "reasons": ["declared_term:PERSON:6e0aeb4d2ed5"], "request_id": "req_..."}}
```

Reason codes: `vault_original`, `declared_term`, `canary`, `secret_pattern:<rule>`, `uninspectable_content:<part type>`, `local_detector_unavailable:<error>` (connection failure or HTTP error), `local_detector_malformed:<kind>` with kind `prose`, `invalid_json`, `schema`, `length`, `repetition` or `timeout`, and for search also `local_rewriter_unavailable:<error>`, `rewrite_empty`, `rewrite_contains_placeholder`. Reasons carry the first 12 hex characters of the value's keyed hash (see the audit section), never the text.

Other errors: `400 invalid_request_error`, `415` (non-JSON POST), `502 airlock_upstream_error`, `503 airlock_not_configured`.

### Review mode: HTTP 409 and `POST /review/{review_id}`

The local detector is a proposer, and on Korean semantic spans it is far from perfect. Review mode puts the user in the loop before anything is sent. It is triggered by the request header `x-airlock-review: required`, or by `AIRLOCK_REVIEW`:

- `always`: every chat request is held for review.
- `uncertain`: only when the local model found a span no deterministic detector confirmed, when spans or generalizations were discarded, or when a Korean quasi-identifier or health rule fired.
- `never` (default): send directly.

A held request returns HTTP 409 and nothing is written to the vault or sent upstream:

```json
{"error": {"type": "airlock_review_required", "review_id": "rev_...", "reasons": ["llm_only_spans"],
  "proposed": [{"span_id": "s1", "type": "PERSON", "action": "mask", "text": "문태오",
                "replacement": "<PERSON_1>", "preview_before": "…동료 문태오 대리가…",
                "preview_after": "…동료 <PERSON_1> 대리가…", "source": "llm", "sources": ["llm", "rule"],
                "confidence": 0.85, "locked": false}],
  "request_id": "req_...", "expires_in_s": 600}}
```

The previews contain the originals. They are a response to the local client only and never go upstream. `confidence` is a heuristic (higher when independent detectors agree), not a calibrated probability. `locked` marks spans that the gate enforces anyway (vault terms, high-confidence secret patterns): rejecting one makes the gate block.

Continue with:

```json
POST /review/rev_...
{"approve": ["s1"], "reject": ["s2"], "add": [{"text": "Nightjar", "type": "PROJECT"}]}
```

Spans not listed are approved. The response is the normal chat completion (or 422 if the gate blocks), and its audit record carries `meta.review` counts. A review id works once and expires after 10 minutes; `POST /vault/reset` discards pending reviews.

### `POST /v1/search`

```json
{"query": "Can my employer fire me without severance?", "context": "I'm Minji Lee at ...", "max_results": 5}
```

Returns `{"request_id", "outbound_query", "results": [{"title", "url", "content", "score", "local_rank"}], "answer"}`. The context never leaves the machine. Masked values found in the query or context may not appear in the rewritten query; generalized topics (a condition, an age range) may.

### `GET /audit/{request_id}`

```json
{
  "request_id": "req_...", "created_at": "2026-09-13T12:00:00+00:00", "kind": "chat",
  "detections": [{"text_sha256": "...", "type": "PERSON", "action": "mask", "source": "llm"}],
  "outbound": [{"destination": "upstream", "payload": {"model": "...", "messages": ["..."]}}],
  "gate": {"decision": "allow", "reasons": []},
  "timings_ms": {"detect": 212.4, "gate": 0.8, "upstream": 1530.2, "rehydrate": 0.1, "total": 1745.0},
  "meta": {"stream": false, "model_used": "nvidia/Nemotron-3-Ultra-550b-a55b", "fallback": false,
           "detector": {"pattern_spans": 1, "masked_before_llm": 1, "rule_spans": 2, "llm_calls": 1,
                        "llm_proposed": 3, "llm_kept": 2, "llm_discarded_ungrounded": 1,
                        "llm_discarded_invalid": 0, "generalize_rejected": 0, "semantic_cues": 1, "...": 0}}
}
```

`meta.detector` holds counts only: how many spans each detector produced, how many the local model proposed and how many were discarded as ungrounded or invalid, and how many generalizations were rejected. A held request is recorded with `gate.decision` `review`.

`text_sha256` is **HMAC-SHA256** of the original under the local audit key (`AIRLOCK_AUDIT_HASH_KEY`, or the generated `.airlock/audit_hash.key`). The field name is kept for compatibility. To check whether a value you know was detected, compute `hmac.new(key, value.encode(), hashlib.sha256).hexdigest()`. The key is never served over HTTP. `action` is `mask`, `generalize`, or `keep` (detected but intentionally left, under `minimal`). `outbound` holds one entry per payload that was sent, so a fallback produces two. `GET /audit?limit=50` lists recent records.

### `POST /vault/terms`

```json
{"terms": ["Jane Park", "Hanbit Labs"], "type": "PERSON", "kind": "sensitive"}
```

`kind: "sensitive"` terms are always masked and enforced by the gate. `kind: "canary"` terms are never masked: if one reaches an outbound payload, the request is blocked. Returns `{"added", "total", "kind"}`.

### `DELETE /vault/terms`

Body `{"terms": ["Hanbit Labs"], "kind": "sensitive"}` (`kind` optional; omitted removes both kinds). Returns `{"removed", "total"}`.

### `POST /vault/reset`

Body `{}`. Clears every declared term, canary and conversation mapping, plus the in-memory detector cache. Audit records are kept. Returns `{"reset": true, "terms_removed", "mappings_removed"}`. Evaluation harnesses call it between runs instead of restarting the server.

All `POST` endpoints require `Content-Type: application/json`, including `/vault/reset`.

### `GET /healthz`

Status, version, protection level, model names, and whether keys are configured. It makes no network calls.

## Threat model and limitations

**What Airlock is designed to stop:** accidental disclosure of identifying or secret strings from your machine to a cloud LLM provider or a web search provider, through an app you control that talks to the OpenAI API.

**What it guarantees, and how:** a string that Airlock knows is sensitive cannot leave through the proxy in any JSON field. That holds regardless of letter case, Unicode width, invisible characters, inserted spaces or punctuation, digit separators or spelled-out numerals, or base64, percent or JSON-string encoding up to two layers deep. "Knows" means it was detected in this request, detected earlier in the conversation, declared by you, configured as a canary, or matched by a high-confidence secret or ID pattern. This check is plain code on the final bytes. A misbehaving local model can cause over-masking or a block. It cannot cause a known string to be sent.

**What it does not protect against.** Please read this before relying on it.

- **Detector misses.** If the local model, the regexes and the Korean rules all fail to recognise something (an unusual name, an internal project described in plain words), and you did not declare it, it is sent. The gate only enforces what is known. Declare your own name, employer, and key project names with `/vault/terms`, and use review mode for sensitive work. In our local-model spike, Nemotron-3-Nano-4B alone found 70% of Korean semantic spans (11% of Korean quasi-identifiers), against 93% in English; the Korean rules exist to narrow that gap and are measured on a small probe set that was also used to tune the prompt, so treat any number as optimistic.
- **Rule false positives.** The Korean rules prefer to over-mask. A private-sounding company name, a name before a title, or a health term in a personal sentence may be masked even when it is harmless. Review mode lets you undo this.
- **Paraphrase and inference.** Airlock removes strings, not meaning. "My wife, the only female neurosurgeon at the hospital in our small town" contains no name and may still identify someone. Generalization of quasi-identifiers reduces this; it does not eliminate it.
- **Combining requests.** The provider sees many sanitized requests from the same account and may link them.
- **Non-text content.** Images, audio, and files are not inspected, so requests containing them are blocked rather than sent.
- **Tool schemas and names are not rewritten.** Rewriting them would break function calling. The gate still scans them and blocks if they contain known sensitive strings.
- **Search results and answers.** Inbound content is not filtered, and a cloud answer may still mention public facts about you.
- **Your machine.** The vault stores originals in plain text under `./.airlock/`. Anyone with access to your account or disk can read it. Airlock does not protect against malware, a compromised local model server, or other local users. Keep `.airlock/` out of backups and file-sync tools you do not trust, or use `AIRLOCK_VAULT_PATH=:memory:`.
- **Other obfuscations.** The variants listed for the gate are covered. Translation, transliteration (`Kim Minsu` for `김민수`), deliberate misspellings, other encodings (hex, ROT13, compression), splitting a value across messages or fields, and encoding more than two layers deep are not.
- **Audit hashes.** Detections and gate reasons use HMAC-SHA256 under a local key, so the audit file alone does not let anyone brute-force short values such as phone numbers. Anyone who has both the audit file and the key (`.airlock/audit_hash.key`, mode 600) can still test guesses. Protect or rotate the key like the vault. Rotating it makes older records unmatchable.
- **Local API exposure.** The server listens on loopback, checks the `Host` header, and requires JSON content types to resist browser-based cross-origin requests. It has no authentication. Do not expose it on a network.
- **Streaming.** Placeholders split across chunks are held back until complete. Tool-call deltas are buffered and delivered in one piece at the end of the stream.

## Project layout

```
airlock/
  config.py         env configuration
  detect/llm.py     local model client + LLM span detector (fail-closed errors)
  detect/patterns.py Korean-aware PII regexes, secret patterns, entropy check
  detect/ko_rules.py deterministic Korean/English semantic rules (quasi-identifiers, health, orgs, names)
  detect/gliner.py  NVIDIA GLiNER-PII wrapper and ensemble policy (agreement, type checks, adjudication)
  detect/verify.py  grounding check for model spans, generalization leak check
  detect/spans.py   span model, term matching, overlap resolution
  placeholders.py   <TYPE_N> syntax, lenient matching for rehydration
  pipeline.py       patterns -> masked local model -> rules -> verification -> vault substitution
  vault.py          original <-> placeholder mappings, declared terms (SQLite)
  gate.py           deterministic allow/block on the exact outbound payload
  textnorm.py       normalized views (compact, digits, decoded) with raw offset maps
  hashing.py        HMAC key loading for audit hashes
  upstream.py       Token Factory client with one-shot fallback
  rehydrate.py      placeholder restoration, including streams and tool calls
  search.py         private search: local rewrite, gate, Tavily, local re-rank
  audit.py          audit records (hashes only)
  server.py         FastAPI app
  cli.py            `airlock serve`, `airlock doctor`
  prompts/          detector, adjudication, search rewrite and re-rank prompts
  static/index.html demo UI
scripts/local_model/  llama.cpp serving for the local model
eval/                 synthetic evaluation set and harness
tests/                offline test suite
```

All examples and evaluation data are synthetic.

## License

Apache License 2.0. Copyright 2026 Tristan Kim. See [LICENSE](LICENSE).
