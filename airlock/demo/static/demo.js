
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const mark = (s) => esc(s).replace(/&lt;[A-Z][A-Z_]*_\d+&gt;|\[\[[A-Z][A-Z_]*_\d+\]\]/g, (m) => `<span class="ph">${m}</span>`);
  const MODE = { chat: "Chat", search: "Private search", agent: "Agent" };
  const REASON = {
    budget_exhausted: "Today's demo budget is used up, so this is a recorded run of the same scenario.",
    rate_limited: "You reached the demo rate limit, so this is a recorded run of the same scenario.",
    busy: "The demo is busy, so this is a recorded run of the same scenario.",
    live_error: "The live run failed, so this is a recorded run of the same scenario.",
    recorded_mode: "Live runs are paused, so this is a recorded run of the same scenario.",
  };
  let running = false;

  async function loadStatus() {
    try {
      const s = await (await fetch("/demo/status")).json();
      const note = $("demo-budget-note");
      if (s.budget && s.budget.exhausted) {
        note.innerHTML = ` · <span class="exhausted">Daily demo budget reached: scenarios show recorded runs until 00:00 UTC.</span> <a href="/demo/budget">Details</a>`;
      } else if (s.limits) {
        note.textContent = ` · Limit: ${s.limits.requests_per_window} requests per ${Math.round(s.limits.window_s / 60)} min, ${s.limits.max_input_chars} characters per input.`;
      }
    } catch { /* the banner still stands without status */ }
  }

  async function loadPresets() {
    const wrap = $("demo-presets");
    try {
      const { presets } = await (await fetch("/demo/presets")).json();
      wrap.innerHTML = "";
      for (const p of presets) {
        const b = document.createElement("button");
        b.type = "button"; b.className = "demo-preset";
        b.innerHTML = `<span class="t">${esc(p.title)}</span><span class="b">${esc(p.blurb)}</span>` +
          `<span class="chips"><span class="chip">${esc(MODE[p.mode] || p.mode)}</span><span class="chip">${esc(p.lang.toUpperCase())}</span></span>`;
        b.onclick = () => run(p);
        wrap.appendChild(b);
      }
    } catch { wrap.innerHTML = `<span class="empty">Scenarios could not be loaded.</span>`; }
  }

  function items(list, withMarks) {
    if (!list || !list.length) return `<span class="empty">Nothing left the server for the cloud.</span>`;
    return list.map((x) => `<div class="demo-item"><span class="role">${esc(x.label)}</span>${withMarks ? mark(x.text) : esc(x.text)}</div>`).join("");
  }

  function render(d) {
    $("demo-result").hidden = false;
    const live = d.source === "live";
    const when = d.recorded_at ? ` (${esc(String(d.recorded_at).slice(0, 10))})` : "";
    const gate = d.gate && d.gate.decision;
    let head = `<h3>${esc(d.title)}</h3>` +
      `<span class="badge ${live ? "live" : "recorded"}">${live ? "live run" : "recorded run" + when}</span>`;
    if (gate) head += `<span class="badge ${gate === "allow" ? "allow" : "block"}">Gate: ${esc(gate.toUpperCase())}</span>`;
    const det = (d.detections || []).map((x) => `${x.type} · ${x.action}`);
    if (det.length) head += `<span class="meta">${esc(det.length)} redaction(s): ${esc([...new Set(det)].join(", "))}</span>`;
    if (!live) head += `<span class="meta">${esc(REASON[d.fallback_reason] || "Recorded run.")}</span>`;
    if (d.models) head += `<span class="meta">detector: ${esc(d.models.detector)} · cloud: ${esc(d.model_used || d.models.upstream)}</span>`;
    $("demo-result-head").innerHTML = head;
    $("demo-typed").innerHTML = items(d.typed, false);
    $("demo-cloud").innerHTML = items(d.cloud_saw, true);
    let answer = "";
    if (d.error) answer = `<span class="empty">${esc(d.error.type)}: ${esc(d.error.message || (d.error.reasons || []).join(", ") || "blocked before leaving")}</span>`;
    else if (d.mode === "search") {
      $("demo-answer-title").textContent = "Results (re-ranked on the server)";
      answer = (d.results || []).map((r) => `<div class="demo-item"><span class="role">#${esc(r.rank)}</span><a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.title)}</a><br>${esc(r.snippet)}</div>`).join("") || `<span class="empty">No results.</span>`;
    } else {
      $("demo-answer-title").textContent = "Answer (placeholders restored)";
      answer = d.answer ? esc(d.answer) : `<span class="empty">No answer.</span>`;
      if (d.stats && d.stats.steps) answer = `<div class="meta">${esc(d.stats.steps)} step(s) · ${esc(d.stats.searches)} search(es) · ${esc(d.stats.search_rewritten)} rewritten · ${esc(d.stats.search_blocked)} blocked</div>` + answer;
    }
    $("demo-answer").innerHTML = answer;
  }

  async function run(p) {
    if (running) return;
    running = true;
    for (const b of document.querySelectorAll(".demo-preset")) b.disabled = true;
    $("demo-run-status").textContent = p.mode === "agent" ? "Running the agent through Airlock (this can take a minute)…" : "Running through Airlock…";
    try {
      const r = await fetch(`/demo/presets/${encodeURIComponent(p.id)}/run`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d?.error?.message || `HTTP ${r.status}`);
      render(d);
      $("demo-run-status").textContent = "";
      $("demo-result").scrollIntoView({ block: "nearest" });
    } catch (e) {
      $("demo-run-status").textContent = "Error: " + e.message;
    } finally {
      running = false;
      for (const b of document.querySelectorAll(".demo-preset")) b.disabled = false;
      loadStatus();
    }
  }

  loadStatus();
  loadPresets();
})();
