(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const state = { pods: [], lastResult: null, stepTimer: null };

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).detail || msg; } catch (_) {}
      throw new Error(`${r.status} · ${msg}`);
    }
    return r.json();
  }

  // ---------- header / config ----------
  async function init() {
    try {
      const cfg = await api("/api/config");
      $("#chip-model").textContent = `model: ${cfg.model}`;
      const chip = $("#chip-status");
      chip.classList.add(cfg.ai_configured ? "ok" : "bad");
      chip.querySelector("span").textContent = cfg.demo ? "demo mode" : cfg.ai_configured ? "AI ready" : "no API key";
    } catch (e) {
      $("#chip-status").classList.add("bad");
      $("#chip-status span").textContent = "backend offline";
    }
    loadNamespaces();
  }

  async function loadNamespaces() {
    const sel = $("#ns");
    try {
      const list = await api("/api/namespaces");
      sel.innerHTML = list.map((n) => `<option>${esc(n)}</option>`).join("");
      const pref = list.find((n) => n === "default") || list[0];
      sel.value = pref;
      loadPods();
    } catch (e) {
      sel.innerHTML = "<option>unavailable</option>";
      $("#pods").innerHTML = `<div class="empty">Cluster not reachable (${esc(e.message)}).<br>Use the <b>Paste logs</b> tab instead.</div>`;
    }
  }

  async function loadPods() {
    const ns = $("#ns").value;
    $("#pods").innerHTML = '<div class="empty">Loading pods…</div>';
    try {
      state.pods = await api(`/api/pods?namespace=${encodeURIComponent(ns)}`);
      renderPods();
    } catch (e) {
      $("#pods").innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    }
  }

  function renderPods() {
    const only = $("#only-bad").checked;
    const list = state.pods.filter((p) => !only || p.unhealthy);
    $("#pod-count").textContent = `(${list.length}/${state.pods.length})`;
    if (!list.length) {
      $("#pods").innerHTML = `<div class="empty">${only ? "🎉 No unhealthy pods here. Untick “only unhealthy” to see all." : "No pods."}</div>`;
      return;
    }
    $("#pods").innerHTML = list.map((p, i) => {
      const cls = p.unhealthy ? "bad" : "ok";
      return `<button class="pod" data-i="${state.pods.indexOf(p)}">
        <span class="name">${esc(p.name)}</span>
        ${p.reason ? `<span class="pill bad">${esc(p.reason)}</span>` : ""}
        <span class="pill ${cls}">${esc(p.phase)} ${esc(p.ready)}</span>
        ${p.restarts ? `<span class="pill warn">↻ ${p.restarts}</span>` : ""}
        <span class="go-arrow">Analyze →</span></button>`;
    }).join("");
  }

  // ---------- loading animation ----------
  function startLoading() {
    $("#result").classList.add("hidden");
    $("#error").classList.add("hidden");
    $("#loading").classList.remove("hidden");
    const items = [...document.querySelectorAll("#steps li")];
    items.forEach((li) => (li.className = ""));
    let i = 0;
    const tick = () => {
      items.forEach((li, idx) => (li.className = idx < i ? "done" : idx === i ? "on" : ""));
      if (i < items.length - 1) i++;
    };
    tick();
    state.stepTimer = setInterval(tick, 1400);
    $("#loading").scrollIntoView({ behavior: "smooth", block: "center" });
  }
  function stopLoading() {
    clearInterval(state.stepTimer);
    $("#loading").classList.add("hidden");
  }

  async function run(path, body) {
    startLoading();
    try {
      const res = await api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      stopLoading();
      state.lastResult = res;
      render(res);
    } catch (e) {
      stopLoading();
      const box = $("#error");
      box.textContent = `✖ ${e.message}`;
      box.classList.remove("hidden");
    }
  }

  // ---------- render ----------
  const li = (arr) => (arr || []).map((x) => `<li>${fmt(x)}</li>`).join("") || "<li>—</li>";
  // turn `backticked` and kubectl lines into code chips
  function fmt(s) {
    const e = esc(s);
    if (/^\s*(kubectl|helm|oc)\s/.test(s)) return `<span class="cmd">${e}</span>`;
    return e.replace(/`([^`]+)`/g, '<span class="cmd">$1</span>');
  }

  function render({ report: r, meta: m }) {
    const sevColor = `var(--sev-${r.severity})`;
    const whys = r.five_whys.map((w, i) => `
      <div class="why ${i === r.five_whys.length - 1 ? "root" : ""}" style="animation-delay:${i * 0.35}s">
        <div class="num">${w.level}</div>
        <div class="body">
          <div class="q"><span>Why?</span> ${esc(w.question)}</div>
          <div class="a">${esc(w.answer)}</div>
          ${w.evidence ? `<code>${esc(w.evidence)}</code>` : ""}
        </div>
      </div>`).join("");

    $("#result").innerHTML = `
      <div class="rhead" style="--sev:${sevColor}">
        <div class="info">
          <span class="sev">${esc(r.severity)}</span>
          <h2>${esc(r.title)}</h2>
          <p>${esc(r.summary)}</p>
          <p style="margin-top:8px"><b>Impact:</b> ${esc(r.impact)}</p>
          <div class="meta">
            <span class="pill">${esc(m.namespace)}/${esc(m.pod)}</span>
            <span class="pill">${esc(m.model)}</span>
            <span class="pill">${m.event_count} events</span>
            <span class="pill">${(m.log_chars / 1000).toFixed(1)}k log chars</span>
            <span class="pill">${(m.latency_ms / 1000).toFixed(1)}s</span>
          </div>
        </div>
        <div class="ring" style="--v:${Math.round(r.confidence * 100)}"><b>${Math.round(r.confidence * 100)}%</b><small>confidence</small></div>
      </div>

      <h3 class="sec">// the 5 whys</h3>
      <div class="chain">${whys}</div>

      <div class="root-card"><h3>🎯 Root cause</h3><p>${esc(r.root_cause)}</p></div>

      <div class="cols">
        <div class="box fix"><h4>⚡ Fix now</h4><ul>${li(r.immediate_actions)}</ul></div>
        <div class="box prev"><h4>🛡 Prevent it</h4><ul>${li(r.preventive_actions)}</ul></div>
      </div>
      <div class="cols">
        <div class="box tl"><h4>⏱ Timeline</h4><ul>${li(r.timeline)}</ul></div>
        <div class="box"><h4 style="color:var(--c)">🧩 Contributing factors</h4><ul>${li(r.contributing_factors)}</ul></div>
        <div class="box gap"><h4>❓ Data gaps</h4><ul>${li(r.data_gaps)}</ul></div>
      </div>

      <div class="actions">
        <button class="btn" id="copy-md">📋 Copy as Markdown</button>
        <button class="btn" id="dl-json">⬇ Download JSON</button>
        <button class="btn" id="again">↺ New analysis</button>
      </div>`;
    $("#result").classList.remove("hidden");
    $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
    $("#copy-md").onclick = (ev) => copy(toMarkdown(state.lastResult), ev.target);
    $("#dl-json").onclick = () => download(state.lastResult);
    $("#again").onclick = () => { $("#result").classList.add("hidden"); window.scrollTo({ top: 0, behavior: "smooth" }); };
  }

  function toMarkdown({ report: r, meta: m }) {
    const L = (a) => (a || []).map((x) => `- ${x}`).join("\n") || "- —";
    return `# RCA: ${r.title}
**Severity:** ${r.severity} · **Confidence:** ${Math.round(r.confidence * 100)}% · **Target:** ${m.namespace}/${m.pod} · **Model:** ${m.model} · **Generated:** ${m.generated_at}

## Summary
${r.summary}

**Impact:** ${r.impact}

## Timeline
${L(r.timeline)}

## 5 Whys
${r.five_whys.map((w) => `${w.level}. **${w.question}**\n   ${w.answer}\n   > evidence: \`${w.evidence}\``).join("\n")}

## Root cause
${r.root_cause}

## Contributing factors
${L(r.contributing_factors)}

## Immediate actions
${L(r.immediate_actions)}

## Preventive actions
${L(r.preventive_actions)}

## Data gaps
${L(r.data_gaps)}
`;
  }
  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); btn.textContent = "✓ Copied"; }
    catch (_) { btn.textContent = "Copy failed"; }
    setTimeout(() => (btn.textContent = "📋 Copy as Markdown"), 1800);
  }
  function download(obj) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }));
    a.download = `rca-${obj.meta.pod}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ---------- events ----------
  document.querySelectorAll(".tab").forEach((t) => (t.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
    $("#tab-live").classList.toggle("hidden", t.dataset.tab !== "live");
    $("#tab-paste").classList.toggle("hidden", t.dataset.tab !== "paste");
  }));
  $("#ns").onchange = loadPods;
  $("#only-bad").onchange = renderPods;
  $("#pods").onclick = (e) => {
    const b = e.target.closest(".pod");
    if (!b) return;
    const p = state.pods[+b.dataset.i];
    run("/api/rca", {
      namespace: $("#ns").value, pod: p.name, tail_lines: +$("#tail").value,
      since_minutes: $("#since").value ? +$("#since").value : null, include_previous: true,
    });
  };
  $("#go-raw").onclick = () => {
    const logs = $("#raw-logs").value.trim();
    if (!logs) { const b = $("#error"); b.textContent = "✖ Paste some logs first."; b.classList.remove("hidden"); return; }
    run("/api/rca/raw", { logs, events: $("#raw-events").value, service: $("#svc").value || "unknown" });
  };

  init();
})();
