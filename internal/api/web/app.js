"use strict";
const state = { zones: [], curId: null, candId: null, plans: [], plan: null, sim: null, probeIdx: 0, viewAt: 0 };
const $ = (id) => document.getElementById(id);

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.style.display = "block";
  setTimeout(() => (t.style.display = "none"), 5000);
}

async function api(method, path, body, reqId) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opt.body = JSON.stringify(body);
  if (reqId) opt.headers["X-Request-Id"] = reqId;
  const res = await fetch(path, opt);
  const text = await res.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
  }
  if (!res.ok) {
    const e = data.error || {};
    throw new Error(`[${e.class || "error"}/${e.code || res.status}] ${e.message || res.statusText}`);
  }
  return data;
}

function fmtFP(fp) { return fp ? fp.slice(0, 12) : "—"; }
function wallClock(sec) {
  const base = Date.UTC(2026, 0, 1);
  return new Date(base + sec * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

async function refreshZones() {
  const data = await api("GET", "/api/zones");
  state.zones = data.zones || [];
  fillZoneSelect($("curSelect"), state.curId);
  fillZoneSelect($("candSelect"), state.candId);
  const cur = state.zones.find((z) => z.id === $("curSelect").value);
  const cand = state.zones.find((z) => z.id === $("candSelect").value);
  $("zoneFps").textContent = cur && cand
    ? `current ${cur.origin} fp=${fmtFP(cur.fingerprint)} ｜ candidate ${cand.origin} fp=${fmtFP(cand.fingerprint)}`
    : "";
}

function fillZoneSelect(sel, preferred) {
  const old = preferred || sel.value;
  sel.innerHTML = "";
  for (const z of state.zones) {
    const o = document.createElement("option");
    o.value = z.id;
    o.textContent = `${z.label || z.origin} (${fmtFP(z.fingerprint)})`;
    sel.appendChild(o);
  }
  if (old && [...sel.options].some((o) => o.value === old)) sel.value = old;
}

$("importBtn").onclick = async () => {
  try {
    const reqId = "zone-" + crypto.randomUUID();
    const a = await api("POST", "/api/zones", { label: "current", text: $("curZone").value }, reqId);
    await api("POST", "/api/zones", { label: "candidate", text: $("candZone").value }, "zone-" + crypto.randomUUID());
    state.curId = a.id;
    await refreshZones();
    toast("zone 已导入，原始输入单独保存在 raw/zones");
  } catch (e) { toast(e.message); }
};
$("refreshZones").onclick = () => refreshZones().catch((e) => toast(e.message));
$("curSelect").onchange = (e) => (state.curId = e.target.value);
$("candSelect").onchange = (e) => (state.candId = e.target.value);

// --- phases ---
let phases = [{ name: "stage-1", min_hold_seconds: 600, changed_keys: ["www.example. A"] }];
function renderPhaseEditor() {
  const box = $("phaseEditor");
  box.innerHTML = "";
  phases.forEach((p, i) => {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML = `
      <div class="two">
        <div><label>阶段名</label><input data-k="name" value="${p.name}"></div>
        <div><label>最短观察时间(秒)</label><input data-k="min_hold_seconds" type="number" value="${p.min_hold_seconds}"></div>
      </div>
      <label>可改变记录（name TYPE，逗号或换行分隔）</label>
      <textarea data-k="changed_keys" style="min-height:60px">${p.changed_keys.join("\n")}</textarea>
      <button class="secondary" data-del="${i}">删除阶段</button>`;
    div.querySelectorAll("input,textarea").forEach((el) => {
      el.onchange = () => {
        const k = el.dataset.k;
        if (k === "min_hold_seconds") p[k] = parseInt(el.value || "0", 10);
        else if (k === "changed_keys") p[k] = el.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
        else p[k] = el.value;
      };
    });
    const del = div.querySelector("[data-del]");
    del.onclick = () => { phases.splice(i, 1); renderPhaseEditor(); };
    box.appendChild(div);
  });
}
$("addPhase").onclick = () => {
  phases.push({ name: `stage-${phases.length + 1}`, min_hold_seconds: 600, changed_keys: [] });
  renderPhaseEditor();
};
renderPhaseEditor();

async function loadPlan(id) {
  state.plan = await api("GET", "/api/plans/" + id);
  phases = JSON.parse(JSON.stringify(state.plan.phases));
  renderPhaseEditor();
  renderPlanStatus();
}

function renderPlanStatus() {
  const p = state.plan;
  if (!p) return;
  const box = $("planStatus");
  box.innerHTML = `<span class="tag ${p.status}">${p.status}</span>
    revision ${p.revision} · ${p.phases.length} 个阶段 · ${p.changes.length} 个 RRset 变化`;
  const fbox = $("findings");
  fbox.innerHTML = "";
  if (!p.findings || p.findings.length === 0) {
    fbox.innerHTML = `<div class="muted">无阻断问题。</div>`;
  }
  for (const f of p.findings) {
    const d = document.createElement("div");
    d.className = "finding " + f.severity;
    d.innerHTML = `<span class="tag ${f.severity}">${f.code}</span>
      <b>${f.name || ""} ${f.type || ""}</b><div class="muted">${f.message}</div>`;
    fbox.appendChild(d);
  }
  const decisions = p.decisions || [];
  if (decisions.length) {
    const table = document.createElement("table");
    table.innerHTML = "<tr><th>阶段</th><th>生效时刻</th><th>决策</th></tr>" +
      decisions.map((d) => `<tr><td>${d.phase_name}</td><td>t=${d.effective_at_seconds}s</td>
      <td><span class="tag ${d.decision === "accepted" ? "ok" : "blocker"}">${d.decision}</span></td></tr>`).join("");
    fbox.appendChild(table);
  }
}

$("createPlanBtn").onclick = async () => {
  try {
    const p = await api("POST", "/api/plans", {
      current_zone_id: $("curSelect").value,
      candidate_zone_id: $("candSelect").value,
      phases,
    }, "plan-" + crypto.randomUUID());
    await refreshPlans(p.id);
    toast("计划已生成（draft），派生结果独立保存");
  } catch (e) { toast(e.message); }
};
async function refreshPlans(selectId) {
  const data = await api("GET", "/api/plans");
  state.plans = data.plans || [];
  const sel = $("planSelect");
  sel.innerHTML = "";
  for (const p of state.plans) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = `${p.id} · ${p.status} · rev${p.revision}`;
    sel.appendChild(o);
  }
  if (selectId) sel.value = selectId;
  if (sel.value) await loadPlan(sel.value);
}
$("planSelect").onchange = (e) => loadPlan(e.target.value);
$("validateBtn").onclick = async () => {
  try { await loadPlan(state.plan.id); state.plan = await api("POST", `/api/plans/${state.plan.id}/validate`); renderPlanStatus(); }
  catch (e) { toast(e.message); }
};
$("commitBtn").onclick = async () => {
  try { state.plan = await api("POST", `/api/plans/${state.plan.id}/commit`); renderPlanStatus(); toast("发布计划已提交"); }
  catch (e) { toast(e.message); }
};
$("copyBtn").onclick = async () => {
  try { const cp = await api("POST", `/api/plans/${state.plan.id}/copy`); await refreshPlans(cp.id); toast("已复制为新 draft，可修改阶段；旧模拟仍绑定旧指纹"); }
  catch (e) { toast(e.message); }
};
$("rollbackBtn").onclick = async () => {
  try { state.plan = await api("POST", `/api/plans/${state.plan.id}/rollback`, { at_seconds: parseInt($("slider").value, 10) }); renderPlanStatus(); toast("回滚已登记；旧 TTL 未到期前不会假装旧记录瞬间回来"); }
  catch (e) { toast(e.message); }
};

// --- simulation ---
function readProbes() {
  return $("probes").value.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
    const parts = l.split(/\s+/);
    return { qname: parts[0], qtype: (parts[1] || "A").toUpperCase() };
  });
}

$("runSimBtn").onclick = async () => {
  if (!state.plan) return toast("先生成并选择计划");
  try {
    const body = {
      plan_id: state.plan.id,
      seed: parseInt($("seed").value, 10),
      probes: readProbes(),
      max_delay_seconds: parseInt($("maxDelay").value, 10),
      query_every_seconds: parseInt($("queryEvery").value, 10),
      horizon_seconds: parseInt($("horizon").value, 10),
      rollback_at_seconds: parseInt($("rollbackAt").value || "0", 10),
    };
    const out = await api("POST", "/api/simulations", body, "sim-" + crypto.randomUUID());
    state.sim = out.simulation;
    state.probeIdx = 0;
    $("slider").max = state.sim.config.horizon_seconds;
    $("slider").step = state.sim.config.query_every_seconds;
    renderSimMeta();
    renderProbePills();
    await updateView(0);
    toast(out.reused ? "命中确定性结果，复用既有模拟（未产生第二份结果）" : "模拟完成");
  } catch (e) { toast(e.message); }
};

function renderSimMeta() {
  const s = state.sim;
  const r = s.report || {};
  $("simMeta").innerHTML = `sim ${s.id}<br>identity ${s.identity}<br>seed ${s.seed} ·
    最后权威变更 t=${r.last_auth_change_at}s ·
    全员收敛 ${r.converged_within ? "t=" + r.converged_at + "s" : "未在 horizon 内收敛"}
    ${s.rollback_report ? "· 回滚报告已附" : ""}`;
  $("convAt").textContent = r.converged_within ? `t=${r.converged_at}s（${wallClock(r.converged_at)}）` : "未收敛";
}

function renderProbePills() {
  const box = $("probePills");
  box.innerHTML = "";
  state.sim.config.probes.forEach((q, i) => {
    const b = document.createElement("button");
    b.className = "secondary";
    b.textContent = `${q.qname} ${q.qtype}`;
    b.onclick = async () => { state.probeIdx = i; renderProbePills(); await updateView(parseInt($("slider").value, 10)); };
    if (i === state.probeIdx) b.style.outline = "2px solid var(--accent)";
    box.appendChild(b);
  });
}

$("slider").oninput = async (e) => {
  state.viewAt = parseInt(e.target.value, 10);
  await updateView(state.viewAt);
};

async function updateView(t) {
  if (!state.sim) return;
  $("timeNow").textContent = `t = ${t}s`;
  $("wallNow").textContent = wallClock(t);
  const q = state.sim.config.probes[state.probeIdx];
  let view;
  try {
    view = await api("POST", `/api/simulations/${state.sim.id}/view`, { at_seconds: t, query: q });
  } catch (e) { return toast(e.message); }
  const grid = $("nodes");
  grid.innerHTML = "";
  const nodeOrder = state.sim.config.nodes || [];
  for (const nc of nodeOrder) {
    const s = view.samples[nc.id];
    const card = document.createElement("div");
    card.className = "node";
    card.innerHTML = `
      <h3><span>${nc.label || nc.id} <span class="muted">(skew ${nc.skew_seconds}s)</span></span>
        <span class="src ${s.source}">${sourceLabel(s.source)}</span></h3>
      <div>${s.status} · DNSSEC <span class="sec-${s.security}">${s.security}</span> · TTL ${s.ttl}</div>
      ${s.wildcard ? `<div class="muted">通配符来源: ${s.wildcard}</div>` : ""}
      <div class="muted">权威: ${s.server}${s.reason ? " · " + s.reason : ""}</div>
      <table>${(s.records || []).map((r) => `<tr><td>${r.type}</td><td>${r.name}</td><td>${r.data}</td></tr>`).join("")}</table>`;
    grid.appendChild(card);
  }
  renderSeries();
}

function sourceLabel(src) {
  return src === "authority" ? "权威答案" : src === "cache" ? "缓存命中" : "负缓存";
}

function renderSeries() {
  const s = state.sim;
  if (!s || !s.report) return;
  const probe = s.report.probes[state.probeIdx];
  const box = $("series");
  box.innerHTML = "";
  for (const series of probe.series) {
    const wrap = document.createElement("div");
    wrap.innerHTML = `<b>${series.node_id}</b> · 本查询${probe.converged_within ? " 于 t=" + probe.converged_at + "s 收敛" : " 未收敛"}`;
    const table = document.createElement("table");
    let rows = `<tr><th>区间</th><th>来源</th><th>结果</th></tr>`;
    for (const iv of series.intervals) {
      const sm = iv.sample;
      rows += `<tr><td>t=${iv.from}→${iv.to}s</td><td><span class="src ${iv.source}">${sourceLabel(iv.source)}</span></td>
        <td>${sm.status}/${sm.security} ${(sm.records || []).slice(-1)[0] ? (sm.records.slice(-1)[0].data) : ""}</td></tr>`;
    }
    table.innerHTML = rows;
    wrap.appendChild(table);
    box.appendChild(wrap);
  }
}

$("adhocBtn").onclick = async () => {
  if (!state.sim) return toast("先运行模拟");
  const q = state.sim.config.probes[state.probeIdx];
  try {
    const v = await api("POST", `/api/simulations/${state.sim.id}/adhoc`, {
      at_seconds: parseInt($("slider").value, 10), qname: q.qname, qtype: q.qtype,
    }, "adhoc-" + crypto.randomUUID());
    toast(`立即查询已记录（不改变确定性报告）：${Object.keys(v.samples).length} 个节点`);
  } catch (e) { toast(e.message); }
};

$("exportBtn").onclick = async () => {
  if (!state.sim) return toast("先运行模拟");
  try {
    const b = await api("GET", `/api/simulations/${state.sim.id}/export`);
    const blob = new Blob([JSON.stringify(b, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `export-${state.sim.id}.json`;
    a.click();
    toast("导出包含完整查询证据、阶段决策与操作事件");
  } catch (e) { toast(e.message); }
};

async function refreshEvents() {
  const data = await api("GET", "/api/events");
  $("events").innerHTML = "<table><tr><th>#</th><th>时间</th><th>事件</th><th>对象</th></tr>" +
    (data.events || []).slice().reverse().map((e) =>
      `<tr><td>${e.seq}</td><td class="muted">${e.at.replace("T", " ").slice(0, 19)}</td><td>${e.type}</td><td class="fp">${e.ref_id || ""} ${e.request_id ? "req=" + e.request_id : ""}</td></tr>`
    ).join("") + "</table>";
}
$("refreshEvents").onclick = () => refreshEvents().catch((e) => toast(e.message));

$("demoBtn").onclick = async () => {
  try {
    const b = await api("POST", "/api/demo/load", {}, "demo-" + new Date().toISOString().slice(0, 10));
    if (b.replayed) return toast("今日演示数据已存在（request_id 幂等）");
    $("curZone").value = ""; $("candZone").value = "";
    await refreshZones();
    $("curSelect").value = b.current.id;
    $("candSelect").value = b.candidate.id;
    state.curId = b.current.id; state.candId = b.candidate.id;
    await refreshPlans(b.plan.id);
    toast("演示数据已载入：一个可提交计划 + 一个被阻断计划");
  } catch (e) { toast(e.message); }
};

$("clockLabel").textContent = "模拟纪元 " + wallClock(0);
refreshZones().catch(() => {});
refreshPlans().catch(() => {});
refreshEvents().catch(() => {});
setInterval(refreshEvents, 8000);
