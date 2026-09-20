"use strict";
const $ = (id) => document.getElementById(id);
const state = { zones: [], plans: [], plan: null, sim: null, query: 0 };

function rid() { return "req-" + crypto.randomUUID(); }
async function api(path, opts) {
  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
  if (!res.ok) throw data?.error || { code: "http_" + res.status, message: res.statusText };
  return data;
}
function post(path, body) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request_id: rid(), ...body }) });
}
function esc(s) { return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function pill(v, cls) { return `<span class="pill ${cls || ""}">${esc(v)}</span>`; }

const DEMO_CURRENT = `$TTL 300
@   IN SOA ns1.example.test. hostmaster.example.test. 2026090101 7200 3600 1209600 60
    IN NS  ns1
    IN NS  ns2
ns1 IN A   10.0.0.11
ns2 IN A   10.0.0.12
www IN A   192.0.2.10
api IN CNAME www
old IN A   192.0.2.90
*.svc IN A 192.0.2.77
`;
const DEMO_CANDIDATE = `$TTL 120
@   IN SOA ns1.example.test. hostmaster.example.test. 2026092001 7200 3600 1209600 60
    IN NS  ns1
    IN NS  ns2
ns1 IN A   10.0.0.11
ns2 IN A   10.0.0.12
www IN A   198.51.100.20
api IN CNAME www
new IN A   198.51.100.91
*.svc IN A 198.51.100.77
`;

$("loadDemo").onclick = () => {
  $("zoneName").value = "example.test";
  $("zoneText").value = $("zoneKind").value === "candidate" ? DEMO_CANDIDATE : DEMO_CURRENT;
};
$("zoneKind").onchange = $("loadDemo").onclick;

async function refreshZones() {
  const d = await api("/api/zones");
  state.zones = d.zones || [];
  const fill = (sel, kind, val) => {
    sel.innerHTML = state.zones.filter((z) => z.kind === kind)
      .map((z) => `<option value="${z.id}">${esc(z.name)} · ${z.record_count} rr · ${z.fingerprint.slice(0, 10)}</option>`).join("");
    if (val) sel.value = val;
  };
  fill($("currentZone"), "current");
  fill($("candidateZone"), "candidate");
  refreshPlans();
}

$("importBtn").onclick = async () => {
  $("importMsg").innerHTML = "";
  try {
    const d = await post("/api/zones", { kind: $("zoneKind").value, name: $("zoneName").value.trim(), text: $("zoneText").value });
    $("importMsg").innerHTML = `<div class="ok-msg">已导入 ${esc(d.record_count)} 条记录，序列号 ${esc(d.serial)}</div><div class="finger">${esc(d.fingerprint)}</div>`;
    await refreshZones();
  } catch (e) { $("importMsg").innerHTML = `<div class="err">${errText(e)}</div>`; }
};

function errText(e) {
  let t = (e.code || "error") + ": " + (e.message || "");
  if (Array.isArray(e.details)) t += "\n" + e.details.map((b) => "  • [" + b.code + "] " + b.message + (b.where ? "  @ " + b.where : "")).join("\n");
  else if (e.details && typeof e.details === "string") t += "\n" + e.details;
  else if (e.details && typeof e.details === "object") t += "\n" + JSON.stringify(e.details, null, 2);
  return esc(t);
}

async function refreshPlans() {
  const d = await api("/api/plans");
  state.plans = d.plans || [];
  $("planSelect").innerHTML = state.plans
    .map((p) => `<option value="${p.id}">${esc(p.zone_name)} · ${esc(p.status)} · ${p.fingerprint.slice(0, 10)}${p.source_plan_id ? " (copy)" : ""}</option>`)
    .join("");
  if (state.plan && state.plans.some((p) => p.id === state.plan.id)) {
    state.plan = state.plans.find((p) => p.id === state.plan.id);
  } else if (state.plans.length) {
    state.plan = state.plans[state.plans.length - 1];
    $("planSelect").value = state.plan.id;
  } else state.plan = null;
  renderPlan();
}
$("planSelect").onchange = () => {
  state.plan = state.plans.find((p) => p.id === $("planSelect").value) || null;
  state.sim = null;
  renderPlan();
};

$("diffPlan").onclick = async () => {
  const current_zone_id = $("currentZone").value;
  const candidate_zone_id = $("candidateZone").value;
  if (!current_zone_id || !candidate_zone_id) { alert("需要先导入并选择 current 与 candidate zone"); return; }
  try {
    const d = await post("/api/plans", { current_zone_id, candidate_zone_id });
    $("planMeta").textContent = `计划 ${d.plan_id.slice(0, 14)} · ${d.phases} 阶段 · ${d.status}`;
    await refreshZones();
  } catch (e) {
    $("planMeta").innerHTML = `<div class="err">${errText(e)}</div>`;
    if (e.code === "publish_blocked") { await refreshZones(); }
  }
};

$("copyPlan").onclick = async () => {
  if (!state.plan) return;
  try {
    const d = await post(`/api/plans/${state.plan.id}/copy`, {});
    alert(`已复制为新计划 ${d.plan_id.slice(0,14)}\n旧计划指纹 ${d.source_plan_fingerprint.slice(0,12)} 仍绑定旧模拟。`);
    await refreshPlans();
    $("planSelect").value = d.plan_id;
    state.plan = state.plans.find((p) => p.id === d.plan_id);
    renderPlan();
  } catch (e) {
    if (e.code === "publish_blocked") { await refreshPlans(); }
    alert(errText(e));
  }
};

function renderPlan() {
  const p = state.plan;
  $("blockList").innerHTML = "";
  $("phaseList").innerHTML = "";
  $("fps").textContent = "";
  if (!p) { $("planMeta").textContent = "尚无计划"; return; }
  if (p.blocks && p.blocks.length) {
    $("blockList").innerHTML = `<div class="blocked">禁止发布：</div>` +
      p.blocks.map((b) => `<div class="err">[${b.code}] ${esc(b.message)} ${esc(b.where || "")}</div>`).join("");
  }
  let html = `<table><tr><th>#</th><th>阶段</th><th>最短观察</th><th>变更</th><th></th></tr>`;
  p.plan.phases.forEach((ph, i) => {
    const isCur = p.status === "ready" && i === p.current_phase;
    html += `<tr><td>${i}</td><td>${esc(ph.name)}${isCur ? " " + pill("当前", "ready") : ""}</td>
      <td>${ph.min_observe_sec}s</td><td>${ph.operations.map((o) =>
        `<div>${o.action === "delete" ? "🗑" : "✎"} ${esc(o.type)} ${esc(o.name)}${o.raw ? " → " + esc(o.raw) : ""}</div>`).join("")}</td>
      <td>${isCur ? `<button class="secondary narrow" data-proceed="${i}">按最早时间推进</button>` : ""}</td></tr>`;
  });
  html += `</table>`;
  if (["completed", "rolled_back"].includes(p.status) || p.current_phase > 0) {
    const rb = p.status !== "rolled_back" ? `<button class="secondary" id="rbBtn">立即回滚（遵守已发 TTL）</button>` : pill("已回滚", "rolled_back");
    html += `<div class="row">${rb}</div>`;
  }
  $("phaseList").innerHTML = html;
  $("fps").textContent = `plan   ${p.fingerprint}\nbase   ${p.base_zone_fp}\nstatus ${p.status}` +
    (p.source_plan_id ? `\ncopy of ${p.source_plan_id}（旧模拟绑定旧指纹）` : "");
  document.querySelectorAll("[data-proceed]").forEach((b) => {
    b.onclick = () => proceed(Number(b.dataset.proceed));
  });
  if ($("rbBtn")) $("rbBtn").onclick = rollback;
}

async function proceed(i) {
  const p = state.plan;
  // Compute earliest time exactly as backend does, then submit that value.
  let t = 0;
  for (let k = 0; k < i; k++) {
    const dec = (p.decisions || []).find((d) => d.action === "proceed" && d.phase_index === k);
    t = Math.max(t + p.plan.phases[k].min_observe_sec, dec ? dec.at_sec : 0);
  }
  const at = t + p.plan.phases[i].min_observe_sec;
  try {
    await post(`/api/plans/${p.id}/phases/${i}/decision`, { action: "proceed", at_sec: at, note: "ui: earliest" });
    await refreshPlans();
  } catch (e) { alert(errText(e)); }
}
async function rollback() {
  const p = state.plan;
  const at = (p.decisions || []).reduce((m, d) => Math.max(m, d.at_sec), 0) + 60;
  try {
    await post(`/api/plans/${p.id}/phases/${p.current_phase}/decision`, { action: "rollback", at_sec: at, note: "ui rollback" });
    await refreshPlans();
  } catch (e) { alert(errText(e)); }
}

$("simBtn").onclick = async () => {
  if (!state.plan) { alert("先选择计划"); return; }
  const params = {
    authoritative_nodes: +$("pAuth").value, recursive_nodes: +$("pRecv").value,
    max_auth_delay_sec: +$("pAD").value, max_recv_delay_sec: +$("pRD").value,
    max_clock_skew_sec: +$("pSkew").value, probe_interval_sec: +$("pGrid").value,
    seed: +$("pSeed").value,
  };
  $("simMeta").textContent = "模拟中…";
  try {
    const d = await post(`/api/plans/${state.plan.id}/simulations`, { parameters: params });
    $("simMeta").innerHTML = `sim ${esc(d.simulation_id.slice(0, 14))} · ${d.reused ? "复用确定性结果" : "新计算"} · 收敛 ${d.earliest_all_converged_sec}s`;
    const full = await api(`/api/simulations/${d.simulation_id}`);
    state.sim = full.result;
    state.simId = full.id;
    setupTimeline();
  } catch (e) { $("simMeta").innerHTML = `<div class="err">${errText(e)}</div>`; }
};

function setupTimeline() {
  const r = state.sim;
  $("timeline").max = r.horizon_sec;
  $("timeline").step = r.parameters.probe_interval_sec;
  $("timeline").value = 0;
  $("convAll").textContent = r.earliest_converged_sec;
  $("stableFrom").textContent = r.stable_from_sec;
  $("querySelect").innerHTML = r.queries.map((q, i) =>
    `<option value="${i}">${esc(q.type)} ${esc(q.name)}</option>`).join("");
  $("querySelect").value = "0";
  state.query = 0;
  renderAt(0);
}
$("querySelect").onchange = () => { state.query = +$("querySelect").value; renderAt(+$("timeline").value); };
$("timeline").oninput = (e) => renderAt(+e.target.value);

function sigClass(s) { return "sig-" + s; }
function renderAt(t) {
  $("tNow").textContent = t;
  if (!state.sim) { $("nodeViews").innerHTML = ""; return; }
  const grid = state.sim.parameters.probe_interval_sec;
  const pIdx = Math.round(t / grid);
  const trace = state.sim.traces[state.query];
  const nNodes = state.sim.recv_nodes.length;
  let html = `<table><tr><th>递归节点</th><th>时钟偏差</th><th>来源</th><th>状态 / 签名</th><th>记录</th><th>权威</th></tr>`;
  for (let n = 0; n < nNodes; n++) {
    const v = trace.views[Math.min(pIdx * nNodes + n, trace.views.length - 1)];
    const node = state.sim.recv_nodes[n];
    const srcCls = v.source === "authoritative" ? "auth" : v.source === "cache" ? "cache" : "neg";
    const recs = (v.answer.records || []).map((r) => `<div>${esc(r.type)} ${esc(r.raw)} <span class="small">ttl ${r.ttl}</span></div>`).join("") ||
      (v.answer.neg_ttl ? `<span class="small">SOA min TTL ${v.answer.neg_ttl}s</span>` : "–");
    const chain = (v.answer.chain || []).map((c) => `<div class="small">↳ CNAME ${esc(c.name)} → ${esc(c.target)}${c.wildcard ? " (wildcard)" : ""}</div>`).join("");
    const wc = v.answer.wildcard ? `<div class="small">wildcard ${esc(v.answer.wildcard)}</div>` : "";
    html += `<tr><td>${esc(node.id)}</td><td class="small">${node.clock_skew_sec >= 0 ? "+" : ""}${node.clock_skew_sec}s</td>
      <td class="${srcCls}">${esc(v.source.replace("_", " "))}</td>
      <td>${esc(v.answer.status)}<div class="${sigClass(v.answer.sig_status)}">${esc(v.answer.sig_status)}${v.answer.sig_keytag ? " #" + v.answer.sig_keytag : ""}</div>${wc}</td>
      <td>${recs}${chain}</td><td class="small">${esc(v.answer.authority || "—")}</td></tr>`;
  }
  html += `</table>`;
  const conv = state.sim.convergence[state.query];
  if (conv) {
    html += `<div class="small">该查询全体收敛于 <b>${conv.all_converged_sec}</b>s · ` +
      Object.entries(conv.node_converged_sec).map(([k, v]) => `${esc(k)}: ${v < 0 ? "未收敛" : v + "s"}`).join(" · ") + `</div>`;
  }
  $("nodeViews").innerHTML = html;
}

$("exportBtn").onclick = async () => {
  if (!state.simId) { alert("先运行模拟"); return; }
  try {
    const d = await post(`/api/simulations/${state.simId}/export`, {});
    const bundle = await api(`/api/exports/${d.export_id}`);
    $("exportOut").hidden = false;
    $("exportOut").textContent = JSON.stringify({
      exported_at: bundle.exported_at,
      plan_id: bundle.plan.id, plan_fingerprint: bundle.plan.fingerprint,
      simulation_id: bundle.simulation.id,
      plan_fingerprint_check: bundle.simulation.plan_fp,
      params_fingerprint: bundle.simulation.params_fp,
      decision_fingerprint: bundle.simulation.decision_fp,
      earliest_all_converged_sec: bundle.simulation.result.earliest_converged_sec,
      queries: bundle.query_evidence.map((q) => ({
        query: q.query, all_converged_sec: q.all_converged_sec,
        node_converged_sec: q.node_converged_sec,
        views: q.views.map((v) => ({ at: v.at_sec, source: v.source, status: v.answer.status,
          sig: v.answer.sig_status, authority: v.answer.authority, records: (v.answer.records || []).map((r) => r.type + " " + r.raw) })),
      })),
      phase_decisions: bundle.phase_decisions,
      operation_events: bundle.operation_events,
    }, null, 2);
  } catch (e) { alert(errText(e)); }
};

refreshZones();
