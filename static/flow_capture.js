// 데이터 흐름 캡처 (/alerts/<id>/flow): one panel per stage, filled from
// /api/alerts/<id>/flow (hawki_alert_analysis/flow_capture.py). Bar widths
// are set through el.style, never inline style attributes, which the page's
// Content-Security-Policy blocks.
(() => {
    const root = document.getElementById("flow-capture-root");
    if (!root) return;
    const alertId = root.dataset.alertId;
    const base = `/api/alerts/${encodeURIComponent(alertId)}/flow`;

    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
    const number = (value) => new Intl.NumberFormat("ko-KR").format(Number(value) || 0);
    const json = (value) => JSON.stringify(value ?? null, null, 2);
    const pre = (value) => `<pre class="flow-pre">${escapeHtml(typeof value === "string" ? value : json(value))}</pre>`;
    const chips = (values) => (values || []).length
        ? `<div class="flow-chips">${values.map((value) => `<code>${escapeHtml(value)}</code>`).join("")}</div>`
        : `<p class="muted">없음</p>`;
    const when = (value) => {
        const parsed = Date.parse(String(value || "").replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
        return Number.isFinite(parsed) ? new Date(parsed).toLocaleString("ko-KR", { hour12: false }) : escapeHtml(value || "");
    };
    const kv = (pairs) => `<dl class="flow-kv">${pairs.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${value}</dd>`).join("")}</dl>`;

    async function requestJson(url) {
        const response = await fetch(url, { headers: { Accept: "application/json" } });
        let body = {};
        try { body = await response.json(); } catch { body = {}; }
        if (!response.ok) throw new Error(body.detail ? `${body.error} (${body.detail})` : (body.error || `요청 실패: ${response.status}`));
        return body;
    }

    function stage(key) {
        const section = root.querySelector(`[data-flow-stage="${key}"]`);
        return {
            where: section?.querySelector("[data-stage-where]"),
            size: section?.querySelector("[data-stage-size]"),
            body: section?.querySelector("[data-stage-body]"),
        };
    }

    function renderSizes(doc) {
        const target = root.querySelector("[data-flow-sizes]");
        const order = (doc.stage_order || []).filter((item) => (doc.sizes || {})[item.key] !== undefined && (doc.sizes || {})[item.key] !== null);
        const max = Math.max(1, ...order.map((item) => Number(doc.sizes[item.key]) || 0));
        const unit = { raw: "줄", event: "건", alert: "건", evidence: "건", ai_judgment: "건 인용" };
        target.innerHTML = `<p class="panel-kicker">단계별 데이터 크기 (문자 수) · ${escapeHtml(doc.basis || "")} · 같은 경보의 데이터가 늘고 줄어드는 모습</p>
            <div class="flow-size-rows">${order.map((item) => {
                const count = (doc.counts || {})[item.key];
                return `<div class="flow-size-row"><span>${escapeHtml(item.label)}</span>
                <span class="flow-size-bar"><i data-width="${(Number(doc.sizes[item.key]) || 0) / max}"></i></span>
                <b>${number(doc.sizes[item.key])}자</b><small class="muted">${count === null || count === undefined ? "" : `${number(count)}${unit[item.key] || ""}`}</small></div>`;
            }).join("")}</div>`;
        target.querySelectorAll("[data-width]").forEach((bar) => { bar.style.width = `${Math.max(0.6, Number(bar.dataset.width) * 100)}%`; });
    }

    function renderRaw(data) {
        return (data.servers || []).map((server) => `
            <article class="flow-server">
                <h3>${escapeHtml(server.server)} <small class="muted">${escapeHtml(server.ip || "")} · ${number(server.count)}줄</small></h3>
                ${(server.sources || []).map((source) => `
                    <div class="flow-source">
                        <p><strong>${escapeHtml(source.label)}</strong> <code>${escapeHtml(source.location)}</code>
                           <span class="flow-tag">${escapeHtml(source.format)}</span> <span class="muted">${number(source.count)}줄</span></p>
                        ${(source.samples || []).map((sample) => `
                            <p class="flow-sample-head"><code>${escapeHtml(sample.evidence_id)}</code> <span class="muted">${when(sample.timestamp)}</span></p>
                            ${pre(sample.full_log || "")}`).join("")}
                    </div>`).join("")}
            </article>`).join("") || `<p class="muted">원본 로그가 없습니다.</p>`;
    }

    function renderEvent(data) {
        return (data.decoders || []).map((group) => `
            <article class="flow-server">
                <h3>${escapeHtml(group.server)} · 디코더 <code>${escapeHtml(group.decoder)}</code> <small class="muted">${escapeHtml(group.label)} · ${number(group.count)}건</small></h3>
                <p class="muted">원본 한 줄이 쪼개진 필드</p>
                ${chips(group.data_fields)}
                ${pre(group.example)}
            </article>`).join("") || `<p class="muted">이벤트가 없습니다.</p>`;
    }

    function renderAlert(data) {
        const trigger = data.trigger || {};
        const related = data.related_rules || [];
        return `${kv([
            ["경보 문서", `<code>${escapeHtml(trigger.id)}</code> · <code>${escapeHtml(trigger.index)}</code>`],
            ["시각", escapeHtml(trigger.timestamp_kst || trigger.timestamp)],
            ["서버", escapeHtml((trigger.agent || {}).name || "")],
            ["룰에 걸리지 않은 원시 이벤트", `${number(data.context_without_rule)}건 (같은 증거 안)`],
        ])}
            <p class="muted">이벤트에 룰이 붙인 필드</p>${chips(data.rule_fields)}
            ${pre(trigger.rule)}
            ${related.length ? `<div class="data-table"><table class="report-table">
                <thead><tr><th>같은 증거 안의 다른 경보 룰</th><th>레벨</th><th>설명</th><th>건수</th><th>증거</th></tr></thead>
                <tbody>${related.map((item) => `<tr><td><code>${escapeHtml(item.rule_id)}</code></td><td>${escapeHtml(item.level)}</td>
                    <td>${escapeHtml(item.description)}</td><td>${number(item.count)}</td><td>${escapeHtml((item.evidence_ids || []).join(", "))}</td></tr>`).join("")}</tbody>
            </table></div>` : ""}`;
    }

    function renderEvidence(data) {
        const outcomes = data.control_outcomes || [];
        return `${kv([
            ["스키마", `<code>${escapeHtml(data.schema)}</code>`],
            ["블록", (data.blocks || []).map((block) => `<code>${escapeHtml(block)}</code>`).join(" ")],
            ["증거 수", `TRIGGER ${number(data.trigger)} + CTX ${number(data.context_count)} · ${escapeHtml(Object.entries(data.context_by_origin || {}).map(([key, value]) => `${key} ${value}`).join(" · "))}`],
            ["차단 판정", escapeHtml(Object.entries(data.control_summary || {}).map(([key, value]) => `${key} ${value}`).join(" · ") || "—")],
            ["우선순위", escapeHtml(Object.entries(data.priority || {}).map(([key, value]) => `${key} ${value}`).join(" · ") || "—")],
            ["자산", escapeHtml((data.assets || []).map((item) => `${item.hostname || item.id} (${item.criticality || "?"} · ${item.exposure || "?"})`).join(", ") || "매칭 없음")],
            ["위협 인텔리전스", escapeHtml((data.threat_intelligence || []).map((item) => `${item.value} (${item.source || ""})`).join(", ") || "매칭 없음")],
            ["수집 조건", `<code>${escapeHtml(JSON.stringify(data.retrieval || {}))}</code>`],
            ["출처 연결 (lineage)", `${number(data.lineage_edges)}개`],
        ])}
            ${outcomes.length ? `<div class="data-table"><table class="report-table">
                <thead><tr><th>증거</th><th>탐지</th><th>통제</th><th>차단 상태</th><th>HTTP</th></tr></thead>
                <tbody>${outcomes.map((item) => `<tr><td><code>${escapeHtml(item.evidence_id)}</code></td><td>${escapeHtml(item.detection)}</td>
                    <td>${escapeHtml(item.control || "—")}</td><td><span class="flow-tag flow-tag-${escapeHtml(String(item.control_status || "").toLowerCase())}">${escapeHtml(item.control_status)}</span></td>
                    <td>${escapeHtml(item.http_status ?? "—")}</td></tr>`).join("")}</tbody>
            </table></div>` : ""}`;
    }

    function renderRetrieval(data) {
        if (!data.ran && !data.before) return `<p class="muted">이 캡처에는 AI 증거 수집 기록이 없습니다. 경보 화면에서 "LLM으로 분석"을 실행하면 그 순간이 저장됩니다.</p>`;
        const size = (item) => item ? `CTX ${number(item.context_count)} · ${number(item.size_chars)}자` : "—";
        return `${kv([
            ["처음 만든 패키지", size(data.before)],
            ["AI 수집 후", size(data.after_agent)],
            ["모델에 보낸 패키지", `${size(data.sent_to_model)} (문맥 한도에 맞춘 뒤)`],
            ["추가된 증거", escapeHtml((data.added_evidence_ids || []).join(", ") || "없음")],
            ["멈춘 이유", `<code>${escapeHtml(data.stopped || "—")}</code>`],
        ])}
            ${(data.calls || []).length ? `<div class="data-table"><table class="report-table">
                <thead><tr><th>#</th><th>도구</th><th>인자</th><th>결과</th></tr></thead>
                <tbody>${data.calls.map((call, index) => `<tr><td>${index + 1}</td><td><code>${escapeHtml(call.tool)}</code></td>
                    <td><code>${escapeHtml(JSON.stringify(call.arguments || {}))}</code></td>
                    <td>${call.accepted === false ? `거부 · ${escapeHtml(call.refused_reason || "")}` : `추가 ${escapeHtml((call.added_evidence_ids || []).join(", ") || "없음")}`}</td></tr>`).join("")}</tbody>
            </table></div>` : ""}`;
    }

    function renderJudgment(data) {
        if (!data.ran) return `<p class="muted">이 캡처에는 AI 판단이 없습니다. 경보 화면에서 "LLM으로 분석"을 실행하면 그 순간이 저장됩니다.</p>`;
        const assessment = data.assessment || {};
        const list = (values) => (values || []).length ? `<ul>${values.map((value) => `<li>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</li>`).join("")}</ul>` : "—";
        return `${kv([
            ["모델", `<code>${escapeHtml(data.model)}</code>${data.demo ? " · 데모 응답" : ""}`],
            ["분석 id", `<code>${escapeHtml(data.analysis_id || "—")}</code>`],
            // The app appends its rendered judgement to `answer` after a rule;
            // the model's own briefing is what comes before it.
            ["요약", escapeHtml(String(data.answer || "").split(/\n\s*---/)[0].trim().slice(0, 600))],
            ["확인된 사실", list(assessment.confirmed_observations)],
            ["해석", escapeHtml(assessment.interpretation || "—")],
            ["공격 가설", escapeHtml(assessment.attack_hypothesis || "—")],
            ["확신도 · 심각도", escapeHtml(`${(assessment.confidence || {}).level || "—"} · ${(assessment.severity || {}).level || "—"}`)],
            ["빠진 증거", list(assessment.evidence_gaps)],
            ["추천 조치", list(assessment.recommended_response)],
            ["검증", escapeHtml(JSON.stringify(data.review || {}))],
        ])}
            <p class="muted">AI 가 인용한 증거와 그 원본 로그 (① 단계로 거슬러 올라감)</p>
            ${(data.citations || []).map((item) => `
                <p class="flow-sample-head"><code>${escapeHtml(item.evidence_id)}</code> ${item.exists ? `<span class="muted">${escapeHtml(item.server || "")}</span>` : `<span class="flow-tag flow-tag-warn">증거에 없는 id</span>`}</p>
                ${item.full_log ? pre(item.full_log) : ""}`).join("") || `<p class="muted">인용 없음</p>`}`;
    }

    function renderResponse(data) {
        const proposed = data.proposed || [];
        const queued = data.queued || [];
        if (!proposed.length && !queued.length) return `<p class="muted">제안되거나 승인 요청된 조치가 없습니다.</p>`;
        return `${proposed.length ? `<p class="muted">AI 가 제안한 조치 (승인 전)</p><ul>${proposed.map((item) => `<li><code>${escapeHtml(item.type)}</code> ${escapeHtml(item.title || "")} → ${escapeHtml(item.target || "")} <span class="muted">${escapeHtml(item.reason || "")}</span></li>`).join("")}</ul>` : ""}
            ${queued.length ? `<div class="data-table"><table class="report-table">
                <thead><tr><th>승인 대기열</th><th>유형</th><th>상태</th><th>요청 시각</th></tr></thead>
                <tbody>${queued.map((item) => `<tr><td><a href="/actions">${escapeHtml(item.id)}</a></td><td><code>${escapeHtml(item.type)}</code></td>
                    <td>${escapeHtml(item.status)}</td><td>${when(item.created_at)}</td></tr>`).join("")}</tbody>
            </table></div>` : ""}
            <p class="muted">승인된 수집(Velociraptor)과 새 룰(Suricata)이 만든 로그·경보는 다시 ① 단계로 들어옵니다.</p>`;
    }

    const RENDERERS = {
        raw: renderRaw, event: renderEvent, alert: renderAlert, evidence: renderEvidence,
        ai_retrieval: renderRetrieval, ai_judgment: renderJudgment, response: renderResponse,
    };

    function render(doc) {
        const meta = root.querySelector("[data-flow-meta]");
        meta.textContent = doc.mode === "captured"
            ? `분석 실행 시점에 저장된 캡처 · ${when(doc.captured_at)}`
            : `지금 Wazuh 문서로 다시 만든 흐름 · ${when(doc.captured_at)} (AI 단계는 분석을 실행하면 저장됩니다)`;
        const select = root.querySelector("[data-flow-capture]");
        const options = [`<option value="live">지금 다시 만들기 (AI 단계 제외)</option>`]
            .concat((doc.captures || []).map((item) => `<option value="${escapeHtml(item.capture_id)}">${when(item.captured_at)} · ${escapeHtml(item.model || "")}</option>`));
        select.innerHTML = options.join("");
        select.value = doc.mode === "captured" ? doc.capture_id : "live";
        const view = doc.mode === "captured" ? doc.capture_id : "live";
        root.querySelector("[data-flow-markdown]").href = `${base}.md?view=${encodeURIComponent(view)}`;
        renderSizes(doc);
        (doc.stage_order || []).forEach((item) => {
            const target = stage(item.key);
            if (!target.body) return;
            if (target.where) target.where.textContent = item.where;
            const size = (doc.sizes || {})[item.key];
            const count = (doc.counts || {})[item.key];
            const parts = [];
            if (count !== undefined && count !== null) parts.push(`${number(count)}건`);
            if (size !== undefined && size !== null) parts.push(`${number(size)}자`);
            if (target.size) target.size.textContent = parts.join(" · ");
            try {
                target.body.innerHTML = RENDERERS[item.key]((doc.stages || {})[item.key] || {});
            } catch (error) {
                target.body.innerHTML = `<p class="muted">이 단계를 그리지 못했습니다 · ${escapeHtml(error.message)}</p>`;
            }
        });
    }

    async function load(view = "") {
        try {
            render(await requestJson(view ? `${base}?view=${encodeURIComponent(view)}` : base));
        } catch (error) {
            root.querySelector("[data-flow-meta]").textContent = `흐름을 불러오지 못했습니다 · ${error.message}`;
            root.querySelectorAll("[data-stage-body]").forEach((body) => { body.innerHTML = ""; });
        }
    }

    root.querySelector("[data-flow-capture]").addEventListener("change", (event) => load(event.target.value));
    load();
})();
