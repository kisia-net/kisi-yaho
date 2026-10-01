// 판단 근거 (XAI) panel, shared by the alert page and the 자동 보고서 page.
// It renders hawki.explanation/v1, which the server computes in code from
// the model's cited ids and the evidence package (hawki_alert_analysis/explain.py).
(() => {
    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const STATUS = {
        grounded: ["근거 확인", "xai-ok"],
        partial: ["일부만 확인", "xai-warn"],
        ungrounded: ["근거 없음", "xai-bad"],
        uncited: ["인용 없음", "xai-muted"],
    };
    const KIND = { supporting: "뒷받침", contradictory: "반대" };
    const ORIGIN = {
        trigger: "트리거 경보",
        same_agent: "같은 에이전트",
        cross_agent: "다른 에이전트",
        agent_search: "에이전트 검색",
        correlated_alert: "연관 경보",
        correlated_event: "연관 이벤트",
    };
    const AGREEMENT = {
        consistent: ["모델 심각도와 우선순위가 일치", "xai-ok"],
        model_lower: ["모델이 우선순위보다 낮게 판단", "xai-warn"],
        model_higher: ["모델이 우선순위보다 높게 판단", "xai-warn"],
        unknown: ["비교할 값 없음", "xai-muted"],
    };
    const SEVERITY = { info: "정보", low: "낮음", medium: "보통", high: "높음", critical: "치명" };
    const CONFIDENCE = { low: "낮음", medium: "보통", high: "높음" };
    const VERDICT = { confirmed: "확인됨", false_positive: "오탐", investigating: "추가 조사" };
    const MATCH = { same_rule: "같은 룰", same_host: "같은 호스트", same_source_ip: "같은 출발지" };
    const FACTOR = {
        wazuh_rule_level: "Wazuh 룰 레벨",
        source_severity: "원본 심각도",
        asset_criticality: "자산 중요도",
        asset_exposure: "자산 노출도",
        asset_data_classification: "민감 데이터",
        asset_not_in_inventory: "자산 목록에 없음",
        threat_intel_match: "위협 인텔리전스 일치",
    };
    const AGENT_STOP = {
        finish: "에이전트가 증거 충분 판단",
        no_tool_call: "추가 수집 불필요",
        max_calls: "호출 상한 도달",
        error: "수집 실패",
        context_limit_reverted: "증거 한도 초과로 원래 증거 사용",
    };

    const time = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? String(value || "—")
            : date.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    };
    const chip = (label, cls) => `<span class="xai-chip ${cls}">${escapeHtml(label)}</span>`;

    function evidenceDetail(record) {
        if (!record) return "";
        const rule = [record.rule_id, record.rule_description].filter(Boolean).join(" ");
        const reasons = (record.retrieval_reasons || []).map((reason) => `<span class="tag">${escapeHtml(reason)}</span>`).join(" ");
        const added = record.source_kind === "agent_expansion" ? chip("에이전트가 추가", "xai-info") : "";
        return `<div class="xai-evidence-body">
            <p><strong>${escapeHtml(time(record.timestamp))}</strong> · ${escapeHtml(record.host || "호스트 없음")} · ${escapeHtml(ORIGIN[record.origin] || record.origin || "")} ${added}</p>
            ${rule ? `<p>룰 ${escapeHtml(rule)}${record.rule_level !== undefined && record.rule_level !== null ? ` · 레벨 ${escapeHtml(record.rule_level)}` : ""}${record.source_ip ? ` · 출발지 ${escapeHtml(record.source_ip)}` : ""}</p>` : ""}
            ${record.log ? `<pre class="xai-log">${escapeHtml(record.log)}</pre>` : ""}
            ${reasons ? `<p class="xai-reasons">수집 이유 ${reasons}</p>` : ""}
        </div>`;
    }

    function claimHtml(claim, evidence) {
        const [label, cls] = STATUS[claim.status] || STATUS.uncited;
        const refs = (claim.event_ids || []).map((id) => {
            const record = Object.prototype.hasOwnProperty.call(evidence, id) ? evidence[id] : null;
            if (!record) {
                return `<span class="xai-ref xai-ref-missing" title="증거 묶음에 없는 ID">${escapeHtml(id)} · 없음</span>`;
            }
            return `<details class="xai-ref-detail"><summary class="xai-ref">${escapeHtml(id)}</summary>${evidenceDetail(record)}</details>`;
        }).join("");
        return `<li class="xai-claim xai-claim-${escapeHtml(claim.kind)}">
            <div class="xai-claim-head">${chip(KIND[claim.kind] || claim.kind, claim.kind === "contradictory" ? "xai-info" : "xai-plain")} ${chip(label, cls)}</div>
            <p class="xai-statement">${escapeHtml(claim.statement)}</p>
            <div class="xai-refs">${refs || `<span class="muted">인용한 증거가 없습니다.</span>`}</div>
        </li>`;
    }

    function render(container, explanation) {
        if (!container) return;
        if (!explanation || explanation.schema !== "hawki.explanation/v1") {
            container.hidden = true;
            container.innerHTML = "";
            return;
        }
        const summary = explanation.summary || {};
        const conclusion = explanation.conclusion || {};
        const evidence = explanation.evidence || {};
        const inputs = explanation.inputs || {};
        const [agreementLabel, agreementClass] = AGREEMENT[conclusion.agreement] || AGREEMENT.unknown;
        const severity = conclusion.severity || {};
        const confidence = conclusion.confidence || {};
        const priority = conclusion.priority || {};
        const expected = (conclusion.expected_severity || []).map((level) => SEVERITY[level] || level).join("~");

        const claims = explanation.claims || [];
        const factors = explanation.priority_factors || [];
        const maxPoints = Math.max(1, ...factors.map((f) => Number(f.points) || 0));
        const factorRows = factors.map((factor) => {
            const points = Number(factor.points) || 0;
            const value = Array.isArray(factor.value) ? factor.value.join(", ") : (factor.value ?? "—");
            return `<li><span class="xai-factor-name">${escapeHtml(FACTOR[factor.factor] || factor.factor)}</span>
                <span class="xai-factor-bar"><i data-width="${Math.round((points / maxPoints) * 100)}"></i></span>
                <span class="xai-factor-points">+${escapeHtml(points)}</span>
                <span class="xai-factor-value">${escapeHtml(value)}</span></li>`;
        }).join("");

        const uncited = Object.values(evidence).filter((record) => !record.cited);
        const feedback = (inputs.feedback || []).map((item) =>
            `<li>${chip(VERDICT[item.verdict] || item.verdict, item.verdict === "false_positive" ? "xai-warn" : "xai-plain")} ${escapeHtml(item.feedback_id)} · ${escapeHtml(time(item.recorded_at))} · ${escapeHtml((item.match || []).map((m) => MATCH[m] || m).join(", "))}</li>`).join("");
        const profile = inputs.correlation_profile || {};
        const inputLines = [
            profile.name ? `상관분석 프로필 <strong>${escapeHtml(profile.name)}</strong> (경보 전 ${escapeHtml(Math.round((profile.seconds_before || 0) / 60))}분 · 후 ${escapeHtml(Math.round((profile.seconds_after || 0) / 60))}분${profile.cross_agent ? " · 다른 에이전트 포함" : ""})` : "",
            inputs.agent_calls ? `증거 수집 에이전트 ${escapeHtml(inputs.agent_calls)}회 호출 · 추가 증거 ${escapeHtml((inputs.agent_added_evidence || []).length)}건 · ${escapeHtml(AGENT_STOP[inputs.agent_stopped] || inputs.agent_stopped || "")}` : "",
        ].filter(Boolean).map((line) => `<li>${line}</li>`).join("");

        container.hidden = false;
        container.innerHTML = `
            <div class="xai-panel">
                <div class="xai-head">
                    <div>
                        <p class="panel-kicker">설명 가능성 · XAI</p>
                        <h3>판단 근거</h3>
                    </div>
                    <div class="xai-stats">
                        <span><strong>${escapeHtml(summary.grounded ?? 0)}</strong>/${escapeHtml(summary.claims ?? 0)} 주장 근거 확인</span>
                        <span><strong>${escapeHtml(summary.evidence_cited ?? 0)}</strong>/${escapeHtml(summary.evidence_total ?? 0)} 증거 사용</span>
                        ${summary.ungrounded || summary.partial ? `<span class="xai-stat-bad"><strong>${escapeHtml((summary.ungrounded || 0) + (summary.partial || 0))}</strong> 주장에 없는 ID 인용</span>` : ""}
                    </div>
                </div>

                <div class="xai-conclusion">
                    <div><span class="xai-label">모델 판단</span>
                        심각도 <strong>${escapeHtml(SEVERITY[severity.level] || "—")}</strong> · 신뢰도 <strong>${escapeHtml(CONFIDENCE[confidence.level] || "—")}</strong>
                        ${severity.rationale ? `<p class="muted">${escapeHtml(severity.rationale)}</p>` : ""}</div>
                    <div><span class="xai-label">HAW-KI 우선순위 (코드 계산)</span>
                        <strong>${escapeHtml(priority.band || "—")}</strong> ${priority.score !== undefined && priority.score !== null ? `· ${escapeHtml(priority.score)}점` : ""}
                        ${expected ? `<p class="muted">이 등급에 보통 맞는 심각도: ${escapeHtml(expected)}</p>` : ""}</div>
                    <div class="xai-agreement">${chip(agreementLabel, agreementClass)}</div>
                </div>

                <h4>주장 → 인용 증거 → 원본 로그</h4>
                ${claims.length ? `<ol class="xai-claims">${claims.map((claim) => claimHtml(claim, evidence)).join("")}</ol>` : `<p class="muted">모델이 증거를 인용한 주장을 내지 않았습니다.</p>`}
                ${uncited.length ? `<details class="xai-uncited"><summary>어떤 주장에도 쓰이지 않은 증거 ${escapeHtml(uncited.length)}건</summary><ul>${uncited.map((record) => `<li><details class="xai-ref-detail"><summary class="xai-ref">${escapeHtml(record.evidence_id)}</summary>${evidenceDetail(record)}</details></li>`).join("")}</ul></details>` : ""}

                ${factorRows ? `<h4>우선순위 요인</h4><ul class="xai-factors">${factorRows}</ul>` : ""}

                ${inputLines || feedback ? `<h4>판단에 들어간 다른 입력</h4><ul class="xai-inputs">${inputLines}${feedback ? `<li>참고한 과거 분석가 판정 (근거가 아닌 맥락)<ul class="xai-feedback">${feedback}</ul></li>` : ""}</ul>` : ""}

                <p class="xai-method">주장의 문장은 모델이 썼고, 연결·확인 상태·개수·우선순위 요인은 코드가 계산했습니다. 증거 묶음에 없는 ID를 인용하면 "근거 없음"으로 표시됩니다.</p>
            </div>`;
        // The CSP (style-src 'self') drops inline style attributes; set widths here.
        container.querySelectorAll(".xai-factor-bar i[data-width]").forEach((bar) => {
            bar.style.width = `${Number(bar.dataset.width) || 0}%`;
        });
    }

    window.HawkiXai = { render };
})();
