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
    const SEVERITY = { info: "정보", low: "낮음", medium: "중간", high: "높음", critical: "치명" };
    const CONFIDENCE = { low: "낮음", medium: "중간", high: "높음" };
    const FACTOR_VALUE = {
        critical: "치명", high: "높음", medium: "중간", low: "낮음",
        internet_facing: "인터넷 노출", dmz: "DMZ", partner_facing: "협력사 노출", internal: "내부망", isolated: "격리망",
        restricted: "제한", confidential: "기밀", secret: "비밀", public: "공개",
        malicious: "악성", suspicious: "의심", benign: "정상", unknown: "알 수 없음",
    };
    const factorValue = (value) => (Array.isArray(value) ? value : [value ?? "—"]).map((item) => FACTOR_VALUE[String(item).toLowerCase()] || item).join(", ");
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
        reconnaissance_ceiling: "정찰·오류 응답 상한",
    };
    const AGENT_STOP = {
        finish: "에이전트가 증거 충분 판단",
        no_tool_call: "추가 수집 불필요",
        max_calls: "호출 상한 도달",
        error: "수집 실패",
        context_limit_reverted: "증거 한도 초과로 원래 증거 사용",
        no_room: "증거가 이미 한도를 넘어 추가 수집 건너뜀",
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
            <div class="xai-claim-head">${chip(KIND[claim.kind] || claim.kind, claim.kind === "contradictory" ? "xai-info" : "xai-plain")} ${chip(label, cls)}${claim.broad ? ` ${chip(`포괄 인용 · ${(claim.event_ids || []).length}건`, "xai-warn")}` : ""}</div>
            <p class="xai-statement">${escapeHtml(claim.statement)}</p>
            <div class="xai-refs">${refs || `<span class="muted">인용한 증거가 없습니다.</span>`}</div>
        </li>`;
    }

    // 추천 검색 확인: a wazuh query from the model is run as a count (size 0)
    // around the trigger time, so "this search finds N events" is checked
    // rather than taken on trust. VQL cannot be run from here and says so.
    const RUNNABLE = new Set(["wazuh", "lucene", "query_string", "kql", "opensearch", "wazuh-lucene", ""]);
    function searchKind(query) {
        const language = String(query.language || "").trim().toLowerCase();
        const value = String(query.value || "").trim();
        if (!value) return "empty";
        if (language === "vql") {
            // Velociraptor artifacts are named <Platform>.<Area>.<Name>
            // (Linux.Sys.Pslist, Windows.EventLogs.Evtx, Generic.Client.Info).
            const artifact = /Artifact\.([A-Za-z0-9_.]+)/.exec(value);
            if (artifact && !/^(Windows|Linux|MacOS|Generic|Server|Custom|Exchange|Admin|Demo|Elastic|Splunk)\./.test(artifact[1])) return "vql_unknown";
            return "vql";
        }
        if (/^\s*select\s/i.test(value)) return "sql";
        return RUNNABLE.has(language) ? "wazuh" : "other";
    }
    function searchWindow(evidence) {
        const trigger = evidence.TRIGGER;
        const when = Date.parse(trigger?.timestamp || "");
        if (!Number.isFinite(when)) return { start: "now-7d", end: "now" };
        return {
            start: new Date(when - 24 * 60 * 60 * 1000).toISOString(),
            end: new Date(Math.min(Date.now(), when + 60 * 60 * 1000)).toISOString(),
        };
    }
    function searchesHtml(queries, evidence) {
        if (!queries.length) return "";
        const window_ = searchWindow(evidence);
        const rows = queries.map((query, index) => {
            const kind = searchKind(query);
            const target = query.index === "archives" ? "archives" : "alerts";
            const logsHref = `/logs?${new URLSearchParams({
                index: target === "archives" ? "wazuh-archives-*" : "wazuh-alerts-*",
                query: query.value || "*",
                start: window_.start,
                end: window_.end,
                size: "100",
                run: "1",
            })}`;
            const state = {
                wazuh: `<span class="xai-chip xai-muted" data-search-state="${index}">확인 중…</span>`,
                vql: `<span class="xai-chip xai-info">Velociraptor에서 실행 · 자동 확인 불가</span>`,
                vql_unknown: `<span class="xai-chip xai-warn">없는 아티팩트일 수 있음 · Velociraptor에서 이름 확인</span>`,
                sql: `<span class="xai-chip xai-bad">실행할 수 없는 형식 (SQL)</span>`,
                other: `<span class="xai-chip xai-muted">${escapeHtml(query.language)} · 자동 확인 불가</span>`,
                empty: `<span class="xai-chip xai-muted">쿼리 없음</span>`,
            }[kind];
            return `<li class="xai-search">
                <div class="xai-search-head"><strong>${escapeHtml(query.title || "추천 검색")}</strong> ${state}</div>
                <code>${escapeHtml(query.value || "")}</code>
                ${kind === "wazuh" ? `<a class="button secondary small" href="${escapeHtml(logsHref)}">로그 검색에서 열기</a>` : ""}
            </li>`;
        }).join("");
        return `<h4>추천 검색 확인</h4>
            <p class="muted xai-search-note">Wazuh 쿼리는 트리거 24시간 전부터 1시간 뒤까지 실제로 실행해 결과 건수를 확인합니다.</p>
            <ol class="xai-searches">${rows}</ol>`;
    }
    async function checkSearches(container, queries, evidence) {
        const window_ = searchWindow(evidence);
        await Promise.all(queries.map(async (query, index) => {
            const badge = container.querySelector(`[data-search-state="${index}"]`);
            if (!badge) return;
            const params = new URLSearchParams({
                query: query.value || "",
                target: query.index === "archives" ? "archives" : "alerts",
                start: window_.start,
                end: window_.end,
            });
            try {
                const response = await fetch(`/api/log-search/check?${params}`, { headers: { Accept: "application/json" } });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
                const label = data.status === "ok" ? `결과 ${Number(data.count).toLocaleString("ko-KR")}건`
                    : data.status === "empty" ? "결과 0건 · 필드나 값 확인 필요"
                    : `쿼리 오류${data.error ? ` · ${data.error}` : ""}`;
                badge.className = `xai-chip ${data.status === "ok" ? "xai-ok" : data.status === "empty" ? "xai-warn" : "xai-bad"}`;
                badge.textContent = label;
            } catch (error) {
                badge.className = "xai-chip xai-muted";
                badge.textContent = `확인하지 못함 · ${error.message}`;
            }
        }));
    }

    function render(container, explanation, options = {}) {
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
        const queries = (Array.isArray(options.queries) ? options.queries : []).filter((query) => query && typeof query === "object").slice(0, 6);
        const factors = explanation.priority_factors || [];
        const maxPoints = Math.max(1, ...factors.map((f) => Number(f.points) || 0));
        const factorRows = factors.map((factor) => {
            const points = Number(factor.points) || 0;
            const value = factorValue(factor.value);
            return `<li><span class="xai-factor-name">${escapeHtml(FACTOR[factor.factor] || factor.factor)}</span>
                <span class="xai-factor-bar"><i data-width="${Math.round((Math.max(0, points) / maxPoints) * 100)}"></i></span>
                <span class="xai-factor-points">${points < 0 ? "" : "+"}${escapeHtml(points)}</span>
                <span class="xai-factor-value">${escapeHtml(value)}</span></li>`;
        }).join("");

        const uncited = Object.values(evidence).filter((record) => !record.cited);
        const feedback = (inputs.feedback || []).map((item) =>
            `<li>${chip(VERDICT[item.verdict] || item.verdict, item.verdict === "false_positive" ? "xai-warn" : "xai-plain")} ${escapeHtml(item.feedback_id)} · ${escapeHtml(time(item.recorded_at))} · ${escapeHtml((item.match || []).map((m) => MATCH[m] || m).join(", "))}</li>`).join("");
        const profile = inputs.correlation_profile || {};
        const inputLines = [
            profile.name ? `상관분석 프로필 <strong>${escapeHtml(profile.name)}</strong> (경보 전 ${escapeHtml(Math.round((profile.seconds_before || 0) / 60))}분 · 후 ${escapeHtml(Math.round((profile.seconds_after || 0) / 60))}분${profile.cross_agent ? " · 다른 에이전트 포함" : ""})` : "",
            inputs.context_fit ? `문맥 한도에 맞추느라 증거 ${escapeHtml((inputs.context_fit.dropped_evidence_ids || []).length)}건 제외 · 긴 텍스트 ${escapeHtml(inputs.context_fit.shortened_fields || 0)}곳 축약${(inputs.context_fit.dropped_evidence_ids || []).length ? ` (${escapeHtml(inputs.context_fit.dropped_evidence_ids.join(", "))})` : ""}` : "",
            (inputs.agent_calls || inputs.agent_stopped === "no_room") ? `증거 수집 에이전트 ${escapeHtml(inputs.agent_calls)}회 호출 · 추가 증거 ${escapeHtml((inputs.agent_added_evidence || []).length)}건 · ${escapeHtml(AGENT_STOP[inputs.agent_stopped] || inputs.agent_stopped || "")}` : "",
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
                        <span><strong>${escapeHtml(summary.broad ? (summary.evidence_cited_specifically ?? 0) : (summary.evidence_cited ?? 0))}</strong>/${escapeHtml(summary.evidence_total ?? 0)} 증거 ${summary.broad ? "구체적으로 인용" : "사용"}</span>
                        ${summary.broad ? `<span class="xai-stat-warn" title="주장 하나가 증거 대부분을 한꺼번에 인용했습니다. 어떤 증거가 그 주장을 뒷받침하는지 드러나지 않아 사용 수에서 뺐습니다."><strong>${escapeHtml(summary.broad)}</strong> 포괄 인용</span>` : ""}
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

                ${searchesHtml(queries, evidence)}

                ${inputLines || feedback ? `<h4>판단에 들어간 다른 입력</h4><ul class="xai-inputs">${inputLines}${feedback ? `<li>참고한 과거 분석가 판정 (근거가 아닌 맥락)<ul class="xai-feedback">${feedback}</ul></li>` : ""}</ul>` : ""}

                <p class="xai-method">문장은 모델, 확인 상태·우선순위는 코드가 계산</p>
            </div>`;
        // The CSP (style-src 'self') drops inline style attributes; set widths here.
        container.querySelectorAll(".xai-factor-bar i[data-width]").forEach((bar) => {
            bar.style.width = `${Number(bar.dataset.width) || 0}%`;
        });
        if (queries.length) checkSearches(container, queries, evidence);
    }

    window.HawkiXai = { render };
})();
