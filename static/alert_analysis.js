(() => {
    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    async function requestJson(url, options = {}) {
        const response = await fetch(url, options);
        let body = {};
        try { body = await response.json(); } catch { body = {}; }
        if (!response.ok) {
            const reason = body.error
                ? (body.detail ? `${body.error} (${body.detail})` : body.error)
                : (body.detail || `요청 실패: ${response.status}`);
            throw new Error(reason);
        }
        return body;
    }

    // Display-only labels for machine values; the values themselves are untouched.
    const ENTITY_LABELS = {
        hosts: "호스트",
        users: "사용자",
        source_ips: "출발지 IP",
        destination_ips: "목적지 IP",
        files: "파일",
        processes: "프로세스",
    };

    const VERDICT_LABELS = {
        malicious: "악성",
        suspicious: "의심",
        benign: "정상",
        unknown: "알 수 없음",
    };

    const formatDateTime = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? String(value ?? "—")
            : date.toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    };

    function markdown(value) {
        if (typeof window.renderMarkdown === "function") return window.renderMarkdown(value);
        return `<p>${escapeHtml(value).replaceAll("\n", "<br>")}</p>`;
    }

    function formatEvent(event) {
        const source = event.source_type || event.source_dataset || "이벤트";
        const host = event.host?.name || event.destination?.ip || "—";
        const reasons = event.correlation?.reasons || [];
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(source)}</span>
                <span class="tag">${escapeHtml(formatDateTime(event["@timestamp"]))}</span>
                ${reasons.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(event.message || event.rule?.name || "이벤트")}</strong>
            <p class="muted">${escapeHtml(host)}</p>
        </div>`;
    }

    function formatAsset(asset) {
        const facts = [
            ["업무 중요도", asset.criticality],
            ["노출 수준", asset.exposure],
            ["네트워크 구역", asset.zone],
            ["데이터 등급", asset.data_classification],
            ["담당자", asset.owner],
        ].filter(([, value]) => value);
        const matchedOn = asset.match?.matched_on || [];
        return `<div class="output-item">
            <div class="action-meta">
                ${asset.match?.on_trigger_alert ? `<span class="tag">트리거 경보에 포함</span>` : ""}
                ${facts.map(([label, value]) => `<span class="tag">${escapeHtml(label)}: ${escapeHtml(value)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(asset.hostname || asset.id)}</strong>
            <p class="muted">${escapeHtml(asset.business_service || "—")}</p>
            <p class="muted">일치 기준: ${escapeHtml(matchedOn.join(", ") || "—")}</p>
        </div>`;
    }

    function formatIndicator(indicator) {
        const match = indicator.match || {};
        const verdictKey = String(indicator.verdict || "").toLowerCase();
        const verdictLabel = indicator.verdict
            ? VERDICT_LABELS[verdictKey] || indicator.verdict
            : "판정 없음";
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(verdictLabel)}</span>
                <span class="tag">신뢰도 ${escapeHtml(indicator.confidence ?? 0)}</span>
                ${match.on_trigger_alert ? `<span class="tag">트리거 경보에 포함</span>` : ""}
                ${match.indicator_expired ? `<span class="tag">만료된 지표</span>` : ""}
            </div>
            <strong>${escapeHtml(match.matched_value || indicator.value)}</strong>
            <p class="muted">${escapeHtml(indicator.description || "")}</p>
            <p class="muted">${escapeHtml(indicator.feed || "피드")} · ${escapeHtml((indicator.categories || []).join(", ") || "분류 없음")}</p>
        </div>`;
    }

    function renderReview(root, result) {
        // Schema coverage for the returned assessment. Sections the model
        // skipped and citations matching no event in the bundle are shown to
        // the analyst rather than quietly accepted.
        const panel = root.querySelector("[data-analysis-review]");
        const review = result.assessment_review;
        if (!panel || !review) return;

        const missing = review.missing_sections || [];
        const ungrounded = review.ungrounded_event_ids || [];
        const notes = review.notes || [];
        const tags = [
            `<span class="tag">${review.complete ? "필수 항목 모두 포함" : `누락 항목: ${missing.length}`}</span>`,
            `<span class="tag">증거 인용: ${escapeHtml(review.citations ?? 0)}</span>`,
            ungrounded.length ? `<span class="tag">근거 없는 인용: ${ungrounded.length}</span>` : "",
            review.repair_attempted ? `<span class="tag">보정 1회 수행</span>` : "",
        ].join("");

        panel.hidden = false;
        panel.innerHTML = `<div class="output-item">
            <div class="action-meta">${tags}</div>
            ${missing.length ? `<p class="muted">보고되지 않은 항목: ${escapeHtml(missing.join(", "))}</p>` : ""}
            ${ungrounded.length ? `<p class="muted">증거 묶음에 없는 참조 이벤트: ${escapeHtml(ungrounded.join(", "))}</p>` : ""}
            ${(review.notes_localized || notes).map((note) => `<p class="muted">${escapeHtml(note)}</p>`).join("")}
        </div>`;
    }

    // 분석가 판정: recorded for later analyses of similar alerts
    // (hawki_alert_analysis/feedback.py).
    const VERDICT_LABELS_KO = { confirmed: "확인됨 (실제 위협)", false_positive: "오탐", investigating: "추가 조사" };

    async function renderFeedbackForm(root, result, alertId, csrf) {
        const panel = root.querySelector("[data-analyst-feedback]");
        if (!panel) return;
        let history = { similar: [], for_alert: [], context_enabled: false };
        try {
            history = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/feedback`);
        } catch (error) {
            console.warn("Analyst feedback unavailable:", error);
        }
        const similar = history.similar || [];
        const confirmed = similar.filter((item) => item.verdict === "confirmed").length;
        const falsePositive = similar.filter((item) => item.verdict === "false_positive").length;
        const used = Number(result.feedback_context) || 0;
        const status = history.context_enabled
            ? (used ? `이번 분석에 비슷한 과거 판정 ${used}건을 참고 맥락으로 넣었습니다.` : "이번 분석에 넣을 비슷한 과거 판정이 없었습니다.")
            : "과거 판정 참고 꺼짐 (판정은 저장됨)";
        const last = (history.for_alert || []).slice(-1)[0];

        panel.hidden = false;
        panel.innerHTML = `<div class="output-item analyst-feedback">
            <p class="panel-kicker">분석가 판정</p>
            <p>이 경보를 어떻게 판단하셨나요? 같은 룰·호스트 또는 출발지의 다음 분석에 참고 맥락으로 쓰입니다.</p>
            <p class="muted">${escapeHtml(status)}${similar.length ? ` 비슷한 과거 판정: 확인됨 ${confirmed}건 · 오탐 ${falsePositive}건.` : ""}</p>
            ${last ? `<p class="muted">마지막 판정: ${escapeHtml(VERDICT_LABELS_KO[last.verdict] || last.verdict)} · ${escapeHtml(formatDateTime(last.recorded_at))} · ${escapeHtml(last.reviewer || "")}</p>` : ""}
            <form class="analyst-feedback-form" data-feedback-form>
                <label>판정
                    <select name="verdict">
                        ${Object.entries(VERDICT_LABELS_KO).map(([value, label]) => `<option value="${value}">${label}</option>`).join("")}
                    </select>
                </label>
                <label class="analyst-feedback-note">메모 (판단 근거)<textarea name="note" rows="2" maxlength="1000" placeholder="예: 내부 점검 스캐너, 차단 완료"></textarea></label>
                <button class="button primary small" type="submit">판정 저장</button>
            </form>
            <p class="muted" data-feedback-result></p>
        </div>`;

        panel.querySelector("[data-feedback-form]").addEventListener("submit", async (event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const values = Object.fromEntries(new FormData(form));
            const button = form.querySelector("button");
            button.disabled = true;
            try {
                await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/feedback`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
                    body: JSON.stringify({ ...values, analysis_id: result.analysis_id || "" }),
                });
                panel.querySelector("[data-feedback-result]").textContent =
                    `'${VERDICT_LABELS_KO[values.verdict] || values.verdict}' 판정을 저장했습니다.`;
                renderHandling(root, alertId, csrf);
            } catch (error) {
                panel.querySelector("[data-feedback-result]").textContent = error.message;
            } finally {
                button.disabled = false;
            }
        });
    }

    // 처리 상태: settle an alert without running an analysis first, so the
    // queue's 미처리 filter can drop it (10주차 멘토링 2번).
    const HANDLING_STATE_KO = { confirmed: "처리됨 · 실제 위협", false_positive: "처리됨 · 오탐", investigating: "추가 조사 중" };

    async function renderHandling(root, alertId, csrf) {
        const box = root.querySelector("[data-alert-handling]");
        if (!box) return;
        let history = { for_alert: [] };
        try {
            history = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/feedback`);
        } catch (error) {
            console.warn("Alert handling state unavailable:", error);
            return;
        }
        const last = (history.for_alert || []).filter((item) => item.verdict !== "withdrawn").slice(-1)[0];
        const current = last ? HANDLING_STATE_KO[last.verdict] || last.verdict : "미처리";
        box.hidden = false;
        box.innerHTML = `
            <span class="muted">처리 상태</span>
            <span class="handling-state">${escapeHtml(current)}</span>
            ${last ? `<span class="muted">${escapeHtml(formatDateTime(last.recorded_at))} · ${escapeHtml(last.reviewer || "")}</span>` : ""}
            <button type="button" class="button secondary small" data-handle="false_positive">오탐으로 처리</button>
            <button type="button" class="button secondary small" data-handle="confirmed">실제 위협으로 처리</button>
            <button type="button" class="button secondary small" data-handle="investigating">추가 조사로 두기</button>
            <span class="muted" data-handling-result></span>`;
        box.querySelectorAll("[data-handle]").forEach((button) => button.addEventListener("click", async () => {
            const verdict = button.dataset.handle;
            box.querySelectorAll("[data-handle]").forEach((item) => { item.disabled = true; });
            try {
                await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/feedback`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
                    body: JSON.stringify({ verdict, note: "", analysis_id: "" }),
                });
                await renderHandling(root, alertId, csrf);
            } catch (error) {
                const result = box.querySelector("[data-handling-result]");
                if (result) result.textContent = error.message;
                box.querySelectorAll("[data-handle]").forEach((item) => { item.disabled = false; });
            }
        }));
    }

    function renderCase(root, data) {
        const caseData = data.case;
        const trigger = caseData.trigger || {};
        root.querySelector("[data-case-title]").textContent = caseData.title || trigger.message || "경보 케이스";
        root.querySelector("[data-case-id]").textContent = `${caseData.case_id} · ${caseData.scenario_id}`;
        root.querySelector("[data-trigger]").innerHTML = formatEvent(trigger);

        const entities = caseData.entities || {};
        root.querySelector("[data-entities]").innerHTML = Object.entries(entities)
            .filter(([, values]) => Array.isArray(values) && values.length)
            .map(([key, values]) => `<div class="output-item"><strong>${escapeHtml(ENTITY_LABELS[key] || key.replaceAll("_", " "))}</strong><div class="action-meta">${values.map((v) => `<span class="tag">${escapeHtml(v)}</span>`).join("")}</div></div>`)
            .join("") || `<div class="empty-state">상관된 개체가 없습니다.</div>`;

        const assets = caseData.assets || [];
        const unresolved = caseData.unresolved_assets || [];
        root.querySelector("[data-assets]").innerHTML = [
            assets.map(formatAsset).join(""),
            unresolved.length
                ? `<div class="output-item"><strong>자산 목록에 없음</strong><div class="action-meta">${unresolved.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")}</div><p class="muted">외부 또는 미등록 개체</p></div>`
                : "",
        ].join("") || `<div class="empty-state">연관된 자산 정보가 없습니다.</div>`;

        const intel = caseData.threat_intelligence || [];
        const stats = caseData.threat_intelligence_stats || {};
        root.querySelector("[data-intel]").innerHTML = [
            intel.map(formatIndicator).join(""),
            `<div class="output-item"><p class="muted">확인한 관측값: ${escapeHtml(stats.observables_checked || 0)} · 위협 정보 없음: ${escapeHtml(stats.observables_without_intelligence_count || 0)}</p></div>`,
        ].join("") || `<div class="empty-state">일치하는 위협 지표가 없습니다.</div>`;

        root.querySelector("[data-timeline]").innerHTML = (caseData.timeline || []).map(formatEvent).join("");
        const host = trigger.host?.name || trigger.destination?.ip || "";
        const params = new URLSearchParams({mode: "alert_summary", alert_id: root.dataset.alertId});
        if (host) params.set("host", host);
        root.querySelector("[data-continue-agent]").href = `/agent?${params}`;
    }

    function renderNativeEvidence(root, evidence) {
        const target = root.querySelector("[data-trigger]");
        if (!target) return;

        const rule = evidence.rule || {};
        const agent = evidence.agent || {};
        const manager = evidence.manager || {};
        const decoder = evidence.decoder || {};
        const data = evidence.data || {};
        const system = data.system || {};
        const eventdata = data.eventdata || {};
        const mitre = rule.mitre || {};

        const joinValues = (value) => {
            if (Array.isArray(value)) return value.join(", ");
            return value ?? "";
        };

        const sourceIp =
            data.srcip ||
            data.src_ip ||
            eventdata.sourceIp ||
            eventdata.sourceIP ||
            "";

        const destinationIp =
            data.dstip ||
            data.dst_ip ||
            eventdata.destinationIp ||
            eventdata.destinationIP ||
            "";

        const sourcePort =
            data.srcport ||
            data.src_port ||
            eventdata.sourcePort ||
            "";

        const destinationPort =
            data.dstport ||
            data.dst_port ||
            eventdata.destinationPort ||
            "";

        const protocol =
            data.protocol ||
            eventdata.protocol ||
            "";

        const fields = [
            ["시각", evidence.timestamp ? formatDateTime(evidence.timestamp) : ""],
            ["에이전트", agent.name],
            ["에이전트 ID", agent.id],
            ["에이전트 IP", agent.ip],
            ["매니저", manager.name],
            ["룰 ID", rule.id],
            ["Wazuh 룰 레벨", rule.level],
            ["룰 설명", rule.description],
            ["룰 그룹", joinValues(rule.groups)],
            ["디코더", decoder.name],
            ["상위 디코더", decoder.parent],
            ["로그 소스", evidence.location],
            ["출발지 IP", sourceIp],
            ["출발지 포트", sourcePort],
            ["목적지 IP", destinationIp],
            ["목적지 포트", destinationPort],
            ["프로토콜",
                decoder.name === "web-accesslog" ? "" : protocol
            ],
            ["HTTP 메서드",
                decoder.name === "web-accesslog" ? data.protocol : ""
            ],
            ["URL", data.url],
            ["HTTP 상태 코드", data.id],
            ["Sysmon 이벤트 ID", system.eventID],
            ["프로세스", eventdata.image],
            ["프로세스 ID", eventdata.processId],
            ["사용자", eventdata.user],
            ["명령줄", eventdata.commandLine],
            ["MITRE ATT&CK ID", joinValues(mitre.id)],
            ["MITRE 전술", joinValues(mitre.tactic)],
            ["MITRE 기법", joinValues(mitre.technique)],
        ].filter(([, value]) =>
            value !== undefined &&
            value !== null &&
            String(value).trim() !== ""
        );

        target.innerHTML = `
            <div class="output-item">
                ${fields.map(([label, value]) => `
                    <p>
                        <strong>${escapeHtml(label)}:</strong>
                        ${escapeHtml(String(value))}
                    </p>
                `).join("")}
            </div>
            ${evidence.full_log ? `
                <details class="log-raw">
                    <summary>원시 이벤트</summary>
                    <pre>${escapeHtml(String(evidence.full_log))}</pre>
                </details>
            ` : ""}
        `;

        const title = root.querySelector("[data-case-title]");
        if (title && rule.description) {
            title.textContent = rule.description;
        }

        const caseId = root.querySelector("[data-case-id]");
        if (caseId) {
            caseId.hidden = false;
            caseId.textContent = [evidence.id, evidence.index]
                .filter(Boolean)
                .join(" · ");
        }

        const link = root.querySelector("[data-continue-agent]");
        if (link) {
            const params = new URLSearchParams({
                mode: "alert_summary",
                alert_id: evidence.id || root.dataset.alertId,
            });
            if (agent.name) params.set("host", agent.name);
            link.href = `/agent?${params}`;
        }

        renderInvestigationPivots(root, evidence);
    }

    function investigationLogUrl({
        index,
        query,
        start,
        end,
        pivot,
        alertId,
    }) {
        const params = new URLSearchParams({
            index,
            query,
            start,
            end,
            size: "100",
            pivot,
            from_alert: alertId,
            run: "1",
        });

        return `/logs?${params.toString()}`;
    }

    function renderInvestigationPivots(root, evidence) {
        const section = root.querySelector("[data-pivots-section]");
        const target = root.querySelector("[data-investigation-pivots]");

        if (!section || !target) return;

        const agent = evidence.agent || {};
        const rule = evidence.rule || {};
        const data = evidence.data || {};

        const alertId = String(
            evidence.id || root.dataset.alertId || ""
        );

        const sourceIp = String(
            data.srcip ||
            data.src_ip ||
            data.sourceIp ||
            data.eventdata?.sourceIp ||
            ""
        ).trim();
        const destinationIp = String(data.dest_ip || data.dstip || "").trim();
        const signatureId = String(data.alert?.signature_id ?? "").trim();

        const agentId = String(agent.id || "").trim();
        const ruleId = String(rule.id || "").trim();

        const timestamp = Date.parse(evidence.timestamp || "");

        if (!Number.isFinite(timestamp)) {
            return;
        }

        /*
         * These values are interpolated into query_string syntax.
         * Restrict them to expected identifier forms rather than trusting
         * arbitrary producer-controlled strings.
         */
        const safeIp =
            /^[0-9A-Fa-f:.]{3,64}$/.test(sourceIp)
                ? sourceIp
                : "";

        const safeAgentId =
            /^[A-Za-z0-9_.-]{1,64}$/.test(agentId)
                ? agentId
                : "";

        const safeRuleId =
            /^[A-Za-z0-9_.-]{1,64}$/.test(ruleId)
                ? ruleId
                : "";

        const historyStart =
            new Date(timestamp - 24 * 60 * 60 * 1000).toISOString();

        const historyEnd =
            new Date(timestamp + 60 * 60 * 1000).toISOString();

        const rawStart =
            new Date(timestamp - 5 * 60 * 1000).toISOString();

        const rawEnd =
            new Date(timestamp + 5 * 60 * 1000).toISOString();

        const links = [];

        if (safeIp) {
            links.push({
                label: "동일 출발지 IP · 24시간",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query:
                        `(data.srcip:"${safeIp}" OR ` +
                        `data.src_ip:"${safeIp}" OR ` +
                        `data.eventdata.sourceIp:"${safeIp}" OR ` +
                        `full_log:"${safeIp}")`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_source_ip",
                    alertId,
                }),
            });
        }

        if (safeAgentId) {
            links.push({
                label: "동일 에이전트 · 24시간",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_agent",
                    alertId,
                }),
            });
        }

        if (safeRuleId) {
            links.push({
                label: "동일 룰 · 24시간",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query: `rule.id:"${safeRuleId}"`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_rule",
                    alertId,
                }),
            });
        }

        // Suricata (10주차 멘토링 6번): the original concept is to collect
        // every log and, when a Suricata signature fires, pull the logs that
        // share its signature id and address so similar traffic is seen
        // together. These pivots do exactly that; the team's AI rule
        // generation is a separate, added step (Suricata 룰 화면).
        const safeSid = /^[0-9]{1,12}$/.test(signatureId) ? signatureId : "";
        const safeDestination = /^[0-9A-Fa-f:.]{3,64}$/.test(destinationIp) ? destinationIp : "";
        if (safeSid) {
            const addresses = [safeIp, safeDestination].filter(Boolean);
            const addressClause = addresses.length
                ? ` AND (${addresses.map((ip) => `data.src_ip:"${ip}" OR data.dest_ip:"${ip}"`).join(" OR ")})`
                : "";
            if (addressClause) {
                links.push({
                    label: `Suricata SID ${safeSid} + 같은 IP · 24시간`,
                    href: investigationLogUrl({
                        index: "wazuh-alerts-*",
                        query: `data.alert.signature_id:"${safeSid}"${addressClause}`,
                        start: historyStart,
                        end: historyEnd,
                        pivot: "suricata_sid_ip",
                        alertId,
                    }),
                });
            }
            links.push({
                label: `같은 SID ${safeSid} · 모든 IP · 24시간`,
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query: `data.alert.signature_id:"${safeSid}"`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "suricata_sid",
                    alertId,
                }),
            });
            if (addresses.length) {
                links.push({
                    label: "같은 IP의 전체 원시 로그 · ±1시간",
                    href: investigationLogUrl({
                        index: "wazuh-archives-*",
                        query: addresses.map((ip) =>
                            `data.src_ip:"${ip}" OR data.dest_ip:"${ip}" OR data.srcip:"${ip}" OR full_log:"${ip}"`).join(" OR "),
                        start: new Date(timestamp - 60 * 60 * 1000).toISOString(),
                        end: new Date(timestamp + 60 * 60 * 1000).toISOString(),
                        pivot: "suricata_ip_raw",
                        alertId,
                    }),
                });
            }
        }

        if (safeAgentId) {
            links.push({
                label: "원시 이벤트 · ±5분",
                href: investigationLogUrl({
                    index: "wazuh-archives-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: rawStart,
                    end: rawEnd,
                    pivot: "raw_window",
                    alertId,
                }),
            });
        }

        if (!links.length) {
            return;
        }

        target.innerHTML = links.map((item) => `
            <a class="button secondary"
               href="${escapeHtml(item.href)}">
                ${escapeHtml(item.label)}
            </a>
        `).join("");
        const note = root.querySelector("[data-suricata-pivot-note]");
        if (note) note.hidden = !safeSid;

        section.hidden = false;
    }

    function renderAnalystContext(root, data) {
        const section = root.querySelector(
            "[data-enrichment-section]"
        );

        const target = root.querySelector(
            "[data-analyst-context]"
        );

        if (!section || !target) return;

        const sameSource = data.same_source || {};

        const cards = [
            {
                label: "출발지 활동",
                value: data.source_ip
                    ? sameSource.count ?? 0
                    : "—",
                detail: data.source_ip
                    ? data.source_ip
                    : "구조화된 출발지 IP 없음",
            },
            {
                label: "출발지의 룰",
                value: data.source_ip
                    ? sameSource.distinct_rules ?? 0
                    : "—",
                detail: "고유 Wazuh 룰 수",
            },
            {
                label: "도달한 호스트",
                value: data.source_ip
                    ? sameSource.distinct_agents ?? 0
                    : "—",
                detail: "고유 모니터링 에이전트 수",
            },
            {
                label: "동일 룰",
                value: data.same_rule_count ?? 0,
                detail: data.rule_id
                    ? `룰 ${data.rule_id}`
                    : "룰 식별자 없음",
            },
            {
                label: "호스트 탐지",
                value: data.same_agent_count ?? 0,
                detail: data.agent_id
                    ? `에이전트 ${data.agent_id}`
                    : "에이전트 식별자 없음",
            },
        ];

        target.innerHTML = cards.map((item) => `
            <div class="analyst-context-card">
                <span>${escapeHtml(item.label)}</span>
                <strong>${escapeHtml(item.value)}</strong>
                <small>${escapeHtml(item.detail)}</small>
            </div>
        `).join("");

        section.hidden = false;
    }

    function renderInvestigationContext(root, context) {
        const target = root.querySelector("[data-investigation-context]");
        const meta = root.querySelector("[data-context-meta]");

        if (!target) return;

        const events = context.events || [];

        if (meta) {
            meta.textContent =
                `관련 이벤트 ${events.length}건 · ±${context.window_seconds || 0}초`;
        }

        if (!events.length) {
            target.innerHTML =
                `<div class="empty-state">선택된 관련 증거가 없습니다.</div>`;
            return;
        }

        target.innerHTML = events.map((event) => {
            const data = event.data || {};
            const rule = event.rule || {};

            const source =
                data.srcip ||
                data.sourceIp ||
                "";

            const destination =
                data.dstip ||
                data.destinationIp ||
                "";

            const eventLabel =
                Object.keys(data).length === 0
                    ? "디코딩되지 않은 원시 이벤트"
                    : "";

            const parts = [
                eventLabel,
                source ? `출발지: ${source}` : "",
                destination ? `목적지: ${destination}` : "",
                data.protocol ? `프로토콜/메서드: ${data.protocol}` : "",
                data.url ? `URL: ${data.url}` : "",
                data.id ? `상태/이벤트: ${data.id}` : "",
                rule.id ? `룰: ${rule.id}` : "",
                rule.level !== undefined && rule.level !== null
                    ? `레벨: ${rule.level}`
                    : "",
            ].filter(Boolean);

            return `
                <div class="output-item investigation-event">
                    <p>
                        <strong>${escapeHtml(event.timestamp ? formatDateTime(event.timestamp) : "시각 알 수 없음")}</strong>
                    </p>

                    ${event.location
                        ? `<p class="muted">${escapeHtml(event.location)}</p>`
                        : ""}

                    ${parts.length
                        ? `<p>${escapeHtml(parts.join(" · "))}</p>`
                        : ""}

                    ${event.full_log
                        ? `<details class="log-raw">
                               <summary>원시 이벤트</summary>
                               <pre>${escapeHtml(event.full_log)}</pre>
                           </details>`
                        : ""}
                </div>
            `;
        }).join("");
    }

    const REVIEW_LABELS = { unreviewed: "검토 전", investigating: "추가 조사", confirmed: "확인됨", false_positive: "오탐" };
    const AI_LABELS = { completed: "AI 분석 완료", pending: "AI 대기", failed: "AI 실패", expired: "AI 만료" };
    async function renderAlertHistory(root, alertId) {
        const target = root.querySelector("[data-alert-history]");
        if (!target) return;
        let data;
        try {
            data = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/history`);
        } catch {
            return;
        }
        const reports = data.reports || [];
        const analyses = data.analyses || [];
        if (!reports.length && !analyses.length) return;
        const when = (value) => {
            const date = new Date(value);
            return Number.isNaN(date.getTime()) ? String(value || "") : date.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
        };
        target.hidden = false;
        target.innerHTML = `
            <strong>이 경보의 이전 기록</strong>
            ${reports.map((report) => `<a class="alert-history-item" href="/auto-reports?id=${encodeURIComponent(report.id)}">
                자동 보고서 ${escapeHtml(report.id)} · ${escapeHtml(report.band || "")} · ${escapeHtml(AI_LABELS[report.ai_status] || report.ai_status || "")} · ${escapeHtml(REVIEW_LABELS[report.review_status] || report.review_status || "")}${report.occurrences > 1 ? ` · 묶인 경보 ${escapeHtml(report.occurrences)}건` : ""}
            </a>`).join("")}
            ${analyses.length ? `<span class="alert-history-item">LLM 분석 ${escapeHtml(analyses.length)}회 · 마지막 ${escapeHtml(when(analyses[0].timestamp))}${analyses[0].by ? ` (${escapeHtml(analyses[0].by)})` : ""}</span>` : ""}
            ${reports.some((report) => report.ai_status === "completed") ? `<span class="muted">완료된 자동 보고서가 있습니다. 재분석 전에 먼저 확인</span>` : ""}`;
        // The last analysis's red team evaluation, so opening the alert from
        // the dashboard shows where it stands without analysing again.
        const last = analyses.find((item) => item.analysis_id && item.redteam && !["disabled", "not_sent"].includes(item.redteam));
        const panel = root.querySelector("[data-history-redteam]");
        if (last && panel && root.querySelector("[data-analysis-section]")?.hidden !== false) {
            window.HawkiRedteam?.render(panel, {
                analysisId: last.analysis_id,
                decision: last.redteam,
                caption: `마지막 LLM 분석 (${when(last.timestamp)}) 기준`,
            });
        }
    }

    async function initDetail(root) {
        const alertId = root.dataset.alertId;
        const csrf = root.dataset.csrf;
        renderAlertHistory(root, alertId);
        renderHandling(root, alertId, csrf);
        try {
            renderCase(root, await requestJson(`/api/alerts/${encodeURIComponent(alertId)}`));
            try {
                const evidence = await requestJson(
                    `/api/alerts/${encodeURIComponent(alertId)}/evidence`
                );
                renderNativeEvidence(root, evidence);

                try {
                    const enrichment = await requestJson(
                        `/api/alerts/${encodeURIComponent(alertId)}/enrichment`
                    );
                    renderAnalystContext(root, enrichment);
                } catch (enrichmentError) {
                    console.warn(
                        "Alert enrichment unavailable:",
                        enrichmentError
                    );
                }

                try {
                    const context = await requestJson(
                        `/api/alerts/${encodeURIComponent(alertId)}/context`
                    );
                    renderInvestigationContext(root, context);
                } catch (contextError) {
                    const target = root.querySelector(
                        "[data-investigation-context]"
                    );
                    if (target) {
                        target.innerHTML =
                            `<div class="empty-state">조사 맥락을 불러오지 못했습니다: ${escapeHtml(contextError.message)}</div>`;
                    }
                }
            } catch (evidenceError) {
                const target = root.querySelector("[data-trigger]");
                if (target) {
                    target.innerHTML =
                        `<div class="empty-state">Wazuh 원본 증거를 불러오지 못했습니다: ${escapeHtml(evidenceError.message)}</div>`;
                }
            }
        } catch (error) {
            const section = root.querySelector("[data-analysis-section]");
            const output = root.querySelector("[data-analysis-output]");

            if (section) section.hidden = false;
            if (output) output.textContent = error.message;
            return;
        }

        const analyzeButton = root.querySelector("[data-analyze]");
        if (!analyzeButton) return;

        // How the evidence was gathered before the analysis (evidence agent).
        const TOOL_LABELS = {
            widen_window: "시간창 확장",
            search_address: "주소 검색(전체 에이전트)",
            search_events: "조건 검색(룰·로그 형식·URL·주소)",
            lookup_asset: "자산 조회",
            lookup_indicator: "위협 인텔리전스 조회",
            finish: "수집 종료",
        };
        const STOP_LABELS = {
            finish: "에이전트가 증거 충분 판단",
            no_tool_call: "추가 수집 불필요",
            max_calls: "호출 상한 도달",
            error: "수집 실패(원래 증거로 분석)",
            context_limit_reverted: "증거가 너무 많아 원래 증거로 분석",
            no_room: "증거가 이미 한도를 넘어 추가 수집 건너뜀",
        };
        const REFUSAL_LABELS = {
            value_not_in_evidence: "증거에 없는 값",
            unknown_tool: "허용되지 않은 도구",
            not_an_ip_address: "IP 주소가 아님",
            no_filter: "검색 조건 없음",
            text_length: "검색어 길이 범위 밖",
        };
        // The alias (e.g. hawki-local) can point at different weights over
        // time; generation.served_model is what vLLM reported actually loaded.
        function modelLabel(result) {
            const alias = result.model || "로컬 모델";
            const served = String((result.generation || {}).served_model || "");
            if (!served || served === alias) return alias;
            const hub = served.match(/models--([^/]+?)--([^/]+)/);
            const name = hub ? `${hub[1]}/${hub[2]}` : served.split("/").filter(Boolean).pop();
            return name ? `${alias} (${name})` : alias;
        }

        function renderAgentRetrieval(output, trace) {
            if (!trace || !output) return;
            const calls = (trace.calls || []).map((call) => {
                const label = TOOL_LABELS[call.tool] || call.tool;
                const args = Object.entries(call.arguments || {}).map(([k, v]) => `${k}=${v}`).join(", ");
                const state = call.accepted ? "실행" : `거부: ${REFUSAL_LABELS[call.refused] || call.refused || "사유 없음"}`;
                let added = (call.added_evidence_ids || []).length ? ` → ${call.added_evidence_ids.join(", ")}` : "";
                if (call.reverted_evidence_count) added += ` → ${call.reverted_evidence_count}건 찾았지만 분량 한도로 제외`;
                if (call.context_full) added += " · 분량 한도에 닿아 추가 중단";
                return `<li><strong>${escapeHtml(label)}</strong> ${escapeHtml(args)} · ${escapeHtml(state)}${escapeHtml(added)}${call.reason ? `<br><span class="muted">${escapeHtml(call.reason)}</span>` : ""}</li>`;
            }).join("");
            const box = document.createElement("div");
            box.className = "agent-retrieval-trace";
            box.innerHTML = `
                <p class="panel-kicker">증거 수집 에이전트</p>
                <p>도구 호출 ${(trace.calls || []).length}회 / 상한 ${escapeHtml(trace.max_calls ?? "—")}회 · 추가된 증거 ${(trace.added_evidence_ids || []).length}건 · ${escapeHtml(STOP_LABELS[trace.stopped] || trace.stopped || "")}</p>
                ${calls ? `<ol>${calls}</ol>` : ""}`;
            output.prepend(box);
        }

        const output = root.querySelector("[data-analysis-output]");
        const section = root.querySelector("[data-analysis-section]");

        function renderAnalysisResult(result, savedAt = "") {
            if (section) section.hidden = false;
            output.classList.remove("empty-state");
            output.innerHTML = `<div class="markdown-body">${markdown(result.answer || "반환된 분석 결과가 없습니다.")}</div>`;
            if (typeof window.enhanceRenderedContent === "function") window.enhanceRenderedContent(output);
            renderReview(root, result);
            window.HawkiXai?.render(root.querySelector("[data-analysis-xai]"), result.explanation, { queries: result.queries });
            renderFeedbackForm(root, result, alertId, csrf);
            const previous = root.querySelector("[data-history-redteam]");
            if (previous) { previous.hidden = true; previous.innerHTML = ""; }
            window.HawkiRedteam?.render(root.querySelector("[data-analysis-redteam]"), {
                analysisId: result.analysis_id,
                decision: result.redteam?.status,
            });
            const counts = result.metadata_counts || {};
            const bundled = [
                `경보 ${counts.security_alerts ?? 0}`,
                `원시 이벤트 ${counts.security_events ?? 0}`,
                `자산 ${counts.assets ?? 0}`,
                `위협 지표 ${counts.threat_indicators ?? 0}`,
            ].join(" · ");
            root.querySelector("[data-analysis-meta]").textContent =
                `${modelLabel(result)} · 제공된 증거: ${bundled}${savedAt ? ` · ${formatDateTime(savedAt)} 분석` : ""}`;
            renderAgentRetrieval(output, result.agent_retrieval);
        }

        // The analysis runs as a background job on the server (it takes
        // minutes); the page asks for its state every few seconds, so a slow
        // model or a dropped connection no longer loses the answer.
        const POLL_MS = 3000;
        let pollTimer = null;

        function setBusy(busy, startedAt = null) {
            analyzeButton.disabled = busy;
            if (!busy) {
                analyzeButton.textContent = "LLM으로 분석";
                return;
            }
            const seconds = startedAt ? Math.max(0, Math.round((Date.now() - Date.parse(startedAt)) / 1000)) : 0;
            analyzeButton.textContent = `분석 중 · ${Math.floor(seconds / 60)}분 ${seconds % 60}초`;
        }

        async function followJob(job) {
            clearTimeout(pollTimer);
            if (section) section.hidden = false;
            if (!output.querySelector(".typing")) {
                output.classList.remove("empty-state");
                output.innerHTML = `<div class="typing"><i></i><i></i><i></i></div>`;
            }
            setBusy(true, job.started_at);
            let current = job;
            try {
                current = await requestJson(`/api/analysis-jobs/${encodeURIComponent(job.id)}`);
            } catch (error) {
                pollTimer = setTimeout(() => followJob(job), POLL_MS * 2);
                return;
            }
            if (current.status === "running") {
                pollTimer = setTimeout(() => followJob(current), POLL_MS);
                setBusy(true, current.started_at);
                return;
            }
            setBusy(false);
            if (current.status === "done" && current.result) {
                renderAnalysisResult(current.result);
                renderAlertHistory(root, alertId);
            } else {
                const error = current.error || {};
                output.innerHTML = `<div class="empty-state">${escapeHtml(error.detail ? `${error.error} (${error.detail})` : (error.error || "분석에 실패했습니다."))}</div>`;
            }
        }

        analyzeButton.addEventListener("click", async () => {
            setBusy(true);
            try {
                const job = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/analysis-jobs`, {
                    method: "POST",
                    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
                    body: JSON.stringify({}),
                });
                followJob(job);
            } catch (error) {
                setBusy(false);
                if (section) section.hidden = false;
                output.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            }
        });

        // The last finished analysis of this alert, and a running one if the
        // page was reloaded while it ran.
        try {
            const last = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/last-analysis`);
            if (last.running) followJob(last.running);
            else if (last.result) renderAnalysisResult(last.result, last.saved_at);
        } catch (error) {
            // No earlier analysis is the usual case.
        }
        if (!analyzeButton.textContent.startsWith("분석 중")) setBusy(false);
    }

    // The alert table used to be rendered with an agent link and then rewritten
    // here, by a MutationObserver watching #alerts-table with subtree: true
    // whose callback assigned link.textContent inside that same subtree.
    // Assigning textContent replaces the text node and counts as a mutation
    // even when the value is unchanged, so the callback re-triggered itself
    // without end. The microtask queue never drained, and the tab stopped
    // painting and stopped accepting input. app.js now renders the correct
    // link directly, so there is nothing to rewrite.

    document.addEventListener("DOMContentLoaded", () => {
        const root = document.getElementById("alert-analysis-root");
        if (root) initDetail(root);
    });
})();
