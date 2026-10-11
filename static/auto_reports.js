// 자동 보고서 page. Self-contained like alert_analysis.js; app.js helpers
// (renderMarkdown, enhanceRenderedContent) are used when present.
(() => {
    const REDTEAM_LABELS = {
        not_sent: "보내지 않음",
        send: "전송함",
        disabled: "꺼짐",
        queued: "전송함",
        dispatched: "전송함",
        skipped_no_token: "토큰 없음",
        skipped_not_live: "실데이터 아님",
        skipped_demo_result: "데모 결과",
        skipped_recursive_request: "평가 요청에서 온 분석",
        skipped_no_runner_url: "실행기 주소 없음",
        skipped_no_tools: "도구 미지정",
    };
    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const REVIEW_LABELS = {
        unreviewed: "검토 전",
        investigating: "추가 조사",
        confirmed: "확인됨",
        false_positive: "오탐",
    };
    const AI_LABELS = {
        pending: "AI 분석 대기",
        completed: "AI 분석 완료",
        failed: "AI 분석 실패",
        expired: "AI 분석 만료",
    };
    const WAITING_LABELS = {
        model_unavailable: "모델 꺼짐",
        rate_limit: "시간당 상한",
        queued: "다음 차례",
        retry: "재시도 예정",
    };
    const REASON_LABELS = {
        priority_P1: "우선순위 P1",
        priority_P2: "우선순위 P2",
        priority_P3: "우선순위 P3",
        priority_P4: "우선순위 P4",
        threat_intel_match: "위협 인텔리전스 일치",
    };
    const FACTOR_LABELS = {
        wazuh_rule_level: "Wazuh 룰 레벨",
        source_severity: "원본 심각도",
        asset_criticality: "자산 중요도",
        asset_exposure: "자산 노출도",
        asset_data_classification: "민감 데이터",
        asset_not_in_inventory: "자산 목록에 없음",
        threat_intel_match: "위협 인텔리전스 일치",
    };
    const VERDICT_LABELS = { malicious: "악성", suspicious: "의심", benign: "정상", unknown: "알 수 없음" };
    const ACTION_LABELS = {
        velociraptor_hunt: "Velociraptor 헌트",
        velociraptor_collection: "Velociraptor 수집",
        velociraptor_isolation: "호스트 격리",
        velociraptor_remediation: "복구 조치",
        suricata_rule: "Suricata 룰",
        suricata_rule_disable: "Suricata 룰 비활성화",
    };

    const formatDateTime = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? String(value || "—")
            : date.toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
    };
    const ago = (value) => {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "기록 없음";
        const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
        if (seconds < 90) return `${seconds}초 전`;
        if (seconds < 5400) return `${Math.round(seconds / 60)}분 전`;
        if (seconds < 129600) return `${Math.round(seconds / 3600)}시간 전`;
        return `${Math.round(seconds / 86400)}일 전`;
    };
    const band = (priority) => {
        const value = String(priority?.band || "").toUpperCase();
        if (!value) return `<span class="prio-chip prio-none">—</span>`;
        const score = priority?.score ?? "—";
        return `<span class="prio-chip prio-${escapeHtml(value.toLowerCase())}" title="우선순위 점수 ${escapeHtml(score)}점">${escapeHtml(value)}</span>`;
    };
    const reviewChip = (status) => `<span class="review-chip review-${escapeHtml(status || "unreviewed")}">${escapeHtml(REVIEW_LABELS[status] || "검토 전")}</span>`;
    const aiChip = (status, waiting) => {
        const reason = status === "pending" && WAITING_LABELS[waiting] ? ` · ${WAITING_LABELS[waiting]}` : "";
        return `<span class="ai-chip ai-${escapeHtml(status || "pending")}">${escapeHtml(AI_LABELS[status] || "AI 분석 대기")}${escapeHtml(reason)}</span>`;
    };
    const markdown = (value) => (typeof window.renderMarkdown === "function"
        ? window.renderMarkdown(value)
        : `<p>${escapeHtml(value).replaceAll("\n", "<br>")}</p>`);

    async function requestJson(url, options = {}) {
        const response = await fetch(url, options);
        let body = {};
        try { body = await response.json(); } catch { body = {}; }
        if (response.status === 401) {
            location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
            throw new Error("로그인이 필요합니다.");
        }
        if (!response.ok) {
            throw new Error(body.error || `요청 실패: ${response.status}`);
        }
        return body;
    }

    function notify(message) {
        if (typeof window.toast === "function") window.toast(message);
    }

    function init(root) {
        const csrf = root.dataset.csrf;
        const isAdmin = root.dataset.role === "admin";
        const form = root.querySelector("[data-filters]");
        const list = root.querySelector("[data-list]");
        const detail = root.querySelector("[data-detail]");
        let selectedId = new URLSearchParams(location.search).get("id") || "";
        let current = null;

        const post = (url, body) => requestJson(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
            body: JSON.stringify(body || {}),
        });

        function renderStatus(data) {
            const counts = data.counts || {};
            root.querySelectorAll("[data-count]").forEach((node) => {
                node.textContent = counts[node.dataset.count] ?? 0;
            });
            const settings = data.settings || {};
            const worker = data.worker || {};
            const state = root.querySelector("[data-worker-state]");
            const detailText = root.querySelector("[data-worker-detail]");
            if (!settings.enabled) {
                state.textContent = "꺼짐";
                detailText.textContent = "AUTO_ANALYSIS_ENABLED=false";
            } else if (worker.running) {
                state.textContent = "동작 중";
                const summary = worker.last_summary || {};
                const model = summary.model_available === false ? " · 모델 꺼짐" : "";
                detailText.textContent = `마지막 실행 ${ago(worker.last_cycle_at)}${model}`;
            } else {
                state.textContent = "멈춤";
                detailText.textContent = worker.last_cycle_at ? `마지막 실행 ${ago(worker.last_cycle_at)} · 작업기 컨테이너 확인` : "작업기가 아직 실행되지 않았습니다";
            }
            state.dataset.state = !settings.enabled ? "off" : (worker.running ? "on" : "stale");

            const bands = (settings.bands || []).join("·") || "P1·P2";
            root.querySelector("[data-policy]").textContent =
                `선정 기준: Wazuh 레벨 ${settings.min_level ?? 8} 이상 AND (우선순위 ${bands} 또는 위협 인텔리전스 일치) · `
                + `같은 룰·출발지·호스트는 ${Math.round((settings.group_seconds || 600) / 60)}분 안에 한 보고서로 묶음 · `
                + `AI 분석 시간당 최대 ${settings.max_ai_per_hour ?? 20}건 · `
                + ((settings.exclude_groups || []).includes("vulnerability-detector") ? "CVE 취약점 경보는 제외(호스트 화면에서 확인) · " : "")
                + `제안 조치는 자동 실행·자동 대기열 등록 없음 · 레드팀 전송 ${settings.forward_redteam ? "켜짐" : "꺼짐"}`;
            const runNow = root.querySelector("[data-run-now]");
            if (runNow) runNow.hidden = !(isAdmin && settings.enabled);
        }

        const SENSITIVE_LABELS = {
            credential: "자격증명", secret_config: "설정·비밀 파일", backup: "백업 파일",
            admin_login: "관리자·로그인", traversal: "경로 조작",
        };

        function renderList(reports, queryCategory = "") {
            root.querySelector("[data-list-count]").textContent = queryCategory
                ? `보고서 ${reports.length}건 · '${SENSITIVE_LABELS[queryCategory] || queryCategory}' 대상 포함`
                : `보고서 ${reports.length}건`;
            if (!reports.length) {
                list.innerHTML = `<div class="empty-state">조건에 맞는 보고서가 없습니다.</div>`;
                return;
            }
            list.innerHTML = reports.map((item) => {
                const repeat = Number(item.occurrences) > 1 ? `<span class="tag">반복 ${escapeHtml(item.occurrences)}건</span>` : "";
                const intel = Number(item.intel_matches) > 0 ? `<span class="tag tag-danger">CTI ${escapeHtml(item.intel_matches)}</span>` : "";
                const sensitive = (item.sensitive || []).map((key) =>
                    `<span class="tag" title="${escapeHtml((item.paths || []).slice(0, 5).join("\n"))}">${escapeHtml(SENSITIVE_LABELS[key] || key)}</span>`).join(" ");
                return `<button type="button" role="listitem" class="auto-report-item ${item.id === selectedId ? "selected" : ""}" data-report-id="${escapeHtml(item.id)}">
                    <span class="auto-report-item-top">${band(item.priority)} ${reviewChip(item.review_status)} ${aiChip(item.ai_status, item.ai_waiting)}</span>
                    <strong>${escapeHtml(item.title || "제목 없는 경보")}</strong>
                    <span class="auto-report-item-meta">${escapeHtml(item.host || "—")} · ${escapeHtml(item.source_ip || "출발지 없음")} · L${escapeHtml(item.level ?? "—")} ${repeat} ${intel} ${sensitive}</span>
                    <span class="auto-report-item-time">${escapeHtml(formatDateTime(item.alert_time || item.created_at))} · ${escapeHtml(item.id)}</span>
                </button>`;
            }).join("");
        }

        async function loadList() {
            const params = new URLSearchParams(new FormData(form));
            try {
                const data = await requestJson(`/api/auto-reports?${params.toString()}`);
                renderStatus(data);
                renderList(data.reports || [], data.query_category || "");
                if (!selectedId && data.reports?.length) selectedId = data.reports[0].id;
                const typing = detail.contains(document.activeElement) && document.activeElement.matches("textarea, select");
                const waitingForAi = current && current.id === selectedId && current.ai?.status === "pending";
                if (selectedId && (!current || current.id !== selectedId || (waitingForAi && !typing))) await loadDetail(selectedId);
            } catch (error) {
                list.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            }
        }

        function section(title, body, extraClass = "") {
            return `<section class="auto-report-section ${extraClass}"><h3>${escapeHtml(title)}</h3>${body}</section>`;
        }

        function table(headers, rows) {
            if (!rows.length) return "";
            return `<div class="data-table"><table class="report-table">
                <thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
                <tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody>
            </table></div>`;
        }

        function renderDetail(report) {
            current = report;
            const alert = report.alert || {};
            const priority = report.priority || {};
            const review = report.review || {};
            const ai = report.ai || {};
            const group = report.group || {};
            const evidence = report.evidence || {};
            const reasons = ((report.selection || {}).reasons || []).map((r) => `<span class="tag">${escapeHtml(REASON_LABELS[r] || r)}</span>`).join(" ");

            const alertRows = [
                ["경보 ID", `<code>${escapeHtml(alert.id)}</code>`],
                ["발생 시각", escapeHtml(formatDateTime(alert.time))],
                ["룰", escapeHtml(`${alert.rule_id || ""} ${alert.title || ""}`.trim() || "—")],
                ["레벨", escapeHtml(alert.level ?? "—")],
                ["호스트", escapeHtml(alert.host || "—")],
                ["출발지 IP", escapeHtml(alert.source_ip || "—")],
                ["MITRE ATT&CK", escapeHtml(alert.mitre || "—")],
                ["요약", escapeHtml(alert.summary || "—")],
            ];
            const repeat = Number(group.occurrences) > 1
                ? `<p class="auto-report-repeat">같은 룰·출발지·호스트로 <strong>${escapeHtml(group.occurrences)}건</strong> 반복 발생 (${escapeHtml(formatDateTime(group.first_seen))} ~ ${escapeHtml(formatDateTime(group.last_seen))})</p>`
                : "";

            const factorRows = (priority.factors || []).map((f) => [
                escapeHtml(FACTOR_LABELS[f.factor] || f.factor),
                escapeHtml(Array.isArray(f.value) ? f.value.join(", ") : (f.value ?? "—")),
                `<strong>+${escapeHtml(f.points ?? 0)}</strong>`,
            ]);
            const assetRows = (report.assets || []).map((a) => [
                escapeHtml(a.hostname || a.id || "—"),
                escapeHtml(a.criticality || "—"),
                escapeHtml(a.exposure || "—"),
                escapeHtml(a.business_service || "—"),
            ]);
            const intelRows = (report.threat_intelligence || []).map((row) => [
                `<code>${escapeHtml(row.value || "—")}</code>`,
                escapeHtml(VERDICT_LABELS[row.verdict] || row.verdict || "—"),
                escapeHtml(row.confidence ?? "—"),
                escapeHtml(row.feed || "—"),
                row.on_trigger ? "경보 자체" : "맥락에서만",
                row.expired ? "만료" : "유효",
            ]);

            let aiBody;
            if (ai.status === "completed") {
                const feedbackNote = Number(ai.feedback_used) > 0 ? ` · 과거 판정 ${escapeHtml(ai.feedback_used)}건 참고` : "";
                aiBody = `<p class="muted">모델 ${escapeHtml(ai.model || "—")} · 분석 ID <code>${escapeHtml(ai.analysis_id || "—")}</code> · ${escapeHtml(formatDateTime(ai.completed_at))}${feedbackNote}</p>
                    <div class="markdown-body" data-ai-answer>${markdown(ai.answer || "반환된 분석 결과가 없습니다.")}</div>
                    <div class="auto-report-xai" data-xai hidden></div>
                    <div class="auto-report-redteam" data-redteam hidden></div>`;
            } else {
                const waiting = WAITING_LABELS[ai.waiting_reason] ? ` (${WAITING_LABELS[ai.waiting_reason]})` : "";
                aiBody = `<div class="empty-state auto-report-ai-waiting">${escapeHtml(AI_LABELS[ai.status] || "AI 분석 대기")}${escapeHtml(waiting)}
                    <br><small>위의 경보·우선순위·자산·위협 인텔리전스는 모델 없이 계산한 사실입니다.${ai.last_error ? ` 마지막 오류: ${escapeHtml(ai.last_error)}` : ""}</small></div>`;
            }

            const actions = (ai.suggested_actions || []).map((action, index) => {
                const suricata = String(action.type || "").startsWith("suricata_");
                const control = suricata
                    ? `<a class="button secondary small" href="/rules">Suricata 룰 화면에서 검증</a>`
                    : `<button class="button secondary small" type="button" data-queue-action="${index}">승인 대기열에 올리기</button>`;
                return `<div class="output-item">
                    <div class="action-meta"><span class="tag">${escapeHtml(ACTION_LABELS[action.type] || action.type)}</span><span class="tag">위험도 ${escapeHtml(action.risk || "unknown")}</span></div>
                    <p><strong>${escapeHtml(action.title || "제목 없음")}</strong></p>
                    <p>${escapeHtml(action.summary || "")}</p>
                    <div class="auto-report-action-controls">${control}</div>
                </div>`;
            }).join("");

            const evidenceRows = (evidence.index || []).map((row) => [
                `<code>${escapeHtml(row.evidence_id || "—")}</code>`,
                escapeHtml(row.timestamp ? formatDateTime(row.timestamp) : "—"),
                escapeHtml(row.host || "—"),
                escapeHtml(row.rule || "—"),
                `<span class="report-log">${escapeHtml(row.log || "")}</span>`,
            ]);

            const history = (review.history || []).slice().reverse().map((entry) => `<li>${escapeHtml(formatDateTime(entry.at))} · ${escapeHtml(entry.reviewer || "—")} · ${reviewChip(entry.status)}${entry.note ? `<br><span class="muted">${escapeHtml(entry.note)}</span>` : ""}</li>`).join("");

            detail.innerHTML = `
                <div class="auto-report-head">
                    <div>
                        <p class="panel-kicker">${escapeHtml(report.id)} · ${escapeHtml(formatDateTime(report.created_at))} 작성</p>
                        <h2>${band(priority)} ${escapeHtml(alert.title || "제목 없는 경보")}</h2>
                        <p class="auto-report-reasons">선정 이유 ${reasons || "—"} · 점수 ${escapeHtml(priority.score ?? "—")}점</p>
                    </div>
                    <div class="auto-report-head-actions">
                        <a class="button secondary small" href="/api/auto-reports/${encodeURIComponent(report.id)}/markdown">마크다운 내려받기</a>
                        <button class="button secondary small" type="button" data-print>인쇄 · PDF</button>
                        <a class="button secondary small" href="/alerts/${encodeURIComponent(alert.id || "")}">경보 열기</a>
                    </div>
                </div>
                <div class="auto-report-notice">${reviewChip(review.status)} ${aiChip(ai.status, ai.waiting_reason)} <span>AI 초안입니다. 분석가가 검토하기 전에는 확인된 사실로 공유하지 마세요.</span></div>
                ${section("1. 경보", table(["항목", "값"], alertRows) + repeat)}
                ${section("2. 우선순위 근거", `<p class="muted">코드로 계산한 점수이며 모델이 바꿀 수 없습니다.</p>${table(["요인", "값", "점수"], factorRows) || "<p class=\"muted\">요인 정보 없음</p>"}`)}
                ${section("3. 자산", table(["자산", "중요도", "노출도", "서비스"], assetRows) || `<p class="muted">자산 목록에서 찾은 기록이 없습니다. 자산 중요도는 알 수 없습니다.</p>`)}
                ${section("4. 위협 인텔리전스", intelRows.length ? `${table(["지표", "판정", "신뢰도", "출처", "위치", "상태"], intelRows)}<p class="muted">지표 일치는 외부 맥락이며 침해를 증명하지 않습니다.</p>` : `<p class="muted">일치한 지표가 없습니다. 일치가 없다고 안전하다는 뜻은 아닙니다.</p>`)}
                ${section("5. AI 분석", aiBody)}
                ${section("6. 제안 조치 (자동 실행 안 됨 · 승인 필요)", actions || `<p class="muted">제안된 조치가 없습니다.</p>`)}
                ${section("7. 증거 목록", evidenceRows.length ? `<details class="auto-report-evidence"><summary>증거 ${escapeHtml(evidenceRows.length)}건${Number(evidence.total) > evidenceRows.length ? ` (전체 ${escapeHtml(evidence.total)}건)` : ""} 보기</summary>${table(["ID", "시각", "호스트", "룰", "내용"], evidenceRows)}</details>` : `<p class="muted">저장된 증거 목록이 없습니다.</p>`)}
                ${section("8. 분석가 검토", `
                    <form class="auto-report-review" data-review-form>
                        <label>판정
                            <select name="status">
                                ${Object.entries(REVIEW_LABELS).map(([value, label]) => `<option value="${value}" ${value === (review.status || "unreviewed") ? "selected" : ""}>${label}</option>`).join("")}
                            </select>
                        </label>
                        <label class="auto-report-note">메모<textarea name="note" rows="2" maxlength="2000" placeholder="판단 근거, 추가로 확인할 것">${escapeHtml(review.note || "")}</textarea></label>
                        <button class="button primary small" type="submit">검토 저장</button>
                    </form>
                    <p class="muted auto-report-feedback-hint">확인됨·오탐 판정은 같은 룰·호스트 또는 출발지 경보의 다음 분석에 참고 맥락으로 쓰입니다 (근거로는 쓰이지 않음).</p>
                    ${history ? `<ol class="auto-report-history">${history}</ol>` : ""}`, "no-print-controls")}
                <p class="auto-report-trace muted">추적 정보: 증거 스키마 <code>${escapeHtml(evidence.bundle_schema || "—")}</code> · prompt <code>${escapeHtml(String(ai.hashes?.prompt_sha256 || "—").slice(0, 16))}</code> · bundle <code>${escapeHtml(String(ai.hashes?.bundle_sha256 || "—").slice(0, 16))}</code> · 레드팀 ${escapeHtml(REDTEAM_LABELS[report.redteam || "not_sent"] || report.redteam)}</p>`;

            window.HawkiXai?.render(detail.querySelector("[data-xai]"), ai.explanation, { queries: ai.queries });
            // Only shown once something was sent (AUTO_ANALYSIS_FORWARD_REDTEAM=true).
            if (ai.analysis_id && report.redteam && report.redteam !== "not_sent") {
                window.HawkiRedteam?.render(detail.querySelector("[data-redteam]"), { analysisId: ai.analysis_id, decision: report.redteam });
            }
            const answer = detail.querySelector("[data-ai-answer]");
            if (answer && typeof window.enhanceRenderedContent === "function") window.enhanceRenderedContent(answer);
            list.querySelectorAll("[data-report-id]").forEach((node) => node.classList.toggle("selected", node.dataset.reportId === report.id));
        }

        async function loadDetail(reportId) {
            selectedId = reportId;
            const url = new URL(location.href);
            url.searchParams.set("id", reportId);
            history.replaceState(null, "", url);
            try {
                const data = await requestJson(`/api/auto-reports/${encodeURIComponent(reportId)}`);
                renderDetail(data.report);
            } catch (error) {
                current = null;
                detail.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            }
        }

        list.addEventListener("click", (event) => {
            const item = event.target.closest("[data-report-id]");
            if (item) loadDetail(item.dataset.reportId);
        });
        form.addEventListener("change", () => loadList());
        form.addEventListener("submit", (event) => { event.preventDefault(); loadList(); });
        form.querySelector("input[name=q]").addEventListener("input", () => {
            clearTimeout(form._timer);
            form._timer = setTimeout(loadList, 300);
        });
        root.querySelectorAll("[data-quick-filter]").forEach((button) => {
            button.addEventListener("click", () => {
                const [name, value] = button.dataset.quickFilter.split("=");
                form.reset();
                form.elements[name].value = value;
                loadList();
            });
        });
        root.querySelector("[data-refresh]").addEventListener("click", () => { current = null; loadList(); });
        root.querySelector("[data-run-now]")?.addEventListener("click", async (event) => {
            const button = event.currentTarget;
            button.disabled = true;
            try {
                await post("/api/auto-reports/run");
                notify("자동 분석을 한 번 실행했습니다. 잠시 후 새로고침하세요.");
                setTimeout(() => { current = null; loadList(); }, 5000);
            } catch (error) {
                notify(error.message);
            } finally {
                button.disabled = false;
            }
        });

        detail.addEventListener("click", async (event) => {
            if (event.target.closest("[data-print]")) {
                detail.querySelectorAll("details").forEach((node) => { node.open = true; });
                window.print();
                return;
            }
            const queue = event.target.closest("[data-queue-action]");
            if (queue && current) {
                const action = (current.ai?.suggested_actions || [])[Number(queue.dataset.queueAction)];
                if (!action) return;
                queue.disabled = true;
                try {
                    const data = await post("/api/actions/queue", { action, source: `auto_report:${current.id}` });
                    queue.outerHTML = `<span class="tag">대기열 등록됨 · ${escapeHtml(data.action?.id || "")}</span>`;
                    notify("승인 대기열에 올렸습니다. 승인자가 결정해야 실행됩니다.");
                } catch (error) {
                    queue.disabled = false;
                    notify(error.message);
                }
            }
        });

        detail.addEventListener("submit", async (event) => {
            const reviewForm = event.target.closest("[data-review-form]");
            if (!reviewForm || !current) return;
            event.preventDefault();
            const values = Object.fromEntries(new FormData(reviewForm));
            try {
                const data = await post(`/api/auto-reports/${encodeURIComponent(current.id)}/review`, values);
                renderDetail(data.report);
                notify(`검토 상태를 '${REVIEW_LABELS[values.status] || values.status}'(으)로 저장했습니다.`);
                current = data.report;
                const listData = await requestJson(`/api/auto-reports?${new URLSearchParams(new FormData(form)).toString()}`);
                renderStatus(listData);
                renderList(listData.reports || []);
            } catch (error) {
                notify(error.message);
            }
        });

        // Ctrl+P prints the evidence too, not only the summary line.
        window.addEventListener("beforeprint", () => {
            detail.querySelectorAll("details").forEach((node) => { node.open = true; });
        });

        loadList();
        setInterval(() => { if (!document.hidden) loadList(); }, 60000);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const root = document.getElementById("auto-report-root");
        if (root) init(root);
    });
})();
