// 레드팀 평가 panel, shared by the alert page and the 자동 보고서 page.
// It follows one analysis through /api/redteam/status/<analysis_id>:
// sending -> refused (with the reason) or accepted -> the runner's job state.
((scope) => {
    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    // What HAW-KI decided before sending (forwarding_decision).
    const DECISION = {
        send: ["실행기로 전송", "rt-info"],
        queued: ["실행기로 전송", "rt-info"],
        disabled: ["자동평가 꺼짐 (REDTEAM_AUTO_EVAL_ENABLED=false)", "rt-muted"],
        not_sent: ["보내지 않음", "rt-muted"],
        skipped_no_token: ["토큰 없음 (REDTEAM_RUNNER_TOKEN)", "rt-warn"],
        skipped_no_runner_url: ["실행기 주소 없음", "rt-warn"],
        skipped_no_tools: ["평가 도구 미지정", "rt-warn"],
        skipped_not_live: ["실데이터 경보가 아니라 보내지 않음", "rt-muted"],
        skipped_demo_result: ["데모 결과라 보내지 않음", "rt-muted"],
        skipped_recursive_request: ["평가 요청에서 온 분석이라 보내지 않음", "rt-muted"],
    };
    // The runner's job states; unknown values are shown as they are.
    const JOB_STATE = {
        queued: "대기", pending: "대기", accepted: "접수", created: "접수",
        running: "평가 중", in_progress: "평가 중", started: "평가 중",
        completed: "완료", complete: "완료", done: "완료", finished: "완료", succeeded: "완료", success: "완료",
        passed: "통과", failed: "실패", error: "오류", cancelled: "취소", canceled: "취소", timeout: "시간 초과",
    };
    const TERMINAL = new Set(["completed", "complete", "done", "finished", "succeeded", "success", "passed", "failed", "error", "cancelled", "canceled", "timeout"]);
    const REFUSAL = {
        400: "실행기가 본문 형식을 거부함 (400)",
        401: "토큰이 맞지 않음 (401)",
        403: "권한 없음 (403)",
        404: "실행기 경로 없음 (404)",
        413: "본문이 너무 큼 (413)",
        422: "본문 검증 실패 (422)",
    };
    const SUMMARY_KEYS = [
        ["passed", "통과"], ["failed", "실패"], ["errors", "오류"], ["total", "전체"],
        ["pass_rate", "통과율"], ["score", "점수"], ["successes", "성공"], ["failures", "실패"],
    ];

    const when = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    };
    const chip = (label, cls) => `<span class="rt-chip ${cls}">${escapeHtml(label)}</span>`;

    const CHECK_STATUS = {
        passed: ["통과", "rt-ok"], failed: ["실패", "rt-bad"], error: ["실행 오류", "rt-bad"],
        warning: ["검토 경고", "rt-warn"], not_applicable: ["해당 없음", "rt-muted"],
        not_verified: ["검증 불가", "rt-warn"], not_available: ["결과 없음", "rt-muted"],
    };
    const CATEGORIES = {
        "functional-control": "정상 분석 대조군", "direct-prompt-injection": "직접 프롬프트 주입",
        "sensitive-information-disclosure": "민감정보 유출", "encoding-bypass": "인코딩 우회",
        "excessive-agency": "권한·승인 우회", "identifier-hallucination": "근거 없는 식별자",
    };
    function checkRows(value) {
        return (Array.isArray(value?.checks) ? value.checks : []).slice(0, 500)
            .filter((row) => row && Object.hasOwn(CHECK_STATUS, row.status)).map((row) => ({
                ...row, assertion: String(row.assertion || "Evaluation").slice(0, 160),
                name_ko: String(row.name_ko || row.assertion || "검사 항목").slice(0, 160),
                description_ko: String(row.description_ko || "검사 설명이 아직 제공되지 않았습니다").slice(0, 1000),
                reason_ko: String(row.reason_ko || "한글 이유 없음 · 원문 참고").slice(0, 1000),
                reason: String(row.reason || "").slice(0, 800),
            }));
    }
    function checkDetailsHtml(value) {
        const rows = checkRows(value);
        if (!rows.length) {
            const messages = {
                report_missing: "결과 파일 없음",
                report_unreadable: "결과 파일 읽기 실패 (권한·형식 확인)",
                pending: "평가 중",
            };
            return `<p class="muted rt-tool-note">${escapeHtml(messages[value?.detail_availability] || "검사별 상세 결과 없음")} · 통과를 뜻하지 않습니다.</p>`;
        }
        const counts = Object.fromEntries(Object.keys(CHECK_STATUS).map((key) => [key, rows.filter((row) => row.status === key).length]));
        const description = Object.entries(counts).filter(([, count]) => count)
            .map(([key, count]) => `${CHECK_STATUS[key][0]} ${count}`).join(" · ");
        function item(row) {
            const [label, cls] = CHECK_STATUS[row.status];
            const caseName = CATEGORIES[row.category] || row.case_name;
            const context = row.case_index ? `사례 ${row.case_index}${caseName ? " · " + caseName : ""}` : "";
            return `<li class="rt-check rt-check-${row.status}">
                <p>${chip(label, cls)} <strong>${escapeHtml(row.name_ko)}</strong> <code>${escapeHtml(row.assertion)}</code></p>
                ${context ? `<p class="muted rt-check-context">${escapeHtml(context)}</p>` : ""}
                ${row.detector ? `<p class="muted">검출기: ${escapeHtml(row.detector)}</p>` : ""}
                <p class="rt-check-description"><strong>검사 내용:</strong> ${escapeHtml(row.description_ko)}</p>
                <p class="rt-check-reason"><strong>판정 이유:</strong> ${escapeHtml(row.reason_ko)}</p>
                ${row.advisory ? '<p class="muted">참고 지표</p>' : ""}
                ${row.reason ? `<details class="rt-check-original"><summary>기록된 이유 원문</summary><p>${escapeHtml(row.reason)}</p></details>` : ''}
            </li>`;
        }
        const important = rows.filter((row) => ["failed", "error", "warning"].includes(row.status));
        const others = rows.filter((row) => !["failed", "error", "warning"].includes(row.status));
        return `<section class="rt-check-results" aria-label="검사 항목별 상세 결과">
            <p class="rt-check-counts">검사 항목 ${rows.length}개${value?.details_truncated ? " (일부 표시)" : ""} · ${escapeHtml(description)}</p>
            <p class="muted rt-tool-note">해당 없음·검증 불가는 통과에 넣지 않음</p>
            ${important.length ? `<p><strong>실패·오류·검토 경고</strong></p><ul class="rt-check-list">${important.map(item).join("")}</ul>` : ""}
            ${others.length ? `<details class="rt-check-all"><summary>나머지 검사별 상세 결과 ${others.length}개 보기</summary><ul class="rt-check-list">${others.map(item).join("")}</ul></details>` : ""}
        </section>`;
    }

    function jobState(runner) {
        const job = runner && typeof runner.job === "object" ? runner.job : {};
        return String(runner?.status || runner?.state || job.status || job.state || "").toLowerCase();
    }

    // Per-tool verdicts from the runner (job.tool_results.<tool>). A job can
    // be "completed" while a tool inside it failed, so the verdict comes from
    // here, not from the job state.
    const TOOL_STATE = {
        passed: ["통과", "rt-ok"], success: ["통과", "rt-ok"], succeeded: ["통과", "rt-ok"], completed: ["실행 완료", "rt-muted"],
        failed: ["실패", "rt-bad"], error: ["오류", "rt-bad"], errored: ["오류", "rt-bad"], timeout: ["시간 초과", "rt-bad"],
        running: ["평가 중", "rt-info"], queued: ["대기", "rt-info"], pending: ["대기", "rt-info"], skipped: ["건너뜀", "rt-muted"],
    };

    function toolResults(runner) {
        const job = runner && typeof runner.job === "object" ? runner.job : {};
        const source = job.tool_results || runner?.tool_results || {};
        if (!source || typeof source !== "object" || Array.isArray(source)) return [];
        return Object.entries(source).filter(([, value]) => value && typeof value === "object").map(([name, value]) => {
            const stats = value.stats && typeof value.stats === "object" ? value.stats : {};
            const num = (key) => (typeof stats[key] === "number" ? stats[key] : null);
            const tokens = stats.tokenUsage && typeof stats.tokenUsage.total === "number" ? stats.tokenUsage.total : null;
            let state = String(value.status || "").toLowerCase();
            // Counts outrank a loose status word.
            if ((num("errors") || 0) > 0) state = "error";
            else if ((num("failures") || 0) > 0) state = "failed";
            const failed = (Array.isArray(value.failures) ? value.failures : [])
                .filter((item) => item && typeof item === "object")
                .slice(0, 10)
                .map((item) => ({
                    assertion: String(item.assertion || item.name || item.metric || "검사 항목").slice(0, 120),
                    reason: String(item.reason || item.message || "").slice(0, 400),
                }));
            return {
                name, state,
                successes: num("successes"), failures: num("failures"), errors: num("errors"),
                exitCode: value.exit_code, durationMs: num("durationMs"), tokens,
                artifacts: Array.isArray(value.artifacts) ? value.artifacts : [],
                mode: String(value.mode || ""),
                failureSummary: typeof value.failure_summary === "string" ? value.failure_summary.slice(0, 400) : "",
                failed,
                details: value,
                // Older jobs predate failure_summary/failures; the runner does not backfill them.
                reasonsReported: "failure_summary" in value || Array.isArray(value.failures),
            };
        });
    }

    function overall(tools) {
        if (!tools.length) return null;
        if (tools.some((tool) => ["error", "errored", "timeout"].includes(tool.state))) return ["검사 오류", "rt-bad"];
        if (tools.some((tool) => tool.state === "failed")) return ["검사 실패", "rt-bad"];
        if (tools.some((tool) => ["running", "queued", "pending"].includes(tool.state))) return null;
        if (tools.every((tool) => (TOOL_STATE[tool.state] || [])[1] === "rt-ok" || tool.state === "skipped")) return ["검사 통과", "rt-ok"];
        return null;
    }

    function toolRows(tools) {
        return tools.map((tool) => {
            const [label, cls] = TOOL_STATE[tool.state] || [tool.state || "상태 미확인", "rt-muted"];
            const parts = [];
            if (tool.successes !== null) parts.push(`분석 결과 통과 ${tool.successes}건`);
            if (tool.failures !== null) parts.push(`분석 결과 실패 ${tool.failures}건`);
            if (tool.errors !== null) parts.push(`오류 ${tool.errors}`);
            if (tool.durationMs !== null) parts.push(`${(tool.durationMs / 1000).toFixed(tool.durationMs < 1000 ? 2 : 1)}초`);
            if (tool.exitCode !== undefined && tool.exitCode !== null) parts.push(`종료 코드 ${escapeHtml(tool.exitCode)}`);
            const warn = tool.mode === "saved_result"
                ? `<p class="muted rt-tool-note">저장된 답변 채점 · 모델 재호출 없음</p>`
                : (tool.tokens === 0
                    ? "" : "");
            const reasons = checkRows(tool.details).length ? "" : tool.failed.length
                ? `<ul class="rt-failures">${tool.failed.map((item) => `<li><strong>${escapeHtml(item.assertion)}</strong>${item.reason ? ` · ${escapeHtml(item.reason)}` : ""}</li>`).join("")}</ul>`
                : (tool.failureSummary ? `<p class="rt-failure-summary">${escapeHtml(tool.failureSummary)}</p>` : "");
            const noReasons = tool.state === "failed" && !tool.reasonsReported
                ? `<p class="muted rt-tool-note">실패 이유 기록 없음 (이전 작업)</p>` : "";
            const files = tool.artifacts.length ? `<p class="muted rt-tool-note">실행기 결과 파일: ${tool.artifacts.map(escapeHtml).join(", ")}</p>` : "";
            return `<div class="rt-tool"><p><strong>${escapeHtml(tool.name)}</strong> ${chip(label, cls)} <span class="muted">${parts.join(" · ")}</span></p>${reasons}${noReasons}${warn}${checkDetailsHtml(tool.details)}${files}</div>`;
        }).join("");
    }

    function summary(runner) {
        const job = runner && typeof runner.job === "object" ? runner.job : {};
        const candidates = [runner?.summary, runner?.result?.summary, runner?.results?.summary, runner?.stats, job.summary, runner?.result, job.result];
        const source = candidates.find((value) => value && typeof value === "object" && !Array.isArray(value)) || {};
        return SUMMARY_KEYS
            .filter(([key]) => typeof source[key] === "number" || (typeof source[key] === "string" && source[key].length < 20))
            .map(([key, label]) => `${label} ${escapeHtml(source[key])}`);
    }

    function draw(container, decision, data, caption) {
        const [decisionLabel, decisionClass] = DECISION[decision] || [decision || "알 수 없음", "rt-muted"];
        let body = "";
        let state = "";
        if (decision !== "send" && decision !== "queued") {
            body = `<p class="muted">이 분석은 레드팀 실행기로 보내지 않았습니다.</p>`;
        } else if (!data) {
            body = `<p class="muted">상태를 확인하는 중…</p>`;
        } else if (data.stage === "sending") {
            body = `<p>${chip("응답 대기", "rt-info")} </p>`;
        } else if (data.stage === "refused") {
            const reason = REFUSAL[data.status_code] || data.error || (data.status_code ? `HTTP ${data.status_code}` : "보내지 못함");
            body = `<p>${chip("접수 안 됨", "rt-bad")} ${escapeHtml(reason)}</p>
                ${data.error && REFUSAL[data.status_code] ? `<p class="muted">${escapeHtml(data.error)}</p>` : ""}`;
        } else {
            state = jobState(data.runner);
            const tools = toolResults(data.runner);
            const verdict = TERMINAL.has(state) ? overall(tools) : null;
            const rows = tools.length ? [] : summary(data.runner);
            const finished = TERMINAL.has(state) && !["failed", "error", "timeout"].includes(state);
            const stateLabel = finished ? "평가 끝남" : (JOB_STATE[state] || state || (data.runner_status === 404 ? "실행기에 작업 없음" : "상태 미확인"));
            const stateClass = ["failed", "error", "timeout"].includes(state) ? "rt-bad" : (TERMINAL.has(state) ? "rt-muted" : "rt-info");
            const note = TERMINAL.has(state)
                ? (verdict && verdict[1] === "rt-bad"
                    ? (tools.some((tool) => tool.failed.length || tool.failureSummary)
                        ? "위 검사 항목 실패"
                        : "검사 도구 중 실패 있음")
                    : "실행기가 평가를 끝냈습니다.")
                : '접수됨 · 결과 대기 (통과 아님)';
            body = `<p>${chip("접수됨 (202)", "rt-ok")} ${chip(stateLabel, stateClass)} ${verdict ? chip(verdict[0], verdict[1]) : ""} <span class="muted">작업 ${escapeHtml(data.job_id || "—")} · ${escapeHtml(when(data.timestamp))}</span></p>
                ${toolRows(tools)}
                ${rows.length ? `<p class="rt-summary">${rows.join(" · ")}</p>` : ""}
                ${data.runner_error ? `<p class="muted">실행기 조회 실패: ${escapeHtml(data.runner_error)}</p>` : ""}
                ${data.runner ? `<details class="rt-raw"><summary>실행기 응답 원문</summary><pre>${escapeHtml(JSON.stringify(data.runner, null, 2))}</pre></details>` : ""}
                <p class="muted rt-note">${escapeHtml(note)}</p>`;
        }
        container.hidden = false;
        container.innerHTML = `
            <div class="rt-panel">
                <div class="rt-head">
                    <div><p class="panel-kicker">${escapeHtml(caption || "AI 판단 견고성 검증")}</p><h3>레드팀 평가</h3></div>
                    <div>${chip(decisionLabel, decisionClass)} <button type="button" class="button secondary small" data-rt-refresh>새로고침</button></div>
                </div>
                ${body}
            </div>`;
        return state;
    }

    // Polls every 5 s while the evaluation is moving, for up to 10 minutes.
    function render(container, { analysisId, decision, caption = "" }) {
        if (!container) return;
        if (!analysisId) {
            container.hidden = true;
            return;
        }
        let timer = null;
        let rounds = 0;
        const stop = () => { if (timer) clearTimeout(timer); timer = null; };
        const tick = async () => {
            stop();
            let data = null;
            try {
                const response = await fetch(`/api/redteam/status/${encodeURIComponent(analysisId)}`, { headers: { Accept: "application/json" } });
                data = await response.json().catch(() => null);
                if (!response.ok) data = { stage: "refused", error: data?.error || `HTTP ${response.status}` };
            } catch (error) {
                data = { stage: "refused", error: error.message };
            }
            if (container.hidden) return;
            const state = draw(container, decision, data, caption);
            container.querySelector("[data-rt-refresh]")?.addEventListener("click", () => { rounds = 0; tick(); });
            rounds += 1;
            const moving = data && (data.stage === "sending" || (data.stage === "accepted" && !TERMINAL.has(state)));
            if (moving && rounds < 120 && !container.hidden && document.body.contains(container)) timer = setTimeout(tick, 5000);
        };
        draw(container, decision, null, caption);
        if (decision === "send" || decision === "queued") tick();
    }

    const api = { render, DECISION, JOB_STATE, toolResults, toolRows, overall, checkRows, checkDetailsHtml };
    if (typeof module !== "undefined" && module.exports) module.exports = api;
    else scope.HawkiRedteam = api;
})(typeof window === "undefined" ? globalThis : window);
