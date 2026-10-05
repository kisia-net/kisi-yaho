// 레드팀 평가 panel, shared by the alert page and the 자동 보고서 page.
// It follows one analysis through /api/redteam/status/<analysis_id>:
// sending -> refused (with the reason) or accepted -> the runner's job state.
(() => {
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

    function jobState(runner) {
        const job = runner && typeof runner.job === "object" ? runner.job : {};
        return String(runner?.status || runner?.state || job.status || job.state || "").toLowerCase();
    }

    // Per-tool verdicts from the runner (job.tool_results.<tool>). A job can
    // be "completed" while a tool inside it failed, so the verdict comes from
    // here, not from the job state.
    const TOOL_STATE = {
        passed: ["통과", "rt-ok"], success: ["통과", "rt-ok"], succeeded: ["통과", "rt-ok"], completed: ["통과", "rt-ok"],
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
            if ((num("failures") || 0) > 0) state = "failed";
            else if ((num("errors") || 0) > 0) state = "error";
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
                // Older jobs predate failure_summary/failures; the runner does not backfill them.
                reasonsReported: "failure_summary" in value || Array.isArray(value.failures),
            };
        });
    }

    function overall(tools) {
        if (!tools.length) return null;
        if (tools.some((tool) => tool.state === "failed")) return ["검사 실패", "rt-bad"];
        if (tools.some((tool) => ["error", "errored", "timeout"].includes(tool.state))) return ["검사 오류", "rt-bad"];
        if (tools.some((tool) => ["running", "queued", "pending"].includes(tool.state))) return null;
        if (tools.every((tool) => (TOOL_STATE[tool.state] || [])[1] === "rt-ok" || tool.state === "skipped")) return ["검사 통과", "rt-ok"];
        return null;
    }

    function toolRows(tools) {
        return tools.map((tool) => {
            const [label, cls] = TOOL_STATE[tool.state] || [tool.state || "상태 미확인", "rt-muted"];
            const parts = [];
            if (tool.successes !== null) parts.push(`성공 ${tool.successes}`);
            if (tool.failures !== null) parts.push(`실패 ${tool.failures}`);
            if (tool.errors !== null) parts.push(`오류 ${tool.errors}`);
            if (tool.durationMs !== null) parts.push(`${(tool.durationMs / 1000).toFixed(tool.durationMs < 1000 ? 2 : 1)}초`);
            if (tool.exitCode !== undefined && tool.exitCode !== null) parts.push(`종료 코드 ${escapeHtml(tool.exitCode)}`);
            const warn = tool.mode === "saved_result"
                ? `<p class="muted rt-tool-note">저장된 분석 결과 채점 · 모델 재호출 없음</p>`
                : (tool.tokens === 0
                    ? `<p class="muted rt-tool-note">모델 토큰 사용 0 · 모델을 다시 부르지 않는 저장 결과 채점이면 정상입니다.</p>` : "");
            const reasons = tool.failed.length
                ? `<ul class="rt-failures">${tool.failed.map((item) => `<li><strong>${escapeHtml(item.assertion)}</strong>${item.reason ? ` · ${escapeHtml(item.reason)}` : ""}</li>`).join("")}</ul>`
                : (tool.failureSummary ? `<p class="rt-failure-summary">${escapeHtml(tool.failureSummary)}</p>` : "");
            const noReasons = tool.state === "failed" && !tool.reasonsReported
                ? `<p class="muted rt-tool-note">이 작업은 실패 이유를 함께 보내기 전에 평가되어, 이유가 기록되어 있지 않습니다.</p>` : "";
            const files = tool.artifacts.length ? `<p class="muted rt-tool-note">실행기 결과 파일: ${tool.artifacts.map(escapeHtml).join(", ")}</p>` : "";
            return `<div class="rt-tool"><p><strong>${escapeHtml(tool.name)}</strong> ${chip(label, cls)} <span class="muted">${parts.join(" · ")}</span></p>${reasons}${noReasons}${warn}${files}</div>`;
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
            body = `<p>${chip("응답 대기", "rt-info")} 실행기 응답을 기다리는 중입니다. 보통 몇 초 안에 접수됩니다.</p>`;
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
                        ? "실행기가 평가를 끝냈고, 위에 표시된 검사 항목이 실패했습니다."
                        : "실행기가 평가를 끝냈고, 검사 도구 중 실패가 있습니다. 자세한 내용은 실행기의 결과 파일에 있습니다.")
                    : "실행기가 평가를 끝냈습니다.")
                : '202는 "접수"이며 검사 통과를 뜻하지 않습니다. 결과는 실행기가 평가를 마친 뒤 이 자리에 나타납니다.';
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

    window.HawkiRedteam = { render, DECISION, JOB_STATE, toolResults, overall };
})();
