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

    function summary(runner) {
        const job = runner && typeof runner.job === "object" ? runner.job : {};
        const candidates = [runner?.summary, runner?.result?.summary, runner?.results?.summary, runner?.stats, job.summary, runner?.result, job.result];
        const source = candidates.find((value) => value && typeof value === "object" && !Array.isArray(value)) || {};
        return SUMMARY_KEYS
            .filter(([key]) => typeof source[key] === "number" || (typeof source[key] === "string" && source[key].length < 20))
            .map(([key, label]) => `${label} ${escapeHtml(source[key])}`);
    }

    function draw(container, decision, data) {
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
            const rows = summary(data.runner);
            const stateLabel = JOB_STATE[state] || state || (data.runner_status === 404 ? "실행기에 작업 없음" : "상태 미확인");
            const stateClass = ["failed", "error", "timeout"].includes(state) ? "rt-bad" : (TERMINAL.has(state) ? "rt-ok" : "rt-info");
            body = `<p>${chip("접수됨 (202)", "rt-ok")} ${chip(stateLabel, stateClass)} <span class="muted">작업 ${escapeHtml(data.job_id || "—")} · ${escapeHtml(when(data.timestamp))}</span></p>
                ${rows.length ? `<p class="rt-summary">${rows.join(" · ")}</p>` : ""}
                ${data.runner_error ? `<p class="muted">실행기 조회 실패: ${escapeHtml(data.runner_error)}</p>` : ""}
                ${data.runner ? `<details class="rt-raw"><summary>실행기 응답 원문</summary><pre>${escapeHtml(JSON.stringify(data.runner, null, 2))}</pre></details>` : ""}
                <p class="muted rt-note">202는 "접수"이며 검사 통과를 뜻하지 않습니다. 결과는 실행기가 평가를 마친 뒤 이 자리에 나타납니다.</p>`;
        }
        container.hidden = false;
        container.innerHTML = `
            <div class="rt-panel">
                <div class="rt-head">
                    <div><p class="panel-kicker">AI 판단 견고성 검증</p><h3>레드팀 평가</h3></div>
                    <div>${chip(decisionLabel, decisionClass)} <button type="button" class="button secondary small" data-rt-refresh>새로고침</button></div>
                </div>
                ${body}
            </div>`;
        return state;
    }

    // Polls every 5 s while the evaluation is moving, for up to 10 minutes.
    function render(container, { analysisId, decision }) {
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
            const state = draw(container, decision, data);
            container.querySelector("[data-rt-refresh]")?.addEventListener("click", () => { rounds = 0; tick(); });
            rounds += 1;
            const moving = data && (data.stage === "sending" || (data.stage === "accepted" && !TERMINAL.has(state)));
            if (moving && rounds < 120 && document.body.contains(container)) timer = setTimeout(tick, 5000);
        };
        draw(container, decision, null);
        if (decision === "send" || decision === "queued") tick();
    }

    window.HawkiRedteam = { render, DECISION, JOB_STATE };
})();
