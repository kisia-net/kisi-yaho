// 레드팀 검증 화면: every LLM analysis and its evaluation, newest first.
// A row opens the runner's result in place (the shared .rt-expand handler in
// app.js) and links to the alert and, for automatic reports, the report.
(() => {
    const root = document.getElementById("redteam-root");
    if (!root) return;

    const escapeHtml = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    const number = (value) => Number(value || 0).toLocaleString("ko-KR");
    const when = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("ko-KR", {
            month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
        });
    };

    const STATUS = {
        passed: ["통과", "rt-ok"],
        failed: ["실패", "rt-bad"],
        error: ["오류", "rt-bad"],
        refused: ["전송 거부", "rt-warn"],
        checking: ["확인 중", "rt-info"],
        not_sent: ["보내지 않음", "rt-muted"],
    };
    const KIND = { manual: "분석가 요청", auto: "자동 보고서", deep: "정밀 검사 중 분석" };
    const NOT_SENT = {
        disabled: "자동평가 꺼짐", not_sent: "보고서 전송 꺼짐", skipped_no_token: "토큰 없음",
        skipped_not_live: "실데이터 아님", skipped_demo_result: "데모 결과", skipped_no_runner_url: "실행기 주소 없음",
        skipped_no_tools: "도구 미지정", skipped_recursive_request: "정밀 검사 중 분석",
    };

    const form = root.querySelector("[data-rt-filters]");
    const list = root.querySelector("[data-rt-list]");
    const pager = root.querySelector("[data-rt-pager]");
    let page = 1;

    async function requestJson(url) {
        const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
        return body;
    }

    function modelName(row) {
        const served = String(row.served_model || "");
        const hub = served.match(/models--([^/]+?)--([^/]+)/);
        if (hub) return `${hub[1]}/${hub[2]}`;
        return served.split("/").filter(Boolean).pop() || row.model || "";
    }

    function renderSummary(data) {
        const summary = data.summary || {};
        const tiles = ["passed", "failed", "error", "refused", "checking", "not_sent"].map((key) => {
            const [label, cls] = STATUS[key];
            return `<button type="button" class="rt-tile ${cls}" data-rt-status="${key}">
                <span>${escapeHtml(label)}</span><strong>${escapeHtml(number(summary[key]))}</strong></button>`;
        }).join("");
        root.querySelector("[data-rt-summary-tiles]").innerHTML = tiles;
        const settings = data.settings || {};
        root.querySelector("[data-rt-settings]").textContent = [
            `분석가 요청 ${settings.auto_eval ? "자동 검증 켜짐" : "자동 검증 꺼짐"}`,
            `자동 보고서 ${settings.auto_reports_forwarded ? "검증 켜짐" : "검증 꺼짐"}`,
            (settings.tools || []).length ? `도구 ${(settings.tools || []).join(", ")}` : "",
        ].filter(Boolean).join(" · ");
        const failing = root.querySelector("[data-rt-failing]");
        const rows = data.failing_checks || [];
        failing.hidden = !rows.length;
        failing.innerHTML = rows.length
            ? `<span class="muted">자주 실패한 검사</span> ${rows.map(([name, count]) => `<span class="tag">${escapeHtml(name)} ${escapeHtml(number(count))}</span>`).join(" ")}`
            : "";
    }

    function renderRows(data) {
        const rows = data.evaluations || [];
        root.querySelector("[data-rt-count]").textContent = `${number(data.total)}건`;
        list.innerHTML = rows.map((row) => {
            const [label, cls] = STATUS[row.status] || [row.status, "rt-muted"];
            const reason = row.status === "not_sent" ? (NOT_SENT[row.decision] || row.decision) : "";
            const expandable = row.decision === "send" || row.decision === "queued";
            const links = [
                row.alert_id ? `<a href="/alerts/${encodeURIComponent(row.alert_id)}">경보 ${escapeHtml(row.alert_id.slice(0, 12))}</a>` : "",
                row.report_id ? `<a href="/auto-reports?id=${encodeURIComponent(row.report_id)}">보고서 ${escapeHtml(row.report_id)}</a>` : "",
            ].filter(Boolean).join(" · ");
            const failed = (row.failed_checks || []).map((name) => `<span class="tag tag-danger">${escapeHtml(name)}</span>`).join(" ");
            return `<li class="rt-recent-item rt-eval-item">
                <div class="rt-eval-row">
                    <span class="rt-eval-time">${escapeHtml(when(row.timestamp))}</span>
                    <span class="rt-eval-kind">${escapeHtml(KIND[row.kind] || row.kind)}${row.by && row.kind === "manual" ? ` · ${escapeHtml(row.by)}` : ""}</span>
                    <span class="rt-eval-links">${links}${modelName(row) ? `<br><span class="muted">${escapeHtml(modelName(row))}</span>` : ""}</span>
                    <span class="rt-eval-state"><span class="rt-chip ${cls}">${escapeHtml(label)}</span>${reason ? ` <span class="muted">${escapeHtml(reason)}</span>` : ""} ${failed}</span>
                    <span>${expandable ? `<button type="button" class="rt-expand" aria-expanded="false" data-rt-analysis="${escapeHtml(row.analysis_id)}" data-rt-decision="${escapeHtml(row.decision)}" data-rt-caption="레드팀 검증 화면에서 확인">결과 보기</button>` : ""}</span>
                </div>
                ${expandable ? `<div class="rt-recent-detail" hidden></div>` : ""}
            </li>`;
        }).join("") || `<li class="muted">조건에 맞는 검증 내역이 없습니다.</li>`;

        pager.hidden = (data.pages || 1) <= 1;
        pager.innerHTML = pager.hidden ? "" : [
            `<button type="button" class="pager-button" data-page="${Math.max(1, data.page - 1)}" ${data.page <= 1 ? "disabled" : ""}>이전</button>`,
            `<span class="muted">${escapeHtml(data.page)} / ${escapeHtml(data.pages)}</span>`,
            `<button type="button" class="pager-button" data-page="${Math.min(data.pages, data.page + 1)}" ${data.page >= data.pages ? "disabled" : ""}>다음</button>`,
        ].join("");
    }

    async function load() {
        const params = new URLSearchParams(new FormData(form));
        params.set("page", String(page));
        try {
            const data = await requestJson(`/api/redteam/evaluations?${params}`);
            renderSummary(data);
            renderRows(data);
        } catch (error) {
            list.innerHTML = `<li class="muted">불러오지 못했습니다 · ${escapeHtml(error.message)}</li>`;
        }
    }

    form.addEventListener("change", () => { page = 1; load(); });
    pager.addEventListener("click", (event) => {
        const button = event.target.closest("[data-page]");
        if (!button || button.disabled) return;
        page = Number(button.dataset.page) || 1;
        load();
    });
    root.querySelector("[data-rt-summary-tiles]").addEventListener("click", (event) => {
        const tile = event.target.closest("[data-rt-status]");
        if (!tile) return;
        form.elements.status.value = tile.dataset.rtStatus;
        page = 1;
        load();
    });

    const preset = new URLSearchParams(window.location.search);
    ["range", "status", "kind"].forEach((key) => {
        const value = preset.get(key);
        if (value && [...form.elements[key].options].some((option) => option.value === value)) form.elements[key].value = value;
    });
    load();
    // Verdicts still being fetched appear on the next look.
    setInterval(() => {
        if (document.visibilityState === "visible" && !list.querySelector(".rt-expand[aria-expanded=\"true\"]")) load();
    }, 60_000);
})();
