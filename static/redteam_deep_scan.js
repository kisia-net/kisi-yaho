(function (scope) {
    "use strict";
    const active = (scan) => ["queued", "running"].includes(scan?.status);
    const count = (value) => Number.isInteger(value) && value >= 0 ? value : 0;
    const ratio = (numerator, denominator) => denominator ?
        `${numerator}/${denominator} (${(100 * numerator / denominator).toFixed(1)}%)` : "미평가";
    function toolRows(scan) {
        return ["promptfoo", "garak"].map((name) => {
            const result = scan?.tools?.[name] || {};
            const counts = result.counts || {};
            const total = count(counts.total), passed = count(counts.passed);
            const metrics = result.security_evaluation;
            let evaluation = "";
            if (name === "promptfoo" && metrics) {
                evaluation = `규칙상 공격 목표 위반 ${ratio(count(metrics.attack_goal_hits), count(metrics.attack_evaluated))}` +
                    ` · 공격 평가 커버리지 ${ratio(count(metrics.attack_evaluated), count(metrics.attack_attempted))}` +
                    ` · 품질 실패 ${count(metrics.counts?.quality_failure)} · 진단 경고 ${count(metrics.counts?.diagnostic_warning)}`;
            } else if (name === "garak" && result.evaluation_coverage === "not_evaluated") {
                evaluation = "detector 평가 없음 — 안전성 판정 불가";
            }
            if (name === "garak" && result.response_audit) {
                evaluation += `${evaluation ? " · " : ""}구조화 응답 ${count(result.response_audit.structured)}/${count(result.response_audit.received)}`;
            }
            if (result.process_exit_verified === false) evaluation += `${evaluation ? " · " : ""}프로세스 종료 코드 미확인`;
            if (result.grading_source === "offline_replay_of_original_received_responses") evaluation += `${evaluation ? " · " : ""}실제 수신 응답 부분 재채점 (재채점 모델 호출 없음)`;
            if (result.request_audit && !result.request_audit.status) {
                evaluation += `${evaluation ? " · " : ""}분석 API 요청 ${count(result.request_audit.sent)} · 응답 ${count(result.request_audit.received)} · 중단 후 생략 ${count(result.request_audit.skipped)} · 재시도 ${count(result.request_audit.retries)}`;
            }
            if (result.request_audit?.status === "invalid") evaluation += `${evaluation ? " · " : ""}API 요청 수 기록 검증 불가`;
            return {
                name, status: result.status || "pending", passed, total,
                hits: count(counts.hits), errors: count(counts.errors), unscored: count(counts.unscored),
                unit: name === "promptfoo" ? "검사 사례" : "probe/detector 평가",
                hitLabel: name === "promptfoo" ? "실패 검사" : "detector 탐지",
                passRate: total ? (100 * passed / total).toFixed(1) + "%" : "미평가",
                reason: [...new Set([result.error_summary, result.failure_summary].filter(Boolean))].join(" · "),
                evaluation,
            };
        });
    }
    function probeRows(scan) {
        return (Array.isArray(scan?.probes) ? scan.probes : []).map((probe) => {
            const passed = count(probe.passed), total = count(probe.total);
            const hits = count(probe.hits), unscored = count(probe.unscored);
            const verdict = probe.status === "error" ? "실행 오류" : hits ? "실패" :
                unscored || !total ? "미평가 포함" : "통과";
            return `${probe.tool} · ${probe.name}${probe.detector ? " / " + probe.detector : ""}` +
                ` · ${verdict} · 통과 ${passed}/${total} · ${probe.tool === "garak" ? "detector 탐지" : "실패 검사"} ${hits} · 미평가 ${unscored}`;
        });
    }
    function mount(root, deps = {}) {
        const fetcher = deps.fetch || scope.fetch.bind(scope);
        const schedule = deps.schedule || scope.setTimeout.bind(scope);
        const confirm = deps.confirm || scope.confirm.bind(scope);
        const document = deps.document || scope.document;
        const input = root.querySelector("[data-scan-alert]");
        const start = root.querySelector("[data-scan-start]");
        const refresh = root.querySelector("[data-scan-refresh]");
        const notice = root.querySelector("[data-scan-notice]");
        let selectedScanId = /^[a-f0-9]{24}$/.test(root.dataset.scanId || "") ? root.dataset.scanId : "";
        let current = null, generation = 0, unavailable = false, submitting = false;
        function buttons() { start.disabled = submitting || active(current) || unavailable; }
        async function getJson(url, options = {}) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 10000);
            try {
                const response = await fetcher(url, {credentials: "same-origin", cache: "no-store", ...options, signal: controller.signal});
                const body = await response.json();
                if (!response.ok) {
                    const error = new Error(body.error || "요청 실패");
                    error.status = response.status; error.body = body; throw error;
                }
                return body;
            } finally { clearTimeout(timer); }
        }
        function render(scan) {
            current = scan; buttons();
            root.querySelector("[data-scan-result]").hidden = false;
            root.querySelector("[data-scan-meta]").textContent =
                `경보 ${scan.alert_id} · 작업 ${scan.scan_id} · 상태 ${scan.status} · 모델 ${scan.model || "미보고"} · 시작 ${scan.started_at || "대기"} · 종료 ${scan.finished_at || "—"}`;
            root.querySelector("[data-scan-summary]").textContent = scan.summary || "";
            const output = root.querySelector("[data-scan-tools]");
            output.replaceChildren();
            for (const row of toolRows(scan)) {
                const item = document.createElement("p");
                item.textContent = `${row.name}: ${row.status} · ${row.passed}/${row.total} ${row.unit} 통과 (${row.passRate}) · ${row.hitLabel} ${row.hits} · 실행 오류 ${row.errors} · 미평가 ${row.unscored}${row.evaluation ? " · " + row.evaluation : ""}${row.reason ? " · " + row.reason : ""}`;
                output.appendChild(item);
            }
            const details = root.querySelector("[data-scan-details]");
            const probes = root.querySelector("[data-scan-probes]");
            if (details && probes) {
                probes.replaceChildren();
                const rows = probeRows(scan);
                details.hidden = false;
                if (!rows.length) {
                    const item = document.createElement("li");
                    item.textContent = active(scan) ? "이 작업은 대기·진행 중으로 아직 세부 평가 결과가 없습니다." :
                        "이 작업에는 세부 평가 결과가 없습니다. 인증 차단·실행 오류 또는 미실행 여부를 확인하세요. 통과 판정이 아닙니다.";
                    probes.appendChild(item);
                }
                for (const row of rows) {
                    const item = document.createElement("li");
                    item.textContent = row;
                    probes.appendChild(item);
                }
            }
            notice.textContent = scan.alert_id !== input.value.trim() && input.value.trim()
                ? "주의: 표시된 최신 검사는 현재 입력한 경보와 다른 경보의 결과입니다."
                : scan.validation_scope === "restart_subset" ? "모델 재시작 후 부분 검증 결과입니다. 기본 6종 전체 검사와 구분해 보세요. 이전 중단·실패 기록은 보존되어 있습니다."
                    : scan.status === "completed" ? "실행 완료입니다. 전체 통과 여부는 각 도구의 판정을 확인하세요."
                    : active(scan) ? "검사 진행 중입니다. 새로고침하거나 화면을 닫아도 서버 검사는 계속됩니다." : "검사 상태와 오류 내용을 확인하세요.";
        }
        function polling(scan) {
            const ticket = ++generation;
            if (!active(scan)) return;
            let attempts = 0;
            const tick = async () => {
                if (ticket !== generation) return;
                try {
                    const next = await getJson("/api/redteam/scans/" + encodeURIComponent(scan.scan_id));
                    if (ticket !== generation) return;
                    unavailable = false; render(next);
                    if (active(next) && ++attempts < 900) schedule(tick, 3000);
                    else if (active(next)) notice.textContent = "화면 조회 시간이 끝났습니다. 결과 새로고침으로 다시 확인하세요.";
                } catch (error) {
                    // A failed status lookup is not permission to start a second scan.
                    notice.textContent = "상태 조회 실패: " + error.message + " · 결과 새로고침으로 확인하세요.";
                    if (++attempts < 10) schedule(tick, 5000);
                }
            };
            schedule(tick, 1000);
        }
        async function loadLatest() {
            ++generation;
            try {
                const scan = await getJson(selectedScanId ? "/api/redteam/scans/" + selectedScanId : "/api/redteam/scans/latest");
                unavailable = false; render(scan); polling(scan);
            } catch (error) {
                unavailable = error.status !== 404;
                if (error.status === 404) {
                    current = null; root.querySelector("[data-scan-result]").hidden = true;
                    notice.textContent = "심층검사 결과 없음";
                } else notice.textContent = "결과 조회 실패: " + error.message;
                buttons();
            }
        }
        async function submit() {
            const alertId = input.value.trim();
            if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(alertId) || /^evt-[a-f0-9]{16}$/i.test(alertId)) {
                notice.textContent = "실제 Wazuh 경보 ID를 입력하세요."; return;
            }
            if (start.disabled || !confirm("추가 모델 호출을 사용해 Promptfoo와 garak을 실행합니다. LLM 서버 사용 가능 여부를 확인했나요?")) return;
            submitting = true; buttons(); notice.textContent = "실행 요청 중…";
            selectedScanId = ""; // A subsequent refresh must check new acceptance, not an older reviewed ID.
            try {
                const scan = await getJson("/api/redteam/scans", {method: "POST", headers: {
                    "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf,
                }, body: JSON.stringify({alert_id: alertId, tools: ["promptfoo", "garak"]})});
                unavailable = false; render(scan); polling(scan);
            } catch (error) {
                if (error.status === 409 && error.body?.scan) {
                    render(error.body.scan); polling(error.body.scan);
                } else {
                    // A timeout can occur after server acceptance. Require a GET
                    // refresh, never blindly repeat this model-affecting POST.
                    unavailable = true;
                    notice.textContent = error.message + " · 재실행 전에 결과 새로고침으로 접수 여부를 확인하세요.";
                }
            } finally { submitting = false; buttons(); }
        }
        start.addEventListener("click", submit);
        refresh.addEventListener("click", loadLatest);
        void loadLatest();
        return {loadLatest, submit};
    }
    const api = {active, toolRows, probeRows, mount};
    if (typeof module !== "undefined" && module.exports) module.exports = api;
    else {
        scope.HawkiDeepScan = api;
        scope.document.querySelectorAll("[data-redteam-scan-card]").forEach((root) => mount(root));
    }
})(typeof window === "undefined" ? globalThis : window);
