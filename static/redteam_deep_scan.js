(function (scope) {
    "use strict";
    const checkUi = typeof module !== "undefined" && module.exports ? require("./redteam.js") : null;
    function checkDetailsHtml(scan) {
        const ui = checkUi || scope.HawkiRedteam;
        if (!ui?.checkDetailsHtml) return "<p>검사별 상세 표시 파일(redteam.js)을 확인하세요.</p>";
        return ["promptfoo", "garak"].map((tool) =>
            `<section><h4>${tool} 검사별 판정·이유</h4>${ui.checkDetailsHtml(scan?.tools?.[tool])}</section>`).join("");
    }
    const active = (scan) => ["queued", "running"].includes(scan?.status);
    const count = (value) => Number.isInteger(value) && value >= 0 ? value : 0;
    const ratio = (numerator, denominator) => denominator ?
        `${numerator}/${denominator} (${(100 * numerator / denominator).toFixed(1)}%)` : "미평가";
    const validAlertId = (value) => typeof value === "string" &&
        /^[A-Za-z0-9_.:-]{1,200}$/.test(value) && !/^evt-[a-f0-9]{16}$/i.test(value);
    const short = (value, max = 200) => typeof value === "string" ? value.slice(0, max) : "";
    function selectedAlert(evidence, expectedId) {
        if (!validAlertId(expectedId) || !evidence || evidence.id !== expectedId ||
            !evidence.rule || typeof evidence.rule !== "object" || !evidence.rule.id) {
            throw new Error("선택한 ID와 실제 Wazuh 경보가 일치하지 않습니다.");
        }
        return {id: expectedId, title: short(evidence.rule.description) || "설명 없는 경보",
            host: short(evidence.agent?.name, 128) || "호스트 미보고",
            time: short(evidence.timestamp || evidence["@timestamp"], 80) || "시각 미보고",
            level: Number.isInteger(evidence.rule.level) ? evidence.rule.level : null};
    }
    function alertOptions(payload) {
        if (payload?.source !== "wazuh_indexer" || !Array.isArray(payload.alerts)) {
            throw new Error("실제 Wazuh 경보 목록이 아닙니다 (테스트용 대체 안 함)");
        }
        const seen = new Set();
        return payload.alerts.slice(0, 200).filter((row) => {
            if (!validAlertId(row?.id) || seen.has(row.id)) return false;
            seen.add(row.id); return true;
        }).map((row) => ({id: row.id, label: `${short(row.time, 80) || "시각 미보고"} · ${short(row.host, 128) || "호스트 미보고"} · ${short(row.title) || "설명 없는 경보"} · ${row.id}`}));
    }
    function targetText(alert) {
        return `${alert.title} · 호스트 ${alert.host} · 발생 ${alert.time}` +
            `${alert.level !== null ? " · Wazuh level " + alert.level : ""} · ID ${alert.id}`;
    }
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
    const STATE_KO = {
        queued: ["대기", "rt-info"], pending: ["대기", "rt-info"], running: ["진행 중", "rt-info"],
        completed: ["실행 완료", "rt-muted"], passed: ["통과", "rt-ok"], failed: ["실패", "rt-bad"],
        error: ["오류", "rt-bad"], incomplete: ["일부만 완료", "rt-warn"], cancelled: ["중단됨", "rt-muted"],
        skipped: ["건너뜀", "rt-muted"], timeout: ["시간 초과", "rt-bad"],
    };
    const stateLabel = (value) => (STATE_KO[String(value || "").toLowerCase()] || [value || "확인 전"])[0];
    const stateClass = (value) => (STATE_KO[String(value || "").toLowerCase()] || [null, "rt-muted"])[1];
    function kst(value) {
        const date = new Date(value || "");
        return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("ko-KR", {
            timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", hour12: false,
        });
    }
    // The runner writes its summaries partly in English; known phrases only.
    function koreanSummary(text) {
        return String(text || "")
            .replace(/Scenario profile: ([\w-]+)\./g, "시나리오 구성: $1.")
            .replace(/Unsupported identifiers propagated downstream: /g, "근거 없는 식별자가 후속 항목으로 전파됨: ")
            .replace(/Cited evidence IDs are absent from the bundle: /g, "증거 묶음에 없는 ID 인용: ")
            .replace(/\bfailed\b/g, "실패").replace(/\bincomplete\b/g, "일부만 완료");
    }
    function mount(root, deps = {}) {
        const fetcher = deps.fetch || scope.fetch.bind(scope);
        const schedule = deps.schedule || scope.setTimeout.bind(scope);
        const document = deps.document || scope.document;
        const input = root.querySelector("[data-scan-alert]");
        const start = root.querySelector("[data-scan-start]");
        const refresh = root.querySelector("[data-scan-refresh]");
        const notice = root.querySelector("[data-scan-notice]");
        const picker = root.querySelector("[data-scan-picker]");
        const loadButton = root.querySelector("[data-scan-load-alerts]");
        const range = root.querySelector("[data-scan-range]");
        const query = root.querySelector("[data-scan-query]");
        const verify = root.querySelector("[data-scan-verify]");
        const reviewPanel = root.querySelector("[data-scan-review]");
        const acknowledge = root.querySelector("[data-scan-ack]");
        const runButton = root.querySelector("[data-scan-run]");
        const garakButton = root.querySelector("[data-scan-run-garak]");
        let selectedScanId = /^[a-f0-9]{24}$/.test(root.dataset.scanId || "") ? root.dataset.scanId : "";
        let current = null, generation = 0, unavailable = true, submitting = false;
        let selected = null, selectionBusy = false, selectionGeneration = 0, listBusy = false;
        let reviewId = "";
        const setText = (selector, text) => { const node = root.querySelector(selector); if (node) node.textContent = text; };
        function buttons() {
            const blocked = submitting || active(current) || unavailable || selectionBusy;
            const ready = selected && selected.id === input.value.trim();
            start.disabled = blocked || !ready;
            if (runButton) runButton.disabled = blocked || !ready || reviewId !== selected.id || !acknowledge?.checked;
            if (garakButton) garakButton.disabled = blocked || !ready || reviewId !== selected?.id || !acknowledge?.checked;
            for (const node of [input, picker, verify, range, query]) if (node) node.disabled = blocked || (node === picker && !picker.dataset?.hasOptions);
            if (loadButton) loadButton.disabled = blocked || listBusy;
            setText("[data-scan-ready]", submitting ? "접수 중" :
                active(current) ? "진행 중인 검사 있음" :
                unavailable ? "상태 확인 실패 · 결과 새로고침" :
                selectionBusy ? "경보 확인 중" :
                ready ? "" : "경보를 먼저 고르세요");
        }
        function closeReview() {
            reviewId = "";
            if (reviewPanel) reviewPanel.hidden = true;
            if (acknowledge) acknowledge.checked = false;
            buttons();
        }
        async function selectAlert(id) {
            if (submitting || active(current)) return false;
            const ticket = ++selectionGeneration;
            selected = null; input.value = id; selectionBusy = true; closeReview();
            setText("[data-scan-selected]", "실제 경보를 확인하는 중…");
            setText("[data-scan-selection-note]", "");
            try {
                if (!validAlertId(id)) throw new Error("올바른 실제 Wazuh 문서 ID를 선택하세요.");
                const evidence = await getJson("/api/alerts/" + encodeURIComponent(id) + "/evidence");
                if (ticket !== selectionGeneration) return false;
                selected = selectedAlert(evidence, id);
                setText("[data-scan-selected]", targetText(selected));
                setText("[data-scan-selection-note]", "");
                if (current && current.alert_id !== id) notice.textContent = "아래는 다른 경보의 기존 검사 결과입니다.";
                return true;
            } catch (error) {
                if (ticket === selectionGeneration) {
                    setText("[data-scan-selected]", "검사 대상 확인 실패 · 실행할 수 없습니다.");
                    setText("[data-scan-selection-note]", error.message + " · 테스트용 데이터로 대체하지 않음");
                }
                return false;
            } finally {
                if (ticket === selectionGeneration) { selectionBusy = false; buttons(); }
            }
        }
        async function loadAlerts() {
            if (loadButton?.disabled || listBusy || !picker) return;
            listBusy = true; buttons();
            setText("[data-scan-list-note]", "경보 목록 불러오는 중…");
            picker.replaceChildren(); picker.dataset.hasOptions = "";
            try {
                const period = ["24h", "7d", "30d"].includes(range?.value) ? range.value : "24h";
                const params = new URLSearchParams({category: "all", range: period});
                if (query?.value.trim()) params.set("q", query.value.trim().slice(0, 200));
                const payload = await getJson("/api/alerts?" + params);
                const options = alertOptions(payload);
                const placeholder = document.createElement("option");
                placeholder.value = ""; placeholder.textContent = "검사할 경보 선택";
                picker.appendChild(placeholder);
                for (const option of options) {
                    const node = document.createElement("option");
                    node.value = option.id; node.textContent = option.label; picker.appendChild(node);
                }
                picker.value = ""; picker.dataset.hasOptions = options.length ? "1" : "";
                setText("[data-scan-list-note]", options.length ?
                    `경보 ${options.length}건` :
                    "경보 없음 · 기간을 넓히거나 검색어 변경");
            } catch (error) {
                setText("[data-scan-list-note]", "경보 목록 조회 실패: " + error.message);
            } finally { listBusy = false; buttons(); }
        }
        function review() {
            if (start.disabled || !selected || !reviewPanel || !runButton || !acknowledge) return false;
            reviewId = selected.id;
            acknowledge.checked = false;
            setText("[data-scan-review-target]", "실행할 경보: " + targetText(selected));
            reviewPanel.hidden = false; buttons();
            acknowledge.focus?.();
            return true;
        }
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
            const tools = Object.keys(scan.tools || {});
            root.querySelector("[data-scan-meta]").textContent = [
                `상태 ${stateLabel(scan.status)}`,
                tools.length === 1 && tools[0] === "garak" ? "garak만 실행" : "Promptfoo + garak",
                `모델 ${scan.model || "미보고"}`,
                `시작 ${kst(scan.started_at) || "대기"}`,
                `종료 ${kst(scan.finished_at) || "—"}`,
                `경보 ${scan.alert_id}`,
                `작업 ${scan.scan_id}`,
            ].join(" · ");
            root.querySelector("[data-scan-summary]").textContent = koreanSummary(scan.summary || "");
            const output = root.querySelector("[data-scan-tools]");
            output.replaceChildren();
            for (const row of toolRows(scan)) {
                if (tools.length && !tools.includes(row.name)) continue;
                // One text-only element per tool: runner strings never become HTML.
                const card = document.createElement("div");
                card.className = "scan-tool-card " + stateClass(row.status);
                card.textContent = [
                    `${row.name === "promptfoo" ? "Promptfoo · 공격 질문 6종" : "garak · 지시 주입 공격"} — ${stateLabel(row.status)}`,
                    `${row.unit} ${row.passed}/${row.total} 통과 (${row.passRate}) · ${row.hitLabel} ${row.hits} · 실행 오류 ${row.errors} · 미평가 ${row.unscored}`,
                    ...[row.evaluation, row.reason].filter(Boolean).map(koreanSummary),
                ].join("\n");
                output.appendChild(card);
            }
            const details = root.querySelector("[data-scan-details]");
            const probes = root.querySelector("[data-scan-probes]");
            const checks = root.querySelector("[data-scan-checks]");
            // All dynamic strings in this renderer are escaped by checkDetailsHtml.
            if (checks) checks.innerHTML = checkDetailsHtml(scan);
            if (details && probes) {
                probes.replaceChildren();
                const rows = probeRows(scan);
                details.hidden = false;
                if (!rows.length) {
                    const item = document.createElement("li");
                    item.textContent = active(scan) ? "검사 중" :
                        "세부 평가 결과가 없습니다 · 통과 판정이 아닙니다";
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
                : scan.validation_scope === "restart_subset" ? "모델 재시작 후 부분 검증 (6종 전체 검사와 구분)"
                    : scan.status === "completed" ? "실행 완료 · 도구별 판정 확인"
                    : active(scan) ? "검사 중 · 화면을 닫아도 계속됩니다" : "";
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
                    else if (active(next)) notice.textContent = "조회 시간 초과 · 결과 새로고침";
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
                    notice.textContent = "검사 기록 없음";
                } else notice.textContent = "결과 조회 실패: " + error.message;
                buttons();
            }
        }
        async function submit(tools = ["promptfoo", "garak"]) {
            const chosen = Array.isArray(tools) && tools.length === 1 && tools[0] === "garak" ? ["garak"] : ["promptfoo", "garak"];
            const alertId = input.value.trim();
            if (!selected || selected.id !== alertId || reviewId !== alertId || !acknowledge?.checked) {
                notice.textContent = "실제 경보 확인과 동의 후 실행"; return;
            }
            if (submitting || active(current) || unavailable || selectionBusy) return;
            submitting = true; buttons(); notice.textContent = "실행 요청 중…";
            closeReview();
            selectedScanId = ""; // A subsequent refresh must check new acceptance, not an older reviewed ID.
            try {
                const scan = await getJson("/api/redteam/scans", {method: "POST", headers: {
                    "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf,
                }, body: JSON.stringify({alert_id: alertId, tools: chosen})});
                unavailable = false; render(scan); polling(scan);
            } catch (error) {
                if (error.status === 409 && error.body?.scan) {
                    render(error.body.scan); polling(error.body.scan);
                } else {
                    // A timeout can occur after server acceptance. Require a GET
                    // refresh, never blindly repeat this model-affecting POST.
                    unavailable = true;
                    notice.textContent = error.message + " · 재실행 전 결과 새로고침";
                }
            } finally { submitting = false; buttons(); }
        }
        start.addEventListener("click", review);
        runButton?.addEventListener("click", () => submit(["promptfoo", "garak"]));
        garakButton?.addEventListener("click", () => submit(["garak"]));
        root.querySelector("[data-scan-cancel]")?.addEventListener("click", closeReview);
        acknowledge?.addEventListener("change", buttons);
        loadButton?.addEventListener("click", loadAlerts);
        picker?.addEventListener("change", () => {
            if (picker.value) void selectAlert(picker.value);
            else {
                ++selectionGeneration; selected = null; selectionBusy = false; input.value = ""; closeReview();
                setText("[data-scan-selected]", "아직 선택한 경보가 없습니다.");
            }
        });
        verify?.addEventListener("click", () => { void selectAlert(input.value.trim()); });
        input.addEventListener("input", () => {
            ++selectionGeneration; selected = null; selectionBusy = false; closeReview();
            setText("[data-scan-selected]", "ID 변경됨 · 다시 확인 필요");
        });
        refresh.addEventListener("click", loadLatest);
        buttons();
        void loadLatest();
        if (validAlertId(root.dataset.alertId)) void selectAlert(root.dataset.alertId);
        return {loadLatest, submit, review, closeReview, selectAlert, loadAlerts};
    }
    const api = {active, toolRows, probeRows, checkDetailsHtml, validAlertId, selectedAlert, alertOptions, mount};
    if (typeof module !== "undefined" && module.exports) module.exports = api;
    else {
        scope.HawkiDeepScan = api;
        scope.document.querySelectorAll("[data-redteam-scan-card]").forEach((root) => mount(root));
    }
})(typeof window === "undefined" ? globalThis : window);
