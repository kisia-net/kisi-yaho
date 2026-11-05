(() => {
    "use strict";

    const select = () => document.getElementById("agent-alerts");
    const summary = () => document.getElementById("agent-alert-summary");
    const analyzeButton = () => document.getElementById("agent-analyze-attached");

    // Display-only labels; alert.severity itself is left untouched.
    const SEVERITY_LABELS = {
        critical: "치명",
        high: "높음",
        medium: "중간",
        low: "낮음",
        info: "정보",
    };

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function selectedAlertIds() {
        const element = select();
        if (!element) return [];
        return Array.from(element.selectedOptions)
            .map((option) => option.value)
            .filter(Boolean);
    }

    function updateSummary() {
        const element = select();
        const output = summary();
        if (!element || !output) return;

        const selected = Array.from(element.selectedOptions);
        const button = analyzeButton();
        if (!selected.length) {
            output.textContent = "첨부된 경보 증거가 없습니다.";
            if (button) button.disabled = true;
            return;
        }

        const names = selected.slice(0, 3).map((option) => option.dataset.title || option.value);
        const suffix = selected.length > 3 ? ` 외 ${selected.length - 3}건` : "";
        output.textContent = `경보 ${selected.length}건 첨부됨: ${names.join(" · ")}${suffix}`;
        if (button) button.disabled = false;
    }

    function initialAlertIds() {
        const params = new URLSearchParams(window.location.search);
        const ids = params.getAll("alert_id");
        const packed = params.get("alert_ids");
        if (packed) ids.push(...packed.split(",").map((value) => value.trim()));
        const legacyIncident = params.get("incident");
        if (legacyIncident?.startsWith("evt-")) ids.push(legacyIncident);
        return [...new Set(ids.filter(Boolean))];
    }

    async function loadAlerts() {
        const element = select();
        if (!element) return;
        const desired = new Set(initialAlertIds());

        try {
            const response = await nativeFetch("/api/alerts", {credentials: "same-origin"});
            let body = {};
            try { body = await response.json(); } catch { body = {}; }
            if (!response.ok) throw new Error(body.detail || body.error || `요청 실패: ${response.status}`);

            const alerts = Array.isArray(body.alerts) ? body.alerts : [];
            element.innerHTML = alerts.map((alert) => {
                const title = alert.title || alert.summary || alert.id;
                const severityKey = String(alert.severity || "").toLowerCase();
                const severity = SEVERITY_LABELS[severityKey] || String(alert.severity || "").toUpperCase();
                const host = alert.host ? ` · ${alert.host}` : "";
                const isSelected = desired.has(alert.id) ? " selected" : "";
                return `<option value="${escapeHtml(alert.id)}" data-title="${escapeHtml(title)}" data-host="${escapeHtml(alert.host || "")}"${isSelected}>${escapeHtml(severity)} · ${escapeHtml(title)}${escapeHtml(host)}</option>`;
            }).join("") || '<option disabled>표시할 경보가 없습니다</option>';
            updateSummary();
        } catch (error) {
            element.innerHTML = `<option disabled>경보를 불러오지 못했습니다: ${escapeHtml(error.message)}</option>`;
            updateSummary();
        }
    }

    // Preserve the user's existing app.js. We only enrich the JSON body sent
    // to the existing agent endpoint with selected alert IDs.
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function hawkiAlertContextFetch(input, init = {}) {
        const url = typeof input === "string" ? input : input?.url || "";
        if (/\/api\/agent\/chat(?:\?|$)/.test(url) && typeof init.body === "string") {
            try {
                const payload = JSON.parse(init.body);
                if (payload && typeof payload === "object") {
                    const ids = selectedAlertIds();
                    payload.context = payload.context && typeof payload.context === "object" ? payload.context : {};
                    payload.context.alert_ids = ids;
                    payload.context.alert_id = ids[0] || "";
                    init = {...init, body: JSON.stringify(payload)};
                }
            } catch {
                // Leave a non-JSON request untouched.
            }
        }
        return nativeFetch(input, init);
    };

    function initialize() {
        select()?.addEventListener("change", () => {
            updateSummary();
            const selected = select()?.selectedOptions?.[0];
            const hostInput = document.getElementById("agent-host");
            if (selected?.dataset.host && hostInput && !hostInput.value.trim()) {
                hostInput.value = selected.dataset.host;
            }
        });

        analyzeButton()?.addEventListener("click", () => {
            if (!selectedAlertIds().length) return;
            const mode = document.querySelector('[data-agent-mode="alert_summary"]');
            mode?.click();
            const input = document.getElementById("agent-input");
            if (!input) return;
            input.value = "첨부한 경보를 분석해 줘. 확인된 사실과 추론을 나누고, 심각도와 다음 확인 사항을 알려 줘.";
            document.getElementById("agent-form")?.requestSubmit();
        });

        loadAlerts();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize, {once: true});
    } else {
        initialize();
    }
})();
