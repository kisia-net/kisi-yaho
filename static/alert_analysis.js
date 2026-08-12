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
        if (!response.ok) throw new Error(body.detail || body.error || `Request failed: ${response.status}`);
        return body;
    }

    function markdown(value) {
        if (typeof window.renderMarkdown === "function") return window.renderMarkdown(value);
        return `<p>${escapeHtml(value).replaceAll("\n", "<br>")}</p>`;
    }

    function formatEvent(event) {
        const source = event.source_type || event.source_dataset || "event";
        const host = event.host?.name || event.destination?.ip || "—";
        const reasons = event.correlation?.reasons || [];
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(source)}</span>
                <span class="tag">${escapeHtml(new Date(event["@timestamp"]).toLocaleString())}</span>
                ${reasons.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(event.message || event.rule?.name || "Event")}</strong>
            <p class="muted">${escapeHtml(host)}</p>
        </div>`;
    }

    function renderCase(root, data) {
        const caseData = data.case;
        const trigger = caseData.trigger || {};
        root.querySelector("[data-case-title]").textContent = caseData.title || trigger.message || "Alert case";
        root.querySelector("[data-case-id]").textContent = `${caseData.case_id} · ${caseData.scenario_id}`;
        root.querySelector("[data-trigger]").innerHTML = formatEvent(trigger);

        const entities = caseData.entities || {};
        root.querySelector("[data-entities]").innerHTML = Object.entries(entities)
            .filter(([, values]) => Array.isArray(values) && values.length)
            .map(([key, values]) => `<div class="output-item"><strong>${escapeHtml(key.replaceAll("_", " "))}</strong><div class="action-meta">${values.map((v) => `<span class="tag">${escapeHtml(v)}</span>`).join("")}</div></div>`)
            .join("") || `<div class="empty-state">No correlated entities.</div>`;

        root.querySelector("[data-timeline]").innerHTML = (caseData.timeline || []).map(formatEvent).join("");
        const host = trigger.host?.name || trigger.destination?.ip || "";
        const params = new URLSearchParams({mode: "alert_summary", alert_id: root.dataset.alertId});
        if (host) params.set("host", host);
        root.querySelector("[data-continue-agent]").href = `/agent?${params}`;
    }

    async function initDetail(root) {
        const alertId = root.dataset.alertId;
        const csrf = root.dataset.csrf;
        try {
            renderCase(root, await requestJson(`/api/alerts/${encodeURIComponent(alertId)}`));
        } catch (error) {
            root.querySelector("[data-analysis-output]").textContent = error.message;
            return;
        }

        root.querySelector("[data-analyze]").addEventListener("click", async (event) => {
            const button = event.currentTarget;
            const output = root.querySelector("[data-analysis-output]");
            button.disabled = true;
            button.textContent = "Analyzing…";
            output.classList.remove("empty-state");
            output.innerHTML = `<div class="typing"><i></i><i></i><i></i></div>`;
            try {
                const result = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/analyze`, {
                    method: "POST",
                    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
                    body: JSON.stringify({}),
                });
                output.innerHTML = `<div class="markdown-body">${markdown(result.answer || "No analysis returned.")}</div>`;
                if (typeof window.enhanceRenderedContent === "function") window.enhanceRenderedContent(output);
                root.querySelector("[data-analysis-meta]").textContent = `${result.model || "local model"} · ${result.related_event_count || 0} related events`;
            } catch (error) {
                output.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            } finally {
                button.disabled = false;
                button.textContent = "Analyze with LLM";
            }
        });
    }

    function upgradeAlertLinks() {
        const table = document.getElementById("alerts-table");
        if (!table) return;
        const rewrite = () => {
            table.querySelectorAll(".alert-row").forEach((row) => {
                const id = row.querySelector("strong")?.textContent?.trim();
                const link = row.querySelector("a.button");
                if (!id || !link || !id.startsWith("evt-")) return;
                link.href = `/alerts/${encodeURIComponent(id)}`;
                link.textContent = "Analyze";
            });
        };
        rewrite();
        new MutationObserver(rewrite).observe(table, {childList: true, subtree: true});
    }

    document.addEventListener("DOMContentLoaded", () => {
        upgradeAlertLinks();
        const root = document.getElementById("alert-analysis-root");
        if (root) initDetail(root);
    });
})();
