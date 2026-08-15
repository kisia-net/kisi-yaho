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

    function formatAsset(asset) {
        const facts = [
            ["criticality", asset.criticality],
            ["exposure", asset.exposure],
            ["zone", asset.zone],
            ["data", asset.data_classification],
            ["owner", asset.owner],
        ].filter(([, value]) => value);
        const matchedOn = asset.match?.matched_on || [];
        return `<div class="output-item">
            <div class="action-meta">
                ${asset.match?.on_trigger_alert ? `<span class="tag">on trigger alert</span>` : ""}
                ${facts.map(([label, value]) => `<span class="tag">${escapeHtml(label)}: ${escapeHtml(value)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(asset.hostname || asset.id)}</strong>
            <p class="muted">${escapeHtml(asset.business_service || "—")}</p>
            <p class="muted">matched on ${escapeHtml(matchedOn.join(", ") || "—")}</p>
        </div>`;
    }

    function formatIndicator(indicator) {
        const match = indicator.match || {};
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(indicator.verdict || "unknown")}</span>
                <span class="tag">confidence ${escapeHtml(indicator.confidence ?? 0)}</span>
                ${match.on_trigger_alert ? `<span class="tag">on trigger alert</span>` : ""}
                ${match.indicator_expired ? `<span class="tag">expired</span>` : ""}
            </div>
            <strong>${escapeHtml(match.matched_value || indicator.value)}</strong>
            <p class="muted">${escapeHtml(indicator.description || "")}</p>
            <p class="muted">${escapeHtml(indicator.feed || "feed")} · ${escapeHtml((indicator.categories || []).join(", ") || "uncategorized")}</p>
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
            `<span class="tag">${review.complete ? "schema complete" : `${missing.length} section(s) missing`}</span>`,
            `<span class="tag">${escapeHtml(review.citations ?? 0)} evidence citations</span>`,
            ungrounded.length ? `<span class="tag">${ungrounded.length} ungrounded id(s)</span>` : "",
            review.repair_attempted ? `<span class="tag">correction pass run</span>` : "",
        ].join("");

        panel.hidden = false;
        panel.innerHTML = `<div class="output-item">
            <div class="action-meta">${tags}</div>
            ${missing.length ? `<p class="muted">Not reported: ${escapeHtml(missing.join(", "))}</p>` : ""}
            ${ungrounded.length ? `<p class="muted">Cited event ids not present in the bundle: ${escapeHtml(ungrounded.join(", "))}</p>` : ""}
            ${notes.map((note) => `<p class="muted">${escapeHtml(note)}</p>`).join("")}
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

        const assets = caseData.assets || [];
        const unresolved = caseData.unresolved_assets || [];
        root.querySelector("[data-assets]").innerHTML = [
            assets.map(formatAsset).join(""),
            unresolved.length
                ? `<div class="output-item"><strong>No inventory record</strong><div class="action-meta">${unresolved.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")}</div><p class="muted">External, unmanaged, or missing from the inventory — unknown, not benign.</p></div>`
                : "",
        ].join("") || `<div class="empty-state">No asset context resolved.</div>`;

        const intel = caseData.threat_intelligence || [];
        const stats = caseData.threat_intelligence_stats || {};
        root.querySelector("[data-intel]").innerHTML = [
            intel.map(formatIndicator).join(""),
            `<div class="output-item"><p class="muted">${escapeHtml(stats.observables_checked || 0)} observables checked · ${escapeHtml(stats.observables_without_intelligence_count || 0)} without intelligence. A match raises suspicion; it does not prove compromise.</p></div>`,
        ].join("") || `<div class="empty-state">No indicator matches.</div>`;

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
                renderReview(root, result);
                const counts = result.metadata_counts || {};
                const bundled = [
                    `${counts.security_alerts ?? 0} alerts`,
                    `${counts.security_events ?? 0} events`,
                    `${counts.assets ?? 0} assets`,
                    `${counts.threat_indicators ?? 0} indicators`,
                ].join(" · ");
                root.querySelector("[data-analysis-meta]").textContent = `${result.model || "local model"} · sent ${bundled}`;
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
