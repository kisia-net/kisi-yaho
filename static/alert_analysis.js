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
            ["Business criticality", asset.criticality],
            ["Exposure", asset.exposure],
            ["Network zone", asset.zone],
            ["Data classification", asset.data_classification],
            ["Owner", asset.owner],
        ].filter(([, value]) => value);
        const matchedOn = asset.match?.matched_on || [];
        return `<div class="output-item">
            <div class="action-meta">
                ${asset.match?.on_trigger_alert ? `<span class="tag">Present in trigger alert</span>` : ""}
                ${facts.map(([label, value]) => `<span class="tag">${escapeHtml(label)}: ${escapeHtml(value)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(asset.hostname || asset.id)}</strong>
            <p class="muted">${escapeHtml(asset.business_service || "—")}</p>
            <p class="muted">Matched on: ${escapeHtml(matchedOn.join(", ") || "—")}</p>
        </div>`;
    }

    function formatIndicator(indicator) {
        const match = indicator.match || {};
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(indicator.verdict || "No verdict")}</span>
                <span class="tag">Confidence ${escapeHtml(indicator.confidence ?? 0)}</span>
                ${match.on_trigger_alert ? `<span class="tag">Present in trigger alert</span>` : ""}
                ${match.indicator_expired ? `<span class="tag">Expired indicator</span>` : ""}
            </div>
            <strong>${escapeHtml(match.matched_value || indicator.value)}</strong>
            <p class="muted">${escapeHtml(indicator.description || "")}</p>
            <p class="muted">${escapeHtml(indicator.feed || "Feed")} · ${escapeHtml((indicator.categories || []).join(", ") || "No category")}</p>
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
            `<span class="tag">${review.complete ? "All required fields present" : `Missing fields: ${missing.length}`}</span>`,
            `<span class="tag">Evidence citations: ${escapeHtml(review.citations ?? 0)}</span>`,
            ungrounded.length ? `<span class="tag">Ungrounded citations: ${ungrounded.length}</span>` : "",
            review.repair_attempted ? `<span class="tag">One repair attempt performed</span>` : "",
        ].join("");

        panel.hidden = false;
        panel.innerHTML = `<div class="output-item">
            <div class="action-meta">${tags}</div>
            ${missing.length ? `<p class="muted">Unreported fields: ${escapeHtml(missing.join(", "))}</p>` : ""}
            ${ungrounded.length ? `<p class="muted">Referenced events not present in evidence bundle: ${escapeHtml(ungrounded.join(", "))}</p>` : ""}
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
                ? `<div class="output-item"><strong>Not found in asset inventory</strong><div class="action-meta">${unresolved.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")}</div><p class="muted">The entity may be external, unmanaged, or absent from inventory. This indicates missing context, not safety.</p></div>`
                : "",
        ].join("") || `<div class="empty-state">No associated asset information.</div>`;

        const intel = caseData.threat_intelligence || [];
        const stats = caseData.threat_intelligence_stats || {};
        root.querySelector("[data-intel]").innerHTML = [
            intel.map(formatIndicator).join(""),
            `<div class="output-item"><p class="muted">Observables checked: ${escapeHtml(stats.observables_checked || 0)} · Without intelligence: ${escapeHtml(stats.observables_without_intelligence_count || 0)}. Intelligence matches increase suspicion but do not prove compromise.</p></div>`,
        ].join("") || `<div class="empty-state">No matching threat indicators.</div>`;

        root.querySelector("[data-timeline]").innerHTML = (caseData.timeline || []).map(formatEvent).join("");
        const host = trigger.host?.name || trigger.destination?.ip || "";
        const params = new URLSearchParams({mode: "alert_summary", alert_id: root.dataset.alertId});
        if (host) params.set("host", host);
        root.querySelector("[data-continue-agent]").href = `/agent?${params}`;
    }

    function renderNativeEvidence(root, evidence) {
        const target = root.querySelector("[data-trigger]");
        if (!target) return;

        const rule = evidence.rule || {};
        const agent = evidence.agent || {};
        const manager = evidence.manager || {};
        const decoder = evidence.decoder || {};
        const data = evidence.data || {};
        const system = data.system || {};
        const eventdata = data.eventdata || {};
        const mitre = rule.mitre || {};

        const joinValues = (value) => {
            if (Array.isArray(value)) return value.join(", ");
            return value ?? "";
        };

        const sourceIp =
            data.srcip ||
            data.src_ip ||
            eventdata.sourceIp ||
            eventdata.sourceIP ||
            "";

        const destinationIp =
            data.dstip ||
            data.dst_ip ||
            eventdata.destinationIp ||
            eventdata.destinationIP ||
            "";

        const sourcePort =
            data.srcport ||
            data.src_port ||
            eventdata.sourcePort ||
            "";

        const destinationPort =
            data.dstport ||
            data.dst_port ||
            eventdata.destinationPort ||
            "";

        const protocol =
            data.protocol ||
            eventdata.protocol ||
            "";

        const fields = [
            ["Time", evidence.timestamp],
            ["Agent", agent.name],
            ["Agent ID", agent.id],
            ["Agent IP", agent.ip],
            ["Manager", manager.name],
            ["Rule ID", rule.id],
            ["Wazuh rule level", rule.level],
            ["Rule description", rule.description],
            ["Rule groups", joinValues(rule.groups)],
            ["Decoder", decoder.name],
            ["Decoder parent", decoder.parent],
            ["Log source", evidence.location],
            ["Source IP", sourceIp],
            ["Source port", sourcePort],
            ["Destination IP", destinationIp],
            ["Destination port", destinationPort],
            ["Protocol",
                decoder.name === "web-accesslog" ? "" : protocol
            ],
            ["HTTP method",
                decoder.name === "web-accesslog" ? data.protocol : ""
            ],
            ["URL", data.url],
            ["HTTP status", data.id],
            ["Sysmon Event ID", system.eventID],
            ["Process", eventdata.image],
            ["Process ID", eventdata.processId],
            ["User", eventdata.user],
            ["Command line", eventdata.commandLine],
            ["MITRE ATT&CK ID", joinValues(mitre.id)],
            ["MITRE tactic", joinValues(mitre.tactic)],
            ["MITRE technique", joinValues(mitre.technique)],
        ].filter(([, value]) =>
            value !== undefined &&
            value !== null &&
            String(value).trim() !== ""
        );

        target.innerHTML = `
            <div class="output-item">
                ${fields.map(([label, value]) => `
                    <p>
                        <strong>${escapeHtml(label)}:</strong>
                        ${escapeHtml(String(value))}
                    </p>
                `).join("")}
            </div>
            ${evidence.full_log ? `
                <details class="log-raw">
                    <summary>Raw event</summary>
                    <pre>${escapeHtml(String(evidence.full_log))}</pre>
                </details>
            ` : ""}
        `;

        const title = root.querySelector("[data-case-title]");
        if (title && rule.description) {
            title.textContent = rule.description;
        }

        const caseId = root.querySelector("[data-case-id]");
        if (caseId) {
            caseId.hidden = false;
            caseId.textContent = [evidence.id, evidence.index]
                .filter(Boolean)
                .join(" · ");
        }

        const link = root.querySelector("[data-continue-agent]");
        if (link) {
            const params = new URLSearchParams({
                mode: "alert_summary",
                alert_id: evidence.id || root.dataset.alertId,
            });
            if (agent.name) params.set("host", agent.name);
            link.href = `/agent?${params}`;
        }

        renderInvestigationPivots(root, evidence);
    }

    function investigationLogUrl({
        index,
        query,
        start,
        end,
        pivot,
        alertId,
    }) {
        const params = new URLSearchParams({
            index,
            query,
            start,
            end,
            size: "100",
            pivot,
            from_alert: alertId,
            run: "1",
        });

        return `/logs?${params.toString()}`;
    }

    function renderInvestigationPivots(root, evidence) {
        const section = root.querySelector("[data-pivots-section]");
        const target = root.querySelector("[data-investigation-pivots]");

        if (!section || !target) return;

        const agent = evidence.agent || {};
        const rule = evidence.rule || {};
        const data = evidence.data || {};

        const alertId = String(
            evidence.id || root.dataset.alertId || ""
        );

        const sourceIp = String(
            data.srcip ||
            data.sourceIp ||
            data.eventdata?.sourceIp ||
            ""
        ).trim();

        const agentId = String(agent.id || "").trim();
        const ruleId = String(rule.id || "").trim();

        const timestamp = Date.parse(evidence.timestamp || "");

        if (!Number.isFinite(timestamp)) {
            return;
        }

        /*
         * These values are interpolated into query_string syntax.
         * Restrict them to expected identifier forms rather than trusting
         * arbitrary producer-controlled strings.
         */
        const safeIp =
            /^[0-9A-Fa-f:.]{3,64}$/.test(sourceIp)
                ? sourceIp
                : "";

        const safeAgentId =
            /^[A-Za-z0-9_.-]{1,64}$/.test(agentId)
                ? agentId
                : "";

        const safeRuleId =
            /^[A-Za-z0-9_.-]{1,64}$/.test(ruleId)
                ? ruleId
                : "";

        const historyStart =
            new Date(timestamp - 24 * 60 * 60 * 1000).toISOString();

        const historyEnd =
            new Date(timestamp + 60 * 60 * 1000).toISOString();

        const rawStart =
            new Date(timestamp - 5 * 60 * 1000).toISOString();

        const rawEnd =
            new Date(timestamp + 5 * 60 * 1000).toISOString();

        const links = [];

        if (safeIp) {
            links.push({
                label: "Same source IP · 24h",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query:
                        `(data.srcip:"${safeIp}" OR ` +
                        `data.eventdata.sourceIp:"${safeIp}" OR ` +
                        `full_log:"${safeIp}")`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_source_ip",
                    alertId,
                }),
            });
        }

        if (safeAgentId) {
            links.push({
                label: "Same agent · 24h",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_agent",
                    alertId,
                }),
            });
        }

        if (safeRuleId) {
            links.push({
                label: "Same rule · 24h",
                href: investigationLogUrl({
                    index: "wazuh-alerts-*",
                    query: `rule.id:"${safeRuleId}"`,
                    start: historyStart,
                    end: historyEnd,
                    pivot: "same_rule",
                    alertId,
                }),
            });
        }

        if (safeAgentId) {
            links.push({
                label: "Raw events · ±5m",
                href: investigationLogUrl({
                    index: "wazuh-archives-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: rawStart,
                    end: rawEnd,
                    pivot: "raw_window",
                    alertId,
                }),
            });
        }

        if (!links.length) {
            return;
        }

        target.innerHTML = links.map((item) => `
            <a class="button secondary"
               href="${escapeHtml(item.href)}">
                ${escapeHtml(item.label)}
            </a>
        `).join("");

        section.hidden = false;
    }

    function renderAnalystContext(root, data) {
        const section = root.querySelector(
            "[data-enrichment-section]"
        );

        const target = root.querySelector(
            "[data-analyst-context]"
        );

        if (!section || !target) return;

        const sameSource = data.same_source || {};

        const cards = [
            {
                label: "Source activity",
                value: data.source_ip
                    ? sameSource.count ?? 0
                    : "—",
                detail: data.source_ip
                    ? data.source_ip
                    : "No structured source IP",
            },
            {
                label: "Rules from source",
                value: data.source_ip
                    ? sameSource.distinct_rules ?? 0
                    : "—",
                detail: "Distinct Wazuh rules",
            },
            {
                label: "Hosts reached",
                value: data.source_ip
                    ? sameSource.distinct_agents ?? 0
                    : "—",
                detail: "Distinct monitored agents",
            },
            {
                label: "Same rule",
                value: data.same_rule_count ?? 0,
                detail: data.rule_id
                    ? `Rule ${data.rule_id}`
                    : "No rule identifier",
            },
            {
                label: "Host detections",
                value: data.same_agent_count ?? 0,
                detail: data.agent_id
                    ? `Agent ${data.agent_id}`
                    : "No agent identifier",
            },
        ];

        target.innerHTML = cards.map((item) => `
            <div class="analyst-context-card">
                <span>${escapeHtml(item.label)}</span>
                <strong>${escapeHtml(item.value)}</strong>
                <small>${escapeHtml(item.detail)}</small>
            </div>
        `).join("");

        section.hidden = false;
    }

    function renderInvestigationContext(root, context) {
        const target = root.querySelector("[data-investigation-context]");
        const meta = root.querySelector("[data-context-meta]");

        if (!target) return;

        const events = context.events || [];

        if (meta) {
            meta.textContent =
                `${events.length} related events · ±${context.window_seconds || 0}s`;
        }

        if (!events.length) {
            target.innerHTML =
                `<div class="empty-state">No related evidence was selected.</div>`;
            return;
        }

        target.innerHTML = events.map((event) => {
            const data = event.data || {};
            const rule = event.rule || {};

            const source =
                data.srcip ||
                data.sourceIp ||
                "";

            const destination =
                data.dstip ||
                data.destinationIp ||
                "";

            const eventLabel =
                Object.keys(data).length === 0
                    ? "Undecoded raw event"
                    : "";

            const parts = [
                eventLabel,
                source ? `Source: ${source}` : "",
                destination ? `Destination: ${destination}` : "",
                data.protocol ? `Protocol/Method: ${data.protocol}` : "",
                data.url ? `URL: ${data.url}` : "",
                data.id ? `Status/Event: ${data.id}` : "",
                rule.id ? `Rule: ${rule.id}` : "",
                rule.level !== undefined && rule.level !== null
                    ? `Level: ${rule.level}`
                    : "",
            ].filter(Boolean);

            return `
                <div class="output-item investigation-event">
                    <p>
                        <strong>${escapeHtml(event.timestamp || "Unknown time")}</strong>
                    </p>

                    ${event.location
                        ? `<p class="muted">${escapeHtml(event.location)}</p>`
                        : ""}

                    ${parts.length
                        ? `<p>${escapeHtml(parts.join(" · "))}</p>`
                        : ""}

                    ${event.full_log
                        ? `<details class="log-raw">
                               <summary>Raw event</summary>
                               <pre>${escapeHtml(event.full_log)}</pre>
                           </details>`
                        : ""}
                </div>
            `;
        }).join("");
    }

    async function initDetail(root) {
        const alertId = root.dataset.alertId;
        const csrf = root.dataset.csrf;
        try {
            renderCase(root, await requestJson(`/api/alerts/${encodeURIComponent(alertId)}`));
            try {
                const evidence = await requestJson(
                    `/api/alerts/${encodeURIComponent(alertId)}/evidence`
                );
                renderNativeEvidence(root, evidence);

                try {
                    const enrichment = await requestJson(
                        `/api/alerts/${encodeURIComponent(alertId)}/enrichment`
                    );
                    renderAnalystContext(root, enrichment);
                } catch (enrichmentError) {
                    console.warn(
                        "Alert enrichment unavailable:",
                        enrichmentError
                    );
                }

                try {
                    const context = await requestJson(
                        `/api/alerts/${encodeURIComponent(alertId)}/context`
                    );
                    renderInvestigationContext(root, context);
                } catch (contextError) {
                    const target = root.querySelector(
                        "[data-investigation-context]"
                    );
                    if (target) {
                        target.innerHTML =
                            `<div class="empty-state">Investigation context could not be loaded: ${escapeHtml(contextError.message)}</div>`;
                    }
                }
            } catch (evidenceError) {
                const target = root.querySelector("[data-trigger]");
                if (target) {
                    target.innerHTML =
                        `<div class="empty-state">Wazuh source evidence could not be loaded: ${escapeHtml(evidenceError.message)}</div>`;
                }
            }
        } catch (error) {
            const section = root.querySelector("[data-analysis-section]");
            const output = root.querySelector("[data-analysis-output]");

            if (section) section.hidden = false;
            if (output) output.textContent = error.message;
            return;
        }

        const analyzeButton = root.querySelector("[data-analyze]");
        if (!analyzeButton) return;

        analyzeButton.addEventListener("click", async (event) => {
            const button = event.currentTarget;
            const output = root.querySelector("[data-analysis-output]");
            const section = root.querySelector("[data-analysis-section]");

            if (section) section.hidden = false;

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
                output.innerHTML = `<div class="markdown-body">${markdown(result.answer || "No analysis result returned.")}</div>`;
                if (typeof window.enhanceRenderedContent === "function") window.enhanceRenderedContent(output);
                renderReview(root, result);
                const counts = result.metadata_counts || {};
                const bundled = [
                    `Alerts ${counts.security_alerts ?? 0}`,
                    `Raw events ${counts.security_events ?? 0}`,
                    `Assets ${counts.assets ?? 0}`,
                    `Threat indicators ${counts.threat_indicators ?? 0}`,
                ].join(" · ");
                root.querySelector("[data-analysis-meta]").textContent = `${result.model || "Local model"} · Evidence supplied: ${bundled}`;
            } catch (error) {
                output.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            } finally {
                button.disabled = false;
                button.textContent = "Analyze with LLM";
            }
        });
    }

    // The alert table used to be rendered with an agent link and then rewritten
    // here, by a MutationObserver watching #alerts-table with subtree: true
    // whose callback assigned link.textContent inside that same subtree.
    // Assigning textContent replaces the text node and counts as a mutation
    // even when the value is unchanged, so the callback re-triggered itself
    // without end. The microtask queue never drained, and the tab stopped
    // painting and stopped accepting input. app.js now renders the correct
    // link directly, so there is nothing to rewrite.

    document.addEventListener("DOMContentLoaded", () => {
        const root = document.getElementById("alert-analysis-root");
        if (root) initDetail(root);
    });
})();
