(() => {
    "use strict";

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    async function requestJson(url) {
        const response = await fetch(url, {
            headers: {
                "Accept": "application/json",
            },
        });

        let body = {};

        try {
            body = await response.json();
        } catch {
            body = {};
        }

        if (!response.ok) {
            throw new Error(
                body.error ||
                `Request failed (${response.status})`
            );
        }

        return body;
    }

    function fact(label, value) {
        return `
            <div class="host-fact">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value || "—")}</strong>
            </div>
        `;
    }

    function localTime(value) {
        if (!value) return "—";

        const parsed = Date.parse(value);

        return Number.isFinite(parsed)
            ? new Date(parsed).toLocaleString()
            : value;
    }

    async function initHosts(root) {
        const list = root.querySelector("[data-host-list]");
        const summary = root.querySelector("[data-host-summary]");

        try {
            const data = await requestJson("/api/siem/hosts");

            summary.textContent =
                `${data.active ?? 0} active · ${data.total ?? 0} total`;

            list.innerHTML = (data.hosts || []).map((host) => `
                <a class="host-row"
                   href="/hosts/${encodeURIComponent(host.id)}">

                    <span class="host-status ${escapeHtml(host.status)}">
                        ${escapeHtml(host.status)}
                    </span>

                    <div>
                        <strong>
                            ${escapeHtml(host.name || host.id)}
                        </strong>
                        <p>
                            Agent ${escapeHtml(host.id)}
                            · ${escapeHtml(host.ip || "No IP")}
                        </p>
                    </div>

                    <div>
                        <strong>
                            ${escapeHtml(
                                [
                                    host.os?.name,
                                    host.os?.version,
                                ].filter(Boolean).join(" ")
                                || "Unknown OS"
                            )}
                        </strong>
                        <p>
                            ${escapeHtml(host.wazuh_version || "")}
                        </p>
                    </div>

                    <span>
                        ${escapeHtml(localTime(host.last_keepalive))}
                    </span>
                </a>
            `).join("") || `
                <div class="empty-state">
                    No monitored Wazuh endpoints were returned.
                </div>
            `;
        } catch (error) {
            summary.textContent = "Host query failed";

            list.innerHTML = `
                <div class="empty-state">
                    ${escapeHtml(error.message)}
                </div>
            `;
        }
    }

    function securityMetric(label, value) {
        return `
            <div class="host-security-metric">
                <span>${escapeHtml(label)}</span>
                <strong>${escapeHtml(value ?? "—")}</strong>
            </div>
        `;
    }

    function hostLogUrl({
        index,
        query,
        start,
        end = "now",
        size = "100",
        pivot,
        agentId,
    }) {
        const params = new URLSearchParams({
            index,
            query,
            start,
            end,
            size,
            pivot,
            from_agent: agentId,
            run: "1",
        });

        /*
         * source_alert_id is intentionally absent because this pivot
         * originates from a host, not an alert. The agent identifier is
         * already present deterministically in the query itself.
         */
        return `/logs?${params.toString()}`;
    }

    function renderHostPivots(root, agentId) {
        const section = root.querySelector(
            "[data-host-pivots-section]"
        );

        const target = root.querySelector(
            "[data-host-pivots]"
        );

        if (!section || !target) return;

        const safeAgentId =
            /^[A-Za-z0-9_.-]{1,64}$/.test(agentId)
                ? agentId
                : "";

        if (!safeAgentId) return;

        const links = [
            {
                label: "Alerts · 24h",
                href: hostLogUrl({
                    index: "wazuh-alerts-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: "now-24h",
                    pivot: "host_alerts",
                    agentId: safeAgentId,
                }),
            },
            {
                label: "Raw events · 1h",
                href: hostLogUrl({
                    index: "wazuh-archives-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: "now-1h",
                    pivot: "host_raw",
                    agentId: safeAgentId,
                }),
            },
            {
                label: "FIM detections · 24h",
                href: hostLogUrl({
                    index: "wazuh-alerts-*",
                    query:
                        `agent.id:"${safeAgentId}" ` +
                        `AND rule.groups:syscheck`,
                    start: "now-24h",
                    pivot: "host_fim",
                    agentId: safeAgentId,
                }),
            },
        ];

        target.innerHTML = links.map((item) => `
            <a class="button secondary"
               href="${escapeHtml(item.href)}">
                ${escapeHtml(item.label)}
            </a>
        `).join("");

        section.hidden = false;
    }

    function fimSearchUrl(agentId) {
        const params = new URLSearchParams({
            index: "wazuh-alerts-*",
            query:
                `agent.id:"${agentId}" AND rule.groups:syscheck`,
            start: "now-24h",
            end: "now",
            size: "100",
            run: "1",
        });

        return `/logs?${params.toString()}`;
    }

    function postureBar(label, value, total) {
        const numericValue = Math.max(
            0,
            Number(value) || 0
        );

        const numericTotal = Math.max(
            numericValue,
            Number(total) || 0,
            1
        );

        return `
            <div class="posture-bar-row">
                <div class="posture-bar-label">
                    <span>${escapeHtml(label)}</span>
                    <strong>${escapeHtml(numericValue)}</strong>
                </div>

                <progress
                    max="${numericTotal}"
                    value="${numericValue}">
                </progress>
            </div>
        `;
    }

    async function loadHostSecurity(root, agentId) {
        const target = root.querySelector("[data-host-security]");
        if (!target) return;

        try {
            const data = await requestJson(
                `/api/siem/hosts/${encodeURIComponent(agentId)}/security`
            );

            const sca = data.sca || {};
            const vulnerabilities = data.vulnerabilities || {};
            const severity = vulnerabilities.severity || {};
            const fim = data.fim || {};

            const policy = Array.isArray(sca.policies)
                ? sca.policies[0]
                : null;

            const scaBody = policy
                ? `
                    <p class="host-security-name">
                        ${escapeHtml(policy.name || policy.id || "SCA policy")}
                    </p>

                    <div class="host-security-metrics">
                        ${securityMetric("Score", policy.score)}
                        ${securityMetric("Passed", policy.pass)}
                        ${securityMetric("Failed", policy.fail)}
                        ${securityMetric("Invalid", policy.invalid)}
                    </div>

                    <p class="muted">
                        ${escapeHtml(policy.total_checks)} checks
                        · Last scan ${escapeHtml(localTime(policy.end_scan))}
                    </p>
                `
                : `
                    <p class="muted">
                        No SCA policy result was returned.
                    </p>
                `;

            const scaTotal = policy
                ? Number(policy.total_checks) || 0
                : 0;

            const vulnTotal =
                Number(vulnerabilities.total_findings) || 0;

            target.innerHTML = `
                <article class="host-security-card">
                    <div class="host-security-heading">
                        <div>
                            <strong>Security configuration</strong>
                            <span>SCA</span>
                        </div>

                        ${policy
                            ? `<div class="posture-score">
                                   <strong>${escapeHtml(policy.score ?? "—")}</strong>
                                   <span>score</span>
                               </div>`
                            : ""}
                    </div>

                    ${policy
                        ? `
                            <p class="host-security-name">
                                ${escapeHtml(
                                    policy.name ||
                                    policy.id ||
                                    "SCA policy"
                                )}
                            </p>

                            <div class="posture-bars">
                                ${postureBar(
                                    "Passed",
                                    policy.pass,
                                    scaTotal
                                )}

                                ${postureBar(
                                    "Failed",
                                    policy.fail,
                                    scaTotal
                                )}

                                ${postureBar(
                                    "Invalid",
                                    policy.invalid,
                                    scaTotal
                                )}
                            </div>

                            <p class="muted">
                                ${escapeHtml(scaTotal)} total checks
                                · Last scan
                                ${escapeHtml(localTime(policy.end_scan))}
                            </p>
                        `
                        : `
                            <div class="empty-state">
                                No SCA policy result was returned.
                            </div>
                        `}
                </article>

                <article class="host-security-card">
                    <div class="host-security-heading">
                        <div>
                            <strong>Vulnerability findings</strong>
                            <span>Indexer state</span>
                        </div>

                        <div class="posture-score">
                            <strong>${escapeHtml(vulnTotal)}</strong>
                            <span>findings</span>
                        </div>
                    </div>

                    <div class="posture-bars">
                        ${postureBar(
                            "Critical",
                            severity.critical ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "High",
                            severity.high ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "Medium",
                            severity.medium ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "Low",
                            severity.low ?? 0,
                            vulnTotal
                        )}
                    </div>

                    <p class="muted">
                        Unknown
                        ${escapeHtml(severity.unknown ?? 0)}
                        · Under evaluation
                        ${escapeHtml(
                            vulnerabilities.under_evaluation ?? 0
                        )}
                    </p>
                </article>

                <article class="host-security-card">
                    <div class="host-security-heading">
                        <div>
                            <strong>File integrity monitoring</strong>
                            <span>FIM</span>
                        </div>

                        <div class="posture-score">
                            <strong>
                                ${escapeHtml(
                                    fim.detections_last_24h ?? 0
                                )}
                            </strong>
                            <span>detections · 24h</span>
                        </div>
                    </div>

                    <div class="fim-state">
                        <span>Tracked baseline</span>
                        <strong>
                            ${escapeHtml(
                                fim.tracked_entries ?? 0
                            )}
                        </strong>
                        <small>current monitored entries</small>
                    </div>

                    <p class="muted">
                        Baseline inventory and recent FIM detections
                        are separate measurements.
                    </p>

                    <a class="button secondary small"
                       href="${escapeHtml(fimSearchUrl(agentId))}">
                        Search FIM detections
                    </a>
                </article>
            `;

        } catch (error) {
            target.innerHTML = `
                <div class="empty-state">
                    Security posture could not be loaded:
                    ${escapeHtml(error.message)}
                </div>
            `;
        }
    }

    async function initHostDetail(root) {
        const agentId = root.dataset.agentId;

        try {
            const data = await requestJson(
                `/api/siem/hosts/${encodeURIComponent(agentId)}`
            );

            const host = data.host || {};
            const system = host.system || {};
            const alerts = data.alerts || {};

            root.querySelector("[data-host-title]").textContent =
                host.name || `Agent ${agentId}`;

            root.querySelector("[data-host-subtitle]").textContent =
                `Agent ${host.id || agentId} · ${host.ip || "No IP"}`;

            renderHostPivots(
                root,
                String(host.id || agentId)
            );

            root.querySelector("[data-host-facts]").innerHTML = [
                fact("Agent ID", host.id),
                fact("IP address", host.ip),
                fact("Status", host.status),
                fact("Last keepalive", localTime(host.last_keepalive)),
                fact("Wazuh version", host.wazuh_version),
                fact("Manager", host.manager),
                fact("Node", host.node),
                fact(
                    "Groups",
                    Array.isArray(host.groups)
                        ? host.groups.join(", ")
                        : ""
                ),
            ].join("");

            root.querySelector("[data-host-system]").innerHTML = [
                fact("Hostname", system.hostname),
                fact("Operating system",
                    [system.os_name, system.os_version]
                        .filter(Boolean)
                        .join(" ")
                ),
                fact("Architecture", system.architecture),
                fact("Kernel", system.kernel_release),
                fact("Syscollector scan", localTime(system.scan_time)),
            ].join("");

            root.querySelector("[data-host-alert-count]").textContent =
                String(alerts.last_24h ?? 0);

            const alertList = root.querySelector("[data-host-alerts]");

            alertList.innerHTML = (alerts.recent || []).map((alert) => `
                <a class="host-alert-row"
                   href="/alerts/${encodeURIComponent(alert.id)}">

                    <span>
                        ${escapeHtml(localTime(alert.timestamp))}
                    </span>

                    <strong class="wazuh-level">
                        ${alert.rule_level !== undefined &&
                          alert.rule_level !== null
                            ? `L${escapeHtml(alert.rule_level)}`
                            : "—"}
                    </strong>

                    <div>
                        <strong>
                            ${escapeHtml(alert.description)}
                        </strong>
                        <p>
                            ${alert.rule_id
                                ? `Rule ${escapeHtml(alert.rule_id)}`
                                : ""}
                            ${alert.source_ip
                                ? ` · Source ${escapeHtml(alert.source_ip)}`
                                : ""}
                        </p>
                    </div>
                </a>
            `).join("") || `
                <div class="empty-state">
                    No Wazuh detections in the last 24 hours.
                </div>
            `;

            loadHostSecurity(root, agentId);

        } catch (error) {
            root.innerHTML = `
                <section class="panel">
                    <div class="empty-state">
                        ${escapeHtml(error.message)}
                    </div>
                </section>
            `;
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const hostsRoot = document.getElementById("hosts-root");
        const detailRoot = document.getElementById("host-detail-root");

        if (hostsRoot) initHosts(hostsRoot);
        if (detailRoot) initHostDetail(detailRoot);
    });
})();
