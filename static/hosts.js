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
                `요청 실패 (${response.status})`
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
            ? new Date(parsed).toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
            : value;
    }

    // Display-only labels for Wazuh agent status values; the raw value is
    // still used for the CSS class.
    const HOST_STATUS_LABELS = {
        active: "연결됨",
        disconnected: "연결 안 됨",
        pending: "연결 대기",
        never_connected: "연결 이력 없음",
    };

    function statusLabel(value) {
        const key = String(value ?? "").toLowerCase();
        return HOST_STATUS_LABELS[key] || value;
    }

    // 24시간 공격 경보 (레벨 10 이상) · 치명 취약점, added to each card.
    async function loadHostBadges(list) {
        let data;
        try {
            data = await requestJson("/api/siem/hosts/badges");
        } catch {
            return;
        }
        const badges = data.badges || {};
        let ctiByAgent = {};
        try {
            ctiByAgent = ((await requestJson("/api/threat-intel/status")).matches_24h || {}).by_agent || {};
        } catch {
            ctiByAgent = {};
        }
        list.querySelectorAll("[data-agent-id]").forEach((row) => {
            const badge = badges[row.dataset.agentId] || {};
            const parts = [
                `<span class="host-badge" title="CVE 경보를 뺀 최근 24시간 경보">경보 ${Number(badge.alerts_24h || 0).toLocaleString("ko-KR")}</span>`,
                badge.high_24h ? `<span class="host-badge host-badge-high" title="레벨 10 이상">고위험 ${Number(badge.high_24h).toLocaleString("ko-KR")}</span>` : "",
                badge.critical_vulnerabilities ? `<span class="host-badge host-badge-vuln" title="치명 등급 취약점">치명 취약점 ${Number(badge.critical_vulnerabilities).toLocaleString("ko-KR")}</span>` : "",
                ctiByAgent[row.dataset.agentId] ? `<span class="host-badge host-badge-high" title="최근 24시간 경보 중 CTI 등재 출발지에서 온 것">CTI 일치 ${Number(ctiByAgent[row.dataset.agentId]).toLocaleString("ko-KR")}</span>` : "",
            ].filter(Boolean).join("");
            const holder = document.createElement("div");
            holder.className = "host-badges";
            holder.innerHTML = parts;
            row.querySelector("div")?.appendChild(holder);
        });
    }

    async function initHosts(root) {
        const list = root.querySelector("[data-host-list]");
        const summary = root.querySelector("[data-host-summary]");

        try {
            const data = await requestJson("/api/siem/hosts");

            summary.textContent =
                `연결됨 ${data.active ?? 0} · 전체 ${data.total ?? 0}`;

            list.innerHTML = (data.hosts || []).map((host) => `
                <a class="host-row"
                   data-agent-id="${escapeHtml(host.id)}"
                   href="/hosts/${encodeURIComponent(host.id)}">

                    <span class="host-status ${escapeHtml(host.status)}">
                        ${escapeHtml(statusLabel(host.status))}
                    </span>

                    <div>
                        <strong>
                            ${escapeHtml(host.name || host.id)}
                        </strong>
                        <p>
                            에이전트 ${escapeHtml(host.id)}
                            · ${escapeHtml(host.ip || "IP 없음")}
                        </p>
                    </div>

                    <div>
                        <strong>
                            ${escapeHtml(
                                [
                                    host.os?.name,
                                    host.os?.version,
                                ].filter(Boolean).join(" ")
                                || "OS 알 수 없음"
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
                    모니터링 중인 Wazuh 엔드포인트가 반환되지 않았습니다.
                </div>
            `;
            loadHostBadges(list);
        } catch (error) {
            summary.textContent = "호스트 조회 실패";

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
                label: "경보 · 24시간",
                href: hostLogUrl({
                    index: "wazuh-alerts-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: "now-24h",
                    pivot: "host_alerts",
                    agentId: safeAgentId,
                }),
            },
            {
                label: "원시 이벤트 · 1시간",
                href: hostLogUrl({
                    index: "wazuh-archives-*",
                    query: `agent.id:"${safeAgentId}"`,
                    start: "now-1h",
                    pivot: "host_raw",
                    agentId: safeAgentId,
                }),
            },
            {
                label: "FIM 탐지 · 24시간",
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

    async function loadHostSecurity(root, agentId, hostName = "") {
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
                        ${escapeHtml(policy.name || policy.id || "SCA 정책")}
                    </p>

                    <div class="host-security-metrics">
                        ${securityMetric("점수", policy.score)}
                        ${securityMetric("통과", policy.pass)}
                        ${securityMetric("실패", policy.fail)}
                        ${securityMetric("유효하지 않음", policy.invalid)}
                    </div>

                    <p class="muted">
                        점검 ${escapeHtml(policy.total_checks)}개
                        · 마지막 스캔 ${escapeHtml(localTime(policy.end_scan))}
                    </p>
                `
                : `
                    <p class="muted">
                        반환된 SCA 정책 결과가 없습니다.
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
                            <strong>보안 설정</strong>
                            <span>SCA</span>
                        </div>

                        ${policy
                            ? `<div class="posture-score">
                                   <strong>${escapeHtml(policy.score ?? "—")}</strong>
                                   <span>점수</span>
                               </div>`
                            : ""}
                    </div>

                    ${policy
                        ? `
                            <p class="host-security-name">
                                ${escapeHtml(
                                    policy.name ||
                                    policy.id ||
                                    "SCA 정책"
                                )}
                            </p>

                            <div class="posture-bars">
                                ${postureBar(
                                    "통과",
                                    policy.pass,
                                    scaTotal
                                )}

                                ${postureBar(
                                    "실패",
                                    policy.fail,
                                    scaTotal
                                )}

                                ${postureBar(
                                    "유효하지 않음",
                                    policy.invalid,
                                    scaTotal
                                )}
                            </div>

                            <p class="muted">
                                전체 점검 ${escapeHtml(scaTotal)}개
                                · 마지막 스캔
                                ${escapeHtml(localTime(policy.end_scan))}
                            </p>
                        `
                        : `
                            <div class="empty-state">
                                반환된 SCA 정책 결과가 없습니다.
                            </div>
                        `}
                </article>

                <article class="host-security-card">
                    <div class="host-security-heading">
                        <div>
                            <strong>취약점 발견 항목</strong>
                            <span>Wazuh Indexer 상태</span>
                        </div>

                        <div class="posture-score">
                            <strong>${escapeHtml(vulnTotal)}</strong>
                            <span>건</span>
                        </div>
                    </div>

                    <div class="posture-bars">
                        ${postureBar(
                            "치명",
                            severity.critical ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "높음",
                            severity.high ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "중간",
                            severity.medium ?? 0,
                            vulnTotal
                        )}

                        ${postureBar(
                            "낮음",
                            severity.low ?? 0,
                            vulnTotal
                        )}
                    </div>

                    <p class="muted">
                        알 수 없음
                        ${escapeHtml(severity.unknown ?? 0)}
                        · 평가 중
                        ${escapeHtml(
                            vulnerabilities.under_evaluation ?? 0
                        )}
                    </p>

                    ${(vulnerabilities.top_packages || []).length ? `
                        <div class="vuln-packages">
                            <p class="vuln-packages-head">취약점이 많은 패키지</p>
                            <ol>
                                ${vulnerabilities.top_packages.map((item) => `
                                    <li>
                                        <code>${escapeHtml(item.name)}</code>
                                        ${item.version ? `<span class="muted">${escapeHtml(item.version)}</span>` : ""}
                                        <span class="vuln-package-count">${escapeHtml(Number(item.findings).toLocaleString("ko-KR"))}건${item.critical_or_high ? ` · 치명·높음 ${escapeHtml(Number(item.critical_or_high).toLocaleString("ko-KR"))}` : ""}</span>
                                    </li>`).join("")}
                            </ol>
                            ${vulnTotal && vulnerabilities.top_packages[0].findings / vulnTotal >= 0.3
                                ? `<p class="vuln-packages-hint">${escapeHtml(vulnerabilities.top_packages[0].name)} 업데이트로 ${escapeHtml(Math.round(vulnerabilities.top_packages[0].findings / vulnTotal * 100))}%(${escapeHtml(Number(vulnerabilities.top_packages[0].findings).toLocaleString("ko-KR"))}건)가 함께 해소될 수 있습니다.</p>`
                                : ""}
                            <a class="button secondary small" href="/alerts?category=vulnerability&amp;range=7d&amp;host=${encodeURIComponent(hostName)}">CVE 경보 보기</a>
                        </div>` : ""}
                </article>

                <article class="host-security-card">
                    <div class="host-security-heading">
                        <div>
                            <strong>파일 무결성 모니터링</strong>
                            <span>FIM</span>
                        </div>

                        <div class="posture-score">
                            <strong>
                                ${escapeHtml(
                                    fim.detections_last_24h ?? 0
                                )}
                            </strong>
                            <span>탐지 · 24시간</span>
                        </div>
                    </div>

                    <div class="fim-state">
                        <span>추적 중인 기준선</span>
                        <strong>
                            ${escapeHtml(
                                fim.tracked_entries ?? 0
                            )}
                        </strong>
                        <small>현재 모니터링 항목</small>
                    </div>

                    <p class="muted">
                        기준선 목록과 최근 FIM 탐지는
                        별도로 측정됩니다.
                    </p>

                    <a class="button secondary small"
                       href="${escapeHtml(fimSearchUrl(agentId))}">
                        FIM 탐지 검색
                    </a>
                </article>
            `;

        } catch (error) {
            target.innerHTML = `
                <div class="empty-state">
                    보안 상태를 불러오지 못했습니다:
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
                host.name || `에이전트 ${agentId}`;

            root.querySelector("[data-host-subtitle]").textContent =
                `에이전트 ${host.id || agentId} · ${host.ip || "IP 없음"}`;

            renderHostPivots(
                root,
                String(host.id || agentId)
            );

            root.querySelector("[data-host-facts]").innerHTML = [
                fact("에이전트 ID", host.id),
                fact("IP 주소", host.ip),
                fact("상태", statusLabel(host.status)),
                fact("마지막 keepalive", localTime(host.last_keepalive)),
                fact("Wazuh 버전", host.wazuh_version),
                fact("매니저", host.manager),
                fact("노드", host.node),
                fact(
                    "그룹",
                    Array.isArray(host.groups)
                        ? host.groups.join(", ")
                        : ""
                ),
            ].join("");

            root.querySelector("[data-host-system]").innerHTML = [
                fact("호스트 이름", system.hostname),
                fact("운영체제",
                    [system.os_name, system.os_version]
                        .filter(Boolean)
                        .join(" ")
                ),
                fact("아키텍처", system.architecture),
                fact("커널", system.kernel_release),
                fact("Syscollector 스캔", localTime(system.scan_time)),
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
                                ? `룰 ${escapeHtml(alert.rule_id)}`
                                : ""}
                            ${alert.source_ip
                                ? ` · 출발지 ${escapeHtml(alert.source_ip)}`
                                : ""}
                        </p>
                    </div>
                </a>
            `).join("") || `
                <div class="empty-state">
                    최근 24시간 동안 Wazuh 탐지가 없습니다.
                </div>
            `;

            loadHostSecurity(root, agentId, host.name || "");

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
