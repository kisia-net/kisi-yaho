const page = document.body.dataset.page;
const byId = (id) => document.getElementById(id);
const state = {
    config: null,
    agentMode: "alert_summary",
    history: [],
    lastAgentResult: null,
    agentSessions: [],
    currentAgentSessionId: null,
    auth: null,
    csrfToken: "",
    agentSaveTimer: null,
    agentAlerts: [],
    alertPage: 1,
};

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
function formatNumber(value) { return new Intl.NumberFormat("ko-KR").format(value ?? 0); }

// Display-only Korean labels for machine values. The raw values stay unchanged.
const SEVERITY_LABELS = {
    critical: "치명",
    high: "높음",
    medium: "중간",
    low: "낮음",
    info: "정보",
    informational: "정보",
    review: "검토 필요",
    unknown: "알 수 없음",
};
function severityLabel(value) {
    const key = String(value ?? "").toLowerCase();
    return SEVERITY_LABELS[key] || String(value ?? "");
}
function riskLabel(value) {
    const key = String(value ?? "").trim().toLowerCase();
    return SEVERITY_LABELS[key] || approvalLabel(value);
}
const HUNT_STATE_LABELS = {
    running: "실행 중",
    completed: "완료",
    finished: "완료",
    paused: "일시 중지",
    stopped: "중지됨",
    pending: "대기",
    scheduled: "예약됨",
    failed: "실패",
    error: "오류",
};
function huntStateLabel(value) {
    const key = String(value ?? "").toLowerCase();
    return HUNT_STATE_LABELS[key] || String(value ?? "");
}

const THEME_STORAGE_KEY = "hawki-theme-v2";
const THEME_COOKIE_KEY = "hawki_theme_v2";

function normalizeTheme(theme) {
    return theme === "light" || theme === "dark" ? theme : null;
}

function currentTheme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function readThemeCookie() {
    const prefix = `${THEME_COOKIE_KEY}=`;
    const item = document.cookie
        .split(";")
        .map((part) => part.trim())
        .find((part) => part.startsWith(prefix));
    return normalizeTheme(item ? decodeURIComponent(item.slice(prefix.length)) : null);
}

function storedTheme() {
    try {
        const saved = normalizeTheme(localStorage.getItem(THEME_STORAGE_KEY));
        if (saved) return saved;
    } catch {
        // Continue to the cookie fallback when localStorage is unavailable.
    }
    return readThemeCookie();
}

function preferredTheme() {
    // Bright operations theme by default, whatever the OS preference.
    return "light";
}

/*
 * Severity shown in alert lists. Wazuh rule levels map the way the Wazuh
 * dashboard groups them (0-6 low, 7-11 medium, 12-14 high, 15 critical); a
 * source without a level (fixtures, other adapters) falls back to its own
 * severity field. Display only: nothing here is sent back to the server.
 */
const SEVERITY_DISPLAY = {
    critical: "치명",
    high: "높음",
    medium: "중간",
    low: "낮음",
    info: "정보",
};

function alertSeverity(alert) {
    const level = Number(alert?.rule_level);
    let key = "";
    if (alert?.rule_level !== undefined && alert?.rule_level !== null && Number.isFinite(level)) {
        key = level >= 15 ? "critical" : level >= 12 ? "high" : level >= 7 ? "medium" : "low";
    } else {
        const raw = String(alert?.severity || "").toLowerCase();
        key = raw === "informational" ? "info" : (SEVERITY_DISPLAY[raw] ? raw : "info");
    }
    return {
        key,
        label: SEVERITY_DISPLAY[key],
        level: Number.isFinite(level) && alert?.rule_level !== null && alert?.rule_level !== undefined
            ? level
            : null,
    };
}

const PRIORITY_FACTOR_LABELS = {
    wazuh_rule_level: "룰 레벨",
    source_severity: "탐지 심각도",
    asset_criticality: "자산 중요도",
    asset_exposure: "노출도",
    asset_data_classification: "민감 데이터",
    asset_not_in_inventory: "미등록 호스트",
    threat_intel_match: "위협 인텔리전스",
    reconnaissance_ceiling: "정찰 상한",
};

/*
 * Priority badge (P1-P4) computed by the server from rule level, asset
 * inventory and threat intelligence. The tooltip spells out every factor so
 * an analyst can see why an alert ranks where it does.
 */
function priorityBadge(alert) {
    const priority = alert?.priority;
    if (!priority || !priority.band) return "";
    const band = String(priority.band).toLowerCase();
    const parts = (priority.factors || [])
        .filter((factor) => Number(factor.points) !== 0)
        .map((factor) => `${PRIORITY_FACTOR_LABELS[factor.factor] || factor.factor} ${Number(factor.points) > 0 ? "+" : ""}${factor.points}`);
    const tip = `HAW-KI 우선순위 ${priority.band} (P1이 가장 급함) · 점수 ${priority.score}점${parts.length ? ` · ${parts.join(" · ")}` : ""}`;
    return `<span class="prio-chip prio-${escapeHtml(band)}" title="${escapeHtml(tip)}" aria-label="${escapeHtml(tip)}">${escapeHtml(priority.band)}</span>`;
}

function priorityScore(alert) {
    const score = Number(alert?.priority?.score);
    return Number.isFinite(score) ? score : -1;
}

function severityChip(alert) {
    const severity = alertSeverity(alert);
    const level = severity.level !== null ? ` <small>L${escapeHtml(String(severity.level))}</small>` : "";
    const tip = severity.level !== null
        ? `Wazuh 심각도 ${severity.label} · 룰 레벨 ${severity.level} (0~15, 높을수록 심각)`
        : `Wazuh 심각도 ${severity.label}`;
    return `<span class="sev-chip sev-${severity.key}" title="${escapeHtml(tip)}">${escapeHtml(severity.label)}${level}</span>`;
}

function persistTheme(theme) {
    try {
        localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
        // Cookies provide a same-origin fallback when storage is blocked.
    }
    document.cookie = `${THEME_COOKIE_KEY}=${encodeURIComponent(theme)}; Path=/; Max-Age=31536000; SameSite=Lax`;
}

function updateThemeControl() {
    const button = byId("theme-toggle");
    if (!button) return;
    const nextTheme = currentTheme() === "dark" ? "light" : "dark";
    const label = `${nextTheme === "dark" ? "어두운" : "밝은"} 화면으로 전환`;
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.setAttribute("aria-pressed", String(currentTheme() === "dark"));
    if (byId("theme-toggle-label")) byId("theme-toggle-label").textContent = label;
}

function applyTheme(theme, persist = true) {
    const normalized = normalizeTheme(theme) || "dark";
    document.documentElement.dataset.theme = normalized;
    document.documentElement.style.colorScheme = normalized;
    if (persist) persistTheme(normalized);
    updateThemeControl();
}

function restoreTheme() {
    applyTheme(storedTheme() || preferredTheme(), false);
}

function initSidebarNavigation() {
    document.querySelectorAll(".nav-list .nav-item[href]").forEach((link) => {
        link.setAttribute("target", "_self");
    });
}

function initTheme() {
    // Restore again from app.js so persistence does not depend solely on the
    // early inline script in base.html.
    restoreTheme();

    byId("theme-toggle")?.addEventListener("click", () => {
        applyTheme(currentTheme() === "dark" ? "light" : "dark", true);
    });

    // Keep other open HAW-KI tabs synchronized.
    window.addEventListener("storage", (event) => {
        if (event.key === THEME_STORAGE_KEY) {
            const theme = normalizeTheme(event.newValue);
            if (theme) applyTheme(theme, false);
        }
    });

    // Browsers may restore a page from the back/forward cache without rerunning
    // normal initialization. Re-read the persisted value in that case.
    window.addEventListener("pageshow", restoreTheme);

    const media = window.matchMedia?.("(prefers-color-scheme: light)");
    media?.addEventListener?.("change", () => {
        if (!storedTheme()) applyTheme(preferredTheme(), false);
    });
}

function inlineFallbackMarkdown(value) {
    const tokens = [];
    let output = escapeHtml(value);

    // Use private-use Unicode delimiters. The former @@HAWKI_INLINE_0@@
    // placeholder was modified by the emphasis regex because it contained
    // underscores, leaving visible strings such as @@HAWKIINLINE0@@.
    output = output.replace(/`([^`\n]+)`/g, (_, code) => {
        const token = `\uE000${tokens.length}\uE001`;
        tokens.push(`<code>${code}</code>`);
        return token;
    });

    output = output
        .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
        .replace(/__([^_]+)__/g, "<strong>$1</strong>")
        .replace(/~~([^~]+)~~/g, "<del>$1</del>")
        .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>")
        .replace(/(^|[^_])_([^_\n]+)_/g, "$1<em>$2</em>");

    tokens.forEach((html, index) => {
        output = output.replaceAll(`\uE000${index}\uE001`, html);
    });

    return output;
}

function splitMarkdownTableRow(line) {
    let source = String(line ?? "").trim();
    if (source.startsWith("|")) source = source.slice(1);
    if (source.endsWith("|") && !source.endsWith("\\|")) source = source.slice(0, -1);

    const cells = [];
    let current = "";
    let escaped = false;
    let codeTicks = 0;

    for (let index = 0; index < source.length; index += 1) {
        const char = source[index];

        if (escaped) {
            current += char;
            escaped = false;
            continue;
        }
        if (char === "\\") {
            current += char;
            escaped = true;
            continue;
        }
        if (char === "`") {
            let count = 1;
            while (source[index + count] === "`") count += 1;
            const ticks = "`".repeat(count);
            current += ticks;
            codeTicks = codeTicks === count ? 0 : count;
            index += count - 1;
            continue;
        }
        if (char === "|" && codeTicks === 0) {
            cells.push(current.trim());
            current = "";
            continue;
        }
        current += char;
    }

    cells.push(current.trim());
    return cells;
}

function isMarkdownTableSeparator(line) {
    const cells = splitMarkdownTableRow(line);
    return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function markdownTableAlignment(separatorCell) {
    const value = String(separatorCell ?? "").trim();
    if (value.startsWith(":") && value.endsWith(":")) return "center";
    if (value.endsWith(":")) return "right";
    return "left";
}

function fallbackMarkdown(source) {
    const lines = String(source ?? "").replaceAll("\r\n", "\n").split("\n");
    const output = [];
    let paragraph = [];
    let listType = null;
    let listItems = [];
    let inFence = false;
    let fenceLanguage = "plaintext";
    let fenceLines = [];

    const flushParagraph = () => {
        if (!paragraph.length) return;
        output.push(`<p>${paragraph.map(inlineFallbackMarkdown).join("<br>")}</p>`);
        paragraph = [];
    };
    const flushList = () => {
        if (!listType || !listItems.length) return;
        output.push(`<${listType}>${listItems.map((item) => `<li>${inlineFallbackMarkdown(item)}</li>`).join("")}</${listType}>`);
        listType = null;
        listItems = [];
    };
    const flushFence = () => {
        output.push(`<pre><code class="language-${escapeHtml(fenceLanguage)}">${escapeHtml(fenceLines.join("\n"))}</code></pre>`);
        fenceLines = [];
    };

    let index = 0;
    while (index < lines.length) {
        const line = lines[index];
        const fence = line.match(/^\s*```\s*([\w#+.-]*)\s*$/);

        if (fence) {
            if (inFence) {
                flushFence();
                inFence = false;
            } else {
                flushParagraph();
                flushList();
                inFence = true;
                fenceLanguage = fence[1] || "plaintext";
            }
            index += 1;
            continue;
        }
        if (inFence) {
            fenceLines.push(line);
            index += 1;
            continue;
        }

        const nextLine = lines[index + 1] ?? "";
        const possibleHeader = line.includes("|")
            ? splitMarkdownTableRow(line)
            : [];
        if (
            possibleHeader.length >= 2
            && nextLine.includes("|")
            && isMarkdownTableSeparator(nextLine)
        ) {
            flushParagraph();
            flushList();

            const separators = splitMarkdownTableRow(nextLine);
            const columnCount = Math.max(possibleHeader.length, separators.length);
            const alignments = Array.from(
                {length: columnCount},
                (_, columnIndex) => markdownTableAlignment(separators[columnIndex] || "---"),
            );
            const headerCells = Array.from(
                {length: columnCount},
                (_, columnIndex) => possibleHeader[columnIndex] || "",
            );

            const bodyRows = [];
            index += 2;
            while (index < lines.length) {
                const rowLine = lines[index];
                if (!rowLine.trim() || !rowLine.includes("|")) break;
                const cells = splitMarkdownTableRow(rowLine);
                if (cells.length < 2) break;
                bodyRows.push(
                    Array.from(
                        {length: columnCount},
                        (_, columnIndex) => cells[columnIndex] || "",
                    ),
                );
                index += 1;
            }

            output.push(`
                <table>
                    <thead>
                        <tr>${headerCells.map((cell, columnIndex) => (
                            `<th data-align="${alignments[columnIndex]}">${inlineFallbackMarkdown(cell)}</th>`
                        )).join("")}</tr>
                    </thead>
                    <tbody>
                        ${bodyRows.map((row) => (
                            `<tr>${row.map((cell, columnIndex) => (
                                `<td data-align="${alignments[columnIndex]}">${inlineFallbackMarkdown(cell)}</td>`
                            )).join("")}</tr>`
                        )).join("")}
                    </tbody>
                </table>
            `);
            continue;
        }

        if (!line.trim()) {
            flushParagraph();
            flushList();
            index += 1;
            continue;
        }
        const heading = line.match(/^(#{1,6})\s+(.+)$/);
        if (heading) {
            flushParagraph();
            flushList();
            const level = heading[1].length;
            output.push(`<h${level}>${inlineFallbackMarkdown(heading[2])}</h${level}>`);
            index += 1;
            continue;
        }
        if (/^\s*(---+|___+|\*\*\*+)\s*$/.test(line)) {
            flushParagraph();
            flushList();
            output.push("<hr>");
            index += 1;
            continue;
        }
        const unordered = line.match(/^\s*[-+*]\s+(.+)$/);
        const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
        if (unordered || ordered) {
            flushParagraph();
            const requestedType = unordered ? "ul" : "ol";
            if (listType && listType !== requestedType) flushList();
            listType = requestedType;
            listItems.push((unordered || ordered)[1]);
            index += 1;
            continue;
        }
        const quote = line.match(/^\s*>\s?(.*)$/);
        if (quote) {
            flushParagraph();
            flushList();
            output.push(`<blockquote><p>${inlineFallbackMarkdown(quote[1])}</p></blockquote>`);
            index += 1;
            continue;
        }

        paragraph.push(line);
        index += 1;
    }

    if (inFence) flushFence();
    flushParagraph();
    flushList();
    return output.join("");
}

function renderMarkdown(value) {
    const source = String(value ?? "");
    if (window.marked?.parse && window.DOMPurify?.sanitize) {
        const parsed = window.marked.parse(source, { gfm: true, breaks: true });
        return window.DOMPurify.sanitize(parsed, {
            USE_PROFILES: { html: true },
            FORBID_TAGS: ["script", "style", "iframe", "object", "embed", "form", "input", "textarea", "select", "button"],
            FORBID_ATTR: ["style", "srcset"],
        });
    }
    return fallbackMarkdown(source);
}

const LANGUAGE_ALIASES = {
    sh: "bash",
    shell: "bash",
    ps1: "powershell",
    py: "python",
    js: "javascript",
    ts: "typescript",
    html: "xml",
    esql: "sql",
    kql: "plaintext",
    vql: "sql",
    suricata: "ini",
    docker: "dockerfile",
    md: "markdown",
    text: "plaintext",
};

function languageFromCode(code) {
    const languageClass = [...code.classList].find((name) => name.startsWith("language-"));
    return languageClass ? languageClass.slice(9).toLowerCase() : "plaintext";
}

function decorateCodeBlocks(container) {
    if (!container) return;
    container.querySelectorAll("pre > code").forEach((code) => {
        const pre = code.parentElement;
        if (pre.parentElement?.classList.contains("code-block")) return;

        const declaredLanguage = languageFromCode(code);
        const highlightLanguage = LANGUAGE_ALIASES[declaredLanguage] || declaredLanguage;
        if (window.hljs && highlightLanguage !== "plaintext" && window.hljs.getLanguage(highlightLanguage)) {
            try {
                code.innerHTML = window.hljs.highlight(code.textContent, { language: highlightLanguage, ignoreIllegals: true }).value;
                code.classList.add("hljs");
            } catch { /* retain escaped plaintext */ }
        }

        const wrapper = document.createElement("div");
        wrapper.className = "code-block";
        const toolbar = document.createElement("div");
        toolbar.className = "code-toolbar";
        const label = document.createElement("span");
        label.textContent = declaredLanguage || "plaintext";
        const copy = document.createElement("button");
        copy.type = "button";
        copy.className = "code-copy";
        copy.textContent = "복사";
        copy.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(code.textContent);
                copy.textContent = "복사됨";
                setTimeout(() => { copy.textContent = "복사"; }, 1400);
            } catch {
                toast("클립보드 접근에 실패했습니다");
            }
        });
        toolbar.append(label, copy);
        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.append(toolbar, pre);
    });
}

function secureRenderedLinks(container) {
    container?.querySelectorAll("a[href]").forEach((link) => {
        const href = link.getAttribute("href") || "";
        if (/^https?:\/\//i.test(href)) {
            link.target = "_blank";
            link.rel = "noopener noreferrer";
        }
    });
}

function wrapMarkdownTables(container) {
    if (!container) return;
    container.querySelectorAll("table").forEach((table) => {
        if (table.parentElement?.classList.contains("markdown-table-wrap")) return;
        const wrapper = document.createElement("div");
        wrapper.className = "markdown-table-wrap";
        wrapper.setAttribute("role", "region");
        wrapper.setAttribute("aria-label", "가로 스크롤 표");
        wrapper.tabIndex = 0;
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
}

function enhanceRenderedContent(container) {
    secureRenderedLinks(container);
    wrapMarkdownTables(container);
    decorateCodeBlocks(container);
}

function toast(message) {
    const region = byId("toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast";
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 3200);
}

// Safety net. Most page loaders await a fetch without catching, so a failed
// request used to leave placeholder text on screen indefinitely and look like
// a page that never loaded. Say what happened instead.
window.addEventListener("unhandledrejection", (event) => {
    const message = event.reason?.message || String(event.reason ?? "요청 실패");
    console.error("HAW-KI 요청 실패:", event.reason);
    toast(`요청 실패: ${message}`);
});
async function api(url, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrfToken) {
        headers.set("X-CSRF-Token", state.csrfToken);
    }

    const response = await fetch(url, {
        ...options,
        method,
        headers,
    });
    let data = {};
    try { data = await response.json(); } catch { data = {}; }

    if (response.status === 401 && page !== "login") {
        location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
        throw new Error("로그인이 필요합니다.");
    }
    if (!response.ok) {
        // The Korean sentence first; the technical detail (an exception text)
        // follows in parentheses rather than replacing it.
        const reason = data.error
            ? (data.detail ? `${data.error} (${data.detail})` : data.error)
            : (data.detail || `요청 실패: ${response.status}`);
        throw new Error(reason);
    }
    return data;
}

function renderAccountControls() {
    const host = document.querySelector(".topbar-actions");
    if (!host || !state.auth || byId("account-controls")) return;

    const controls = document.createElement("div");
    controls.id = "account-controls";
    controls.className = "account-controls";
    controls.innerHTML = `
        <a class="topbar-icon-button" href="/account"
            aria-label="계정: ${escapeHtml(state.auth.username)} (${escapeHtml(state.auth.role)})"
            title="계정: ${escapeHtml(state.auth.username)} · ${escapeHtml(state.auth.role)}">
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="8" r="4"></circle>
                <path d="M4.5 21a7.5 7.5 0 0 1 15 0"></path>
            </svg>
        </a>
        ${state.auth.role === "admin" ? `
            <a class="topbar-icon-button" href="/admin/users"
                aria-label="사용자 관리" title="사용자 관리">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <circle cx="9" cy="8" r="3"></circle>
                    <path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path>
                    <path d="M17 8v6M14 11h6"></path>
                </svg>
            </a>
        ` : ""}
        <button id="logout-button" class="topbar-icon-button" type="button"
            aria-label="로그아웃" title="로그아웃">
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M10 5H5v14h5"></path>
                <path d="M14 8l4 4-4 4"></path>
                <path d="M18 12H9"></path>
            </svg>
        </button>
    `;
    host.prepend(controls);

    byId("logout-button")?.addEventListener("click", async () => {
        try {
            await api("/api/auth/logout", { method: "POST" });
        } finally {
            location.href = "/login";
        }
    });
}

async function loadAuth() {
    const data = await api("/api/auth/me");
    state.auth = data.user;
    state.csrfToken = data.csrf_token || "";
    renderAccountControls();
}
function setService(name, details) {
    const configured = details?.configured !== false;
    const online = Boolean(details?.ok);
    document.querySelectorAll(`[data-service-dot="${name}"]`).forEach((dot) => {
        dot.classList.remove("unknown", "online", "offline", "unconfigured");
        dot.classList.add(!configured ? "unconfigured" : online ? "online" : "offline");
    });
    const reason = { refused: " · 서비스 미실행", timeout: " · 응답 없음" }[details?.error_kind] || "";
    const autoEval = typeof details?.auto_eval_enabled === "boolean"
        ? ` · 자동평가 ${details.auto_eval_enabled ? "켜짐" : "꺼짐"}`
        : "";
    document.querySelectorAll(`[data-service-label="${name}"]`).forEach((label) => {
        label.textContent = (!configured ? "미설정" : online ? `연결됨 · HTTP ${details.status_code}` : `연결 안 됨${reason}`) + (configured ? autoEval : "");
    });
    document.querySelectorAll(`[data-service-latency="${name}"]`).forEach((label) => {
        label.textContent = details?.latency_ms != null ? `${details.latency_ms} ms` : "—";
    });
    // Sidebar: one short word, the full line on hover.
    const full = (!configured ? "미설정" : online ? `연결됨 · HTTP ${details.status_code}` : `연결 안 됨${reason}`)
        + (configured ? autoEval : "") + (details?.latency_ms != null ? ` · ${details.latency_ms} ms` : "");
    document.querySelectorAll(`[data-service-short="${name}"]`).forEach((label) => {
        label.textContent = !configured ? "미설정" : online ? "연결됨" : "연결 안 됨";
        label.closest("[data-service-row]")?.setAttribute("title", full);
    });
}
async function loadServices() {
    try {
        const data = await api("/api/status");
        const services = data.services || {};
        Object.entries(services).forEach(([name, details]) => setService(name, details));
        const configured = Object.values(services).filter((x) => x.configured !== false);
        const online = configured.filter((x) => x.ok).length;
        if (byId("global-health-text")) byId("global-health-text").textContent = `설정된 서비스 ${configured.length}개 중 ${online}개 연결됨`;
        if (byId("status-checked-at")) byId("status-checked-at").textContent = new Date(data.checked_at).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", hour12: false });
    } catch (error) {
        if (byId("global-health-text")) byId("global-health-text").textContent = "상태 확인 실패";
    }
}
async function loadConfig() {
    try { state.config = await api("/api/config"); } catch { state.config = {}; }
}

function renderDashboardAlerts(alerts) {
    const target = byId("dashboard-alert-list");
    if (!target) return;

    target.classList.remove("loading-block");

    // Same rule, source and host fold into one row with a count.
    const rows = groupAlerts(alerts || []).slice(0, 6);
    target.innerHTML = rows.map(({ lead: alert, count }) => {
        const timestamp = Date.parse(alert.time);
        const time = Number.isFinite(timestamp)
            ? new Date(timestamp).toLocaleString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
            : (alert.time || "—");

        return `
            <a class="dashboard-alert-row sev-row sev-${alertSeverity(alert).key}"
               href="/alerts/${encodeURIComponent(alert.id)}">

                <span class="dashboard-alert-time">
                    ${escapeHtml(time)}
                </span>

                <span class="wazuh-level">
                    ${priorityBadge(alert)}
                    ${severityChip(alert)}
                </span>

                <div>
                    <strong>
                        ${escapeHtml(alert.title || "Wazuh 경보")}
                    </strong>

                    <p>
                        ${escapeHtml(alert.host || "—")}
                        ${alert.rule_id
                            ? ` · 룰 ${escapeHtml(alert.rule_id)}`
                            : ""}
                        ${alert.source_ip ? ` · ${escapeHtml(alert.source_ip)}` : ""}
                        ${count > 1 ? ` · <span class="dashboard-repeat">같은 경보 ${escapeHtml(formatNumber(count))}건</span>` : ""}
                    </p>
                </div>
            </a>
        `;
    }).join("") || `
        <div class="empty-state">
            최근 Wazuh 경보가 없습니다.
        </div>
    `;
}

function renderDashboardVisuals(visuals) {
    const activityTarget = byId("dashboard-activity-chart");
    const levelTarget = byId("dashboard-level-chart");

    const activity = visuals?.activity || [];
    const levels = visuals?.levels || [];

    if (activityTarget) {
        if (!activity.length) {
            activityTarget.innerHTML =
                `<div class="empty-state">반환된 경보 탐지 추이가 없습니다.</div>`;
        } else {
            const maxCount = Math.max(
                1,
                ...activity.map((item) => Number(item.count) || 0)
            );

            const width = 720;
            const height = 190;
            const baseline = 150;
            const slot = width / activity.length;
            const barWidth = Math.max(5, slot - 5);

            const bars = activity.map((item, index) => {
                const count = Number(item.count) || 0;
                const barHeight = Math.round(
                    (count / maxCount) * 118
                );

                const x = Math.round(index * slot + 2);
                const y = baseline - barHeight;

                const parsed = Date.parse(item.time || "");
                const label = Number.isFinite(parsed)
                    ? new Date(parsed).toLocaleTimeString("ko-KR", {
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                    })
                    : "";

                const showLabel =
                    index === 0 ||
                    index === activity.length - 1 ||
                    index % 6 === 0;

                const bucketStart = Number.isFinite(parsed) ? new Date(parsed) : null;
                const href = bucketStart
                    ? `/logs?${new URLSearchParams({
                        index: "wazuh-alerts-*",
                        query: "*",
                        start: bucketStart.toISOString(),
                        end: new Date(bucketStart.getTime() + 60 * 60 * 1000).toISOString(),
                        size: "200",
                        run: "1",
                    })}`
                    : "";

                return `
                    <g>
                        <title>${escapeHtml(label)} · 경보 ${count}건${href ? " · 눌러서 검색" : ""}</title>
                        ${href ? `<a href="${escapeHtml(href)}" class="activity-link">` : ""}
                        <rect class="activity-hit" x="${Math.round(index * slot)}" y="0" width="${Math.ceil(slot)}" height="${baseline}"></rect>
                        <rect class="activity-bar"
                              x="${x}"
                              y="${y}"
                              width="${barWidth}"
                              height="${Math.max(1, barHeight)}"
                              rx="2">
                        </rect>
                        ${href ? "</a>" : ""}

                        ${showLabel
                            ? `<text class="activity-axis-label"
                                     x="${x}"
                                     y="174">${escapeHtml(label)}</text>`
                            : ""}
                    </g>
                `;
            }).join("");

            activityTarget.innerHTML = `
                <svg class="activity-svg"
                     viewBox="0 0 ${width} ${height}"
                     role="img"
                     aria-label="최근 24시간 Wazuh 탐지 추이">
                    <line class="activity-baseline"
                          x1="0"
                          y1="${baseline}"
                          x2="${width}"
                          y2="${baseline}">
                    </line>

                    ${bars}
                </svg>
            `;
        }
    }

    if (levelTarget) {
        if (!levels.length) {
            levelTarget.innerHTML =
                `<div class="empty-state">반환된 Wazuh 룰 레벨이 없습니다.</div>`;
        } else {
            const maxCount = Math.max(
                1,
                ...levels.map((item) => Number(item.count) || 0)
            );

            levelTarget.innerHTML = levels.map((item) => `
                <a class="level-distribution-row" href="/alerts?min_level=${encodeURIComponent(item.level)}&range=24h&category=all&sort=priority" title="레벨 ${escapeHtml(item.level)} 이상 경보 보기">
                    <strong>L${escapeHtml(item.level)}</strong>

                    <progress max="${maxCount}"
                              value="${Number(item.count) || 0}">
                    </progress>

                    <span>${escapeHtml(formatNumber(item.count))}</span>
                </a>
            `).join("");
        }
    }
}

// Wazuh 대시보드 시각화와 같은 집계 (/api/dashboard/wazuh-visuals).
// 막대 높이·칸 색은 SVG 속성과 클래스로만 정합니다: 페이지 CSP 가 인라인
// style 속성을 막습니다.
const WZ_BAND_ORDER = ["low", "mid", "high"];

function wzLogsHref(query, start, end) {
    const params = new URLSearchParams({ index: "wazuh-alerts-*", query, size: "200", run: "1" });
    if (start) params.set("start", start);
    if (end) params.set("end", end);
    return `/logs?${params}`;
}

function renderSeverityActivity(data) {
    const target = byId("dashboard-activity-chart");
    const legend = byId("dashboard-activity-legend");
    const activity = data.activity || [];
    if (!target || !activity.length) return;
    const labels = Object.fromEntries((data.bands || []).map((band) => [band.key, band.label]));
    if (legend) {
        legend.innerHTML = WZ_BAND_ORDER.map((key) => `<span class="wz-legend-item"><i class="wz-swatch activity-band-${key}"></i>${escapeHtml(labels[key] || key)}</span>`).join("");
        legend.removeAttribute("aria-hidden");
    }
    const width = 720;
    const baseline = 150;
    const slot = width / activity.length;
    const barWidth = Math.max(5, slot - 5);
    const maxCount = Math.max(1, ...activity.map((item) => Number(item.count) || 0));
    const bars = activity.map((item, index) => {
        const parsed = Date.parse(item.time || "");
        const label = Number.isFinite(parsed)
            ? new Date(parsed).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", hour12: false })
            : "";
        const showLabel = index === 0 || index === activity.length - 1 || index % 6 === 0;
        const href = Number.isFinite(parsed)
            ? wzLogsHref("*", new Date(parsed).toISOString(), new Date(parsed + 3600 * 1000).toISOString())
            : "";
        const x = Math.round(index * slot + 2);
        let top = baseline;
        const segments = WZ_BAND_ORDER.map((key) => {
            const count = Number((item.bands || {})[key]) || 0;
            if (!count) return "";
            const height = Math.max(1, Math.round((count / maxCount) * 118));
            top -= height;
            return `<rect class="activity-bar activity-band-${key}" x="${x}" y="${top}" width="${barWidth}" height="${height}" rx="1.5"></rect>`;
        }).join("");
        const breakdown = WZ_BAND_ORDER.map((key) => `${labels[key] || key} ${formatNumber((item.bands || {})[key] || 0)}`).join(" · ");
        return `<g>
            <title>${escapeHtml(label)} · 경보 ${formatNumber(item.count)}건 (${escapeHtml(breakdown)})${href ? " · 눌러서 검색" : ""}</title>
            ${href ? `<a href="${escapeHtml(href)}" class="activity-link">` : ""}
            <rect class="activity-hit" x="${Math.round(index * slot)}" y="0" width="${Math.ceil(slot)}" height="${baseline}"></rect>
            ${segments}
            ${href ? "</a>" : ""}
            ${showLabel ? `<text class="activity-axis-label" x="${x}" y="174">${escapeHtml(label)}</text>` : ""}
        </g>`;
    }).join("");
    target.innerHTML = `<svg class="activity-svg" viewBox="0 0 ${width} 190" role="img" aria-label="최근 24시간 Wazuh 탐지 추이, 심각도별">
        <line class="activity-baseline" x1="0" y1="${baseline}" x2="${width}" y2="${baseline}"></line>${bars}</svg>`;
}

function renderBlockPass(data) {
    const target = byId("wz-block-pass");
    const summaryTarget = byId("wz-block-pass-summary");
    if (!target) return;
    target.classList.remove("loading-block");
    const rows = data.block_pass || [];
    const signals = data.signals || [];
    const summary = data.block_pass_summary || {};
    const totals = data.block_pass_totals || {};
    if (summaryTarget) {
        // The verdict counts are over the rows found, not every address: say both.
        summaryTarget.textContent = `IP ${formatNumber(totals.shown_ips ?? rows.length)}개 · 통과 의심 ${formatNumber(summary.passed || 0)} · 막힘 ${formatNumber(summary.blocked || 0)} · 관찰 ${formatNumber(summary.observed || 0)}`;
        summaryTarget.title = Number.isFinite(totals.web_ips)
            ? `웹 경보 출발지 IP 전체 약 ${formatNumber(totals.web_ips)}개, 성공 응답 있는 IP 약 ${formatNumber(totals.passed_ips || 0)}개`
            : "";
    }
    if (!rows.length) {
        target.innerHTML = `<div class="empty-state">최근 24시간 출발지 IP가 있는 웹 경보가 없습니다.</div>`;
        return;
    }
    const max = Math.max(1, ...rows.flatMap((row) => signals.map((signal) => Number(row[signal.key]) || 0)));
    const heat = (value) => (value ? Math.min(4, 1 + Math.floor((value / max) * 4)) : 0);
    target.innerHTML = `<div class="data-table"><table class="report-table wz-table">
        <thead><tr><th>출발지 IP</th><th>판정</th>${signals.map((signal) => `<th class="num">${escapeHtml(signal.label)}</th>`).join("")}<th class="num">경보</th></tr></thead>
        <tbody>${rows.map((row) => `<tr class="wz-row-${escapeHtml(row.verdict)}">
            <td><a href="/alerts?${new URLSearchParams({ q: row.ip, range: "24h", category: "all", sort: "priority" })}">${escapeHtml(row.ip)}</a></td>
            <td><span class="wz-verdict wz-verdict-${escapeHtml(row.verdict)}">${escapeHtml(row.verdict_label)}</span></td>
            ${signals.map((signal) => {
                const value = Number(row[signal.key]) || 0;
                const tone = signal.key === "status_2xx" || signal.key === "success_rule" ? "pass" : "block";
                return `<td class="num"><span class="wz-cell wz-${tone}-${heat(value)}">${value ? escapeHtml(formatNumber(value)) : "·"}</span></td>`;
            }).join("")}
            <td class="num">${escapeHtml(formatNumber(row.alerts))}${row.partial ? "<sup title=\"성공 신호만 센 값\">*</sup>" : ""}</td>
        </tr>`).join("")}</tbody></table></div>`;
}

function renderMitre(data) {
    const target = byId("wz-mitre");
    if (!target) return;
    target.classList.remove("loading-block");
    const tactics = data.mitre || [];
    if (!tactics.length) {
        target.innerHTML = `<div class="empty-state">MITRE 매핑이 있는 경보가 없습니다.</div>`;
        return;
    }
    const max = Math.max(1, ...tactics.flatMap((tactic) => tactic.techniques.map((item) => item.count)));
    target.innerHTML = tactics.map((tactic) => `
        <div class="wz-mitre-row">
            <strong class="wz-mitre-tactic">${escapeHtml(tactic.tactic)}<small>${escapeHtml(formatNumber(tactic.count))}</small></strong>
            <div class="wz-mitre-cells">${tactic.techniques.map((item) => `
                <a class="wz-mitre-cell wz-heat-${Math.min(4, 1 + Math.floor((item.count / max) * 4))}"
                   href="${escapeHtml(wzLogsHref(`rule.mitre.technique:"${item.technique.replace(/"/g, "")}"`))}"
                   title="${escapeHtml(`${tactic.tactic} · ${item.technique} · ${formatNumber(item.count)}건`)}">
                    <span>${escapeHtml(item.technique)}</span><b>${escapeHtml(formatNumber(item.count))}</b>
                </a>`).join("")}</div>
        </div>`).join("");
}

function renderStatuses(data) {
    const target = byId("wz-statuses");
    if (!target) return;
    target.classList.remove("loading-block");
    const statuses = data.statuses || [];
    if (!statuses.length) {
        target.innerHTML = `<div class="empty-state">상태 코드가 있는 웹 경보가 없습니다.</div>`;
        return;
    }
    const max = Math.max(1, ...statuses.map((item) => item.count));
    const meaning = (code) => code.startsWith("2") ? "성공" : code === "403" ? "거부(WAF 등)" : code.startsWith("4") ? "실패" : code.startsWith("5") ? "서버 오류" : "";
    target.innerHTML = statuses.map((item) => `
        <a class="level-distribution-row wz-status-row wz-status-${escapeHtml(item.code.charAt(0))}xx" href="${escapeHtml(wzLogsHref(`rule.groups:web AND data.id:"${item.code}"`))}" title="${escapeHtml(meaning(item.code))}">
            <strong>${escapeHtml(item.code)}</strong>
            <progress max="${max}" value="${Number(item.count) || 0}"></progress>
            <span>${escapeHtml(formatNumber(item.count))}</span>
        </a>`).join("");
}

function renderUrls(data) {
    const target = byId("wz-urls");
    if (!target) return;
    target.classList.remove("loading-block");
    const urls = data.urls || [];
    if (!urls.length) {
        target.innerHTML = `<div class="empty-state">URL이 있는 웹 경보가 없습니다.</div>`;
        return;
    }
    target.innerHTML = `<div class="data-table"><table class="report-table wz-table">
        <thead><tr><th>URL</th><th class="num">요청</th><th class="num">출발지 IP</th></tr></thead>
        <tbody>${urls.map((item) => `<tr>
            <td class="wz-url"><a href="/alerts?${new URLSearchParams({ q: item.url, range: "24h", category: "attack" })}" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</a></td>
            <td class="num">${escapeHtml(formatNumber(item.count))}</td>
            <td class="num">${escapeHtml(formatNumber(item.sources))}</td>
        </tr>`).join("")}</tbody></table></div>`;
}

async function loadWazuhVisuals() {
    const panels = ["wz-block-pass", "wz-mitre", "wz-statuses", "wz-urls"];
    try {
        const data = await api("/api/dashboard/wazuh-visuals");
        if (!data.available) {
            // Fixture data has no Indexer to aggregate.
            document.querySelectorAll("[data-wazuh-visuals]").forEach((section) => section.remove());
            return;
        }
        renderSeverityActivity(data);
        renderBlockPass(data);
        renderMitre(data);
        renderStatuses(data);
        renderUrls(data);
    } catch (error) {
        panels.forEach((id) => {
            const target = byId(id);
            if (!target) return;
            target.classList.remove("loading-block");
            target.innerHTML = `<p class="muted">Wazuh 시각화를 불러오지 못했습니다 · ${escapeHtml(error.message)}</p>`;
        });
    }
}

async function initDashboard() {
    const data = await api("/api/dashboard");
    const stats = data.stats || {};

    // 전체 / 최근 24시간 (10주차 멘토링 1번): the total is shown first and
    // smaller, the last 24 hours after it, as analysts usually read them.
    const totals = data.totals || {};
    const pair = (id, total, recent) => {
        const target = byId(id);
        if (!target) return;
        target.innerHTML = Number.isFinite(Number(total)) && total !== undefined && total !== null
            ? `<span class="metric-total">전체 ${escapeHtml(formatNumber(total))}</span><span class="metric-recent">${escapeHtml(formatNumber(recent || 0))}<small>최근 24시간</small></span>`
            : `<span class="metric-recent">${escapeHtml(formatNumber(recent || 0))}<small>최근 24시간</small></span>`;
    };
    pair("metric-alerts-24h", totals.alerts, stats.alerts_24h);
    pair("metric-level8-24h", totals.level_8_plus, stats.level_8_plus_24h);
    pair("metric-archive-24h", totals.archive_events, stats.archive_events_24h);
    pair("metric-actions", totals.pending_actions ?? stats.pending_actions, stats.pending_actions_24h);
    const windowNote = byId("metric-window");
    if (windowNote && data.window?.start && data.window?.end) {
        const stamp = (value) => new Date(value).toLocaleString("ko-KR", {
            timeZone: "Asia/Seoul", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
        });
        windowNote.textContent = `최근 ${data.window.hours || 24}시간: ${stamp(data.window.start)} ~ ${stamp(data.window.end)} KST`;
    }

    const attackOnly = stats.level_8_plus_attack_24h;
    if (byId("metric-level8-note") && Number.isFinite(attackOnly)) {
        const attackTotal = (data.totals || {}).level_8_plus_attack;
        byId("metric-level8-note").textContent = Number.isFinite(attackTotal)
            ? `CVE 취약점 경보 제외 ${formatNumber(attackTotal)} / ${formatNumber(attackOnly)}건`
            : `CVE 취약점 경보 제외 ${formatNumber(attackOnly)}건`;
    }
    if (data.recent_alerts_kind === "top_attack") {
        if (byId("dashboard-alert-kicker")) byId("dashboard-alert-kicker").textContent = "공격 경보 · 최근 24시간 · 우선순위 순";
    } else if (byId("dashboard-alert-title")) {
        byId("dashboard-alert-title").textContent = "최근 경보";
    }

    renderDashboardAlerts(data.recent_alerts || []);
    renderDashboardVisuals(data.visuals || {});
    loadWazuhVisuals();
    loadDashboardFlow();
    loadDashboardCti();
}

// 처리 흐름 (10주차 멘토링 1번): one card per stage, from collection to the
// analyst. Widths are set through the DOM (el.style), never as inline style
// attributes, which the page's Content-Security-Policy blocks.
const FLOW_REFRESH_MS = 60_000;
const RT_NOT_SENT_LABELS = {
    disabled: "자동평가 꺼짐", not_sent: "보고서 전송 꺼짐", skipped_no_token: "토큰 없음",
    skipped_not_live: "실데이터 아님", skipped_demo_result: "데모 결과", skipped_no_runner_url: "실행기 주소 없음",
    skipped_no_tools: "도구 미지정", unknown: "기록 없음",
};
let flowTimer = null;

function flowSparkline(points) {
    if (!points.length) return "";
    const values = points.map((point) => Number(point.count) || 0);
    const max = Math.max(1, ...values);
    const width = 160;
    const height = 34;
    const step = values.length > 1 ? width / (values.length - 1) : width;
    const path = values.map((value, index) => `${(index * step).toFixed(1)},${(height - 2 - (value / max) * (height - 4)).toFixed(1)}`).join(" ");
    const last = values[values.length - 1];
    return `<svg class="flow-spark" viewBox="0 0 ${width} ${height}" role="img" aria-label="최근 ${values.length}분 분당 유입량, 마지막 1분 ${last}건">
        <polyline class="flow-spark-line" points="${path}"></polyline></svg>
        <span class="flow-spark-note">최근 ${values.length}분 · 마지막 1분 ${escapeHtml(formatNumber(last))}건</span>`;
}

function renderDashboardFlow(data) {
    const root = byId("dashboard-flow");
    const list = root?.querySelector("[data-flow-stages]");
    if (!list) return;
    const stages = data.stages || [];
    const max = Math.max(1, ...stages.map((stage) => Number(stage.count) || 0));
    list.innerHTML = stages.map((stage) => {
        const known = stage.count !== null && stage.count !== undefined;
        const drop = stage.drop;
        const reasons = drop && drop.reasons
            ? Object.entries(drop.reasons).map(([key, value]) => `${RT_NOT_SENT_LABELS[key] || key} ${formatNumber(value)}`).join(" · ")
            : "";
        const verdicts = stage.verdicts
            ? `<span class="flow-verdicts" aria-hidden="true">${["passed", "failed", "error", "checking"].map((key) =>
                `<span class="flow-verdict flow-verdict-${key}" data-share="${key === "error" ? (stage.verdicts.error || 0) + (stage.verdicts.refused || 0) : stage.verdicts[key] || 0}"></span>`).join("")}</span>`
            : "";
        return `<li class="flow-stage flow-stage-${escapeHtml(stage.id)}">
            ${drop && drop.count !== 0 ? `<p class="flow-drop" title="${escapeHtml(reasons)}">${drop.count !== null && drop.count !== undefined ? `<strong>${escapeHtml(formatNumber(drop.count))}건</strong> ` : ""}${escapeHtml(drop.text)}${reasons ? ` <span class="muted">(${escapeHtml(reasons)})</span>` : ""}</p>` : `<p class="flow-drop flow-drop-empty"></p>`}
            <a class="flow-card" href="${escapeHtml(stage.link || "/")}">
                <span class="flow-label">${escapeHtml(stage.label)}</span>
                <strong class="flow-count">${known ? escapeHtml(formatNumber(stage.count)) : "—"}</strong>
                <span class="flow-bar"><span class="flow-fill" data-count="${known ? Number(stage.count) || 0 : 0}"></span></span>
                ${verdicts}
                ${stage.detail ? `<span class="flow-detail">${escapeHtml(stage.detail)}</span>` : ""}
                ${stage.id === "raw" ? flowSparkline(data.per_minute || []) : ""}
                ${stage.extra?.deep_scan_calls ? `<span class="flow-detail">심층 점검 분석 ${escapeHtml(formatNumber(stage.extra.deep_scan_calls))}건 제외</span>` : ""}
            </a>
            ${stage.switch === "source" ? `<button type="button" class="flow-switch-link" data-flow-select="source">출처별로 보기 ↓</button>` : ""}
        </li>`;
    }).join("") || `<li class="muted">표시할 흐름이 없습니다.</li>`;
    const scale = Math.log10(max + 1);
    list.querySelectorAll(".flow-fill").forEach((fill) => {
        const count = Number(fill.dataset.count) || 0;
        fill.style.width = `${count ? Math.max(4, (Math.log10(count + 1) / scale) * 100) : 0}%`;
    });
    list.querySelectorAll(".flow-verdicts").forEach((bar) => {
        const parts = [...bar.querySelectorAll(".flow-verdict")];
        const total = parts.reduce((sum, part) => sum + (Number(part.dataset.share) || 0), 0);
        parts.forEach((part) => {
            const share = Number(part.dataset.share) || 0;
            part.style.width = total ? `${(share / total) * 100}%` : "0";
        });
    });
    const updated = root.querySelector("[data-flow-updated]");
    if (updated && data.window?.end) {
        updated.textContent = `${new Date(data.window.end).toLocaleTimeString("ko-KR", { hour12: false })} 기준`;
    }
}

// 출처 흐름: sensor -> detection type -> priority, drawn as a Sankey (or a
// table). Same panel and window as 처리 흐름; colours follow the source.
const SOURCE_FORMAT_KEY = "hawki.dashboard.sourceFormat";
const SOURCE_SLOTS = ["web", "modsecurity", "suricata", "ssh", "vulnerability", "system", "other"];

function storedChoice(key, allowed, fallback) {
    try {
        const value = window.localStorage.getItem(key);
        return allowed.includes(value) ? value : fallback;
    } catch {
        return fallback;
    }
}

function storeChoice(key, value) {
    try {
        window.localStorage.setItem(key, value);
    } catch {
        /* private mode: the choice is simply not remembered */
    }
}

function sankeyLayout(data, width, height) {
    const nodes = (data.nodes || []).map((node) => ({ ...node }));
    const links = (data.links || []).map((link) => ({ ...link }));
    const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]));
    // A type's ribbons onward take the colour of its largest source.
    const mainSource = {};
    links.filter((link) => link.from.startsWith("s:")).forEach((link) => {
        if (!mainSource[link.to] || link.value > mainSource[link.to].value) mainSource[link.to] = link;
    });
    const columns = [0, 1, 2].map((column) => nodes.filter((node) => node.column === column));
    const top = 34;
    const gap = 8;
    const labelRoom = 34; // two label lines beside a node
    const xs = [width * 0.22, width * 0.52, width * 0.80];
    // Small nodes still need room for their labels: each node takes at least
    // labelRoom, and the scale shrinks until every column fits.
    const fits = (scale) => columns.every((column) =>
        column.reduce((sum, node) => sum + Math.max(node.value * scale, labelRoom) + gap, top) <= height);
    let scale = (height - top) / Math.max(1, ...columns.map((column) => column.reduce((sum, node) => sum + node.value, 0)));
    for (let tries = 0; tries < 40 && !fits(scale); tries += 1) scale *= 0.92;
    columns.forEach((column, index) => {
        let y = top;
        column.forEach((node) => {
            node.h = Math.max(2, node.value * scale);
            const room = Math.max(node.h, labelRoom);
            node.x = xs[index];
            node.y = y + (room - node.h) / 2;
            node.outOffset = 0;
            node.inOffset = 0;
            y += room + gap;
        });
    });
    links.forEach((link) => {
        const from = nodeById[link.from];
        const to = nodeById[link.to];
        const h = Math.max(1, link.value * scale);
        link.y0 = from.y + from.outOffset;
        link.y1 = to.y + to.inOffset;
        link.h = h;
        link.x0 = from.x + 12;
        link.x1 = to.x;
        from.outOffset += h;
        to.inOffset += h;
        link.source = from.column === 0 ? from.key : (mainSource[from.id]?.from || "s:other").slice(2);
    });
    return { nodes, links, xs };
}

function sourceSlot(key) {
    const index = SOURCE_SLOTS.indexOf(key);
    return index >= 0 ? index + 1 : SOURCE_SLOTS.length;
}

function renderSourceSankey(target, data) {
    if (!data.links?.length) {
        target.innerHTML = `<p class="muted">최근 24시간 경보가 없습니다.</p>`;
        return;
    }
    const width = 1080;
    const height = 460;
    const { nodes, links, xs } = sankeyLayout(data, width, height);
    const ribbon = (link) => {
        const xm = (link.x0 + link.x1) / 2;
        return `M${link.x0},${link.y0} C${xm},${link.y0} ${xm},${link.y1} ${link.x1},${link.y1} L${link.x1},${link.y1 + link.h} C${xm},${link.y1 + link.h} ${xm},${link.y0 + link.h} ${link.x0},${link.y0 + link.h} Z`;
    };
    const name = Object.fromEntries(nodes.map((node) => [node.id, node.label]));
    const ribbons = links.map((link) => `<path class="sankey-link src-${sourceSlot(link.source)}${link.from.startsWith("t:") ? " second" : ""}" d="${ribbon(link)}"><title>${escapeHtml(`${name[link.from]} → ${name[link.to]} · ${formatNumber(link.value)}건`)}</title></path>`).join("");
    const nodeMarks = nodes.map((node) => {
        const cls = node.column === 0 ? `src-${sourceSlot(node.key)}` : (node.key === "P1" ? "p1" : node.column === 1 ? "mid" : "target");
        const labelX = node.column === 0 ? node.x - 10 : node.x + 22;
        const anchor = node.column === 0 ? "end" : "start";
        const center = node.y + node.h / 2;
        const href = node.column === 1
            ? (node.key === "cve" ? "/alerts?category=vulnerability&range=24h&status=all" : "/alerts?category=all&range=24h&status=all")
            : node.column === 2 && node.key !== "below_8" && node.key !== "unscored" ? "/alerts?min_level=8&range=24h&category=all&status=all" : "";
        const label = `<text x="${labelX}" y="${center - 7}" text-anchor="${anchor}" class="sankey-label${node.column === 1 ? " halo" : ""}">${escapeHtml(node.label)}</text>
            <text x="${labelX}" y="${center + 10}" text-anchor="${anchor}" class="sankey-value${node.column === 1 ? " halo" : ""}">${escapeHtml(formatNumber(node.value))}건</text>`;
        const mark = `<rect class="sankey-node ${cls}" x="${node.x}" y="${node.y}" width="12" height="${node.h}" rx="3"><title>${escapeHtml(`${node.label} · ${formatNumber(node.value)}건`)}</title></rect>`;
        return href ? `<a href="${href}">${mark}${label}</a>` : `${mark}${label}`;
    }).join("");
    const heads = [["출처", xs[0] + 6, "end"], ["탐지 유형", xs[1] + 6, "middle"], ["우선순위", xs[2], "start"]]
        .map(([text, x, anchor]) => `<text x="${x}" y="16" text-anchor="${anchor}" class="sankey-head">${text}</text>`).join("");
    target.innerHTML = `<svg class="sankey" viewBox="0 0 ${width} ${height}" role="img" aria-label="출처에서 탐지 유형, 우선순위로 이어지는 최근 24시간 경보 흐름">${heads}${ribbons}${nodeMarks}</svg>`;
}

function heatClass(value) {
    if (!value) return "hm-0";
    if (value >= 300) return "hm-5";
    if (value >= 150) return "hm-4";
    if (value >= 80) return "hm-3";
    if (value >= 30) return "hm-2";
    return "hm-1";
}

function renderSourceTable(target, data) {
    const table = data.table || {};
    const columns = table.columns || [];
    const rows = table.rows || [];
    if (!rows.length) {
        target.innerHTML = `<p class="muted">최근 24시간 경보가 없습니다.</p>`;
        return;
    }
    const totals = table.column_totals || {};
    target.innerHTML = `<div class="heat-wrap"><table class="heat">
        <thead><tr><th scope="col">출처</th>${columns.map((column) => `<th scope="col">${escapeHtml(column.label)}</th>`).join("")}<th scope="col">합계</th><th scope="col">레벨 8 이상</th></tr></thead>
        <tbody>${rows.map((row) => `<tr><th scope="row"><span class="heat-swatch src-${sourceSlot(row.source)}"></span>${escapeHtml(row.label)}</th>
            ${columns.map((column) => {
                const value = Number(row.cells[column.key]) || 0;
                return `<td class="hm ${heatClass(value)}">${value ? escapeHtml(formatNumber(value)) : "·"}</td>`;
            }).join("")}
            <td class="heat-total">${escapeHtml(formatNumber(row.total))}</td><td class="heat-total">${escapeHtml(formatNumber(row.level_8_plus || 0))}</td></tr>`).join("")}
        <tr class="heat-sum"><th scope="row">합계</th>${columns.map((column) => `<td>${escapeHtml(formatNumber(totals[column.key] || 0))}</td>`).join("")}<td class="heat-total">${escapeHtml(formatNumber(data.total || 0))}</td><td class="heat-total">${escapeHtml(formatNumber(data.level8_total || 0))}</td></tr>
        </tbody></table></div>
        <p class="heat-legend"><span class="hm-1"></span>1–29 <span class="hm-2"></span>30–79 <span class="hm-3"></span>80–149 <span class="hm-4"></span>150–299 <span class="hm-5"></span>300+</p>`;
}

function renderSourceFlow(data) {
    const root = byId("dashboard-flow");
    if (!root) return;
    const caption = root.querySelector("[data-source-flow-caption]");
    if (caption) caption.textContent = `Wazuh 경보 ${formatNumber(data.total || 0)}건 · 레벨 8 이상 ${formatNumber(data.level8_total || 0)}건`;
    renderSourceSankey(root.querySelector("[data-source-flow-chart]"), data);
    renderSourceTable(root.querySelector("[data-source-flow-table]"), data);
    const bridge = root.querySelector("[data-source-flow-bridge]");
    if (bridge) {
        const unscored = Math.max((data.level8_total || 0) - (data.scored || 0), 0);
        bridge.innerHTML = `P1·P2 ${escapeHtml(formatNumber(data.urgent || 0))}건 → <a href="/auto-reports?range=24h">자동 선별 ${escapeHtml(formatNumber(data.selected_reports || 0))}건</a>${unscored ? ` · 우선순위 미계산 ${escapeHtml(formatNumber(unscored))}건` : ""}`;
    }
}

// 처리 흐름 and 출처 흐름 are shown together; "출처별로 보기" scrolls down.
function showFlowView(view) {
    const root = byId("dashboard-flow");
    if (!root) return;
    root.querySelector(`[data-flow-pane="${view}"]`)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showSourceFormat(format, remember = true) {
    const root = byId("dashboard-flow");
    if (!root) return;
    root.querySelector("[data-source-flow-chart]").hidden = format !== "chart";
    root.querySelector("[data-source-flow-table]").hidden = format !== "table";
    root.querySelectorAll("[data-source-format]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.sourceFormat === format)));
    if (remember) storeChoice(SOURCE_FORMAT_KEY, format);
}

async function loadSourceFlow() {
    const root = byId("dashboard-flow");
    if (!root) return;
    try {
        renderSourceFlow(await api("/api/dashboard/source-flow"));
        root.dataset.sourceLoaded = "1";
    } catch (error) {
        const chart = root.querySelector("[data-source-flow-chart]");
        if (chart) chart.innerHTML = `<p class="muted">출처 흐름을 불러오지 못했습니다 · ${escapeHtml(error.message)}</p>`;
    }
}

function initFlowPanel() {
    const root = byId("dashboard-flow");
    if (!root || root.dataset.flowReady) return;
    root.dataset.flowReady = "1";
    root.addEventListener("click", (event) => {
        const select = event.target.closest("[data-flow-select]");
        if (select) {
            event.preventDefault();
            showFlowView(select.dataset.flowSelect);
            return;
        }
        const format = event.target.closest("[data-source-format]");
        if (format) showSourceFormat(format.dataset.sourceFormat);
    });
    // A narrow screen cannot read a Sankey: the table is shown instead.
    const narrow = window.matchMedia("(max-width: 720px)").matches;
    showSourceFormat(narrow ? "table" : storedChoice(SOURCE_FORMAT_KEY, ["chart", "table"], "chart"), false);
}

async function loadDashboardFlow() {
    const root = byId("dashboard-flow");
    if (!root) return;
    initFlowPanel();
    try {
        renderDashboardFlow(await api("/api/dashboard/flow"));
    } catch (error) {
        const list = root.querySelector("[data-flow-stages]");
        if (list) list.innerHTML = `<li class="muted">처리 흐름을 불러오지 못했습니다 · ${escapeHtml(error.message)}</li>`;
    }
    loadSourceFlow();
    clearTimeout(flowTimer);
    flowTimer = setTimeout(() => {
        if (document.visibilityState === "visible") loadDashboardFlow();
        else document.addEventListener("visibilitychange", loadDashboardFlow, { once: true });
    }, FLOW_REFRESH_MS);
}

const CTI_STATE = {
    ok: ["정상", "ok"],
    stale: ["오래됨", "warn"],
    empty: ["비어 있음", "warn"],
    no_key: ["키 없음 (건너뜀)", "muted"],
    error: ["가져오기 실패", "bad"],
    missing: ["아직 안 받음", "muted"],
};

function shortTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return date.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
}

// 대시보드 CTI 카드: what each feed holds, when it was refreshed, and how
// many of the last 24 hours' alerts came from a listed address.
async function loadDashboardCti() {
    const root = byId("dashboard-cti");
    if (!root) return;
    let data;
    try {
        data = await api("/api/threat-intel/status");
    } catch (error) {
        root.querySelector("[data-cti-summary]").textContent = `확인 실패 · ${error.message}`;
        return;
    }
    const feeds = data.feeds || [];
    const total = feeds.reduce((sum, feed) => sum + (Number(feed.indicators) || 0), 0);
    const healthy = feeds.filter((feed) => feed.state === "ok").length;
    root.querySelector("[data-cti-summary]").textContent = data.configured
        ? `지표 ${formatNumber(total)}개 · 정상 피드 ${healthy}/${feeds.length}`
        : "피드 없음 · tools/import_cti.py 실행 필요";
    root.querySelector("[data-cti-feeds]").innerHTML = feeds.map((feed) => {
        const [label, tone] = CTI_STATE[feed.state] || [feed.state, "muted"];
        const refreshed = feed.generated_at ? `${shortTime(feed.generated_at)} 갱신` : "";
        return `<li title="${escapeHtml(feed.message || feed.kind || "")}">
            <span class="cti-dot cti-${escapeHtml(tone)}"></span>
            <strong>${escapeHtml(feed.label)}</strong>
            <span class="muted">${escapeHtml(feed.kind || "")}</span>
            <span class="cti-count">${feed.indicators ? `지표 ${formatNumber(feed.indicators)}` : ""}${refreshed ? ` · ${escapeHtml(refreshed)}` : ""}</span>
            <span class="cti-state cti-${escapeHtml(tone)}">${escapeHtml(label)}</span>
        </li>`;
    }).join("");
    const matches = data.matches_24h;
    const target = root.querySelector("[data-cti-matches]");
    if (!matches) {
        target.textContent = "";
    } else if (matches.error) {
        target.textContent = `최근 24시간 일치 확인 실패 · ${matches.error}`;
    } else if (!matches.alerts) {
        target.textContent = "최근 24시간 CTI 일치 출발지 없음";
    } else {
        const top = (matches.top || []).slice(0, 3).map((item) =>
            `<a href="/alerts?range=24h&amp;category=all&amp;q=${encodeURIComponent(item.ip)}">${escapeHtml(item.ip)}</a> ${escapeHtml(item.verdict === "malicious" ? "악성" : "의심")} · 경보 ${escapeHtml(formatNumber(item.alerts))}`).join(" / ");
        target.innerHTML = `최근 24시간 <strong>경보 ${escapeHtml(formatNumber(matches.alerts))}건</strong>이 CTI 등재 주소 ${escapeHtml(matches.addresses)}곳에서 옴 · ${top}`;
    }
}

// One handler for every row: opens the evaluation under the row and asks
// the runner for its job state; a second click closes it and stops polling.
document.addEventListener("click", (event) => {
    const button = event.target.closest?.(".rt-expand");
    if (!button) return;
    const detail = button.closest(".rt-recent-item")?.querySelector(".rt-recent-detail");
    if (!detail) return;
    const open = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!open));
    button.textContent = open ? "결과 보기" : "접기";
    if (open) {
        detail.hidden = true;
        detail.innerHTML = "";
        return;
    }
    window.HawkiRedteam?.render(detail, {
        analysisId: button.dataset.rtAnalysis,
        decision: button.dataset.rtDecision,
        caption: button.dataset.rtCaption || "대시보드에서 확인",
    });
});


const AGENT_GREETING = "모드를 고르고 경보·증거·지표 또는 궁금한 점을 적어 주세요. 실제 변경을 일으키는 결과는 제안 상태로만 올라갑니다.";

const modeTitles = {
    conversation: "일반 대화",
    alert_summary: "경보 설명",
    log_search: "로그 검색",
    file_hunt: "의심 파일 추적",
    velociraptor_response: "Velociraptor 호스트 대응",
    suricata_rule: "Suricata 룰",
    incident_report: "사건 보고서",
};

const modePlaceholders = {
    conversation: "메시지를 입력하세요.",
    alert_summary: "경보를 고르거나 경보 내용을 붙여넣으세요. 심각도, 증거, 공격 맥락, 다음 확인 순서를 물어볼 수 있습니다.",
    log_search: "찾으려는 이벤트나 지표를 적어 주세요. 관련 사용자, 호스트, IP, 프로세스, 예상되는 동작을 함께 적으면 좋습니다.",
    file_hunt: "의심스러운 파일이나 지표를 적어 주세요. 해시, 경로, 파일명, 서명자, 관찰된 동작을 함께 적으면 좋습니다.",
    velociraptor_response: "필요한 호스트 조치를 적어 주세요. 증거 수집, 프로세스 종료, 격리, 원복 등이 있습니다.",
    suricata_rule: "탐지하거나 차단할 트래픽·행위를 적어 주세요. 프로토콜, 방향, 주소, 포트, 조치를 포함해 주세요.",
    incident_report: "사건 내용과 필요한 보고서를 적어 주세요. 보고 대상, 시간 흐름, 영향, 증거, 아직 미해결인 부분을 포함해 주세요.",
};
function agentSessionId() {
    if (window.crypto?.randomUUID) return window.crypto.randomUUID();
    return `chat-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function emptyAgentContext() {
    return {
        host: "",
        incident: "",
        index: "logs-*",
        time_range: "now-1h to now",
    };
}

function createAgentSession(mode = state.agentMode, context = {}, persist = true) {
    const now = new Date().toISOString();
    const session = {
        id: agentSessionId(),
        title: "새 분석",
        mode: modeTitles[mode] ? mode : "alert_summary",
        history: [],
        transcript: [],
        context: { ...emptyAgentContext(), ...context },
        lastResult: null,
        createdAt: now,
        updatedAt: now,
    };
    state.agentSessions.unshift(session);
    state.currentAgentSessionId = session.id;
    if (persist) saveAgentSessions();
    return session;
}

function normalizeStoredAgentSession(value) {
    if (!value || typeof value !== "object" || typeof value.id !== "string") return null;
    const mode = modeTitles[value.mode] ? value.mode : "alert_summary";
    const history = Array.isArray(value.history)
        ? value.history
            .filter((item) => item && ["user", "assistant"].includes(item.role) && typeof item.content === "string")
            .slice(-16)
        : [];
    const transcript = Array.isArray(value.transcript)
        ? value.transcript
            .filter((item) => item && ["user", "assistant"].includes(item.role) && typeof item.text === "string")
            .map((item) => ({
                id: typeof item.id === "string" ? item.id : agentSessionId(),
                role: item.role,
                text: item.text,
                meta: typeof item.meta === "string" ? item.meta : "",
                mode: modeTitles[item.mode] ? item.mode : mode,
                suricataAction: item.suricataAction && typeof item.suricataAction === "object"
                    ? item.suricataAction
                    : null,
                suricataStaged: Boolean(item.suricataStaged),
            }))
            .slice(-50)
        : [];
    return {
        id: value.id,
        title: String(value.title || "저장된 분석").slice(0, 80),
        mode,
        history,
        transcript,
        context: { ...emptyAgentContext(), ...(value.context && typeof value.context === "object" ? value.context : {}) },
        lastResult: value.lastResult && typeof value.lastResult === "object" ? value.lastResult : null,
        createdAt: value.createdAt || new Date().toISOString(),
        updatedAt: value.updatedAt || value.createdAt || new Date().toISOString(),
    };
}

async function loadAgentSessions() {
    state.agentSessions = [];
    state.currentAgentSessionId = null;
    try {
        const data = await api("/api/chat-sessions");
        state.agentSessions = Array.isArray(data.sessions)
            ? data.sessions.map(normalizeStoredAgentSession).filter(Boolean).slice(0, 40)
            : [];
        if (state.agentSessions.length) {
            state.currentAgentSessionId = state.agentSessions[0].id;
        }
    } catch (error) {
        toast(error.message);
    }
}

async function persistAgentSessionNow(session) {
    if (!session) return;
    try {
        const data = await api("/api/chat-sessions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(session),
        });
        if (data.updatedAt) session.updatedAt = data.updatedAt;
    } catch (error) {
        toast(`대화 기록 저장 실패: ${error.message}`);
    }
}

function saveAgentSessions() {
    const session = currentAgentSession();
    if (!session) return;
    clearTimeout(state.agentSaveTimer);
    state.agentSaveTimer = setTimeout(() => {
        persistAgentSession(session);
    }, 250);
}

function currentAgentSession() {
    return state.agentSessions.find((item) => item.id === state.currentAgentSessionId) || null;
}

function localDateTimeValue(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const offset = date.getTimezoneOffset();
    return new Date(date.getTime() - offset * 60_000).toISOString().slice(0, 16);
}

function defaultAgentTimeWindow() {
    const end = new Date();
    const start = new Date(end.getTime() - 60 * 60 * 1000);
    return {
        start: localDateTimeValue(start),
        end: localDateTimeValue(end),
    };
}

function timeRangeFromInputs(startValue, endValue) {
    const start = String(startValue || "").trim();
    const end = String(endValue || "").trim();
    if (start && end) return `${start} to ${end}`;
    if (start) return `${start} onward`;
    if (end) return `until ${end}`;
    return "now-1h to now";
}

function selectedAgentAlert() {
    const alertId = byId("agent-alert-id")?.value || "";
    return state.agentAlerts.find((alert) => String(alert.id) === alertId) || null;
}

function readModeContext(mode = state.agentMode) {
    if (mode === "conversation") return {};
    if (mode === "alert_summary") {
        const alert = selectedAgentAlert();
        const selectedHost = byId("agent-alert-host")?.value.trim() || "";
        return {
            host: alert?.host || selectedHost,
            incident: alert?.id || "",
            alert_id: alert?.id || "",
            alert_title: alert?.title || "",
            alert_summary: alert?.summary || "",
            alert_severity: alert?.severity || "",
            alert_status: alert?.status || "",
            time_range: "alert history",
        };
    }

    if (mode === "log_search") {
        const start = byId("agent-log-start")?.value || "";
        const end = byId("agent-log-end")?.value || "";
        return {
            index: byId("agent-log-index")?.value.trim() || "logs-*",
            start_time: start,
            end_time: end,
            time_range: timeRangeFromInputs(start, end),
        };
    }

    if (mode === "file_hunt") {
        return {
            host: byId("agent-hunt-host")?.value.trim() || "",
        };
    }

    if (mode === "velociraptor_response") {
        return {
            host: byId("agent-response-host")?.value.trim() || "",
            incident: byId("agent-response-incident")?.value.trim() || "",
        };
    }

    if (mode === "incident_report") {
        const start = byId("agent-report-start")?.value || "";
        const end = byId("agent-report-end")?.value || "";
        return {
            host: byId("agent-report-host")?.value.trim() || "",
            incident: byId("agent-report-incident")?.value.trim() || "",
            start_time: start,
            end_time: end,
            time_range: timeRangeFromInputs(start, end),
        };
    }

    return {};
}

function readAgentWorkspaceContext() {
    return {
        mode_contexts: Object.fromEntries(
            Object.keys(modeTitles).map((mode) => [mode, readModeContext(mode)]),
        ),
    };
}

function readAgentContext() {
    return readModeContext(state.agentMode);
}

function applyModeContext(mode, context = {}) {
    if (mode === "alert_summary") {
        if (byId("agent-alert-host")) byId("agent-alert-host").value = context.host || "";
        renderAgentAlertOptions(context.incident || context.alert_id || "");
        return;
    }

    if (mode === "log_search") {
        const defaults = defaultAgentTimeWindow();
        if (byId("agent-log-index")) byId("agent-log-index").value = context.index || "logs-*";
        if (byId("agent-log-start")) byId("agent-log-start").value = context.start_time || defaults.start;
        if (byId("agent-log-end")) byId("agent-log-end").value = context.end_time || defaults.end;
        return;
    }

    if (mode === "file_hunt" && byId("agent-hunt-host")) {
        byId("agent-hunt-host").value = context.host || "";
        return;
    }

    if (mode === "velociraptor_response") {
        if (byId("agent-response-host")) byId("agent-response-host").value = context.host || "";
        if (byId("agent-response-incident")) byId("agent-response-incident").value = context.incident || "";
        return;
    }

    if (mode === "incident_report") {
        if (byId("agent-report-host")) byId("agent-report-host").value = context.host || "";
        if (byId("agent-report-incident")) byId("agent-report-incident").value = context.incident || "";
        if (byId("agent-report-start")) byId("agent-report-start").value = context.start_time || "";
        if (byId("agent-report-end")) byId("agent-report-end").value = context.end_time || "";
    }
}

function applyAgentContext(context = {}) {
    const modeContexts = context.mode_contexts && typeof context.mode_contexts === "object"
        ? context.mode_contexts
        : null;

    Object.keys(modeTitles).forEach((mode) => {
        applyModeContext(mode, modeContexts?.[mode] || {});
    });

    if (!modeContexts) {
        applyModeContext(state.agentMode, context);
    }
}

function renderAgentModeContext() {
    document.querySelectorAll("[data-mode-context]").forEach((section) => {
        section.hidden = section.dataset.modeContext !== state.agentMode;
    });
    const container = byId("agent-mode-context");
    if (container) {
        container.hidden = ["suricata_rule", "conversation"].includes(state.agentMode);
    }
}

function renderAgentHostOptions() {
    const hosts = [...new Set(
        state.agentAlerts
            .map((alert) => String(alert.host || "").trim())
            .filter(Boolean),
    )].sort((a, b) => a.localeCompare(b));

    const hostSelect = byId("agent-alert-host");
    const currentHost = hostSelect?.value || "";
    if (hostSelect) {
        hostSelect.innerHTML = [
            '<option value="">호스트 전체</option>',
            ...hosts.map((host) => `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`),
        ].join("");
        if (hosts.includes(currentHost)) hostSelect.value = currentHost;
    }

    const datalist = byId("agent-host-options");
    if (datalist) {
        datalist.innerHTML = hosts
            .map((host) => `<option value="${escapeHtml(host)}"></option>`)
            .join("");
    }
}

function renderAgentAlertOptions(preferredAlertId = "") {
    const select = byId("agent-alert-id");
    if (!select) return;

    const selectedHost = byId("agent-alert-host")?.value || "";
    const search = byId("agent-alert-search")?.value.trim().toLowerCase() || "";
    const current = preferredAlertId || select.value;

    const filtered = state.agentAlerts.filter((alert) => {
        if (selectedHost && String(alert.host || "") !== selectedHost) return false;
        if (!search) return true;
        const haystack = [
            alert.id,
            alert.title,
            alert.summary,
            alert.host,
            alert.severity,
            alert.status,
        ].join(" ").toLowerCase();
        return haystack.includes(search);
    });

    select.innerHTML = [
        '<option value="">경보를 선택하세요</option>',
        ...filtered.map((alert) => {
            const label = `${alert.id} · ${severityLabel(alert.severity || "")} · ${alert.title}`;
            return `<option value="${escapeHtml(alert.id)}">${escapeHtml(label)}</option>`;
        }),
    ].join("");

    if (filtered.some((alert) => String(alert.id) === String(current))) {
        select.value = String(current);
    }
}

async function loadAgentAlertContext() {
    try {
        const data = await api("/api/alerts?category=all&range=7d&sort=priority");
        state.agentAlerts = Array.isArray(data.alerts) ? data.alerts : [];
        renderAgentHostOptions();
        renderAgentAlertOptions();
    } catch (error) {
        state.agentAlerts = [];
        renderAgentHostOptions();
        renderAgentAlertOptions();
    }
}

function updateCurrentAgentSession() {
    const session = currentAgentSession();
    if (!session) return;
    session.mode = state.agentMode;
    session.context = readAgentWorkspaceContext();
    session.history = state.history.slice(-16);
    session.lastResult = state.lastAgentResult;
    session.updatedAt = new Date().toISOString();
    saveAgentSessions();
    renderAgentHistory();
}

function deriveAgentSessionTitle(message) {
    const clean = String(message || "").replace(/\s+/g, " ").trim();
    if (!clean) return "새 분석";
    return clean.length > 48 ? `${clean.slice(0, 47)}…` : clean;
}

function formatAgentHistoryTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
        return date.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", hour12: false });
    }
    return date.toLocaleDateString("ko-KR", { month: "short", day: "numeric" });
}

function renderAgentHistory() {
    const container = byId("agent-history-list");
    if (!container) return;
    if (!state.agentSessions.length) {
        container.innerHTML = `<div class="empty-state">아직 대화가 없습니다.</div>`;
        return;
    }
    container.innerHTML = state.agentSessions.map((session) => `
        <div class="agent-history-entry ${session.id === state.currentAgentSessionId ? "active" : ""}">
            <button class="agent-history-select" type="button" data-session-id="${escapeHtml(session.id)}">
                <span class="agent-history-mode">${escapeHtml(modeTitles[session.mode] || session.mode)}</span>
                <strong>${escapeHtml(session.title)}</strong>
                <small>${escapeHtml(formatAgentHistoryTime(session.updatedAt))}</small>
            </button>
            <button class="agent-history-delete" type="button" data-delete-session="${escapeHtml(session.id)}" aria-label="${escapeHtml(session.title)} 삭제" title="대화 삭제">×</button>
        </div>
    `).join("");

    container.querySelectorAll("[data-session-id]").forEach((button) => {
        button.addEventListener("click", () => selectAgentSession(button.dataset.sessionId));
    });
    container.querySelectorAll("[data-delete-session]").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.stopPropagation();
            deleteAgentSession(button.dataset.deleteSession);
        });
    });
}

function setAgentMode(mode, persist = true) {
    if (!modeTitles[mode]) return;
    state.agentMode = mode;
    document.querySelectorAll("[data-agent-mode]").forEach((button) => {
        const active = button.dataset.agentMode === mode;
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", String(active));
    });
    renderAgentModeContext();
    renderAgentStarters();
    const input = byId("agent-input");
    if (input) {
        input.placeholder = modePlaceholders[mode] || "요청 내용을 입력하세요…";
    }
    if (persist) updateCurrentAgentSession();
}

function appendAgentMessage(role, text, meta = "", options = {}) {
    const messageMode = modeTitles[options.mode] ? options.mode : state.agentMode;
    const modeLabel = modeTitles[messageMode] || messageMode;
    const item = document.createElement("div");
    item.className = `message ${role}`;
    item.dataset.messageId = options.messageId || "";
    item.dataset.messageMode = messageMode;
    item.innerHTML = `
        <span class="avatar">${role === "assistant" ? "H" : "U"}</span>
        <div class="message-shell">
            <strong>
                <span class="message-mode-dot mode-${escapeHtml(messageMode)}"
                    title="${escapeHtml(modeLabel)}"
                    aria-label="${escapeHtml(modeLabel)}"></span>
                <span>${role === "assistant" ? "HAW-KI" : "나"}${meta ? ` · ${escapeHtml(meta)}` : ""}</span>
            </strong>
            <div class="message-content markdown-body"></div>
        </div>`;
    const content = item.querySelector(".message-content");
    content.innerHTML = renderMarkdown(text);
    enhanceRenderedContent(content);

    if (role === "assistant" && options.suricataAction) {
        attachSuricataTransferControl(
            item,
            options.suricataAction,
            Boolean(options.suricataStaged),
            options.messageId || "",
        );
    }

    byId("agent-messages").querySelector(".agent-starters")?.remove();
    byId("agent-messages").appendChild(item);
    byId("agent-messages").scrollTop = byId("agent-messages").scrollHeight;
    return item;
}

function addMessage(role, text, meta = "", record = true, options = {}) {
    const messageId = options.messageId || agentSessionId();
    const item = appendAgentMessage(role, text, meta, { ...options, messageId });
    if (record) {
        const session = currentAgentSession();
        if (session) {
            session.transcript.push({
                id: messageId,
                role,
                text,
                meta,
                mode: modeTitles[options.mode] ? options.mode : state.agentMode,
                suricataAction: options.suricataAction || null,
                suricataStaged: Boolean(options.suricataStaged),
            });
            session.transcript = session.transcript.slice(-50);
            session.updatedAt = new Date().toISOString();
            saveAgentSessions();
            renderAgentHistory();
        }
    }
    return item;
}

// 새 대화의 빈 화면: what each mode is good for, as one-click starters.
const AGENT_STARTERS = {
    conversation: [
        "지난 24시간 동안 web-01에서 가장 많이 걸린 룰과 출발지를 정리해 줘",
        "오늘 공격 경보를 시간대별로 요약하고 눈에 띄는 변화를 알려 줘",
        "자산 목록에서 인터넷에 노출된 서버를 알려 줘",
    ],
    alert_summary: [
        "선택한 경보를 설명하고, 오탐일 가능성과 그 근거를 알려 줘",
        "이 경보의 출발지 IP가 다른 호스트에도 접근했는지 정리해 줘",
        "이 경보에서 가장 먼저 확인해야 할 것 세 가지만 알려 줘",
    ],
    log_search: [
        "최근 24시간 web-01에서 403/404를 많이 만든 출발지 IP를 찾는 쿼리를 만들어 줘",
        "/.env, /.git 같은 민감 파일 요청을 찾는 Wazuh 쿼리를 만들어 줘",
        "같은 IP가 짧은 간격으로 반복 요청한 흔적을 찾는 방법을 알려 줘",
    ],
    file_hunt: [
        "웹 서버에서 최근 바뀐 실행 파일을 찾는 수집 계획을 세워 줘",
        "웹 루트에 새로 생긴 PHP 파일을 찾는 Velociraptor 수집을 제안해 줘",
    ],
    velociraptor_response: [
        "web-01에서 스캐닝 이후 침해 여부를 확인할 수집 순서를 제안해 줘",
        "격리 전에 먼저 확보해야 할 증거 목록을 정리해 줘",
    ],
    suricata_rule: [
        "/.env 요청을 탐지하는 Suricata 룰 초안을 만들어 줘",
        "wp-login.php 무차별 요청을 탐지하는 룰을 탐지 전용으로 제안해 줘",
    ],
    incident_report: [
        "오늘 web-01에서 있었던 스캐닝 활동을 사건 보고서로 정리해 줘",
        "최근 P1 경보를 시간 순서대로 요약해 줘",
    ],
};

function renderAgentStarters() {
    const list = byId("agent-messages");
    if (!list) return;
    list.querySelector(".agent-starters")?.remove();
    if (list.querySelector(".message")) return;
    const starters = AGENT_STARTERS[state.agentMode] || [];
    if (!starters.length) return;
    const block = document.createElement("div");
    block.className = "agent-starters";
    block.innerHTML = `
        <p class="agent-starters-title">${escapeHtml(modeTitles[state.agentMode] || "")} · 이렇게 시작해 보세요</p>
        <div class="agent-starter-list">
            ${starters.map((text) => `<button type="button" class="agent-starter">${escapeHtml(text)}</button>`).join("")}
        </div>
        <p class="muted">${escapeHtml(AGENT_GREETING)}</p>`;
    block.querySelectorAll(".agent-starter").forEach((button) => button.addEventListener("click", () => {
        const input = byId("agent-input");
        if (!input) return;
        input.value = button.textContent.trim();
        input.focus();
    }));
    list.appendChild(block);
}

function renderAgentTranscript(session) {
    const list = byId("agent-messages");
    list.innerHTML = "";
    (session.transcript || []).forEach((item) => {
        appendAgentMessage(item.role, item.text, item.meta || "", {
            messageId: item.id || agentSessionId(),
            mode: modeTitles[item.mode] ? item.mode : session.mode,
            suricataAction: item.suricataAction || null,
            suricataStaged: Boolean(item.suricataStaged),
        });
    });
    renderAgentStarters();
    if (conversationPending.has(session.id)) addTyping();
}

function addTyping() {
    const item = document.createElement("div");
    item.className = "message assistant";
    item.id = "agent-typing";
    item.dataset.messageMode = state.agentMode;
    item.innerHTML = `
        <span class="avatar">H</span>
        <div class="message-shell">
            <strong>
                <span class="message-mode-dot mode-${escapeHtml(state.agentMode)}"
                    title="${escapeHtml(modeTitles[state.agentMode] || state.agentMode)}"></span>
                <span>HAW-KI · 분석 중</span>
            </strong>
            <span class="typing"><i></i><i></i><i></i></span>
        </div>`;
    byId("agent-messages").querySelector(".agent-starters")?.remove();
    byId("agent-messages").appendChild(item);
    byId("agent-messages").scrollTop = byId("agent-messages").scrollHeight;
}

function extractSuricataDraft(value) {
    // Remove any Markdown fence label, including plaintext. Detection is based
    // on the rule syntax itself rather than the fence language chosen by the
    // model.
    const source = String(value || "")
        .replace(/```[^\n]*\n?/g, "")
        .replace(/```/g, "")
        .trim();

    // Accept an active rule or a commented draft such as "#alert ..." or
    // "# alert ...". The comment marker is preserved in rawRule.
    const startMatch = source.match(
        /(?:^|\n)([ \t]*)(#\s*)?(alert|drop|reject|pass)\s+[A-Za-z0-9_]+\s+/i,
    );
    if (!startMatch || startMatch.index == null) return null;

    const fullStart = startMatch.index + (startMatch[0].startsWith("\n") ? 1 : 0);
    const lineStart = source.slice(fullStart);
    const actionOffset = lineStart.search(/(?:alert|drop|reject|pass)/i);
    if (actionOffset < 0) return null;

    const commented = Boolean(startMatch[2]);
    const rawCandidate = lineStart.trimStart();
    const activeCandidate = rawCandidate.slice(actionOffset);
    const opening = activeCandidate.indexOf("(");
    if (opening < 0) return null;

    let depth = 0;
    let quote = null;
    let escaped = false;
    let closing = -1;

    for (let index = opening; index < activeCandidate.length; index += 1) {
        const character = activeCandidate[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (character === "\\") {
            escaped = true;
            continue;
        }
        if (quote) {
            if (character === quote) quote = null;
            continue;
        }
        if (character === '"' || character === "'") {
            quote = character;
            continue;
        }
        if (character === "(") depth += 1;
        if (character === ")") {
            depth -= 1;
            if (depth === 0) {
                closing = index;
                break;
            }
        }
    }

    if (closing < 0) return null;

    const activeRule = activeCandidate.slice(0, closing + 1).trim();
    const prefixLength = actionOffset;
    const rawRule = rawCandidate.slice(0, prefixLength + closing + 1).trim();

    return {
        rawRule,
        activeRule,
        commented,
    };
}

function requestedSuricataAction(analystRequest) {
    const requestText = String(analystRequest || "").toLowerCase();
    if (/\b(block|drop|deny|reject|prevent)\b/.test(requestText)) return "blocking";
    if (/\b(alert|detect|monitor|observe|log)\b/.test(requestText)) return "alerting";
    return null;
}

function inspectSuricataDraft(draft, analystRequest = "") {
    if (!draft?.activeRule) return null;

    const normalized = String(draft.activeRule).replace(/\s+/g, " ").trim();
    const headerPattern = /^(alert|drop|reject|pass)\s+[A-Za-z0-9_]+\s+\S+\s+\S+\s+(?:->|<>|<-)\s+\S+\s+\S+\s*\(/i;
    const headerMatch = normalized.match(headerPattern);
    if (!headerMatch || !normalized.endsWith(")")) return null;

    // These fields are sufficient to identify the text as a real Suricata rule
    // draft. It may still be disabled or semantically inconsistent, which is
    // reported as a review warning rather than suppressing the transfer box.
    if (!/\bmsg\s*:\s*["'][^"']+["']\s*;/i.test(normalized)) return null;
    if (!/\bsid\s*:\s*\d+\s*;/i.test(normalized)) return null;
    if (!/\brev\s*:\s*\d+\s*;/i.test(normalized)) return null;

    const generatedAction = headerMatch[1].toLowerCase();
    const requestedAction = requestedSuricataAction(analystRequest);
    const warnings = [];

    if (draft.commented) {
        warnings.push("반환된 룰은 주석 처리되어 비활성 상태입니다.");
    }
    if (
        requestedAction === "blocking" &&
        !["drop", "reject"].includes(generatedAction)
    ) {
        warnings.push(
            `분석가는 차단을 요청했지만 생성된 룰 조치는 ${generatedAction}입니다.`,
        );
    }
    if (requestedAction === "alerting" && generatedAction !== "alert") {
        warnings.push(
            `분석가는 경보 탐지를 요청했지만 생성된 룰 조치는 ${generatedAction}입니다.`,
        );
    }

    return {
        generatedAction,
        requestedAction,
        warnings,
    };
}

function getSuricataAction(result, analystRequest = "") {
    const actions = Array.isArray(result?.actions)
        ? result.actions
        : [];

    const verified = actions.find((action) =>
        action?.type === "suricata_rule" &&
        typeof action?.payload?.rule === "string" &&
        action.payload.rule.trim() &&
        action?.payload?.verification_status === "passed" &&
        action?.payload?.verification?.verification === "PASS"
    );

    if (!verified) return null;

    const warnings = [];

    const requestedAction = String(
        verified?.payload?.requested_action || ""
    ).toLowerCase();

    const enforcementMode = String(
        verified?.payload?.live_enforcement_mode || ""
    ).toLowerCase();

    if (
        ["drop", "reject"].includes(requestedAction) &&
        enforcementMode === "detection_only"
    ) {
        warnings.push(
            "현재 센서는 detection-only이며 실제 차단은 검증되지 않았습니다."
        );
    }

    return {
        ...verified,
        summary: verified.summary ||
            "결정적 검증을 통과한 Suricata 룰입니다.",
        payload: {
            ...verified.payload,
            review_warnings: warnings,
        },
    };
}

function withoutSuricataActions(result) {
    return {
        ...result,
        actions: (Array.isArray(result?.actions) ? result.actions : [])
            .filter((action) => action?.type !== "suricata_rule"),
    };
}

function actionRuleKey(action) {
    return String(action?.payload?.rule || "").trim();
}

function stageRuleInStructuredResults(action, messageId, button) {
    const session = currentAgentSession();
    if (!session || !actionRuleKey(action)) return;

    const base = state.lastAgentResult && typeof state.lastAgentResult === "object"
        ? state.lastAgentResult
        : { answer: "", evidence: [], queries: [], actions: [] };
    const actions = Array.isArray(base.actions) ? [...base.actions] : [];
    if (!actions.some((item) => item?.type === "suricata_rule" && actionRuleKey(item) === actionRuleKey(action))) {
        actions.push(action);
    }

    const stagedResult = { ...base, actions };
    state.lastAgentResult = stagedResult;
    session.lastResult = stagedResult;

    const transcriptItem = session.transcript.find((item) => item.id === messageId);
    if (transcriptItem) transcriptItem.suricataStaged = true;

    session.updatedAt = new Date().toISOString();
    saveAgentSessions();
    renderStructured(stagedResult);

    button.disabled = true;
    button.classList.add("staged");
    button.textContent = "✓";
    button.title = "증거 및 제안 칸에 추가됨";
    button.setAttribute("aria-label", "증거 및 제안 칸에 추가됨");
    toast("Suricata 룰을 증거 및 제안 칸에 추가했습니다");
}

function attachSuricataTransferControl(messageElement, action, staged, messageId) {
    const shell = messageElement.querySelector(".message-shell");
    if (!shell || !actionRuleKey(action)) return;

    const transfer = document.createElement("div");
    transfer.className = "chat-rule-transfer";
    transfer.innerHTML = `
        <div>
            <strong>Suricata 룰 감지됨</strong>
            <span>${staged ? "증거 및 제안 칸에 추가됨" : "이 룰을 증거 및 제안 칸으로 옮겨 검토합니다."}</span>
        </div>
        <button class="chat-rule-transfer-button ${staged ? "staged" : ""}" type="button"
            title="${staged ? "증거 및 제안 칸에 추가됨" : "증거 및 제안 칸에 추가"}"
            aria-label="${staged ? "증거 및 제안 칸에 추가됨" : "Suricata 룰을 증거 및 제안 칸에 추가"}"
            ${staged ? "disabled" : ""}>${staged ? "✓" : "→"}</button>
    `;
    const button = transfer.querySelector(".chat-rule-transfer-button");
    if (!staged) {
        button.addEventListener("click", () => {
            stageRuleInStructuredResults(action, messageId, button);
            const description = transfer.querySelector("span");
            if (description) description.textContent = "증거 및 제안 칸에 추가됨";
        });
    }
    shell.appendChild(transfer);
}

function renderActionRule(action) {
    if (
        action?.type !== "suricata_rule" ||
        typeof action?.payload?.rule !== "string" ||
        !action.payload.rule.trim()
    ) {
        return "";
    }

    return `
        <pre><code class="language-suricata">${escapeHtml(action.payload.rule.trim())}</code></pre>
    `;
}

function renderActionCard(action, index, originMode) {
    const mode = action?.origin_mode || originMode || "alert_summary";
    const modeLabel = modeTitles[mode] || mode;
    return `
        <div class="action-card" data-origin-mode="${escapeHtml(mode)}">
            <div class="action-card-title-row">
                <span class="action-origin-dot mode-${escapeHtml(mode)}"
                    title="작성: ${escapeHtml(modeLabel)}"
                    aria-label="작성: ${escapeHtml(modeLabel)}"></span>
                <strong>${escapeHtml(action.title || action.type)}</strong>
            </div>
            <p>${escapeHtml(action.summary || "")}</p>
            ${renderActionRule(action)}
            <div class="action-meta">
                <span class="tag">${escapeHtml(action.type)}</span>
                <span class="tag">위험도: ${escapeHtml(severityLabel(action.risk || "unknown"))}</span>
            </div>
            <button class="button warning small queue-agent-action" data-index="${index}" type="button">${action?.type === "suricata_rule" ? "Suricata 룰에 저장" : "승인 요청"}</button>
        </div>
    `;
}

function renderStructured(result) {
    if (result?.mode === "conversation") {
        result.actions = [];
        state.lastAgentResult = result;
        const output = byId("agent-structured-output");
        if (output) renderConversationTools(output, result.tool_trace || []);
        return;
    }
    const originMode = result?.mode || currentAgentSession()?.mode || state.agentMode;
    const actionItems = (Array.isArray(result?.actions) ? result.actions : []).map((action) => ({
        ...action,
        origin_mode: action?.origin_mode || originMode,
    }));
    result.actions = actionItems;
    state.lastAgentResult = result;

    const evidenceItems = Array.isArray(result?.evidence) ? result.evidence : [];
    const queryItems = Array.isArray(result?.queries) ? result.queries : [];

    const evidence = evidenceItems
        .map((value) => `<div class="output-item"><p>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</p></div>`)
        .join("") || `<div class="empty-state">별도 증거 항목이 없습니다.</div>`;

    const queries = queryItems
        .map((query) => {
            const language = String(query.language || "plaintext").toLowerCase();
            return `<div class="output-item"><strong>${escapeHtml(query.title || "쿼리")}</strong><span class="tag">${escapeHtml(language)}</span><pre class="query-code"><code class="language-${escapeHtml(language)}">${escapeHtml(query.value || "")}</code></pre></div>`;
        })
        .join("") || `<div class="empty-state">생성된 쿼리가 없습니다.</div>`;

    const actions = actionItems
        .map((action, index) => renderActionCard(action, index, originMode))
        .join("") || `<div class="empty-state">제안된 변경 조치가 없습니다.</div>`;

    const container = byId("agent-structured-output");
    container.className = "structured-output";
    container.innerHTML = `
        <section class="output-section"><h3>증거</h3>${evidence}</section>
        <section class="output-section"><h3>쿼리</h3>${queries}</section>
        <section class="output-section"><h3>조치</h3>${actions}</section>
    `;

    enhanceRenderedContent(container);

    container.querySelectorAll(".queue-agent-action").forEach((button) => {
        button.addEventListener("click", async () => {
            const action = actionItems[Number(button.dataset.index)];
            try {
                if (action?.type === "suricata_rule") {
                    const data =
                        await importVerifiedSuricataRule(action);

                    button.disabled = true;
                    button.textContent = data.reused
                        ? "이미 룰에 있음"
                        : "룰에 저장됨";
                    button.title = (
                        "Suricata 룰에서 검토 후 "
                        + "배포 승인 요청을 진행하세요."
                    );
                    return;
                }

                const source =
                    `agent:${action.origin_mode || originMode}`;

                await queueAction(action, source);

                button.disabled = true;
                button.textContent = "대기 중";
                button.title = "승인 요청됨";
            } catch (error) {
                toast(error.message);
            }
        });
    });

    const session = currentAgentSession();
    if (session) {
        session.lastResult = result;
        session.updatedAt = new Date().toISOString();
        saveAgentSessions();
    }
}

function renderEmptyStructuredOutput() {
    const container = byId("agent-structured-output");
    container.className = "structured-output";
    container.innerHTML = `
        <section class="output-section">
            <h3>증거</h3>
            <div class="empty-state">별도 증거 항목이 없습니다.</div>
        </section>
        <section class="output-section">
            <h3>쿼리</h3>
            <div class="empty-state">생성된 쿼리가 없습니다.</div>
        </section>
        <section class="output-section">
            <h3>조치</h3>
            <div class="empty-state">제안된 변경 조치가 없습니다.</div>
        </section>
    `;
}

function selectAgentSession(sessionId) {
    const session = state.agentSessions.find((item) => item.id === sessionId);
    if (!session) return;
    state.currentAgentSessionId = session.id;
    state.history = session.history.slice(-16);
    state.lastAgentResult = session.lastResult;
    setAgentMode(session.mode, false);
    applyAgentContext(session.context);
    renderAgentModeContext();
    renderAgentTranscript(session);
    if (session.lastResult) renderStructured(session.lastResult);
    else renderEmptyStructuredOutput();
    byId("agent-session-state").textContent = session.title;
    saveAgentSessions();
    renderAgentHistory();
}

async function deleteAgentSession(sessionId) {
    if (conversationPending.has(sessionId)) {
        toast("응답을 받은 뒤에 이 대화를 삭제할 수 있습니다.");
        return;
    }
    try {
        await api(`/api/chat-sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
        });
    } catch (error) {
        toast(error.message);
        return;
    }

    state.agentSessions = state.agentSessions.filter((item) => item.id !== sessionId);
    if (state.currentAgentSessionId === sessionId) {
        const replacement = state.agentSessions[0] || createAgentSession(state.agentMode, {}, false);
        state.currentAgentSessionId = replacement.id;
    }
    renderAgentHistory();
    selectAgentSession(state.currentAgentSessionId);
    saveAgentSessions();
}

function startNewAgentChat(mode = state.agentMode, context = {}) {
    const session = createAgentSession(mode, context, false);
    saveAgentSessions();
    renderAgentHistory();
    selectAgentSession(session.id);
    byId("agent-input").value = "";
    byId("agent-input").focus();
}

async function clearAgentHistory() {
    if (conversationPending.size) {
        toast("진행 중인 응답이 끝난 뒤에 기록을 지울 수 있습니다.");
        return;
    }
    try {
        await api("/api/chat-sessions", { method: "DELETE" });
    } catch (error) {
        toast(error.message);
        return;
    }

    state.agentSessions = [];
    state.currentAgentSessionId = null;
    const session = createAgentSession("alert_summary", {}, false);
    renderAgentHistory();
    selectAgentSession(session.id);
    saveAgentSessions();
}

async function queueAction(action, source) {
    // On an alert page the proposal is tied to that alert, so the alert's
    // data flow capture (⑦ 조치) can show what happened to it.
    const alertId = byId("alert-analysis-root")?.dataset.alertId || "";
    const data = await api("/api/actions/queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(alertId ? { action, source, alert_id: alertId } : { action, source }),
    });
    toast(`${data.action.id} 승인 요청을 올렸습니다.`);
    return data.action;
}

async function importVerifiedSuricataRule(action) {
    const spec = action?.payload?.detection_spec;

    if (
        !spec ||
        spec.schema !== "hawki.detection-spec/v1"
    ) {
        throw new Error(
            "검증된 DetectionSpec이 없습니다."
        );
    }

    const data = await api(
        "/api/rules/import-verified",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                spec,
            }),
        }
    );

    const ruleId = data?.rule?.id || "Suricata 룰";

    toast(
        data.reused
            ? `${ruleId}은(는) 이미 룰 목록에 있습니다.`
            : `${ruleId}을(를) 룰 목록에 저장했습니다.`
    );

    return data;
}



const conversationPending = new Set();
const agentSessionWrites = new Map();

function persistAgentSession(session) {
    if (!session) return Promise.resolve();
    const snapshot = JSON.parse(JSON.stringify(session));
    const previous = agentSessionWrites.get(session.id) || Promise.resolve();
    const task = previous.catch(() => {}).then(() => persistAgentSessionNow(snapshot));
    agentSessionWrites.set(session.id, task);
    const cleanup = () => {
        if (agentSessionWrites.get(session.id) === task) {
            agentSessionWrites.delete(session.id);
        }
    };
    task.then(cleanup, cleanup);
    return task;
}

function renderConversationTools(container, trace) {
    container.replaceChildren();
    const labels = {
        summarize_logs: "로그 집계",
        search_logs: "로그 검색",
        get_alert: "경보 증거",
        list_assets: "자산",
        lookup_indicator: "위협 인텔리전스",
        environment: "환경 설정",
    };
    for (const entry of trace) {
        const item = document.createElement("div");
        item.className = "output-item";
        const heading = document.createElement("strong");
        heading.textContent = `${entry.ref} · ${labels[entry.tool] || entry.tool}`;
        const body = document.createElement("p");
        const result = entry.result || {};
        const statusLabels = { success: "성공", partial: "일부만", failed: "실패", disabled: "검색 꺼짐", invalid_request: "잘못된 요청", duplicate: "중복 요청" };
        const parts = [statusLabels[result.status] || result.status || "알 수 없음"];
        if (result.total_matches != null) parts.push(`일치 ${result.total_matches}건`);
        if (result.returned != null) parts.push(`모델에 ${result.returned}건 제공`);
        if (result.scope) {
            parts.push(result.scope.host, `${result.scope.start} – ${result.scope.end}`);
        }
        if (result.context_truncated || result.content_truncated) {
            parts.push("증거 일부 축약");
        }
        body.textContent = parts.filter(Boolean).join(" · ");
        item.append(heading, body);
        container.appendChild(item);
    }
}

async function sendConversation(message) {
    let session = currentAgentSession();
    if (!session) {
        session = createAgentSession("conversation", readAgentWorkspaceContext(), false);
    }
    const sessionId = session.id;
    const requestId = agentSessionId();
    const context = readAgentContext();
    const history = session.history.slice(-16);
    conversationPending.add(sessionId);
    session.context = readAgentWorkspaceContext();
    session.mode = "conversation";
    if (session.title === "새 분석") session.title = deriveAgentSessionTitle(message);

    session.history = [...history, {role: "user", content: message}].slice(-16);
    session.transcript.push({
        id: requestId, role: "user", text: message,
        meta: "", mode: "conversation", suricataAction: null, suricataStaged: false,
    });
    session.transcript = session.transcript.slice(-50);
    session.updatedAt = new Date().toISOString();
    state.history = session.history.slice();
    renderAgentTranscript(session);
    renderAgentHistory();
    byId("agent-session-state").textContent = session.title;

    try {
        await persistAgentSession(session);
        const result = await api("/api/agent/conversation", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({message, session_id: sessionId, request_id: requestId}),
        });
        const target = state.agentSessions.find(item => item.id === sessionId);
        if (!target) return;

        result.mode = "conversation";
        result.actions = [];
        const answer = result.answer || "응답을 받지 못했습니다.";
        target.transcript.push({
            id: agentSessionId(), role: "assistant", text: answer,
            meta: result.model || "", mode: "conversation",
            suricataAction: null, suricataStaged: false,
        });
        target.transcript = target.transcript.slice(-50);
        if (!result.incomplete) {
            target.history = [
                ...target.history, {role: "assistant", content: answer},
            ].slice(-16);
        }
        target.lastResult = result;
        target.updatedAt = new Date().toISOString();
        await persistAgentSession(target);
    } catch (error) {
        const target = state.agentSessions.find(item => item.id === sessionId);
        if (target) {
            target.transcript.push({
                id: agentSessionId(), role: "assistant", text: error.message,
                meta: "error", mode: "conversation",
                suricataAction: null, suricataStaged: false,
            });
            target.transcript = target.transcript.slice(-50);
            target.updatedAt = new Date().toISOString();
            await persistAgentSession(target);
        }
    } finally {
        conversationPending.delete(sessionId);
        const target = state.agentSessions.find(item => item.id === sessionId);
        if (target && state.currentAgentSessionId === sessionId) {
            state.history = target.history.slice(-16);
            state.lastAgentResult = target.lastResult;
            renderAgentTranscript(target);
            if (target.lastResult) renderStructured(target.lastResult);
            byId("agent-session-state").textContent = target.title;
        }
        renderAgentHistory();
    }
}

async function sendAgent(message) {
    if (conversationPending.has(state.currentAgentSessionId)) {
        byId("agent-input").value = message;
        toast("아직 응답을 기다리는 중입니다.");
        return;
    }
    if (state.agentMode === "conversation") return sendConversation(message);
    const requestMode = state.agentMode;
    let session = currentAgentSession();
    if (!session) {
        session = createAgentSession(state.agentMode, readAgentContext(), false);
        state.currentAgentSessionId = session.id;
    }

    addMessage("user", message, "", true, { mode: state.agentMode });
    state.history.push({ role: "user", content: message });
    session.history = state.history.slice(-16);
    session.context = readAgentWorkspaceContext();
    if (session.title === "새 분석") session.title = deriveAgentSessionTitle(message);
    session.updatedAt = new Date().toISOString();
    saveAgentSessions();
    renderAgentHistory();

    addTyping();
    const context = readAgentContext();
    try {
        const result = await api(requestMode === "conversation" ? "/api/agent/conversation" : "/api/agent/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mode: state.agentMode,
                message,
                context,
                history: state.history.slice(0, -1),
            }),
        });
        byId("agent-typing")?.remove();
        const suricataAction = requestMode === "conversation" ? null : getSuricataAction(result, message);
        const structuredResult = suricataAction ? withoutSuricataActions(result) : result;
        addMessage(
            "assistant",
            result.answer || "응답이 없습니다.",
            result.model,
            true,
            {
                mode: state.agentMode,
                suricataAction,
                suricataStaged: false,
            },
        );
        state.history.push({ role: "assistant", content: result.answer || "" });
        state.history = state.history.slice(-16);
        state.lastAgentResult = structuredResult;
        session.history = state.history;
        session.lastResult = structuredResult;
        session.mode = state.agentMode;
        session.context = readAgentWorkspaceContext();
        session.updatedAt = new Date().toISOString();
        byId("agent-session-state").textContent = session.title;
        saveAgentSessions();
        renderAgentHistory();
        renderStructured(structuredResult);
    } catch (error) {
        byId("agent-typing")?.remove();
        addMessage("assistant", error.message, "오류", true, { mode: state.agentMode });
        state.history.push({ role: "assistant", content: error.message });
        session.history = state.history.slice(-16);
        session.updatedAt = new Date().toISOString();
        saveAgentSessions();
    }
}

async function initAgent() {
    enhanceRenderedContent(byId("agent-messages"));
    await Promise.all([loadAgentSessions(), loadAgentAlertContext()]);

    const params = new URLSearchParams(location.search);
    const requestedMode = modeTitles[params.get("mode")] ? params.get("mode") : null;
    const launchMode = requestedMode || "alert_summary";
    const requestedContext = {
        mode_contexts: {
            [launchMode]: {
                host: params.get("host") || "",
                incident: params.get("incident") || "",
                index: params.get("index") || "logs-*",
                time_range: params.get("time_range") || "now-1h to now",
            },
        },
    };
    const hasLaunchContext = Boolean(
        requestedMode ||
        params.get("host") ||
        params.get("incident") ||
        params.get("prompt")
    );

    if (hasLaunchContext) {
        const session = createAgentSession(requestedMode || "alert_summary", requestedContext, false);
        state.currentAgentSessionId = session.id;
    } else if (!state.currentAgentSessionId) {
        const session = createAgentSession("alert_summary", {}, false);
        state.currentAgentSessionId = session.id;
    }

    renderAgentHistory();
    selectAgentSession(state.currentAgentSessionId);

    byId("agent-mode-list").querySelectorAll("[data-agent-mode]").forEach((button) => {
        button.addEventListener("click", () => setAgentMode(button.dataset.agentMode));
    });
    byId("new-agent-chat").addEventListener("click", () => startNewAgentChat(state.agentMode));
    byId("clear-agent-history").addEventListener("click", clearAgentHistory);

    [
        "agent-alert-id",
        "agent-log-index",
        "agent-log-start",
        "agent-log-end",
        "agent-hunt-host",
        "agent-response-host",
        "agent-response-incident",
        "agent-report-host",
        "agent-report-incident",
        "agent-report-start",
        "agent-report-end",
    ].forEach((id) => {
        byId(id)?.addEventListener("change", updateCurrentAgentSession);
        byId(id)?.addEventListener("blur", updateCurrentAgentSession);
    });

    byId("agent-alert-host")?.addEventListener("change", () => {
        renderAgentAlertOptions();
        updateCurrentAgentSession();
    });
    byId("agent-alert-search")?.addEventListener("input", () => {
        renderAgentAlertOptions();
    });

    byId("agent-form").addEventListener("submit", (event) => {
        event.preventDefault();
        const input = byId("agent-input");
        const text = input.value.trim();
        if (!text) return;
        input.value = "";
        sendAgent(text);
    });
    byId("agent-input").addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            byId("agent-form").requestSubmit();
        }
    });

    if (params.get("prompt")) {
        byId("agent-input").value = params.get("prompt");
        byId("agent-input").focus();
    }

    saveAgentSessions();
}
async function loadAlerts() {
    const count = byId("alert-count");
    const table = byId("alerts-table");

    if (!count || !table) return;

    try {
        await loadAlertsInner();
    } catch (error) {
        count.textContent = "경보를 불러오지 못했습니다";
        table.innerHTML = `
            <div class="empty-state">
                ${escapeHtml(error.message)}
                <br><br>
                서버 로그를 확인하세요:
                <code>docker compose logs hawki-web</code>
            </div>
        `;
    }
}

const ALERT_CATEGORY_NOTES = {
    attack: "CVE 취약점 경보 제외",
    vulnerability: "CVE 취약점 경보 (호스트 화면에서 묶어 보기)",
    all: "모든 경보입니다.",
};
const ALERT_RANGE_LABELS = { "1h": "최근 1시간", "24h": "최근 24시간", "7d": "최근 7일", "30d": "최근 30일", "": "기간 제한 없음" };

function formatAlertTime(value, withSeconds = true) {
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) return value || "—";
    return new Date(timestamp).toLocaleString("ko-KR", {
        year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
        ...(withSeconds ? { second: "2-digit" } : {}), hour12: false,
    });
}

// 같은 룰·출발지·호스트 경보를 한 줄로: the row shows the highest-priority
// (then newest) alert of the group, with how many and over what span.
function groupAlerts(alerts) {
    const groups = new Map();
    alerts.forEach((alert) => {
        const key = [alert.rule_id || alert.title, alert.source_ip || "-", alert.host || "-"].join("|");
        const group = groups.get(key);
        if (!group) {
            groups.set(key, { lead: alert, count: 1, first: alert.time, last: alert.time });
            return;
        }
        group.count += 1;
        if ((Date.parse(alert.time) || 0) < (Date.parse(group.first) || 0)) group.first = alert.time;
        if ((Date.parse(alert.time) || 0) > (Date.parse(group.last) || 0)) group.last = alert.time;
        if (priorityScore(alert) > priorityScore(group.lead)
            || (priorityScore(alert) === priorityScore(group.lead) && (Date.parse(alert.time) || 0) > (Date.parse(group.lead.time) || 0))) {
            group.lead = alert;
        }
    });
    return [...groups.values()];
}

function alertSearchLink(alert) {
    const parts = [];
    if (alert.rule_id) parts.push(`rule.id:"${alert.rule_id}"`);
    if (alert.source_ip) parts.push(`(data.srcip:"${alert.source_ip}" OR data.src_ip:"${alert.source_ip}")`);
    if (alert.host) parts.push(`agent.name:"${alert.host}"`);
    const range = byId("alert-range")?.value ?? "24h";
    const params = new URLSearchParams({
        index: "wazuh-alerts-*",
        query: parts.join(" AND ") || "*",
        start: range ? `now-${range}` : "now-30d",
        end: "now",
        size: "200",
        run: "1",
    });
    return `/logs?${params}`;
}

function renderAlertRow(alert, group = null) {
    const ruleParts = [
        alert.rule_id ? `룰 ${alert.rule_id}` : "",
        alert.mitre && alert.mitre !== "—" ? `MITRE ${alert.mitre}` : "",
        alert.decoder ? `디코더 ${alert.decoder}` : "",
    ].filter(Boolean);
    const repeated = group && group.count > 1;
    const span = repeated
        ? `<p class="alert-repeat"><a href="${escapeHtml(alertSearchLink(alert))}">같은 경보 ${formatNumber(group.count)}건</a> · ${escapeHtml(formatAlertTime(group.first, false))} ~ ${escapeHtml(formatAlertTime(group.last, false))}</p>`
        : "";

    return `
        <div class="alert-row sev-row sev-${alertSeverity(alert).key}${repeated ? " alert-row-grouped" : ""}">
            <span class="alert-time">${escapeHtml(formatAlertTime(alert.time))}${handlingChip(alert)}</span>
            <span class="wazuh-level">${priorityBadge(alert)} ${severityChip(alert)}</span>
            <div class="alert-description">
                <strong>${escapeHtml(alert.title || "Wazuh 경보")}</strong>
                ${alert.summary ? `<p class="muted">${escapeHtml(alert.summary)}</p>` : ""}
                ${span}
                ${alert.groups?.length
                    ? `<div class="action-meta">${alert.groups.slice(0, 4).map((name) => `<span class="tag">${escapeHtml(name)}</span>`).join("")}</div>`
                    : ""}
            </div>
            <span>${escapeHtml(alert.host || "—")}</span>
            <div class="alert-rule-meta">${ruleParts.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>
            <a class="button secondary small" href="/alerts/${encodeURIComponent(alert.id)}">열기</a>
        </div>`;
}

function currentAlertCategory() {
    return document.querySelector(".alert-tab[aria-selected='true']")?.dataset.category || "attack";
}

async function loadAlertsInner() {
    const queryInput = byId("alert-query");
    const levelInput = byId("alert-min-level");
    const count = byId("alert-count");
    const table = byId("alerts-table");

    if (!queryInput || !levelInput || !count || !table) {
        return;
    }

    const category = currentAlertCategory();
    const range = byId("alert-range")?.value ?? "24h";
    const sortMode = byId("alert-sort")?.value || "priority";
    const grouped = byId("alert-group")?.checked ?? true;
    const note = document.querySelector("[data-category-note]");
    if (note) note.textContent = ALERT_CATEGORY_NOTES[category] || "";

    const status = byId("alert-status")?.value || "open";
    const pageSize = Number(byId("alert-page-size")?.value || 50);
    const params = new URLSearchParams({
        q: queryInput.value.trim(),
        min_level: levelInput.value || "0",
        category,
        range,
        sort: sortMode,
        status,
        page: String(state.alertPage || 1),
        page_size: String(pageSize),
        view: "queue",
        group: grouped ? "1" : "0",
    });
    if (state.alertHost) params.set("host", state.alertHost);
    const data = await api(`/api/alerts?${params}`);
    // A filter that leaves fewer pages than the one shown: go to the last.
    if (data.total && data.page > data.pages) {
        state.alertPage = data.pages;
        return loadAlertsInner();
    }

    const level = Number(levelInput.value || 0);
    const alerts = [...(data.alerts || [])];
    // The server ranks (HAW-KI priority, then newest) and groups over the
    // whole period before cutting the page, so page 2 continues page 1.
    let rows;
    if (Array.isArray(data.groups) && data.groups.length === alerts.length) {
        rows = alerts.map((alert, i) => ({ lead: alert, ...data.groups[i] }));
    } else {
        // Older server: rank and group inside this page only.
        if (sortMode === "priority") {
            alerts.sort((left, right) =>
                priorityScore(right) - priorityScore(left)
                || (Date.parse(right.time) || 0) - (Date.parse(left.time) || 0));
        }
        rows = grouped ? groupAlerts(alerts) : alerts.map((alert) => ({ lead: alert, count: 1 }));
    }
    const units = data.unit === "group" ? Number(data.unit_total || 0) : Number(data.unit_total ?? data.total ?? 0);
    const first = units ? (data.page - 1) * data.page_size + 1 : 0;
    const last = Math.min(data.page * data.page_size, units);
    const unitWord = data.unit === "group" ? "묶음" : "건";
    count.textContent = [
        `${ALERT_RANGE_LABELS[range] ?? "최근"} ${ALERT_STATUS_LABELS[status] || ""} 경보 전체 ${formatNumber(data.total)}건${data.total_relation === "gte" ? " 이상" : ""}`,
        data.unit === "group" ? `${formatNumber(units)}개 묶음` : "",
        units ? `${formatNumber(first)}–${formatNumber(last)}번째 ${unitWord} (${sortMode === "priority" ? "우선순위 높은 순" : "최신순"})` : "",
        data.scan_limited ? `${sortMode === "priority" ? "레벨 높은" : "최근"} ${formatNumber(data.scanned)}건 기준` : "",
        level > 0 ? `Wazuh 레벨 ≥ ${level}` : "",
        state.alertHost ? `호스트 ${state.alertHost}` : "",
    ].filter(Boolean).join(" · ");

    const header = rows.length ? `
        <div class="alert-row alert-row-head" role="row">
            <span>시각</span>
            <span title="P1~P4: HAW-KI 우선순위 · L: Wazuh 룰 레벨">우선순위 · 심각도</span>
            <span>경보</span>
            <span>호스트</span>
            <span>룰 · MITRE</span>
            <span></span>
        </div>` : "";

    table.innerHTML = header + rows.map((row) => renderAlertRow(row.lead, row)).join("") || `
        <div class="empty-state">
            ${status === "open" && !data.total ? "미처리 경보 없음" : "조건에 맞는 경보 없음"}
        </div>
    `;
    renderAlertPager(data);
}

const ALERT_STATUS_LABELS = { open: "미처리", handled: "처리됨", all: "" };
const HANDLING_LABELS = {
    confirmed: ["처리됨 · 실제 위협", "handling-confirmed"],
    false_positive: ["처리됨 · 오탐", "handling-fp"],
    investigating: ["추가 조사 중", "handling-open"],
};

function handlingChip(alert) {
    const record = alert.handling;
    if (!record) return "";
    const [label, css] = HANDLING_LABELS[record.verdict] || [record.verdict, "handling-open"];
    const when = record.recorded_at ? ` · ${formatAlertTime(record.recorded_at, false)}` : "";
    return `<span class="handling-chip ${css}" title="${escapeHtml(`${label}${when}${record.reviewer ? ` · ${record.reviewer}` : ""}`)}">${escapeHtml(label)}</span>`;
}

// Page numbers around the current one, with the first and last always shown.
function pagerNumbers(current, total) {
    const wanted = new Set([1, total, current - 2, current - 1, current, current + 1, current + 2]);
    const numbers = [...wanted].filter((n) => n >= 1 && n <= total).sort((a, b) => a - b);
    const out = [];
    numbers.forEach((n, i) => {
        if (i && n - numbers[i - 1] > 1) out.push("…");
        out.push(n);
    });
    return out;
}

function renderAlertPager(data) {
    const pager = byId("alert-pager");
    if (!pager) return;
    if (!data.total || data.pages <= 1) {
        pager.hidden = true;
        pager.innerHTML = "";
        return;
    }
    const current = data.page;
    const button = (label, target, extra = "") => `<button type="button" class="pager-button${target === current ? " active" : ""}" data-page="${target}" ${target === current ? 'aria-current="page"' : ""} ${extra}>${label}</button>`;
    pager.hidden = false;
    pager.innerHTML = [
        button("이전", Math.max(1, current - 1), current <= 1 ? "disabled" : ""),
        ...pagerNumbers(current, data.pages).map((n) => (n === "…" ? `<span class="pager-gap">…</span>` : button(formatNumber(n), n))),
        button("다음", Math.min(data.pages, current + 1), current >= data.pages ? "disabled" : ""),
        data.window_limited ? `<span class="muted">1만 번째 이후는 검색 조건을 좁혀 주세요</span>` : "",
    ].join("");
}

function initAlerts() {
    const form = byId("alert-filter-form");

    /*
     * Alert list and alert detail pages share page="alerts".
     * The detail page does not contain this form.
     */
    if (!form) return;

    form.addEventListener("submit", (event) => {
        event.preventDefault();
        state.alertPage = 1;
        loadAlerts();
    });
    ["alert-sort", "alert-range", "alert-group", "alert-min-level", "alert-status", "alert-page-size"].forEach((id) => {
        byId(id)?.addEventListener("change", () => {
            state.alertPage = 1;
            loadAlerts();
        });
    });
    byId("alert-pager")?.addEventListener("click", (event) => {
        const target = event.target.closest("[data-page]");
        if (!target || target.disabled) return;
        state.alertPage = Number(target.dataset.page) || 1;
        loadAlerts();
        byId("alert-count")?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
    const tabs = [...document.querySelectorAll(".alert-tab")];
    const selectTab = (category) => tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab.dataset.category === category)));
    tabs.forEach((tab) => tab.addEventListener("click", () => {
        selectTab(tab.dataset.category);
        state.alertPage = 1;
        loadAlerts();
    }));

    // Dashboard cards and charts link here with a filter already chosen
    // (e.g. /alerts?min_level=8&range=24h), so the queue opens pre-filtered.
    const params = new URLSearchParams(window.location.search);
    const preset = (id, value) => {
        const select = byId(id);
        if (select && value !== null && [...select.options].some((option) => option.value === value)) select.value = value;
    };
    // Dashboard level rows link with any level; add it when the list lacks it.
    const presetLevel = params.get("min_level");
    const levelSelect = byId("alert-min-level");
    if (levelSelect && /^\d{1,2}$/.test(presetLevel || "") && Number(presetLevel) >= 1 && Number(presetLevel) <= 16
        && ![...levelSelect.options].some((option) => option.value === presetLevel)) {
        levelSelect.add(new Option(`레벨 ${presetLevel} 이상`, presetLevel));
    }
    preset("alert-min-level", presetLevel);
    state.alertHost = /^[A-Za-z0-9_.:-]{1,128}$/.test(params.get("host") || "") ? params.get("host") : "";
    preset("alert-range", params.get("range"));
    preset("alert-sort", params.get("sort"));
    // A dashboard count links here with its filter; it counts every alert,
    // so the list it opens shows every alert too unless a status is given.
    const linkedFilter = ["min_level", "range", "host", "q", "category"].some((key) => params.has(key));
    preset("alert-status", params.get("status") || (linkedFilter ? "all" : null));
    preset("alert-page-size", params.get("page_size"));
    if (/^\d{1,4}$/.test(params.get("page") || "")) state.alertPage = Math.max(1, Number(params.get("page")));
    if (["attack", "vulnerability", "all"].includes(params.get("category"))) selectTab(params.get("category"));
    if (params.get("group") === "0" && byId("alert-group")) byId("alert-group").checked = false;
    const presetQuery = params.get("q");
    if (presetQuery && byId("alert-query")) byId("alert-query").value = presetQuery;

    loadAlerts();
}

function formatLogEndpoint(ip, port) {
    if (!ip) return "";
    return port ? `${ip}:${port}` : ip;
}

function normalizeLog(source = {}) {
    const rule = source.rule || {};
    const agent = source.agent || {};
    const decoder = source.decoder || {};
    const data = source.data || {};
    const eventdata = data.eventdata || {};
    const system = data.system || {};

    const eventId = String(system.eventID || "");
    const host = agent.name || agent.ip || "—";

    let category =
        rule.description ||
        (Array.isArray(rule.groups)
            ? rule.groups.join(", ")
            : "Wazuh 이벤트");

    let message = "";
    let detail = "";

    if (decoder.name === "sysmon-linux" || eventId) {
        if (eventId === "1") {
            category = "Sysmon 프로세스 생성";

            message =
                eventdata.image ||
                "프로세스 생성됨";

            detail = [
                eventdata.user
                    ? `사용자: ${eventdata.user}`
                    : "",
                eventdata.processId
                    ? `PID: ${eventdata.processId}`
                    : "",
                eventdata.commandLine
                    ? `명령줄: ${eventdata.commandLine}`
                    : "",
                eventdata.parentImage
                    ? `부모 프로세스: ${eventdata.parentImage}`
                    : "",
            ].filter(Boolean).join(" · ");
        } else if (eventId === "3") {
            category = "Sysmon 네트워크 연결";

            const sourceEndpoint = formatLogEndpoint(
                eventdata.sourceIp,
                eventdata.sourcePort
            );

            const destinationEndpoint = formatLogEndpoint(
                eventdata.destinationIp,
                eventdata.destinationPort
            );

            message =
                sourceEndpoint || destinationEndpoint
                    ? `${sourceEndpoint || "?"} → ${destinationEndpoint || "?"}`
                    : "네트워크 연결";

            detail = [
                eventdata.image
                    ? `프로세스: ${eventdata.image}`
                    : "",
                eventdata.user
                    ? `사용자: ${eventdata.user}`
                    : "",
                eventdata.protocol
                    ? `프로토콜: ${String(eventdata.protocol).toUpperCase()}`
                    : "",
                eventdata.initiated
                    ? `연결 시작: ${eventdata.initiated}`
                    : "",
            ].filter(Boolean).join(" · ");
        }
    }

    if (!message) {
        message =
            source.data?.url ||
            source.data?.srcip ||
            rule.description ||
            source.full_log ||
            JSON.stringify(source);
    }

    const ruleMeta = [
        rule.id
            ? `룰 ${rule.id}`
            : "",
        rule.level !== undefined && rule.level !== null
            ? `레벨 ${rule.level}`
            : "",
        eventId
            ? `이벤트 ID ${eventId}`
            : "",
    ].filter(Boolean);

    return {
        time: source.timestamp || source["@timestamp"] || "—",
        host,
        category,
        message,
        detail,
        ruleMeta,
        raw: source.full_log || "",
    };
}

// Wazuh stores UTC ("2026-10-01T05:10:00.000+0000"); show the analyst's local
// time and keep the stored value in the tooltip.
function formatLogResultTime(value) {
    const text = String(value || "");
    const date = new Date(text.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    if (!text || Number.isNaN(date.getTime())) return text || "—";
    return date.toLocaleString("ko-KR", {
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
}

function renderLogResult(result) {
    const x = normalizeLog(result.source || {});

    const metadata = [
        ...x.ruleMeta,
        x.detail,
    ].filter(Boolean);

    const rawEvent = x.raw && x.raw !== x.message
        ? `
            <details class="log-raw">
                <summary>원시 이벤트</summary>
                <pre>${escapeHtml(x.raw)}</pre>
            </details>
        `
        : "";

    return `
        <div class="log-row">
            <span title="${escapeHtml(x.time)}">${escapeHtml(formatLogResultTime(x.time))}</span>

            <strong>${escapeHtml(x.host)}</strong>

            <span>${escapeHtml(x.category)}</span>

            <div class="log-message">
                <div>${escapeHtml(x.message)}</div>

                ${metadata.length
                    ? `<div class="log-meta">${escapeHtml(metadata.join(" · "))}</div>`
                    : ""}

                ${rawEvent}
            </div>
        </div>
    `;
}

async function runLogSearch() {
    const index = byId("log-index");
    const language = byId("log-language");
    const query = byId("log-query");
    const start = byId("log-start");
    const end = byId("log-end");
    const size = byId("log-size");
    const count = byId("log-count");
    const results = byId("log-results");

    if (
        !index ||
        !language ||
        !query ||
        !start ||
        !end ||
        !size ||
        !count ||
        !results
    ) {
        return;
    }

    if (!refreshLogRange()) {
        count.textContent = "기간을 확인하세요";
        return;
    }

    const pageParams = new URLSearchParams(window.location.search);

    const payload = {
        index: index.value,
        language: language.value,
        query: query.value,
        start_time: start.value,
        end_time: end.value,
        size: Number(size.value),
        pivot: pageParams.get("pivot") || "",
        source_alert_id: pageParams.get("from_alert") || "",
        source_agent_id: pageParams.get("from_agent") || "",
    };

    count.textContent = "검색 중…";

    try {
        const data = await api("/api/log-search", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        const dashboardLink = byId("open-wazuh-link");

        if (data.wazuh_dashboard_url && dashboardLink) {
            dashboardLink.href = data.wazuh_dashboard_url;
        }

        count.textContent =
            `일치하는 이벤트 ${formatNumber(data.total)}건`;

        results.innerHTML =
            (data.results || [])
                .map(renderLogResult)
                .join("") ||
            `<div class="empty-state">쿼리와 일치하는 이벤트가 없습니다.</div>`;
    } catch (error) {
        count.textContent = "검색 실패";

        results.innerHTML = `
            <div class="empty-state">
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}

// 검색 도우미: turns plain fields into a Lucene query_string for /api/log-search.
// Values are quoted and escaped here, so an IP or a path with special
// characters cannot change the shape of the query.
const LOG_IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const LOG_IPV6 = /^[0-9A-Fa-f:]{2,39}$/;

function quoteLogValue(value) {
    return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function buildLogQuery(fields) {
    const clauses = [];
    const errors = [];
    const anyOf = (names, value) => names.length === 1
        ? `${names[0]}:${quoteLogValue(value)}`
        : `(${names.map((name) => `${name}:${quoteLogValue(value)}`).join(" OR ")})`;
    const ip = (label, value, names) => {
        const text = String(value || "").trim();
        if (!text) return;
        if (!LOG_IPV4.test(text) && !(text.includes(":") && LOG_IPV6.test(text))) {
            errors.push(`${label} 형식이 올바르지 않습니다: ${text}`);
            return;
        }
        clauses.push(anyOf(names, text));
    };

    // Wazuh decoders name the same address differently (web logs, Suricata, Windows).
    ip("출발지 IP", fields.src_ip, ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress"]);
    ip("목적지 IP", fields.dst_ip, ["data.dstip", "data.dest_ip"]);

    const host = String(fields.host || "").trim();
    if (host) clauses.push(`agent.name:${quoteLogValue(host)}`);

    const rules = String(fields.rule_id || "").split(/[\s,]+/).filter(Boolean);
    const badRules = rules.filter((rule) => !/^\d{1,10}$/.test(rule));
    if (badRules.length) errors.push(`룰 ID는 숫자여야 합니다: ${badRules.join(", ")}`);
    const goodRules = rules.filter((rule) => /^\d{1,10}$/.test(rule));
    if (goodRules.length === 1) clauses.push(`rule.id:${quoteLogValue(goodRules[0])}`);
    if (goodRules.length > 1) clauses.push(`(${goodRules.map((rule) => `rule.id:${quoteLogValue(rule)}`).join(" OR ")})`);

    const level = Number(fields.min_level);
    if (Number.isInteger(level) && level > 0 && level <= 15) clauses.push(`rule.level:>=${level}`);

    const keyword = String(fields.keyword || "").trim();
    if (keyword) clauses.push(`full_log:${quoteLogValue(keyword)}`);

    return { query: clauses.length ? clauses.join(" AND ") : "*", errors };
}

function initLogQueryBuilder() {
    const builder = byId("log-builder");
    const queryInput = byId("log-query");
    if (!builder || !queryInput) return;

    const inputs = [...builder.querySelectorAll("[data-builder]")];
    const errorBox = builder.querySelector("[data-builder-error]");

    const update = () => {
        const fields = Object.fromEntries(inputs.map((input) => [input.dataset.builder, input.value]));
        const { query, errors } = buildLogQuery(fields);
        queryInput.value = query;
        if (errorBox) {
            errorBox.hidden = !errors.length;
            errorBox.textContent = errors.join(" · ");
        }
    };

    inputs.forEach((input) => input.addEventListener("input", update));
    inputs.forEach((input) => input.addEventListener("change", update));
    builder.querySelector("[data-builder-clear]")?.addEventListener("click", () => {
        inputs.forEach((input) => { input.value = ""; });
        update();
    });
}

// 로그 검색 · 기간: preset buttons send OpenSearch date math ("now-24h"), which
// the indexer evaluates at search time; 직접 지정 converts the browser's local
// time to an ISO instant with "Z". A zone-less time would be read as UTC by the
// indexer and be off by 9 hours in Korea, so it is never sent.
const LOG_RANGE_PRESETS = {
    "now-15m": ["최근 15분", 15 * 60 * 1000],
    "now-1h": ["최근 1시간", 60 * 60 * 1000],
    "now-24h": ["최근 24시간", 24 * 60 * 60 * 1000],
    "now-7d": ["최근 7일", 7 * 24 * 60 * 60 * 1000],
    "now-30d": ["최근 30일", 30 * 24 * 60 * 60 * 1000],
};
const LOG_RELATIVE_UNITS = { s: [1000, "초"], m: [60 * 1000, "분"], h: [60 * 60 * 1000, "시간"], d: [24 * 60 * 60 * 1000, "일"], w: [7 * 24 * 60 * 60 * 1000, "주"] };
const LOG_ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})$/;
let refreshLogRange = () => true;

function parseLogTime(value) {
    const text = String(value || "").trim();
    if (text === "now") return new Date();
    const relative = /^now-(\d{1,4})([smhdw])$/.exec(text);
    if (relative) return new Date(Date.now() - Number(relative[1]) * LOG_RELATIVE_UNITS[relative[2]][0]);
    if (LOG_ISO_INSTANT.test(text)) {
        const date = new Date(text);
        return Number.isNaN(date.getTime()) ? null : date;
    }
    return null;
}

function describeLogTime(value) {
    const text = String(value || "").trim();
    if (text === "now") return "지금";
    const relative = /^now-(\d{1,4})([smhdw])$/.exec(text);
    if (relative) return `${relative[1]}${LOG_RELATIVE_UNITS[relative[2]][1]} 전`;
    const date = parseLogTime(text);
    return date ? formatLogRangeTime(date) : text;
}

function toLocalInputValue(date) {
    const pad = (number) => String(number).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatLogRangeTime(date) {
    return date.toLocaleString("ko-KR", {
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", hour12: false,
    });
}

function browserZoneLabel() {
    try {
        const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        return zone === "Asia/Seoul" ? "한국 시간" : (zone || "브라우저 시간");
    } catch {
        return "브라우저 시간";
    }
}

function initLogRange() {
    const start = byId("log-start");
    const end = byId("log-end");
    const chips = [...document.querySelectorAll(".log-range [data-range]")];
    const custom = document.querySelector("[data-range-custom]");
    const startLocal = byId("log-start-local");
    const endLocal = byId("log-end-local");
    const summary = byId("log-range-summary");
    if (!start || !end || !chips.length || !custom || !startLocal || !endLocal || !summary) return;

    const zone = browserZoneLabel();
    let mode = "";

    const press = (value) => chips.forEach((chip) => chip.setAttribute("aria-pressed", String(chip.dataset.range === value)));
    const show = (text, invalid = false) => {
        summary.textContent = text;
        summary.classList.toggle("is-invalid", invalid);
        return !invalid;
    };
    const describePreset = (value) => {
        const [label, span] = LOG_RANGE_PRESETS[value];
        return show(`${label} · ${formatLogRangeTime(new Date(Date.now() - span))} ~ 지금 (${zone})`);
    };
    const usePreset = (value) => {
        mode = value;
        press(value);
        custom.hidden = true;
        start.value = value;
        end.value = "now";
        return describePreset(value);
    };
    const applyCustom = () => {
        if (!startLocal.value || !endLocal.value) return show("시작과 끝을 모두 고르세요.", true);
        const from = new Date(startLocal.value);
        const to = new Date(endLocal.value);
        if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return show("날짜 형식이 올바르지 않습니다.", true);
        if (from >= to) return show("시작이 끝보다 앞서야 합니다.", true);
        start.value = from.toISOString();
        end.value = to.toISOString();
        return show(`${formatLogRangeTime(from)} ~ ${formatLogRangeTime(to)} (${zone})`);
    };
    const useCustom = (from, to) => {
        mode = "custom";
        press("custom");
        custom.hidden = false;
        startLocal.value = toLocalInputValue(from);
        endLocal.value = toLocalInputValue(to);
        return applyCustom();
    };

    chips.forEach((chip) => chip.addEventListener("click", () => {
        if (chip.dataset.range !== "custom") {
            usePreset(chip.dataset.range);
            return;
        }
        // Open on the period already selected, so switching is not a reset.
        const to = parseLogTime(end.value) || new Date();
        const from = parseLogTime(start.value) || new Date(to.getTime() - LOG_RANGE_PRESETS["now-24h"][1]);
        useCustom(from, to < from ? new Date() : to);
        startLocal.focus();
    }));
    [startLocal, endLocal].forEach((input) => {
        input.addEventListener("input", applyCustom);
        input.addEventListener("change", applyCustom);
    });

    // Re-checked right before each search: preset times move with the clock.
    refreshLogRange = () => {
        if (mode === "custom") return applyCustom();
        if (LOG_RANGE_PRESETS[mode]) return describePreset(mode);
        return true;
    };

    // First state comes from the hidden values (set from investigation links).
    if (LOG_RANGE_PRESETS[start.value] && end.value === "now") {
        usePreset(start.value);
    } else if (LOG_ISO_INSTANT.test(start.value) && LOG_ISO_INSTANT.test(end.value)) {
        useCustom(parseLogTime(start.value), parseLogTime(end.value));
    } else {
        press("");
        custom.hidden = true;
        show(`링크로 받은 기간 · ${describeLogTime(start.value)} ~ ${describeLogTime(end.value)}`);
    }
}

// 로그 검색 · 검색 대상: the two Wazuh indices by name; any other pattern
// stays possible under 고급 설정 (investigation links may carry one).
function initLogTarget() {
    const target = byId("log-target");
    const index = byId("log-index");
    const advanced = byId("log-advanced");
    const note = document.querySelector("[data-target-note]");
    const customOption = target?.querySelector("[data-target-custom]");
    if (!target || !index || !customOption) return;

    const sync = () => {
        const value = index.value.trim();
        const match = [...target.options].find((option) => option !== customOption && option.value === value);
        customOption.hidden = Boolean(match);
        target.value = match ? match.value : "__custom";
        if (note) note.textContent = match ? (match.dataset.note || "") : `고급 설정의 인덱스: ${value || "(비어 있음)"}`;
        if (!match && advanced) advanced.open = true;
    };

    target.addEventListener("change", () => {
        if (target.value === "__custom") {
            if (advanced) advanced.open = true;
            index.focus();
        } else {
            index.value = target.value;
        }
        sync();
    });
    index.addEventListener("input", sync);
    sync();
}

// 로그 검색 · 호스트 드롭다운: registered Wazuh agents with their status
// (/api/log-search/hosts falls back to names seen in the last 7 days).
const LOG_HOST_STATUS = {
    active: "연결됨",
    disconnected: "끊김",
    pending: "대기",
    never_connected: "연결된 적 없음",
};

async function initLogHosts() {
    const builder = byId("log-builder");
    const select = builder?.querySelector("[data-host-select]");
    const input = builder?.querySelector("[data-host-custom]");
    const note = builder?.querySelector("[data-host-note]");
    if (!select || !input) return;
    const customOption = select.querySelector('option[value="__custom"]');

    const choose = ({ focus = true } = {}) => {
        if (select.value === "__custom") {
            input.hidden = false;
            if (focus) input.focus();
            return;
        }
        input.hidden = true;
        input.value = select.value;
        input.dispatchEvent(new Event("change"));
    };
    select.addEventListener("change", () => choose());
    let listed = 0;
    builder.querySelector("[data-builder-clear]")?.addEventListener("click", () => {
        if (!listed) return; // no list: the typed field is the only way in
        select.value = "";
        input.hidden = true;
    });

    let data = null;
    try {
        data = await api("/api/log-search/hosts");
    } catch {
        data = null;
    }
    select.querySelector("[data-host-loading]")?.remove();

    const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
    listed = hosts.length;
    hosts.forEach((host) => {
        const option = document.createElement("option");
        option.value = host.name;
        option.textContent = [
            host.name,
            host.id ? `(${host.id})` : "",
            host.manager ? "· 관리자" : "",
            LOG_HOST_STATUS[host.status] ? `· ${LOG_HOST_STATUS[host.status]}` : "",
            Number.isFinite(host.events_7d) ? `· 7일 ${formatNumber(host.events_7d)}건` : "",
        ].filter(Boolean).join(" ");
        select.insertBefore(option, customOption);
    });

    if (!hosts.length) {
        if (note) note.textContent = "호스트 목록을 가져오지 못했습니다. 이름을 직접 입력하세요.";
        select.value = "__custom";
        choose({ focus: false });
    } else if (note) {
        note.textContent = data.source === "indexer"
            ? "Wazuh 관리자 API에 연결되지 않아 최근 7일 경보에 나온 호스트를 보여 줍니다."
            : "";
    }
}

function initLogs() {
    const form = byId("log-search-form");
    if (!form) return;

    initLogQueryBuilder();

    const policy = byId("log-policy-note");
    const params = new URLSearchParams(window.location.search);

    if (policy) {
        policy.textContent = state.config.wazuh_search_enabled
            ? "읽기 전용 Wazuh Indexer 검색이 활성화되어 있습니다."
            : "서버 정책에 따라 Wazuh Indexer 검색이 비활성화되어 있습니다.";
    }

    const fields = {
        index: "log-index",
        query: "log-query",
        start: "log-start",
        end: "log-end",
        size: "log-size",
    };

    Object.entries(fields).forEach(([parameter, elementId]) => {
        const value = params.get(parameter);
        const element = byId(elementId);

        if (value !== null && element) {
            element.value = value;
        }
    });

    initLogTarget();
    initLogRange();
    initLogHosts();

    const pivotLabels = {
        same_source_ip: "동일 출발지 IP",
        same_agent: "동일 Wazuh 에이전트",
        same_rule: "동일 Wazuh 룰",
        raw_window: "원시 아카이브 시간 구간",
        host_alerts: "호스트 경보 이력",
        host_raw: "호스트 원시 텔레메트리",
        host_fim: "호스트 FIM 탐지",
    };

    const pivot = params.get("pivot");

    if (pivot && policy && pivotLabels[pivot]) {
        policy.textContent +=
            ` 조사 피벗: ${pivotLabels[pivot]}.`;
    }

    form.addEventListener("submit", (event) => {
        event.preventDefault();
        runLogSearch();
    });

    byId("copy-log-query")?.addEventListener(
        "click",
        async () => {
            const input = byId("log-query");
            if (!input) return;

            await navigator.clipboard.writeText(input.value);
            toast("쿼리를 복사했습니다.");
        }
    );

    if (params.get("run") === "1") {
        runLogSearch();
    }
}

async function initHunts() {
    byId("hunt-agent-form").addEventListener("submit", (event) => {
        event.preventDefault();
        const query = new URLSearchParams({
            mode: "file_hunt",
            host: byId("hunt-target").value,
            incident: byId("hunt-incident").value,
            prompt: byId("hunt-indicator").value ? `파일 단서: ${byId("hunt-indicator").value}` : "",
        });
        location.href = `/agent?${query}`;
    });
    loadVelociraptorClients("hunt-target");
    loadVelociraptorFlows("hunt-target", "hunt-flow-list");
    const list = byId("hunt-list");
    try {
        const data = await api("/api/hunts");
        list.innerHTML = data.hunts.map((hunt) => {
            const artifacts = Array.isArray(hunt.artifacts) ? hunt.artifacts.join(", ") : "";
            return `<div class="hunt-card"><div class="hunt-top"><strong>${escapeHtml(hunt.hunt_id)} · ${escapeHtml(hunt.hunt_description || "")}</strong><span class="status-text">${escapeHtml(String(hunt.state ?? "미확인"))}</span></div><p>${escapeHtml(artifacts || "수집 항목 미표시")}</p></div>`;
        }).join("") || '<div class="empty-state">이번 조회에서 등록된 추적 작업이 반환되지 않았습니다.</div>';
        const note = document.createElement("p");
        note.className = "muted";
        note.textContent = `추적 작업 ${data.returned_hunts}개 반환개`;
        list.appendChild(note);
    } catch (error) {
        list.textContent = "추적 작업 조회 실패: " + error.message;
    }
}

function actionCard(a, decisionButtons = false) {
    const buttons = decisionButtons && a.status === "pending_approval" ? `<div class="approval-actions"><button class="button danger small action-decision" data-id="${escapeHtml(a.id)}" data-decision="reject">반려</button><button class="button primary small action-decision" data-id="${escapeHtml(a.id)}" data-decision="approve">승인</button></div>` : "";
    return `<div class="approval-card"><div class="approval-top"><strong>${escapeHtml(a.id)} · ${escapeHtml(a.title)}</strong><span class="status-text ${escapeHtml(a.status)}">${escapeHtml(approvalStatusLabel(a.status))}</span></div><p>${escapeHtml(a.summary)}</p><div class="approval-meta"><span class="tag" title="${escapeHtml(a.type)}">${escapeHtml(approvalLabel(a.type))}</span><span class="tag">위험도: ${escapeHtml(severityLabel(a.risk))}</span><span class="tag" title="${escapeHtml(a.created_at)}">${escapeHtml(formatAlertTime(a.created_at, false))}</span></div>${a.dispatch_result && DISPATCH_MESSAGES[normalizeApprovalValue(a.dispatch_result.message)] ? `<p class="muted approval-not-run">${escapeHtml(DISPATCH_MESSAGES[normalizeApprovalValue(a.dispatch_result.message)])}</p>` : ""}${buttons}</div>`;
}

async function loadActionList(containerId, prefix = "") {
    const data = await api(`/api/actions${prefix ? `?type=${encodeURIComponent(prefix)}` : ""}`);
    const container = byId(containerId);
    container.innerHTML = data.actions.map((a) => actionCard(a, false)).join("") || `<div class="empty-state">이 대기열에 조치가 없습니다.</div>`;
    return data;
}

function normalizeApprovalValue(value) {
    return String(value ?? "").trim();
}

// Raw action values shown on cards; anything not listed falls back to Title Case.
const APPROVAL_VALUE_LABELS = {
    velociraptor_collection: "Velociraptor 수집",
    velociraptor_hunt: "Velociraptor 헌트",
    velociraptor_isolation: "Velociraptor 격리",
    velociraptor_remediation: "Velociraptor 조치",
    suricata_rule: "Suricata 룰",
    suricata_rule_disable: "Suricata 룰 비활성화",
    staging: "스테이징",
    production: "운영",
    alert: "탐지(경보만)",
    drop: "차단",
    reject: "거부",
    pass: "통과",
    disable: "사용 중지",
    inventory_draft: "룰 목록 초안",
    superseded: "대체됨",
    verified: "검증됨",
    passed: "통과",
    detection_only: "탐지 전용",
    draft: "초안",
    review: "검토 필요",
    deployment: "배포 단계",
    requested_action: "요청 동작",
    detection_spec: "탐지 명세",
    verification: "검증 결과",
    verification_status: "검증 상태",
    live_enforcement_mode: "실제 적용 방식",
    blocking_verified: "차단 검증",
    validation: "검증 항목",
    review_warnings: "검토 경고",
    rule_id: "룰 ID",
    host: "호스트",
    interface: "인터페이스",
    target_enabled: "적용 후 활성화",
    previous_state: "이전 상태",
    collection_type: "수집 종류",
    filters: "조건",
    artifact: "아티팩트",
    agent_id: "에이전트 ID",
    id: "ID",
    low: "낮음",
    medium: "중간",
    high: "높음",
    critical: "치명",
};
const DISPATCH_MESSAGES = {
    "Execution is disabled by server policy.": "승인되었지만 아직 실행되지 않았습니다.",
    "No trusted action gateway is configured.": "조치 게이트웨이(Velociraptor 연동)가 설정되지 않아 승인만 기록했습니다.",
};

function approvalLabel(value) {
    const key = normalizeApprovalValue(value).toLowerCase();
    if (APPROVAL_VALUE_LABELS[key]) return APPROVAL_VALUE_LABELS[key];
    return normalizeApprovalValue(value)
        .replace(/^agent[:-]?/i, "")
        .replace(/_/g, " ")
        .replace(/\b\w/g, (character) => character.toUpperCase());
}

function approvalMode(action) {
    const source = normalizeApprovalValue(action.source).toLowerCase();
    const type = normalizeApprovalValue(action.type).toLowerCase();

    const sourceModes = [
        "alert_summary",
        "log_search",
        "file_hunt",
        "velociraptor_response",
        "suricata_rule",
        "incident_report",
    ];
    const explicitMode = sourceModes.find((mode) => source.includes(mode));
    if (explicitMode) return explicitMode;

    if (type.startsWith("suricata_")) return "suricata_rule";
    if (type === "velociraptor_hunt") return "file_hunt";
    if (type.startsWith("velociraptor_")) return "velociraptor_response";
    return "log_search";
}

function approvalModeLabel(mode) {
    const labels = {
        alert_summary: "경보 설명",
        log_search: "로그 검색",
        file_hunt: "의심 파일 추적",
        velociraptor_response: "호스트 대응",
        suricata_rule: "Suricata 룰",
        incident_report: "사건 보고서",
    };
    return labels[mode] || approvalLabel(mode);
}

function approvalStatusLabel(status) {
    const labels = {
        pending_approval: "승인 대기",
        approved_staged: "승인됨 · 실행 안 됨",
        submitted: "제출됨",
        rejected: "반려됨",
        dispatch_failed: "전송 실패",
        approved: "승인됨",
        superseded: "대체됨",
        verification_blocked: "검증 차단",
        pending: "검토 대기",
        failed: "실패",
        unknown: "알 수 없음",
    };
    return labels[status] || approvalLabel(status || "unknown");
}

function approvalRiskRank(risk) {
    const ranks = {
        critical: 6,
        high: 5,
        review: 4,
        medium: 3,
        low: 2,
        informational: 1,
        unknown: 0,
    };
    return ranks[normalizeApprovalValue(risk).toLowerCase()] ?? 0;
}

function approvalDateValue(value) {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) ? timestamp : 0;
}

function approvalDateLabel(value) {
    const timestamp = approvalDateValue(value);
    if (!timestamp) return "시각 불명";
    return `${new Date(timestamp).toLocaleString("ko-KR", {
        timeZone: "Asia/Seoul",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
    })} KST`;
}

// Some older actions stored their tag list as one JSON text that was later
// split on commas: ['["HAW-KI"', '"Verified"]']. Rebuild real tag values.
function cleanApprovalTags(value) {
    let items = value;
    if (typeof items === "string") {
        try { items = JSON.parse(items); } catch { items = items.split(","); }
    }
    if (!Array.isArray(items)) return [];
    return items.flatMap((item) => {
        const text = String(item ?? "").trim();
        if (text.startsWith("[")) {
            try { return cleanApprovalTags(JSON.parse(text)); } catch { /* a fragment, cleaned below */ }
        }
        const bare = text.replace(/^[\s\["']+|[\s\]"']+$/g, "").trim();
        return bare ? [bare] : [];
    });
}

function approvalTagLabel(value) {
    const key = normalizeApprovalValue(value).toLowerCase().replace(/[\s-]+/g, "_");
    return APPROVAL_VALUE_LABELS[key] || normalizeApprovalValue(value);
}

function approvalTags(action) {
    const payload = action?.payload && typeof action.payload === "object" ? action.payload : {};
    const mode = approvalMode(action);
    const candidates = [
        approvalTagLabel(action.type),
        approvalModeLabel(mode),
        normalizeApprovalValue(payload.deployment) ? approvalTagLabel(payload.deployment) : "",
        normalizeApprovalValue(payload.requested_action) ? approvalTagLabel(payload.requested_action) : "",
        normalizeApprovalValue(payload.artifact) ? approvalTagLabel(payload.artifact) : "",
        normalizeApprovalValue(action.resubmitted_from) ? "재제출" : "",
        ...cleanApprovalTags(action?.tags).map(approvalTagLabel),
    ];
    // One tag per meaning: "Suricata 룰" and "suricata rule" are the same.
    const seen = new Set();
    return candidates.filter(Boolean).filter((tag) => {
        const key = tag.toLowerCase().replace(/[\s_-]+/g, "");
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

// Older and server-made records keep English titles and summaries. Show them
// in Korean here; the stored record stays as it was.
const APPROVAL_TEXT_KO = [
    [/^Deterministic Suricata ([\d.]+) verification passed\.?\s*/i, "Suricata $1 검증 통과. "],
    [/Save this proposal to the rule inventory before staging\.?\s*/i, "배포 전에 룰 목록에 저장하세요. "],
    [/The live sensor is detection-only; blocking is not verified\.?\s*/i, "센서가 탐지 전용이라 차단은 확인하지 않았습니다. "],
    [/Stage only after configuration validation, representative traffic testing, and false-positive review\.?\s*/i, "설정 검증, 대표 트래픽 시험, 오탐 검토 뒤 배포하세요. "],
    [/^Superseded by (?:a newer|the current) staging action\.?$/i, "새 배포 요청으로 대체됨"],
    [/^Rule inventory changed after staging\.?$/i, "요청 뒤 룰이 수정되어 대체됨"],
    [/^Suricata ([\d.]+) syntax test$/i, "Suricata $1 문법 검사"],
    [/^deterministic positive replay$/i, "탐지 재현 시험"],
    [/^deterministic benign control replay$/i, "정상 트래픽 대조 시험"],
];

function approvalText(value) {
    let text = normalizeApprovalValue(value);
    APPROVAL_TEXT_KO.forEach(([pattern, replacement]) => {
        text = text.replace(pattern, replacement);
    });
    return text.trim();
}

const APPROVAL_FIXED_TITLES = {
    "review verified suricata rule": "검증된 Suricata 룰 제안",
    "verified suricata rule proposal": "검증된 Suricata 룰 제안",
    "review generated suricata rule": "생성된 Suricata 룰 검토",
};

function approvalTitle(action) {
    const raw = normalizeApprovalValue(action?.title);
    if (!raw) return approvalLabel(action?.type);
    const deploy = raw.match(/^Deploy\s+(.+)$/i);
    if (deploy) return `${deploy[1]} 배포`;
    const disable = raw.match(/^Disable\s+(.+)$/i);
    if (disable) return `${disable[1]} 사용 중지`;
    return APPROVAL_FIXED_TITLES[raw.toLowerCase()] || raw;
}

const APPROVAL_VIEW_STATUSES = {
    pending: ["pending_approval"],
    approved: ["approved_staged", "submitted", "approved"],
    rejected: ["rejected", "dispatch_failed", "verification_blocked", "failed"],
    superseded: ["superseded"],
};

const APPROVAL_VIEW_LABELS = {
    pending: "처리할 것",
    approved: "승인됨",
    rejected: "반려 · 실패",
    superseded: "대체됨",
    all: "전체",
};

function approvalView(action) {
    const status = normalizeApprovalValue(action?.status).toLowerCase();
    const match = Object.entries(APPROVAL_VIEW_STATUSES).find(([, list]) => list.includes(status));
    return match ? match[0] : "other";
}

function approvalPayload(action) {
    return action?.payload && typeof action.payload === "object" ? action.payload : {};
}

function approvalTarget(action) {
    const payload = approvalPayload(action);
    const parts = [payload.host, payload.interface].map(normalizeApprovalValue).filter(Boolean);
    if (normalizeApprovalValue(action?.type).startsWith("suricata_")) {
        const {sid, revision} = suricataRuleIdentifiers(action);
        if (sid) parts.push(`SID ${sid} · rev ${revision}`);
    }
    if (!parts.length && normalizeApprovalValue(payload.agent_id)) parts.push(normalizeApprovalValue(payload.agent_id));
    if (normalizeApprovalValue(payload.artifact)) parts.push(normalizeApprovalValue(payload.artifact));
    return parts.join(" · ");
}

// Rule inventory requests store "host / interface · SID n" as the summary,
// which the target line already shows.
function approvalSummaryText(action) {
    const summary = normalizeApprovalValue(action?.summary);
    if (!summary || /^\S+\s*\/\s*\S+\s*·\s*SID\s*\d+$/i.test(summary)) return "";
    return approvalText(summary);
}

function approvalSearchText(action) {
    return [
        action.id,
        action.title,
        approvalTitle(action),
        action.summary,
        approvalTarget(action),
        action.type,
        action.risk,
        action.status,
        action.source,
        JSON.stringify(action.payload || {}),
        JSON.stringify(action.dispatch_result || {}),
        action.decision_note,
        action.resubmitted_from,
        action.resubmission_note,
        ...approvalTags(action),
    ].join(" ").toLowerCase();
}

// Only these fields hold enum values worth translating; a host or name that
// happens to read "production" stays as written.
const APPROVAL_ENUM_KEYS = new Set(["deployment", "requested_action", "verification_status", "live_enforcement_mode", "status", "risk"]);

function renderApprovalValue(value, key = "") {
    if (Array.isArray(value)) {
        return value.length
            ? `<ul>${value.map((item) => `<li>${escapeHtml(typeof item === "object" ? JSON.stringify(item) : approvalText(item))}</li>`).join("")}</ul>`
            : `<span class="approval-empty-value">없음</span>`;
    }
    if (value && typeof value === "object") {
        // Machine records (DetectionSpec, verification) stay one click away.
        return `<details class="approval-json-toggle"><summary>원본 보기 · ${escapeHtml(Object.keys(value).length)}개 항목</summary><pre class="approval-json"><code>${escapeHtml(JSON.stringify(value, null, 2))}</code></pre></details>`;
    }
    if (typeof value === "boolean") return `<span>${value ? "예" : "아니요"}</span>`;
    const text = normalizeApprovalValue(value);
    if (String(key).toLowerCase() === "previous_state") {
        return `<span title="${escapeHtml(text)}">${escapeHtml(ruleStateLabel(text))}</span>`;
    }
    const label = APPROVAL_ENUM_KEYS.has(String(key).toLowerCase()) ? APPROVAL_VALUE_LABELS[text.toLowerCase()] : "";
    return label ? `<span title="${escapeHtml(text)}">${escapeHtml(label)}</span>` : `<span>${escapeHtml(text)}</span>`;
}

function suricataRuleIdentifiers(action) {
    const payload = action?.payload && typeof action.payload === "object" ? action.payload : {};
    const rule = normalizeApprovalValue(payload.rule);
    const sidMatch = rule.match(/\bsid\s*:\s*(\d+)\s*;/i);
    const revisionMatch = rule.match(/\brev\s*:\s*(\d+)\s*;/i);
    return {
        sid: normalizeApprovalValue(payload.sid || sidMatch?.[1]),
        revision: normalizeApprovalValue(payload.revision || revisionMatch?.[1] || "1"),
    };
}

function renderApprovalRule(action, editable) {
    const payload = approvalPayload(action);
    const rule = normalizeApprovalValue(payload.rule);
    if (!rule) return "";
    const suricata = normalizeApprovalValue(action.type).startsWith("suricata_");
    const identifiers = suricata ? suricataRuleIdentifiers(action) : null;
    const pending = normalizeApprovalValue(action.status) === "pending_approval";
    const editor = suricata && editable ? `
        <div class="approval-rule-editor">
            <label>
                <span>SID</span>
                <input class="approval-rule-sid" data-id="${escapeHtml(action.id)}"
                    type="number" min="1000000" max="4294967295"
                    value="${escapeHtml(identifiers.sid)}">
            </label>
            <label>
                <span>개정 번호</span>
                <input class="approval-rule-revision" data-id="${escapeHtml(action.id)}"
                    type="number" min="1" max="65535"
                    value="${escapeHtml(identifiers.revision)}">
            </label>
            ${pending ? `
                <button class="button secondary small save-rule-identifiers"
                    data-id="${escapeHtml(action.id)}" type="button">SID / rev 저장</button>
            ` : ""}
        </div>
    ` : "";
    return `
        <section class="approval-action-display approval-rule-display">
            <pre><code>${escapeHtml(rule)}</code></pre>
            ${editor}
        </section>
    `;
}

function renderApprovalPayload(action) {
    const payload = approvalPayload(action);
    const entries = Object.entries(payload).filter(([key]) => !["rule", "sid", "revision"].includes(key));
    if (!entries.length) return `<p class="approval-empty-value">추가 정보 없음</p>`;
    return `
        <dl class="approval-payload-grid">
            ${entries.map(([key, value]) => `
                <div>
                    <dt>${escapeHtml(approvalLabel(key))}</dt>
                    <dd>${renderApprovalValue(value, key)}</dd>
                </div>
            `).join("")}
        </dl>
    `;
}

function renderApprovalOutcome(action) {
    const parts = [];
    const note = approvalText(action.decision_note || action.superseded_reason);
    if (note) {
        parts.push(`
            <div class="approval-outcome-row">
                <strong>${approvalView(action) === "superseded" ? "대체 사유" : "결정 메모"}</strong>
                <span>${escapeHtml(note)}</span>
            </div>
        `);
    }
    if (action.dispatch_result && typeof action.dispatch_result === "object"
        && DISPATCH_MESSAGES[normalizeApprovalValue(action.dispatch_result.message)]) {
        parts.push(`
            <div class="approval-outcome-row approval-outcome-note">
                <strong>실행 안 됨</strong>
                <span>${escapeHtml(DISPATCH_MESSAGES[normalizeApprovalValue(action.dispatch_result.message)])}</span>
            </div>
        `);
    } else if (action.dispatch_result && typeof action.dispatch_result === "object") {
        const routineMessage = normalizeApprovalValue(action.dispatch_result.message);
        const hiddenRoutineMessages = new Set([
            "서버 정책에 의해 실행이 비활성화되어 있습니다.",
            "신뢰된 조치 게이트웨이가 설정되어 있지 않습니다.",
            "반려되어 전송하지 않았습니다.",
        ]);
        if (!hiddenRoutineMessages.has(routineMessage)) {
            parts.push(`
                <div class="approval-outcome-row">
                    <strong>전송 결과</strong>
                    <pre class="approval-json"><code>${escapeHtml(JSON.stringify(action.dispatch_result, null, 2))}</code></pre>
                </div>
            `);
        }
    }
    return parts.length ? `<section class="approval-outcome">${parts.join("")}</section>` : "";
}

function approvalMetaLine(action) {
    const items = [
        `<span>${escapeHtml(action.id)}</span>`,
        `<span>요청 ${escapeHtml(approvalDateLabel(action.created_at))}</span>`,
    ];
    if (normalizeApprovalValue(action.decided_at)) items.push(`<span>결정 ${escapeHtml(approvalDateLabel(action.decided_at))}</span>`);
    if (normalizeApprovalValue(action.resubmitted_from)) items.push(`<span>이전 요청 ${escapeHtml(action.resubmitted_from)}</span>`);
    return `<div class="approval-time-list">${items.join("")}</div>`;
}

function approvalTagRow(action) {
    const tags = approvalTags(action);
    return tags.length
        ? `<div class="approval-tag-list">${tags.map((tag) => `<span class="approval-tag"><span></span>${escapeHtml(tag)}</span>`).join("")}</div>`
        : "";
}

function approvalChips(action) {
    const risk = normalizeApprovalValue(action.risk || "unknown").toLowerCase();
    const status = normalizeApprovalValue(action.status || "unknown").toLowerCase();
    return `
        <span class="approval-risk-chip risk-${escapeHtml(risk)}"><span></span>위험도 ${escapeHtml(riskLabel(risk))}</span>
        <span class="approval-status-chip status-${escapeHtml(status)}"><span></span>${escapeHtml(approvalStatusLabel(status))}</span>
    `;
}

function approvalDetails(action) {
    return `
        <details class="approval-more">
            <summary>세부 정보</summary>
            ${approvalTagRow(action)}
            ${renderApprovalPayload(action)}
            ${approvalMetaLine(action)}
        </details>
    `;
}

function pendingApprovalCard(action) {
    const mode = approvalMode(action);
    const target = approvalTarget(action);
    const summary = approvalSummaryText(action);
    const rule = renderApprovalRule(action, true);
    return `
        <article class="approval-card approval-card-detailed approval-card-pending" data-action-id="${escapeHtml(action.id)}">
            <header class="approval-card-header">
                <div class="approval-card-heading">
                    <span class="approval-mode-dot mode-${escapeHtml(mode)}"
                        title="${escapeHtml(approvalModeLabel(mode))}"
                        aria-label="${escapeHtml(approvalModeLabel(mode))}"></span>
                    <div>
                        <h3 title="${escapeHtml(action.title || "")}">${escapeHtml(approvalTitle(action))}</h3>
                        <p class="approval-target">${escapeHtml(approvalModeLabel(mode))}${target ? ` · ${escapeHtml(target)}` : ""}</p>
                    </div>
                </div>
                <div class="approval-chip-row">${approvalChips(action)}</div>
            </header>

            ${summary ? `<p class="approval-summary-text">${escapeHtml(summary)}</p>` : ""}

            <div class="approval-decision-panel">
                <label>
                    <span>결정 메모</span>
                    <input class="approval-decision-note" data-id="${escapeHtml(action.id)}"
                        placeholder="사유 (선택)">
                </label>
                <div class="approval-actions">
                    <button class="button danger small action-decision"
                        data-id="${escapeHtml(action.id)}" data-decision="reject" type="button">반려</button>
                    <button class="button primary small action-decision"
                        data-id="${escapeHtml(action.id)}" data-decision="approve" type="button">승인</button>
                </div>
            </div>

            ${rule ? `<details class="approval-more" open><summary>룰 본문 · SID 수정</summary>${rule}</details>` : ""}
            ${approvalDetails(action)}
        </article>
    `;
}

function finishedApprovalCard(action) {
    const view = approvalView(action);
    const resendable = view !== "superseded";
    const target = approvalTarget(action);
    const summary = approvalSummaryText(action);
    const when = normalizeApprovalValue(action.decided_at || action.superseded_at || action.created_at);
    const status = normalizeApprovalValue(action.status || "unknown").toLowerCase();
    return `
        <details class="approval-card approval-card-done" data-action-id="${escapeHtml(action.id)}">
            <summary class="approval-done-row">
                <span class="approval-status-chip status-${escapeHtml(status)}"><span></span>${escapeHtml(approvalStatusLabel(status))}</span>
                <strong title="${escapeHtml(action.title || "")}">${escapeHtml(approvalTitle(action))}</strong>
                <span class="approval-target">${escapeHtml(target)}</span>
                <span class="approval-done-time">${escapeHtml(approvalDateLabel(when))}</span>
            </summary>
            <div class="approval-done-body">
                ${summary ? `<p class="approval-summary-text">${escapeHtml(summary)}</p>` : ""}
                ${renderApprovalOutcome(action)}
                ${renderApprovalRule(action, resendable)}
                ${approvalDetails(action)}
                ${resendable ? `
                    <div class="approval-resend-panel">
                        <label>
                            <span>재요청 메모</span>
                            <input class="approval-resend-note" data-id="${escapeHtml(action.id)}"
                                placeholder="메모 (선택)">
                        </label>
                        <button class="button secondary small action-resend"
                            data-id="${escapeHtml(action.id)}" type="button">승인 재요청</button>
                    </div>
                ` : ""}
            </div>
        </details>
    `;
}

function detailedApprovalCard(action) {
    return approvalView(action) === "pending" ? pendingApprovalCard(action) : finishedApprovalCard(action);
}

const approvalWorkspaceState = {
    actions: [],
    view: "",
};

const suricataRuleInventoryState = {
    rules: [],
    facets: {
        hosts: [],
        interfaces: [],
        states: [],
        tags: [],
        counts: {},
    },
};

function populateApprovalFilter(selectId, values, allLabel, labeler = approvalLabel) {
    const select = byId(selectId);
    if (!select) return;
    const current = select.value;
    select.innerHTML = `<option value="">${escapeHtml(allLabel)}</option>${values
        .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(labeler(value))}</option>`)
        .join("")}`;
    if ([...select.options].some((option) => option.value === current)) {
        select.value = current;
    }
}

function refreshApprovalFilterOptions(actions) {
    const tags = [...new Set(actions.flatMap(approvalTags))].sort((a, b) => a.localeCompare(b));
    const risks = [...new Set(actions.map((action) => normalizeApprovalValue(action.risk || "unknown").toLowerCase()))]
        .filter(Boolean)
        .sort((a, b) => approvalRiskRank(b) - approvalRiskRank(a));
    const statuses = [...new Set(actions.map((action) => normalizeApprovalValue(action.status || "unknown").toLowerCase()))]
        .filter(Boolean)
        .sort((a, b) => approvalStatusLabel(a).localeCompare(approvalStatusLabel(b)));

    populateApprovalFilter("approval-tag-filter", tags, "태그 전체");
    populateApprovalFilter("approval-risk-filter", risks, "위험도 전체", riskLabel);
    populateApprovalFilter("approval-status-filter", statuses, "상태 전체", approvalStatusLabel);
}

function filteredApprovalActions() {
    const search = normalizeApprovalValue(byId("approval-search")?.value).toLowerCase();
    const tag = normalizeApprovalValue(byId("approval-tag-filter")?.value);
    const risk = normalizeApprovalValue(byId("approval-risk-filter")?.value).toLowerCase();
    const status = normalizeApprovalValue(byId("approval-status-filter")?.value).toLowerCase();
    const time = normalizeApprovalValue(byId("approval-time-filter")?.value);
    const sort = normalizeApprovalValue(byId("approval-sort")?.value || "newest");
    const now = Date.now();
    const windows = {
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
        "30d": 30 * 24 * 60 * 60 * 1000,
    };

    const filtered = approvalWorkspaceState.actions.filter((action) => {
        if (search && !approvalSearchText(action).includes(search)) return false;
        if (tag && !approvalTags(action).includes(tag)) return false;
        if (risk && normalizeApprovalValue(action.risk).toLowerCase() !== risk) return false;
        if (status && normalizeApprovalValue(action.status).toLowerCase() !== status) return false;
        if (time) {
            const createdAt = approvalDateValue(action.created_at);
            if (!createdAt || now - createdAt > windows[time]) return false;
        }
        return true;
    });

    filtered.sort((left, right) => {
        if (sort === "oldest") return approvalDateValue(left.created_at) - approvalDateValue(right.created_at);
        if (sort === "risk_desc") return approvalRiskRank(right.risk) - approvalRiskRank(left.risk)
            || approvalDateValue(right.created_at) - approvalDateValue(left.created_at);
        if (sort === "risk_asc") return approvalRiskRank(left.risk) - approvalRiskRank(right.risk)
            || approvalDateValue(right.created_at) - approvalDateValue(left.created_at);
        if (sort === "status") return approvalStatusLabel(left.status).localeCompare(approvalStatusLabel(right.status))
            || approvalDateValue(right.created_at) - approvalDateValue(left.created_at);
        if (sort === "type") return approvalLabel(left.type).localeCompare(approvalLabel(right.type))
            || approvalDateValue(right.created_at) - approvalDateValue(left.created_at);
        return approvalDateValue(right.created_at) - approvalDateValue(left.created_at);
    });

    return filtered;
}

function renderApprovalSummary(actions) {
    const counts = {pending: 0, approved: 0, rejected: 0, superseded: 0};
    actions.forEach((action) => {
        const view = approvalView(action);
        if (view in counts) counts[view] += 1;
    });
    Object.entries(counts).forEach(([view, count]) => {
        byId(`approval-count-${view}`).textContent = String(count);
    });
    const all = byId("approval-count-all");
    if (all) all.textContent = String(actions.length);
    const total = byId("approval-total-label");
    if (total) total.textContent = `조치 ${actions.length}건`;
}

function setApprovalView(view) {
    approvalWorkspaceState.view = APPROVAL_VIEW_LABELS[view] ? view : "pending";
    renderApprovalWorkspace();
}

function renderApprovalWorkspace() {
    const view = approvalWorkspaceState.view || "pending";
    const matched = filteredApprovalActions();
    const actions = view === "all" ? matched : matched.filter((action) => approvalView(action) === view);
    const container = byId("approval-list");
    container.classList.remove("loading-block");

    let html = "";
    if (view === "all") {
        const open = actions.filter((action) => approvalView(action) === "pending");
        const done = actions.filter((action) => approvalView(action) !== "pending");
        html = open.map(detailedApprovalCard).join("");
        if (done.length) {
            html += `<p class="approval-list-divider">처리 끝난 요청 ${done.length}건</p>${done.map(detailedApprovalCard).join("")}`;
        }
    } else {
        html = actions.map(detailedApprovalCard).join("");
    }
    container.innerHTML = html || (view === "pending"
        ? `<div class="empty-state">처리할 승인 요청이 없습니다. <button class="button secondary small" type="button" data-approval-view="all">지난 기록 보기</button></div>`
        : `<div class="empty-state">조건에 맞는 요청이 없습니다.</div>`);

    document.querySelectorAll(".approval-view-tabs [data-approval-view]").forEach((button) => {
        const active = button.dataset.approvalView === view;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-selected", active ? "true" : "false");
    });
    container.querySelectorAll("[data-approval-view]").forEach((button) => {
        button.addEventListener("click", () => setApprovalView(button.dataset.approvalView));
    });

    byId("approval-results-label").textContent = `${APPROVAL_VIEW_LABELS[view]} ${actions.length}건`;
    wireApprovalDecisionButtons();
}

async function loadApprovalWorkspace() {
    const container = byId("approval-list");
    container.classList.add("loading-block");
    container.textContent = "승인 대기열을 불러오는 중…";
    const data = await api("/api/actions");
    approvalWorkspaceState.actions = Array.isArray(data.actions) ? data.actions : [];
    // First visit: open on what needs a decision, or on the history when nothing does.
    if (!approvalWorkspaceState.view) {
        const hasPending = approvalWorkspaceState.actions.some((action) => approvalView(action) === "pending");
        approvalWorkspaceState.view = hasPending ? "pending" : "all";
    }
    refreshApprovalFilterOptions(approvalWorkspaceState.actions);
    renderApprovalSummary(approvalWorkspaceState.actions);
    renderApprovalWorkspace();
    return data;
}

async function reloadVisibleActionWorkspace() {
    if (page === "actions") {
        await loadApprovalWorkspace();
    } else if (page === "rules") {
        await loadRuleApprovalWorkspace();
    }
}

async function decideAction(id, decision, note = "") {
    await api(`/api/actions/${encodeURIComponent(id)}/decision`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({decision, note}),
    });
    toast(`${id} ${decision === "approve" ? "승인됨" : "반려됨"}`);
    await reloadVisibleActionWorkspace();
}

function approvalRuleEditValues(id) {
    const escapedId = CSS.escape(id);
    const sid = document.querySelector(`.approval-rule-sid[data-id="${escapedId}"]`)?.value || "";
    const revision = document.querySelector(`.approval-rule-revision[data-id="${escapedId}"]`)?.value || "";
    return {sid, revision};
}

async function saveSuricataIdentifiers(id) {
    const values = approvalRuleEditValues(id);
    await api(`/api/actions/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(values),
    });
    toast(`${id} 룰 식별자를 수정했습니다.`);
    await reloadVisibleActionWorkspace();
}

async function resendApproval(id) {
    const action = approvalWorkspaceState.actions.find((item) => item.id === id);
    const body = {
        note: document.querySelector(
            `.approval-resend-note[data-id="${CSS.escape(id)}"]`
        )?.value || "",
    };
    if (normalizeApprovalValue(action?.type) === "suricata_rule") {
        Object.assign(body, approvalRuleEditValues(id));
    }
    const result = await api(`/api/actions/${encodeURIComponent(id)}/resend`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body),
    });
    toast(`${result.action.id} 승인을 다시 요청했습니다.`);
    await reloadVisibleActionWorkspace();
}

function wireApprovalDecisionButtons() {
    document.querySelectorAll(".action-decision").forEach((button) => {
        button.addEventListener("click", async () => {
            const id = button.dataset.id;
            const note = document.querySelector(`.approval-decision-note[data-id="${CSS.escape(id)}"]`)?.value || "";
            const card = button.closest(".approval-card");
            card?.querySelectorAll("button").forEach((item) => { item.disabled = true; });
            try {
                await decideAction(id, button.dataset.decision, note);
            } catch (error) {
                card?.querySelectorAll("button").forEach((item) => { item.disabled = false; });
                toast(error.message);
            }
        });
    });

    document.querySelectorAll(".save-rule-identifiers").forEach((button) => {
        button.addEventListener("click", async () => {
            const card = button.closest(".approval-card");
            card?.querySelectorAll("button").forEach((item) => { item.disabled = true; });
            try {
                await saveSuricataIdentifiers(button.dataset.id);
            } catch (error) {
                card?.querySelectorAll("button").forEach((item) => { item.disabled = false; });
                toast(error.message);
            }
        });
    });

    document.querySelectorAll(".action-resend").forEach((button) => {
        button.addEventListener("click", async () => {
            const card = button.closest(".approval-card");
            card?.querySelectorAll("button").forEach((item) => { item.disabled = true; });
            try {
                await resendApproval(button.dataset.id);
            } catch (error) {
                card?.querySelectorAll("button").forEach((item) => { item.disabled = false; });
                toast(error.message);
            }
        });
    });
}

function initResponse() {
    loadVelociraptorClients("response-host");
    loadVelociraptorFlows("response-host", "response-flow-list");
    loadActionList("response-action-list", "velociraptor_");
    byId("response-agent-form").addEventListener("submit", (e) => { e.preventDefault(); const params = new URLSearchParams({mode:"velociraptor_response", host:byId("response-host").value, incident:byId("response-incident").value, prompt:`원하는 결과: ${byId("response-outcome").value}\n증거: ${byId("response-evidence").value}`}); location.href = `/agent?${params}`; });
}

const RULE_CHECK_KO = {
    "Rule length must be between 30 and 8000 characters.": "룰 길이는 30~8000자여야 합니다.",
    "Rule must begin with an action and protocol, such as alert tcp.": "동작과 프로토콜로 시작해야 합니다 (예: alert tcp).",
    "Rule options must be enclosed in parentheses.": "옵션을 괄호 ( ) 안에 넣어야 합니다.",
    "Rule must include msg.": "msg 옵션이 필요합니다.",
    "Rule must include a numeric sid.": "숫자 sid가 필요합니다.",
    "Use a locally managed SID range to avoid vendor-rule collisions.": "기본 룰과 겹치지 않게 1000000 이상 SID를 쓰세요.",
    "Rule should include rev.": "rev(개정 번호)를 넣는 것이 좋습니다.",
    "Consider a flow direction/state constraint to reduce false positives.": "오탐을 줄이려면 flow 조건을 넣어 보세요.",
    "The rule has no content or PCRE condition and may be overly broad.": "content나 pcre 조건이 없어 너무 넓게 잡힐 수 있습니다.",
};

const ruleEditorState = {validated: false, saved: false, staged: ""};

function updateRuleSteps() {
    const {validated, saved, staged} = ruleEditorState;
    const current = staged ? "" : !validated ? "validate" : !saved ? "save" : "stage";
    const done = {
        write: Boolean(byId("rule-name")?.value.trim() && byId("rule-text")?.value.trim()) || validated,
        validate: validated,
        save: saved,
        stage: Boolean(staged),
    };
    document.querySelectorAll("#rule-steps [data-rule-step]").forEach((item) => {
        const step = item.dataset.ruleStep;
        item.classList.toggle("is-done", done[step]);
        item.classList.toggle("is-current", done.write ? step === current : step === "write");
    });
    document.querySelectorAll("[data-rule-step-button]").forEach((button) => {
        const next = button.dataset.ruleStepButton === current;
        button.classList.toggle("primary", next);
        button.classList.toggle("secondary", !next);
    });
}

function markRuleEditorChanged() {
    ruleEditorState.validated = false;
    ruleEditorState.saved = false;
    ruleEditorState.staged = "";
    updateRuleSteps();
}

async function validateRule() {
    const data = await api("/api/rules/validate", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({rule:byId("rule-text").value})});
    const ko = (text) => RULE_CHECK_KO[text] || text;
    const errors = data.errors.map((x) => `<li>${escapeHtml(ko(x))}</li>`).join("");
    const warnings = data.warnings.map((x) => `<li>${escapeHtml(ko(x))}</li>`).join("");
    const box = byId("rule-validation");
    box.className = `validation-output ${data.valid ? "rule-check-ok" : "rule-check-bad"}`;
    box.innerHTML = `<div class="validation-block"><strong>${data.valid ? "문법 통과" : "문법 오류"}</strong>${errors ? `<ul>${errors}</ul>` : ""}${warnings ? `<p class="muted">참고</p><ul>${warnings}</ul>` : ""}<p class="muted">형식만 확인합니다. 실제 센서 적용 전 suricata -T 확인이 필요합니다.</p></div>`;
    ruleEditorState.validated = Boolean(data.valid);
    if (!data.valid) ruleEditorState.saved = false;
    updateRuleSteps();
    return data;
}

const RULE_SOURCE_LABELS = {
    rule_editor: "직접 작성",
    manual: "직접 작성",
    verified: "검증된 제안",
    agent: "AI 제안",
    suricata_rule: "AI 제안",
};

const RULE_ACTION_LABELS = {alert: "탐지", drop: "차단", reject: "거부", pass: "통과"};

function ruleInventoryLabel(value) {
    return approvalLabel(normalizeApprovalValue(value));
}

function ruleSourceLabel(value) {
    const key = normalizeApprovalValue(value).toLowerCase();
    if (RULE_SOURCE_LABELS[key]) return RULE_SOURCE_LABELS[key];
    if (key.startsWith("agent")) return "AI 제안";
    return ruleInventoryLabel(value);
}

// Display-only Korean labels for rule state values; the raw state is kept for filtering.
const RULE_STATE_LABELS = {
    draft: "초안",
    staged: "준비됨",
    active: "적용 중",
    enabled: "활성화됨",
    disabled: "비활성화됨",
    pending: "검토 대기",
    pending_approval: "검토 대기",
    approved: "승인됨",
    approved_staged: "승인됨 · 실행 안 됨",
    submitted: "제출됨",
    deployed: "배포됨",
    rejected: "반려됨",
    failed: "실패",
    dispatch_failed: "전송 실패",
};

function ruleStateLabel(value) {
    const key = normalizeApprovalValue(value).toLowerCase();
    return RULE_STATE_LABELS[key] || ruleInventoryLabel(value);
}

function ruleInventoryStateClass(value) {
    return `state-${normalizeApprovalValue(value).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

function ruleInventorySearchText(rule) {
    return [
        rule.id,
        rule.name,
        rule.description,
        rule.host,
        rule.interface,
        rule.rule,
        rule.action,
        rule.protocol,
        rule.sid,
        rule.revision,
        rule.state,
        rule.source,
        ...(Array.isArray(rule.tags) ? rule.tags : []),
    ].map((value) => normalizeApprovalValue(value).toLowerCase()).join(" ");
}

function refreshRuleInventoryOptions() {
    const facets = suricataRuleInventoryState.facets || {};
    const options = [
        ["rule-db-host", facets.hosts || [], "호스트 전체", ruleInventoryLabel],
        ["rule-db-interface", facets.interfaces || [], "인터페이스 전체", ruleInventoryLabel],
        ["rule-db-state", facets.states || [], "상태 전체", ruleStateLabel],
        ["rule-db-tag", facets.tags || [], "태그 전체", ruleInventoryLabel],
    ];
    options.forEach(([id, values, defaultLabel, labeler]) => {
        const select = byId(id);
        if (!select) return;
        const selected = select.value;
        select.innerHTML = `<option value="">${escapeHtml(defaultLabel)}</option>`
            + values.map((value) => (
                `<option value="${escapeHtml(value)}">${escapeHtml(labeler(value))}</option>`
            )).join("");
        if (values.includes(selected)) select.value = selected;
    });

    byId("rule-host-options").innerHTML = (facets.hosts || [])
        .map((value) => `<option value="${escapeHtml(value)}"></option>`)
        .join("");
    byId("rule-interface-options").innerHTML = (facets.interfaces || [])
        .map((value) => `<option value="${escapeHtml(value)}"></option>`)
        .join("");
}

function filteredRuleInventory() {
    const search = normalizeApprovalValue(byId("rule-db-search")?.value).toLowerCase();
    const host = normalizeApprovalValue(byId("rule-db-host")?.value);
    const iface = normalizeApprovalValue(byId("rule-db-interface")?.value);
    const state = normalizeApprovalValue(byId("rule-db-state")?.value);
    const tag = normalizeApprovalValue(byId("rule-db-tag")?.value).toLowerCase();
    const enabled = normalizeApprovalValue(byId("rule-db-enabled")?.value);
    const sort = normalizeApprovalValue(byId("rule-db-sort")?.value || "updated_desc");

    const rules = suricataRuleInventoryState.rules.filter((rule) => {
        if (search && !ruleInventorySearchText(rule).includes(search)) return false;
        if (host && rule.host !== host) return false;
        if (iface && rule.interface !== iface) return false;
        if (state && rule.state !== state) return false;
        if (tag && !(rule.tags || []).some((value) => value.toLowerCase() === tag)) return false;
        if (enabled === "true" && !rule.enabled) return false;
        if (enabled === "false" && rule.enabled) return false;
        return true;
    });

    rules.sort((left, right) => {
        if (sort === "updated_asc") {
            return approvalDateValue(left.updated_at) - approvalDateValue(right.updated_at);
        }
        if (sort === "host") {
            return left.host.localeCompare(right.host)
                || left.interface.localeCompare(right.interface)
                || left.sid - right.sid;
        }
        if (sort === "interface") {
            return left.interface.localeCompare(right.interface)
                || left.host.localeCompare(right.host)
                || left.sid - right.sid;
        }
        if (sort === "sid") return left.sid - right.sid;
        if (sort === "state") {
            return left.state.localeCompare(right.state)
                || approvalDateValue(right.updated_at) - approvalDateValue(left.updated_at);
        }
        return approvalDateValue(right.updated_at) - approvalDateValue(left.updated_at);
    });
    return rules;
}

function ruleInventorySummary() {
    const counts = suricataRuleInventoryState.facets?.counts || {};
    return [
        ["사용함", counts.enabled || 0, "state-active"],
        ["사용 안 함", counts.disabled || 0, "state-disabled"],
        ["적용 중", counts.active || 0, "state-active"],
        ["준비됨", counts.staged || 0, "state-staged"],
    ].map(([label, value, className]) => `
        <span class="rule-stat"><span class="rule-db-dot ${className}"></span>${escapeHtml(label)} <strong>${escapeHtml(value)}</strong></span>
    `).join("");
}

function ruleDatabaseCard(rule) {
    const tags = (Array.isArray(rule.tags) ? rule.tags : [])
        .map((tag) => `<span class="approval-tag">${escapeHtml(tag)}</span>`)
        .join("");
    const updated = approvalDateLabel(rule.updated_at);
    const stateClass = ruleInventoryStateClass(rule.state);
    const stageLabel = rule.enabled ? "배포 승인 요청" : "사용 중지 승인 요청";
    const action = normalizeApprovalValue(rule.action).toLowerCase();
    const meta = [
        `${rule.host} · ${rule.interface}`,
        `${RULE_ACTION_LABELS[action] || rule.action} · ${normalizeApprovalValue(rule.protocol).toUpperCase()}`,
        `SID ${rule.sid} · rev ${rule.revision}`,
        rule.state === "disabled" ? "" : (rule.enabled ? "사용함" : "사용 안 함"),
    ].filter(Boolean);

    return `
        <article class="rule-database-card" data-rule-id="${escapeHtml(rule.id)}">
            <header class="rule-database-card-header">
                <div class="rule-database-title">
                    <span class="rule-db-dot ${stateClass}"></span>
                    <div>
                        <h3>${escapeHtml(rule.name)}</h3>
                        <p class="rule-database-meta-line">${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</p>
                    </div>
                </div>
                <span class="approval-status-chip ${stateClass}">
                    <span></span>${escapeHtml(ruleStateLabel(rule.state))}
                </span>
            </header>

            ${normalizeApprovalValue(rule.description) ? `<p class="rule-database-description">${escapeHtml(rule.description)}</p>` : ""}
            ${tags ? `<div class="approval-tag-row">${tags}</div>` : ""}

            <pre class="rule-database-code"><code>${escapeHtml(rule.rule)}</code></pre>

            <p class="rule-database-foot">
                <span>${escapeHtml(ruleSourceLabel(rule.source))}</span>
                <span>수정 ${escapeHtml(updated)}</span>
                ${rule.last_action_id ? `<span>최근 요청 ${escapeHtml(rule.last_action_id)}</span>` : ""}
                <span class="rule-database-id">${escapeHtml(rule.id)}</span>
            </p>

            <footer class="rule-database-actions">
                ${rule.state !== "active" ? `
                    <button class="button ghost small rule-delete-button delete-rule-record"
                        data-id="${escapeHtml(rule.id)}" type="button">삭제</button>
                ` : ""}
                <span class="rules-editor-spacer"></span>
                <button class="button secondary small edit-rule-record"
                    data-id="${escapeHtml(rule.id)}" type="button">수정</button>
                <button class="button secondary small toggle-rule-record"
                    data-id="${escapeHtml(rule.id)}" type="button">
                    ${rule.enabled ? "사용 안 함으로" : "사용함으로"}
                </button>
                <button class="button primary small stage-rule-record-card"
                    data-id="${escapeHtml(rule.id)}" type="button">${escapeHtml(stageLabel)}</button>
            </footer>
        </article>
    `;
}

function renderRuleInventory() {
    const rules = filteredRuleInventory();
    const container = byId("rule-database-list");
    if (!container) return;

    container.classList.remove("loading-block");
    container.innerHTML = rules.map(ruleDatabaseCard).join("")
        || `<div class="empty-state">선택한 필터와 일치하는 룰이 없습니다.</div>`;

    byId("rule-db-results").textContent =
        `전체 ${suricataRuleInventoryState.rules.length}개 중 ${rules.length}개 표시`;
    byId("rule-inventory-total").textContent =
        `룰 ${suricataRuleInventoryState.rules.length}개`;
    byId("rule-inventory-summary").innerHTML = ruleInventorySummary();

    container.querySelectorAll(".edit-rule-record").forEach((button) => {
        button.addEventListener("click", () => editRuleRecord(button.dataset.id));
    });
    container.querySelectorAll(".toggle-rule-record").forEach((button) => {
        button.addEventListener("click", () => toggleRuleRecord(button.dataset.id));
    });
    container.querySelectorAll(".stage-rule-record-card").forEach((button) => {
        button.addEventListener("click", () => stageRuleRecord(button.dataset.id));
    });
    container.querySelectorAll(".delete-rule-record").forEach((button) => {
        button.addEventListener("click", () => deleteRuleRecord(button.dataset.id));
    });
}

async function loadRuleInventory() {
    const container = byId("rule-database-list");
    container.classList.add("loading-block");
    container.textContent = "룰을 불러오는 중…";
    const data = await api("/api/rules");
    suricataRuleInventoryState.rules = Array.isArray(data.rules) ? data.rules : [];
    suricataRuleInventoryState.facets = data.facets || {};
    refreshRuleInventoryOptions();
    renderRuleInventory();
}

function clearRuleEditor() {
    byId("rule-record-id").value = "";
    byId("rule-name").value = "";
    byId("rule-host").value = "";
    byId("rule-interface").value = "";
    byId("rule-tags").value = "";
    byId("rule-intent").value = "";
    byId("rule-enabled").checked = true;
    byId("rule-validation").className = "validation-output empty-state";
    byId("rule-validation").textContent = "문법 검증 전";
    byId("save-rule-record").textContent = "저장";
    markRuleEditorChanged();
}

function editRuleRecord(id) {
    const rule = suricataRuleInventoryState.rules.find((item) => item.id === id);
    if (!rule) return;
    byId("rule-record-id").value = rule.id;
    byId("rule-name").value = rule.name;
    byId("rule-host").value = rule.host;
    byId("rule-interface").value = rule.interface;
    byId("rule-tags").value = (rule.tags || []).join(", ");
    byId("rule-intent").value = rule.description || "";
    byId("rule-text").value = rule.rule;
    byId("rule-enabled").checked = Boolean(rule.enabled);
    byId("save-rule-record").textContent = "수정 저장";
    // A stored rule passed validation when it was saved.
    ruleEditorState.validated = true;
    ruleEditorState.saved = true;
    ruleEditorState.staged = "";
    byId("rule-validation").className = "validation-output empty-state";
    byId("rule-validation").textContent = `${rule.name} 불러옴 · 바꾸면 다시 검증합니다`;
    updateRuleSteps();
    byId("rule-form").scrollIntoView({behavior: "smooth", block: "start"});
}

function ruleEditorPayload() {
    return {
        name: byId("rule-name").value,
        host: byId("rule-host").value,
        interface: byId("rule-interface").value,
        tags: byId("rule-tags").value,
        description: byId("rule-intent").value,
        rule: byId("rule-text").value,
        enabled: byId("rule-enabled").checked,
        source: "rule_editor",
    };
}

async function saveRuleRecord() {
    const validation = await validateRule();
    if (!validation.valid) {
        toast("저장하기 전에 검증 오류를 고쳐 주세요");
        return null;
    }

    const id = byId("rule-record-id").value;
    const result = await api(id ? `/api/rules/${encodeURIComponent(id)}` : "/api/rules", {
        method: id ? "PATCH" : "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(ruleEditorPayload()),
    });
    toast(`${result.rule.id} ${id ? "수정됨" : "저장됨"}`);
    await loadRuleInventory();
    editRuleRecord(result.rule.id);
    return result.rule;
}

async function stageRuleRecord(id) {
    let ruleId = id || byId("rule-record-id").value;
    if (!ruleId) {
        const saved = await saveRuleRecord();
        ruleId = saved?.id || "";
    }
    if (!ruleId) return;

    const result = await api(`/api/rules/${encodeURIComponent(ruleId)}/stage`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: "{}",
    });
    toast(`${result.action.id} 승인 요청을 올렸습니다.`);
    await loadRuleInventory();
    if (!id || id === byId("rule-record-id").value) {
        ruleEditorState.staged = result.action.id;
        const box = byId("rule-validation");
        box.className = "validation-output rule-check-ok";
        box.innerHTML = `<div class="validation-block"><strong>승인 요청을 올렸습니다 (${escapeHtml(result.action.id)})</strong><p><a href="/actions">승인 대기열에서 보기 →</a></p></div>`;
        updateRuleSteps();
    }
}

async function toggleRuleRecord(id) {
    const rule = suricataRuleInventoryState.rules.find((item) => item.id === id);
    if (!rule) return;
    await api(`/api/rules/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            enabled: !rule.enabled,
            state: !rule.enabled ? "draft" : "disabled",
        }),
    });
    toast(`${id} 목표 상태를 변경했습니다.`);
    await loadRuleInventory();
}

async function deleteRuleRecord(id) {
    const rule = suricataRuleInventoryState.rules.find((item) => item.id === id);
    if (!rule) return;
    if (!window.confirm(`${rule.name} 룰을 삭제할까요?`)) return;
    await api(`/api/rules/${encodeURIComponent(id)}`, {method: "DELETE"});
    toast(`${id} 삭제됨`);
    if (byId("rule-record-id").value === id) clearRuleEditor();
    await loadRuleInventory();
}

function initRules() {
    [
        "rule-db-search",
        "rule-db-host",
        "rule-db-interface",
        "rule-db-state",
        "rule-db-tag",
        "rule-db-enabled",
        "rule-db-sort",
    ].forEach((id) => {
        byId(id)?.addEventListener(
            id === "rule-db-search" ? "input" : "change",
            renderRuleInventory
        );
    });

    byId("clear-rule-db-filters")?.addEventListener("click", () => {
        byId("rule-inventory-filters").reset();
        renderRuleInventory();
    });
    byId("refresh-rule-inventory")?.addEventListener("click", loadRuleInventory);
    byId("new-rule-record")?.addEventListener("click", clearRuleEditor);
    byId("rule-form").addEventListener("input", markRuleEditorChanged);
    byId("validate-rule").addEventListener("click", () => validateRule().catch((error) => toast(error.message)));
    updateRuleSteps();
    byId("ask-rule-agent").addEventListener("click", () => {
        const params = new URLSearchParams({
            mode: "suricata_rule",
            prompt: `탐지 의도: ${byId("rule-intent").value}\n룰 초안: ${byId("rule-text").value}`,
        });
        location.href = `/agent?${params}`;
    });
    byId("rule-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            await saveRuleRecord();
        } catch (error) {
            toast(error.message);
        }
    });
    byId("stage-rule-record").addEventListener("click", async () => {
        try {
            await stageRuleRecord();
        } catch (error) {
            toast(error.message);
        }
    });

    loadRuleInventory().catch((error) => {
        byId("rule-database-list").classList.remove("loading-block");
        byId("rule-database-list").innerHTML =
            `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    });
}


async function initActions() {
    const filterIds = [
        "approval-search",
        "approval-tag-filter",
        "approval-risk-filter",
        "approval-time-filter",
        "approval-sort",
    ];
    filterIds.forEach((id) => {
        byId(id)?.addEventListener(id === "approval-search" ? "input" : "change", renderApprovalWorkspace);
    });
    document.querySelectorAll(".approval-view-tabs [data-approval-view]").forEach((button) => {
        button.addEventListener("click", () => setApprovalView(button.dataset.approvalView));
    });
    byId("clear-approval-filters")?.addEventListener("click", () => {
        byId("approval-filters")?.reset();
        renderApprovalWorkspace();
    });
    byId("refresh-approvals")?.addEventListener("click", loadApprovalWorkspace);
    await loadApprovalWorkspace();
}

const AUDIT_LABELS = {
    login_succeeded: "로그인 성공",
    login_failed: "로그인 실패",
    logout: "로그아웃",
    password_changed: "비밀번호 변경",
    user_created: "사용자 생성",
    user_password_reset: "비밀번호 초기화",
    user_role_changed: "역할 변경",
    user_status_changed: "계정 상태 변경",
    wazuh_log_search: "로그 검색",
    wazuh_log_search_check: "추천 검색 건수 확인",
    agent_request: "AI 작업공간 요청",
    agent_conversation: "AI 일반 대화",
    agent_processing_error: "AI 작업공간 처리 오류",
    alert_analysis_request: "경보 분석 요청",
    alert_analysis_completed: "경보 분석 완료",
    evidence_fitted_to_context: "증거를 문맥 한도에 맞춤",
    evidence_agent_completed: "증거 수집 에이전트 완료",
    evidence_agent_failed: "증거 수집 에이전트 실패",
    evidence_agent_reverted: "증거 수집 결과 되돌림",
    evidence_agent_skipped: "증거 수집 에이전트 건너뜀",
    analyst_feedback_recorded: "분석가 판정 저장",
    redteam_eval_dispatched: "레드팀 평가 전송",
    action_queued: "조치 승인 요청",
    action_decision: "조치 승인 결정",
    action_resubmitted: "조치 재요청",
    action_updated: "조치 수정",
    rule_validation: "룰 검증",
    suricata_rule_created: "Suricata 룰 생성",
    suricata_rule_updated: "Suricata 룰 수정",
    suricata_rule_deleted: "Suricata 룰 삭제",
    suricata_rule_verified: "Suricata 룰 검증 통과",
    suricata_rule_verification_failed: "Suricata 룰 검증 실패",
    suricata_rule_staged: "Suricata 룰 승인 요청",
    suricata_rule_stage_blocked: "Suricata 룰 승인 요청 차단",
    suricata_action_approval_blocked: "Suricata 승인 차단",
    suricata_actions_superseded: "Suricata 이전 요청 대체",
    suricata_verified_rule_imported: "검증된 룰 가져오기",
    suricata_verified_import_blocked: "검증된 룰 가져오기 차단",
    auto_report_created: "자동 보고서 생성",
    auto_report_analyzed: "자동 보고서 AI 분석",
    auto_report_ai_failed: "자동 보고서 AI 실패",
    auto_report_ai_expired: "자동 보고서 AI 만료",
    auto_report_bundle_failed: "자동 보고서 증거 수집 실패",
    auto_report_fetch_failed: "자동 보고서 경보 조회 실패",
    auto_report_cycle_failed: "자동 보고서 실행 실패",
    auto_report_reviewed: "자동 보고서 검토",
    auto_report_run_requested: "자동 보고서 수동 실행",
    auto_report_rescored: "자동 보고서 우선순위 재계산",
    agent_tool_call: "AI 도구 호출",
    agent_collection_review_created: "AI 수집 검토 요청 생성",
    workspace_continued: "AI 작업공간에서 이어가기",
    log_search_link: "로그 검색 바로가기",
    log_search_direct: "로그 직접 검색",
    redteam_deep_scan_requested: "레드팀 심층 점검 요청",
    suricata_legacy_action_superseded: "Suricata 이전 요청 정리",
    test_action_record_removed: "테스트 조치 기록 삭제",
    velociraptor_collection_submitted: "Velociraptor 수집 제출",
    velociraptor_collection_reviewed: "Velociraptor 수집 검토",
    velociraptor_collection_decision: "Velociraptor 수집 승인 결정",
    velociraptor_collection_cancel_requested: "Velociraptor 수집 취소 요청",
};
const AUDIT_GROUPS = [
    ["로그인 · 계정", /^(login|logout|password|user_)/],
    ["AI 분석", /^(agent|alert_analysis|evidence|analyst_feedback|workspace)/],
    ["자동 보고서", /^auto_report/],
    ["레드팀", /^redteam/],
    ["조치 · 승인", /^(action_|test_action)/],
    ["Suricata 룰", /^(suricata|rule_)/],
    ["Velociraptor", /^velociraptor/],
    ["로그 검색", /^(wazuh_log|log_search)/],
];
// Background count checks from the search page; noisy, so hidden unless asked for.
const AUDIT_QUIET_TYPES = new Set(["wazuh_log_search_check"]);
const AUDIT_TONE = {
    login_failed: "bad", auto_report_ai_failed: "bad", auto_report_fetch_failed: "bad", auto_report_cycle_failed: "bad",
    evidence_agent_failed: "bad", agent_processing_error: "bad", suricata_rule_verification_failed: "bad",
    suricata_rule_stage_blocked: "warn", suricata_action_approval_blocked: "warn", suricata_verified_import_blocked: "warn",
    evidence_agent_reverted: "warn", evidence_fitted_to_context: "warn",
};
// One readable line per event; the full record stays one click away.
const AUDIT_SUMMARY_KEYS = [
    ["username", "사용자"], ["query", "쿼리"], ["index", "인덱스"], ["result_count", "결과"],
    ["alert_id", "경보"], ["report_id", "보고서"], ["analysis_id", "분석"], ["action_id", "조치"],
    ["mode", "모드"], ["verdict", "판정"], ["decision", "결정"], ["status", "상태"], ["status_code", "HTTP"],
    ["job_id", "작업"], ["dropped", "제외"], ["final_chars", "최종 글자 수"], ["reason", "이유"],
    ["remote_addr", "접속 주소"], ["error", "오류"], ["redteam", "레드팀"],
];

function auditSummary(detail = {}) {
    return AUDIT_SUMMARY_KEYS
        .filter(([key]) => detail[key] !== undefined && detail[key] !== null && detail[key] !== "")
        .slice(0, 5)
        .map(([key, label]) => `${label} ${typeof detail[key] === "object" ? JSON.stringify(detail[key]) : String(detail[key])}`)
        .map((text) => (text.length > 90 ? `${text.slice(0, 89)}…` : text))
        .join(" · ");
}

async function initAudit() {
    const list = byId("audit-list");
    const typeSelect = byId("audit-type");
    const actorSelect = byId("audit-actor");
    const params = new URLSearchParams({
        type: typeSelect?.value || "",
        actor: actorSelect?.value || "",
        q: byId("audit-q")?.value.trim() || "",
    });
    const data = await api(`/api/audit?${params}`);

    const fillTypes = (select, values) => {
        if (!select) return;
        const current = select.value;
        const label = (value) => AUDIT_LABELS[value] || value;
        const groups = AUDIT_GROUPS.map(([name, pattern]) => [name, values.filter((value) => pattern.test(value))]);
        const grouped = new Set(groups.flatMap(([, items]) => items));
        groups.push(["기타", values.filter((value) => !grouped.has(value))]);
        select.innerHTML = `<option value="">전체</option>` + groups
            .filter(([, items]) => items.length)
            .map(([name, items]) => `<optgroup label="${escapeHtml(name)}">${items
                .sort((a, b) => label(a).localeCompare(label(b), "ko"))
                .map((value) => `<option value="${escapeHtml(value)}" title="${escapeHtml(value)}">${escapeHtml(label(value))}</option>`).join("")}</optgroup>`)
            .join("");
        select.value = values.includes(current) ? current : "";
    };
    const fill = (select, values, label) => {
        if (!select) return;
        const current = select.value;
        select.innerHTML = `<option value="">전체</option>` + values
            .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(label(value))}</option>`).join("");
        select.value = values.includes(current) ? current : "";
    };
    fillTypes(typeSelect, data.event_types || []);
    fill(actorSelect, data.actors || [], (value) => value);

    if (byId("audit-count")) {
        byId("audit-count").textContent = data.matched === data.total
            ? `전체 ${formatNumber(data.total)}건 중 최근 ${formatNumber((data.events || []).length)}건`
            : `조건에 맞는 ${formatNumber(data.matched)}건 (전체 ${formatNumber(data.total)}건) 중 최근 ${formatNumber((data.events || []).length)}건`;
    }
    const showQuiet = Boolean(typeSelect?.value) || Boolean(byId("audit-show-quiet")?.checked);
    const events = (data.events || []).filter((event) => showQuiet || !AUDIT_QUIET_TYPES.has(event.event_type));
    const hidden = (data.events || []).length - events.length;
    if (byId("audit-count") && hidden) byId("audit-count").textContent += ` · 추천 검색 건수 확인 ${formatNumber(hidden)}건 숨김`;
    list.classList.remove("loading-block");
    list.innerHTML = events.map((event) => {
        const actor = event.actor?.username || (event.actor?.kind === "system" ? "자동" : "");
        const summary = auditSummary(event.detail || {});
        return `<div class="audit-row audit-row-${AUDIT_TONE[event.event_type] || "plain"}">
            <span class="audit-time">${escapeHtml(new Date(event.timestamp).toLocaleString("ko-KR", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }))}</span>
            <strong class="audit-type" title="${escapeHtml(event.event_type)}">${escapeHtml(AUDIT_LABELS[event.event_type] || event.event_type)}</strong>
            <span class="audit-actor">${escapeHtml(actor || "—")}</span>
            <details class="audit-detail">
                <summary>${escapeHtml(summary || "상세 보기")}</summary>
                <pre>${escapeHtml(JSON.stringify(event.detail, null, 2))}</pre>
            </details>
        </div>`;
    }).join("") || `<div class="empty-state">조건에 맞는 감사 이벤트가 없습니다.</div>`;
}

function initAuditPage() {
    byId("refresh-audit")?.addEventListener("click", initAudit);
    byId("audit-filter")?.addEventListener("submit", (event) => {
        event.preventDefault();
        initAudit();
    });
    ["audit-type", "audit-actor", "audit-show-quiet"].forEach((id) => byId(id)?.addEventListener("change", initAudit));
    return initAudit();
}

async function init() {
    initSidebarNavigation();
    initTheme();
    await loadAuth();
    byId("refresh-services")?.addEventListener("click", loadServices);
    // Pages need the config. Wazuh service reachability is checked separately, so
    // the reachability probe runs alongside rather than delaying the content.
    await loadConfig();
    loadServices();
    if (page === "dashboard") await initDashboard();
    if (page === "agent") await initAgent();
    if (page === "alerts") initAlerts();
    if (page === "logs") initLogs();
    if (page === "hunts") await initHunts();
    if (page === "response") initResponse();
    if (page === "rules") initRules();
    if (page === "actions") await initActions();
    if (page === "audit") await initAuditPage();
}
init();


async function loadVelociraptorClients(selectId) {
    const select = byId(selectId);
    select.disabled = true;
    try {
        const data = await api("/api/velociraptor/clients");
        select.innerHTML = '<option value="">대상 클라이언트 선택</option>';
        for (const client of data.items) {
            const option = document.createElement("option");
            option.value = client.client_id;
            option.textContent = `${client.hostname || client.client_id} · ${client.client_id}`;
            select.appendChild(option);
        }
        select.disabled = data.items.length === 0;
        let note = document.getElementById(`${selectId}-inventory-note`);
        if (!note) {
            note = document.createElement("p");
            note.id = `${selectId}-inventory-note`;
            note.className = "muted";
            select.closest("label").after(note);
        }
        note.textContent = `조회된 클라이언트 ${data.retrieved_clients}개`;
    } catch (error) {
        select.innerHTML = '<option value="">클라이언트 조회 실패</option>';
        toast(error.message);
    }
}


async function loadVelociraptorFlows(selectId, containerId) {
    const select = byId(selectId);
    const container = byId(containerId);
    if (!select || !container) return;

    async function refresh() {
        const clientId = String(select.value || "").trim();
        if (!clientId) {
            container.innerHTML = `<div class="empty-state">클라이언트를 선택하면 기존 수집 결과를 조회합니다.</div>`;
            return;
        }

        container.textContent = "기존 수집 결과를 불러오는 중…";
        try {
            const data = await api(
                `/api/velociraptor/flows?client_id=${encodeURIComponent(clientId)}`
            );
            const flows = Array.isArray(data.flows) ? data.flows : [];

            container.innerHTML = flows.map((flow) => {
                const request = (
                    flow.request && typeof flow.request === "object"
                ) ? flow.request : {};
                const artifacts = Array.isArray(flow.artifacts)
                    ? flow.artifacts
                    : (
                        Array.isArray(request.artifacts)
                            ? request.artifacts
                            : []
                    );
                const flowId = flow.flow_id || flow.session_id || "flow ID 미표시";
                const state = flow.state || flow.status || "상태 미표시";
                const started = (
                    flow.create_time ||
                    flow.start_time ||
                    flow.timestamp ||
                    ""
                );

                return `<div class="hunt-card">
                    <div class="hunt-top">
                        <strong>${escapeHtml(String(flowId))}</strong>
                        <span class="status-text">${escapeHtml(String(state))}</span>
                    </div>
                    <p>${escapeHtml(
                        artifacts.length
                            ? artifacts.join(", ")
                            : "수집 항목 미표시"
                    )}</p>
                    <span class="muted">${escapeHtml(String(started))}</span>
                </div>`;
            }).join("") || `<div class="empty-state">
                이 클라이언트에 기존 수집 결과가 없습니다.
            </div>`;

            const note = document.createElement("p");
            note.className = "muted";
            note.textContent =
                `기존 수집 ${data.returned_flows}개 반환개`;
            container.appendChild(note);
        } catch (error) {
            container.textContent = "기존 수집 결과 조회 실패: " + error.message;
        }
    }

    select.addEventListener("change", refresh);
    await refresh();
}


/* HAWKI API workspace promotion */
function promoteVelociraptorWorkspace(flowId, formId, label) {
    const flow = byId(flowId);
    if (!flow) return;

    const form = byId(formId);
    const apiPanel = flow.closest(".panel");
    const proposalPanel = form?.closest(".panel");
    const workflow = apiPanel?.closest(".workflow-stack");

    // Keep the API workspace before the optional proposal section.
    if (workflow && apiPanel && proposalPanel && apiPanel !== proposalPanel) {
        workflow.insertBefore(apiPanel, workflow.firstElementChild);

        const link = proposalPanel.querySelector(
            'a[href*="/velociraptor/"]'
        );
        const header = apiPanel.querySelector(".panel-header");
        if (
            link &&
            header &&
            !header.querySelector('a[href*="/velociraptor/"]')
        ) {
            header.append(link);
        }
    }

    const parent = flow.parentElement;
    if (!parent || parent.querySelector("select[data-api-client-picker]")) {
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "api-client-picker";

    const title = document.createElement("label");
    title.className = "api-client-picker-label";
    title.textContent = label;

    const select = document.createElement("select");
    select.id = `api-${flowId}-client`;
    select.dataset.apiClientPicker = "true";
    select.setAttribute("aria-label", label);

    const count = document.createElement("span");
    count.className = "api-client-count";

    wrapper.append(title, select, count);
    parent.insertBefore(wrapper, flow);

    api("/api/velociraptor/clients")
        .then((data) => {
            const clients = Array.isArray(data.clients) ? data.clients : [];
            count.textContent = `조회된 클라이언트 ${clients.length}개`;

            for (const client of clients) {
                const option = document.createElement("option");
                option.value = String(client.client_id || "");
                option.textContent =
                    `${client.hostname || "알 수 없는 호스트"} · ` +
                    `${client.client_id || ""}`;
                select.append(option);
            }

            select.addEventListener("change", () => {
                if (typeof loadVelociraptorFlows === "function") {
                    loadVelociraptorFlows(select.id, flowId);
                }
            });

            if (select.value && typeof loadVelociraptorFlows === "function") {
                loadVelociraptorFlows(select.id, flowId);
            } else if (!clients.length) {
                flow.textContent = "등록된 클라이언트가 없습니다.";
            }
        })
        .catch(() => {
            count.textContent = "클라이언트 정보를 불러오지 못했습니다.";
        });
}

document.addEventListener("DOMContentLoaded", () => {
    promoteVelociraptorWorkspace(
        "hunt-flow-list",
        "hunt-agent-form",
        "대상 클라이언트",
    );
    promoteVelociraptorWorkspace(
        "response-flow-list",
        "response-agent-form",
        "대상 클라이언트",
    );
});


/* HAWKI reuse populated Velociraptor client picker */
function reuseVelociraptorClientPicker(flowId, formId, label) {
    const flow = byId(flowId);
    const form = byId(formId);
    const apiPanel = flow?.closest(".panel");
    if (!flow || !form || !apiPanel) return;

    const source = Array.from(form.querySelectorAll("select")).find((item) => {
        const id = String(item.id || "").toLowerCase();
        return (
            id.includes("client") ||
            Array.from(item.options).some((option) =>
                String(option.value || "").startsWith("C.")
            )
        );
    });

    if (!source) return;

    const hasClientOptions = Array.from(source.options).some((option) =>
        String(option.value || "").startsWith("C.")
    );
    if (!hasClientOptions) return;

    const generated = apiPanel.querySelector(
        "select[data-api-client-picker]"
    );
    generated?.closest(".api-client-picker")?.remove();

    const oldPicker = flow.parentElement?.querySelector(
        "select[data-api-client-picker]"
    );
    if (oldPicker && oldPicker !== source) {
        oldPicker.closest(".api-client-picker")?.remove();
    }

    const parent = flow.parentElement;
    if (!parent || parent.querySelector("select[data-api-client-picker]")) {
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "api-client-picker";

    const title = document.createElement("label");
    title.className = "api-client-picker-label";
    title.textContent = label;

    const count = document.createElement("span");
    count.className = "api-client-count";
    count.textContent = `조회된 클라이언트 ${source.options.length}개`;

    source.dataset.apiClientPicker = "true";
    wrapper.append(title, source, count);
    parent.insertBefore(wrapper, flow);

    if (!source.__hawkiFlowBound) {
        source.addEventListener("change", () => {
            if (typeof loadVelociraptorFlows === "function") {
                loadVelociraptorFlows(source.id, flowId);
            }
        });
        source.__hawkiFlowBound = true;
    }

    if (source.value && typeof loadVelociraptorFlows === "function") {
        loadVelociraptorFlows(source.id, flowId);
    }
}

function scheduleVelociraptorClientPickerRepair(
    flowId,
    formId,
    label,
) {
    [0, 300, 1000, 2000].forEach((delay) => {
        window.setTimeout(
            () => reuseVelociraptorClientPicker(flowId, formId, label),
            delay,
        );
    });
}

document.addEventListener("DOMContentLoaded", () => {
    scheduleVelociraptorClientPickerRepair(
        "hunt-flow-list",
        "hunt-agent-form",
        "대상 클라이언트",
    );
    scheduleVelociraptorClientPickerRepair(
        "response-flow-list",
        "response-agent-form",
        "대상 클라이언트",
    );
});


/* HAWKI readable Velociraptor timestamps */
function formatVelociraptorFlowTimes(container) {
    if (!container) return;

    const walker = document.createTreeWalker(
        container,
        NodeFilter.SHOW_TEXT,
    );
    const nodes = [];
    let node;
    while ((node = walker.nextNode())) {
        nodes.push(node);
    }

    for (const textNode of nodes) {
        const raw = textNode.nodeValue.trim();
        if (!/^\d{16}$/.test(raw)) continue;

        const date = new Date(Number(raw) / 1000);
        if (Number.isNaN(date.getTime())) continue;

        textNode.nodeValue = new Intl.DateTimeFormat(undefined, {
            dateStyle: "medium",
            timeStyle: "short",
        }).format(date);
    }
}

function observeVelociraptorFlowTimes(containerId) {
    const container = byId(containerId);
    if (!container || container.dataset.timeObserverAttached) return;

    container.dataset.timeObserverAttached = "true";
    formatVelociraptorFlowTimes(container);

    const observer = new MutationObserver(() => {
        formatVelociraptorFlowTimes(container);
    });
    observer.observe(container, {
        childList: true,
        subtree: true,
    });
}

document.addEventListener("DOMContentLoaded", () => {
    observeVelociraptorFlowTimes("hunt-flow-list");
    observeVelociraptorFlowTimes("response-flow-list");
});


/* HAWKI bounded flow-result cards V1 */
function hawkiFlowDate(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) {
        return value ? String(value) : "—";
    }

    const milliseconds =
        numeric > 100000000000000
            ? numeric / 1000
            : numeric > 100000000000
                ? numeric
                : numeric * 1000;

    const date = new Date(milliseconds);
    if (Number.isNaN(date.getTime())) return String(value);

    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
    }).format(date);
}

function hawkiFlowArtifacts(flow) {
    // Use the result sources recorded for this collection.
    if (Array.isArray(flow?.artifacts_with_results)) {
        return [...new Set(flow.artifacts_with_results.filter(
            value => typeof value === "string" && value.trim()
        ).map(value => value.trim()))];
    }
    const values = [];

    for (const candidate of [
        flow?.artifacts,
        flow?.artifact_names,
        flow?.request?.artifacts,
    ]) {
        if (Array.isArray(candidate)) values.push(...candidate);
        else if (candidate) values.push(candidate);
    }

    for (const candidate of [
        flow?.artifact,
        flow?.artifact_name,
    ]) {
        if (candidate) values.push(candidate);
    }

    return [...new Set(
        values
            .map((value) => String(value).trim())
            .filter(Boolean),
    )];
}

function hawkiJsonCell(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "object") {
        try {
            return JSON.stringify(value);
        } catch (_) {
            return String(value);
        }
    }
    return String(value);
}

function hawkiRenderFlowRows(container, payload) {
    const rows = Array.isArray(payload?.rows) ? payload.rows : [];
    if (!rows.length) {
        container.innerHTML =
            '<div class="empty-state">표시할 결과가 없습니다.</div>';
        return;
    }

    const columns = [
        ...new Set(rows.flatMap((row) => Object.keys(row))),
    ].slice(0, 8);

    const header = columns
        .map((column) => `<th>${escapeHtml(column)}</th>`)
        .join("");

    const body = rows
        .map((row) => {
            const cells = columns
                .map((column) =>
                    `<td>${escapeHtml(hawkiJsonCell(row[column]))}</td>`
                )
                .join("");
            return `<tr>${cells}</tr>`;
        })
        .join("");

    container.innerHTML =
        `<div class="flow-results-meta">` +
        `${escapeHtml(payload.artifact || "")} · ` +
        `${Number(payload.returned_rows || rows.length)}건` +
        `</div>` +
        `<div class="flow-results-table-wrap">` +
        `<table class="flow-results-table"><thead><tr>${header}</tr>` +
        `</thead><tbody>${body}</tbody></table></div>`;
}

async function hawkiLoadFlowRows(button) {
    const card = button.closest(".flow-card");
    const target = card?.querySelector(".flow-results-preview");
    if (!card || !target) return;

    target.hidden = false;
    target.innerHTML = '<div class="loading-block">결과를 불러오는 중…</div>';
    button.disabled = true;

    const params = new URLSearchParams({
        client_id: button.dataset.clientId || "",
        flow_id: button.dataset.flowId || "",
        artifact: button.dataset.artifact || "",
        limit: "50",
    });

    try {
        const payload = await api(
            `/api/velociraptor/flow-results?${params.toString()}`
        );
        hawkiRenderFlowRows(target, payload);
    } catch (_) {
        target.innerHTML =
            '<div class="empty-state">결과를 불러오지 못했습니다.</div>';
    } finally {
        button.disabled = false;
    }
}

function loadVelociraptorFlows(selectId, containerId) {
    const select = byId(selectId);
    const container = byId(containerId);
    if (!select || !container) return Promise.resolve();

    const clientId = select.value;
    if (!clientId) {
        container.innerHTML =
            '<div class="empty-state">클라이언트를 선택하세요.</div>';
        return Promise.resolve();
    }

    container.innerHTML =
        '<div class="loading-block">기존 수집을 불러오는 중…</div>';

    return api(
        `/api/velociraptor/flows?client_id=${encodeURIComponent(clientId)}`
    ).then((payload) => {
        const flows = Array.isArray(payload?.flows) ? payload.flows : [];
        if (!flows.length) {
            container.innerHTML =
                '<div class="empty-state">기존 수집이 없습니다.</div>';
            return;
        }

        container.innerHTML = flows.map((flow) => {
            const flowId = String(flow.flow_id || flow.session_id || flow.id || "");
            const artifacts = hawkiFlowArtifacts(flow);
            const artifact = artifacts[0] || "";
            const state = String(flow.state || flow.status || "UNKNOWN");
            const start = flow.start_time || flow.create_time || flow.started_at || "";
            const end = flow.end_time || flow.completed_at || "";

            const resultButton = flowId ? artifacts.map((source) =>
                `<button class="button secondary small flow-results-button" ` +
                `data-client-id="${escapeHtml(clientId)}" ` +
                `data-flow-id="${escapeHtml(flowId)}" ` +
                `data-artifact="${escapeHtml(source)}">` +
                `${escapeHtml(source)} · 결과 보기</button>`
            ).join(" ") : "";

            return (
                `<article class="flow-card">` +
                `<div class="flow-card-header">` +
                `<strong>${escapeHtml(flowId || "알 수 없는 수집")}</strong>` +
                `<span class="status-text">${escapeHtml(state)}</span>` +
                `</div>` +
                `<p>${escapeHtml(artifacts.join(", ") || "아티팩트 정보 없음")}</p>` +
                `<p class="muted">${escapeHtml(hawkiFlowDate(start))}` +
                `${end ? ` – ${escapeHtml(hawkiFlowDate(end))}` : ""}</p>` +
                `<div class="flow-card-actions">${resultButton}</div>` +
                `<div class="flow-results-preview" hidden></div>` +
                `</article>`
            );
        }).join("");

        container
            .querySelectorAll(".flow-results-button")
            .forEach((button) => {
                button.addEventListener(
                    "click",
                    () => hawkiLoadFlowRows(button),
                );
            });
    }).catch(() => {
        container.innerHTML =
            '<div class="empty-state">기존 수집을 불러오지 못했습니다.</div>';
    });
}
