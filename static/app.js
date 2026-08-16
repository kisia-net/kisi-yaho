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
};

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
function formatNumber(value) { return new Intl.NumberFormat("en-US").format(value ?? 0); }

const THEME_STORAGE_KEY = "hawki-theme";
const THEME_COOKIE_KEY = "hawki_theme";

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
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
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
    const label = `Switch to ${nextTheme} mode`;
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
    document.querySelectorAll(".sidebar a[href]").forEach((link) => {
        link.removeAttribute("target");
        link.removeAttribute("rel");
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
        copy.textContent = "Copy";
        copy.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(code.textContent);
                copy.textContent = "Copied";
                setTimeout(() => { copy.textContent = "Copy"; }, 1400);
            } catch {
                toast("Clipboard access failed");
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
        wrapper.setAttribute("aria-label", "Scrollable table");
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
    const message = event.reason?.message || String(event.reason ?? "Request failed");
    console.error("HAW-KI request failed:", event.reason);
    toast(`Request failed: ${message}`);
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
        throw new Error("Authentication required.");
    }
    if (!response.ok) {
        throw new Error(data.detail || data.error || `Request failed: ${response.status}`);
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
            aria-label="Account: ${escapeHtml(state.auth.username)} (${escapeHtml(state.auth.role)})"
            title="Account: ${escapeHtml(state.auth.username)} · ${escapeHtml(state.auth.role)}">
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="8" r="4"></circle>
                <path d="M4.5 21a7.5 7.5 0 0 1 15 0"></path>
            </svg>
        </a>
        ${state.auth.role === "admin" ? `
            <a class="topbar-icon-button" href="/admin/users"
                aria-label="User management" title="User management">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <circle cx="9" cy="8" r="3"></circle>
                    <path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path>
                    <path d="M17 8v6M14 11h6"></path>
                </svg>
            </a>
        ` : ""}
        <button id="logout-button" class="topbar-icon-button" type="button"
            aria-label="Sign out" title="Sign out">
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
    document.querySelectorAll(`[data-service-label="${name}"]`).forEach((label) => {
        label.textContent = !configured ? "Not configured" : online ? `Reachable · HTTP ${details.status_code}` : "Unreachable";
    });
    document.querySelectorAll(`[data-service-latency="${name}"]`).forEach((label) => {
        label.textContent = details?.latency_ms != null ? `${details.latency_ms} ms` : "—";
    });
}
async function loadServices() {
    try {
        const data = await api("/api/status");
        const services = data.services || {};
        Object.entries(services).forEach(([name, details]) => setService(name, details));
        const configured = Object.values(services).filter((x) => x.configured !== false);
        const online = configured.filter((x) => x.ok).length;
        if (byId("global-health-text")) byId("global-health-text").textContent = `${online}/${configured.length} configured services reachable`;
        if (byId("status-checked-at")) byId("status-checked-at").textContent = new Date(data.checked_at).toLocaleTimeString();
    } catch (error) {
        if (byId("global-health-text")) byId("global-health-text").textContent = "Status check failed";
    }
}
async function loadConfig() {
    try { state.config = await api("/api/config"); } catch { state.config = {}; }
}

function renderNotices(notices) {
    byId("notice-list").innerHTML = notices.map((n) => `
        <div class="notice-item"><span class="notice-bar ${escapeHtml(n.level)}"></span>
        <div><strong>${escapeHtml(n.title)}</strong><p>${escapeHtml(n.detail)}</p></div>
        <a class="button secondary small" href="${escapeHtml(n.target)}">${escapeHtml(n.action)}</a></div>`).join("");
}
async function initDashboard() {
    const data = await api("/api/dashboard");
    byId("metric-critical").textContent = data.stats.critical_alerts;
    byId("metric-incidents").textContent = data.stats.open_incidents;
    byId("metric-actions").textContent = data.stats.pending_actions;
    byId("metric-hunts").textContent = data.stats.active_hunts;
    renderNotices(data.notices);
}

const AGENT_GREETING = "Select a mode and provide the alert, evidence, indicator, or operational question. Write-capable output is staged as a proposal only.";

const modeTitles = {
    alert_summary: "Alert explanation",
    log_search: "Log search",
    file_hunt: "Suspicious file hunt",
    velociraptor_response: "Velociraptor host response",
    suricata_rule: "Suricata rule",
    incident_report: "Incident report",
};

const modePlaceholders = {
    alert_summary: "Select an alert or paste alert details. Ask for severity, evidence, attack context, or next investigation steps.",
    log_search: "Describe the event or indicator to search for. Include relevant users, hosts, IP addresses, processes, or expected behavior.",
    file_hunt: "Describe the suspicious file or indicator. Include a hash, path, filename, signer, or observed behavior.",
    velociraptor_response: "Describe the host response required, such as evidence collection, process termination, isolation, or rollback.",
    suricata_rule: "Describe the traffic or behavior to detect or block, including protocol, direction, addresses, ports, and action.",
    incident_report: "Describe the incident and required report, including audience, timeline, impact, evidence, and unresolved questions.",
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
        title: "New investigation",
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
        title: String(value.title || "Saved investigation").slice(0, 80),
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

async function persistAgentSession(session) {
    if (!session) return;
    try {
        const data = await api("/api/chat-sessions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(session),
        });
        if (data.updatedAt) session.updatedAt = data.updatedAt;
    } catch (error) {
        toast(`Chat history save failed: ${error.message}`);
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
        container.hidden = state.agentMode === "suricata_rule";
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
            '<option value="">All hosts</option>',
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
        '<option value="">Select an alert</option>',
        ...filtered.map((alert) => {
            const label = `${alert.id} · ${String(alert.severity || "").toUpperCase()} · ${alert.title}`;
            return `<option value="${escapeHtml(alert.id)}">${escapeHtml(label)}</option>`;
        }),
    ].join("");

    if (filtered.some((alert) => String(alert.id) === String(current))) {
        select.value = String(current);
    }
}

async function loadAgentAlertContext() {
    try {
        const data = await api("/api/alerts?q=&severity=&status=");
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
    if (!clean) return "New investigation";
    return clean.length > 48 ? `${clean.slice(0, 47)}…` : clean;
}

function formatAgentHistoryTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function renderAgentHistory() {
    const container = byId("agent-history-list");
    if (!container) return;
    if (!state.agentSessions.length) {
        container.innerHTML = `<div class="empty-state">No chat sessions yet.</div>`;
        return;
    }
    container.innerHTML = state.agentSessions.map((session) => `
        <div class="agent-history-entry ${session.id === state.currentAgentSessionId ? "active" : ""}">
            <button class="agent-history-select" type="button" data-session-id="${escapeHtml(session.id)}">
                <span class="agent-history-mode">${escapeHtml(modeTitles[session.mode] || session.mode)}</span>
                <strong>${escapeHtml(session.title)}</strong>
                <small>${escapeHtml(formatAgentHistoryTime(session.updatedAt))}</small>
            </button>
            <button class="agent-history-delete" type="button" data-delete-session="${escapeHtml(session.id)}" aria-label="Delete ${escapeHtml(session.title)}" title="Delete chat">×</button>
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
    const input = byId("agent-input");
    if (input) {
        input.placeholder = modePlaceholders[mode] || "Enter a request…";
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
                <span>${role === "assistant" ? "HAW-KI" : "Me"}${meta ? ` · ${escapeHtml(meta)}` : ""}</span>
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
                <span>HAW-KI · analyzing</span>
            </strong>
            <span class="typing"><i></i><i></i><i></i></span>
        </div>`;
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
        warnings.push("The returned rule is commented out and disabled.");
    }
    if (
        requestedAction === "blocking" &&
        !["drop", "reject"].includes(generatedAction)
    ) {
        warnings.push(
            `The analyst requested blocking, but the generated rule action is ${generatedAction}.`,
        );
    }
    if (requestedAction === "alerting" && generatedAction !== "alert") {
        warnings.push(
            `The analyst requested alerting, but the generated rule action is ${generatedAction}.`,
        );
    }

    return {
        generatedAction,
        requestedAction,
        warnings,
    };
}

function getSuricataAction(result, analystRequest = "") {
    // A rule may be placed in a plaintext fence and may be commented out as a
    // draft. Both are eligible for transfer to Structured Results for review.
    // The original generated text is preserved; this function never silently
    // activates or rewrites the rule.
    const draft = extractSuricataDraft(result?.answer);
    const inspection = inspectSuricataDraft(draft, analystRequest);
    if (!inspection) return null;

    const warnings = inspection.warnings;
    const summary = warnings.length
        ? `Generated Suricata draft requires review: ${warnings.join(" ")}`
        : "Review this generated rule in Structured Results before staging it for approval.";

    const actions = Array.isArray(result?.actions) ? result.actions : [];
    const existing = actions.find((action) =>
        action?.type === "suricata_rule" &&
        typeof action?.payload?.rule === "string" &&
        action.payload.rule.trim() === draft.rawRule
    );
    if (existing) {
        return {
            ...existing,
            summary,
            payload: {
                ...existing.payload,
                rule: draft.rawRule,
                review_warnings: warnings,
            },
        };
    }

    return {
        type: "suricata_rule",
        title: warnings.length
            ? "Review generated Suricata draft"
            : "Generated Suricata rule",
        summary,
        risk: warnings.length ? "review" : "high",
        requires_approval: true,
        payload: {
            rule: draft.rawRule,
            deployment: "staging",
            review_warnings: warnings,
            validation: ["suricata -T", "pcap replay", "false-positive review"],
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
    button.title = "Added to Structured Results";
    button.setAttribute("aria-label", "Added to Structured Results");
    toast("Suricata rule added to Structured Results");
}

function attachSuricataTransferControl(messageElement, action, staged, messageId) {
    const shell = messageElement.querySelector(".message-shell");
    if (!shell || !actionRuleKey(action)) return;

    const transfer = document.createElement("div");
    transfer.className = "chat-rule-transfer";
    transfer.innerHTML = `
        <div>
            <strong>Suricata rule detected</strong>
            <span>${staged ? "Added to Structured Results" : "Move this rule to Structured Results for review."}</span>
        </div>
        <button class="chat-rule-transfer-button ${staged ? "staged" : ""}" type="button"
            title="${staged ? "Added to Structured Results" : "Add to Structured Results"}"
            aria-label="${staged ? "Added to Structured Results" : "Add Suricata rule to Structured Results"}"
            ${staged ? "disabled" : ""}>${staged ? "✓" : "→"}</button>
    `;
    const button = transfer.querySelector(".chat-rule-transfer-button");
    if (!staged) {
        button.addEventListener("click", () => {
            stageRuleInStructuredResults(action, messageId, button);
            const description = transfer.querySelector("span");
            if (description) description.textContent = "Added to Structured Results";
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
                    title="Created by ${escapeHtml(modeLabel)}"
                    aria-label="Created by ${escapeHtml(modeLabel)}"></span>
                <strong>${escapeHtml(action.title || action.type)}</strong>
            </div>
            <p>${escapeHtml(action.summary || "")}</p>
            ${renderActionRule(action)}
            <div class="action-meta">
                <span class="tag">${escapeHtml(action.type)}</span>
                <span class="tag">risk: ${escapeHtml(action.risk || "unknown")}</span>
            </div>
            <button class="button warning small queue-agent-action" data-index="${index}" type="button">Stage for approval</button>
        </div>
    `;
}

function renderStructured(result) {
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
        .join("") || `<div class="empty-state">No separate evidence objects.</div>`;

    const queries = queryItems
        .map((query) => {
            const language = String(query.language || "plaintext").toLowerCase();
            return `<div class="output-item"><strong>${escapeHtml(query.title || "Query")}</strong><span class="tag">${escapeHtml(language)}</span><pre class="query-code"><code class="language-${escapeHtml(language)}">${escapeHtml(query.value || "")}</code></pre></div>`;
        })
        .join("") || `<div class="empty-state">No generated queries.</div>`;

    const actions = actionItems
        .map((action, index) => renderActionCard(action, index, originMode))
        .join("") || `<div class="empty-state">No write-capable action proposed.</div>`;

    const container = byId("agent-structured-output");
    container.className = "structured-output";
    container.innerHTML = `
        <section class="output-section"><h3>Evidence</h3>${evidence}</section>
        <section class="output-section"><h3>Queries</h3>${queries}</section>
        <section class="output-section"><h3>Actions</h3>${actions}</section>
    `;

    enhanceRenderedContent(container);

    container.querySelectorAll(".queue-agent-action").forEach((button) => {
        button.addEventListener("click", async () => {
            const action = actionItems[Number(button.dataset.index)];
            try {
                const source = `agent:${action.origin_mode || originMode}`;
                await queueAction(action, source);
                button.disabled = true;
                button.textContent = "Queued";
                button.title = "Staged for approval";
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
            <h3>Evidence</h3>
            <div class="empty-state">No separate evidence objects.</div>
        </section>
        <section class="output-section">
            <h3>Queries</h3>
            <div class="empty-state">No generated queries.</div>
        </section>
        <section class="output-section">
            <h3>Actions</h3>
            <div class="empty-state">No write-capable action proposed.</div>
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
    const data = await api("/api/actions/queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, source }),
    });
    toast(`${data.action.id} staged for approval`);
    return data.action;
}

async function sendAgent(message) {
    let session = currentAgentSession();
    if (!session) {
        session = createAgentSession(state.agentMode, readAgentContext(), false);
        state.currentAgentSessionId = session.id;
    }

    addMessage("user", message, "", true, { mode: state.agentMode });
    state.history.push({ role: "user", content: message });
    session.history = state.history.slice(-16);
    session.context = readAgentWorkspaceContext();
    if (session.title === "New investigation") session.title = deriveAgentSessionTitle(message);
    session.updatedAt = new Date().toISOString();
    saveAgentSessions();
    renderAgentHistory();

    addTyping();
    const context = readAgentContext();
    try {
        const result = await api("/api/agent/chat", {
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
        const suricataAction = getSuricataAction(result, message);
        const structuredResult = suricataAction ? withoutSuricataActions(result) : result;
        addMessage(
            "assistant",
            result.answer || "No answer returned.",
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
        addMessage("assistant", error.message, "error", true, { mode: state.agentMode });
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
    try {
        await loadAlertsInner();
    } catch (error) {
        // Without this the table kept its "Loading alerts" placeholder, which
        // reads as a page that never finished rather than a failed request.
        byId("alert-count").textContent = "Could not load alerts";
        byId("alerts-table").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}<br><br>Check the server logs: <code>docker compose logs hawki-web</code></div>`;
    }
}
async function loadAlertsInner() {
    const q = encodeURIComponent(byId("alert-query").value.trim());
    const sev = encodeURIComponent(byId("alert-severity").value); const status = encodeURIComponent(byId("alert-status").value);
    const data = await api(`/api/alerts?q=${q}&severity=${sev}&status=${status}`);
    byId("alert-count").textContent = `${data.total} alerts`;
    byId("alerts-table").innerHTML = data.alerts.map((a) => {
        // Enrichment previews: inventory criticality and intelligence verdict
        // for the alert host, so triage order reflects more than severity.
        const enrichment = [
            a.asset_criticality ? `<span class="tag">asset: ${escapeHtml(a.asset_criticality)}</span>` : "",
            a.threat_verdict ? `<span class="tag">intel: ${escapeHtml(a.threat_verdict)}</span>` : "",
        ].join("");
        return `<div class="alert-row"><strong>${escapeHtml(a.id)}</strong><span class="severity ${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span><div><strong>${escapeHtml(a.title)}</strong><p class="muted">${escapeHtml(a.summary)}</p>${enrichment ? `<div class="action-meta">${enrichment}</div>` : ""}</div><span>${escapeHtml(a.host)}</span><span>${escapeHtml(a.mitre)}</span><span>${escapeHtml(a.status)}</span><a class="button secondary small" href="/agent?mode=alert_summary&host=${encodeURIComponent(a.host)}&incident=${encodeURIComponent(a.id)}">Explain</a></div>`;
    }).join("") || `<div class="empty-state">No alerts match the filters.</div>`;
}
function initAlerts() { byId("alert-filter-form").addEventListener("submit", (e) => {e.preventDefault(); loadAlerts();}); loadAlerts(); }

function normalizeLog(source = {}) { return { time: source["@timestamp"] || "—", host: source.host?.name || source["host.name"] || source.source?.ip || source["source.ip"] || "—", category: source.event?.category || source["event.category"] || source.rule?.name || source["rule.name"] || "event", message: source.message || source.file?.path || JSON.stringify(source) }; }
async function runLogSearch() {
    const payload = { index: byId("log-index").value, language: byId("log-language").value, query: byId("log-query").value, start_time: byId("log-start").value, end_time: byId("log-end").value, size: Number(byId("log-size").value) };
    byId("log-count").textContent = "Searching…";
    try {
        const data = await api("/api/log-search", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
        if (data.kibana_url) byId("open-kibana-link").href = data.kibana_url;
        if (data.mode === "link-only") { byId("log-count").textContent = "Kibana query prepared"; byId("log-results").innerHTML = `<div class="empty-state">${escapeHtml(data.message)}<br><br><a class="button secondary" href="${escapeHtml(data.kibana_url)}" target="_blank" rel="noopener noreferrer">Open in Kibana</a></div>`; return; }
        byId("log-count").textContent = `${formatNumber(data.total)} matching events`;
        byId("log-results").innerHTML = (data.results || []).map((r) => { const x = normalizeLog(r.source); return `<div class="log-row"><span>${escapeHtml(x.time)}</span><strong>${escapeHtml(x.host)}</strong><span>${escapeHtml(x.category)}</span><span>${escapeHtml(x.message)}</span></div>`; }).join("") || `<div class="empty-state">No matching events.</div>`;
    } catch (e) { byId("log-count").textContent = "Search failed"; byId("log-results").innerHTML = `<div class="empty-state">${escapeHtml(e.message)}</div>`; }
}
function initLogs() {
    byId("log-policy-note").textContent = state.config.elasticsearch_search_enabled ? "Direct read-only Elasticsearch query-string search is enabled. KQL still opens in Kibana." : "Direct Elasticsearch search is disabled. Queries are prepared for Kibana unless the server policy is enabled.";
    byId("log-search-form").addEventListener("submit", (e) => {e.preventDefault(); runLogSearch();});
    byId("copy-log-query").addEventListener("click", async () => { await navigator.clipboard.writeText(byId("log-query").value); toast("Query copied"); });
}

async function initHunts() {
    const data = await api("/api/hunts");
    byId("hunt-list").innerHTML = data.hunts.map((h) => `<div class="hunt-card"><div class="hunt-top"><strong>${escapeHtml(h.id)} · ${escapeHtml(h.name)}</strong><span class="status-text">${escapeHtml(h.state)}</span></div><p>${escapeHtml(h.target)} · ${escapeHtml(h.artifact)}</p><div class="progress"><span style="width:${Number(h.progress)}%"></span></div><div class="hunt-bottom"><span class="muted">${h.progress}% complete</span><span class="tag">${h.hits} hits</span></div></div>`).join("");
    byId("hunt-agent-form").addEventListener("submit", (e) => { e.preventDefault(); const query = new URLSearchParams({mode:"file_hunt", host:byId("hunt-target").value, incident:byId("hunt-incident").value, prompt:byId("hunt-indicator").value}); location.href = `/agent?${query}`; });
}

function actionCard(a, decisionButtons = false) {
    const buttons = decisionButtons && a.status === "pending_approval" ? `<div class="approval-actions"><button class="button danger small action-decision" data-id="${escapeHtml(a.id)}" data-decision="reject">Reject</button><button class="button primary small action-decision" data-id="${escapeHtml(a.id)}" data-decision="approve">Approve</button></div>` : "";
    return `<div class="approval-card"><div class="approval-top"><strong>${escapeHtml(a.id)} · ${escapeHtml(a.title)}</strong><span class="status-text ${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></div><p>${escapeHtml(a.summary)}</p><div class="approval-meta"><span class="tag">${escapeHtml(a.type)}</span><span class="tag">risk: ${escapeHtml(a.risk)}</span><span class="tag">${escapeHtml(a.created_at)}</span></div>${buttons}</div>`;
}

async function loadActionList(containerId, prefix = "") {
    const data = await api(`/api/actions${prefix ? `?type=${encodeURIComponent(prefix)}` : ""}`);
    const container = byId(containerId);
    container.innerHTML = data.actions.map((a) => actionCard(a, false)).join("") || `<div class="empty-state">No actions in this queue.</div>`;
    return data;
}

function normalizeApprovalValue(value) {
    return String(value ?? "").trim();
}

function approvalLabel(value) {
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
        alert_summary: "Alert explanation",
        log_search: "Log search",
        file_hunt: "Suspicious file hunt",
        velociraptor_response: "Host response",
        suricata_rule: "Suricata rule",
        incident_report: "Incident report",
    };
    return labels[mode] || approvalLabel(mode);
}

function approvalStatusLabel(status) {
    const labels = {
        pending_approval: "Pending approval",
        approved_staged: "Approved · staged",
        submitted: "Submitted",
        rejected: "Rejected",
        dispatch_failed: "Dispatch failed",
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
    if (!timestamp) return "Unknown time";
    return new Date(timestamp).toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function approvalTags(action) {
    const payload = action?.payload && typeof action.payload === "object" ? action.payload : {};
    const mode = approvalMode(action);
    const rawTags = Array.isArray(action?.tags) ? action.tags : [];
    const candidates = [
        approvalLabel(action.type),
        approvalModeLabel(mode),
        normalizeApprovalValue(payload.deployment) ? approvalLabel(payload.deployment) : "",
        normalizeApprovalValue(payload.requested_action) ? approvalLabel(payload.requested_action) : "",
        normalizeApprovalValue(payload.artifact) ? approvalLabel(payload.artifact) : "",
        normalizeApprovalValue(action.resubmitted_from) ? "Resubmitted" : "",
        ...rawTags.map(approvalLabel),
    ];
    return [...new Set(candidates.filter(Boolean))];
}

function approvalSearchText(action) {
    return [
        action.id,
        action.title,
        action.summary,
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

function renderApprovalValue(value) {
    if (Array.isArray(value)) {
        return value.length
            ? `<ul>${value.map((item) => `<li>${escapeHtml(typeof item === "object" ? JSON.stringify(item) : item)}</li>`).join("")}</ul>`
            : `<span class="approval-empty-value">None</span>`;
    }
    if (value && typeof value === "object") {
        return `<pre class="approval-json"><code>${escapeHtml(JSON.stringify(value, null, 2))}</code></pre>`;
    }
    return `<span>${escapeHtml(value ?? "")}</span>`;
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

function renderApprovalPayload(action) {
    const payload = action?.payload && typeof action.payload === "object" ? action.payload : {};
    const rule = normalizeApprovalValue(payload.rule);
    const suricata = normalizeApprovalValue(action.type) === "suricata_rule" && Boolean(rule);
    const identifiers = suricata ? suricataRuleIdentifiers(action) : null;
    const entries = Object.entries(payload).filter(([key]) => !["rule", "sid", "revision"].includes(key));
    const sections = [];

    if (rule) {
        sections.push(`
            <section class="approval-action-display approval-rule-display">
                <div class="approval-display-title">
                    <span class="approval-display-dot"></span>
                    <strong>Suricata rule</strong>
                </div>
                <pre><code>${escapeHtml(rule)}</code></pre>
                ${suricata ? `
                    <div class="approval-rule-editor">
                        <label>
                            <span>SID</span>
                            <input class="approval-rule-sid" data-id="${escapeHtml(action.id)}"
                                type="number" min="1000000" max="4294967295"
                                value="${escapeHtml(identifiers.sid)}">
                        </label>
                        <label>
                            <span>Revision</span>
                            <input class="approval-rule-revision" data-id="${escapeHtml(action.id)}"
                                type="number" min="1" max="65535"
                                value="${escapeHtml(identifiers.revision)}">
                        </label>
                        ${normalizeApprovalValue(action.status) === "pending_approval" ? `
                            <button class="button secondary small save-rule-identifiers"
                                data-id="${escapeHtml(action.id)}" type="button">
                                Save SID / rev
                            </button>
                        ` : ""}
                    </div>
                ` : ""}
            </section>
        `);
    }

    if (entries.length) {
        sections.push(`
            <section class="approval-action-display">
                <div class="approval-display-title">
                    <span class="approval-display-dot"></span>
                    <strong>${suricata ? "Rule metadata" : "Action details"}</strong>
                </div>
                <dl class="approval-payload-grid">
                    ${entries.map(([key, value]) => `
                        <div>
                            <dt>${escapeHtml(approvalLabel(key))}</dt>
                            <dd>${renderApprovalValue(value)}</dd>
                        </div>
                    `).join("")}
                </dl>
            </section>
        `);
    }

    if (!sections.length) {
        sections.push(`
            <section class="approval-action-display">
                <div class="approval-display-title">
                    <span class="approval-display-dot"></span>
                    <strong>Action</strong>
                </div>
                <p class="approval-empty-value">No additional action parameters.</p>
            </section>
        `);
    }

    return sections.join("");
}

function renderApprovalOutcome(action) {
    const parts = [];
    if (normalizeApprovalValue(action.decision_note)) {
        parts.push(`
            <div class="approval-outcome-row">
                <strong>Decision note</strong>
                <span>${escapeHtml(action.decision_note)}</span>
            </div>
        `);
    }
    if (action.dispatch_result && typeof action.dispatch_result === "object") {
        const routineMessage = normalizeApprovalValue(action.dispatch_result.message);
        const hiddenRoutineMessages = new Set([
            "Execution is disabled by server policy.",
            "No trusted action gateway is configured.",
            "Action rejected and not dispatched.",
        ]);
        if (!hiddenRoutineMessages.has(routineMessage)) {
            parts.push(`
                <div class="approval-outcome-row">
                    <strong>Dispatch result</strong>
                    <pre class="approval-json"><code>${escapeHtml(JSON.stringify(action.dispatch_result, null, 2))}</code></pre>
                </div>
            `);
        }
    }
    return parts.length ? `<section class="approval-outcome">${parts.join("")}</section>` : "";
}

function detailedApprovalCard(action) {
    const mode = approvalMode(action);
    const risk = normalizeApprovalValue(action.risk || "unknown").toLowerCase();
    const status = normalizeApprovalValue(action.status || "unknown").toLowerCase();
    const tags = approvalTags(action);
    const createdAt = approvalDateLabel(action.created_at);
    const decidedAt = normalizeApprovalValue(action.decided_at)
        ? approvalDateLabel(action.decided_at)
        : "";
    const pending = status === "pending_approval";

    return `
        <article class="approval-card approval-card-detailed" data-action-id="${escapeHtml(action.id)}">
            <header class="approval-card-header">
                <div class="approval-card-heading">
                    <span class="approval-mode-dot mode-${escapeHtml(mode)}"
                        title="${escapeHtml(approvalModeLabel(mode))}"
                        aria-label="${escapeHtml(approvalModeLabel(mode))}"></span>
                    <div>
                        <span class="approval-action-id">${escapeHtml(action.id)}</span>
                        <h3>${escapeHtml(action.title || approvalLabel(action.type))}</h3>
                    </div>
                </div>
                <span class="approval-status-chip status-${escapeHtml(status)}">
                    <span></span>${escapeHtml(approvalStatusLabel(status))}
                </span>
            </header>

            ${normalizeApprovalValue(action.summary) ? `<p class="approval-summary-text">${escapeHtml(action.summary)}</p>` : ""}

            <div class="approval-card-meta">
                <div class="approval-tag-list">
                    ${tags.map((tag) => `<span class="approval-tag"><span></span>${escapeHtml(tag)}</span>`).join("")}
                    <span class="approval-risk-chip risk-${escapeHtml(risk)}">
                        <span></span>Risk: ${escapeHtml(approvalLabel(risk))}
                    </span>
                </div>
                <div class="approval-time-list">
                    <span>Created ${escapeHtml(createdAt)}</span>
                    ${decidedAt ? `<span>Decided ${escapeHtml(decidedAt)}</span>` : ""}
                    ${normalizeApprovalValue(action.resubmitted_from)
                        ? `<span>From ${escapeHtml(action.resubmitted_from)}</span>`
                        : ""}
                </div>
            </div>

            ${renderApprovalPayload(action)}
            ${renderApprovalOutcome(action)}

            ${pending ? `
                <div class="approval-decision-panel">
                    <label>
                        <span>Decision note</span>
                        <input class="approval-decision-note" data-id="${escapeHtml(action.id)}"
                            placeholder="Optional reason or review note">
                    </label>
                    <div class="approval-actions">
                        <button class="button danger small action-decision"
                            data-id="${escapeHtml(action.id)}" data-decision="reject" type="button">Reject</button>
                        <button class="button primary small action-decision"
                            data-id="${escapeHtml(action.id)}" data-decision="approve" type="button">Approve</button>
                    </div>
                </div>
            ` : `
                <div class="approval-resend-panel">
                    <label>
                        <span>Resubmission note</span>
                        <input class="approval-resend-note" data-id="${escapeHtml(action.id)}"
                            placeholder="Optional note for the new approval">
                    </label>
                    <button class="button secondary small action-resend"
                        data-id="${escapeHtml(action.id)}" type="button">
                        Resend for approval
                    </button>
                </div>
            `}
        </article>
    `;
}

const approvalWorkspaceState = {
    actions: [],
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

function populateApprovalFilter(selectId, values, allLabel) {
    const select = byId(selectId);
    if (!select) return;
    const current = select.value;
    select.innerHTML = `<option value="">${escapeHtml(allLabel)}</option>${values
        .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(approvalLabel(value))}</option>`)
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

    populateApprovalFilter("approval-tag-filter", tags, "All tags");
    populateApprovalFilter("approval-risk-filter", risks, "All risks");
    populateApprovalFilter("approval-status-filter", statuses, "All statuses");
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
    const pending = actions.filter((action) => action.status === "pending_approval").length;
    const approved = actions.filter((action) => ["approved_staged", "submitted"].includes(action.status)).length;
    const rejected = actions.filter((action) => ["rejected", "dispatch_failed"].includes(action.status)).length;
    byId("approval-count-pending").textContent = String(pending);
    byId("approval-count-approved").textContent = String(approved);
    byId("approval-count-rejected").textContent = String(rejected);
    byId("approval-total-label").textContent = `${actions.length} action${actions.length === 1 ? "" : "s"}`;
}

function renderApprovalWorkspace() {
    const actions = filteredApprovalActions();
    const container = byId("approval-list");
    container.classList.remove("loading-block");
    container.innerHTML = actions.map(detailedApprovalCard).join("")
        || `<div class="empty-state">No actions match the selected filters.</div>`;

    const total = approvalWorkspaceState.actions.length;
    byId("approval-results-label").textContent = `Showing ${actions.length} of ${total} actions`;
    wireApprovalDecisionButtons();
}

async function loadApprovalWorkspace() {
    const container = byId("approval-list");
    container.classList.add("loading-block");
    container.textContent = "Loading approval queue…";
    const data = await api("/api/actions");
    approvalWorkspaceState.actions = Array.isArray(data.actions) ? data.actions : [];
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
    toast(`${id} ${decision === "approve" ? "approved" : "rejected"}`);
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
    toast(`${id} rule identifiers updated`);
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
    toast(`${result.action.id} sent for approval`);
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
    loadActionList("response-action-list", "velociraptor_");
    byId("response-agent-form").addEventListener("submit", (e) => { e.preventDefault(); const params = new URLSearchParams({mode:"velociraptor_response", host:byId("response-host").value, incident:byId("response-incident").value, prompt:`Requested outcome: ${byId("response-outcome").value}\nEvidence: ${byId("response-evidence").value}`}); location.href = `/agent?${params}`; });
}

async function validateRule() {
    const data = await api("/api/rules/validate", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({rule:byId("rule-text").value})});
    const errors = data.errors.map((x) => `<li>${escapeHtml(x)}</li>`).join(""); const warnings = data.warnings.map((x) => `<li>${escapeHtml(x)}</li>`).join("");
    byId("rule-validation").classList.remove("empty-state"); byId("rule-validation").innerHTML = `<div class="validation-block"><strong>${data.valid ? "Basic structural validation passed" : "Validation failed"}</strong>${errors ? `<ul>${errors}</ul>` : ""}${warnings ? `<ul>${warnings}</ul>` : ""}<p class="muted">${escapeHtml(data.note)}</p></div>`;
    return data;
}

function ruleInventoryLabel(value) {
    return approvalLabel(normalizeApprovalValue(value));
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
        ["rule-db-host", facets.hosts || [], "All hosts"],
        ["rule-db-interface", facets.interfaces || [], "All interfaces"],
        ["rule-db-state", facets.states || [], "All states"],
        ["rule-db-tag", facets.tags || [], "All tags"],
    ];
    options.forEach(([id, values, defaultLabel]) => {
        const select = byId(id);
        if (!select) return;
        const selected = select.value;
        select.innerHTML = `<option value="">${escapeHtml(defaultLabel)}</option>`
            + values.map((value) => (
                `<option value="${escapeHtml(value)}">${escapeHtml(ruleInventoryLabel(value))}</option>`
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
        ["Enabled", counts.enabled || 0, "state-active"],
        ["Disabled", counts.disabled || 0, "state-disabled"],
        ["Active", counts.active || 0, "state-active"],
        ["Staged", counts.staged || 0, "state-staged"],
    ].map(([label, value, className]) => `
        <div class="approval-summary-item">
            <span class="approval-summary-dot ${className}"></span>
            <strong>${escapeHtml(value)}</strong>
            <span>${escapeHtml(label)}</span>
        </div>
    `).join("");
}

function ruleDatabaseCard(rule) {
    const tags = (Array.isArray(rule.tags) ? rule.tags : [])
        .map((tag) => `<span class="approval-tag">${escapeHtml(tag)}</span>`)
        .join("");
    const updated = rule.updated_at
        ? new Date(rule.updated_at).toLocaleString()
        : "Unknown";
    const stateClass = ruleInventoryStateClass(rule.state);
    const stageLabel = rule.enabled
        ? "Stage deployment"
        : "Stage disable";

    return `
        <article class="rule-database-card" data-rule-id="${escapeHtml(rule.id)}">
            <header class="rule-database-card-header">
                <div class="rule-database-title">
                    <span class="rule-db-dot ${stateClass}"></span>
                    <div>
                        <span class="approval-card-id">${escapeHtml(rule.id)}</span>
                        <h3>${escapeHtml(rule.name)}</h3>
                    </div>
                </div>
                <span class="approval-status-chip ${stateClass}">
                    <span></span>${escapeHtml(ruleInventoryLabel(rule.state))}
                </span>
            </header>

            <p class="rule-database-description">${escapeHtml(rule.description || "No description.")}</p>

            <div class="approval-tag-row">
                <span class="approval-tag">${escapeHtml(rule.host)}</span>
                <span class="approval-tag">${escapeHtml(rule.interface)}</span>
                <span class="approval-tag">${escapeHtml(rule.action)}</span>
                <span class="approval-tag">${escapeHtml(rule.protocol)}</span>
                <span class="approval-tag">${rule.enabled ? "Enabled" : "Disabled"}</span>
                ${tags}
            </div>

            <pre class="rule-database-code"><code>${escapeHtml(rule.rule)}</code></pre>

            <dl class="rule-database-meta">
                <div><dt>SID</dt><dd>${escapeHtml(rule.sid)}</dd></div>
                <div><dt>Revision</dt><dd>${escapeHtml(rule.revision)}</dd></div>
                <div><dt>Source</dt><dd>${escapeHtml(ruleInventoryLabel(rule.source))}</dd></div>
                <div><dt>Updated</dt><dd>${escapeHtml(updated)}</dd></div>
                ${rule.last_action_id
                    ? `<div><dt>Last action</dt><dd>${escapeHtml(rule.last_action_id)}</dd></div>`
                    : ""}
            </dl>

            <footer class="rule-database-actions">
                <button class="button secondary small edit-rule-record"
                    data-id="${escapeHtml(rule.id)}" type="button">Edit</button>
                <button class="button secondary small toggle-rule-record"
                    data-id="${escapeHtml(rule.id)}" type="button">
                    ${rule.enabled ? "Set disabled" : "Set enabled"}
                </button>
                <button class="button warning small stage-rule-record-card"
                    data-id="${escapeHtml(rule.id)}" type="button">${escapeHtml(stageLabel)}</button>
                ${rule.state !== "active" ? `
                    <button class="button danger small delete-rule-record"
                        data-id="${escapeHtml(rule.id)}" type="button">Delete</button>
                ` : ""}
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
        || `<div class="empty-state">No rules match the selected filters.</div>`;

    byId("rule-db-results").textContent =
        `Showing ${rules.length} of ${suricataRuleInventoryState.rules.length} rules`;
    byId("rule-inventory-total").textContent =
        `${suricataRuleInventoryState.rules.length} rule${suricataRuleInventoryState.rules.length === 1 ? "" : "s"}`;
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
    container.textContent = "Loading rules…";
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
    byId("rule-validation").textContent = "Validation output will appear here.";
    byId("save-rule-record").textContent = "Save rule";
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
    byId("save-rule-record").textContent = "Update rule";
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
        toast("Fix validation errors before saving");
        return null;
    }

    const id = byId("rule-record-id").value;
    const result = await api(id ? `/api/rules/${encodeURIComponent(id)}` : "/api/rules", {
        method: id ? "PATCH" : "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(ruleEditorPayload()),
    });
    toast(`${result.rule.id} ${id ? "updated" : "saved"}`);
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
    toast(`${result.action.id} staged for approval`);
    await loadRuleInventory();
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
    toast(`${id} target state changed`);
    await loadRuleInventory();
}

async function deleteRuleRecord(id) {
    const rule = suricataRuleInventoryState.rules.find((item) => item.id === id);
    if (!rule) return;
    if (!window.confirm(`Delete ${rule.name}?`)) return;
    await api(`/api/rules/${encodeURIComponent(id)}`, {method: "DELETE"});
    toast(`${id} deleted`);
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
    byId("validate-rule").addEventListener("click", validateRule);
    byId("ask-rule-agent").addEventListener("click", () => {
        const params = new URLSearchParams({
            mode: "suricata_rule",
            prompt: `Detection intent: ${byId("rule-intent").value}\nRule draft: ${byId("rule-text").value}`,
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
        "approval-status-filter",
        "approval-time-filter",
        "approval-sort",
    ];
    filterIds.forEach((id) => {
        byId(id)?.addEventListener(id === "approval-search" ? "input" : "change", renderApprovalWorkspace);
    });
    byId("clear-approval-filters")?.addEventListener("click", () => {
        byId("approval-filters")?.reset();
        renderApprovalWorkspace();
    });
    byId("refresh-approvals")?.addEventListener("click", loadApprovalWorkspace);
    await loadApprovalWorkspace();
}

async function initAudit() { const data = await api("/api/audit"); byId("audit-list").innerHTML = data.events.map((e) => `<div class="audit-row"><span>${escapeHtml(new Date(e.timestamp).toLocaleString())}</span><strong>${escapeHtml(e.event_type)}</strong><code>${escapeHtml(JSON.stringify(e.detail))}</code></div>`).join("") || `<div class="empty-state">No audit events recorded yet.</div>`; }

async function init() {
    initSidebarNavigation();
    initTheme();
    await loadAuth();
    byId("refresh-services")?.addEventListener("click", loadServices);
    // Pages need the config. They do not need to know whether Kibana is up, so
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
    if (page === "audit") { await initAudit(); byId("refresh-audit").addEventListener("click", initAudit); }
}
init();
