(() => {
    "use strict";
    const root = document.getElementById("agent-workspace");
    if (!root) return;
    const $ = id => document.getElementById(id);
    const ui = { sessions: [], current: null, csrf: "", models: [], pending: new Map(), selection: 0, poll: null };
    const uid = () => crypto.randomUUID ? crypto.randomUUID() : `chat-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const make = (tag, text, className) => {
        const el = document.createElement(tag);
        if (text !== undefined) el.textContent = text;
        if (className) el.className = className;
        return el;
    };
    const fresh = () => ({id: uid(), title: "새 대화", mode: "conversation", transcript: [], history: [], evidence: [], saved: false, draft: "", scope: {}});
    const busy = s => !!s && (ui.pending.has(s.id) || Boolean(s.investigation?.running));
    function notice(text, retry) {
        const box = $("aw-notice");
        box.replaceChildren(); box.hidden = !text;
        if (!text) return;
        box.append(make("span", text));
        if (retry) {
            const button = make("button", "다시 시도"); button.type = "button";
            button.addEventListener("click", retry); box.append(button);
        }
    }
    async function api(url, options = {}) {
        const headers = new Headers(options.headers || {});
        const method = options.method || "GET";
        if (!["GET", "HEAD"].includes(method)) headers.set("X-CSRF-Token", ui.csrf);
        if (options.body) headers.set("Content-Type", "application/json");
        const response = await fetch(url, {...options, headers, credentials: "same-origin"}).catch(() => { throw new Error("연결을 확인한 뒤 다시 시도해 주세요."); });
        let data = {}; try { data = await response.json(); } catch (_) {}
        if (response.status === 401) {
            location.assign(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
            throw new Error("로그인이 필요합니다.");
        }
        if (!response.ok) {
            const messages={400:"입력값을 확인해 주세요.",403:"이 작업을 수행할 권한이 없습니다.",404:"해당 항목을 찾을 수 없습니다.",409:"현재 상태에서 처리할 수 없습니다. 새로고침해 주세요.",429:"잠시 후 다시 시도해 주세요."};
            const error = new Error(messages[response.status] || "요청을 처리하지 못했습니다. 다시 시도해 주세요.");
            error.status = response.status; throw error;
        }
        return data;
    }
    const post = (url, body = {}) => api(url, {method: "POST", body: JSON.stringify(body)});
    const collectionPanel = window.HawkiCollectionPanel({root, api, post,
        currentSession: () => ui.current?.id, changed: refreshInvestigation,
        ask: text => {
            if ($("aw-input").value.trim()) { notice("작성 중인 메시지를 먼저 보내주세요."); return false; }
            $("aw-input").value = text; rememberDraft(); $("aw-input").focus(); return true;
        }});
    function evidenceMap() {
        const s = ui.current;
        return new Map([...(s?.evidence || []), ...(s?.lastResult?.tool_trace || [])]
            .filter(record => /^E-[a-f0-9]{32}$/.test(record?.ref || ""))
            .map(record => [record.ref, record]));
    }
    const evidencePanel = window.HawkiEvidencePanel({root, api, currentSession: () => ui.current, notice});
    function showEvidence(ref) { evidencePanel.open(ref); }
    function evidenceButton(ref) {
        const button = make("button", ref, "aw-citation");
        button.type = "button"; button.title = `근거 보기: ${ref}`;
        button.addEventListener("click", () => showEvidence(ref));
        return button;
    }
    function linkEvidence(body) {
        const known = evidenceMap(), walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
        const nodes = [];
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (!node.parentElement.closest("a, pre, button, summary") && /E-[a-f0-9]{32}/.test(node.textContent)) nodes.push(node);
        }
        for (const node of nodes) {
            const text = node.textContent, fragment = document.createDocumentFragment();
            let last = 0;
            for (const match of text.matchAll(/E-[a-f0-9]{32}(?![a-f0-9])/g)) {
                // Resolve older citations through the owned evidence archive on demand.
                fragment.append(document.createTextNode(text.slice(last, match.index)), evidenceButton(match[0]));
                last = match.index + match[0].length;
            }
            if (last) { fragment.append(document.createTextNode(text.slice(last))); node.replaceWith(fragment); }
        }
    }
    async function refreshInvestigation() {
        evidencePanel.invalidate();
        const s = ui.current;
        if (!s?.saved) return;
        try {
            const data = await api(`/api/agent/workspace/sessions/${encodeURIComponent(s.id)}`);
            if (ui.current !== s) return;
            mergeSession(s, data); renderAll();
        } catch (error) { if (ui.current === s) notice(error.message); }
    }

    function markdown(text) {
        const body = make("div", undefined, "aw-message-body");
        if (window.marked?.parse && window.DOMPurify?.sanitize) {
            body.innerHTML = window.DOMPurify.sanitize(window.marked.parse(String(text), {gfm: true, breaks: true, async: false}), {
                ALLOWED_TAGS: ["p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "del", "s", "blockquote", "ul", "ol", "li", "pre", "code", "table", "thead", "tbody", "tr", "th", "td", "a"],
                ALLOWED_ATTR: ["href", "title", "start", "colspan", "rowspan"],
                ALLOW_DATA_ATTR: false, ALLOW_ARIA_ATTR: false,
            });
            body.querySelectorAll("a").forEach(a => {
                const href = a.getAttribute("href") || "";
                if (!/^(https?:\/\/|\/(?!\/)|#)/i.test(href)) a.removeAttribute("href");
                if (/^https?:/i.test(href)) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
            });
            body.querySelectorAll("table").forEach(table => {
                const wrap = make("div", undefined, "aw-table"); wrap.tabIndex = 0;
                table.replaceWith(wrap); wrap.append(table);
            });
        } else { body.textContent = text; body.classList.add("aw-plain"); }
        linkEvidence(body);
        return body;
    }
    function scopeText(scope) {
        if (!scope) return "";
        const pieces = [];
        if (scope.host) pieces.push(scope.host);
        if (scope.alert_id) pieces.push(scope.alert_id);
        if (scope.start_time) pieces.push(`${new Date(scope.start_time).toLocaleString()} → ${new Date(scope.end_time).toLocaleString()}`);
        return pieces.join(" · ");
    }
    function renderMessages() {
        const s = ui.current, list = $("aw-messages");
        const nearEnd = list.scrollHeight - list.scrollTop - list.clientHeight < 100;
        const oldTop = list.scrollTop;
        const fragment = document.createDocumentFragment();
        let records = Array.isArray(s.transcript) ? [...s.transcript] : [];
        const pending = ui.pending.get(s.id) || s.pending_request;
        if (pending && !records.some(x => x.id === pending.request_id)) records.push({role: "user", text: pending.message, context: pending.context, id: pending.request_id});
        for (const entry of records) {
            if (!["user", "assistant"].includes(entry.role)) continue;
            const item = make("article", undefined, `aw-message aw-message-${entry.role}`);
            const header = make("header");
            header.append(make("span", entry.role === "user" ? "U" : "H", "aw-avatar"));
            header.append(make("span", entry.role === "user" ? "나" : `HAW-KI${entry.meta ? " · " + entry.meta : ""}`));
            item.append(header);
            item.append(entry.role === "user" ? make("div", entry.text || "", "aw-message-body") : markdown(entry.text || ""));
            if (scopeText(entry.context)) item.append(make("div", scopeText(entry.context), "aw-message-context"));
            fragment.append(item);
        }
        if (busy(s)) {
            const completed = Number(s.investigation?.tools_completed || 0);
            const progress = s.investigation?.phase === "reconnecting" ? "진행 상태를 확인하고 있습니다…"
                : completed ? `증거 조회 ${completed}건 완료 · 분석 중…` : "응답을 준비하고 있습니다…";
            fragment.append(make("div", progress, "aw-pending"));
        }
        list.replaceChildren(fragment);
        list.scrollTop = nearEnd ? list.scrollHeight : oldTop;
        $("aw-title").textContent = s.title || "새 대화";
        $("aw-state").textContent = busy(s) ? "진행 중" : s.mode !== "conversation" ? "이전 대화" : s.saved ? "저장됨" : "준비";
        $("aw-send").disabled = busy(s);
    }
    function renderEvidence() { evidencePanel.sync(); }
    function renderSessions() {
        const list = $("aw-sessions"), query = $("aw-search").value.toLocaleLowerCase(); list.replaceChildren();
        for (const s of ui.sessions.filter(x => (x.title || "").toLocaleLowerCase().includes(query))) {
            const row = make("div", undefined, `aw-session${s.id === ui.current?.id ? " active" : ""}`);
            const open = make("button", undefined, "aw-session-open"); open.type = "button";
            open.append(make("span", s.title || "대화"));
            open.append(make("small", s.updatedAt ? new Date(s.updatedAt).toLocaleDateString() : ""));
            open.addEventListener("click", () => select(s.id).catch(error => notice(error.message)));
            const del = make("button", "×", "aw-session-delete"); del.type = "button";
            del.setAttribute("aria-label", `${s.title || "대화"} 삭제`);
            del.disabled = busy(s) || busy(ui.current) && s.id === ui.current.id;
            del.addEventListener("click", async () => {
                if (!confirm("이 대화를 삭제할까요?")) return;
                try {
                    await api(`/api/chat-sessions/${encodeURIComponent(s.id)}`, {method: "DELETE"});
                    ui.sessions = ui.sessions.filter(x => x.id !== s.id);
                    if (ui.current?.id === s.id) newChat(); else renderSessions();
                } catch (error) { notice(error.message); }
            });
            row.append(open, del); list.append(row);
        }
    }
    function renderScope() {
        const target = $("aw-scope"); target.replaceChildren();
        const scope = ui.current.scope || {};
        for (const [key, label] of [["alert_id", "경보"], ["host", "대상"], ["start_time", "기간"]]) {
            if (!scope[key]) continue;
            const text = key === "start_time" ? scopeText({start_time: scope.start_time, end_time: scope.end_time}) : scope[key];
            const button = make("button", `${label}: ${text} ×`); button.type = "button";
            button.addEventListener("click", () => {
                delete scope[key]; if (key === "start_time") delete scope.end_time;
                renderScope();
            }); target.append(button);
        }
    }
    let proposalSequence = 0, proposalOffset = 0;
    async function renderProposals(offset = proposalOffset) {
        const target = $("aw-proposal-list"), s = ui.current, sequence = ++proposalSequence;
        const opened = new Set([...target.querySelectorAll("details[open][data-proposal]")].map(el => el.dataset.proposal));
        if (!s?.saved || s.mode !== "conversation") { target.replaceChildren(); target.dataset.session = ""; return; }
        if (target.dataset.session !== s.id) target.replaceChildren();
        target.dataset.session = s.id;
        const endpoint = `/api/agent/workspace/sessions/${encodeURIComponent(s.id)}/collection-proposals`;
        const labels = {proposed:"검토 대기", draft:"검토 중", pending_approval:"승인 대기",
            queued:"대기 중", active:"수집 중", finished:"처리 완료", failed:"실패",
            rejected:"반려", cancelled:"취소", expired:"검토 만료", submission_unknown:"접수 확인 필요"};
        try {
            const data = await api(`${endpoint}?offset=${offset}`);
            if (sequence !== proposalSequence || ui.current !== s) return;
            proposalOffset = offset; target.replaceChildren();
            if (!data.items?.length) return;
            target.append(make("h2", "수집 제안"));
            for (const p of data.items) {
                const card = make("details", undefined, "aw-evidence-card");
                card.dataset.proposal = p.id; card.open = opened.has(p.id);
                const operations={files:"파일 검색",hash:"해시 검색",yara:"YARA 검사",directory:"디렉터리 목록",acquire:"파일 수집",processes:"프로세스",network:"네트워크",services:"서비스",cron:"예약 작업",keys:"SSH 키",users:"사용자",logins:"로그인",disk:"디스크",triage:"초동 조사"};
                card.append(make("summary", `${operations[p.operation] || "수집"} · ${labels[p.status] || "상태 확인 필요"}`));
                card.append(make("p", p.id));
                card.append(make("p", p.rationale));
                card.append(make("p", p.client_ids.join(", ")));
                const settings = make("details");settings.append(make("summary", "수집 설정"),make("pre", JSON.stringify({parameters:p.params, artifacts:p.artifacts}, null, 2)));card.append(settings);
                const refs = make("p", "근거: ");
                for (const ref of p.evidence_refs) {
                    refs.append(evidenceMap().has(ref) ? evidenceButton(ref) : make("span", ref), document.createTextNode(" "));
                }
                card.append(refs);
                const proof = make("button", "근거 보기"); proof.type = "button";
                proof.addEventListener("click", async () => {
                    proof.disabled = true;
                    try {
                        const detail = await api(`${endpoint}/${encodeURIComponent(p.id)}`);
                        if (ui.current === s && card.isConnected) card.append(make("pre", JSON.stringify(detail.evidence, null, 2)));
                    } catch (error) { if (ui.current === s) notice(error.message); proof.disabled = false; }
                });
                card.append(proof);
                const review = make("button", p.job_id && p.status !== "draft" ? "작업 보기" : "수집 검토");
                review.type = "button"; review.disabled = p.status === "expired";
                review.addEventListener("click", async () => {
                    review.disabled = true;
                    try {
                        const result = await post(`${endpoint}/${encodeURIComponent(p.id)}/review`, {});
                        if (!/^\/response\?hawki_review=VR-[A-F0-9]{16}$/.test(result.review_url)) throw new Error("검토 경로를 확인할 수 없습니다.");
                        if (ui.current === s) {
                            updateLocation(s.id);
                            const reviewURL = new URL(result.review_url, location.origin);
                            await collectionPanel.open({jobId:reviewURL.searchParams.get("hawki_review"),sessionId:s.id,proposalId:p.id});
                            review.disabled = false;
                        }
                    } catch (error) { if (ui.current === s) notice(error.message); review.disabled = false; }
                });
                card.append(review);
                if (p.job_id) card.append(make("p", p.job_id));
                const policy = p.approval_required === true ? "승인 필요" :
                    p.approval_required === false ? "직접 제출" : "검토 필요";
                if (["proposed", "draft", "pending_approval"].includes(p.status)) card.append(make("small", policy));
                for (const flow of p.flows || []) {
                    const detail = make("div", undefined, "aw-flow");
                    detail.append(make("code", flow.flow_id), make("small", flow.client_id),
                        make("small", `${flow.artifact || ""} · ${flow.state || "상태 미확인"}`));
                    card.append(detail);
                }
                if (p.flows?.length) {
                    const follow = make("button", "대화에서 분석"); follow.type = "button";
                    follow.addEventListener("click", () => {
                        if ($("aw-input").value.trim()) { notice("작성 중인 메시지를 먼저 보내주세요."); return false; }
                        $("aw-input").value = `작업 ${p.job_id}의 수집 결과를 분석해 주세요.`;
                        rememberDraft(); $("aw-input").focus();
                    });
                    card.append(follow);
                }
                target.append(card);
            }
            if (offset) {
                const back=make("button","최근 제안"); back.type="button";
                back.addEventListener("click",()=>renderProposals(0)); target.append(back);
            }
            if (data.has_more) {
                const more=make("button","이전 제안"); more.type="button";
                more.addEventListener("click",()=>renderProposals(data.next_offset)); target.append(more);
            }
        } catch (error) {
            if (sequence===proposalSequence && ui.current===s) target.append(make("p", error.message));
        }
    }

    function renderAll() { collectionPanel.sync(); renderMessages(); renderEvidence(); renderSessions(); renderProposals(); }
    function rememberDraft() { if (ui.current) ui.current.draft = $("aw-input").value; }
    function updateLocation(id) {
        const url = new URL(location.href); url.search = "";
        if (id) url.searchParams.set("session", id);
        history.replaceState(null, "", url);
    }
    function newChat() {
        rememberDraft(); ui.selection++; proposalOffset = 0; ui.current = fresh();
        $("aw-input").value = ""; notice(""); updateLocation(null);
        renderAll(); renderScope(); $("aw-input").focus();
    }
    function mergeSession(target, data) {
        const draft = target.draft, scope = target.scope;
        Object.assign(target, data, {saved: true, draft: draft || "", scope: scope || {}});
        const index = ui.sessions.findIndex(x => x.id === target.id);
        if (index >= 0) ui.sessions[index] = target; else ui.sessions.unshift(target);
        return target;
    }
    async function select(id) {
        collectionPanel.close(false); rememberDraft(); const turn = ++ui.selection;
        const data = await api(`/api/agent/workspace/sessions/${encodeURIComponent(id)}`);
        if (turn !== ui.selection) return;
        const target = ui.sessions.find(x => x.id === id) || {};
        proposalOffset = 0; ui.current = mergeSession(target, data); updateLocation(id);
        $("aw-input").value = ui.current.draft; notice(""); renderAll(); renderScope();
        if (data.pending_request && !busy(ui.current)) notice("이전 요청이 완료되지 않았습니다.", () => submit(data.pending_request));
    }
    async function loadSessions() {
        const data = await api("/api/chat-sessions");
        ui.sessions = (data.sessions || []).map(s => ({...s, saved: true, draft: "", scope: {}}));
        renderSessions();
    }
    async function submit(retryPayload) {
        let s = ui.current;
        if (busy(s)) return;
        const message = retryPayload?.message || $("aw-input").value.trim(); if (!message) return;
        const capturedScope = structuredClone(retryPayload?.context || s.scope || {});
        const model = retryPayload?.model || $("aw-model").value;
        const requestId = retryPayload?.request_id || uid();
        const originalId = s.id;
        ui.pending.set(s.id, {message, context: capturedScope, request_id: requestId});
        notice(""); renderMessages(); renderSessions();
        try {
            if (s.mode !== "conversation") {
                const fork = await post(`/api/agent/workspace/sessions/${encodeURIComponent(s.id)}/continue`);
                const data = await api(`/api/agent/workspace/sessions/${encodeURIComponent(fork.id)}`);
                const previous = s;
                s = mergeSession({}, data);
                ui.pending.delete(originalId);
                ui.pending.set(s.id, {message, context: capturedScope, request_id: requestId});
                if (ui.current === previous) { ui.current = s; updateLocation(s.id); }
            } else if (!s.saved) {
                s.title = message.replace(/\s+/g, " ").slice(0, 60);
                await post("/api/chat-sessions", {id: s.id, title: s.title, mode: "conversation", context: {}, history: [], transcript: [], lastResult: null});
                s.saved = true; ui.sessions.unshift(s);
                if (ui.current === s) updateLocation(s.id);
            }
            const payload = retryPayload || {message, model, context: capturedScope, session_id: s.id, request_id: requestId};
            ui.pending.set(s.id, payload); s.pending_request = payload;
            s.scope = {}; s.draft = "";
            if (ui.current === s) { $("aw-input").value = ""; renderScope(); renderAll(); }
            await post("/api/agent/workspace/turn", payload);
            const data = await api(`/api/agent/workspace/sessions/${encodeURIComponent(s.id)}`);
            mergeSession(s, data);
        } catch (error) {
            try {
                if (s.saved) mergeSession(s, await api(`/api/agent/workspace/sessions/${encodeURIComponent(s.id)}`));
            } catch (_) {}
            if (ui.current === s) {
                const pending = s.pending_request || ui.pending.get(s.id);
                notice(error.message, pending?.session_id && !s.investigation?.running ? () => submit(pending) : null);
                if (!s.saved) { $("aw-input").value = message; s.draft = message; }
            }
        } finally {
            ui.pending.delete(originalId); ui.pending.delete(s.id);
            if (ui.current === s) renderAll(); else renderSessions();
        }
    }
    async function poll() {
        const s = ui.current;
        if (!s?.saved || document.hidden || !busy(s)) return;
        try {
            const data = await api(`/api/agent/workspace/sessions/${encodeURIComponent(s.id)}`);
            if (ui.current !== s) return;
            const changed = JSON.stringify([s.transcript, s.investigation]) !== JSON.stringify([data.transcript, data.investigation]);
            mergeSession(s, data);
            if (changed) renderAll();
            if (data.pending_request && !busy(s)) notice("이전 요청이 완료되지 않았습니다.", () => submit(data.pending_request));
        } catch (error) { if (ui.current === s) notice(error.message); }
    }
    let alertSearch = 0;
    async function loadAlerts() {
        const sequence = ++alertSearch, target = $("aw-alert-results");
        target.textContent = "조회 중…";
        try {
            const query = new URLSearchParams({category: "all", range: "7d", sort: "priority", q: $("aw-alert-query").value});
            const data = await api(`/api/alerts?${query}`);
            if (sequence !== alertSearch) return;
            target.replaceChildren();
            if (!data.alerts?.length) target.append(make("p", "조회된 경보가 없습니다."));
            for (const item of (data.alerts || []).slice(0, 60)) {
                const id = String(item.id || item.alert_id || ""); if (!id) continue;
                const button = make("button", item.title || item.description || id, "aw-alert-choice"); button.type = "button";
                button.append(make("small", [id, item.host, item.timestamp].filter(Boolean).join(" · ")));
                button.addEventListener("click", () => { ui.current.scope.alert_id = id; renderScope(); $("aw-alert-dialog").close(); });
                target.append(button);
            }
        } catch (error) { if (sequence === alertSearch) target.textContent = error.message; }
    }
    async function loadHosts() {
        try {
            const data = await api("/api/log-search/hosts");
            const target = $("aw-host-options"); target.replaceChildren();
            for (const item of data.hosts || []) {
                const value = typeof item === "string" ? item : item.name || item.host || item.hostname;
                if (value) { const option = make("option"); option.value = value; target.append(option); }
            }
        } catch (_) { /* The target can still be entered explicitly. */ }
    }
    async function services() {
        try {
            const data = await api("/api/status"); let online = 0, configured = 0;
            for (const [name, value] of Object.entries(data.services || {})) {
                if (value.configured !== false) { configured++; if (value.ok) online++; }
                document.querySelectorAll("[data-service-dot]").forEach(dot => {
                    if (dot.dataset.serviceDot !== name) return;
                    dot.classList.remove("unknown", "online", "offline", "unconfigured");
                    dot.classList.add(value.configured === false ? "unconfigured" : value.ok ? "online" : "offline");
                });
            }
            $("global-health-text").textContent = `설정된 서비스 ${configured}개 중 ${online}개 연결됨`;
        } catch (_) { $("global-health-text").textContent = "상태 확인 실패"; }
    }
    function chrome(user) {
        const host = document.querySelector(".topbar-actions");
        const controls = make("div", undefined, "account-controls"); controls.id = "account-controls";
        const account = make("a", "◉", "topbar-icon-button"); account.href = "/account";
        account.title = `${user.username} (${user.role})`; account.setAttribute("aria-label", "계정"); controls.append(account);
        if (user.role === "admin") { const admin = make("a", "⚙", "topbar-icon-button"); admin.href = "/admin/users"; admin.setAttribute("aria-label", "사용자 관리"); controls.append(admin); }
        const logout = make("button", "↪", "topbar-icon-button"); logout.type = "button"; logout.setAttribute("aria-label", "로그아웃");
        logout.addEventListener("click", async () => { try { await post("/api/auth/logout"); location.assign("/login"); } catch (e) { notice(e.message); } }); controls.append(logout); host.prepend(controls);
        $("theme-toggle")?.addEventListener("click", () => {
            const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
            document.documentElement.dataset.theme = next;
            try { localStorage.setItem("hawki-theme-v2", next); } catch (_) {}
            document.cookie = `hawki_theme_v2=${next}; Path=/; Max-Age=31536000; SameSite=Lax`;
        });
        $("refresh-services")?.addEventListener("click", services);
    }
    async function boot() {
        const auth = await api("/api/auth/me"); ui.csrf = auth.csrf_token; chrome(auth.user);
        ui.current = fresh(); renderAll();
        $("aw-new").addEventListener("click", newChat);
        $("aw-refresh").addEventListener("click", refreshInvestigation);
        window.addEventListener("pageshow", event => { if (event.persisted) refreshInvestigation(); });
        document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshInvestigation(); });
        $("aw-search").addEventListener("input", renderSessions);
        $("aw-input").addEventListener("input", rememberDraft);
        $("aw-form").addEventListener("submit", event => { event.preventDefault(); submit(); });
        $("aw-input").addEventListener("keydown", event => {
            if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); $("aw-form").requestSubmit(); }
        });
        $("aw-evidence-toggle").addEventListener("click", () => {
            const hidden = root.classList.toggle("aw-evidence-hidden"); $("aw-evidence-toggle").setAttribute("aria-expanded", String(!hidden));
        });
        root.querySelectorAll("[data-aw-dialog]").forEach(button => button.addEventListener("click", () => {
            const dialog = $(button.dataset.awDialog); dialog.showModal();
            if (dialog.id === "aw-alert-dialog") loadAlerts();
            if (dialog.id === "aw-host-dialog") { $("aw-host").value = ui.current.scope.host || ""; loadHosts(); }
        }));
        root.querySelectorAll("[data-aw-close]").forEach(button => button.addEventListener("click", () => button.closest("dialog").close()));
        $("aw-alert-search-form").addEventListener("submit", event => { event.preventDefault(); loadAlerts(); });
        $("aw-host-form").addEventListener("submit", event => { event.preventDefault(); ui.current.scope.host = $("aw-host").value.trim(); renderScope(); $("aw-host-dialog").close(); });
        $("aw-timezone").textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;
        $("aw-time-form").addEventListener("submit", event => {
            event.preventDefault(); const start = new Date($("aw-start").value), end = new Date($("aw-end").value);
            if (!(end > start) || end - start > 31 * 86400000) { $("aw-time-error").textContent = "시작 이후, 31일 이내의 종료 시각을 선택하세요."; return; }
            ui.current.scope.start_time = start.toISOString(); ui.current.scope.end_time = end.toISOString();
            $("aw-time-error").textContent = ""; renderScope(); $("aw-time-dialog").close();
        });
        const params = new URLSearchParams(location.search);
        // Links from other screens name what they want done (mode); the
        // conversation starts with that request written out, not sent.
        function starterPrompt(query) {
            const given = (query.get("prompt") || "").trim();
            const incident = (query.get("incident") || "").trim();
            const lead = {
                alert_summary: "선택한 경보를 증거·해석·다음 확인 사항으로 설명해 줘.",
                log_search: "이 조건으로 관련 로그를 찾아 정리해 줘.",
                file_hunt: "이 파일 단서로 어느 호스트에 같은 파일이 있는지 확인할 수집 계획을 세워 줘.",
                velociraptor_response: "이 호스트에서 확인할 증거와 대응 조치 제안을 정리해 줘.",
                suricata_rule: "이 탐지 의도에 맞는 Suricata 룰 초안을 검토해 줘.",
                incident_report: "이 사건을 보고서 형식으로 정리해 줘.",
            }[query.get("mode")] || "";
            return [lead, incident ? `사건: ${incident}` : "", given].filter(Boolean).join("\n");
        }
        await loadSessions();
        if (params.get("session")) await select(params.get("session"));
        else {
            for (const key of ["host", "alert_id"]) if (params.get(key)) ui.current.scope[key] = params.get(key);
            const ids = params.get("alert_ids"); if (!ui.current.scope.alert_id && ids) ui.current.scope.alert_id = ids.split(",")[0];
            $("aw-input").value = starterPrompt(params); rememberDraft(); renderScope();
        }
        services();
        try {
            const catalog = await api("/api/agent/workspace/bootstrap"); ui.models = catalog.models || [];
            const select = $("aw-model"); select.replaceChildren();
            for (const model of ui.models) { const option = make("option", model.label); option.value = model.id; select.append(option); }
            select.value = catalog.default_model; select.disabled = ui.models.length < 2;
            if (!ui.models.some(model => model.ready)) notice("모델 연결을 확인할 수 없습니다.", () => location.reload());
        } catch (error) { notice(error.message); }
        ui.poll = setInterval(poll, 3000);
    }
    boot().catch(error => notice(error.message));
})();
