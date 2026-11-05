// 왼쪽 메뉴의 서비스 연결 상태. Every page has the sidebar, but not every page
// loads app.js (AI 작업공간, 파일 추적, 호스트 대응), so the sidebar keeps
// itself current: one /api/status call now and once a minute.
(() => {
    const rows = document.querySelectorAll("[data-service-short]");
    if (!rows.length) return;
    const reasonText = { refused: " · 서비스 미실행", timeout: " · 응답 없음" };
    async function refresh() {
        try {
            const response = await fetch("/api/status", { credentials: "same-origin", headers: { Accept: "application/json" } });
            if (!response.ok) return;
            const data = await response.json();
            for (const [name, details] of Object.entries(data.services || {})) {
                const configured = details?.configured !== false;
                const online = Boolean(details?.ok);
                document.querySelectorAll(`[data-service-dot="${CSS.escape(name)}"]`).forEach((dot) => {
                    dot.classList.remove("unknown", "online", "offline", "unconfigured");
                    dot.classList.add(!configured ? "unconfigured" : online ? "online" : "offline");
                });
                const full = (!configured ? "미설정" : online ? `연결됨 · HTTP ${details.status_code}` : `연결 안 됨${reasonText[details?.error_kind] || ""}`)
                    + (details?.latency_ms != null ? ` · ${details.latency_ms} ms` : "");
                document.querySelectorAll(`[data-service-short="${CSS.escape(name)}"]`).forEach((label) => {
                    label.textContent = !configured ? "미설정" : online ? "연결됨" : "연결 안 됨";
                    label.closest("[data-service-row]")?.setAttribute("title", full);
                });
            }
            const checked = document.getElementById("status-checked-at");
            const when = new Date(data.checked_at);
            if (checked && !Number.isNaN(when.getTime())) {
                checked.textContent = when.toLocaleTimeString("ko-KR", { timeZone: "Asia/Seoul", hour: "2-digit", minute: "2-digit", hour12: false });
            }
        } catch (_) { /* The next minute tries again. */ }
    }
    refresh();
    setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 60_000);
})();
