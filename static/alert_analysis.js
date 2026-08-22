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
        if (!response.ok) throw new Error(body.detail || body.error || `요청 실패: ${response.status}`);
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
            <strong>${escapeHtml(event.message || event.rule?.name || "이벤트")}</strong>
            <p class="muted">${escapeHtml(host)}</p>
        </div>`;
    }

    function formatAsset(asset) {
        const facts = [
            ["업무 중요도", asset.criticality],
            ["노출 범위", asset.exposure],
            ["망 구역", asset.zone],
            ["데이터 등급", asset.data_classification],
            ["담당자", asset.owner],
        ].filter(([, value]) => value);
        const matchedOn = asset.match?.matched_on || [];
        return `<div class="output-item">
            <div class="action-meta">
                ${asset.match?.on_trigger_alert ? `<span class="tag">트리거 경보에 직접 등장</span>` : ""}
                ${facts.map(([label, value]) => `<span class="tag">${escapeHtml(label)}: ${escapeHtml(value)}</span>`).join("")}
            </div>
            <strong>${escapeHtml(asset.hostname || asset.id)}</strong>
            <p class="muted">${escapeHtml(asset.business_service || "—")}</p>
            <p class="muted">매칭 근거: ${escapeHtml(matchedOn.join(", ") || "—")}</p>
        </div>`;
    }

    function formatIndicator(indicator) {
        const match = indicator.match || {};
        return `<div class="output-item">
            <div class="action-meta">
                <span class="tag">${escapeHtml(indicator.verdict || "판정 없음")}</span>
                <span class="tag">신뢰도 ${escapeHtml(indicator.confidence ?? 0)}</span>
                ${match.on_trigger_alert ? `<span class="tag">트리거 경보에 직접 등장</span>` : ""}
                ${match.indicator_expired ? `<span class="tag">만료된 지표</span>` : ""}
            </div>
            <strong>${escapeHtml(match.matched_value || indicator.value)}</strong>
            <p class="muted">${escapeHtml(indicator.description || "")}</p>
            <p class="muted">${escapeHtml(indicator.feed || "피드")} · ${escapeHtml((indicator.categories || []).join(", ") || "분류 없음")}</p>
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
            `<span class="tag">${review.complete ? "필수 항목 모두 채움" : `미작성 항목 ${missing.length}개`}</span>`,
            `<span class="tag">증거 인용 ${escapeHtml(review.citations ?? 0)}건</span>`,
            ungrounded.length ? `<span class="tag">근거 없는 인용 ${ungrounded.length}건</span>` : "",
            review.repair_attempted ? `<span class="tag">보정 1회 수행</span>` : "",
        ].join("");

        panel.hidden = false;
        panel.innerHTML = `<div class="output-item">
            <div class="action-meta">${tags}</div>
            ${missing.length ? `<p class="muted">보고되지 않은 항목: ${escapeHtml(missing.join(", "))}</p>` : ""}
            ${ungrounded.length ? `<p class="muted">번들에 없는 이벤트를 인용함: ${escapeHtml(ungrounded.join(", "))}</p>` : ""}
            ${notes.map((note) => `<p class="muted">${escapeHtml(note)}</p>`).join("")}
        </div>`;
    }

    function renderCase(root, data) {
        const caseData = data.case;
        const trigger = caseData.trigger || {};
        root.querySelector("[data-case-title]").textContent = caseData.title || trigger.message || "경보 케이스";
        root.querySelector("[data-case-id]").textContent = `${caseData.case_id} · ${caseData.scenario_id}`;
        root.querySelector("[data-trigger]").innerHTML = formatEvent(trigger);

        const entities = caseData.entities || {};
        root.querySelector("[data-entities]").innerHTML = Object.entries(entities)
            .filter(([, values]) => Array.isArray(values) && values.length)
            .map(([key, values]) => `<div class="output-item"><strong>${escapeHtml(key.replaceAll("_", " "))}</strong><div class="action-meta">${values.map((v) => `<span class="tag">${escapeHtml(v)}</span>`).join("")}</div></div>`)
            .join("") || `<div class="empty-state">상관분석된 대상이 없습니다.</div>`;

        const assets = caseData.assets || [];
        const unresolved = caseData.unresolved_assets || [];
        root.querySelector("[data-assets]").innerHTML = [
            assets.map(formatAsset).join(""),
            unresolved.length
                ? `<div class="output-item"><strong>자산 명단에 없음</strong><div class="action-meta">${unresolved.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")}</div><p class="muted">외부 자산이거나, 관리 대상이 아니거나, 명단에서 빠진 것입니다 — 안전하다는 뜻이 아니라 정보가 없다는 뜻입니다.</p></div>`
                : "",
        ].join("") || `<div class="empty-state">연결된 자산 정보가 없습니다.</div>`;

        const intel = caseData.threat_intelligence || [];
        const stats = caseData.threat_intelligence_stats || {};
        root.querySelector("[data-intel]").innerHTML = [
            intel.map(formatIndicator).join(""),
            `<div class="output-item"><p class="muted">관측값 ${escapeHtml(stats.observables_checked || 0)}건 조회 · 그중 ${escapeHtml(stats.observables_without_intelligence_count || 0)}건은 정보 없음. 매칭은 의심을 높일 뿐, 침해를 증명하지 않습니다.</p></div>`,
        ].join("") || `<div class="empty-state">매칭된 위협 지표가 없습니다.</div>`;

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
            button.textContent = "분석 중…";
            output.classList.remove("empty-state");
            output.innerHTML = `<div class="typing"><i></i><i></i><i></i></div>`;
            try {
                const result = await requestJson(`/api/alerts/${encodeURIComponent(alertId)}/analyze`, {
                    method: "POST",
                    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
                    body: JSON.stringify({}),
                });
                output.innerHTML = `<div class="markdown-body">${markdown(result.answer || "분석 결과가 없습니다.")}</div>`;
                if (typeof window.enhanceRenderedContent === "function") window.enhanceRenderedContent(output);
                renderReview(root, result);
                const counts = result.metadata_counts || {};
                const bundled = [
                    `경보 ${counts.security_alerts ?? 0}건`,
                    `원본 이벤트 ${counts.security_events ?? 0}건`,
                    `자산 ${counts.assets ?? 0}건`,
                    `위협 지표 ${counts.threat_indicators ?? 0}건`,
                ].join(" · ");
                root.querySelector("[data-analysis-meta]").textContent = `${result.model || "로컬 모델"} · 전달한 증거: ${bundled}`;
            } catch (error) {
                output.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
            } finally {
                button.disabled = false;
                button.textContent = "LLM으로 분석하기";
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
