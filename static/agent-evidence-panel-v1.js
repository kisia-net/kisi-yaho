/* Saved evidence browser. Opening, paging and copying never submit collections. */
window.HawkiEvidencePanel = function ({root, api, currentSession, notice}) {
    const list = root.querySelector('#aw-evidence-list');
    const count = root.querySelector('#aw-evidence-count');
    let session = null, signature = '', generation = 0, cursor = null, more = false, loading = false;
    let total = 0, records = new Map(), cards = new Map(), summaries, status, next;
    const make = (tag, text, cls) => {
        const el = document.createElement(tag);
        if (text !== undefined) el.textContent = text;
        if (cls) el.className = cls;
        return el;
    };
    const endpoint = () => `/api/agent/workspace/sessions/${encodeURIComponent(session.id)}/evidence`;
    const valid = (g, s) => g === generation && s === session && currentSession() === s;
    function update() {
        count.textContent = total;
        status.textContent = `저장된 증거 ${total}건 · 표시 ${cards.size}건`;
        next.hidden = !more; next.disabled = loading;
        next.textContent = loading ? '불러오는 중…' : '이전 증거 20건 더 보기';
    }
    async function detail(ref, card) {
        if (card.dataset.loaded === 'true' || card.dataset.loading === 'true') return;
        const g = generation, s = session;
        card.dataset.loading = 'true';
        const state = make('p', '증거 불러오는 중…'); card.append(state);
        try {
            let record = records.get(ref);
            if (!record) {
                const data = await api(`${endpoint()}/${encodeURIComponent(ref)}`);
                record = data.record;
            }
            if (!valid(g,s)) return;
            if (!record || record.ref !== ref) throw Error('증거 ID가 일치하지 않습니다.');
            records.set(ref,record); state.remove();
            card.append(make('pre',JSON.stringify(record,null,2)));
            const copy = make('button','JSON 복사');copy.type='button';
            copy.addEventListener('click',async () => {
                try { await navigator.clipboard.writeText(JSON.stringify(record,null,2)); copy.textContent='복사됨'; }
                catch (_) { copy.textContent='복사 실패 · 아래 JSON을 선택하세요'; }
            });
            card.insertBefore(copy,card.querySelector('pre'));
            card.dataset.loaded='true';
        } catch (error) {
            if (valid(g,s)) state.textContent = error.message;
        } finally { card.dataset.loading='false'; }
    }
    function add(item) {
        if (!/^E-[a-f0-9]{32}$/.test(item.ref || '') || cards.has(item.ref)) return cards.get(item.ref);
        const card=make('details',undefined,'aw-evidence-card');card.id=`aw-proof-${item.ref}`;
        card.append(make('summary',item.ref),make('p',`${item.tool || ''} · ${item.status || 'unknown'}`));
        if (item.recorded_at) card.append(make('p',item.recorded_at));
        card.addEventListener('toggle',()=>{if(card.open) detail(item.ref,card);});
        cards.set(item.ref,card);summaries.append(card);return card;
    }
    async function page() {
        if (loading || !session?.saved) return;
        const g=generation,s=session;loading=true;update();
        try {
            const data=await api(endpoint()+(cursor ? `?before=${cursor}` : ''));
            if (!valid(g,s)) return;
            for (const item of data.items || []) add(item);
            total=data.total;more=data.has_more;cursor=data.next_before;
        } catch (error) {
            if (valid(g,s)) {more=true;notice(error.message);}
        } finally { if(valid(g,s)){loading=false;update();} }
    }
    function sync() {
        const s=currentSession();
        const key=JSON.stringify([s?.id,s?.saved,s?.investigation?.revision,s?.investigation?.updated_at,
                                  s?.evidence?.map(x=>x.ref),s?.lastResult?.tool_trace?.map(x=>x.ref)]);
        if(s===session && key===signature)return;
        session=s;signature=key;generation++;loading=false;cursor=null;more=false;total=0;
        records=new Map();cards=new Map();list.replaceChildren();
        status=make('p','','aw-evidence-status');status.setAttribute('role','status');
        const coverage=make('p','저장된 증거를 표시합니다. 보관 기능 적용 전에 제거된 이전 증거는 없을 수 있습니다.','aw-evidence-coverage');
        summaries=make('div');next=make('button','이전 증거 20건 더 보기');next.type='button';next.hidden=true;
        next.addEventListener('click',page);list.append(status,coverage,summaries,next);
        if (!s) {update();return;}
        for(const record of [...(s.evidence||[]),...(s.lastResult?.tool_trace||[])]) if(record?.ref)records.set(record.ref,record);
        if(s.saved)page();
        else {for(const record of records.values())add({ref:record.ref,tool:record.tool,status:record.result?.status});total=cards.size;update();}
    }
    async function open(ref) {
        sync();const g=generation,s=session;
        try {
            let card=cards.get(ref);
            if(!card) {
                const record=records.get(ref) || (await api(`${endpoint()}/${encodeURIComponent(ref)}`)).record;
                if(!valid(g,s))return;
                if(!record || record.ref!==ref)throw Error('증거 ID가 일치하지 않습니다.');
                records.set(ref,record);card=add({ref,tool:record.tool,status:record.result?.status,recorded_at:record.recorded_at});
                update();
            }
            root.classList.remove('aw-evidence-hidden');
            root.querySelector('#aw-evidence-toggle').setAttribute('aria-expanded','true');
            card.open=true;await detail(ref,card);
            if(valid(g,s)){card.scrollIntoView({block:'nearest',behavior:'smooth'});card.querySelector('summary').focus();}
        }catch(error){if(valid(g,s))notice(error.message);}
    }
    return {sync,open,invalidate:()=>{signature='';}};
};
