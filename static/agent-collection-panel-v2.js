"use strict";
/* Existing native collection API, displayed inside the owned agent session. */
window.HawkiCollectionPanel = function ({root, api, post, currentSession, changed, ask}) {
    const make = (tag, text, cls) => { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e; };
    const panel=make('section',undefined,'aw-collection-panel'); panel.hidden=true;
    panel.setAttribute('aria-label','수집 검토 및 결과');
    const heading=make('header',undefined,'aw-heading'), title=make('h2','수집 검토 및 결과');
    const closeButton=make('button','닫기'); closeButton.type='button'; heading.append(title,closeButton);
    const status=make('p','', 'aw-collection-status'); status.setAttribute('role','status');
    const content=make('div',undefined,'aw-collection-content'), results=make('div',undefined,'aw-collection-results');
    panel.append(heading,status,content,results); document.getElementById('aw-evidence-panel').prepend(panel);
    let context=null, generation=0, timer=null, loading=false, mutating=false, resultGeneration=0, focusBefore=null;
    const labels={draft:'검토 중 · 미제출',pending_approval:'승인 대기',queued:'실행 대기',active:'수집 진행',
        finished:'수집 처리 종료',failed:'실패',rejected:'반려',cancelled:'취소',cancel_requested:'취소 요청',submission_unknown:'접수 확인 필요'};
    function valid(g) { return context && g===generation && currentSession()===context.sessionId; }
    function button(label, fn) { const b=make('button',label);b.type='button';b.addEventListener('click',fn);return b; }
    function close(restore=true) { generation++;resultGeneration++;clearTimeout(timer);context=null;loading=false;mutating=false;panel.hidden=true;root.classList.remove('aw-collection-open'); if(restore&&focusBefore?.isConnected)focusBefore.focus(); }
    closeButton.addEventListener('click',()=>close());
    panel.addEventListener('keydown',e=>{if(e.key==='Escape'){e.preventDefault();close();}});
    function schedule(g) { clearTimeout(timer); if(valid(g))timer=setTimeout(()=>refresh(g),5000); }
    function showError(e,g) { if(valid(g))status.textContent=e.message || '조회에 실패했습니다.'; }
    async function mutate(action,body,g) {
        if(!valid(g)||mutating)return;
        mutating=true;content.querySelectorAll('[data-mutation]').forEach(b=>b.disabled=true);
        try {
            await post(`/api/vr/jobs/${encodeURIComponent(context.jobId)}/${action}`,body);
            if(valid(g)){status.textContent='요청이 접수되었습니다. 작업 상태를 확인합니다.';await changed();}
        } catch(e){showError(e,g);}
        finally {if(valid(g)){mutating=false;context.signature=null;await refresh(g,true);}}
    }
    function render(job,g) {
        content.replaceChildren();
        const m=job.manifest||{};
        content.append(make('p',`${job.id} · ${labels[job.state]||job.state}`));
        content.append(make('h3',m.label||'수집 작업'));
        for(const target of m.targets||[])content.append(make('p',`${target.hostname||''} · ${target.client_id||''}`));
        content.append(make('p',m.approval_required?'제출 후 별도 승인이 필요합니다.':'별도 승인 없이, 직접 제출하면 수집 대기열에 등록됩니다.'));
        const detail=make('details');detail.append(make('summary','대상 · 매개변수 · 수집 한도'));
        detail.append(make('pre',JSON.stringify({client_ids:m.client_ids,artifacts:m.spec,parameters:m.params,limits:m.limits,incident:m.incident},null,2)));
        content.append(detail);
        const actions=make('div',undefined,'aw-collection-actions');
        function action(label,route,body) {const b=button(label,()=>mutate(route,body,g));b.dataset.mutation='true';b.disabled=mutating;actions.append(b);}
        if(job.state==='draft') {
            if(job.expires && job.expires*1000<=Date.now())content.append(make('p','검토 기한이 만료되었습니다. 새 제안을 검토하세요.'));
            else action(m.approval_required?'승인 요청 제출':'수집 시작','submit',{});
            content.append(make('p','수집은 대상 시스템 자원을 사용합니다. 대상, 매개변수와 한도를 검토한 후 제출하세요.'));
        }
        if(job.state==='pending_approval' && context.canApprove) {
            action('승인','decision',{approve:true});action('반려','decision',{approve:false});
        }
        if(['queued','active','submission_unknown','cancel_requested'].includes(job.state)&&context.canApprove)
            action('남은 수집 취소 요청','cancel',{});
        actions.append(button('상태 새로고침',()=>refresh(g,true)));
        content.append(actions);
        for(const u of job.units||[]) {
            const row=make('div',undefined,'aw-collection-unit');
            row.append(make('p',`${u.client_id} · ${u.artifact}`),make('p',`${u.state} / ${u.native?.state||'원격 상태 미확인'}`));
            if(u.error)row.append(make('p',u.error));
            if(u.flow_id) {
                row.append(make('code',u.flow_id));
                row.append(button('결과 소스 보기',()=>sources(u,g)));
            }
            content.append(row);
        }
        if((job.units||[]).some(u=>u.flow_id))content.append(button('이 수집 결과를 대화에서 분석',()=>{
            if(valid(g))ask(`제안 ${context.proposalId}, 작업 ${job.id}에 연결된 수집 결과를 읽기 전용 도구로 확인해 주세요. 정확한 flow ID, 수집 시각, 반환 범위와 한계를 확인하고 증거 ID를 인용해 주세요. 새 수집을 시작하지 마세요.`);
        }));
        content.append(make('small',`작업 조회 시각: ${new Date().toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})} KST. 완료 상태만으로 조사 결론이 검증되지는 않습니다.`));
    }
    async function refresh(g,force=false) {
        if(!valid(g)||loading||mutating)return;
        if(document.hidden&&!force){schedule(g);return;}
        loading=true;
        try {
            const job=await api(`/api/vr/jobs/${encodeURIComponent(context.jobId)}`);
            if(!valid(g))return;
            if(job.id!==context.jobId)throw Error('작업 식별자가 일치하지 않습니다.');
            // Avoid replacing buttons/focus and expanded details on unchanged polling responses.
            const signature=JSON.stringify(job);
            if(signature!==context.signature){context.signature=signature;render(job,g);}
        }catch(e){showError(e,g);}finally{if(valid(g)){loading=false;schedule(g);}}
    }
    async function sources(u,g) {
        const rg=++resultGeneration; results.replaceChildren(make('p','결과 소스 확인 중…'));
        try {
            const q=new URLSearchParams({client_id:u.client_id,flow_id:u.flow_id,kind:'logs',size:'1'});
            const metadata=await api('/api/vr/results?'+q);
            const flow=metadata.flow||{};
            if(metadata.client_id!==u.client_id||metadata.flow_id!==u.flow_id)throw Error('수집 식별자가 일치하지 않습니다.');
            if(!valid(g)||rg!==resultGeneration)return;
            results.replaceChildren(make('h3','수집 결과'));
            results.append(make('p',`${u.client_id} · ${u.flow_id} · ${flow.state||'상태 미확인'}`));
            const names=flow.artifacts_with_results||[];
            if(!names.length)results.append(make('p','반환된 결과 소스가 없습니다. 수집 상태와 로그를 확인하세요.'));
            for(const artifact of names)results.append(button(artifact,()=>rows(u,artifact,0,g)));
            results.append(button('수집 로그',()=>rows(u,'',0,g,'logs')));
        }catch(e){if(valid(g)&&rg===resultGeneration)results.replaceChildren(make('p',e.message));}
    }
    async function rows(u,artifact,offset,g,kind='rows') {
        const rg=++resultGeneration; results.replaceChildren(make('p','결과 조회 중…'));
        try {
            const q=new URLSearchParams({client_id:u.client_id,flow_id:u.flow_id,artifact,offset:String(offset),size:'10',kind});
            const data=await api('/api/vr/results?'+q);
            if(!valid(g)||rg!==resultGeneration)return;
            if(data.client_id!==u.client_id||data.flow_id!==u.flow_id||data.artifact!==artifact)throw Error('결과 식별자가 일치하지 않습니다.');
            results.replaceChildren(make('h3',artifact||'수집 로그'));
            results.append(make('p',`${u.client_id} · ${u.flow_id} · ${data.flow?.state||''}`));
            const micro=value=>Number.isFinite(Number(value))&&Number(value)>0?new Date(Number(value)/1000).toISOString():'미확인';
            results.append(make('p',`수집 시작: ${micro(data.flow?.start_time)} / 마지막 활동: ${micro(data.flow?.active_time)} (UTC)`));
            results.append(make('p',`행 위치 ${offset}부터 ${data.items?.length||0}행 · 추가 페이지 ${data.has_more?'있음':'없음'}. 수집 시점의 기록이며 현재 상태를 보장하지 않습니다.`));
            results.append(make('pre',JSON.stringify(data.items||[],null,2)));
            const navigation=make('div',undefined,'aw-collection-actions');
            navigation.append(button('결과 소스',()=>sources(u,g)));
            if(offset>0)navigation.append(button('이전 10행',()=>rows(u,artifact,Math.max(0,offset-10),g,kind)));
            if(data.has_more&&offset+10<=10000)navigation.append(button('다음 10행',()=>rows(u,artifact,offset+10,g,kind)));
            results.append(navigation);
        }catch(e){if(valid(g)&&rg===resultGeneration)results.replaceChildren(make('p',e.message));}
    }
    return {
        close,
        sync(){if(context&&currentSession()!==context.sessionId)close(false);},
        async open({jobId,sessionId,proposalId}) {
            if(!/^VR-[A-F0-9]{16}$/.test(jobId)||currentSession()!==sessionId)throw Error('검토 대상이 올바르지 않습니다.');
            close(false);focusBefore=document.activeElement;const g=++generation;
            context={jobId,sessionId,proposalId,canApprove:false,signature:null};
            panel.hidden=false;root.classList.add('aw-collection-open');root.classList.remove('aw-evidence-hidden');
            document.getElementById('aw-evidence-toggle').setAttribute('aria-expanded','true');
            status.textContent='기존 수집 작업을 확인합니다.';content.replaceChildren();results.replaceChildren();closeButton.focus();
            // Opening performs reads only. Draft creation happened in the owned review endpoint.
            try {const auth=await api('/api/auth/me');if(valid(g))context.canApprove=['admin','approver'].includes(auth.user?.role);}
            catch(e){showError(e,g);}
            if(valid(g)){status.textContent='';await refresh(g,true);}
        }
    };
};
