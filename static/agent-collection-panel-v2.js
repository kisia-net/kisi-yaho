"use strict";
/* Existing native collection API, displayed inside the owned agent session. */
window.HawkiCollectionPanel = function ({root, api, post, currentSession, changed, ask}) {
    const make = (tag, text, cls) => { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e; };
    const panel=make('dialog',undefined,'aw-collection-panel'); panel.hidden=true;
    panel.setAttribute('aria-modal','true'); panel.setAttribute('aria-labelledby','aw-collection-title');
    panel.setAttribute('aria-label','수집 상세');
    const heading=make('header',undefined,'aw-heading'), title=make('h2','수집 상세');
    title.id='aw-collection-title';
    const closeButton=make('button','닫기'); closeButton.type='button'; heading.append(title,closeButton);
    const status=make('p','', 'aw-collection-status'); status.setAttribute('role','status');
    const content=make('div',undefined,'aw-collection-content'), results=make('div',undefined,'aw-collection-results');
    panel.append(heading,status,content,results); root.append(panel);
    let context=null, generation=0, timer=null, loading=false, mutating=false, resultGeneration=0, focusBefore=null;
    const labels={draft:'검토 중',pending_approval:'승인 대기',queued:'대기 중',active:'수집 중',
        finished:'처리 완료',failed:'실패',rejected:'반려',cancelled:'취소',cancel_requested:'취소 요청',submission_unknown:'접수 확인 필요'};
    function valid(g) { return context && g===generation && currentSession()===context.sessionId; }
    function button(label, fn) { const b=make('button',label);b.type='button';b.addEventListener('click',fn);return b; }
    function close(restore=true) { generation++;resultGeneration++;clearTimeout(timer);context=null;loading=false;mutating=false;if(panel.open)panel.close();panel.hidden=true; if(restore&&focusBefore?.isConnected)focusBefore.focus(); }
    closeButton.addEventListener('click',()=>close());
    panel.addEventListener('cancel',e=>{e.preventDefault();close();});
    function schedule(g) { clearTimeout(timer); if(valid(g))timer=setTimeout(()=>refresh(g),5000); }
    function showError(e,g) { if(valid(g)){context.error=true;status.textContent=e.message || '요청을 처리하지 못했습니다.';} }
    async function mutate(action,body,g) {
        if(!valid(g)||mutating)return;
        context.error=false;status.textContent='';mutating=true;content.querySelectorAll('[data-mutation]').forEach(b=>b.disabled=true);
        try {
            await post(`/api/vr/jobs/${encodeURIComponent(context.jobId)}/${action}`,body);
            if(valid(g)){status.textContent='';await changed();}
        } catch(e){showError(e,g);}
        finally {if(valid(g)){mutating=false;context.signature=null;await refresh(g);}}
    }
    function render(job,g) {
        content.replaceChildren();
        const m=job.manifest||{};
        content.append(make('p',labels[job.state]||'상태 확인 필요','aw-collection-badge'));
        content.append(make('h3',m.label||'수집 작업'));
        for(const target of m.targets||[])content.append(make('p',target.hostname||target.client_id||'대상 미확인')); 
        if(job.state==='draft' && m.approval_required)content.append(make('p','승인 필요'));
        const detail=make('details');detail.append(make('summary','수집 설정'));
        detail.append(make('pre',JSON.stringify({job_id:job.id,client_ids:m.client_ids,artifacts:m.spec,parameters:m.params,limits:m.limits,incident:m.incident},null,2)));
        content.append(detail);
        const actions=make('div',undefined,'aw-collection-actions');
        function action(label,route,body) {const b=button(label,()=>mutate(route,body,g));b.dataset.mutation='true';b.disabled=mutating;actions.append(b);}
        if(job.state==='draft') {
            if(job.expires && job.expires*1000<=Date.now())content.append(make('p','검토 기한이 만료되었습니다.'));
            else action(m.approval_required?'승인 요청':'수집 시작','submit',{});
        }
        if(job.state==='pending_approval' && context.canApprove) {
            action('승인','decision',{approve:true});action('반려','decision',{approve:false});
        }
        if(['queued','active','submission_unknown','cancel_requested'].includes(job.state)&&context.canApprove)
            action('취소 요청','cancel',{});
        actions.append(button('새로고침',()=>refresh(g,true)));
        content.append(actions);
        for(const u of job.units||[]) {
            const row=make('div',undefined,'aw-collection-unit');
            const nativeLabels={FINISHED:'완료',RUNNING:'수집 중',WAITING:'대기 중',ERROR:'실패',CANCELLED:'취소',STOPPED:'중지'};
            row.append(make('p',u.artifact||'수집 결과'),make('p',labels[u.state]||nativeLabels[u.native?.state]||'상태 확인 필요'));
            const info=make('details');info.append(make('summary','상세 정보'),make('pre',JSON.stringify({client_id:u.client_id,flow_id:u.flow_id,state:u.state,collection_state:u.native?.state,error:u.error},null,2)));row.append(info);
            if(u.error)row.append(make('p','수집 중 오류가 발생했습니다.'));
            if(u.flow_id) {
                row.append(button('결과 보기',()=>sources(u,g)));
            }
            content.append(row);
        }
        if((job.units||[]).some(u=>u.flow_id))content.append(button('대화에서 분석',()=>{
            if(valid(g)) {
                if(ask(`작업 ${job.id}의 수집 결과를 분석해 주세요.`)===false) { status.textContent='작성 중인 메시지를 먼저 보내주세요.'; return; }
                close(false);root.querySelector('#aw-input')?.focus();
            }
        }));
    }
    async function refresh(g,force=false) {
        if(!valid(g)||loading||mutating)return;
        if(document.hidden&&!force){schedule(g);return;}
        if(force && !mutating)context.error=false;
        loading=true;
        try {
            const job=await api(`/api/vr/jobs/${encodeURIComponent(context.jobId)}`);
            if(!valid(g))return;
            if(job.id!==context.jobId)throw Error('작업을 불러오지 못했습니다.');
            // Avoid replacing buttons/focus and expanded details on unchanged polling responses.
            if(!context.error)status.textContent='';
            const signature=JSON.stringify(job);
            if(signature!==context.signature){context.signature=signature;render(job,g);}
        }catch(e){showError(e,g);}finally{if(valid(g)){loading=false;schedule(g);}}
    }
    async function sources(u,g) {
        const rg=++resultGeneration; results.replaceChildren(make('p','불러오는 중…'));
        try {
            const q=new URLSearchParams({client_id:u.client_id,flow_id:u.flow_id,kind:'logs',size:'1'});
            const metadata=await api('/api/vr/results?'+q);
            const flow=metadata.flow||{};
            if(metadata.client_id!==u.client_id||metadata.flow_id!==u.flow_id)throw Error('결과를 불러오지 못했습니다.');
            if(!valid(g)||rg!==resultGeneration)return;
            results.replaceChildren(make('h3','수집 결과'));
            const info=make('details');info.append(make('summary','수집 정보'),make('pre',JSON.stringify({client_id:u.client_id,flow_id:u.flow_id,state:flow.state},null,2)));results.append(info);
            const names=flow.artifacts_with_results||[];
            if(!names.length)results.append(make('p','표시할 결과가 없습니다.'));
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
            if(data.client_id!==u.client_id||data.flow_id!==u.flow_id||data.artifact!==artifact)throw Error('결과를 불러오지 못했습니다.');
            results.replaceChildren(make('h3',artifact||'수집 로그'));
            const info=make('details');info.append(make('summary','수집 정보'),make('pre',JSON.stringify({client_id:u.client_id,flow_id:u.flow_id,state:data.flow?.state},null,2)));results.append(info);
            const micro=value=>Number.isFinite(Number(value))&&Number(value)>0?new Date(Number(value)/1000).toISOString():'미확인';
            results.append(make('p',`수집 시작: ${micro(data.flow?.start_time)} / 마지막 활동: ${micro(data.flow?.active_time)} (UTC)`));
            results.append(make('p',`${data.items?.length ? offset+1 : 0}–${offset+(data.items?.length||0)}행${data.has_more?' · 다음 페이지 있음':''}`));
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
            if(!/^VR-[A-F0-9]{16}$/.test(jobId)||currentSession()!==sessionId)throw Error('검토 화면을 열지 못했습니다.');
            close(false);focusBefore=document.activeElement;const g=++generation;
            context={jobId,sessionId,proposalId,canApprove:false,signature:null};
            panel.hidden=false;
            try {panel.showModal();} catch(e) {close();throw e;}
            status.textContent='불러오는 중…';content.replaceChildren();results.replaceChildren();closeButton.focus();
            // Opening performs reads only. Draft creation happened in the owned review endpoint.
            try {const auth=await api('/api/auth/me');if(valid(g))context.canApprove=['admin','approver'].includes(auth.user?.role);}
            catch(e){showError(e,g);}
            if(valid(g)){status.textContent='';await refresh(g,true);}
        }
    };
};
