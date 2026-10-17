import {escape as esc, formatTime, valueAt, printable, pathOf, bytes, badge, columns} from "./vr-utils.js";

const root=document.getElementById("vr-workspace");
const $=id=>document.getElementById(id);
const apiRoot="/api/vr";
const mode=root.dataset.mode;
const state={clients:[],client:null,catalog:[],tab:mode==="files"?"recent":"overview",epoch:0,clientEpoch:0,rows:[],rowContext:null,review:null,canApprove:false,ready:false,clientOffset:0,clientMore:false,busy:false};
const tabs=mode==="files"?[["recent","최근 수정"],["search","파일 검색"],["browse","파일 탐색"],["hunts","헌트"],["flows","수집 기록"],["jobs","수집 요청"]]:[["overview","개요"],["processes","프로세스"],["network","네트워크"],["persistence","지속성"],["accounts","계정·로그인"],["evidence","증거"],["flows","수집 기록"],["jobs","작업 이력"]];
const requestedTab=new URL(location.href).searchParams.get("tab");
if(tabs.some(([id])=>id===requestedTab))state.tab=requestedTab;
const current=epoch=>epoch===state.epoch;
const empty=text=>`<div class="vr-empty">${esc(text)}</div>`;
const button=(label,action,extra="")=>`<button type="button" class="vr-button" data-action="${action}" ${extra}>${esc(label)}</button>`;

async function request(path, options={}) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),30000);
  try {
    const response=await fetch(path.startsWith("/api/")?path:apiRoot+path,{
      credentials:"same-origin",cache:"no-store",...options,signal:controller.signal,
      headers:{"Accept":"application/json",...(options.body?{"Content-Type":"application/json","X-CSRF-Token":root.dataset.csrf}:{}),...options.headers},
    });
    if (response.status===401) {
      location.href="/login?next="+encodeURIComponent(location.pathname+location.search);
      throw new Error("로그인이 필요합니다.");
    }
    const type=response.headers.get("content-type") || "";
    if (!type.includes("application/json")) throw new Error("서버 응답을 확인할 수 없습니다.");
    const data=await response.json();
    if (!response.ok) {const messages={400:"입력값을 확인해 주세요.",403:"이 작업을 수행할 권한이 없습니다.",404:"해당 항목을 찾을 수 없습니다.",409:"현재 상태에서 처리할 수 없습니다. 새로고침해 주세요.",429:"잠시 후 다시 시도해 주세요."};throw new Error(messages[response.status] || "요청을 처리하지 못했습니다. 다시 시도해 주세요.");}
    return data;
  } catch(error) {
    if (error.name==="AbortError") throw new Error("응답 시간이 초과되었습니다.");
    throw error;
  } finally { clearTimeout(timer); }
}
const post=(path,data={})=>request(path,{method:"POST",body:JSON.stringify(data)});
function error(text) {
  $("vr-error").textContent=text; $("vr-error").hidden=!text;
  if(text && $("vr-detail").open){
    let note=$("vr-detail-error");
    if(!note){note=document.createElement("p");note.id="vr-detail-error";note.className="vr-error-text";$("vr-detail-content").prepend(note);}
    note.textContent=text;
  }
}
function showDetail(title,html) { $("vr-detail-title").textContent=title; $("vr-detail-content").innerHTML=html; if (!$("vr-detail").open) $("vr-detail").showModal(); }
function keyValues(values) { return `<dl class="vr-key-values">${values.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(printable(v))}</dd>`).join("")}</dl>`; }
function pager(data,action) {
  const offset=data.offset || 0, size=data.page_size || 50;
  return `<div class="vr-pager"><span>${data.items.length ? `${offset+1}–${offset+data.items.length}행` : "0행"}${data.has_more?" · 다음 결과 있음":""}</span>${button("이전",action,`data-offset="${Math.max(0,offset-size)}" ${offset?"":"disabled"}`)}${button("다음",action,`data-offset="${offset+size}" ${data.has_more?"":"disabled"}`)}</div>`;
}
function renderClients() {
  $("vr-client-list").innerHTML=state.clients.map(c=>`<button type="button" class="vr-client" data-client="${esc(c.client_id)}" aria-current="${c.client_id===state.client?.client_id}"><strong>${esc(c.hostname || c.client_id)}</strong><code>${esc(c.client_id)}</code><small>${esc(c.os || "OS 미확인")} · ${esc(formatTime(c.last_seen_at))}</small></button>`).join("") || empty("검색 결과가 없습니다.");
  $("vr-client-count").textContent=state.clients.length+"개"+(state.clientMore?"+":"");
  $("vr-clients-more").hidden=!state.clientMore;
}
async function loadClients(append=false) {
  const token=++state.clientEpoch;
  const offset=append?state.clientOffset+50:0;
  const data=await request("/clients?"+new URLSearchParams({search:$("vr-search-input").value,offset}));
  if (token!==state.clientEpoch) return;
  state.clients=append?[...state.clients,...data.items]:data.items;
  state.clientOffset=offset; state.clientMore=data.has_more;
  if (state.client) {
    const refreshed=state.clients.find(c=>c.client_id===state.client.client_id);
    if (refreshed) state.client=refreshed;
  }
  renderClients();
  if (!state.client && state.clients.length) {
    const wanted=new URL(location.href).searchParams.get("client_id");
    selectClient(state.clients.find(c=>c.client_id===wanted) || state.clients[0]);
  } else if (state.client) renderHost();
}
function renderHost() {
  const c=state.client;
  $("vr-host-name").textContent=c?.hostname || "호스트를 선택하세요";
  $("vr-host-id").textContent=c?.client_id || "";
  $("vr-host-facts").innerHTML=c?`${esc(c.os || "OS 미확인")} ${esc(c.release || "")}<br>최근 체크인 ${esc(formatTime(c.last_seen_at))}`:"";
}
function selectClient(c) {
  state.client=c; renderClients(); renderHost();
  const url=new URL(location.href); url.searchParams.set("client_id",c.client_id);history.replaceState(null,"",url);
  loadTab();
}
function renderTabs() {
  $("vr-tabs").innerHTML=tabs.map(([id,label])=>`<button type="button" class="vr-tab" data-tab="${id}" aria-current="${state.tab===id}">${label}</button>`).join("");
}
async function loadCatalog() {
  const data=await request("/catalog");
  state.catalog=data.items;state.canApprove=data.can_approve;state.ready=data.worker.ready;
  $("vr-connection").textContent=state.ready?"수집 서비스 연결됨":"수집 서비스 연결 안 됨";
  $("vr-new").disabled=!state.catalog.length;
}
async function loadTab(offset=0) {
  const epoch=++state.epoch;
  renderTabs(); error("");
  const content=$("vr-content"); content.innerHTML=empty("불러오는 중…");
  if (!state.client && !["hunts","jobs","search"].includes(state.tab)) {content.innerHTML=empty("호스트를 선택하세요.");return;}
  try {
    if (state.tab==="jobs") return await jobs(epoch,offset);
    if (state.tab==="hunts") return await hunts(epoch,offset);
    if (state.tab==="flows") return await flowList(epoch,offset);
    if (state.tab==="browse") return await browse(epoch,"/",offset);
    if (state.tab==="search") return renderSearch();
    if (state.tab==="overview") return await overview(epoch);
    const group={recent:["files"],processes:["processes"],network:["network"],persistence:["services","cron","keys"],accounts:["users","logins"],evidence:["acquire"]}[state.tab];
    return await snapshots(epoch,group);
  } catch(e) { if (current(epoch)) {content.innerHTML=empty("조회하지 못했습니다.");error(e.message);} }
}
function operationButtons(ids) {return `<div class="vr-buttons">${ids.map(id=>button((state.catalog.find(o=>o.id===id)?.label || id)+" 수집","compose",`data-op="${id}"`)).join("")}</div>`;}
function renderSearch() {
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>파일 조사</h3></div><div class="vr-cards">${state.catalog.filter(o=>o.area==="files").map(o=>`<article class="vr-card"><h3>${esc(o.label)}</h3><span class="vr-muted">${esc(o.artifacts.join(", "))}</span>${button("수집 설정","compose",`data-op="${o.id}" ${o.available?"":"disabled"}`)}</article>`).join("")}</div>`;
}
async function overview(epoch) {
  const ids=["processes","network","services","cron","keys","users","logins","disk"];
  const results=await Promise.allSettled(ids.map(async id=>{
    const op=state.catalog.find(o=>o.id===id);
    const data=await request("/flows?"+new URLSearchParams({client_id:state.client.client_id,artifact:op.artifacts[0],size:1}));
    return {op,flow:data.items[0]};
  }));
  if (!current(epoch)) return;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>호스트 조사</h3>${operationButtons(["triage"])}</div><div class="vr-cards">${results.map((r,i)=>{
    if(r.status!=="fulfilled")return `<article class="vr-card"><h3>${esc(state.catalog.find(o=>o.id===ids[i])?.label || ids[i])}</h3><span class="vr-error-text">조회 실패</span></article>`;
    const {op,flow}=r.value;
    return `<article class="vr-card"><div class="vr-rowline"><h3>${esc(op.label)}</h3>${flow?badge(flow.state):""}</div><span class="vr-muted">${flow?`수집 ${esc(formatTime(flow.start_time || flow.create_time))}`:"기존 수집 없음"}</span>${flow?button("결과 보기","open-flow",`data-flow="${esc(flow.flow_id)}"`):button("수집","compose",`data-op="${op.id}"`)}</article>`;
  }).join("")}</div>`;
}
async function snapshots(epoch,ids) {
  const requested=ids.flatMap(id=>state.catalog.find(o=>o.id===id)?.artifacts || []);
  const batches=await Promise.allSettled(requested.map(artifact=>request("/flows?"+new URLSearchParams({client_id:state.client.client_id,artifact,size:5}))));
  if (!current(epoch)) return;
  const records=[]; const seen=new Set();
  for (const b of batches) if (b.status==="fulfilled") for (const f of b.value.items) if (!seen.has(f.flow_id)){seen.add(f.flow_id);records.push(f);}
  records.sort((a,b)=>Number(b.create_time)-Number(a.create_time));
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>${esc(tabs.find(x=>x[0]===state.tab)?.[1])}</h3>${operationButtons(ids)}</div>${batches.some(b=>b.status==="rejected")?'<p class="vr-error-text">일부 수집 목록을 조회하지 못했습니다.</p>':""}<div id="vr-evidence-view"></div>`;
  if (!records.length){$("vr-evidence-view").innerHTML=empty(batches.some(b=>b.status==="rejected")?"조회를 다시 시도하세요.":"기존 수집이 없습니다.");return;}
  if(state.tab==="recent" && records.length>1){
    const controls=document.createElement("div");controls.className="vr-toolbar";
    controls.innerHTML=`<label>비교 기준<select id="vr-baseline">${records.slice(1).map(f=>`<option value="${esc(f.flow_id)}">${esc(formatTime(f.create_time))} · ${esc(f.flow_id)}</option>`).join("")}</select></label>${button("최신 수집과 비교","compare",`data-new="${esc(records[0].flow_id)}"`)}`;
    $("vr-evidence-view").before(controls);
  }
  await evidence(records,epoch,state.tab==="recent"?"mtime":"");
}
async function flowList(epoch,offset) {
  const data=await request("/flows?"+new URLSearchParams({client_id:state.client.client_id,offset}));
  if (!current(epoch)) return;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>수집 기록</h3>${button("새 수집","compose")}</div>${flowTable(data.items)}${pager(data,"tab-page")}`;
}
function flowTable(flows) {
  if(!flows.length)return empty("수집 기록이 없습니다.");
  return `<div class="vr-table-wrap"><table class="vr-table"><thead><tr><th>수집</th><th>상태</th><th>요청 시각</th><th>결과 행</th><th></th></tr></thead><tbody>${flows.map(f=>`<tr><td><strong>${esc((f.request?.artifacts || f.artifacts || []).join(", "))}</strong><small>${esc(f.flow_id || f.FlowId || "")}</small></td><td>${badge(f.state)}</td><td>${esc(formatTime(f.create_time))}</td><td>${esc(f.total_collected_rows ?? "—")}</td><td>${button("열기","open-flow",`data-flow="${esc(f.flow_id)}"`)}</td></tr>`).join("")}</tbody></table></div>`;
}
async function openFlow(flowId,clientId=state.client?.client_id) {
  if (!clientId || !flowId) return;
  const epoch=++state.epoch;
  if(clientId!==state.client?.client_id){
    const target=await request("/client?"+new URLSearchParams({client_id:clientId}));
    if(!current(epoch))return;
    state.client=target;renderHost();renderClients();
  }
  $("vr-content").innerHTML=`<div class="vr-toolbar">${button("목록으로","back")}<h3>${esc(flowId)}</h3></div><div id="vr-evidence-view">${empty("불러오는 중…")}</div>`;
  // Results/logs reads validate and return the exact flow, independent of pagination.
  const data=await request("/results?"+new URLSearchParams({client_id:clientId,flow_id:flowId,kind:"logs",size:1}));
  if (!current(epoch)) return;
  await evidence([data.flow],epoch,"",clientId);
}
let evidenceState=null;
async function evidence(flows,epoch,order="",clientId=state.client.client_id) {
  evidenceState={flows,index:0,source:"",kind:"rows",offset:0,epoch,order,clientId};
  await evidencePage();
}
async function evidencePage() {
  const s=evidenceState;
  if (!s || !current(s.epoch)) return;
  const flow=s.flows[s.index];
  const sources=flow.artifacts_with_results || [];
  if (!sources.includes(s.source)) s.source=sources[0] || "";
  const target=$("vr-evidence-view");
  if (!target)return;
  target.innerHTML=`<div class="vr-toolbar"><label>수집<select id="vr-flow-select">${s.flows.map((f,i)=>`<option value="${i}" ${i===s.index?"selected":""}>${esc(formatTime(f.create_time))} · ${esc(f.flow_id)}</option>`).join("")}</select></label><div class="vr-buttons">${["rows","logs","uploads"].map((kind,i)=>button(["결과","로그","수집 파일"][i],"result-kind",`data-kind="${kind}" ${s.kind===kind?'disabled':""}`)).join("")}${button("상태 새로고침","refresh-evidence")}</div></div><div id="vr-flow-state" class="vr-rowline">${badge(flow.state)}<span class="vr-muted">수집 ${esc(formatTime(flow.start_time || flow.create_time))}</span></div>${flow.status?`<p class="vr-error-text">${esc(flow.status)}</p>`:""}<div class="vr-provenance">${esc(s.clientId)} · ${esc(flow.flow_id)}</div>${s.kind==="rows" && sources.length?`<div class="vr-toolbar"><label>결과 소스<select id="vr-source-select">${sources.map(a=>`<option ${a===s.source?"selected":""}>${esc(a)}</option>`).join("")}</select></label>${button("표시 결과 내보내기","export")}</div>`:""}<div id="vr-result-table">${empty("불러오는 중…")}</div><details><summary>수집 요청 정보</summary><pre>${esc(JSON.stringify(flow.request || {},null,2))}</pre></details>`;
  if (s.kind==="rows" && !s.source) {$("vr-result-table").innerHTML=empty("표시할 결과가 없습니다.");return;}
  const token=Symbol();s.token=token;
  const query=new URLSearchParams({client_id:s.clientId,flow_id:flow.flow_id,artifact:s.source,kind:s.kind,offset:s.offset});
  if (s.order && s.source==="Linux.Search.FileFinder" && s.kind==="rows")query.set("order",s.order);
  try {
    const data=await request("/results?"+query);
    if (!current(s.epoch) || s.token!==token || s!==evidenceState)return;
    state.rows=data.items;state.rowContext=data;
    s.flows[s.index]=data.flow;
    $("vr-flow-state").innerHTML=badge(data.flow.state)+`<span class="vr-muted">수집 ${esc(formatTime(data.flow.start_time || data.flow.create_time))}</span>`;
    $("vr-result-table").innerHTML=resultTable(data.items,s.kind==="rows"?s.source:"")+pager(data,"result-page");
  }catch(e){if(current(s.epoch)&&s.token===token){$("vr-result-table").innerHTML=empty("결과를 조회하지 못했습니다.");error(e.message);}}
}
function resultTable(rows,artifact) {
  if (!rows.length)return empty("이 조회에서 반환된 행이 없습니다.");
  const cols=columns(artifact,rows);
  return `<div class="vr-table-wrap"><table class="vr-table"><thead><tr>${cols.map(([k])=>`<th>${esc(k)}</th>`).join("")}<th></th></tr></thead><tbody>${rows.map((r,i)=>`<tr>${cols.map(([,get])=>`<td><span class="vr-truncate">${esc(printable(get(r)))}</span></td>`).join("")}<td>${button("상세","row",`data-row="${i}"`)}</td></tr>`).join("")}</tbody></table></div>`;
}
function rowDetail(index) {
  const row=state.rows[index];if(!row)return;
  const path=pathOf(row),ctx=state.rowContext;
  const file=path.startsWith("/") && /FileFinder|VFS\.|HashHunter|Yara.Glob/.test(ctx?.artifact || "");
  const modeValue=valueAt(row,["Mode.String","Mode"]);
  const isDir=row.IsDir===true || String(modeValue || "").startsWith("d");
  showDetail(path || "결과 상세",`${keyValues([["클라이언트",ctx?.client_id],["수집",ctx?.flow_id],["결과 소스",ctx?.artifact]])}${file?`<div class="vr-buttons vr-end">${button(isDir?"디렉터리 열기":"파일 증거 수집",isDir?"row-browse":"row-acquire",`data-row="${index}"`)}</div>`:""}<pre>${esc(JSON.stringify(row,null,2))}</pre>`);
}
async function browse(epoch,path="/",offset=0) {
  const clientId=state.client.client_id;
  $("vr-content").innerHTML=`<form id="vr-path-form" class="vr-toolbar"><label class="vr-grow">디렉터리<input id="vr-path" value="${esc(path)}"></label><div class="vr-buttons"><button type="submit" class="vr-button">목록 조회</button>${button("새 목록 수집","refresh-directory")}</div></form><div id="vr-directory-results">${empty("불러오는 중…")}</div>`;
  const data=await request("/directory?"+new URLSearchParams({client_id:clientId,path,offset}));
  if(!current(epoch))return;
  state.browsePath=path;
  if(data.uncached) {$("vr-directory-results").innerHTML=empty(data.search_incomplete?"최근 디렉터리 수집에서 이 경로를 찾지 못했습니다.":"이 경로의 저장된 디렉터리 수집이 없습니다.");return;}
  if(data.no_source){$("vr-directory-results").innerHTML=`${badge(data.flow.state)}${empty("목록이 아직 반환되지 않았습니다.")}`;return;}
  state.rows=data.items;state.rowContext=data;
  $("vr-directory-results").innerHTML=`<div class="vr-provenance">저장된 목록 · 수집 ${esc(formatTime(data.flow.start_time || data.flow.create_time))} · ${esc(data.flow_id)}</div>${badge(data.flow.state)}${resultTable(data.items,data.artifact)}${pager(data,"directory-page")}`;
}
async function hunts(epoch,offset) {
  const data=await request("/hunts?offset="+offset);
  if (!current(epoch))return;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>Velociraptor 헌트</h3>${button("새 헌트","new-hunt")}</div>${data.items.length?`<div class="vr-table-wrap"><table class="vr-table"><thead><tr><th>헌트</th><th>상태</th><th>생성</th><th>만료</th><th></th></tr></thead><tbody>${data.items.map(h=>`<tr><td>${esc(h.hunt_description || h.hunt_id)}<small>${esc(h.hunt_id)}</small></td><td>${badge(h.state)}</td><td>${esc(formatTime(h.create_time))}</td><td>${esc(formatTime(h.expires))}</td><td>${button("수집 보기","hunt-flows",`data-hunt="${esc(h.hunt_id)}"`)}</td></tr>`).join("")}</tbody></table></div>`:empty("등록된 헌트가 없습니다.")}${pager(data,"tab-page")}`;
}
async function huntFlows(hunt,offset=0) {
  const epoch=++state.epoch;
  state.hunt=hunt;
  const data=await request("/hunt-flows?"+new URLSearchParams({hunt_id:hunt,offset}));
  if(!current(epoch))return;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>${esc(hunt)}</h3>${button("헌트 목록","back")}</div>${data.items.length?`<div class="vr-table-wrap"><table class="vr-table"><thead><tr><th>클라이언트</th><th>수집</th><th>상태</th><th></th></tr></thead><tbody>${data.items.map(r=>{const c=r.ClientId || r.client_id,f=r.FlowId || r.flow_id || r.session_id;return `<tr><td>${esc(c)}</td><td>${esc(f)}</td><td>${badge(r.state || r.Context?.state || "")}</td><td>${button("열기","open-flow",`data-flow="${esc(f)}" data-cid="${esc(c)}"`)}</td></tr>`;}).join("")}</tbody></table></div>`:empty("이 헌트에 반환된 수집이 없습니다.")}${pager(data,"hunt-page")}`;
}
async function jobs(epoch,offset) {
  // Cross-host approvals remain visible; every row carries its exact targets.
  const data=await request("/jobs?offset="+offset);
  if(!current(epoch))return;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>수집 요청</h3>${button("새 수집","compose")}</div>${data.items.length?`<div class="vr-table-wrap"><table class="vr-table"><thead><tr><th>요청</th><th>대상</th><th>상태</th><th>요청 시각</th><th></th></tr></thead><tbody>${data.items.map(j=>`<tr><td>${esc(j.manifest.label)}<small>${esc(j.id)}${j.manifest.incident?" · "+esc(j.manifest.incident):""}</small></td><td>${esc(j.manifest.targets.map(c=>c.hostname || c.client_id).join(", "))}</td><td>${badge(j.state)}</td><td>${esc(formatTime(j.created))}</td><td>${button("상세","job",`data-job="${esc(j.id)}"`)}</td></tr>`).join("")}</tbody></table></div>`:empty("수집 요청이 없습니다.")}${pager(data,"tab-page")}`;
}
async function jobDetail(id) {
  const j=await request("/jobs/"+encodeURIComponent(id));
  state.detailJob=id;
  const m=j.manifest;
  const needsApproval=j.state==="pending_approval";
  showDetail(m.label,`${keyValues([["요청",j.id],["대상",m.targets.map(c=>`${c.hostname} · ${c.client_id}`).join("\n")],["사건",m.incident],["요청자",j.actor],["승인자",j.approver],["헌트",j.hunt_id],["요청 만료",formatTime(j.expires)],["시간 제한",`${m.limits.timeout}초 / 수집`],["전송 상한",`${bytes(m.limits.max_bytes)} / 수집`]])}<p class="vr-provenance">${badge(j.state)}</p><pre>${esc(JSON.stringify(m.params,null,2))}</pre>${state.canApprove?`<div class="vr-buttons">${needsApproval?button("승인","approve",`data-job="${esc(id)}"`)+button("반려","reject",`data-job="${esc(id)}"`):""}${["queued","active","submitted","submission_unknown"].includes(j.state)?button("남은 수집 취소","cancel-job",`data-job="${esc(id)}"`):""}${button("상태 새로고침","job",`data-job="${esc(id)}"`)}</div>`:""}<div class="vr-table-wrap"><table class="vr-table"><thead><tr><th>대상 / 수집 항목</th><th>상태</th><th>수집 ID</th><th></th></tr></thead><tbody>${j.units.map(u=>`<tr><td>${esc(u.artifact)}<small>${esc(u.client_id)}</small></td><td>${badge(u.native?.state || u.state)}${u.error?`<small>${esc(unitError(u.error))}</small>`:""}</td><td>${esc(u.flow_id || "—")}</td><td>${u.flow_id?button("결과","job-flow",`data-cid="${esc(u.client_id)}" data-flow="${esc(u.flow_id)}"`):""}</td></tr>`).join("")}</tbody></table></div><details><summary>작업 기록</summary><pre>${esc(JSON.stringify(j.events.map(e=>({시각:formatTime(e.time),행위:e.event,사용자:e.actor,상세:JSON.parse(e.detail)})),null,2))}</pre>`);
}
async function compareSnapshots(oldFlow,newFlow,offset=0){
  const epoch=++state.epoch;
  state.comparison={oldFlow,newFlow};
  const data=await request("/compare?"+new URLSearchParams({client_id:state.client.client_id,old_flow:oldFlow,new_flow:newFlow,offset}));
  if(!current(epoch))return;
  state.rows=data.items;state.rowContext=data;
  $("vr-content").innerHTML=`<div class="vr-toolbar"><h3>파일 목록 비교</h3>${button("수집으로 돌아가기","back")}</div><p class="vr-provenance">${esc(oldFlow)} → ${esc(newFlow)} · 변경 ${data.total_changes}개</p>${resultTable(data.items,"")}${pager(data,"compare-page")}`;
}
function unitError(code) { return ({preflight_failed:"수집 전 확인 실패",submission_unknown:"서버 접수 확인 필요",worker_interrupted:"서버 접수 확인 필요",hunt_submission_unknown:"헌트 생성 확인 필요",hunt_link_failed:"헌트 연결 실패",cancel_sent:"취소 요청 전송됨"})[code] || "처리 상태 확인 필요"; }
function openComposer(operation=mode==="files"?"files":"triage",prefill={},hunt=false) {
  if(!state.catalog.length){error("수집 항목을 불러오지 못했습니다.");return;}
  state.composeHunt=hunt;state.composeKey=crypto.randomUUID();
  $("vr-operation").innerHTML=state.catalog.map(o=>`<option value="${o.id}" ${o.id===operation?"selected":""} ${o.available?"":"disabled"}>${esc(o.label)}${o.available?"":" · 사용 불가"}</option>`).join("");
  const choices=[...state.clients];
  if(state.client && !choices.some(c=>c.client_id===state.client.client_id))choices.unshift(state.client);
  $("vr-targets").innerHTML=choices.map(c=>`<label><input type="checkbox" name="target" value="${esc(c.client_id)}" ${c.client_id===state.client?.client_id?"checked":""} ${String(c.os).toLowerCase()==="linux"?"":"disabled"}><span>${esc(c.hostname || c.client_id)} <small class="vr-muted">${esc(c.client_id)}</small></span></label>`).join("") || "호스트를 검색하세요.";
  $("vr-targets-note").textContent=state.clientMore?"호스트 목록에서 더 보기":"";
  $("vr-compose-title").textContent=hunt?"새 헌트":"새 수집";
  $("vr-compose-error").textContent="";
  fields(prefill);
  $("vr-compose").showModal();
}
function fields(prefill={}) {
  const op=state.catalog.find(o=>o.id===$("vr-operation").value);
  $("vr-fields").innerHTML=op.fields.map(f=>{
    const v=prefill[f.name] ?? f.default;
    const attrs=`id="vr-field-${f.name}" name="${f.name}" ${f.required?"required":""}`;
    const full=["path","rule","sha256"].includes(f.name)?"vr-field-full":"";
    if(f.kind==="boolean")return `<label class="${full}"><span><input ${attrs} type="checkbox" ${v?"checked":""}> ${esc(f.label)}</span></label>`;
    if(f.kind==="textarea")return `<label class="${full}">${esc(f.label)}<textarea ${attrs} rows="7" maxlength="16000">${esc(v)}</textarea></label>`;
    return `<label class="${full}">${esc(f.label)}<input ${attrs} type="${f.kind==="integer"?"number":f.kind==="datetime"?"datetime-local":"text"}" value="${esc(v)}" ${f.kind==="integer"?`min="${f.min}" max="${f.max}" step="1"`:""}></label>`;
  }).join("");
}
async function prepare(event) {
  event.preventDefault(); if(state.busy)return;state.busy=true;
  const submit=event.submitter;submit.disabled=true;
  try {
    const op=state.catalog.find(o=>o.id===$("vr-operation").value);
    const params={};
    for(const f of op.fields){const el=$("vr-field-"+f.name);params[f.name]=f.kind==="boolean"?el.checked:f.kind==="integer"?Number(el.value):f.kind==="datetime"&&el.value?new Date(el.value).toISOString():el.value;}
    const client_ids=[...$("vr-targets").querySelectorAll("input:checked")].map(x=>x.value);
    const result=await post("/preview",{operation:op.id,params,client_ids,incident:$("vr-incident").value,idempotency_key:state.composeKey,hunt:state.composeHunt});
    showProposalReview(result);
  }catch(e){$("vr-compose-error").textContent=e.message;}finally{state.busy=false;submit.disabled=false;}
}
function showProposalReview(result) {
    state.review=result;
    const m=result.manifest;
    $("vr-review-content").innerHTML=keyValues([["수집 항목",m.label],["대상",m.targets.map(c=>`${c.hostname} · ${c.client_id}`).join("\n")],["사건",m.incident],["수집 수",m.client_ids.length*Object.keys(m.spec).length],["시간 제한",`${m.limits.timeout}초 / 수집`],["파일 전송 상한",`${bytes(m.limits.max_bytes)} / 수집`],["승인",m.approval_required?"승인 필요":"분석가 실행"],["방식",m.hunt?"선택한 호스트에 헌트 실행":"호스트 수집"]])+`<pre>${esc(JSON.stringify(m.params,null,2))}</pre><details><summary>수집 아티팩트</summary><pre>${esc(Object.keys(m.spec).join("\n"))}</pre></details>`;
    $("vr-submit").textContent=m.approval_required?"승인 요청":"수집 시작";
    $("vr-review-error").textContent="";$("vr-compose").close();$("vr-review").showModal();
}
async function submitReview() {
  if(!state.review || state.busy)return;state.busy=true;$("vr-submit").disabled=true;
  try {
    const j=await post("/jobs/"+state.review.id+"/submit");
    $("vr-review").close();state.tab="jobs";await loadTab();await jobDetail(j.id);
  }catch(e){$("vr-review-error").textContent=e.message;}finally{state.busy=false;$("vr-submit").disabled=false;}
}
function exportRows() {
  if(!state.rowContext)return;
  const data={exported_at:new Date().toISOString(),...state.rowContext};
  const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`${data.flow_id}-rows-${data.offset || 0}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
root.addEventListener("click",async event=>{
  const c=event.target.closest("[data-client]");if(c){selectClient(state.clients.find(x=>x.client_id===c.dataset.client));return;}
  const tab=event.target.closest("[data-tab]");if(tab){state.tab=tab.dataset.tab;loadTab();return;}
  const close=event.target.closest("[data-close]");if(close){$(close.dataset.close).close();return;}
  const a=event.target.closest("[data-action]");if(!a)return;
  const d=a.dataset;
  try {
    if(d.action==="compose")openComposer(d.op);
    else if(d.action==="new-hunt")openComposer("files",{},true);
    else if(d.action==="tab-page")await loadTab(Number(d.offset));
    else if(d.action==="back")await loadTab();
    else if(d.action==="open-flow")await openFlow(d.flow,d.cid);
    else if(d.action==="job-flow"){$("vr-detail").close();await openFlow(d.flow,d.cid);}
    else if(d.action==="result-kind"){evidenceState.kind=d.kind;evidenceState.offset=0;await evidencePage();}
    else if(d.action==="refresh-evidence"){const s=evidenceState;const i=s.index;const data=await request("/results?"+new URLSearchParams({client_id:s.clientId,flow_id:s.flows[i].flow_id,kind:"logs",size:1}));if(s===evidenceState && current(s.epoch)){s.flows[i]=data.flow;await evidencePage();}}
    else if(d.action==="result-page"){evidenceState.offset=Number(d.offset);await evidencePage();}
    else if(d.action==="row")rowDetail(Number(d.row));
    else if(d.action==="export")exportRows();
    else if(d.action==="refresh-directory")openComposer("directory",{path:$("vr-path").value});
    else if(d.action==="directory-page")await browse(++state.epoch,state.browsePath,Number(d.offset));
    else if(d.action==="row-acquire"){$("vr-detail").close();openComposer("acquire",{path:pathOf(state.rows[Number(d.row)])});}
    else if(d.action==="row-browse"){$("vr-detail").close();state.tab="browse";renderTabs();await browse(++state.epoch,pathOf(state.rows[Number(d.row)]));}
    else if(d.action==="hunt-flows")await huntFlows(d.hunt);
    else if(d.action==="hunt-page")await huntFlows(state.hunt,Number(d.offset));
    else if(d.action==="job")await jobDetail(d.job);
    else if(d.action==="compare")await compareSnapshots($("vr-baseline").value,d.new);
    else if(d.action==="compare-page")await compareSnapshots(state.comparison.oldFlow,state.comparison.newFlow,Number(d.offset));
    else if(["approve","reject","cancel-job"].includes(d.action)){
      a.disabled=true;
      await post(`/jobs/${d.job}/${d.action==="cancel-job"?"cancel":"decision"}`,d.action==="cancel-job"?{}:{approve:d.action==="approve"});
      await jobDetail(d.job);
      if(state.tab==="jobs")await loadTab();
    }
  }catch(e){error(e.message);if(a.isConnected)a.disabled=false;}
});
root.addEventListener("change",e=>{
  if(e.target.id==="vr-operation")fields();
  if(e.target.id==="vr-flow-select"){evidenceState.index=Number(e.target.value);evidenceState.offset=0;evidencePage().catch(x=>error(x.message));}
  if(e.target.id==="vr-source-select"){evidenceState.source=e.target.value;evidenceState.offset=0;evidencePage().catch(x=>error(x.message));}
});
root.addEventListener("submit",e=>{if(e.target.id==="vr-path-form"){e.preventDefault();browse(++state.epoch,$("vr-path").value).catch(x=>error(x.message));}});
$("vr-compose-form").addEventListener("submit",prepare);
$("vr-submit").addEventListener("click",submitReview);
$("vr-new").addEventListener("click",()=>openComposer());
$("vr-client-search").addEventListener("submit",e=>{e.preventDefault();loadClients().catch(x=>error(x.message));});
$("vr-clients-more").addEventListener("click",()=>loadClients(true).catch(x=>error(x.message)));
$("vr-refresh").addEventListener("click",async()=>{try{await loadCatalog();await loadClients();await loadTab();}catch(e){error(e.message);}});
// Header: same controls and wording as the pages that load app.js.
const THEME_KEY="hawki-theme-v2";
function themeLabel(){const next=document.documentElement.dataset.theme==="dark"?"밝은":"어두운";const t=$("theme-toggle");if(!t)return;t.setAttribute("aria-label",`${next} 화면으로 전환`);t.title=`${next} 화면으로 전환`;}
$("theme-toggle")?.addEventListener("click",()=>{
  const theme=document.documentElement.dataset.theme==="light"?"dark":"light";
  document.documentElement.dataset.theme=theme;document.documentElement.style.colorScheme=theme;
  try{localStorage.setItem(THEME_KEY,theme);}catch{/* cookie fallback in base.html */}
  themeLabel();
});
themeLabel();
async function serviceHealth() {
  try {
    const data=await request("/api/status");
    let good=0,total=0;
    for(const [name,s] of Object.entries(data.services || {})){
      const configured=s.configured!==false;
      if(configured){total++;if(s.ok)good++;}
      document.querySelectorAll(`[data-service-dot="${CSS.escape(name)}"]`).forEach(el=>{el.className="status-dot "+(!configured?"unconfigured":s.ok?"online":"offline");});
    }
    if($("global-health-text"))$("global-health-text").textContent=`설정된 서비스 ${total}개 중 ${good}개 연결됨`;
  }catch{if($("global-health-text"))$("global-health-text").textContent="상태 확인 실패";}
}
$("refresh-services")?.addEventListener("click",serviceHealth);
const svg=paths=>`<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
const account=document.createElement("div");account.id="account-controls";account.className="account-controls";
account.innerHTML=`<a class="topbar-icon-button" href="/account" aria-label="계정" title="계정">${svg('<circle cx="12" cy="8" r="4"></circle><path d="M4.5 21a7.5 7.5 0 0 1 15 0"></path>')}</a><button id="logout-button" class="topbar-icon-button" type="button" aria-label="로그아웃" title="로그아웃">${svg('<path d="M10 5H5v14h5"></path><path d="M14 8l4 4-4 4"></path><path d="M18 12H9"></path>')}</button>`;
document.querySelector(".topbar-actions")?.prepend(account);
$("logout-button").addEventListener("click",async()=>{try{await post("/api/auth/logout");}finally{location.href="/login";}});
request("/api/auth/me").catch(()=>null).then(me=>{
  const user=me?.user;if(!user)return;
  const link=account.querySelector('a[href="/account"]');link.title=`계정: ${user.username} · ${user.role}`;link.setAttribute("aria-label",link.title);
  if(user.role==="admin")link.insertAdjacentHTML("afterend",`<a class="topbar-icon-button" href="/admin/users" aria-label="사용자 관리" title="사용자 관리">${svg('<circle cx="9" cy="8" r="3"></circle><path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path><path d="M17 8v6M14 11h6"></path>')}</a>`);
});
renderTabs();
await serviceHealth();
try {await loadCatalog();await loadClients();if(!state.client)await loadTab();}catch(e){error(e.message);$("vr-content").innerHTML=empty("연결을 확인한 뒤 새로고침하세요.");}
// Return destinations are constructed locally from bounded identifiers, never a supplied URL.
const agentParams = new URL(location.href).searchParams;
const agentSession = agentParams.get("agent_session");
const agentProposal = agentParams.get("agent_proposal");
if (/^[A-Za-z0-9_-]{1,128}$/.test(agentSession || "") && /^WP-[a-f0-9]{24}$/.test(agentProposal || "")) {
  const back = document.createElement("a"); back.className="vr-button"; back.textContent="조사 대화로 돌아가기";
  back.href="/agent?"+new URLSearchParams({session:agentSession});
  back.title=agentProposal; document.querySelector(".topbar-actions")?.prepend(back);
}
// An owned proposal handoff only opens an existing native review draft.
const proposalReview = new URL(location.href).searchParams.get("hawki_review");
if (proposalReview) {
  try {
    if (!/^VR-[A-F0-9]{16}$/.test(proposalReview)) throw new Error("잘못된 검토 식별자입니다.");
    const reviewed = await request("/jobs/" + encodeURIComponent(proposalReview));
    if (reviewed.state === "draft") showProposalReview(reviewed);
    else await jobDetail(reviewed.id);
  } catch (e) { error(e.message); }
}
// Poll only request status. Refreshing never creates endpoint work and does not
// reset result pagination, directory position, or a user's open review dialog.
setInterval(async()=>{
  if(document.hidden || $("vr-compose").open || $("vr-review").open || $("vr-detail").open || state.tab!=="jobs")return;
  try{await jobs(state.epoch,0);}catch{/* keep last displayed data */}
},15000);
