const {test} = require('node:test');
const assert = require('node:assert/strict');
const {active, toolRows, probeRows, mount} = require('../static/redteam_deep_scan.js');

test('completion is not a pass and denominators remain separate', () => {
    const rows = toolRows({status: 'completed', tools: {
        promptfoo: {status: 'failed', counts: {passed: 5, total: 6, hits: 1, errors: 0}},
        garak: {status: 'passed', counts: {passed: 4, total: 4, hits: 0}},
    }});
    assert.equal(rows[0].status, 'failed');
    assert.equal(rows[0].passRate, '83.3%');
    assert.equal(rows[1].passRate, '100.0%');
    assert.notEqual(rows[0].unit, rows[1].unit);
    assert.equal(rows[1].errors, 0);
});

test('empty and error-only results are not reported as zero-percent security failures', () => {
    assert.equal(toolRows({})[0].passRate, '미평가');
    assert.equal(toolRows({tools: {promptfoo: {status: 'error', counts: {total: 0, errors: 1, unscored: 1}}}})[0].passRate, '미평가');
    assert.equal(active({status: 'running'}), true);
    assert.equal(active({status: 'queued'}), true);
    assert.equal(active({status: 'completed'}), false);
});

test('partial real-response recovery is labeled and retains both failure and runtime reason', () => {
    const row = toolRows({tools:{promptfoo:{status:'error',counts:{passed:3,total:4,hits:1,errors:1,unscored:2},
        grading_source:'offline_replay_of_original_received_responses',
        error_summary:'Fifth request timed out',failure_summary:'GroundedCitations failed'}}})[0];
    assert.equal(row.unscored,2);
    assert.match(row.evaluation,/실제 수신 응답 부분 재채점/);
    assert.match(row.reason,/Fifth request timed out/);
    assert.match(row.reason,/GroundedCitations failed/);
});

test('identical failure and runtime reasons are not repeated', () => {
    const row = toolRows({tools:{garak:{error_summary:'Unavailable',failure_summary:'Unavailable'}}})[1];
    assert.equal(row.reason,'Unavailable');
});

test('restart subset is not described as a complete standard suite', async () => {
    const {elements}=setup(async()=>({ok:true,status:200,json:async()=>({
        status:'completed',validation_scope:'restart_subset',alert_id:'real-wazuh-1',tools:{},summary:'Actual restart subset'})}));
    await flush();
    assert.match(elements.notice.textContent,/부분 검증/);
    assert.match(elements.notice.textContent,/6종 전체 검사와 구분/);
});

function setup(fetch) {
    const elements = {};
    for (const key of ['alert', 'start', 'refresh', 'notice', 'result', 'meta', 'summary', 'tools', 'details', 'probes']) {
        elements[key] = {value: key === 'alert' ? 'real-wazuh-1' : '', textContent: '', hidden: false, disabled: false,
            addEventListener() {}, replaceChildren() {this.children = [];}, appendChild(item) {(this.children ||= []).push(item);}};
    }
    const root = {dataset: {csrf: 'local-csrf'}, querySelector(selector) {
        return elements[selector.match(/data-scan-([^\]]+)/)[1]];
    }};
    const api = mount(root, {fetch, schedule() {}, confirm: () => true, document: {createElement: () => ({textContent: ''})}});
    return {api, elements};
}
const noResult = () => Promise.resolve({ok: false, status: 404, json: async () => ({error: 'none'})});
const flush = () => new Promise(setImmediate);

test('security goal rate excludes errors and does not merge with quality failures', () => {
    const row = toolRows({tools: {promptfoo: {security_evaluation: {
        attack_attempted: 5, attack_evaluated: 4, attack_goal_hits: 1,
        counts: {quality_failure: 1, diagnostic_warning: 1},
    }}}})[0];
    assert.match(row.evaluation, /공격 목표 위반 1\/4 \(25.0%\)/);
    assert.match(row.evaluation, /커버리지 4\/5 \(80.0%\)/);
    assert.match(row.evaluation, /품질 실패 1/);
});

test('garak with malformed responses and no evaluations has no safety verdict', () => {
    const row = toolRows({tools: {garak: {evaluation_coverage: 'not_evaluated',
        response_audit: {received: 1, structured: 0}, process_exit_verified: false}}})[1];
    assert.equal(row.passRate, '미평가');
    assert.match(row.evaluation, /안전성 판정 불가/);
    assert.match(row.evaluation, /구조화 응답 0\/1/);
    assert.match(row.evaluation, /종료 코드 미확인/);
});

test('button posts fixed tools and CSRF then disables during an accepted scan', async () => {
    const calls = [];
    const {api, elements} = setup(async (url, options) => {
        calls.push({url, options});
        if (!options.method) return noResult();
        return {ok: true, status: 202, json: async () => ({scan_id: 'a'.repeat(24), alert_id: 'real-wazuh-1', status: 'queued', tools: {}})};
    });
    await flush(); await api.submit();
    const call = calls.find((item) => item.options.method === 'POST');
    assert.equal(call.url, '/api/redteam/scans');
    assert.equal(call.options.headers['X-CSRF-Token'], 'local-csrf');
    assert.equal(call.options.headers.Authorization, undefined);
    assert.deepEqual(JSON.parse(call.options.body), {alert_id: 'real-wazuh-1', tools: ['promptfoo', 'garak']});
    assert.equal(elements.start.disabled, true);
});

test('failed POST is never automatically replayed and requires GET confirmation', async () => {
    let posts = 0;
    const {api, elements} = setup(async (_, options) => {
        if (!options.method) return noResult();
        posts++; throw new Error('timeout after possible acceptance');
    });
    await flush(); await api.submit(); await api.submit();
    assert.equal(posts, 1);
    assert.equal(elements.start.disabled, true);
    await api.loadLatest();
    assert.equal(elements.start.disabled, false);
});

test('untrusted summaries use textContent and do not create injected HTML', async () => {
    const marker = '<img src=x onerror=alert(1)>';
    const {elements} = setup(async () => ({ok: true, status: 200, json: async () => ({
        scan_id: 'a'.repeat(24), alert_id: 'other-alert', status: 'completed', summary: marker, tools: {},
    })}));
    await flush();
    assert.equal(elements.summary.textContent, marker);
    assert.equal(elements.summary.innerHTML, undefined);
    assert.match(elements.notice.textContent, /다른 경보/);
});

test('probe details distinguish test cases, detector rows and unscored errors', () => {
    const rows = probeRows({probes: [
        {tool:'promptfoo',name:'identifier-resistance',passed:1,total:1,hits:0},
        {tool:'garak',name:'promptinject.HijackLongPrompt',detector:'promptinject.AttackRogueString',passed:1,total:1,hits:0},
        {tool:'garak',name:'not-scored',passed:0,total:0,hits:0,unscored:1,status:'error'},
    ]});
    assert.match(rows[0],/통과 1\/1 · 실패 검사 0/);
    assert.match(rows[1],/HijackLongPrompt \/ promptinject.AttackRogueString/);
    assert.match(rows[1],/detector 탐지 0/);
    assert.match(rows[2],/실행 오류 · 통과 0\/0/);
    assert.match(rows[2],/미평가 1/);
});

test('probe render is text-only and refresh replaces stale verdicts without POST', async () => {
    let passed=0;
    const calls=[];
    const marker='<img src=x onerror=alert(1)>';
    const {api,elements}=setup(async(url,options)=>{
        calls.push(options.method||'GET');
        return {ok:true,status:200,json:async()=>({alert_id:'real-wazuh-1',status:'completed',tools:{},
            probes:[{tool:'promptfoo',name:marker,passed,total:1,hits:1-passed}]})};
    });
    await flush();
    assert.match(elements.probes.children[0].textContent,/통과 0\/1/);
    passed=1;
    await api.loadLatest();
    assert.equal(elements.probes.children.length,1);
    assert.equal(elements.probes.children[0].innerHTML,undefined);
    assert.ok(elements.probes.children[0].textContent.includes(marker));
    assert.match(elements.probes.children[0].textContent,/통과 1\/1/);
    assert.deepEqual(calls,['GET','GET']);
});

test('no probe details explains absent evaluations without inventing passes', async () => {
    const {elements}=setup(async()=>({ok:true,status:200,json:async()=>({status:'completed',tools:{}})}));
    await flush();
    assert.equal(elements.details.hidden,false);
    assert.equal(elements.probes.children.length,1);
    assert.match(elements.probes.children[0].textContent,/세부 평가 결과가 없습니다/);
    assert.match(elements.probes.children[0].textContent,/통과 판정이 아닙니다/);
    assert.deepEqual(probeRows({probes:null}),[]);
});

test('selected historical scan is read without replacing latest or requesting a model', async () => {
    const calls=[];
    const elements={};
    for(const key of ['alert','start','refresh','notice','result','meta','summary','tools','details','probes']) {
        elements[key]={value:'',addEventListener(){},replaceChildren(){this.children=[];},appendChild(row){(this.children||=[]).push(row);}};
    }
    const root={dataset:{csrf:'test-csrf',scanId:'b'.repeat(24)},querySelector(selector){return elements[selector.match(/data-scan-([^\]]+)/)[1]];}};
    const api=mount(root,{fetch:async(url,options)=>{
        calls.push([url,options.method||'GET']);
        return {ok:true,status:200,json:async()=>({scan_id:'b'.repeat(24),status:'completed',tools:{}})};
    },schedule(){},confirm:()=>true,document:{createElement:()=>({})}});
    await flush(); await api.loadLatest();
    assert.deepEqual(calls,[['/api/redteam/scans/'+'b'.repeat(24),'GET'],['/api/redteam/scans/'+'b'.repeat(24),'GET']]);
});
