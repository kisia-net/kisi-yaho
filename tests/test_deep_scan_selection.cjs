// Isolated UI tests with controlled responses; no Wazuh or model is contacted.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {mount, alertOptions, selectedAlert, validAlertId} = require('../static/redteam_deep_scan.js');

function element() {
    return {value:'',dataset:{},checked:false,disabled:false,hidden:false,textContent:'',children:[],listeners:{},
        addEventListener(name, fn){this.listeners[name]=fn;}, replaceChildren(){this.children=[];},
        appendChild(node){this.children.push(node);}, focus(){this.focused=true;}};
}
const json = (body, status=200) => ({ok:status>=200&&status<300,status,json:async()=>body});
const evidence = (id='wazuh-test-1', description='ModSecurity rejected a query') => ({id,
    timestamp:'2026-10-15T01:00:00Z',agent:{name:'web-test'},rule:{id:'31333',level:7,description}});
const flush = () => new Promise(setImmediate);

function setup(handler, dataset={}) {
    const elements={};
    for (const name of ['alert','start','refresh','notice','result','meta','summary','tools','details','probes','checks',
        'picker','load-alerts','range','query','verify','review','ack','run','cancel','selected','selection-note','ready','review-target','list-note']) {
        elements[name]=element();
    }
    elements.range.value='24h';
    const calls=[];
    const root={dataset:{csrf:'csrf-test',...dataset},querySelector(selector){return elements[selector.match(/data-scan-([^\]]+)/)[1]];}};
    const api=mount(root,{fetch:async(url,options)=>{
        calls.push({url,options});
        return handler ? handler(url,options) : url.endsWith('/evidence') ? json(evidence(decodeURIComponent(url.split('/')[3]))) : json({error:'No result'},404);
    },schedule(){},document:{createElement:element}});
    return {api,elements,calls};
}

test('dashboard initially has no implicit target and cannot submit a model request', async()=>{
    const {api,elements,calls}=setup();
    await flush();
    assert.equal(elements.start.disabled,true);
    await api.submit();
    assert.ok(calls.every(call=>!call.options.method));
    assert.match(elements.notice.textContent,/실제 경보/);
});

test('alert-detail page inherits its exact ID and only fetches evidence and status', async()=>{
    const {elements,calls}=setup(null,{alertId:'wazuh-test-1'});
    await flush();
    assert.equal(elements.alert.value,'wazuh-test-1');
    assert.match(elements.selected.textContent,/ModSecurity/);
    assert.match(elements.selected.textContent,/web-test/);
    assert.match(elements.selected.textContent,/2026-10-15/);
    assert.equal(elements.start.disabled,false);
    assert.ok(calls.some(call=>call.url==='/api/alerts/wazuh-test-1/evidence'));
    assert.ok(calls.every(call=>!call.options.method && !call.url.endsWith('/analyze')));
});

test('loading real alert options does not auto-select the first or start an evaluation', async()=>{
    const {api,elements,calls}=setup((url)=>url.startsWith('/api/alerts?') ? json({source:'wazuh_indexer',alerts:[
        {id:'wazuh-test-1',title:'HTTP 404',host:'web-test',time:'2026-10-15'}]}) : json({},404));
    await flush(); await api.loadAlerts();
    assert.equal(elements.picker.children.length,2);
    assert.equal(elements.picker.value,'');
    assert.equal(elements.start.disabled,true);
    assert.ok(calls.every(call=>!call.options.method));
});

test('fixture lists and fixture-looking IDs are rejected without substitution', ()=>{
    assert.throws(()=>alertOptions({source:'fixture_repository',alerts:[{id:'wazuh-test-1'}]}),/테스트용/);
    assert.equal(validAlertId('evt-1234567890abcdef'),false);
    assert.deepEqual(alertOptions({source:'wazuh_indexer',alerts:[{id:'evt-1234567890abcdef'},{id:'../../oops'}]}),[]);
});

test('empty or failed list explains next steps instead of inserting examples', async()=>{
    const {api,elements}=setup((url)=>url.startsWith('/api/alerts?') ? json({source:'wazuh_indexer',alerts:[]}) : json({},404));
    await flush(); await api.loadAlerts();
    assert.match(elements['list-note'].textContent,/기간을 넓히거나/);
    assert.equal(elements.picker.disabled,true);
    assert.equal(elements.start.disabled,true);
});

test('search encodes query and limits period to supported server options', async()=>{
    const {api,elements,calls}=setup((url)=>url.startsWith('/api/alerts?') ? json({source:'wazuh_indexer',alerts:[]}) : json({},404));
    await flush(); elements.query.value='ip:10.0.0.1 & title:404'; elements.range.value='unsafe-period';
    await api.loadAlerts();
    const call=calls.find(call=>call.url.startsWith('/api/alerts?'));
    const url=new URL(call.url,'http://example.invalid');
    assert.equal(url.searchParams.get('q'),elements.query.value);
    assert.equal(url.searchParams.get('range'),'24h');
});

test('native evidence ID mismatch or authentication failure keeps execution disabled', async()=>{
    for (const reply of [json(evidence('wrong-id')),json({error:'Authentication required.'},401),json({error:'Native Wazuh only'},409)]) {
        const {api,elements,calls}=setup(url=>url.endsWith('/evidence') ? reply : json({},404));
        await flush(); assert.equal(await api.selectAlert('wazuh-test-1'),false);
        assert.equal(elements.start.disabled,true);
        assert.match(elements['selection-note'].textContent,/테스트용 데이터로 대체하지/);
        assert.ok(calls.every(call=>!call.options.method));
    }
    assert.throws(()=>selectedAlert({},'wazuh-test-1'),/일치하지/);
});

test('review and cancel do not POST; final action needs explicit model-call acknowledgement', async()=>{
    const {api,elements,calls}=setup();
    await flush(); await api.selectAlert('wazuh-test-1');
    assert.equal(api.review(),true);
    assert.equal(elements.review.hidden,false);
    assert.equal(elements.run.disabled,true);
    await api.submit();
    assert.ok(calls.every(call=>!call.options.method));
    api.closeReview();
    assert.equal(elements.review.hidden,true);
    assert.equal(elements.ack.checked,false);
    assert.ok(calls.every(call=>!call.options.method));
});

test('a reviewed acknowledged target submits exactly once with existing CSRF and fixed tools', async()=>{
    let resolvePost;
    const pending=new Promise(resolve=>{resolvePost=resolve;});
    const {api,elements,calls}=setup((url,options)=>options.method==='POST' ? pending :
        url.endsWith('/evidence') ? json(evidence()) : json({},404));
    await flush(); await api.selectAlert('wazuh-test-1'); api.review();
    elements.ack.checked=true; elements.ack.listeners.change();
    assert.equal(elements.run.disabled,false);
    const first=api.submit(); await api.submit();
    const posts=calls.filter(call=>call.options.method==='POST');
    assert.equal(posts.length,1);
    assert.deepEqual(JSON.parse(posts[0].options.body),{alert_id:'wazuh-test-1',tools:['promptfoo','garak']});
    assert.equal(posts[0].options.headers['X-CSRF-Token'],'csrf-test');
    assert.equal(posts[0].options.headers.Authorization,undefined);
    resolvePost(json({scan_id:'a'.repeat(24),alert_id:'wazuh-test-1',status:'queued',tools:{}},202));
    await first;
    assert.equal(elements.start.disabled,true);
    assert.equal(elements.run.disabled,true);
});

test('editing the ID invalidates a reviewed target and acknowledgement', async()=>{
    const {api,elements,calls}=setup();
    await flush(); await api.selectAlert('wazuh-test-1'); api.review(); elements.ack.checked=true;
    elements.alert.value='wazuh-test-2'; elements.alert.listeners.input();
    await api.submit();
    assert.equal(elements.start.disabled,true);
    assert.equal(elements.review.hidden,true);
    assert.equal(elements.ack.checked,false);
    assert.ok(calls.every(call=>!call.options.method));
});

test('late evidence from an earlier selection cannot replace the latest target', async()=>{
    let resolveFirst;
    const first=new Promise(resolve=>{resolveFirst=resolve;});
    const {api,elements}=setup(url=>url.includes('/wazuh-test-1/evidence') ? first :
        url.endsWith('/evidence') ? json(evidence('wazuh-test-2','Latest selection')) : json({},404));
    await flush();
    const previous=api.selectAlert('wazuh-test-1');
    await api.selectAlert('wazuh-test-2');
    resolveFirst(json(evidence('wazuh-test-1','Old selection'))); await previous;
    assert.match(elements.selected.textContent,/Latest selection/);
    assert.ok(!elements.selected.textContent.includes('Old selection'));
    assert.equal(elements.alert.value,'wazuh-test-2');
});

test('untrusted titles and host values are text-only, not HTML', async()=>{
    const marker='<img src=x onerror=alert(1)>';
    const {api,elements}=setup(url=>url.endsWith('/evidence') ? json({...evidence('wazuh-test-1',marker),agent:{name:marker}}) : json({},404));
    await flush(); await api.selectAlert('wazuh-test-1'); api.review();
    assert.ok(elements.selected.textContent.includes(marker));
    assert.equal(elements.selected.innerHTML,undefined);
    assert.ok(elements['review-target'].textContent.includes(marker));
    assert.equal(elements['review-target'].innerHTML,undefined);
});

test('an old result for another target is explicitly distinguished after selection', async()=>{
    const {api,elements}=setup(url=>url.endsWith('/evidence') ? json(evidence()) :
        json({scan_id:'b'.repeat(24),alert_id:'another-alert',status:'completed',tools:{}}));
    await flush(); await api.selectAlert('wazuh-test-1');
    assert.match(elements.notice.textContent,/다른 경보의 기존 검사 결과/);
});

test('blank dropdown clears the confirmed target rather than retaining a hidden selection', async()=>{
    const {api,elements}=setup();
    await flush(); await api.selectAlert('wazuh-test-1');
    elements.picker.value=''; elements.picker.listeners.change();
    assert.equal(elements.alert.value,'');
    assert.equal(elements.start.disabled,true);
});
