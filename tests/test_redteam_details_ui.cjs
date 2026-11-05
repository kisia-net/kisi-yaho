// Controlled renderer inputs only; not a real operational scan or Wazuh alert.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { checkDetailsHtml, toolRows, toolResults, overall } = require('../static/redteam.js');
const deep = require('../static/redteam_deep_scan.js');
const check = (assertion, status, reason_ko = '한국어 이유') => ({ assertion, status, reason_ko });

test('shows checks separately from one saved analysis and excludes N/A from passes', () => {
    const tool = { mode: 'saved_result', status: 'passed', stats: { successes: 1, failures: 0, errors: 0 },
        checks: [check('HumanApproval', 'passed'), check('LogInstructionCanary', 'not_applicable')] };
    const html = toolRows(toolResults({ tool_results: { promptfoo: tool } }));
    assert.match(html, /분석 결과 통과 1건/);
    assert.match(html, /검사 항목 2개 · 통과 1 · 해당 없음 1/);
    assert.match(html, /모델 재호출 없음/);
});

test('failures are immediately visible and passing checks are folded below', () => {
    const html = checkDetailsHtml({ checks: [check('PassOne', 'passed'), check('FailedOne', 'failed')] });
    assert.ok(html.indexOf('FailedOne') < html.indexOf('PassOne'));
    assert.ok(html.indexOf('FailedOne') < html.indexOf('<details class="rt-check-all">'));
    assert.match(html, /나머지 검사별 상세 결과 1개 보기/);
});

test('keeps scenario identity for repeated failed metrics', () => {
    const html = checkDetailsHtml({ checks: [
        { ...check('HumanApproval', 'failed'), case_index: 2, category: 'direct-prompt-injection' },
        { ...check('HumanApproval', 'failed'), case_index: 5, category: 'excessive-agency' },
    ] });
    assert.match(html, /사례 2 · 직접 프롬프트 주입/);
    assert.match(html, /사례 5 · 권한·승인 우회/);
    assert.equal((html.match(/<code>HumanApproval<\/code>/g) || []).length, 2);
});

test('all interpolated reasons names and context escape HTML', () => {
    const attack = '<img src=x onerror=alert(1)>';
    const html = checkDetailsHtml({ checks: [{ ...check(attack, 'failed', attack), reason: attack,
        description_ko: attack, name_ko: attack, case_name: attack, case_index: 1, detector: attack }] });
    assert.ok(!html.includes(attack));
    assert.match(html, /&lt;img/);
    assert.match(html, /기록된 이유 원문/);
});

test('shows check purpose separately from the verdict reason', () => {
    const html = checkDetailsHtml({ checks: [{...check('HumanApproval', 'passed', '기록된 판정 이유'),
        description_ko: '조치의 승인 요건을 확인합니다.'}] });
    assert.match(html, /검사 내용:<\/strong> 조치의 승인 요건을 확인합니다/);
    assert.match(html, /판정 이유:<\/strong> 기록된 판정 이유/);
    assert.ok(html.indexOf('검사 내용:') < html.indexOf('판정 이유:'));
});

test('older server without purpose fields is labeled rather than guessed', () => {
    const html = checkDetailsHtml({checks:[check('UnknownMetric', 'passed')]});
    assert.match(html, /검사 설명이 아직 제공되지 않았습니다/);
    assert.match(html, /판정 이유:/);
});

test('unavailable details do not imply a pass and incomplete output is labeled', () => {
    assert.match(checkDetailsHtml({ detail_availability: 'report_unreadable' }), /권한·형식/);
    assert.match(checkDetailsHtml({}), /통과를 뜻하지 않습니다/);
    assert.match(checkDetailsHtml({ checks: [check('X', 'passed')], details_truncated: true }), /일부 표시/);
});

test('diagnostic warnings and unknown verification are not merged into failures', () => {
    const html = checkDetailsHtml({ checks: [check('A', 'warning'), check('B', 'not_verified'), check('C', 'not_available')] });
    assert.match(html, /검토 경고 1 · 검증 불가 1 · 결과 없음 1/);
    assert.ok(!html.includes('통과 3'));
});

test('runtime errors outrank failures and completed is not automatically passed', () => {
    const tools = toolResults({ tool_results: { promptfoo: { status: 'completed', stats: { successes: 0, failures: 1, errors: 1 } } } });
    assert.equal(tools[0].state, 'error');
    assert.equal(overall(tools)[0], '검사 오류');
    assert.equal(overall(toolResults({ tool_results: { promptfoo: { status: 'completed' } } })), null);
});

test('deep scan includes separate Promptfoo and garak explanation sections', () => {
    const html = deep.checkDetailsHtml({ tools: { promptfoo: { checks: [check('HumanApproval', 'failed')] },
        garak: { checks: [check('promptinject.HijackLongPrompt', 'passed', '검출기 집계만 표시')] } } });
    assert.match(html, /promptfoo 검사별 판정·이유/);
    assert.match(html, /garak 검사별 판정·이유/);
    assert.match(html, /검출기 집계만 표시/);
});

test('prototype property names and unknown statuses are not treated as checks', () => {
    assert.match(checkDetailsHtml({ checks: [check('X', '__proto__'), check('Y', 'unknown')] }), /통과를 뜻하지 않습니다/);
});
