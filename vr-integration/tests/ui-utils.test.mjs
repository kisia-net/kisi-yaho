import test from 'node:test';
import assert from 'node:assert/strict';
import {escape,formatTime,pathOf,columns,printable} from '../static/vr-utils.js';

test('stored script content is escaped',()=>{
  const payload='<img src=x onerror="alert(1)">';
  assert.ok(!escape(payload).includes('<'));
  assert.ok(escape(payload).includes('&quot;'));
});
test('microsecond and ISO timestamps have the same displayed instant',()=>{
  assert.equal(formatTime(1790911556883730),formatTime(new Date(1790911556883).toISOString()));
  assert.equal(formatTime(0),'—');
  assert.equal(formatTime('not a date'),'—');
});
test('Linux ctime is presented separately from modification and never creation',()=>{
  const names=columns('Linux.Search.FileFinder',[]).map(c=>c[0]);
  assert.ok(names.includes('메타데이터 변경'));
  assert.ok(!names.includes('생성 시각'));
});
test('VFS nested path and complete nested records remain available',()=>{
  assert.equal(pathOf({_OSPath:{Components:['tmp','file']}}),'/tmp/file');
  assert.equal(printable({a:{b:'full'}}),'{"a":{"b":"full"}}');
});
