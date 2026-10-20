const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hasGuard, classify, comparison } = require('./15005-diagnostics.cjs');

const passed = {
  logs: '', elapsedMs: 90000, operations: 89,
  state: { Running: true }, restartCount: 0,
};
const blocked = {
  logs: '{"s":"F","id":12257600}', error: 'Container exited',
  elapsedMs: 0, operations: 0, state: { Running: false }, restartCount: 0,
};

test('only complete, running, restart-free observations pass', () => {
  assert.match(classify(passed), /^Passed/);
  for (const change of [
    { elapsedMs: 89999 }, { operations: 0 }, { state: { Running: false } },
    { restartCount: 1 }, { restartCount: null },
  ]) {
    assert.doesNotMatch(classify({ ...passed, ...change }), /^Passed/);
  }
});

test('a guard is not classified as an observed kernel crash', () => {
  assert.equal(hasGuard('2026-10-20 {"id": 12257600, "s":"F"}'), true);
  assert.equal(hasGuard('{"id":122576000}'), false);
  assert.match(classify(blocked), /actual kernel defect not established/);
  assert.match(classify({ ...passed, error: 'ECONNREFUSED' }), /not attributed to rseq/);
  assert.match(classify({ ...blocked, infrastructureError: true }), /inconclusive/);
  assert.match(classify({ ...blocked, collectionError: 'Logs unavailable' }), /inconclusive/);
});

test('same-VM comparison distinguishes the Ubuntu gate fix from the kernel defect', () => {
  assert.match(comparison([
    { ...blocked, label: '8.3.13' }, { ...passed, label: '8.3.14' },
  ]), /SERVER-131779/);
  assert.match(comparison([
    { ...blocked, label: '8.3.13' }, { ...blocked, label: '8.3.14' },
  ]), /version gate alone does not demonstrate/);
  assert.match(comparison([
    { ...passed, label: '8.3.13' }, { ...passed, label: '8.3.14' },
  ]), /not reproduced/);
  assert.match(comparison([]), /incomplete/);
  assert.match(comparison([
    { ...passed, label: '8.3.13', infrastructureError: true },
    { ...passed, label: '8.3.14' },
  ]), /incomplete/);
});
