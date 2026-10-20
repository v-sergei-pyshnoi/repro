const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hasGuard, ubuntuUpstreamVersion, hasKernelFix, classify, comparison } = require('./15005-diagnostics.cjs');

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

test('Ubuntu signature parsing uses upstream version rather than ABI suffix', () => {
  assert.equal(ubuntuUpstreamVersion('Ubuntu 7.0.0-1017.17-azure 7.0.14\n'), '7.0.14');
  assert.equal(ubuntuUpstreamVersion('Linux 7.0.0-1017-azure\nUbuntu 7.0.0-1017.17-azure 7.0.14\n'), '7.0.14');
  assert.equal(ubuntuUpstreamVersion('7.0.0-1017-azure'), null);
  assert.equal(ubuntuUpstreamVersion('Ubuntu 7.0.14'), null);
  assert.equal(ubuntuUpstreamVersion(undefined), null);
});

test('fixed kernel boundary is inclusive of 7.0.14', () => {
  for (const version of [null, '6.17.0', '6.19.0', '7.0.0', '7.0.13']) {
    assert.equal(hasKernelFix(version), false);
  }
  for (const version of ['7.0.14', '7.0.15', '7.1.0', '8.0.0']) {
    assert.equal(hasKernelFix(version), true);
  }
});

test('same-VM comparison requires matching fixed kernel signatures for false-rejection evidence', () => {
  const results = [
    { ...blocked, label: '8.3.13', upstreamVersion: '7.0.14' },
    { ...passed, label: '9.0.4', upstreamVersion: '7.0.14' },
  ];
  const verdict = comparison(results, '7.0.14');
  assert.match(verdict, /false rejection addressed by SERVER-131779/);
  assert.match(verdict, /not a single-patch A\/B test/);
  assert.match(comparison(results), /inconclusive/);
  assert.match(comparison(results, '7.0.13'), /inconclusive/);
  assert.match(comparison([
    results[0], { ...results[1], upstreamVersion: '7.0.15' },
  ], '7.0.14'), /inconclusive/);
});

test('same-VM comparison handles blocked, successful and incomplete controls', () => {
  assert.match(comparison([
    { ...blocked, label: '8.3.13' }, { ...blocked, label: '9.0.4' },
  ]), /version gate alone does not demonstrate/);
  assert.match(comparison([
    { ...passed, label: '8.3.13' }, { ...passed, label: '9.0.4' },
  ]), /not reproduced/);
  assert.match(comparison([]), /incomplete/);
  assert.match(comparison([
    { ...passed, label: '8.3.13', infrastructureError: true },
    { ...passed, label: '9.0.4' },
  ]), /incomplete/);
  assert.match(comparison([
    { ...blocked, label: '8.3.13' }, { ...passed, label: '9.0.4', collectionError: 'Missing inspect' },
  ]), /incomplete/);
});
