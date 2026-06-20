/**
 * Standalone regression test for the frontend reorderByConstraints logic.
 * Verifies deterministic topological sort with original-order tie-breaking.
 *
 * Run: node desktop-app/frontend/test-reorder-constraints.mjs
 * Exit code 0 = all tests passed, non-zero = failure.
 */

const assert = {
  ok(condition, message) {
    if (!condition) throw new Error(`Assertion failed: ${message}`);
  },
  deepEqual(actual, expected, message) {
    const a = JSON.stringify(actual);
    const e = JSON.stringify(expected);
    if (a !== e) throw new Error(`${message}\n  expected: ${e}\n  actual:   ${a}`);
  },
};

/**
 * Deterministic topological sort matching state.ts reorderByConstraints.
 */
function reorderByConstraints(passes, constraints) {
  const passIds = passes.map((p) => p.id);
  const passIdSet = new Set(passIds);
  const originalIndex = new Map(passIds.map((id, i) => [id, i]));

  const relevant = constraints.filter(
    (c) => passIdSet.has(c.before) && passIdSet.has(c.after),
  );

  const adjacency = new Map();
  const inDegree = new Map();
  for (const id of passIds) {
    adjacency.set(id, []);
    inDegree.set(id, 0);
  }
  for (const c of relevant) {
    adjacency.get(c.before).push(c.after);
    inDegree.set(c.after, (inDegree.get(c.after) ?? 0) + 1);
  }

  const zeroQueue = [];
  for (const [id, degree] of inDegree) {
    if (degree === 0) zeroQueue.push(id);
  }
  zeroQueue.sort((a, b) => (originalIndex.get(a) ?? 0) - (originalIndex.get(b) ?? 0));

  const sorted = [];
  while (zeroQueue.length > 0) {
    const current = zeroQueue.shift();
    sorted.push(current);
    for (const neighbor of adjacency.get(current) ?? []) {
      const newDegree = (inDegree.get(neighbor) ?? 1) - 1;
      inDegree.set(neighbor, newDegree);
      if (newDegree === 0) {
        const insertIdx = zeroQueue.findIndex(
          (id) => (originalIndex.get(id) ?? 0) > (originalIndex.get(neighbor) ?? 0),
        );
        if (insertIdx === -1) {
          zeroQueue.push(neighbor);
        } else {
          zeroQueue.splice(insertIdx, 0, neighbor);
        }
      }
    }
  }

  if (sorted.length < passIds.length) {
    return passes;
  }

  const passMap = new Map(passes.map((p) => [p.id, p]));
  return sorted.map((id) => passMap.get(id));
}

function makePass(id) {
  return { id, name: id, description: '', tagIds: [], category: '', enabled: true, params: {}, paramSchemas: [], stability: 'stable', risk: 'low', requiresOptIn: false };
}

// Test runner
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${e.message}`);
  }
}

console.log('Frontend reorderByConstraints regression tests\n');

// 1. Renaming before virtualization (user selected virtualization first)
test('rename before virtualization even when user selected virtualization first', () => {
  const passes = ['method-virtualization', 'rename-packages', 'rename-classes', 'rename-methods'].map(makePass);
  const constraints = [
    { before: 'rename-classes', after: 'method-virtualization', reason: '', hard: true },
    { before: 'rename-packages', after: 'method-virtualization', reason: '', hard: true },
    { before: 'rename-methods', after: 'method-virtualization', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  assert.ok(result[0].id === 'rename-packages' || result.indexOf(result.find(p => p.id === 'rename-packages')) < result.indexOf(result.find(p => p.id === 'method-virtualization')), 'rename-packages before method-virtualization');
  const ids = result.map(p => p.id);
  assert.ok(ids.indexOf('rename-classes') < ids.indexOf('method-virtualization'), 'rename-classes before method-virtualization');
  assert.ok(ids.indexOf('rename-methods') < ids.indexOf('method-virtualization'), 'rename-methods before method-virtualization');
  assert.ok(ids.indexOf('rename-packages') < ids.indexOf('method-virtualization'), 'rename-packages before method-virtualization');
});

// 2. Renaming before loader
test('rename before loader', () => {
  const passes = ['class-encryption-loader', 'rename-classes', 'rename-packages'].map(makePass);
  const constraints = [
    { before: 'rename-classes', after: 'class-encryption-loader', reason: '', hard: true },
    { before: 'rename-packages', after: 'class-encryption-loader', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  const ids = result.map(p => p.id);
  assert.ok(ids.indexOf('rename-classes') < ids.indexOf('class-encryption-loader'), 'rename-classes before loader');
  assert.ok(ids.indexOf('rename-packages') < ids.indexOf('class-encryption-loader'), 'rename-packages before loader');
});

// 4. Unconstrained passes preserve original order
test('unconstrained passes preserve original order', () => {
  const passes = ['obfuscate-int-constants', 'inject-junk-code', 'apply-reference-proxy'].map(makePass);
  const result = reorderByConstraints(passes, []);
  assert.deepEqual(result.map(p => p.id), ['obfuscate-int-constants', 'inject-junk-code', 'apply-reference-proxy']);
});

// 5. Empty pass list
test('empty pass list', () => {
  const result = reorderByConstraints([], []);
  assert.deepEqual(result, []);
});

// 6. Single pass
test('single pass', () => {
  const result = reorderByConstraints([makePass('rename-classes')], []);
  assert.deepEqual(result.map(p => p.id), ['rename-classes']);
});

// 7. Cycle falls back to original order
test('cycle falls back to original order', () => {
  const passes = ['a', 'b', 'c'].map(makePass);
  const constraints = [
    { before: 'a', after: 'b', reason: '', hard: true },
    { before: 'b', after: 'c', reason: '', hard: true },
    { before: 'c', after: 'a', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  assert.deepEqual(result.map(p => p.id), ['a', 'b', 'c']);
});

// 8. Deterministic: same input produces same output
test('deterministic output for same input', () => {
  const passes = ['method-virtualization', 'rename-classes', 'rename-methods', 'rename-packages', 'callsite-rotation-protection'].map(makePass);
  const constraints = [
    { before: 'rename-classes', after: 'method-virtualization', reason: '', hard: true },
    { before: 'rename-methods', after: 'method-virtualization', reason: '', hard: true },
    { before: 'rename-classes', after: 'callsite-rotation-protection', reason: '', hard: true },
  ];
  const r1 = reorderByConstraints(passes, constraints);
  const r2 = reorderByConstraints(passes, constraints);
  const r3 = reorderByConstraints(passes, constraints);
  assert.deepEqual(r1.map(p => p.id), r2.map(p => p.id), 'deterministic r1 vs r2');
  assert.deepEqual(r2.map(p => p.id), r3.map(p => p.id), 'deterministic r2 vs r3');
});

// 9. Metadata stripping before loader
test('metadata stripping before loader', () => {
  const passes = ['class-encryption-loader', 'strip-source-debug', 'strip-line-numbers'].map(makePass);
  const constraints = [
    { before: 'strip-source-debug', after: 'class-encryption-loader', reason: '', hard: true },
    { before: 'strip-line-numbers', after: 'class-encryption-loader', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  const ids = result.map(p => p.id);
  assert.ok(ids.indexOf('strip-source-debug') < ids.indexOf('class-encryption-loader'), 'strip-source before loader');
  assert.ok(ids.indexOf('strip-line-numbers') < ids.indexOf('class-encryption-loader'), 'strip-line before loader');
});

// 10. Planner before loader and delayed decryption
// 11. Invoke dynamic before bootstrap table encryption
test('invoke-dynamic before bootstrap-table-encryption', () => {
  const passes = ['bootstrap-table-encryption', 'invoke-dynamic-indirection'].map(makePass);
  const constraints = [
    { before: 'invoke-dynamic-indirection', after: 'bootstrap-table-encryption', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  assert.deepEqual(result.map(p => p.id), ['invoke-dynamic-indirection', 'bootstrap-table-encryption']);
});

// 13. Native and runtime defense passes without constraints preserve order
test('native passes without constraints preserve order', () => {
  const passes = ['anti-instrumentation', 'anti-jvmti-agent', 'anti-dump-protection', 'anti-bytebuddy-transform'].map(makePass);
  const result = reorderByConstraints(passes, []);
  assert.deepEqual(result.map(p => p.id), ['anti-instrumentation', 'anti-jvmti-agent', 'anti-dump-protection', 'anti-bytebuddy-transform']);
});

// 14. 2-node chain
test('2-node chain reorders correctly', () => {
  const passes = ['b', 'a'].map(makePass);
  const constraints = [{ before: 'a', after: 'b', reason: '', hard: true }];
  const result = reorderByConstraints(passes, constraints);
  assert.deepEqual(result.map(p => p.id), ['a', 'b']);
});

// 15. Diamond dependency (a->b, a->c, b->d, c->d)
test('diamond dependency resolves deterministically', () => {
  const passes = ['d', 'c', 'b', 'a'].map(makePass);
  const constraints = [
    { before: 'a', after: 'b', reason: '', hard: true },
    { before: 'a', after: 'c', reason: '', hard: true },
    { before: 'b', after: 'd', reason: '', hard: true },
    { before: 'c', after: 'd', reason: '', hard: true },
  ];
  const result = reorderByConstraints(passes, constraints);
  const ids = result.map(p => p.id);
  assert.ok(ids.indexOf('a') === 0, 'a is first');
  assert.ok(ids.indexOf('d') === 3, 'd is last');
  assert.ok(ids.indexOf('b') < ids.indexOf('d'), 'b before d');
  assert.ok(ids.indexOf('c') < ids.indexOf('d'), 'c before d');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
