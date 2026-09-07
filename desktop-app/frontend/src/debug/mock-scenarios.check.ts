import {
  MOCK_SCENARIO_IDS,
  parseMockScenarioId,
  resolveMockScenario,
} from './mock-scenarios.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

assert(parseMockScenarioId('error') === 'error', 'expected error scenario id')
assert(parseMockScenarioId('unknown') === 'default', 'expected unknown scenario to fall back')

const empty = resolveMockScenario('empty')
assert(empty.inspection.classCount === 0, 'expected empty inspection')
assert(empty.inputJarPath === '', 'expected empty input path')

const done = resolveMockScenario('done')
assert(done.runSteps.some((step) => step.type === 'done'), 'expected done outcome')

const error = resolveMockScenario('error')
assert(error.runSteps.some((step) => step.type === 'error'), 'expected error outcome')

const canceled = resolveMockScenario('canceled')
assert(canceled.runSteps.some((step) => step.type === 'canceled'), 'expected canceled outcome')

const longPaths = resolveMockScenario('long-paths')
assert(longPaths.inputJarPath.length > 120, 'expected long input path')
assert(/^C:\\debug\\/.test(longPaths.inputJarPath), 'expected a single Windows drive root')
assert(!longPaths.inputJarPath.slice(2).includes('C:\\'), 'expected no extra drive roots in long path')

const largeTree = resolveMockScenario('large-tree')
assert(largeTree.inspection.classCount >= 80, 'expected large class tree')

const stream = resolveMockScenario('stream')
assert(stream.runSteps.length >= 20, 'expected stream log volume')

const fullCatalog = resolveMockScenario('full-catalog')
assert(fullCatalog.schema.modules.length >= 12, 'expected representative module volume')
assert(fullCatalog.schema.modules.some((moduleDefinition) => moduleDefinition.params.length >= 4), 'expected modules with real param volume')
assert(fullCatalog.inspection.classCount >= 80, 'expected full-catalog to reuse large tree stress')

assert(MOCK_SCENARIO_IDS.includes('default'), 'expected default scenario registry')
assert(resolveMockScenario('default').schema.schemaVersion === '2', 'expected current schema version')

console.log('mock-scenarios checks passed')
