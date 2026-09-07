import { createInitialRunState } from './state'
import { getReadinessIssue, runIsBusy, runStatusLabel } from './workbench-view'

const equal = (actual: unknown, expected: unknown): void => {
  if (actual !== expected) throw new Error(`Expected ${String(expected)}, received ${String(actual)}`)
}
const initial = createInitialRunState()
equal(getReadinessIssue(initial, 'en')?.message, 'Waiting for engine capabilities')
const loaded = { ...initial, schema: { schemaVersion: '2', engineVersion: 'check', tags: [], modules: [], compatibility: [], orderingConstraints: [], defaultPipeline: [] } }
equal(getReadinessIssue(loaded, 'en')?.message, 'Choose an input JAR')
const input = { ...loaded, inputJar: { fileName: 'app.jar', inputJarPath: 'C:\\app.jar', sizeLabel: 'System file', detectedMainClass: null } }
equal(getReadinessIssue(input, 'en')?.message, 'Set the output JAR path')
equal(getReadinessIssue({ ...input, outputJarPath: 'C:\\out.jar' }, 'en')?.page, 'passes')
equal(runStatusLabel('ready', 'en', 'canceled'), 'Canceled')
equal(runStatusLabel('running', 'en', 'canceled'), 'Running')
equal(runStatusLabel('failed', 'zh'), '发生错误')
equal(runIsBusy('canceling'), true)
equal(runIsBusy('done'), false)
console.log('workbench view checks passed')
