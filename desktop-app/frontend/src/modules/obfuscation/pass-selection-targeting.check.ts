import { parsePassSelectionTarget } from './pass-selection-targeting.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
}

for (const target of [
  'sample/Target',
  'sample/Target#value:()I',
  'sample/Target#find:(Ljava/lang/String;[I)[Ljava/lang/String;',
  'sample/Target#<init>:()V',
]) {
  assert(parsePassSelectionTarget(target) !== null, `expected canonical selector: ${target}`)
}

for (const target of [
  '',
  '*',
  'sample/*',
  'sample.*',
  'sample/*/Target',
  'sample/Target#field:I',
  'sample/Target#value',
  'sample/Target#*:()V',
  'sample/Target#value:(*)V',
  'sample/Target#value:()Q',
  'sample/Target#value:(V)V',
  'sample/Target#<init>:()I',
  'sample/Target#<clinit>:(I)V',
  'sample//Target',
]) {
  assert(parsePassSelectionTarget(target) === null, `expected invalid pass selector: ${target}`)
}

assert(parsePassSelectionTarget(' sample/Target#value:()I ')?.target === 'sample/Target#value:()I', 'expected target trimming')
assert(parsePassSelectionTarget('sample/Target')?.kind === 'class', 'expected class kind')
assert(parsePassSelectionTarget('sample/Target#value:()I')?.kind === 'method', 'expected method kind')

console.log('pass-selection-targeting checks passed')
