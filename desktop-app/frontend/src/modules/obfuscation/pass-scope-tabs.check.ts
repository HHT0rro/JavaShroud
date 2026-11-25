import { resolveActivePassScopeTabId, resolvePassScopeTabIdForKey } from './pass-scope-tabs.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
}

const passIds = ['rename-classes', 'method-virtualization', 'string-encryption'] as const

assert(resolveActivePassScopeTabId(passIds, null) === 'rename-classes', 'expected first enabled pass to become active')
assert(resolveActivePassScopeTabId(passIds, 'method-virtualization') === 'method-virtualization', 'expected existing enabled active pass to stay selected')
assert(resolveActivePassScopeTabId(passIds, 'removed-pass') === 'rename-classes', 'expected removed active pass to fall back to first enabled pass')
assert(resolveActivePassScopeTabId([], 'method-virtualization') === null, 'expected no active tab without enabled passes')
assert(resolvePassScopeTabIdForKey(passIds, 'method-virtualization', 'ArrowRight') === 'string-encryption', 'expected ArrowRight to select the next tab')
assert(resolvePassScopeTabIdForKey(passIds, 'string-encryption', 'ArrowRight') === 'rename-classes', 'expected ArrowRight to wrap')
assert(resolvePassScopeTabIdForKey(passIds, 'rename-classes', 'ArrowLeft') === 'string-encryption', 'expected ArrowLeft to wrap')
assert(resolvePassScopeTabIdForKey(passIds, 'method-virtualization', 'Home') === 'rename-classes', 'expected Home to select the first tab')
assert(resolvePassScopeTabIdForKey(passIds, 'method-virtualization', 'End') === 'string-encryption', 'expected End to select the last tab')
assert(resolvePassScopeTabIdForKey(passIds, 'method-virtualization', 'Enter') === null, 'expected native button activation keys to remain native')

console.log('pass-scope-tabs checks passed')
