import type { TargetKind } from './types.ts'

export interface PassSelectionTarget {
  readonly target: string
  readonly kind: TargetKind
}

/**
 * Parses an engine-issued canonical pass-selection selector. Pass scopes deliberately
 * accept only concrete class selectors or complete JVM method selectors; package,
 * field, glob, and descriptor-pattern rules remain global-rule concepts.
 */
export const parsePassSelectionTarget = (rawTarget: string): PassSelectionTarget | null => {
  const target = rawTarget.trim()
  if (target.length === 0 || target.includes('*')) return null

  const hashIndex = target.indexOf('#')
  if (hashIndex < 0) {
    return isConcreteInternalClassName(target) ? { target, kind: 'class' } : null
  }
  if (hashIndex !== target.lastIndexOf('#')) return null

  const owner = target.slice(0, hashIndex)
  const memberWithDescriptor = target.slice(hashIndex + 1)
  const colonIndex = memberWithDescriptor.indexOf(':')
  if (!isConcreteInternalClassName(owner) || colonIndex <= 0 || colonIndex !== memberWithDescriptor.lastIndexOf(':')) {
    return null
  }

  const memberName = memberWithDescriptor.slice(0, colonIndex)
  const descriptor = memberWithDescriptor.slice(colonIndex + 1)
  if (!isConcreteMethodName(memberName) || !isJvmMethodDescriptor(descriptor)) return null
  if (!isCanonicalConstructorSelector(memberName, descriptor)) return null

  return { target, kind: 'method' }
}

const isConcreteInternalClassName = (value: string): boolean => {
  if (value.length === 0 || value.endsWith('/') || value.endsWith('.')) return false
  return value.split('/').every((segment): boolean => (
    segment.length > 0 && !/[\\.#:;[\]()*\s<>]/.test(segment)
  ))
}

const isConcreteMethodName = (value: string): boolean => {
  if (value === '<init>' || value === '<clinit>') return true
  return value.length > 0 && !/[#.:;[\]()/\s*<>]/.test(value)
}

/**
 * The method-descriptor grammar accepts more strings than the JVM permits for
 * special methods. Canonical selectors emitted by the inspection tree always
 * use `()V` for <clinit> and a void return for <init>; reject impossible
 * imported selectors so an apparently non-empty independent-scope rule
 * cannot silently match nothing.
 */
const isCanonicalConstructorSelector = (memberName: string, descriptor: string): boolean => (
  (memberName !== '<init>' || descriptor.endsWith('V')) &&
  (memberName !== '<clinit>' || descriptor === '()V')
)

const isJvmMethodDescriptor = (descriptor: string): boolean => {
  if (!descriptor.startsWith('(')) return false

  let index = 1
  while (index < descriptor.length && descriptor[index] !== ')') {
    const next = consumeJvmFieldDescriptor(descriptor, index)
    if (next === null) return false
    index = next
  }
  if (index >= descriptor.length || descriptor[index] !== ')') return false

  index += 1
  if (descriptor[index] === 'V') return index + 1 === descriptor.length

  const returnEnd = consumeJvmFieldDescriptor(descriptor, index)
  return returnEnd === descriptor.length
}

const consumeJvmFieldDescriptor = (descriptor: string, start: number): number | null => {
  let index = start
  while (descriptor[index] === '[') index += 1
  if (index >= descriptor.length) return null

  switch (descriptor[index]) {
    case 'B':
    case 'C':
    case 'D':
    case 'F':
    case 'I':
    case 'J':
    case 'S':
    case 'Z':
      return index + 1
    case 'L': {
      const end = descriptor.indexOf(';', index + 1)
      if (end < 0 || !isConcreteInternalClassName(descriptor.slice(index + 1, end))) return null
      return end + 1
    }
    default:
      return null
  }
}
