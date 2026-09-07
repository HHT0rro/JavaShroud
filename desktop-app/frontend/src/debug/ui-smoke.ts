export interface UiCheckResult {
  readonly status: 'idle' | 'running' | 'passed' | 'failed'
  readonly passed: readonly string[]
  readonly error?: string
}

interface UiSmokeHost {
  readonly setScenario: (id: string) => unknown
  readonly getEmittedEvents: () => readonly { readonly type: string; readonly message: string; readonly outPath: string | null }[]
  readonly onProgress?: (passed: readonly string[]) => void
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => {
  window.setTimeout(resolve, ms)
})

const visible = (element: Element | null): element is HTMLElement => {
  if (!(element instanceof HTMLElement)) {
    return false
  }
  const style = window.getComputedStyle(element)
  if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) {
    return false
  }
  return element.getClientRects().length > 0
}

const enabledControl = (element: HTMLElement): boolean => {
  if (element.hasAttribute('disabled') || element.getAttribute('aria-disabled') === 'true') {
    return false
  }
  const native = element as HTMLButtonElement
  if ('disabled' in native && native.disabled) {
    return false
  }
  return !element.closest('[disabled], .n-button--disabled, .n-checkbox--disabled')
}

const labelOf = (element: HTMLElement): string => [
  element.getAttribute('aria-label') ?? '',
  element.getAttribute('title') ?? '',
  element.textContent ?? '',
].join(' ')

const matchesLabel = (element: HTMLElement, candidates: readonly string[]): boolean => {
  const label = labelOf(element)
  return candidates.some((candidate) => label.includes(candidate))
}

const click = (element: HTMLElement): void => {
  if (!enabledControl(element)) {
    throw new Error(`refusing to click disabled control: ${labelOf(element).slice(0, 80)}`)
  }
  element.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }))
}

const setInputValue = (element: HTMLInputElement, value: string): void => {
  const prototype = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
  prototype?.set?.call(element, value)
  element.dispatchEvent(new Event('input', { bubbles: true }))
  element.dispatchEvent(new Event('change', { bubbles: true }))
}

const waitFor = async (predicate: () => boolean, message: string, timeoutMs = 8000): Promise<void> => {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (predicate()) {
      return
    }
    await sleep(40)
  }
  throw new Error(message)
}

const byTestId = (id: string): HTMLElement => {
  const element = document.querySelector(`[data-testid="${id}"]`)
  if (!(element instanceof HTMLElement) || !visible(element)) {
    throw new Error(`missing ${id}`)
  }
  return element
}

const page = (id: string): HTMLElement => {
  const element = document.querySelector(`[data-page="${id}"]`)
  if (!(element instanceof HTMLElement) || !visible(element)) {
    throw new Error(`page ${id} not visible`)
  }
  return element
}

const findLabeled = (root: ParentNode, selector: string, candidates: readonly string[]): HTMLElement | null => {
  const nodes = Array.from(root.querySelectorAll(selector))
  return nodes.find((node): node is HTMLElement => visible(node) && matchesLabel(node, candidates)) ?? null
}

const waitLabeled = async (
  root: () => ParentNode,
  selector: string,
  candidates: readonly string[],
  message: string,
  options: { enabled?: boolean; timeoutMs?: number } = {},
): Promise<HTMLElement> => {
  let found: HTMLElement | null = null
  await waitFor(() => {
    found = findLabeled(root(), selector, candidates)
    if (!found) {
      return false
    }
    return options.enabled === false ? true : enabledControl(found)
  }, message, options.timeoutMs ?? 8000)
  if (!found) {
    throw new Error(message)
  }
  return found
}

const textIncludes = (root: ParentNode, snippets: readonly string[]): boolean => {
  const text = root.textContent ?? ''
  return snippets.some((snippet) => text.includes(snippet))
}

const goHome = async (): Promise<void> => {
  click(byTestId('nav-home'))
  await waitFor(() => visible(document.querySelector('[data-page="home"]')), 'home page not visible')
}

export const runUiSmokeChecks = async (host: UiSmokeHost): Promise<UiCheckResult> => {
  if (!import.meta.env.DEV) {
    throw new Error('UI smoke checks are development-only')
  }

  const passed: string[] = []
  const note = (name: string): void => {
    passed.push(name)
    host.onProgress?.(passed)
  }

  await waitFor(() => Boolean(document.querySelector('[data-testid="nav-home"]')), 'workbench nav not ready')

  const navPages = [
    ['nav-home', 'home'],
    ['nav-passes', 'passes'],
    ['nav-classes', 'classes'],
    ['nav-logs', 'logs'],
    ['nav-about', 'about'],
  ] as const
  for (const [navId, pageId] of navPages) {
    click(byTestId(navId))
    await waitFor(() => visible(document.querySelector(`[data-page="${pageId}"]`)), `nav ${pageId} did not render`)
  }
  await goHome()
  note('nav-all-five')

  click(await waitLabeled(() => page('home'), 'button', ['浏览', 'Browse'], 'browse button not enabled'))
  await waitFor(() => {
    const input = document.getElementById('input-jar-path')
    return input instanceof HTMLInputElement && input.value.includes('.jar')
  }, 'browse did not fill input jar')
  await waitFor(() => textIncludes(page('home'), ['96 个类', '96 classes']), 'inspection did not show 96 classes', 10000)
  note('browse-inspect-96')

  const startButton = await waitLabeled(
    () => document,
    'button',
    ['开始混淆', 'Start run'],
    'start button never became enabled (output/status still blocking canStart)',
    { timeoutMs: 12000 },
  )
  if (document.querySelector('.result-path') && visible(document.querySelector('.result-path'))) {
    throw new Error('output path must not appear before done')
  }
  click(startButton)
  const cancelButton = await waitLabeled(
    () => document,
    'button',
    ['取消任务', 'Cancel run'],
    'start did not switch to enabled cancel control',
  )
  click(cancelButton)
  await waitFor(() => textIncludes(document.body, ['已取消', 'Canceled', '任务已取消', 'Run canceled']), 'cancel did not render canceled outcome', 10000)
  await goHome()
  if (visible(document.querySelector('.result-path'))) {
    throw new Error('output path must not appear after cancel')
  }
  note('start-cancel-in-progress')

  host.setScenario('done')
  click(await waitLabeled(() => document, 'button', ['开始混淆', 'Start run'], 'start not enabled for done scenario'))
  await waitFor(() => host.getEmittedEvents().some((event) => event.type === 'done'), 'done event not emitted', 10000)
  await goHome()
  await waitFor(() => {
    const path = document.querySelector('[data-page="home"] .result-path')
    return visible(path) && (path?.textContent ?? '').includes('.jar')
  }, 'done run did not show output path on home', 8000)
  note('complete-shows-output-path')

  host.setScenario('error')
  click(await waitLabeled(() => document, 'button', ['开始混淆', 'Start run'], 'start not enabled for error scenario'))
  await waitFor(() => host.getEmittedEvents().some((event) => event.type === 'error'), 'error event not emitted', 10000)
  await goHome()
  await waitFor(() => textIncludes(page('home'), ['任务未完成', 'Task not completed', '模拟失败']), 'error scenario did not render failure on home', 8000)
  note('error-scenario')

  click(await waitLabeled(() => document, 'button', ['导入', 'Import'], 'import button not enabled'))
  await waitFor(() => {
    const input = document.getElementById('input-jar-path')
    return input instanceof HTMLInputElement && input.value.length > 0
  }, 'import did not restore input path')
  click(await waitLabeled(() => document, 'button', ['导出', 'Export'], 'export button not enabled'))
  await waitFor(() => host.getEmittedEvents().some((event) => event.message.includes('已保存配置')), 'export did not emit save log', 8000)
  note('import-export')

  const inputSnapshot = (document.getElementById('input-jar-path') as HTMLInputElement | null)?.value ?? ''
  click(await waitLabeled(
    () => document,
    'button',
    ['最大化窗口', 'Maximize window', '还原窗口', 'Restore window'],
    'maximize control missing (aria-label)',
  ))
  await sleep(120)
  const inputAfterMax = (document.getElementById('input-jar-path') as HTMLInputElement | null)?.value ?? ''
  if (inputAfterMax !== inputSnapshot) {
    throw new Error('maximize reset config')
  }
  note('maximize-preserves-config')

  click(byTestId('nav-passes'))
  await waitFor(() => visible(document.querySelector('[data-page="passes"]')), 'pipeline page missing')
  const search = Array.from(page('passes').querySelectorAll('input')).find((input) => {
    const placeholder = input.getAttribute('placeholder') ?? ''
    return visible(input) && (placeholder.includes('Search') || placeholder.includes('搜索'))
  })
  if (!(search instanceof HTMLInputElement)) {
    throw new Error('pipeline search missing on passes page')
  }
  setInputValue(search, 'rename')
  await waitFor(() => {
    const rows = Array.from(page('passes').querySelectorAll('.pass-item')).filter((row) => visible(row))
    return rows.length >= 4 && rows.length < 15
  }, 'rename search did not leave a movable filtered set')
  const renameRow = Array.from(page('passes').querySelectorAll('.pass-item')).find((row) => (
    visible(row) && textIncludes(row, ['Rename classes', 'Rename Classes', '重命名类'])
  ))
  if (!(renameRow instanceof HTMLElement)) {
    throw new Error('rename-classes row missing after search')
  }
  click(renameRow)
  const enable = findLabeled(page('passes'), 'button, [role="checkbox"], .n-switch, .n-checkbox', [
    'Enable Rename classes',
    'Disable Rename classes',
    'Enable Rename Classes',
    'Disable Rename Classes',
    '启用 重命名类',
    '停用 重命名类',
    '启用当前模块',
    '停用当前模块',
  ])
  if (!(enable instanceof HTMLElement) || !enabledControl(enable)) {
    throw new Error('pipeline enable/disable control not enabled')
  }
  click(enable)
  const selectedBefore = page('passes').querySelector('.pass-item.selected')
  const moveDown = await waitLabeled(() => page('passes'), 'button', ['下移', 'Move down'], 'move down never enabled in filtered rename set')
  click(moveDown)
  await sleep(80)
  const selectedAfter = page('passes').querySelector('.pass-item.selected')
  if (!(selectedAfter instanceof HTMLElement) || selectedAfter.textContent !== selectedBefore?.textContent) {
    throw new Error('pipeline selection was not preserved after move')
  }
  note('pipeline-search-toggle-reorder')

  click(byTestId('nav-classes'))
  await waitFor(() => visible(document.querySelector('[data-page="classes"]')), 'scope page missing')
  const globalTab = page('classes').querySelector('#class-tree-scope-global')
  if (!(globalTab instanceof HTMLElement) || !visible(globalTab)) {
    throw new Error('global scope tab missing')
  }
  click(globalTab)
  await waitFor(() => Boolean(page('classes').querySelector('[role="tree"]')), 'class tree missing on classes page')
  const actionButtons = Array.from(page('classes').querySelectorAll('[role="treeitem"] button')).filter((button) => (
    visible(button)
    && enabledControl(button)
    && !matchesLabel(button, ['Expand', 'Collapse', '展开', '折叠'])
  ))
  if (actionButtons.length === 0) {
    throw new Error('no enabled class-tree exclude action on visible tree')
  }
  click(actionButtons[actionButtons.length - 1] as HTMLElement)
  await waitFor(() => textIncludes(page('classes'), ['· 1']), 'global exclude count did not become 1')
  const passTab = Array.from(page('classes').querySelectorAll('[id^="class-tree-scope-"]')).find((tab) => (
    visible(tab) && tab.id !== 'class-tree-scope-global'
  ))
  if (!(passTab instanceof HTMLElement)) {
    throw new Error('pass scope tab missing on classes page')
  }
  click(passTab)
  click(await waitLabeled(() => page('classes'), 'button', ['使用独立范围', 'Use independent scope'], 'independent scope button not enabled'))
  await waitFor(() => textIncludes(page('classes'), ['Independent scope does not inherit', '独立范围不继承']), 'independent default did not render')
  if (textIncludes(page('classes'), ['live-inherits the global baseline', '当前实时继承全局排除基线'])) {
    throw new Error('independent scope still showing inherit copy')
  }
  note('scope-exclude-then-independent')

  return { status: 'passed', passed }
}
