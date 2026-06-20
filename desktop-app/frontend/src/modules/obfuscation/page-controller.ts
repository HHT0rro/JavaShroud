import { applyBridgeError } from './state'
import type { RunState } from './types'
import type { WailsBridge } from './wails-bridge'
import { loadEngineCapabilities, loadWindowMaximiseState } from './frontend-controller'

export const loadWorkbenchState = async (
  state: RunState,
  bridge: WailsBridge,
): Promise<{ readonly nextState: RunState; readonly isWindowMaximised: boolean | null }> => {
  const stateAfterCapabilities: RunState = await loadEngineCapabilities(state, bridge)

  try {
    return {
      nextState: stateAfterCapabilities,
      isWindowMaximised: await loadWindowMaximiseState(bridge),
    }
  } catch (error) {
    return {
      nextState: applyBridgeError(stateAfterCapabilities, error, '读取窗口状态失败'),
      isWindowMaximised: null,
    }
  }
}
