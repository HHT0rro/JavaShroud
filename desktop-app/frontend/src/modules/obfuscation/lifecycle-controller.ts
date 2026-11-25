import { OnFileDrop, OnFileDropOff } from '../../../wailsjs/runtime/runtime'
import type { WailsBridge } from './wails-bridge'

export interface FrontendLifecycleBindings {
  readonly unsubscribeEngineEvent: (() => void) | null
  readonly nativeFileDropActive: boolean
}

export const attachFrontendLifecycle = (
  bridge: WailsBridge,
  onEnginePayload: (payload: unknown) => void,
  onNativeFileDrop: (x: number, y: number, paths: string[]) => void,
): FrontendLifecycleBindings => ({
  unsubscribeEngineEvent: bridge.onEngineEvent(onEnginePayload),
  nativeFileDropActive: enableNativeFileDrop(onNativeFileDrop),
})

export const detachFrontendLifecycle = (bindings: FrontendLifecycleBindings): void => {
  if (bindings.nativeFileDropActive) {
    OnFileDropOff()
  }

  bindings.unsubscribeEngineEvent?.()
}

const enableNativeFileDrop = (onNativeFileDrop: (x: number, y: number, paths: string[]) => void): boolean => {
  OnFileDrop(onNativeFileDrop, false)
  return true
}
