import type { RunState } from './types'

interface MessageApi {
  readonly error: (message: string) => void
  readonly success: (message: string) => void
}

export const emitStateError = (messageApi: MessageApi, state: RunState, fallbackMessage: string): void => {
  messageApi.error(state.errorMessage ?? fallbackMessage)
}

export const emitSuccess = (messageApi: MessageApi, message: string): void => {
  messageApi.success(message)
}
