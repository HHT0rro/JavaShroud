package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCliAdapter

internal fun handleMainArgs(args: Array<String>): Unit {
    EngineCliAdapter().handle(args)
}
