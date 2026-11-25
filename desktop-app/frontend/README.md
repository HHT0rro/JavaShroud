# JavaShroud Workbench Frontend

Vue 3 + TypeScript + Vite frontend for the JavaShroud desktop workbench.

## Commands

From `desktop-app/frontend`:

```bash
corepack yarn install --immutable
corepack yarn dev
corepack yarn dev:mock
corepack yarn check
corepack yarn build
```

From the repository root (Windows-safe):

```bash
node desktop-app/frontend/run-frontend-checks.mjs
```

`corepack yarn check` (or the root `node` command) runs the explicit parser/state checks, then discovers every `src/**/*.check.ts`, then `test-reorder-constraints.mjs`.

Named subsets:

```bash
corepack yarn check:capabilities
corepack yarn check:events
corepack yarn check:pass-selections
corepack yarn check:class-tree-view
corepack yarn check:config
corepack yarn check:input-flow
corepack yarn check:state-dependencies
corepack yarn check:reorder
corepack yarn check:mock-scenarios
```

## Browser mock (development only)

`yarn dev` serves production `index.html` / `src/main.ts` and requires Wails `window.go`.

`yarn dev:mock` is the explicit debug page:

```bash
corepack yarn dev:mock
```

It starts Vite with `vite.mock.config.ts` on port **5174** and opens `/debug.html`, which loads `src/browser-debug.ts`. That entry throws if `import.meta.env.DEV` is false, so it is not a production `window.go` fallback.

URL: `http://localhost:5174/debug.html`

Deterministic query scenarios:

- `?scenario=default`
- `?scenario=empty`
- `?scenario=done`
- `?scenario=error`
- `?scenario=canceled`
- `?scenario=long-paths`
- `?scenario=large-tree`
- `?scenario=stream`
- `?scenario=full-catalog`

Browser hooks (DEV mock only): `window.__JAVASHROUD_DEBUG_MOCK__`

- `scenarioId`, `scenario`, `emittedEvents`, `activeRunToken`
- `setScenario(id)`, `reset()`
- `runUiChecks()` — starts DOM smoke **immediately** (does not await). Poll `uiCheckResult`.
- `uiCheckResult`: `{ status: 'idle' | 'running' | 'passed' | 'failed', passed: string[], error?: string }`

Load `?scenario=full-catalog` first. In the debug page console:

```js
window.__JAVASHROUD_DEBUG_MOCK__.runUiChecks()
// later:
window.__JAVASHROUD_DEBUG_MOCK__.uiCheckResult
```

`runUiChecks` clicks real DOM (nav `data-testid`, `data-page`, bilingual button labels, `#input-jar-path`). It does not call Vue state helpers. Expect up to ~20s. `StartObfuscation` returns immediately and streams events on a run token so cancel can overlap.

`vite.file-preview.config.ts` is a development alias of `vite.mock.config.ts`. Do not use it to ship a production bundle of `debug.html`.

## Runtime Contract

The UI expects Wails v2 bindings at `window.go.main.App`:

- `StartObfuscation(request)`
- `CancelObfuscation()`

The event bridge subscribes to `engine:event`. Events must contain:

```ts
{
  level: 'info' | 'warn' | 'error' | 'success'
  type: 'progress' | 'log' | 'warn' | 'error' | 'done'
  message: string
  progress?: number
  outPath?: string
}
```

## Validation status

`corepack yarn check` is the frontend state/parser suite. `corepack yarn build` is the production Vue/Vite build (`index.html` + `src/main.ts`). The full desktop binary can be built from `desktop-app/build-desktop.bat` when the local Go environment is routed to a healthy toolchain.
