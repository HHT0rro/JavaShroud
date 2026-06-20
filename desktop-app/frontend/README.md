# JavaShroud Workbench Frontend

Vue 3 + TypeScript + Vite frontend for the JavaShroud desktop workbench.

## Commands

```bash
corepack yarn install --immutable
corepack yarn dev
corepack yarn build
```

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

`corepack yarn build` succeeds locally. The full desktop binary can be built from `desktop-app/build-desktop.bat` when the local Go environment is routed to a healthy toolchain.
