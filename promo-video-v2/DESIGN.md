---
colors:
  background: "#050706"
  graphite: "#0b0f0d"
  surface: "#101512"
  surfaceRaised: "#151b17"
  line: "#2b332e"
  text: "#f4f7f5"
  textMuted: "#9ba6a0"
  accent: "#8cff3f"
  accentDim: "#426f2c"
  warning: "#d6b85b"
typography:
  display: "Arial Black"
  body: "Arial"
  mono: "Cascadia Mono"
rounded: "minimal"
spacing: "architectural"
motion: "mechanical shutter + grid dissolve"
---

# JavaShroud Technical Launch v2 — Design System

## Overview

The video presents Java bytecode protection as a measured engineering process, not as a hacker fantasy. The visual balance is **70% Apple-style launch restraint** and **30% NVIDIA-style technical density**: large negative space, sharp physical surfaces, dense evidence only when the narrative needs it.

Every frame must feel like a precision instrument on a black graphite workbench. The primary contrast is **readable source code versus changed execution form**. Fluorescent green is an execution signal—not ambient decoration.

## Colors

- `#050706` — master background. Never use a blue or purple gradient.
- `#0b0f0d` / `#101512` — workstation and terminal surfaces.
- `#f4f7f5` — primary copy and evidence.
- `#9ba6a0` — supporting labels, hashes, paths, and secondary code.
- `#8cff3f` — verified state, selected method, `VMBC`, `CFR`, `JNI`, `RESULT MATCH`, and CTA verbs only.
- `#426f2c` — subdued green borders and traces. It may support but must not compete with the accent.
- `#d6b85b` — truthful warnings such as the analyzer-safe control-flow edge limit. Never turn a limitation into an error spectacle.

The JavaShroud logo may retain its original colors only in the 5–10 second brand statement and 86–90 second CTA.

## Typography

- Display voice: an extremely heavy system grotesque (`Arial Black`) for launch statements and chapter-scale terms.
- Evidence voice: `Cascadia Mono` for commands, source, CFR, `javap`, hashes, resources, engine events, and metadata.
- Supporting voice: `Arial` at a lighter visual weight.
- Chinese titles should use the installed system CJK fallback if the selected Latin face lacks glyphs.
- Display tracking is tight (`-0.035em` to `-0.05em`); technical labels use wider tracking (`0.08em` to `0.18em`).
- Body text never drops below 22 px at 1920×1080. Code may use 18–23 px only inside evidence panes with generous leading.

## Layout

- Use hard edges, 1 px rules, square corners, and measured inset lines.
- Avoid rounded SaaS cards, floating pills, glassmorphism, and dashboard-template symmetry.
- Keep two focal points in evidence scenes: proof on one side, interpretation or state on the other.
- Anchor major elements to the frame edges or to a strict 96 px / 120 px inset grid.
- Technical panels can become dense, but every number and path must come from `generated-evidence/evidence.js`.

## Motion

- Primary transition: mechanical shutter, 0.50–0.60 seconds.
- The shutter closes the current scene, swaps the next scene while closed, and opens into the next scene.
- A restrained grid-dissolve accent rides the closed phase. It is a sparse data break-up, not a tiled arcade effect.
- Scene exits are not pre-animated; the transition performs the exit.
- The 45 second VMBC reveal gets the only high-energy compression/opening transformation: readable Java collapses into a dispatcher token, passes through JNI, and opens as a sealed VMBC resource/runtime chain.
- All timelines are deterministic, paused, synchronously constructed, and registered in `window.__timelines`.
- No infinite repeats, random values, or time-dependent logic.

## Surfaces and Components

### Workbench

- English Vue/Wails semantic workbench, rebuilt as a motion graphic rather than a screenshot.
- Left rail: input artifact, scan, passes, rules.
- Main area: pass configuration, TOML, and engine events.
- Status values are based on the real build log. A small label may say `WORKFLOW VISUALIZATION · REAL ENGINE EVIDENCE`.

### Terminals

- Windows PowerShell and Ubuntu terminal treatments differ by tiny platform labels—not by fake chrome.
- Commands use a cold-white prompt; verified output and exit code `0` use fluorescent green.
- No Matrix rain, fake latitude/longitude, meaningless waveforms, or decorative security meters.

### Code comparison

- Left: complete original `AccessPolicy.java`.
- Right: complete CFR 0.152 output from the frozen protected JAR.
- Both panes scroll in synchronization; readable policy thresholds align against decompiled dispatch structures.
- Highlight only genuine lines: qualification gates, tier switch, risk loop, threshold branches, opaque predicate, `lookupswitch`, and `tableswitch` evidence.

## Do

- Show exact verified hashes and randomized resource paths from the manifest.
- Name `Method body moved to VMBC resource` when the dispatcher replaces the readable method body.
- Preserve the distinction between Java 21 used to run the engine build and Java 17 used to run the protected artifact.
- Show the control-flow edge-injection limitation in a precise footnote while still showing the transformations that did apply.
- Use `Renaming`, `Constant Obfuscation`, and `InvokeDynamic` only as an additional capability montage.

## Don’t

- Do not claim absolute protection, irreversibility, or immunity from analysis.
- Do not invent mappings, resource paths, progress, native platform labels, outputs, or screenshots.
- Do not imply all methods were virtualized; only `ProtectedOperation.execute:(II)J` was selected.
- Do not imply the three montage capabilities were part of the verified four-pass JAR.
- Do not use blue-purple SaaS gradients, green code rain, hooded figures, fake HUD layers, soft rounded cards, or decorative cybersecurity clichés.

