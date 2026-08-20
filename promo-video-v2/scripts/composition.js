      const E = window.JAVASHROUD_EVIDENCE;

      function requireEvidence(condition, message) {
        if (!condition) throw new Error(`Verified evidence required: ${message}`);
      }
      function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
      function isStringArray(value) { return Array.isArray(value) && value.every((entry) => typeof entry === "string"); }
      function byId(items, key, value, label) {
        const item = items.find((entry) => entry[key] === value);
        requireEvidence(isRecord(item), `missing ${label} ${value}`);
        return item;
      }

      requireEvidence(isRecord(E), "window.JAVASHROUD_EVIDENCE is absent");
      requireEvidence(E.schemaVersion === 2, "unsupported root schema version");
      requireEvidence(E.evidencePolicy === "single-frozen-artifact-fail-closed", "unexpected evidence policy");
      requireEvidence(E.resultMatch === true && E.artifact?.universal === true && E.artifact?.sameShaAcrossPlatforms === true, "universal artifact gate");
      requireEvidence(/^[a-f0-9]{64}$/.test(E.artifact.sha256), "artifact SHA-256");
      requireEvidence(E.cfr?.inputProtectedJarSha256 === E.artifact.sha256, "CFR SHA chain");
      requireEvidence(E.platforms?.windows?.artifactSha256 === E.artifact.sha256 && E.platforms?.linux?.artifactSha256 === E.artifact.sha256, "platform SHA chain");
      requireEvidence(Array.isArray(E.cases) && E.cases.length === 3, "three cases");
      requireEvidence(Array.isArray(E.passes) && E.passes.length === 4, "four verified passes");
      requireEvidence(isStringArray(E.engineEvents) && E.engineEvents.length > 0, "engine events");
      requireEvidence(isStringArray(E.code?.accessPolicySource) && isStringArray(E.code?.accessPolicyCfr), "AccessPolicy evidence");
      requireEvidence(isStringArray(E.code?.protectedOperationSource) && isStringArray(E.vmbc?.javapTail), "VMBC code evidence");
      requireEvidence(E.vmbc?.resource === E.artifact.vmbcResource, "VMBC resource identity");
      requireEvidence(E.stringEvidence?.directLiteralRemoved === true && E.stringEvidence.finalEntryHits?.length === 0, "direct literal scan");
      requireEvidence(E.platforms.linux.launcherDiagnosticExcludedFromApplicationStderr === true, "Linux launcher diagnostic boundary");
      requireEvidence(isStringArray(E.artifact.jarEntries) && E.artifact.jarEntries.includes(E.artifact.bootResource) && E.artifact.jarEntries.includes(E.artifact.vmbcResource) && E.artifact.jarEntries.includes(E.artifact.nativeEntries["windows-x64"]) && E.artifact.jarEntries.includes(E.artifact.nativeEntries["linux-x64"]), "artifact resource tree");

      const windows = E.platforms.windows;
      const linux = E.platforms.linux;
      const cases = {
        approved: byId(E.cases, "case", "approved", "case"),
        stepUp: byId(E.cases, "case", "step-up", "case"),
        denied: byId(E.cases, "case", "denied", "case")
      };
      const passById = Object.fromEntries(E.passes.map((entry) => [entry.id, entry]));
      requireEvidence(passById["method-virtualization"]?.status === "applied", "VMBC status");
      requireEvidence(passById["control-flow-obfuscation"]?.status === "applied-with-safe-edge-limit", "control-flow status");
      requireEvidence(passById["string-encryption"]?.status === "applied", "string status");
      requireEvidence(passById["jni-microkernel-loader"]?.status === "applied-windows-linux", "JNI status");

      const text = (id, value) => { document.getElementById(id).textContent = String(value); };
      const append = (parentId, html) => { document.getElementById(parentId).insertAdjacentHTML("beforeend", html); };
      const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"})[char]);

      function renderHookCases(parentId) {
        [cases.approved, cases.stepUp, cases.denied].forEach((item) => {
          append(parentId, `<div class="verify-case hook-case"><div class="hook-command">${escapeHtml(item.command)}</div><div class="hook-output">${escapeHtml(item.output)}</div></div>`);
        });
      }
      renderHookCases("hook-win-cases");
      renderHookCases("hook-linux-cases");
      text("hook-win-java", windows.java);
      text("hook-linux-java", linux.java);
      text("hook-sha", E.artifact.shaShort);

      text("brand-claim", E.narrative.coreClaim);

      text("wb-input-name", E.baseline.jarName);
      text("wb-engine-meta", `ENGINE ${E.engine.version} · VBC ${E.engine.vbcVersion} · BUILD ${E.engine.javaBuildRuntime}`);
      ["Input JAR", "Scan Jar", "Passes", "Rules", "TOML", "Engine Events", "Done"].forEach((step, index) => append("wb-steps", `<div class="wb-step active" data-wb-step="${index}">${escapeHtml(step)}</div>`));
      E.passes.forEach((pass) => append("pass-list", `<div class="pass-row selected"><div class="pass-dot"></div><div><div class="pass-name">${escapeHtml(pass.label)}</div><div class="pass-target">${escapeHtml(pass.target)}</div></div><div class="pass-state">${escapeHtml(pass.status)}</div></div>`));
      text("toml-view", [
        "[[passes]]",
        'id = "method-virtualization"',
        'methodSelection = "selected-only"',
        `target = "${passById["method-virtualization"].target}"`,
        "",
        "[[passes]]",
        'id = "jni-microkernel-loader"',
        'targetPlatform = "windows-x64,linux-x64"'
      ].join("\n"));
      E.engineEvents.forEach((eventText, index) => append("engine-events", `<div class="event-row"><span class="event-index">${String(index + 1).padStart(2, "0")}</span><span class="event-text">${escapeHtml(eventText)}</span></div>`));
      text("wb-evidence-strip", `JAVA ${E.baseline.javaRelease} · CFR ${E.cfr.version} · SHA ${E.artifact.shaShort}`);

      text("source-code", E.code.accessPolicySource.join("\n"));
      text("cfr-code", E.code.accessPolicyCfr.join("\n"));
      text("cfr-meta", `CFR ${E.cfr.version} · SHA ${E.artifact.shaShort}`);

      text("vmbc-source-code", E.code.protectedOperationSource.join("\n"));
      text("vmbc-target", E.vmbc.target);
      text("dispatcher-tail", E.vmbc.javapTail.filter((line) => line !== "STDERR").slice(-12).join("\n"));
      text("vmbc-caption", E.vmbc.caption);
      const vmbcNodes = [
        ["01", "Java stub", E.vmbc.dispatcherDisplay],
        ["02", "JNI", "Native microkernel dispatch"],
        ["03", "VMBC resource", E.vmbc.resource],
        ["04", "Native runtime", "Windows x64 + Linux x64"]
      ];
      vmbcNodes.forEach(([index, title, body]) => append("vmbc-chain", `<article class="vmbc-node"><div class="vmbc-node-index">${index}</div><h3>${escapeHtml(title)}</h3><p>${escapeHtml(body)}</p></article>`));

      E.controlFlow.javapHighlights.slice(0, 12).forEach((line, index) => append("flow-lines", `<div class="flow-line"><b>${String(index + 1).padStart(2, "0")}</b><span>${escapeHtml(line)}</span></div>`));
      text("baseline-hit-count", E.stringEvidence.baselineEntryHits.length);
      text("baseline-hit-entry", E.stringEvidence.baselineEntryHits.join(", "));
      text("final-hit-count", E.stringEvidence.finalEntryHits.length);
      text("decoder-code", `${E.stringEvidence.decoderCall}\n${E.stringEvidence.cfrLines.slice(0, 3).join("\n")}`);
      text("edge-note", E.controlFlow.edgeInjectionNote);

      text("artifact-tree-name", E.artifact.jarName);
      text("artifact-name", E.artifact.jarName);
      text("artifact-size", E.artifact.sizeMiB.toFixed(2));
      text("artifact-sha", E.artifact.sha256);
      const resourceRows = [
        ["VMBC", E.artifact.vmbcResource],
        ["WINDOWS X64", E.artifact.nativeEntries["windows-x64"]],
        ["LINUX X64", E.artifact.nativeEntries["linux-x64"]],
        ["BOOT", E.artifact.bootResource]
      ];
      const extraEntries = E.artifact.jarEntries.filter((entry) => !resourceRows.some((row) => row[1] === entry)).slice(0, 10).map((entry) => ["JAR ENTRY", entry]);
      resourceRows.concat(extraEntries).forEach(([kind, path]) => append("tree-lines", `<div class="tree-line"><span class="tree-kind">${escapeHtml(kind)}</span><span class="tree-path">${escapeHtml(path)}</span></div>`));
      E.moreCapabilities.forEach((capability) => append("capabilities", `<div class="capability"><strong>${escapeHtml(capability)}</strong><span>TOOLCHAIN</span></div>`));

      function renderVerifyCases(parentId, exitKey) {
        [cases.approved, cases.stepUp, cases.denied].forEach((item) => append(parentId, `<div class="verify-case"><div class="verify-command">${escapeHtml(item.command)}</div><div class="verify-result"><span>${escapeHtml(item.output)}</span><span>EXIT ${item[exitKey]}</span></div></div>`));
      }
      text("verify-win-label", `${windows.label} · ${windows.java}`);
      text("verify-linux-label", `${linux.label} · ${linux.java}`);
      text("verify-win-path", windows.javaPath);
      text("verify-linux-path", linux.javaPath);
      renderVerifyCases("verify-win-cases", "windowsExit");
      renderVerifyCases("verify-linux-cases", "linuxExit");
      text("verify-sha-lock", `SAME SHA-256 · ${E.artifact.shaShort}`);

      text("cta-title", E.narrative.cta);
      text("cta-repo", E.narrative.repository);
      text("cta-license", E.narrative.licenseLine);

      window.__timelines = window.__timelines || {};
      const tl = gsap.timeline({ paused: true });
      window.__timelines["main"] = tl;

      const sceneIds = ["#scene-hook", "#scene-claim", "#scene-workflow", "#scene-compare", "#scene-vmbc", "#scene-proofs", "#scene-artifact", "#scene-verify", "#scene-cta"];
      const sceneStarts = [0, 5, 10, 30, 45, 60, 68, 78, 86];
      tl.set(sceneIds, { opacity: 0 }, 0);
      tl.set("#scene-hook", { opacity: 1 }, 0);

      function transition(outgoing, incoming, boundary) {
        const closeAt = boundary - 0.28;
        tl.to("#shutter-top", { yPercent: 100, duration: 0.25, ease: "power3.in" }, closeAt);
        tl.to("#shutter-bottom", { yPercent: -100, duration: 0.25, ease: "power3.in" }, closeAt);
        tl.to("#grid-dissolve", { opacity: .72, duration: .16, ease: "power2.in" }, closeAt + .08);
        tl.set(outgoing, { opacity: 0 }, boundary);
        tl.set(incoming, { opacity: 1 }, boundary);
        tl.to("#grid-dissolve", { opacity: 0, duration: .22, ease: "power2.out" }, boundary + .02);
        tl.to("#shutter-top", { yPercent: 0, duration: .27, ease: "power3.out" }, boundary + .02);
        tl.to("#shutter-bottom", { yPercent: 0, duration: .27, ease: "power3.out" }, boundary + .02);
      }
      for (let index = 1; index < sceneIds.length; index += 1) transition(sceneIds[index - 1], sceneIds[index], sceneStarts[index]);

      // Scene 1 entrances.
      tl.from(".hook-kicker", { opacity: 0, y: 22, duration: .55, ease: "power3.out" }, .18);
      tl.from("#hook-windows", { opacity: 0, x: -55, duration: .72, ease: "expo.out" }, .34);
      tl.from("#hook-linux", { opacity: 0, x: 55, duration: .72, ease: "back.out(1.25)" }, .42);
      tl.from("#hash-spine", { opacity: 0, scaleY: .4, duration: .62, ease: "power2.out" }, .68);
      tl.from("#hook-windows .hook-case", { opacity: 0, y: 18, duration: .34, stagger: .62, ease: "power3.out" }, .92);
      tl.from("#hook-linux .hook-case", { opacity: 0, y: 18, duration: .34, stagger: .62, ease: "sine.out" }, 1.02);
      tl.from("#hook-match", { opacity: 0, scale: .72, duration: .55, ease: "back.out(1.6)" }, 3.62);

      // Scene 2 entrances.
      tl.from("#brand-slit", { opacity: 0, scaleY: .08, duration: .7, ease: "expo.out" }, 5.16);
      tl.from("#brand-logo", { opacity: 0, scale: .74, y: 28, duration: .66, ease: "back.out(1.35)" }, 5.34);
      tl.from("#brand-claim", { opacity: 0, clipPath: "inset(0 50% 0 50%)", duration: .82, ease: "power4.out" }, 5.62);
      tl.from("#brand-meta", { opacity: 0, y: 22, duration: .5, ease: "sine.out" }, 6.18);

      // Scene 3 entrances and staged workflow.
      tl.from("#scene-workflow .chapter", { opacity: 0, x: -28, duration: .48, ease: "power3.out" }, 10.16);
      tl.from("#scene-workflow .headline", { opacity: 0, y: 30, duration: .66, ease: "expo.out" }, 10.28);
      tl.from("#workbench", { opacity: 0, y: 38, scale: .985, duration: .78, ease: "power4.out" }, 10.58);
      tl.from(".wb-brand", { opacity: 0, x: -24, duration: .48, ease: "back.out(1.2)" }, 10.92);
      tl.from(".wb-input", { opacity: 0, x: -24, duration: .48, ease: "sine.out" }, 11.12);
      tl.from(".wb-step", { opacity: 0, x: -20, duration: .28, stagger: .42, ease: "power2.out" }, 11.42);
      tl.from(".pass-row", { opacity: 0, y: 18, duration: .38, stagger: .58, ease: "power3.out" }, 14.0);
      tl.from("#toml-view", { opacity: 0, y: 20, duration: .58, ease: "expo.out" }, 16.55);
      tl.from(".event-row", { opacity: 0, x: 22, duration: .27, stagger: .76, ease: "sine.out" }, 18.1);
      tl.from("#progress-fill", { scaleX: 0, duration: 8.4, ease: "power1.inOut" }, 20.2);

      // Scene 4 entrances and synchronized full-code scroll.
      tl.from("#scene-compare .chapter", { opacity: 0, x: -28, duration: .48, ease: "power3.out" }, 30.16);
      tl.from("#scene-compare .headline", { opacity: 0, y: 30, duration: .62, ease: "expo.out" }, 30.28);
      tl.from("#source-pane", { opacity: 0, x: -44, duration: .72, ease: "power4.out" }, 30.58);
      tl.from("#cfr-pane", { opacity: 0, x: 44, duration: .72, ease: "back.out(1.18)" }, 30.66);
      tl.from(".compare-marker", { opacity: 0, scale: .55, duration: .52, ease: "back.out(1.5)" }, 31.08);
      tl.from(".compare-callout", { opacity: 0, y: 16, duration: .36, stagger: .32, ease: "sine.out" }, 31.35);
      tl.to("#source-code", { y: -970, duration: 12.2, ease: "none" }, 32.0);
      tl.to("#cfr-code", { y: -1540, duration: 12.2, ease: "none" }, 32.0);

      // Scene 5: the only high-energy compression/open transformation.
      tl.from("#scene-vmbc .chapter", { opacity: 0, x: -28, duration: .48, ease: "power3.out" }, 45.16);
      tl.from("#scene-vmbc .headline", { opacity: 0, y: 34, duration: .64, ease: "expo.out" }, 45.26);
      tl.from("#vmbc-source-box", { opacity: 0, x: -50, duration: .72, ease: "power4.out" }, 45.58);
      tl.to("#vmbc-source-code", { scaleX: .07, opacity: .18, transformOrigin: "50% 50%", duration: .62, ease: "power4.in" }, 47.08);
      tl.to("#vmbc-token", { opacity: 1, scale: 1, duration: .62, ease: "back.out(1.7)" }, 47.44);
      tl.from(".vmbc-node", { opacity: 0, scaleX: .14, transformOrigin: "left center", duration: .62, stagger: .52, ease: "expo.out" }, 48.2);
      tl.from(".dispatcher-proof", { opacity: 0, y: 32, duration: .72, ease: "power3.out" }, 50.55);
      tl.from("#vmbc-caption", { opacity: 0, y: 18, duration: .58, ease: "sine.out" }, 51.0);

      // Scene 6 entrances.
      tl.from("#scene-proofs .chapter", { opacity: 0, x: -28, duration: .44, ease: "power3.out" }, 60.16);
      tl.from("#scene-proofs .headline", { opacity: 0, y: 28, duration: .58, ease: "expo.out" }, 60.25);
      tl.from("#scene-proofs .proof-panel", { opacity: 0, y: 30, duration: .62, stagger: .14, ease: "power4.out" }, 60.58);
      tl.from(".flow-line", { opacity: 0, x: -20, duration: .22, stagger: .18, ease: "sine.out" }, 61.05);
      tl.from(".literal-row", { opacity: 0, x: 20, duration: .36, stagger: .4, ease: "back.out(1.1)" }, 61.18);
      tl.from("#edge-note", { opacity: 0, y: 16, duration: .52, ease: "power3.out" }, 64.6);

      // Scene 7 entrances.
      tl.from("#scene-artifact .chapter", { opacity: 0, x: -28, duration: .44, ease: "power3.out" }, 68.16);
      tl.from("#scene-artifact .headline", { opacity: 0, y: 28, duration: .58, ease: "expo.out" }, 68.25);
      tl.from(".jar-tree", { opacity: 0, x: -42, duration: .7, ease: "power4.out" }, 68.58);
      tl.from(".artifact-card", { opacity: 0, x: 42, duration: .7, ease: "back.out(1.12)" }, 68.7);
      tl.from(".tree-line", { opacity: 0, x: -16, duration: .25, stagger: .26, ease: "sine.out" }, 69.1);
      tl.from(".capability", { opacity: 0, y: 16, duration: .34, stagger: .38, ease: "power3.out" }, 72.7);

      // Scene 8 entrances.
      tl.from("#scene-verify .chapter", { opacity: 0, x: -28, duration: .44, ease: "power3.out" }, 78.16);
      tl.from("#scene-verify .headline", { opacity: 0, y: 28, duration: .58, ease: "expo.out" }, 78.25);
      tl.from("#verify-windows", { opacity: 0, x: -45, duration: .68, ease: "power4.out" }, 78.58);
      tl.from("#verify-linux", { opacity: 0, x: 45, duration: .68, ease: "back.out(1.14)" }, 78.66);
      tl.from("#verify-windows .verify-case", { opacity: 0, y: 18, duration: .3, stagger: .7, ease: "power3.out" }, 79.2);
      tl.from("#verify-linux .verify-case", { opacity: 0, y: 18, duration: .3, stagger: .7, ease: "sine.out" }, 79.3);
      tl.from(".verify-lock", { opacity: 0, scale: .75, duration: .58, ease: "back.out(1.6)" }, 83.45);

      // CTA entrance and the only final exit.
      tl.from("#cta-logo", { opacity: 0, scale: .7, y: 24, duration: .58, ease: "back.out(1.45)" }, 86.16);
      tl.from("#cta-title", { opacity: 0, clipPath: "inset(0 50% 0 50%)", duration: .76, ease: "power4.out" }, 86.36);
      tl.from("#cta-repo", { opacity: 0, y: 18, duration: .46, ease: "sine.out" }, 86.78);
      tl.from("#cta-license", { opacity: 0, y: 18, duration: .46, ease: "power3.out" }, 86.94);
      tl.from("#cta-line", { opacity: 0, scaleX: .15, duration: .68, ease: "expo.out" }, 87.08);
      tl.to("#cta-stage", { opacity: 0, duration: .8, ease: "power2.in" }, 89.2);
      tl.to("#final-black", { opacity: 1, duration: .8, ease: "power2.in" }, 89.2);
