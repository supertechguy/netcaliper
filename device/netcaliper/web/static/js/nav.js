// SPDX-License-Identifier: GPL-3.0-only
// Keyboard-first navigation: arrows move focus spatially, letters jump to tiles, Esc goes back.
(() => {
  // Power saving: the kiosk session blanks the backlight after data-blank-after seconds without
  // input. The page sees every key/pointer event, so it mirrors that timer: the gesture that wakes
  // the screen is swallowed (pressing "s" to wake must not open Security), and polling pauses
  // while dark.
  const blankMs = (Number(document.body?.dataset.blankAfter) || 0) * 1000;
  let lastInput = Date.now();
  let swallowUntil = 0;
  // Treat the last few seconds before blanking as asleep too: the page's clock starts a moment after
  // swayidle's (Chromium startup), and swallowing one key while the screen is still dim is harmless.
  const marginMs = Math.min(10000, blankMs / 10);
  window.ncalAsleep = () => blankMs > 0 && Date.now() - lastInput >= blankMs - marginMs;
  const ACTIONS = ["keydown", "keypress", "keyup", "mousedown", "mouseup", "pointerdown", "pointerup",
                   "click", "dblclick", "auxclick", "contextmenu", "wheel"];
  const guard = (e) => {
    const now = Date.now();
    if (window.ncalAsleep()) swallowUntil = now + 600; // the rest of this gesture is part of waking
    lastInput = now;
    if (now < swallowUntil) { e.preventDefault(); e.stopImmediatePropagation(); }
  };
  for (const t of ACTIONS) window.addEventListener(t, guard, { capture: true });
  // Pure movement wakes the screen too (swayidle resumes on any input) but is never an action.
  window.addEventListener("pointermove", () => { lastInput = Date.now(); }, { capture: true, passive: true });

  // Only what can actually take focus: content of a closed <details> still has layout boxes in
  // Chromium (content-visibility), so it would win the spatial search and swallow the keypress.
  const visible = (el) => (el.checkVisibility ? el.checkVisibility() : el.offsetParent !== null)
    && el.tabIndex >= 0;
  const focusables = () => [...document.querySelectorAll(
    "[data-grid] .tile, [data-list] [tabindex], main button, main a[href], main input, main select, main summary",
  )].filter(visible);
  const typing = (el) => el && (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));

  function move(dir) {
    const items = focusables();
    if (!items.length) return;
    const cur = document.activeElement;
    if (!items.includes(cur)) { items[0].focus(); return; }
    const r = cur.getBoundingClientRect();
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    let best = null, bestScore = Infinity;
    for (const el of items) {
      if (el === cur) continue;
      const b = el.getBoundingClientRect();
      const dx = b.left + b.width / 2 - cx, dy = b.top + b.height / 2 - cy;
      const along = { left: -dx, right: dx, up: -dy, down: dy }[dir];
      const across = dir === "left" || dir === "right" ? Math.abs(dy) : Math.abs(dx);
      if (along <= 1) continue;
      const score = along + across * 2;
      if (score < bestScore) { bestScore = score; best = el; }
    }
    if (best) { best.focus(); best.scrollIntoView({ block: "nearest" }); }
  }

  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.altKey || e.metaKey) return;
    const help = document.getElementById("help");
    if (typing(document.activeElement)) { if (e.key === "Escape") document.activeElement.blur(); return; }
    const arrows = { ArrowLeft: "left", ArrowRight: "right", ArrowUp: "up", ArrowDown: "down" };
    if (arrows[e.key]) { e.preventDefault(); move(arrows[e.key]); return; }
    if (e.key === "?") { help.hidden = !help.hidden; return; }
    if (e.key === "Escape" || e.key === "Backspace") {
      e.preventDefault();
      if (!help.hidden) { help.hidden = true; return; }
      if (location.pathname !== "/") history.length > 1 ? history.back() : (location.href = "/");
      return;
    }
    if (e.key === "Enter" && document.activeElement?.matches("[data-list] [tabindex]")) {
      document.activeElement.querySelector("a")?.click();
      return;
    }
    if (e.key === "h" && location.pathname !== "/") { location.href = "/"; return; }
    const tile = document.querySelector(`.tile[data-hotkey="${CSS.escape(e.key.toLowerCase())}"]`);
    if (tile) { tile.focus(); tile.click(); return; }
    // Off the home screen, section hotkeys still jump directly.
    const target = { a: "autotest", w: "wired", f: "wifi", d: "discovery", s: "security", m: "airmapper",
                     r: "rf", t: "tools", l: "results", ",": "settings" }[e.key.toLowerCase()];
    if (target && location.pathname !== "/") location.href = `/s/${target}`;
  });

  window.addEventListener("DOMContentLoaded", () => {
    const af = document.querySelector("[autofocus]") || focusables()[0];
    af?.focus();
  });
})();
