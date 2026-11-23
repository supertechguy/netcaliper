// SPDX-License-Identifier: GPL-3.0-only
// Locate: poll the transmitter's signal and render it as a meter plus a Geiger-counter click rate and
// tone pitch (WebAudio, generated locally — no audio files). Stronger = faster clicks, higher pitch.
(() => {
  const root = document.querySelector(".locate");
  const mac = root.dataset.mac, freq = root.dataset.freq;
  const $ = (id) => document.getElementById(id);
  let sound = true, peak = null, last = null, lastAt = 0, ctx = null;

  const pct = (dbm) => Math.max(0, Math.min(100, (dbm + 95) * (100 / 65))); // -95 → 0 %, -30 → 100 %

  function click(dbm) {
    if (!sound) return;
    ctx = ctx || new AudioContext();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 300 + pct(dbm) * 12; // 300 Hz … 1500 Hz
    g.gain.setValueAtTime(0.25, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.05);
    o.connect(g).connect(ctx.destination);
    o.start(); o.stop(ctx.currentTime + 0.06);
  }

  function ticker() {
    // click interval: ~1 s when barely heard, ~60 ms when very close; silent when lost (>3 s stale)
    const fresh = last !== null && Date.now() - lastAt < 3000;
    if (fresh) click(last);
    const wait = fresh ? 1000 - pct(last) * 9.4 : 400;
    setTimeout(ticker, wait);
  }

  async function poll() {
    if (window.ncalAsleep && ncalAsleep()) return setTimeout(poll, 1000);
    try {
      const r = await fetch(`/api/v1/wifi/sample?mac=${encodeURIComponent(mac)}&freq=${freq}`);
      const j = await r.json();
      if (!r.ok) {
        $("info").textContent = j.detail || `error ${r.status}`;
      } else if (j.signal_dbm === null) {
        $("info").textContent = "no frames from this transmitter in the last half second";
      } else {
        last = j.signal_dbm; lastAt = Date.now();
        peak = peak === null ? last : Math.max(peak, last);
        $("dbm").textContent = Math.round(last);
        $("bar").style.width = `${pct(last)}%`;
        $("peak").style.left = `${pct(peak)}%`;
        $("info").textContent = `${j.samples} frames · avg ${j.avg_dbm} dBm · peak ${Math.round(peak)} dBm`;
      }
    } catch (e) {
      $("info").textContent = "connection lost";
    }
    setTimeout(poll, 300);
  }

  $("sound").addEventListener("click", () => {
    sound = !sound;
    $("sound").querySelector("span").textContent = `Sound: ${sound ? "on" : "off"}`;
  });
  $("reset").addEventListener("click", () => { peak = last; });
  document.addEventListener("keydown", (e) => { if (e.key === "r") $("reset").click(); });
  poll(); ticker();
})();
