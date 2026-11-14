// Theme, local times, remembered filters, search help and display preferences.
(function () {
  "use strict";
  function get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function set(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* blocked */ } }

  // ---- theme ----
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    set("theme", t);
  }

  // ---- time zone and clock ----
  function prefs() {
    return { tz: get("tz") || "", clock: get("clock") || "" };
  }
  function zone(p) {
    if (p.tz === "UTC") return "UTC";
    if (p.tz) return p.tz;
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return "UTC"; }
  }
  function offsetMinutes(tz) {
    try {
      var now = new Date();
      var parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).formatToParts(now);
      var m = {};
      parts.forEach(function (x) { m[x.type] = x.value; });
      var asUtc = Date.UTC(+m.year, +m.month - 1, +m.day, +m.hour % 24, +m.minute);
      return Math.round((asUtc - now.getTime()) / 60000);
    } catch (e) { return 0; }
  }
  // The server buckets charts by this offset.
  function syncTzCookie() {
    var off = offsetMinutes(zone(prefs()));
    var cur = (document.cookie.match(/(?:^|; )clamv_tz=([^;]*)/) || [])[1];
    if (cur !== String(off)) {
      document.cookie = "clamv_tz=" + off + "; Path=/; Max-Age=31536000; SameSite=Strict" + (location.protocol === "https:" ? "; Secure" : "");
      return cur !== undefined || off !== 0;
    }
    return false;
  }
  var UTC_RE = /\b(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) UTC\b/g;
  function localizeTimes(root) {
    var p = prefs();
    var tz = zone(p);
    if (tz === "UTC" && p.clock !== "12") return;
    var opts = { timeZone: tz, year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" };
    if (p.clock === "12") opts.hour12 = true;
    if (p.clock === "24") opts.hourCycle = "h23";
    var fmt;
    try { fmt = new Intl.DateTimeFormat(undefined, opts); } catch (e) { return; }
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var nodes = [];
    while (walker.nextNode()) {
      var n = walker.currentNode;
      if (n.nodeValue && n.nodeValue.indexOf(" UTC") !== -1 && !(n.parentNode && /^(SCRIPT|STYLE|TEXTAREA|PRE|CODE)$/.test(n.parentNode.nodeName))) nodes.push(n);
    }
    nodes.forEach(function (n) {
      var text = n.nodeValue;
      UTC_RE.lastIndex = 0;
      if (!UTC_RE.test(text)) return;
      UTC_RE.lastIndex = 0;
      n.nodeValue = text.replace(UTC_RE, function (all, y, mo, d, h, mi, s) {
        var dt = new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s));
        if (n.parentNode && n.parentNode.nodeType === 1 && !n.parentNode.title) n.parentNode.title = all;
        return fmt.format(dt);
      });
    });
  }

  // ---- remembered filters ----
  function rememberFilters() {
    var form = document.querySelector("form[data-remember]");
    if (!form) return;
    var key = "filters:" + form.getAttribute("data-remember");
    var params = new URLSearchParams(location.search);
    if (params.has("reset")) { set(key, null); return; }
    params.delete("page");
    var qs = params.toString();
    if (qs) { set(key, qs); return; }
    var saved = get(key);
    if (saved) location.replace(location.pathname + "?" + saved);
  }

  // ---- display preferences (account page) ----
  function initPrefs() {
    var tzSel = document.getElementById("pref-tz");
    var clockSel = document.getElementById("pref-clock");
    var themeSel = document.getElementById("pref-theme");
    if (!tzSel || !clockSel || !themeSel) return;
    var p = prefs();
    try {
      var zones = Intl.supportedValuesOf ? Intl.supportedValuesOf("timeZone") : [];
      zones.forEach(function (z) {
        var o = document.createElement("option");
        o.value = z; o.textContent = z;
        tzSel.appendChild(o);
      });
    } catch (e) { /* older browser: browser zone and UTC only */ }
    tzSel.value = p.tz;
    clockSel.value = p.clock;
    themeSel.value = get("theme") || "";
    var saved = document.getElementById("pref-saved");
    function save() {
      set("tz", tzSel.value || null);
      set("clock", clockSel.value || null);
      if (themeSel.value) applyTheme(themeSel.value); else { set("theme", null); }
      syncTzCookie();
      if (saved) { saved.classList.remove("d-none"); }
    }
    [tzSel, clockSel, themeSel].forEach(function (el) { el.addEventListener("change", save); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    rememberFilters();
    var btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", function () {
      applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
    });
    document.addEventListener("click", function (ev) {
      var t = ev.target.closest("[data-toggle-help]");
      if (t) {
        var el = document.getElementById(t.getAttribute("data-toggle-help"));
        if (el) {
          var open = el.classList.toggle("d-none") === false;
          t.setAttribute("aria-expanded", open ? "true" : "false");
        }
      }
      var f = ev.target.closest("[data-forget]");
      if (f) set("filters:" + f.getAttribute("data-forget"), null);
    });
    initPrefs();
    var changed = syncTzCookie();
    localizeTimes(document.body);
    // First visit with a non-UTC zone: redraw charts in local time once.
    if (changed && document.querySelector(".chart")) location.reload();
  });
})();
