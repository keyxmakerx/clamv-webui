// Theme, local times, remembered filters, search help, display preferences,
// background refresh, phone tables and upload progress.
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
    var cur = (document.cookie.match(/(?:^|; )palisade_tz=([^;]*)/) || [])[1];
    if (cur !== String(off)) {
      document.cookie = "palisade_tz=" + off + "; Path=/; Max-Age=31536000; SameSite=Strict" + (location.protocol === "https:" ? "; Secure" : "");
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


  // ---- phone tables: label each cell with its column so rows can stack ----
  function stackTables(root) {
    (root || document).querySelectorAll("table.table").forEach(function (t) {
      var heads = t.tHead ? t.tHead.rows[0] : null;
      if (!heads) return;
      var labels = [];
      Array.prototype.forEach.call(heads.cells, function (th) {
        var span = th.colSpan || 1;
        for (var i = 0; i < span; i++) labels.push(th.textContent.trim());
      });
      t.classList.add("table-stack");
      Array.prototype.forEach.call(t.tBodies, function (tb) {
        Array.prototype.forEach.call(tb.rows, function (tr) {
          var col = 0;
          Array.prototype.forEach.call(tr.cells, function (td) {
            if (td.colSpan > 1 && td.colSpan >= labels.length) { td.setAttribute("data-label", ""); }
            else if (!td.hasAttribute("data-label")) td.setAttribute("data-label", labels[col] || "");
            col += td.colSpan || 1;
          });
        });
      });
    });
  }

  // ---- background refresh: swap only the parts marked data-refresh-region ----
  // Sent with X-Palisade-Refresh so the server does not count it as activity,
  // and the idle sign-out still happens on an open tab.
  function initRefresh() {
    var timer = null;
    function secs() {
      var el = document.querySelector("[data-refresh-region][data-refresh]");
      var n = el ? parseInt(el.getAttribute("data-refresh"), 10) : NaN;
      return n >= 2 ? n : 0;
    }
    function schedule() {
      clearTimeout(timer);
      var n = secs();
      if (n) timer = setTimeout(tick, n * 1000);
    }
    function busy(region) {
      var a = document.activeElement;
      return a && a !== document.body && region.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.nodeName);
    }
    function tick() {
      // Pause in a hidden tab, except where a check must keep going
      // (a firewall apply rolls back unless this page confirms it in time).
      if (document.hidden && !document.querySelector("[data-refresh-region][data-refresh-hidden]")) return;
      fetch(location.href, { headers: { "X-Palisade-Refresh": "1" }, credentials: "same-origin", cache: "no-store" })
        .then(function (r) {
          // Signed out (idle limit or elsewhere): load the page properly.
          if (r.redirected && new URL(r.url).pathname !== location.pathname) { location.reload(); return null; }
          return r.ok ? r.text() : null;
        })
        .then(function (html) {
          if (html === null) { schedule(); return; }
          var doc = new DOMParser().parseFromString(html, "text/html");
          document.querySelectorAll("[data-refresh-region]").forEach(function (old) {
            var fresh = old.id && doc.getElementById(old.id);
            if (!fresh || busy(old)) return;
            var open = Array.prototype.map.call(old.querySelectorAll("details[open][id]"), function (d) { return d.id; });
            var node = document.importNode(fresh, true);
            old.replaceWith(node);
            open.forEach(function (id) { var d = document.getElementById(id); if (d) d.open = true; });
            localizeTimes(node);
            stackTables(node);
          });
          schedule();
        })
        .catch(function () { schedule(); });
    }
    document.addEventListener("visibilitychange", function () { if (!document.hidden) schedule(); });
    schedule();
  }

  // ---- uploads: drag and drop, and a progress bar ----
  function initUpload() {
    var form = document.querySelector("form[data-upload]");
    if (!form || !window.XMLHttpRequest || !window.FormData) return;
    var input = form.querySelector("input[type=file]");
    var zone = form.querySelector(".dropzone");
    var bar = form.querySelector(".upload-progress");
    var note = form.querySelector(".upload-note");
    if (zone && input) {
      ["dragenter", "dragover"].forEach(function (e) {
        zone.addEventListener(e, function (ev) { ev.preventDefault(); zone.classList.add("drag"); });
      });
      ["dragleave", "drop"].forEach(function (e) {
        zone.addEventListener(e, function (ev) { ev.preventDefault(); zone.classList.remove("drag"); });
      });
      zone.addEventListener("drop", function (ev) {
        if (ev.dataTransfer && ev.dataTransfer.files.length) {
          input.files = ev.dataTransfer.files;
          input.dispatchEvent(new Event("change"));
        }
      });
      input.addEventListener("change", function () {
        var n = input.files ? input.files.length : 0;
        if (note) note.textContent = n ? n + " file(s) chosen" : "";
      });
    }
    form.addEventListener("submit", function (ev) {
      if (!input || !input.files || !input.files.length) return;
      ev.preventDefault();
      var btn = form.querySelector("button[type=submit]");
      if (btn) btn.disabled = true;
      var xhr = new XMLHttpRequest();
      xhr.open("POST", form.action);
      if (bar) { bar.classList.remove("d-none"); bar.value = 0; }
      xhr.upload.addEventListener("progress", function (e) {
        if (!e.lengthComputable) return;
        var pct = Math.round((e.loaded / e.total) * 100);
        if (bar) bar.value = pct;
        if (note) note.textContent = pct < 100 ? "Uploading " + pct + "%" : "Scanning…";
      });
      xhr.addEventListener("load", function () {
        var to = xhr.responseURL || "";
        if (xhr.status < 400 && to && new URL(to).pathname !== new URL(form.action, location.href).pathname) {
          location.assign(to);
          return;
        }
        // An error page: show it as a normal navigation would.
        document.open(); document.write(xhr.responseText); document.close();
      });
      xhr.addEventListener("error", function () {
        if (btn) btn.disabled = false;
        if (note) note.textContent = "The upload failed. Check the connection and try again.";
      });
      xhr.send(new FormData(form));
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    rememberFilters();
    document.querySelectorAll("#theme-toggle, [data-theme-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
      });
    });
    var menu = document.getElementById("nav-toggle");
    var side = document.getElementById("app-sidebar");
    if (menu && side) menu.addEventListener("click", function () {
      menu.setAttribute("aria-expanded", side.classList.toggle("nav-open") ? "true" : "false");
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
      // Copy a setup snippet: data-copy names the element whose text to copy.
      var c = ev.target.closest("[data-copy]");
      if (c) {
        var src = document.getElementById(c.getAttribute("data-copy"));
        if (src && navigator.clipboard) {
          navigator.clipboard.writeText(src.textContent).then(function () {
            c.classList.add("copied");
            setTimeout(function () { c.classList.remove("copied"); }, 1500);
          }, function () { /* clipboard refused; the text stays selectable */ });
        }
      }
    });
    // A link to a Setup row (#key) opens that row.
    function openHash() {
      var id = location.hash.slice(1);
      var d = id && document.getElementById(id);
      if (d && d.tagName === "DETAILS") d.open = true;
    }
    window.addEventListener("hashchange", openHash);
    openHash();
    initPrefs();
    stackTables(document);
    initRefresh();
    initUpload();
    var changed = syncTzCookie();
    localizeTimes(document.body);
    // First visit with a non-UTC zone: redraw charts in local time once.
    if (changed && document.querySelector(".chart")) location.reload();
  });
})();
