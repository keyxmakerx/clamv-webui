// Palisade UI behaviour: theme and motion preferences, local times, remembered filters, search help,
// display preferences, background refresh (focus, scroll and disclosure state kept; changed values
// highlighted), phone tables, uploads, copy buttons, sidebar rail and phone drawer, popovers, flash
// toasts, busy submit buttons and the command palette.
// Rules: every page works without this file; untrusted text only ever goes in via textContent.
(function () {
  "use strict";
  var doc = document;
  var root = doc.documentElement;
  // Success flashes become toasts only when this file runs (motion.css keys on it).
  root.classList.add("has-toasts");
  function get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function set(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* blocked */ } }
  function $(sel, el) { return (el || doc).querySelector(sel); }
  function $$(sel, el) { return Array.prototype.slice.call((el || doc).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }
  // Translated strings rendered by the server into #js-strings (English if missing).
  function str(key, fallback) {
    var s = doc.getElementById("js-strings");
    var v = s && s.getAttribute("data-" + key);
    return v || fallback;
  }

  // ---- motion: "reduce" / "full" in localStorage override the OS; unset follows it ----
  var reduceQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  function motionOK() {
    var m = root.getAttribute("data-motion");
    if (m === "reduce") return false;
    if (m === "full") return true;
    return !(reduceQuery && reduceQuery.matches);
  }
  function applyMotion(m) {
    if (m === "reduce" || m === "full") { root.setAttribute("data-motion", m); set("motion", m); }
    else { root.removeAttribute("data-motion"); set("motion", null); }
  }
  // Run `done` after `node`'s exit animation (or at once when motion is off).
  function afterExit(node, cls, done) {
    if (!motionOK()) { done(); return; }
    var finished = false;
    var finish = function () {
      if (finished) return;
      finished = true;
      node.removeEventListener("animationend", onEnd);
      done();
    };
    var onEnd = function (ev) { if (ev.target === node || node.contains(ev.target)) finish(); };
    node.addEventListener("animationend", onEnd);
    node.classList.add(cls);
    setTimeout(finish, 400); // never leave anything half-closed
  }

  // ---- theme ----
  function applyTheme(t) {
    root.setAttribute("data-theme", t);
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
    var cur = (doc.cookie.match(/(?:^|; )palisade_tz=([^;]*)/) || [])[1];
    if (cur !== String(off)) {
      doc.cookie = "palisade_tz=" + off + "; Path=/; Max-Age=31536000; SameSite=Strict" + (location.protocol === "https:" ? "; Secure" : "");
      return cur !== undefined || off !== 0;
    }
    return false;
  }
  var UTC_RE = /\b(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) UTC\b/g;
  function localizeTimes(node) {
    var p = prefs();
    var tz = zone(p);
    if (tz === "UTC" && p.clock !== "12") return;
    var opts = { timeZone: tz, year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" };
    if (p.clock === "12") opts.hour12 = true;
    if (p.clock === "24") opts.hourCycle = "h23";
    var fmt;
    try { fmt = new Intl.DateTimeFormat(undefined, opts); } catch (e) { return; }
    var walker = doc.createTreeWalker(node, NodeFilter.SHOW_TEXT, null);
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
    var form = $("form[data-remember]");
    if (!form) return false;
    var key = "filters:" + form.getAttribute("data-remember");
    var params = new URLSearchParams(location.search);
    if (params.has("reset")) { set(key, null); return false; }
    params.delete("page");
    var qs = params.toString();
    if (qs) { set(key, qs); return false; }
    var saved = get(key);
    if (saved) { location.replace(location.pathname + "?" + saved); return true; }
    return false;
  }

  // ---- display preferences (account page) ----
  function initPrefs() {
    var saved = doc.getElementById("pref-saved");
    function shown() { if (saved) { saved.classList.remove("d-none"); saved.hidden = false; } }
    var motionSel = doc.getElementById("pref-motion");
    if (motionSel) {
      var m = get("motion");
      // "system" (or an empty value) means: follow the OS.
      motionSel.value = m === "reduce" || m === "full" ? m : (motionSel.querySelector("option[value='system']") ? "system" : "");
      motionSel.addEventListener("change", function () { applyMotion(motionSel.value); shown(); });
    }
    var tzSel = doc.getElementById("pref-tz");
    var clockSel = doc.getElementById("pref-clock");
    var themeSel = doc.getElementById("pref-theme");
    if (!tzSel || !clockSel || !themeSel) return;
    var p = prefs();
    try {
      var zones = Intl.supportedValuesOf ? Intl.supportedValuesOf("timeZone") : [];
      zones.forEach(function (z) {
        var o = doc.createElement("option");
        o.value = z; o.textContent = z;
        tzSel.appendChild(o);
      });
    } catch (e) { /* older browser: browser zone and UTC only */ }
    tzSel.value = p.tz;
    clockSel.value = p.clock;
    themeSel.value = get("theme") || "";
    function save() {
      set("tz", tzSel.value || null);
      set("clock", clockSel.value || null);
      if (themeSel.value) applyTheme(themeSel.value); else { set("theme", null); }
      syncTzCookie();
      shown();
    }
    [tzSel, clockSel, themeSel].forEach(function (s) { s.addEventListener("change", save); });
  }

  // ---- phone tables: label each cell with its column so rows can stack ----
  function stackTables(scope) {
    $$("table.table", scope || doc).forEach(function (t) {
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
  var POPOVERS = "details.confirm, details.edit, details[data-menu]";
  // Path of child indexes from `top` down to `node`, to find "the same element" in a fresh copy.
  function pathOf(top, node) {
    var path = [];
    while (node && node !== top) {
      var i = 0, s = node;
      while ((s = s.previousElementSibling)) i++;
      path.unshift(i);
      node = node.parentElement;
    }
    return node === top ? path : null;
  }
  function byPath(top, path) {
    var n = top;
    for (var i = 0; n && i < path.length; i++) n = n.children[path[i]];
    return n || null;
  }
  // What to look for after a swap to give focus back to the same control.
  function focusKey(region) {
    var a = doc.activeElement;
    if (!a || a === doc.body || !region.contains(a)) return null;
    return {
      id: a.id || null,
      href: a.getAttribute("href"),
      text: (a.textContent || "").trim(),
      tag: a.tagName,
      path: pathOf(region, a)
    };
  }
  function restoreFocus(node, k) {
    if (!k) return;
    var t = null;
    if (k.id) t = doc.getElementById(k.id);
    if (!t && k.href) {
      t = $$("a[href]", node).filter(function (x) { return x.getAttribute("href") === k.href; })[0] || null;
    }
    if (!t && k.path) {
      var c = byPath(node, k.path);
      if (c && c.tagName === k.tag && (c.textContent || "").trim() === k.text) t = c;
    }
    if (t && node.contains(t)) {
      try { t.focus({ preventScroll: true }); } catch (e) { t.focus(); }
    }
  }
  // A region is left alone while someone is typing in it or has a popover or ad-hoc disclosure open.
  function busy(region, fresh) {
    var a = doc.activeElement;
    if (a && a !== doc.body && region.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.nodeName)) return true;
    if ($(POPOVERS.split(", ").map(function (s) { return s + "[open]"; }).join(", "), region)) return true;
    if ($("form[data-submitting]", region)) return true; // a submit from this region is on its way
    // An open disclosure without an id that the fresh copy would close.
    var olds = $$("details:not([id])", region), news = $$("details:not([id])", fresh);
    for (var i = 0; i < olds.length; i++) {
      if (olds[i].open && !(news[i] && news[i].open)) return true;
    }
    return false;
  }
  // Text of the cells worth watching, keyed so that inserted rows don't mark every row below.
  var LIVE = "[data-live], .stat-value, .badge, .status-dot, dd";
  function rowKey(tr) {
    if (tr.id) return "#" + tr.id;
    if (tr.getAttribute("data-key")) return "k:" + tr.getAttribute("data-key");
    var a = tr.querySelector("a[href]");
    return a ? "a:" + a.getAttribute("href") : null;
  }
  // Rows with their keys; repeated keys (several detections of one job) get a running number.
  function keyedRows(scope) {
    var seen = {}, out = [];
    $$("table tbody tr", scope).forEach(function (tr) {
      if (tr.closest("[data-live='off']")) return;
      var k = rowKey(tr);
      if (!k) return;
      seen[k] = (seen[k] || 0) + 1;
      out.push({ k: k + "~" + seen[k], tr: tr });
    });
    return out;
  }
  function liveText(n) {
    // Badges and dots carry state in their class as much as in their text.
    var t = (n.textContent || "").replace(/\s+/g, " ").trim();
    return n.classList.contains("badge") || n.classList.contains("status-dot") ? t + "|" + n.className.replace(/\bis-changed\b/g, "").trim() : t;
  }
  function snapshot(region) {
    var rows = {};
    keyedRows(region).forEach(function (kr) {
      rows[kr.k] = Array.prototype.map.call(kr.tr.cells, function (td) { return liveText(td); });
    });
    var live = $$(LIVE, region).filter(function (n) { return !n.closest("table") && !n.closest("[data-live='off']"); }).map(liveText);
    return { rows: rows, live: live };
  }
  function markChanged(node, before) {
    if (node.closest("[data-live='off']") || node.hasAttribute("data-live") && node.getAttribute("data-live") === "off") return;
    var marks = [], units = 0; // a new row counts once, however many cells it has
    keyedRows(node).forEach(function (kr) {
      var old = before.rows[kr.k];
      if (!old) { units++; Array.prototype.forEach.call(kr.tr.cells, function (td) { marks.push(td); }); return; }
      Array.prototype.forEach.call(kr.tr.cells, function (td, i) {
        if (old[i] !== undefined && old[i] !== liveText(td)) { marks.push(td); units++; }
      });
    });
    var lives = $$(LIVE, node).filter(function (n) { return !n.closest("table") && !n.closest("[data-live='off']"); });
    if (lives.length === before.live.length) {
      lives.forEach(function (n, i) { if (before.live[i] !== liveText(n)) { marks.push(n); units++; } });
    }
    // Many changes at once (a new period, a reshuffled list) is not news: don't light up the page.
    if (!units || units > 12) return;
    marks.forEach(function (n) { n.classList.add("is-changed"); });
    setTimeout(function () { marks.forEach(function (n) { n.classList.remove("is-changed"); }); }, 1300);
  }
  function initRefresh() {
    var timer = null;
    function secs() {
      var r = $("[data-refresh-region][data-refresh]");
      var n = r ? parseInt(r.getAttribute("data-refresh"), 10) : NaN;
      return n >= 2 ? n : 0;
    }
    function schedule() {
      clearTimeout(timer);
      var n = secs();
      if (n) timer = setTimeout(tick, n * 1000);
    }
    function swap(old, fresh) {
      var fk = focusKey(old);
      var openById = {};
      $$("details[id]", old).forEach(function (d) { openById[d.id] = d.open; });
      var scrolls = $$(".table-responsive, .table-scroll, [data-keep-scroll]", old).map(function (s) { return [s.scrollLeft, s.scrollTop]; });
      var before = snapshot(old);
      var node = doc.importNode(fresh, true);
      localizeTimes(node);
      stackTables(node);
      // Keep what the user opened or closed, both ways (Setup rows the server opens stay closed if closed).
      $$("details[id]", node).forEach(function (d) { if (d.id in openById) d.open = openById[d.id]; });
      old.replaceWith(node);
      $$(".table-responsive, .table-scroll, [data-keep-scroll]", node).forEach(function (s, i) {
        if (scrolls[i]) { s.scrollLeft = scrolls[i][0]; s.scrollTop = scrolls[i][1]; }
      });
      restoreFocus(node, fk);
      markChanged(node, before);
    }
    function tick() {
      // Pause in a hidden tab, except where a check must keep going
      // (a firewall apply rolls back unless this page confirms it in time).
      if (doc.hidden && !$("[data-refresh-region][data-refresh-hidden]")) return;
      fetch(location.href, { headers: { "X-Palisade-Refresh": "1" }, credentials: "same-origin", cache: "no-store" })
        .then(function (r) {
          // Signed out (idle limit or elsewhere): load the page properly.
          if (r.redirected && new URL(r.url).pathname !== location.pathname) { location.reload(); return null; }
          return r.ok ? r.text() : null;
        })
        .then(function (html) {
          if (html === null) { schedule(); return; }
          var fresh = new DOMParser().parseFromString(html, "text/html");
          $$("[data-refresh-region]").forEach(function (old) {
            var f = old.id && fresh.getElementById(old.id);
            if (!f || busy(old, f)) return;
            swap(old, f);
          });
          schedule();
        })
        .catch(function () { schedule(); });
    }
    doc.addEventListener("visibilitychange", function () { if (!doc.hidden) schedule(); });
    schedule();
  }

  // ---- uploads: drag and drop, and a progress bar ----
  function initUpload() {
    var form = $("form[data-upload]");
    if (!form || !window.XMLHttpRequest || !window.FormData) return;
    var input = form.querySelector("input[type=file]");
    var dz = form.querySelector(".dropzone");
    var bar = form.querySelector(".upload-progress");
    var note = form.querySelector(".upload-note");
    function msg(name, fallback, vars) {
      var s = form.getAttribute("data-msg-" + name) || fallback;
      Object.keys(vars || {}).forEach(function (k) { s = s.split("{" + k + "}").join(String(vars[k])); });
      return s;
    }
    if (dz && input) {
      ["dragenter", "dragover"].forEach(function (e) {
        dz.addEventListener(e, function (ev) { ev.preventDefault(); dz.classList.add("drag"); });
      });
      ["dragleave", "drop"].forEach(function (e) {
        dz.addEventListener(e, function (ev) { ev.preventDefault(); dz.classList.remove("drag"); });
      });
      dz.addEventListener("drop", function (ev) {
        if (ev.dataTransfer && ev.dataTransfer.files.length) {
          input.files = ev.dataTransfer.files;
          input.dispatchEvent(new Event("change"));
        }
      });
      input.addEventListener("change", function () {
        var n = input.files ? input.files.length : 0;
        if (note) note.textContent = n ? msg("chosen", "{n} file(s) chosen", { n: n }) : "";
      });
    }
    form.addEventListener("submit", function (ev) {
      if (!input || !input.files || !input.files.length) return;
      ev.preventDefault();
      var btn = form.querySelector("button[type=submit]");
      if (btn) setBusy(btn, true);
      var xhr = new XMLHttpRequest();
      xhr.open("POST", form.action);
      if (bar) { bar.classList.remove("d-none"); bar.hidden = false; bar.value = 0; }
      xhr.upload.addEventListener("progress", function (e) {
        if (!e.lengthComputable) return;
        var pct = Math.round((e.loaded / e.total) * 100);
        if (bar) bar.value = pct;
        if (note) note.textContent = pct < 100 ? msg("uploading", "Uploading {pct}%", { pct: pct }) : msg("scanning", "Scanning…");
      });
      xhr.addEventListener("load", function () {
        var to = xhr.responseURL || "";
        if (xhr.status < 400 && to && new URL(to).pathname !== new URL(form.action, location.href).pathname) {
          location.assign(to);
          return;
        }
        // An error page: show it as a normal navigation would.
        doc.open(); doc.write(xhr.responseText); doc.close();
      });
      xhr.addEventListener("error", function () {
        if (btn) setBusy(btn, false);
        if (note) note.textContent = msg("failed", "The upload failed. Check the connection and try again.");
      });
      xhr.send(new FormData(form));
    });
  }

  // ---- copy buttons: data-copy names the element whose text is copied ----
  function announce(text) {
    var region = doc.getElementById("toast-region");
    if (!region) return;
    var n = el("span", "visually-hidden", text);
    region.appendChild(n);
    setTimeout(function () { n.remove(); }, 2000);
  }
  function copyText(btn) {
    var src = doc.getElementById(btn.getAttribute("data-copy"));
    if (!src || btn.classList.contains("copied")) return;
    // Keep the button's own nodes (icon and label) to put back, and its width so nothing shifts.
    var kept = Array.prototype.slice.call(btn.childNodes);
    var w = btn.getBoundingClientRect().width;
    var done = function (ok) {
      var label = ok ? str("copied", "Copied") : str("copy-failed", "Select and copy");
      btn.style.minWidth = w + "px"; // CSSOM, not a style attribute: allowed by the CSP
      btn.textContent = label;
      btn.classList.add("copied");
      announce(label);
      setTimeout(function () {
        btn.textContent = "";
        kept.forEach(function (n) { btn.appendChild(n); });
        btn.classList.remove("copied");
        btn.style.minWidth = "";
      }, 1500);
    };
    // Without a secure context the clipboard API is missing: select the text instead.
    var selectIt = function () {
      var r = doc.createRange();
      r.selectNodeContents(src);
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      done(false);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(src.textContent).then(function () { done(true); }, selectIt);
    } else {
      selectIt();
    }
  }

  // ---- toasts ----
  function toast(text, tone, opts) {
    var region = doc.getElementById("toast-region");
    if (!region) return null;
    opts = opts || {};
    var t = el("div", "toast toast-" + (tone || "info"));
    t.setAttribute("role", tone === "danger" ? "alert" : "status");
    if (opts.icon) { var i = el("i", "fas " + opts.icon + " toast-icon"); i.setAttribute("aria-hidden", "true"); t.appendChild(i); }
    t.appendChild(el("div", "toast-body", text));
    var close = el("button", "icon-btn toast-close");
    close.type = "button";
    close.setAttribute("aria-label", str("dismiss", "Dismiss"));
    var x = el("i", "fas fa-times"); x.setAttribute("aria-hidden", "true");
    close.appendChild(x);
    t.appendChild(close);
    var timer = null;
    function dismiss() {
      clearTimeout(timer);
      if (t.contains(doc.activeElement)) { var m = doc.getElementById("main"); if (m) m.focus({ preventScroll: true }); }
      afterExit(t, "is-leaving", function () { t.remove(); });
    }
    function arm() { clearTimeout(timer); if (opts.timeout) timer = setTimeout(dismiss, opts.timeout); }
    close.addEventListener("click", dismiss);
    // Never hide a message while it is being read or used.
    t.addEventListener("mouseenter", function () { clearTimeout(timer); });
    t.addEventListener("mouseleave", arm);
    t.addEventListener("focusin", function () { clearTimeout(timer); });
    t.addEventListener("focusout", arm);
    region.appendChild(t);
    arm();
    return t;
  }
  // Success flashes become toasts (hidden in the page by motion.css when script runs);
  // errors stay in the page, where they explain what to fix, and can be dismissed.
  function initFlash() {
    $$(".flash-region > .callout-ok.flash").forEach(function (c) {
      var body = c.querySelector(".callout-body");
      var text = body ? body.textContent.trim() : c.textContent.trim();
      // Long enough to read: 6 s, plus a little per word for longer messages.
      toast(text, "ok", { timeout: Math.max(6000, text.split(/\s+/).length * 400), icon: "fa-check-circle" });
      c.remove();
    });
  }
  function dismissCallout(btn) {
    var c = btn.closest(".callout, .toast");
    if (!c) return;
    var m = doc.getElementById("main");
    if (m) m.focus({ preventScroll: true });
    afterExit(c, "is-leaving", function () { c.remove(); });
  }

  // ---- busy submit buttons: one click, one request ----
  function setBusy(btn, on) {
    if (on) {
      btn.classList.add("is-busy");
      btn.setAttribute("aria-busy", "true");
      btn.disabled = true;
    } else {
      btn.classList.remove("is-busy");
      btn.removeAttribute("aria-busy");
      btn.disabled = false;
    }
  }
  function releaseForm(form) {
    delete form.dataset.submitting;
    $$(".is-busy", form).forEach(function (b) { setBusy(b, false); });
    if (form.id) $$('.is-busy[form="' + form.id + '"]').forEach(function (b) { setBusy(b, false); });
  }
  function releaseAll() {
    $$("form[data-submitting]").forEach(releaseForm);
    $$(".is-busy").forEach(function (b) { setBusy(b, false); });
  }
  function initBusy() {
    // Runs after every other submit handler (bubbling to document), so a handler that took over
    // the submit (upload, passkeys) has already called preventDefault and is skipped.
    doc.addEventListener("submit", function (ev) {
      var form = ev.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.dataset.submitting) { ev.preventDefault(); return; } // second Enter / click
      if (ev.defaultPrevented || form.hasAttribute("data-no-busy")) return;
      var method = (form.getAttribute("method") || "get").toLowerCase();
      var target = form.getAttribute("target");
      if (method !== "post" || (target && target !== "_self")) return;
      form.dataset.submitting = "1";
      var btn = ev.submitter || form.querySelector("button[type=submit], button:not([type]), input[type=submit]");
      // Disable after this task: a disabled submitter would drop its name=value from the request.
      setTimeout(function () { if (btn && form.dataset.submitting) setBusy(btn, true); }, 0);
      // A response that doesn't navigate (a download) must not leave the form locked.
      setTimeout(function () { releaseForm(form); }, 20000);
    });
    // The browser blocked the submit (required field etc.): nothing was sent.
    doc.addEventListener("invalid", function (ev) { if (ev.target.form) releaseForm(ev.target.form); }, true);
    // Back/forward cache restores the page as it was when we left: busy. Undo that.
    window.addEventListener("pageshow", function (ev) { if (ev.persisted) releaseAll(); });
  }

  // ---- popovers: <details class="confirm|edit"> and menus ----
  function closeDetails(d, refocus) {
    if (!d.open || d.classList.contains("is-closing")) return;
    var s = d.querySelector("summary");
    var hadFocus = d.contains(doc.activeElement);
    afterExit(d, "is-closing", function () {
      d.classList.remove("is-closing");
      d.open = false;
      if ((refocus || hadFocus) && s) s.focus({ preventScroll: true });
    });
  }
  function initPopovers() {
    doc.addEventListener("click", function (ev) {
      // Clicking an open popover's own summary: animate the close instead of snapping shut.
      var sum = ev.target.closest("summary");
      var own = sum && sum.parentElement;
      if (own && own.matches(POPOVERS) && own.open) { ev.preventDefault(); closeDetails(own, true); }
      // Clicking anywhere else closes every other open popover.
      $$(POPOVERS.split(", ").map(function (s) { return s + "[open]"; }).join(", ")).forEach(function (d) {
        if (!d.contains(ev.target)) closeDetails(d, false);
      });
    });
  }

  // ---- sidebar: desktop icon rail and phone drawer ----
  var desktop = window.matchMedia ? window.matchMedia("(min-width: 1024px)") : { matches: true };
  function railTitles() {
    var collapsed = root.getAttribute("data-sidebar") === "collapsed";
    $$("#app-sidebar .nav-item").forEach(function (a) {
      var l = a.querySelector(".nav-label");
      if (!l) return;
      if (collapsed) a.setAttribute("title", l.textContent.trim()); else a.removeAttribute("title");
    });
  }
  function initSidebar() {
    var side = doc.getElementById("app-sidebar");
    if (!side) return;
    $$("[data-sidebar-toggle]").forEach(function (b) {
      b.setAttribute("aria-expanded", root.getAttribute("data-sidebar") === "collapsed" ? "false" : "true");
      b.addEventListener("click", function () {
        var collapse = root.getAttribute("data-sidebar") !== "collapsed";
        if (collapse) { root.setAttribute("data-sidebar", "collapsed"); set("sidebar", "collapsed"); }
        else { root.removeAttribute("data-sidebar"); set("sidebar", null); }
        $$("[data-sidebar-toggle]").forEach(function (x) { x.setAttribute("aria-expanded", collapse ? "false" : "true"); });
        railTitles();
      });
    });
    railTitles();

    var menu = doc.getElementById("nav-toggle");
    var main = $(".app-main");
    function isOpen() { return side.classList.contains("nav-open"); }
    function focusables() {
      return $$("a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex='-1'])", side)
        .filter(function (n) { return n.offsetParent !== null || n === doc.activeElement; });
    }
    function open() {
      side.classList.add("nav-open");
      root.classList.add("nav-locked");
      if (menu) menu.setAttribute("aria-expanded", "true");
      if (main) main.inert = true;
      side.setAttribute("role", "dialog");
      side.setAttribute("aria-modal", "true");
      var first = $("[aria-current='page']", side) || focusables()[0];
      if (first) first.focus({ preventScroll: true });
    }
    function close(refocus) {
      if (!isOpen()) return;
      side.classList.remove("nav-open");
      root.classList.remove("nav-locked");
      if (menu) menu.setAttribute("aria-expanded", "false");
      if (main) main.inert = false;
      side.removeAttribute("role");
      side.removeAttribute("aria-modal");
      if (refocus !== false && menu) menu.focus({ preventScroll: true });
    }
    if (menu) menu.addEventListener("click", function () { if (isOpen()) close(); else open(); });
    $$("[data-nav-close]").forEach(function (b) { b.addEventListener("click", function () { close(); }); });
    side.addEventListener("keydown", function (ev) {
      if (!isOpen()) return;
      if (ev.key === "Escape") { ev.preventDefault(); close(); return; }
      if (ev.key !== "Tab") return;
      var f = focusables();
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (ev.shiftKey && doc.activeElement === first) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && doc.activeElement === last) { ev.preventDefault(); first.focus(); }
    });
    var onWide = function () { if (desktop.matches) close(false); };
    if (desktop.addEventListener) desktop.addEventListener("change", onWide);
    window.addEventListener("pageshow", function (ev) { if (ev.persisted) close(false); });
  }

  // ---- command palette: Ctrl/⌘+K or [data-palette-open]; pages come from the sidebar ----
  var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  function fold(s) {
    s = (s || "").toLowerCase();
    try { s = s.normalize("NFD").replace(/[̀-ͯ]/g, ""); } catch (e) { /* old browser */ }
    return s;
  }
  // Subsequence match with a score: word starts and runs score higher, earlier is better.
  function score(q, text) {
    if (!q) return { s: 1, hits: [] };
    var t = fold(text), hits = [], s = 0, ti = 0, run = 0;
    for (var qi = 0; qi < q.length; qi++) {
      var c = q.charAt(qi);
      if (c === " ") continue;
      var found = t.indexOf(c, ti);
      if (found < 0) return null;
      var wordStart = found === 0 || /[\s\-/_.(]/.test(t.charAt(found - 1));
      run = found === ti && qi > 0 ? run + 1 : 0;
      s += 1 + (wordStart ? 6 : 0) + run * 3 - Math.min(found - ti, 6) * 0.2;
      hits.push(found);
      ti = found + 1;
    }
    if (t.indexOf(q) === 0) s += 10;
    return { s: s, hits: hits };
  }
  function paletteEntries() {
    var out = [];
    var seen = {};
    $$("#app-sidebar a.nav-item[href], .user-menu a.menu-item[href]").forEach(function (a) {
      var href = a.getAttribute("href");
      if (!href || seen[href]) return;
      seen[href] = true;
      var label = a.querySelector(".nav-label");
      var nav = a.closest("nav[aria-label]");
      var icon = a.querySelector("i.fas, i.far, i.fab");
      out.push({
        label: (label ? label.textContent : a.textContent).trim(),
        group: nav ? nav.getAttribute("aria-label") : "",
        href: href,
        icon: icon ? Array.prototype.filter.call(icon.classList, function (c) { return /^fa[srb]?$|^fa-/.test(c) && c !== "nav-icon"; }).join(" ") : "",
        current: a.getAttribute("aria-current") === "page"
      });
    });
    var theme = doc.getElementById("theme-toggle");
    if (theme) {
      out.push({ label: theme.getAttribute("aria-label") || "Switch theme", group: "", icon: "fas fa-adjust", run: function () { theme.click(); } });
    }
    return out;
  }
  function buildPalette() {
    var tpl = doc.getElementById("palette-tpl");
    var p = tpl && tpl.content ? tpl.content.firstElementChild.cloneNode(true) : null;
    if (!p) {
      p = el("div", "palette");
      p.setAttribute("role", "dialog");
      p.setAttribute("aria-modal", "true");
      p.setAttribute("aria-label", "Go to page");
      var panel = el("div", "palette-panel");
      var inp = el("input", "palette-input");
      inp.type = "text";
      inp.setAttribute("role", "combobox");
      inp.setAttribute("aria-expanded", "true");
      inp.setAttribute("aria-controls", "palette-list");
      inp.setAttribute("aria-autocomplete", "list");
      inp.setAttribute("autocomplete", "off");
      inp.setAttribute("spellcheck", "false");
      inp.setAttribute("aria-label", "Search pages");
      inp.placeholder = "Jump to a page…";
      var ul = el("ul", "palette-list");
      ul.id = "palette-list";
      ul.setAttribute("role", "listbox");
      var empty = el("p", "palette-empty", "No matching page");
      empty.hidden = true;
      panel.appendChild(inp); panel.appendChild(ul); panel.appendChild(empty);
      p.appendChild(panel);
    }
    return p;
  }
  function initPalette() {
    var entries = null, pal = null, input = null, list = null, empty = null, opener = null, items = [], sel = 0;
    function render() {
      var q = fold(input.value.trim());
      var ranked = [];
      entries.forEach(function (e) {
        var r = score(q, e.label);
        var g = r ? null : score(q, e.group + " " + e.label);
        var best = r || (g && { s: g.s - 5, hits: [] });
        if (best) ranked.push({ e: e, s: best.s + (e.current ? -0.5 : 0), hits: best.hits });
      });
      if (q) ranked.sort(function (a, b) { return b.s - a.s; });
      list.textContent = "";
      items = ranked;
      ranked.forEach(function (r, i) {
        var li = el("li", "palette-item");
        li.id = "pal-" + i;
        li.setAttribute("role", "option");
        if (r.e.icon) { var ic = el("i", r.e.icon); ic.setAttribute("aria-hidden", "true"); li.appendChild(ic); }
        var lab = el("span", "palette-label");
        // Matched characters in <mark>, built node by node (labels are our own, still no innerHTML).
        var hitSet = {};
        r.hits.forEach(function (h) { hitSet[h] = true; });
        var txt = r.e.label, buf = "";
        for (var k = 0; k < txt.length; k++) {
          if (hitSet[k]) {
            if (buf) { lab.appendChild(doc.createTextNode(buf)); buf = ""; }
            lab.appendChild(el("mark", null, txt.charAt(k)));
          } else buf += txt.charAt(k);
        }
        if (buf) lab.appendChild(doc.createTextNode(buf));
        li.appendChild(lab);
        if (r.e.group) li.appendChild(el("span", "palette-group", r.e.group));
        li.addEventListener("mousemove", function () { if (sel !== i) select(i); });
        li.addEventListener("click", function () { go(i); });
        list.appendChild(li);
      });
      empty.hidden = ranked.length > 0;
      select(0);
    }
    function select(i) {
      if (!items.length) { input.removeAttribute("aria-activedescendant"); return; }
      sel = (i + items.length) % items.length;
      $$(".palette-item", list).forEach(function (li, k) { li.setAttribute("aria-selected", k === sel ? "true" : "false"); });
      var cur = doc.getElementById("pal-" + sel);
      input.setAttribute("aria-activedescendant", "pal-" + sel);
      if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: "nearest" });
    }
    function go(i, newTab) {
      var r = items[i];
      if (!r) return;
      if (r.e.run) { close(); r.e.run(); return; }
      if (newTab) { window.open(r.e.href, "_blank", "noopener"); close(); return; }
      close(false);
      location.assign(r.e.href);
    }
    function open(from) {
      if (pal) { input.focus(); input.select(); return; }
      entries = paletteEntries();
      if (!entries.length) return;
      opener = from || doc.activeElement;
      pal = buildPalette();
      input = pal.querySelector(".palette-input");
      list = pal.querySelector(".palette-list");
      empty = pal.querySelector(".palette-empty") || el("p", "palette-empty");
      var shell = $(".app-shell");
      if (shell) shell.inert = true;
      root.classList.add("nav-locked", "palette-open");
      doc.body.appendChild(pal);
      input.addEventListener("input", render);
      input.addEventListener("keydown", function (ev) {
        if (ev.key === "ArrowDown") { ev.preventDefault(); select(sel + 1); }
        else if (ev.key === "ArrowUp") { ev.preventDefault(); select(sel - 1); }
        else if (ev.key === "Home" && ev.ctrlKey) { ev.preventDefault(); select(0); }
        else if (ev.key === "End" && ev.ctrlKey) { ev.preventDefault(); select(items.length - 1); }
        else if (ev.key === "Enter") { ev.preventDefault(); go(sel, ev.ctrlKey || ev.metaKey); }
        else if (ev.key === "Escape") { ev.preventDefault(); close(); }
        else if (ev.key === "Tab") { ev.preventDefault(); select(sel + (ev.shiftKey ? -1 : 1)); }
      });
      // A click on the dim backdrop (the dialog itself, outside the panel) closes it.
      pal.addEventListener("mousedown", function (ev) { if (ev.target === pal) { ev.preventDefault(); close(); } });
      render();
      input.focus();
    }
    function close(refocus) {
      if (!pal) return;
      var p = pal;
      pal = null;
      var shell = $(".app-shell");
      if (shell) shell.inert = false;
      root.classList.remove("nav-locked", "palette-open");
      afterExit(p, "is-closing", function () { p.remove(); });
      if (refocus !== false && opener && opener.focus) opener.focus({ preventScroll: true });
    }
    $$("[data-palette-open]").forEach(function (b) {
      b.addEventListener("click", function () { open(b); });
    });
    if (isMac) $$("[data-palette-open] .palette-kbd, [data-palette-kbd]").forEach(function (k) { k.textContent = "⌘K"; });
    doc.addEventListener("keydown", function (ev) {
      if ((ev.key === "k" || ev.key === "K") && (ev.ctrlKey || ev.metaKey) && !ev.altKey && !ev.shiftKey) {
        if (!$("#app-sidebar")) return;
        ev.preventDefault();
        if (pal) close(); else open(null);
      }
    });
  }

  // ---- keyboard: "/" focuses the page's search field, Esc closes popovers ----
  function typing(t) {
    return t && (t.isContentEditable || /^(INPUT|SELECT|TEXTAREA)$/.test(t.nodeName));
  }
  function initKeys() {
    doc.addEventListener("keydown", function (ev) {
      if (ev.key === "/" && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !typing(ev.target) && !root.classList.contains("palette-open")) {
        var s = $("#main [data-page-search], #main input[type=search], #main .filter-search input, #main input[name=q]");
        if (s && s.offsetParent !== null) { ev.preventDefault(); s.focus(); if (s.select) s.select(); }
        return;
      }
      if (ev.key === "Escape" && !root.classList.contains("palette-open")) {
        var openPops = $$(POPOVERS.split(", ").map(function (x) { return x + "[open]"; }).join(", "));
        if (openPops.length) {
          ev.preventDefault();
          // Innermost first: the one holding focus, else the last opened in document order.
          var inner = openPops.filter(function (d) { return d.contains(doc.activeElement); }).pop() || openPops[openPops.length - 1];
          closeDetails(inner, true);
        }
      }
    });
  }

  // ---- boot ----
  // Toasts for flashes go first so a later failure can't swallow a success message.
  function boot() {
    if (rememberFilters()) return; // navigating to the saved filters
    try { initFlash(); } catch (e) { /* keep going */ }
    $$("#theme-toggle, [data-theme-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        applyTheme(root.getAttribute("data-theme") === "light" ? "dark" : "light");
      });
    });
    doc.addEventListener("click", function (ev) {
      var t = ev.target.closest("[data-toggle-help]");
      if (t) {
        var h = doc.getElementById(t.getAttribute("data-toggle-help"));
        if (h) {
          var open = h.classList.toggle("d-none") === false;
          t.setAttribute("aria-expanded", open ? "true" : "false");
        }
      }
      var f = ev.target.closest("[data-forget]");
      if (f) set("filters:" + f.getAttribute("data-forget"), null);
      var c = ev.target.closest("[data-copy]");
      if (c) copyText(c);
      var d = ev.target.closest("[data-dismiss]");
      if (d) dismissCallout(d);
    });
    // A link to a Setup row (#key) opens that row.
    function openHash() {
      var id = location.hash.slice(1);
      var h = id && doc.getElementById(id);
      if (h && h.tagName === "DETAILS") h.open = true;
    }
    window.addEventListener("hashchange", openHash);
    openHash();
    initPrefs();
    stackTables(doc);
    initSidebar();
    initPopovers();
    initBusy();
    initPalette();
    initKeys();
    initRefresh();
    initUpload();
    var changed = syncTzCookie();
    localizeTimes(doc.body);
    // First visit with a non-UTC zone: redraw charts in local time once.
    if (changed && $(".chart")) location.reload();
  }
  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
