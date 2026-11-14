// Passkeys: add one (account page), sign in with one, or use one as the second step.
(function () {
  "use strict";
  function toBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function toB64u(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function showError(msg) {
    var el = document.getElementById("passkey-error");
    if (el) { el.textContent = msg; el.classList.remove("d-none"); }
  }
  async function post(url, body) {
    var r = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    var j = {};
    try { j = await r.json(); } catch (e) { /* not JSON */ }
    if (!r.ok) throw new Error(j.error || "Request failed (" + r.status + ").");
    return j;
  }
  function supported() {
    if (!window.PublicKeyCredential || !window.isSecureContext) {
      showError("Passkeys need HTTPS (or localhost) and a browser that supports them.");
      return false;
    }
    return true;
  }
  async function register(btn) {
    var csrf = btn.getAttribute("data-csrf");
    var nameEl = document.getElementById("passkey-name");
    var opt = await post("/account/passkeys/options", { csrf: csrf });
    var pk = opt.publicKey;
    pk.challenge = toBytes(pk.challenge);
    pk.user.id = toBytes(pk.user.id);
    pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) { return { type: c.type, id: toBytes(c.id) }; });
    var cred = await navigator.credentials.create({ publicKey: pk });
    var res = await post("/account/passkeys", {
      csrf: csrf,
      handle: opt.handle,
      name: nameEl ? nameEl.value : "",
      clientDataJson: toB64u(cred.response.clientDataJSON),
      attestationObject: toB64u(cred.response.attestationObject)
    });
    window.location.assign(res.redirect || "/account/security");
  }
  async function signIn(mode) {
    var opt = await post("/login/passkey/options", { mode: mode });
    var pk = opt.publicKey;
    pk.challenge = toBytes(pk.challenge);
    pk.allowCredentials = (pk.allowCredentials || []).map(function (c) { return { type: c.type, id: toBytes(c.id) }; });
    var cred = await navigator.credentials.get({ publicKey: pk });
    var res = await post("/login/passkey", {
      handle: opt.handle,
      id: toB64u(cred.rawId),
      clientDataJson: toB64u(cred.response.clientDataJSON),
      authenticatorData: toB64u(cred.response.authenticatorData),
      signature: toB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? toB64u(cred.response.userHandle) : null
    });
    window.location.assign(res.redirect || "/dashboard");
  }
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-passkey]");
    if (!btn) return;
    ev.preventDefault();
    if (!supported()) return;
    var mode = btn.getAttribute("data-passkey");
    btn.disabled = true;
    var job = mode === "register" ? register(btn) : signIn(mode);
    job.catch(function (e) {
      showError(e && e.name === "NotAllowedError" ? "Cancelled or timed out." : (e.message || String(e)));
    }).finally(function () { btn.disabled = false; });
  });
})();
