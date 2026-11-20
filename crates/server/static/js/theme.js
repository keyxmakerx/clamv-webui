// Runs before first paint so the saved theme never flashes.
(function () {
  var t = null;
  try { t = localStorage.getItem("theme"); } catch (e) { /* storage blocked */ }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", t);
  // Motion preference: "reduce" or "full" overrides the OS setting; unset follows it.
  var m = null;
  try { m = localStorage.getItem("motion"); } catch (e) { /* storage blocked */ }
  if (m === "reduce" || m === "full") document.documentElement.setAttribute("data-motion", m);
  // Desktop sidebar folded to an icon rail (remembered); applied before paint so it never jumps.
  var c = null;
  try { c = localStorage.getItem("sidebar"); } catch (e) { /* storage blocked */ }
  if (c === "collapsed") document.documentElement.setAttribute("data-sidebar", "collapsed");
  // Lets the stylesheet fold the menu on narrow screens only when script can reopen it.
  document.documentElement.classList.add("js");
})();
