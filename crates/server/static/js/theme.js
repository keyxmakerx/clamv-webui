// Runs before first paint so the saved theme never flashes.
(function () {
  var t = null;
  try { t = localStorage.getItem("theme"); } catch (e) { /* storage blocked */ }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", t);
  // Lets the stylesheet fold the menu on narrow screens only when script can reopen it.
  document.documentElement.classList.add("js");
})();
