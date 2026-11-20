# Palisade UI design system

A calm, dense, professional security console. Neutral slate surfaces, one accent colour, and semantic
colours reserved for status. Dark and light themes are equally supported (dark is the default and follows
the OS). Everything works without JavaScript; script only adds convenience.

Priorities, in order: stability, correctness and security, then useful quality-of-life features, then
looks and motion. Never break a working flow to make it prettier.

## Files

| File | Owner area | Contents |
|---|---|---|
| `static/css/all.css` + `webfonts/` | icons | Font Awesome 5 (self-hosted) |
| `static/css/app.css` | foundation | tokens, reset, Bootstrap-compatible utilities, shell, shared components |
| `static/css/ops.css` | operations pages | dashboard, charts, map, jobs, detections, timeline, host checks, CrowdSec |
| `static/css/admin.css` | admin/account pages | setup checklist, forms, secrets, danger zones |
| `static/css/motion.css` | motion | keyframes, view transitions, reduced-motion kill switch |
| `static/js/theme.js` | pre-paint | sets `data-theme`, `data-motion`, `data-sidebar` and `.js` on `<html>` before first paint |
| `static/js/script.js` | behaviour | everything interactive (see [Interaction](#interaction)) |

Load order (base.html): `all.css → app.css → ops.css → admin.css → motion.css`. Plain CSS, single-class
selectors, no `!important` (except in the reduced-motion kill switch), no build step.

Hard constraints: strict CSP (`script-src 'self'; style-src 'self'`): no inline `<script>`, `<style>` or
`style="…"` (also not in SVG generated in Rust); no external fonts or CDNs; no new JS libraries. JS never
inserts untrusted text with `innerHTML`.

## Tokens

Use only these; they are defined on `:root` (dark), `html[data-theme="light"]`, and a media-query copy of
the light set for script-off visitors whose OS prefers light.

| Group | Tokens |
|---|---|
| Surfaces | `--bg` (page) · `--bg-subtle` (sidebar, code, row hover) · `--surface` (cards) · `--surface-2` (table head, muted badges) · `--surface-raised` (menus, popovers, palette, toasts) · `--input-bg` |
| Lines | `--border` (dividers, card edges) · `--border-strong` (anything you type in or click that has an outline; ≥ 3:1) |
| Text | `--text` · `--text-muted` (secondary) · `--text-subtle` (captions, icons) |
| Accent | `--accent` · `--accent-hover` · `--accent-fg` (text on accent) · `--accent-soft` (selected/tinted bg) · `--focus` |
| Status | `--ok --warn --danger --info`, each with `-soft` (bg) and `--ok-fg --warn-fg --danger-fg` (text on a solid tone) |
| Charts | `--chart-clean --chart-hit --chart-fail` |
| Space | `--sp-1..7` = 4, 8, 12, 16, 24, 32, 48 px |
| Radius | `--r-sm` 6 (controls) · `--r-md` 10 (cards, callouts) · `--r-lg` 14 (dialogs, sign-in) · `--r-pill` |
| Type | `--font-sans` (system), `--font-mono`; `--fs-xs` .75 · `--fs-sm` .875 (body, 14px) · `--fs-md` 1 · `--fs-lg` 1.125 · `--fs-xl` 1.375 (page title) · `--fs-2xl` 1.75 (stat values) rem; numbers tabular (`.num`) |
| Elevation | `--shadow-sm` (cards) · `--shadow-md` (sign-in) · `--shadow-lg` (menus, drawer, palette, toasts) |
| Layout | `--sidebar-w` 248px · `--sidebar-w-collapsed` 64px · `--topbar-h` 56px · `--content-max` 1440px |
| Layers | `--z-nav` 100 < `--z-popover` 200 < `--z-overlay` 300 (drawer, palette) < `--z-toast` 400 |
| Motion | `--dur-instant` 80ms · `--dur-fast` 140ms · `--dur-base` 220ms · `--dur-slow` 360ms; `--ease-out` (enter, feedback) · `--ease-in-out` (exit, swap) · `--ease-emph` (rare overshoot) |

Contrast (WCAG relative luminance, dark / light): `--text` on `--surface` 14.7 / 17.1 · `--text-muted` 8.2 / 7.3 ·
`--text-subtle` 6.0 / 5.4 · `--accent` links 6.4 / 5.8 · `--accent-fg` on `--accent` 6.7 / 5.8 · each status
tone ≥ 5.9 on `--surface` and ≥ 5.0 on its `-soft` bg · `--border-strong` 3.5 / 3.3 · `--focus` 8.7 / 5.8.
Status colour only means status; decoration uses neutrals and the accent.

## Shell

- **Sidebar** (`#app-sidebar`): brand mark, groups *Operations* / *Administration* (admins only, role-filtered
  on the server), `a.nav-item > i.nav-icon + span.nav-label`, current page `aria-current="page"`. On desktop
  (≥ 1024px) "Collapse sidebar" folds it to a 64px icon rail (`html[data-sidebar="collapsed"]`, remembered in
  `localStorage.sidebar`, applied before paint; links get `title` tooltips while folded).
- **Narrow (< 1024px):** an off-canvas drawer opened by `#nav-toggle` (`.nav-open`): scrim, focus moved in, Tab
  trapped, Esc / scrim / close button dismiss, focus returns to the toggle, the page behind is `inert`. Without
  script the menu sits above the page as a compact link grid.
- **Topbar:** breadcrumb (group / page), search & jump (`[data-palette-open]`, Ctrl K / ⌘K), theme toggle, user
  menu (`<details class="user-menu" data-menu>`: account, sign-out form). Script-only buttons hide without `.js`.
- **Flash messages** render server-side in `.flash-region` as callouts (`role="alert"` errors, `role="status"`
  success). With script, success messages become toasts (6 s or longer for long text, paused while hovered or
  focused); errors stay in the page and get a dismiss button.

## Components (app.css)

`.page-head` (`.page-head-text` > `h1.page-title` + `.page-sub`; `.page-actions`) · `.card` (`.card-head` with
`.card-title`/`.card-sub`/`.card-actions`; `.card-body`; `.card-foot`; `.card-table`) · `.stat-grid > .stat`
(`.stat-label`, `.stat-value`, `.stat-delta`, `.is-ok/-warn/-danger/-info`; `.kpi*` aliases) · `.badge` +
`.badge-ok/-warn/-danger/-info/-accent/-muted` (`bg-*` aliases, `.badge-solid`) · `.status-dot` + tones
(`.is-muted` hollow, `.is-live` pulses) · `.empty-state` (`-icon`, `-title`, `-text`, `-action`) · `.toolbar`,
`.filter-bar`, `.chip`, `.seg > .seg-btn` · `.kv` · `.table` (`-sm`, `-sticky`, `-responsive`; phones stack rows
into cards via `data-label` added by script) · `.tabs > .tab` · `.callout` + tones · `.code-block` + `[data-copy]`
· `.confirm`/`.confirm-box`, `.edit`/`.edit-form` · `.toast-region > .toast` · `.palette*` · `.skeleton`.
Buttons: `.btn` + `-primary` (one per view), `-secondary`, `-outline-*`, `-danger` (destructive only), `-warning`,
`-success`, `-ghost`, `-link`, `-sm`, `-lg`; `.icon-btn`. Forms: `.form-label`, `.form-control`, `.form-select`,
`.form-text`, `.form-check*`. Layout: `.grid-two`, `.grid-three`, `.stack`, Bootstrap-style `row`/`col-*`/`g-*`
and spacing utilities. Phones (≤ 700px) get 44px targets automatically; focus is always visible.

## Page patterns

**Every page:** page head (title, one-line purpose, primary action or range `.seg` on the right), then cards.
Empty data shows an `.empty-state` saying what will appear and how to get it ("Not set up yet" panels reuse the
Setup fix partial). Don't hide content that must be announced; clip it with `.visually-hidden`.

**Operations** (`ops.css`, `charts.rs`): `.ops-page` gives a 16px rhythm (no `mt-*` spacers); long pages split
into `section.ops-section` with an anchor `.seg` in the head.
- *Dashboard answers "is everything OK?" first:* `.dash-status.is-ok|warn|danger` headline ("All clear" / "N checks
  need attention") with `.dash-checks` tiles (scanners, detections, failed scans, EICAR control, agents; tiles link
  only where the role may go), then latest detections, the "Trends" KPIs, the activity chart and top lists.
- *Verdicts:* OK `badge-ok`, VIRUS_FOUND `badge-danger`, ERROR `badge-warn`, pending `badge-muted` (+ `.live-dot`
  while running). Sensors: ClamAV danger, Canary warn, Integrity info, CrowdSec accent, Falco muted. Signatures are
  `.sig-text` (mono, danger colour); job types/tools `.kind`; bad rows `.row-danger`/`.row-warn` (3px inset bar).
- *Tables:* `section.card > .table-responsive > table.table.table-sm.ops-table`, `nav.pager` at the end; long
  histories (Host checks, Timeline) scroll in `.table-scroll` with a sticky head (desktop).
- *Search + facets:* `form.filter-bar` then `.det-layout` (248px `aside.facets` of `.facet-card`s beside results;
  under 1000px results first). Active filters show as removable `a.chip.chip-active`.
- *Charts:* `charts::stacked()` SVG, `role="group"` + `<title>/<desc>`, every bar an `<a>` with `aria-label` (Tab
  reaches it), hover/focus band + value label, others dim. Bars grow once from the baseline (`.chart-grow`, added
  only on full page loads, never on refresh swaps). Attack map: one focusable `<a>` per dot.
- *Coverage:* host cards (score, coloured rule, per-protection list in `details#cov-host-N`), then the threat ×
  host matrix (state by colour and shape). *Timeline:* incidents as `section.card.incident` with an `ol.tl-list`
  rail, then the full table with linked rows tinted.

**Administration and account** (`admin.css`):
- *List pages:* the create form is a `details.card.add-panel` under the page head: closed when the list has rows,
  open when it is empty, after a validation error or when `#add-x` is in the URL. The list card follows; row
  actions cluster in `.row-actions`, in-place edits use `details.edit > form.edit-form`.
- *Forms:* every control has a visible label; help in `.form-text` via `aria-describedby`; `.form-stack` >
  `.form-grid` of `.field`s (`.field-wide`), grouped in `fieldset.form-section` when longer than ~5 fields;
  `.check-grid` for checkbox groups; `.form-actions` (primary first); long settings use `.setting-row`s and a
  sticky `.form-actions-sticky` bar, and nothing is saved until the review page.
- *Destructive actions:* always `details.confirm > summary.btn.btn-sm.btn-outline-danger > .confirm-box` with one
  sentence on what happens and whether it can be undone, and a solid `btn-danger` that names the action. Merely
  disruptive actions (new agent token, reset 2FA) use `btn-outline-warning`.
- *Secrets shown once:* `.card.secret-reveal` (warn head, "shown once" badge, `role="alert"`) at the top, the value
  in `.secret-value` with a primary Copy button and one line on where to store it; never re-rendered on reload.
- *Step-up:* `_confirm.html` ("Confirm it's you") card; collapses to an ok callout once confirmed.
- *Setup checklist:* progress summary, then numbered groups (Required, Recommended, Optional) of `details.setup-row`
  rows with a status disc (done / warn / danger / pending / off; problems open by default) whose body shows what it
  gives, the compose snippet with Copy, steps and docs links.
- *Account:* security (password, 2FA, passkeys) and display preferences (theme, motion, time zone, clock), stored
  per browser.

## Motion

Motion explains a state change; it never decorates.

- **Durations:** feedback ≤ `--dur-fast`, entering ≤ `--dur-base`, large surfaces ≤ `--dur-slow`. Exits are
  faster than entrances (popovers close in `--dur-instant`).
- **Properties:** only `opacity` and `transform` move; colour may fade on hover. Never animate width,
  height, top or left. Hover changes colour only (no lifts).
- **Write transitions with tokens:** `transition: opacity var(--dur-fast) var(--ease-out)`.
- **No infinite animation** except genuine live indicators (`.status-dot.is-live`, `.live-dot`, the busy
  spinner), which stop under reduced motion.
- **Never animate numbers.** A security console must never show a value that isn't real.
- **Refresh swaps** (`[data-refresh-region]`) must not flash or shift layout; don't put entrance animations
  inside a region (they would replay on every swap). Changed values get `.is-changed`: a 1.2 s accent tint
  that fades (a ring on badges); under reduced motion a steady tint for the same time.
- **Catalogue (motion.css):** popovers and menus `pal-pop-in` (4px rise + fade, `--dur-fast`); toasts
  `pal-toast-in` (8px rise, `--dur-base`) / `pal-toast-out`; flash callouts `pal-rise-in`; palette fade +
  pop; drawer slide (app.css, `--dur-base`); busy button spinner; live-dot ping.
- **Page navigation:** cross-document View Transitions (`@view-transition { navigation: auto }`) where the
  browser supports them. Sidebar, topbar and toasts are named and held still; only the page under them
  cross-fades (`--dur-fast` out, `--dur-base` in). The phone drawer never takes part.
- **Reduced motion:** `--dur-*` become 0ms under `prefers-reduced-motion: reduce` and under
  `html[data-motion="reduce"]`; motion.css adds a kill switch (`animation/transition-duration: .01ms
  !important`, one iteration, no smooth scrolling, no view-transition animation) for anything that
  forgot the tokens. **Account > Display preferences > Motion** offers *Follow the system* (default),
  *Reduce* and *Full*. *Full* overrides an OS "reduce" setting: it is an explicit choice made in this app
  for this browser, and nothing here moves far, parallaxes, auto-plays or loops apart from live dots.

## Interaction

| Feature | How |
|---|---|
| Command palette | Ctrl/⌘ K or `[data-palette-open]`. Pages come from the sidebar DOM (so only what the role can see) plus Account and the theme switch. Fuzzy, accent-insensitive; ↑ ↓, Enter (Ctrl/⌘ Enter opens a new tab), Esc. ARIA combobox + listbox with `aria-activedescendant`. Markup: `<template id="palette-tpl">` in shell.html. |
| Page search | `/` focuses `[data-page-search]`, else the first search field in `#main`. |
| Popovers | `details.confirm`, `details.edit`, `details[data-menu]`: animated open/close, Esc closes the innermost and returns focus to its summary, a click outside closes, one open at a time. |
| Busy submit | POST forms: the clicked button gets `disabled`, `aria-busy="true"` and `.is-busy` (spinner) after the request starts; a second click or Enter is ignored. Released on back/forward-cache restore, when the browser blocks the submit (`invalid`), and after 20 s (downloads). Opt out: `data-no-busy`. |
| Background refresh | Regions refresh by id with `X-Palisade-Refresh: 1` (not counted as activity). A region is skipped while a field in it is focused or a popover/ad-hoc disclosure in it is open. After a swap: focus, open/closed state of `details[id]` and table scroll are restored; changed cells get `.is-changed`. Hooks: `data-live="off"` (never highlight), `data-key` on `<tr>` (row identity; default id or first link). |
| Copy | `[data-copy="id"]` copies that element's text, keeps its width, announces "Copied" politely. |
| Preferences | `#pref-theme`, `#pref-motion`, `#pref-tz`, `#pref-clock` (localStorage `theme`, `motion`, `tz`, `clock`). |
| Translatable JS strings | `#js-strings` data attributes; upload messages via `data-msg-*` on `form[data-upload]`. |

## Accessibility checklist

Skip link to `#main`; visible `:focus-visible` ring (`--focus`); `aria-current="page"`; every control
labelled; flash `role="alert"`/`"status"`; 44px touch targets on phones; text ≥ 4.5:1, UI ≥ 3:1 in both
themes; nothing relies on colour alone (badges carry words); keyboard reaches everything; reduced motion
respected; pages work with JavaScript off.

## Animation audit of the previous UI (summary)

Before the redesign, motion was limited to hover lifts (`translateY`) on sidebar links and KPI cards,
a slide on toggle switches and Bootstrap's colour transitions. None of the custom CSS honoured
`prefers-reduced-motion`; dead PJAX spinners and loaders were left in the stylesheet; `backdrop-filter`
blur over a fixed gradient made scrolling expensive. Background refreshes did not shift the layout (CLS 0),
but they dropped keyboard focus to `<body>` on every swap, closed open confirm popovers, re-opened Setup
rows the user had closed and reset table scroll. There was no busy state, so a double click could submit
twice, and the phone menu had no scrim, Esc or focus handling. All of these are addressed above.
