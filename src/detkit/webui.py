"""Chrome shared by the generated pages: palette, nav, and the hover-tooltip widget.

Both `site/index.html` and `site/about.html` are single self-contained files with
no external assets, so anything they share has to be a Python constant rather
than a stylesheet they both link. Keeping it here means the two pages cannot
drift apart visually, and the tooltip behaviour is defined once.

Tooltip contract: any element carrying `data-tip` (literal HTML, escaped with
``tip_attr``) or `data-tipid` (a key into the page's ``TIPS`` object) shows a
panel after a deliberate hover delay. Keyboard focus and tap show it immediately.
"""
from __future__ import annotations

import html

# How long the pointer must rest before the panel appears. Long enough that it
# never fires while the eye is passing over a card, short enough to feel like an
# answer rather than a wait.
TIP_DELAY_MS = 600

PALETTE = """
  :root { --bg:#0d1117; --card:#161b22; --line:#30363d; --fg:#e6edf3;
          --muted:#8b949e; --accent:#58a6ff; --ok:#3fb950; --warn:#d29922;
          --bad:#ff7b72; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
  a { color:var(--accent); }
  nav.top { border-bottom:1px solid var(--line); background:#0d1117f2; position:sticky;
            top:0; z-index:20; backdrop-filter:blur(6px); }
  nav.top div { max-width:1100px; margin:0 auto; padding:10px 24px; display:flex;
                gap:18px; align-items:center; font-size:14px; }
  nav.top a { color:var(--muted); text-decoration:none; padding:4px 0;
              border-bottom:2px solid transparent; }
  nav.top a:hover { color:var(--fg); }
  nav.top a.on { color:var(--fg); border-bottom-color:var(--accent); }
  nav.top .spacer { flex:1; }
"""

TIP_CSS = """
  [data-tip], [data-tipid] { cursor:help; }
  .tip { position:absolute; z-index:50; max-width:380px; width:max-content;
         background:#1c2129; border:1px solid #3d444d; border-radius:10px;
         padding:12px 14px; box-shadow:0 10px 34px #000a; font-size:13px;
         line-height:1.5; color:var(--fg); opacity:0; visibility:hidden;
         transition:opacity .12s ease; pointer-events:none; text-align:left;
         text-transform:none; letter-spacing:normal; font-weight:400; }
  .tip.on { opacity:1; visibility:visible; }
  .tip b.h { display:block; font-size:13.5px; margin:0 0 6px; color:var(--fg); }
  .tip p { margin:0 0 7px; color:#c9d1d9; }
  .tip p:last-child { margin-bottom:0; }
  .tip .calc { display:block; background:#0d1117; border:1px solid var(--line);
               border-radius:6px; padding:7px 9px; margin:0 0 7px;
               font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
               font-size:12.5px; color:var(--accent); white-space:normal; }
  .tip code { background:#0d1117; border-radius:4px; padding:1px 4px; font-size:12px; }
  .tip .src { color:var(--muted); font-size:12px; border-top:1px solid var(--line);
              padding-top:7px; }
  .tip .gate { font-size:12px; color:var(--muted); }
  .tip .pass { color:var(--ok); font-weight:600; }
  .tip .fail { color:var(--bad); font-weight:600; }
"""

# Delegated so it also covers cards rendered after load. Content resolves from
# `data-tip` (literal HTML) or `data-tipid` (a key into the page's TIPS map),
# which keeps JS-built tooltips out of attribute-escaping territory.
TIP_JS = """
(function () {
  const DELAY = __TIP_DELAY__;
  const SEL = '[data-tip],[data-tipid]';
  let panel = null, timer = null, current = null;

  function body(el) {
    return el.dataset.tip || (window.TIPS || {})[el.dataset.tipid] || '';
  }
  function ensure() {
    if (!panel) {
      panel = document.createElement('div');
      panel.className = 'tip';
      panel.setAttribute('role', 'tooltip');
      document.body.appendChild(panel);
    }
    return panel;
  }
  function show(el) {
    const content = body(el);
    if (!content) return;
    const t = ensure();
    t.innerHTML = content;
    // Measured while hidden: visibility:hidden still lays out, so the panel
    // never flashes in the wrong place before being positioned.
    const r = el.getBoundingClientRect(), w = t.offsetWidth, h = t.offsetHeight;
    let x = r.left + r.width / 2 - w / 2;
    x = Math.max(10, Math.min(x, document.documentElement.clientWidth - w - 10));
    let y = r.top - h - 10;
    if (y < 10) y = r.bottom + 10;
    t.style.left = (x + window.scrollX) + 'px';
    t.style.top = (y + window.scrollY) + 'px';
    t.classList.add('on');
    current = el;
  }
  function hide() {
    clearTimeout(timer);
    if (panel) panel.classList.remove('on');
    current = null;
  }
  document.addEventListener('mouseover', function (e) {
    const el = e.target.closest(SEL);
    if (!el || el === current) return;
    hide();
    timer = setTimeout(function () { show(el); }, DELAY);
  });
  document.addEventListener('mouseout', function (e) {
    if (e.target.closest(SEL)) hide();
  });
  document.addEventListener('focusin', function (e) {
    const el = e.target.closest(SEL);
    if (el) { hide(); show(el); }
  });
  document.addEventListener('focusout', hide);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hide(); });
  window.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
  document.addEventListener('click', function (e) {
    const el = e.target.closest(SEL);
    if (!el) { hide(); return; }
    if (current === el) { hide(); } else { hide(); show(el); }
  });
})();
""".replace("__TIP_DELAY__", str(TIP_DELAY_MS))


def tip_attr(markup: str) -> str:
    """Escape a tooltip's HTML for use as an attribute value.

    The parser decodes the attribute back to exactly `markup`, so tags inside it
    stay tags and literal angle brackets stay literal.
    """
    return html.escape(markup, quote=True)


def nav(active: str) -> str:
    """Site navigation. `active` is 'index' or 'about'."""
    def link(href: str, key: str, label: str) -> str:
        cls = ' class="on"' if key == active else ""
        return f'<a href="{href}"{cls}>{label}</a>'

    return (
        '<nav class="top"><div>'
        + link("index.html", "index", "Coverage")
        + link("about.html", "about", "How it works")
        + '<span class="spacer"></span>'
        + '<a href="https://github.com/canmenzo/detection-engineering">GitHub ↗</a>'
        + "</div></nav>"
    )
