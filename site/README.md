# Explainer site

The illustrated short version of SATM, published to GitHub Pages at
**<https://yorkerhodes3.github.io/sovereign-agent-trust-mesh/>**.

```
site/
  index.html          the problem, the binding, revocation, status
  how-it-works.html   checks B1–B15 and V1–V8, and why the ordering matters
  evidence.html       proven vs measured vs merely specified
  architecture.html   six planes, components, two-sided enforcement, threats
  404.html
  assets/
    style.css
    diagrams/*.svg    hand-authored
```

## Why there is no build step

Plain HTML, CSS and SVG. No Jekyll, no static-site generator, no npm, no CDN,
no JavaScript required for anything on the page.

That is a deliberate choice rather than laziness:

- **A docs site with a toolchain is a docs site that eventually stops
  building.** This one has no dependency that can drift, deprecate, or pull a
  compromised transitive package.
- **`docs/` already holds markdown** that Jekyll would try to render, so the
  usual `/docs` Pages source was not available without disruption.
- **It can be verified locally in full.** `python -m http.server` serves the
  exact bytes GitHub will serve.

## Diagrams

Hand-authored SVG here; **Mermaid in the markdown docs** (`SPECIFICATION.md` has
five). That split is deliberate, and the dividing line is *what the layout is
doing*:

- **Mermaid for sequences and flowcharts**, where layout is mechanical —
  participants across the top, time down. Auto-layout is exactly right, and
  GitHub renders it natively in markdown at zero cost.
- **Hand-authored SVG for conceptual diagrams**, where the layout carries the
  argument. `missing-joint.svg` is about an *absence* — Mermaid draws
  connections, so a missing arrow reads as an unfinished diagram rather than as
  the thesis. `attestation.svg` is a two-panel before/after comparison, which
  Mermaid has no primitive for.

`revocation.svg` is a linear pipeline and would convert to Mermaid cleanly if
someone prefers that; it is hand-authored only for consistency with its three
neighbours.

Two practical reasons this site does not pre-render Mermaid: the output bakes in
one palette at render time, which would break the `prefers-color-scheme`
switching below; and `mermaid-cli` pulls npm and puppeteer into a repo that
currently has no npm dependencies at all.

Each SVG:

- carries `<title>` and `<desc>`, referenced by `aria-labelledby`, so it is
  meaningful to a screen reader and not merely decorative;
- embeds its own `<style>` including a `prefers-color-scheme` block, so it
  themes itself even when loaded through `<img>`, where the parent page's CSS
  custom properties do not reach;
- uses the same semantic colours as the site — green for verified, amber for
  changed or unproven, red for a denial or an attack.

The trade-off to be aware of: absolute coordinates mean adding a box usually
means re-laying out its neighbours. That is the price of the control, and it is
why anything sequence-shaped should go in markdown as Mermaid instead.

## Editing

Run the checks before pushing. CI runs the identical ones — it calls this same
script rather than an inlined copy, because an inlined copy drifts. The first
version of the Pages workflow inlined it and immediately failed on paths the
local script handled correctly.

```bash
python tools/check-site.py          # markup well-formed, references resolve
python -m http.server -d site 8099  # preview at http://127.0.0.1:8099
```

`tools/check-site.py` verifies that every SVG parses as XML, that every HTML tag
is balanced and closed in order, that every relative `href`/`src` resolves to a
file that exists, and that every in-page `#anchor` has a matching `id`.

It has been negative-tested: an unclosed tag, a dead link, a dangling anchor and
a malformed SVG are each detected and fail the build.

### Use relative paths, never root-relative

This is a **project** Pages site, so it is served from
`/sovereign-agent-trust-mesh/`, not from the domain root. A link to
`/assets/style.css` resolves to `yorkerhodes3.github.io/assets/style.css` and
404s in production while looking perfectly fine in local preview.

Write `assets/style.css`. The site is flat, so relative paths always work — and
they keep local preview honest, since it then exercises the same resolution the
live site does.

## Keeping it honest

The site states test counts and status claims. Those go stale silently, which is
worse than not stating them.

When the numbers change, update:

- the `.stats` block on `index.html` and `evidence.html`,
- the status table on `index.html`,
- the tier-three "specified, but not yet proven" table on `evidence.html`.

Current figures came from `go test ./... -v`, `go test -tags integration -list`,
and `forge test --summary`. Prefer re-running those over trusting the page.
