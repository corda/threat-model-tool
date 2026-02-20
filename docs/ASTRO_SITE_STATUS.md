# Astro Starlight Site — Testing & Progress

## Quick Test

```bash
cd threat-model-tool

# Build the site from example TMs
npm run build:astroSite:examples

# Serve locally (port 4321)
npm run serve:astroSite
```

Open <http://localhost:4321/> to view.

## Current Layout

- **Top bar**: Starlight header with site title ("Threat Models"), search (⌘K), and theme toggle
- **Second bar**: Horizontal nav links — Home + one link per TM (active page highlighted)
- **Left panel**: "On this page" TOC with h2/h3 headings (moved from default right position)
- **Main content**: Full-width TM report

## What's Working

- [x] Build pipeline: discover TMs → build reports → stage into Astro → build static site
- [x] MKdocs template (no inline TOC — Starlight generates heading nav)
- [x] PlantUML diagrams rendered as SVG, served from `public/<slug>/img/`
- [x] Pagefind full-text search
- [x] Dark mode
- [x] Top navigation bar (JS-injected from `__TM_NAV_LINKS__`)
- [x] Template folder overlay (`--templateSiteFolderSRC` for extra pages/CSS)
- [x] Duplicate h1 title stripped (Starlight renders frontmatter title)
- [x] Left sidebar hidden via CSS
- [x] Right TOC moved to left via `flex-direction: row-reverse`

## Known Issues / TODO

### 1. "On this page" heading still partially clipped
The TOC panel top offset (`3rem` below nav height) may still not be enough depending on whether the top nav wraps to multiple lines. May need a JS-based approach to measure the actual top nav height and set the offset dynamically.

**File**: `astro-site/src/styles/threatmodel.css` — search for `right-sidebar-container`

### 2. TOC width tuning
The inner `.sl-container` in the TOC panel is forced to `14rem`. This might need adjustment depending on heading length. The override is needed because Starlight computes it from `--sl-sidebar-width` which is set to `0rem`.

**File**: `astro-site/src/styles/threatmodel.css` — search for `.right-sidebar-panel .sl-container`

### 3. Mobile layout not tested
The mobile TOC uses Starlight's default dropdown. The top nav bar wraps on small screens but hasn't been tested on narrow viewports.

### 4. README documentation
The README has been updated with `build:astroSite` docs but may need refinement after layout is finalized.

## Key Files

| File | Purpose |
|------|---------|
| `src/scripts/build-astro-site.ts` | Main orchestrator — CLI, TM discovery, staging, config generation |
| `astro-site/src/styles/threatmodel.css` | All CSS overrides (layout, TOC positioning, top nav, dark mode) |
| `astro-site/public/js/tm.js` | Top nav injection + copy-link-to-heading (vanilla JS) |
| `astro-site/src/content.config.ts` | Astro 5 content collection with `docsLoader()` |
| `astro-site/astro.config.mjs` | Auto-generated at build time — do not edit manually |

## CSS Architecture Notes

Starlight uses these CSS variables for layout sizing:
- `--sl-sidebar-width` — controls left sidebar AND right TOC container width (set to `0rem` since left sidebar is hidden)
- `--sl-content-width` — max content width (set to `75rem`)
- `--sl-nav-height` — header height (used for sticky offsets)

Because `--sl-sidebar-width: 0rem` also zeros out the right TOC, explicit `width` overrides are needed on `.right-sidebar-container`, `.right-sidebar`, and `.right-sidebar-panel .sl-container`.

The layout uses `flex-direction: row-reverse` on `.lg\:sl-flex` to swap the TOC from right to left without changing the HTML structure.
