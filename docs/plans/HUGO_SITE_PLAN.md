# Hugo Docs Site — Implementation Plan

## Goal

Add a **Hugo** static documentation site generation path, produced entirely from the TypeScript tool, as an alternative to Astro Starlight. Running `npm run build:hugoSite` discovers all TMs in a directory, builds each one, and produces a fully navigable static site with:

- all primary links in a **left navigation sidebar**
- **no right-side “On this page” column**
- search support
- dark mode support

## Architecture

```
┌──────────────────────┐
│  TM Directory        │    <name>/<name>.yaml  (convention)
└───────┬──────────────┘
        │  discover
        ▼
┌──────────────────────┐
│  buildFullDirectory  │    Reuses existing directory build logic
│  (per-TM builds)     │    Produces MD + HTML + PlantUML per TM
└───────┬──────────────┘
        │  stage into Hugo content/static
        ▼
┌──────────────────────┐
│  hugo-site/          │    Hugo project scaffolding
│  content/docs/       │    ← MD files (with front matter)
│  static/<TM>/img/    │    ← PlantUML SVGs + images
│  assets/css/         │    ← threatmodel.css (ported from MkDocs)
└───────┬──────────────┘
        │  hugo build
        ▼
┌──────────────────────┐
│  outputDir/          │    Final static site (HTML/CSS/JS)
│  (default: build/site-hugo)
└──────────────────────┘
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Static site framework | **Hugo** | Fast static builds, flexible templating, mature docs ecosystem |
| Theme approach | Hugo Book-style left sidebar (or equivalent custom layout) | Keeps all navigation links on the left |
| Right TOC column | **Disabled globally** | Matches requirement: no right “On this page” column |
| Hugo project location | `threat-model-tool-js/hugo-site/` | Isolated site dependencies and config |
| Image serving | `static/<TM>/img/` | Preserves existing relative `img/` references in generated MD |
| URL style | Pretty URLs + trailing slash | Ensures `/<TM>/` + `img/foo.svg` resolves predictably |
| TM template | `MKdocs` (existing) | Existing output format is already docs-friendly |
| Template site overlay | Supported via `--templateSiteFolderSRC` | Allows custom docs/assets/CSS overlays |
| npm task name | `build:hugoSite` | Dedicated build pipeline for Hugo |

## Implementation Steps

### 1. Scaffold Hugo project (`hugo-site/`)

Create a minimal Hugo project:

```
threat-model-tool-js/hugo-site/
├── hugo.toml                     # base config (updated at build time)
├── content/
│   └── docs/
│       └── _index.md             # docs section landing
├── layouts/
│   ├── _default/
│   │   ├── baseof.html
│   │   └── single.html
│   └── partials/
│       ├── sidebar.html          # left navigation only
│       ├── head-extra.html
│       └── search.html
├── assets/
│   └── css/
│       └── threatmodel.css
├── static/
│   ├── js/
│   │   └── tm.js
│   └── .gitkeep
└── themes/
    └── (optional, if using vendored theme)
```

Notes:
- Keep navigation rendering in `partials/sidebar.html`.
- Do not render any right-column TOC partial.

### 2. Enforce left-only navigation / disable right TOC

Implement layout behavior so links are only on the left:

- Sidebar: render docs tree in left column from section/pages.
- Right TOC: disabled globally via config and templates.
- CSS: ensure content width expands when no right TOC exists.

Recommended Hugo config flags:

```toml
[params]
  showToc = false
  toc = false
```

Template constraints:
- Remove/avoid `{{ .TableOfContents }}` in right-column containers.
- If in-page TOC is needed later, place optional inline TOC at top of article body (not right rail).

### 3. Port CSS for Hugo (`assets/css/threatmodel.css`)

Port from Python `MKDOCS_init/docs/css/threatmodel.css`:
- `.proposal` styling
- `.current` wrapper
- `.tooltip` behavior
- `.anchorLink` / `.linky`
- print styles (`.pagebreak`, margins)

Adjust for Hugo theme tokens:
- map colors to CSS variables
- include dark-mode variable overrides
- avoid framework/theme-specific classes from MkDocs RTD

### 4. Vanilla JS `tm.js` (no jQuery)

Reuse/rewrite JS without jQuery:
- heading copy-link behavior for `h1-h5`
- `copyClipboard()` using DOM APIs
- avoid duplicating theme-provided anchor logic

### 5. Create `src/scripts/build-hugo-site.ts`

Main orchestrator script.

**CLI arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `--TMDirectory <path>` | `.` | Root directory with TM subdirectories |
| `--outputDir <path>` | `./build/site-hugo` | Final static site output directory |
| `--template <name>` | `MKdocs` | Render template used per TM generation |
| `--visibility full\|public` | `full` | Content visibility filter |
| `--templateSiteFolderSRC <path>` | *(none)* | User-provided pages/CSS/assets overlay |
| `--siteName <text>` | `"Threat Models"` | Site title |
| `--baseURL <url>` | `/` | Hugo `baseURL` |
| `--generatePDF` | *(off)* | Also generate PDFs per TM |
| `--no-headerNumbering` | *(on)* | Disable heading auto-numbers |
| `--help` | | Print help |

**Flow:**

1. **Discover TMs** — scan `--TMDirectory` for `<name>/<name>.yaml`
2. **Build each TM** — delegate to existing TM build routine with MKdocs template into staging
3. **Stage into Hugo content/static**
   - Write TM markdown to `hugo-site/content/docs/<TM>/index.md`
   - Inject front matter:
     ```yaml
     ---
     title: "<TM Title> Threat Model"
     weight: <auto-increment>
     ---
     ```
   - Copy TM images to `hugo-site/static/<TM>/img/`
4. **Generate docs landing page** — `hugo-site/content/docs/_index.md` with TM list
5. **Generate/update Hugo config** — set menu/params/baseURL/disable TOC
6. **Apply template folder overlay** (`--templateSiteFolderSRC`)
   - `docs/**/*.md` → `content/docs/`
   - `css/*.css` → `assets/css/`
   - `public/**` or other assets → `static/`
7. **Build Hugo site**
   - run `hugo --minify --destination <tempDist>`
8. **Copy output**
   - `<tempDist>/` → `--outputDir`

### 6. Add npm scripts

In `threat-model-tool-js/package.json`:

```json
"build:hugoSite": "tsx src/scripts/build-hugo-site.ts",
"build:hugoSite:examples": "tsx src/scripts/build-hugo-site.ts --TMDirectory tests/exampleThreatModels --outputDir ./build/site-hugo"
```

### 7. Add VS Code task

In `.vscode/tasks.json`:

```json
{
  "label": "TS: Build Hugo docs site",
  "type": "shell",
  "command": "npm",
  "args": ["run", "build:hugoSite:examples"],
  "options": { "cwd": "${workspaceFolder}/threat-model-tool-js" }
}
```

### 8. Add Makefile target

In root `Makefile`:

```makefile
build-site-hugo-ts:
	cd threat-model-tool-js && npm run build:hugoSite:examples
```

### 9. Update README

Document:
- `build:hugoSite` and `build:hugoSite:examples`
- CLI options and examples
- left-only navigation design and how to customize sidebar structure

## Image Path Resolution

```
TM page:    content/docs/<TM>/index.md    → served at /docs/<TM>/
TM images:  static/<TM>/img/              → served at /<TM>/img/
MD ref:     img/foo.svg                   → resolves relative to /docs/<TM>/
```

Implementation note:
- If Hugo page bundle resolution needs stronger guarantees, use one of:
  - keep images in page bundle (`content/docs/<TM>/img/*`) and keep refs as `img/...`, or
  - rewrite `img/...` references to absolute `/<TM>/img/...` during staging.

Choose one strategy and keep it consistent across all generated docs.

## Template Site Folder Support

Support user overlays similar to Python behavior:

```
user-template/
├── docs/
│   ├── extra-page.md          → content/docs/extra-page.md
│   └── css/
│       └── custom.css         → assets/css/custom.css (included in build)
├── public/
│   └── logo.png               → static/logo.png
└── data/
    └── menu.yaml              → optional custom nav metadata
```

Overlay rule:
- user-provided files override scaffold defaults when paths conflict.

## Navigation Model (Left Sidebar)

To guarantee all links stay on the left:

- Sidebar source:
  - generated from `content/docs` hierarchy (and optional menu metadata)
- Ordering:
  - use `weight` in front matter for TM ordering
- Right rail:
  - disabled entirely in templates/config
- Mobile:
  - sidebar collapses into drawer, still the primary nav source

## Verification Checklist

- [ ] `npm run build:hugoSite:examples` completes without errors
- [ ] Static output exists in `build/site-hugo/` with `index.html`
- [ ] Left sidebar lists all TMs and extra pages
- [ ] No right-side “On this page” column appears on TM pages
- [ ] TM pages render with expected styling (`.proposal`, `.tooltip`, tables)
- [ ] SVG diagrams load from markdown image references
- [ ] Search indexes TM content
- [ ] Dark mode remains readable with TM CSS
- [ ] `--templateSiteFolderSRC` overlays pages/CSS/assets successfully
