# Astro Starlight Docs Site — Implementation Plan

## Goal

Replace the Python MkDocs site-generation step with an **Astro Starlight** static documentation site, generated entirely from the TypeScript tool. Running `npm run build:astroSite` discovers all TMs in a directory, builds each one, and produces a fully navigable static site with sidebar, search, and dark mode.

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
        │  stage into Starlight
        ▼
┌──────────────────────┐
│  astro-site/         │    Starlight project scaffolding
│  src/content/docs/   │    ← MD files (with injected frontmatter)
│  public/<TM>/img/    │    ← PlantUML SVGs + images
│  src/styles/         │    ← threatmodel.css (ported from MkDocs)
└───────┬──────────────┘
        │  astro build
        ▼
┌──────────────────────┐
│  outputDir/          │    Final static site (HTML/CSS/JS)
│  (default: build/site)│    Ready to serve or deploy
└──────────────────────┘
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Static site framework | **Astro Starlight** | Built-in sidebar, search (Pagefind), dark mode, responsive |
| Astro project location | `threat-model-tool-js/astro-site/` | Isolated deps; users who don't need site generation don't pay the cost |
| Image serving | `public/<TM>/img/` | Preserves existing relative `img/` paths in MD — no rewriting needed |
| Trailing slash | `trailingSlash: 'always'` | Ensures `/<TM>/` + `img/foo.svg` = `/<TM>/img/foo.svg` |
| TM template | `MKdocs` (existing) | TOC-less variant — Starlight handles TOC natively |
| Template site overlay | Supported via `--templateSiteFolderSRC` | User can add extra pages (`.md`), CSS, and assets — overlaid on scaffold |
| npm task name | `build:astroSite` | Dedicated task, takes CLI args for directory/output/options |

## Implementation Steps

### 1. Scaffold Starlight project (`astro-site/`)

Create a minimal Astro Starlight project:

```
threat-model-tool-js/astro-site/
├── package.json              # astro + @astrojs/starlight deps
├── astro.config.mjs          # Base config (overwritten at build time)
├── tsconfig.json              # Extends astro/tsconfigs/strict
├── src/
│   ├── content/
│   │   └── docs/
│   │       └── .gitkeep      # Populated at build time
│   └── styles/
│       └── threatmodel.css   # Ported from Python MKDOCS_init
├── public/
│   ├── js/
│   │   └── tm.js             # Vanilla JS (no jQuery) heading copy-link
│   └── .gitkeep
└── .gitignore                 # node_modules/, dist/, src/content/docs/*
```

### 2. Port CSS for Starlight (`src/styles/threatmodel.css`)

Port from Python's `MKDOCS_init/docs/css/threatmodel.css`:
- `.proposal` — purple-bordered proposal watermark sections
- `.current` — z-index wrapper
- `.tooltip` — CSS-only tooltip system
- `.anchorLink` / `.linky` — heading anchor link icons
- Print styles from `mkdocs.css` (`.pagebreak`, body margin)
- Drop ReadTheDocs-specific selectors (`.wy-nav-content`, `.wy-side-nav-search`)
- Adapt for dark mode using Starlight CSS custom properties

### 3. Vanilla JS `tm.js` (no jQuery)

Rewrite `tm.js` without jQuery dependency:
- `copyClipboard()` → uses `document.getElementById` / `parentElement`
- Auto-add `.linky` spans to `h1-h5` elements using `document.querySelectorAll()`
- Starlight already provides heading anchors — only add copy-to-clipboard functionality

### 4. Create `src/scripts/build-astro-site.ts`

Main orchestrator script:

**CLI arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `--TMDirectory <path>` | `.` | Root directory with TM subdirectories |
| `--outputDir <path>` | `../build/site` | Final static site output directory |
| `--template <name>` | `MKdocs` | Render template (MKdocs recommended for site) |
| `--visibility full\|public` | `full` | Content visibility filter |
| `--templateSiteFolderSRC <path>` | *(none)* | User-provided extra pages/CSS/assets to overlay |
| `--siteName <text>` | `"Threat Models"` | Site title in header/sidebar |
| `--base <path>` | `/` | Base URL path for deployment |
| `--generatePDF` | *(off)* | Also generate PDFs per TM |
| `--no-headerNumbering` | *(on)* | Disable heading auto-numbers |
| `--help` | | Print help |

**Flow:**

1. **Discover TMs** — scan `--TMDirectory` for `<name>/<name>.yaml` pattern
2. **Build each TM** — delegate to `buildSingleTM()` with MKdocs template into a staging area
3. **Stage content into Starlight:**
   - For each TM: read YAML → extract `title`, `ID`
   - Copy `.md` → `astro-site/src/content/docs/<TM>/index.md` with injected frontmatter:
     ```yaml
     ---
     title: "<TM Title> Threat Model"
     ---
     ```
   - Copy `img/` → `astro-site/public/<TM>/img/`
4. **Generate index page** — `astro-site/src/content/docs/index.mdx` with TM listing + links
5. **Generate Starlight config** — write `astro-site/astro.config.mjs` with sidebar entries
6. **Handle template folders** — if `--templateSiteFolderSRC` provided:
   - `docs/**/*.md` → `src/content/docs/` (extra sidebar entries)
   - `css/*.css` → `src/styles/` (added to `customCss`)
   - Other assets → `public/`
7. **Install deps** — run `npm install` in `astro-site/` if needed
8. **Build** — run `npx astro build` in `astro-site/`
9. **Copy output** — `astro-site/dist/` → `--outputDir`

### 5. Add npm scripts

In `threat-model-tool-js/package.json`:

```json
"build:astroSite": "tsx src/scripts/build-astro-site.ts",
"build:astroSite:examples": "tsx src/scripts/build-astro-site.ts --TMDirectory tests/exampleThreatModels --outputDir ../build/site"
```

### 6. Add VS Code task

In `.vscode/tasks.json`:

```json
{
    "label": "TS: Build Astro docs site",
    "type": "shell",
    "command": "npm",
    "args": ["run", "build:astroSite:examples"],
    "options": { "cwd": "${workspaceFolder}/threat-model-tool-js" }
}
```

### 7. Add Makefile target

In root `Makefile`:

```makefile
build-site-ts:
	cd threat-model-tool-js && npm run build:astroSite:examples
```

### 8. Update README

Document `build:astroSite` in the npm scripts table, CLI options, and usage examples.

## Image Path Resolution

```
TM page:    src/content/docs/<TM>/index.md  →  served at /<TM>/
TM images:  public/<TM>/img/                →  served at /<TM>/img/
MD ref:     img/foo.svg                     →  resolves to /<TM>/img/foo.svg ✓
```

`trailingSlash: 'always'` ensures consistent path resolution.

## Template Site Folder Support

Mirrors Python's `--templateSiteFolderSRC` mechanism:

```
user-template/
├── docs/
│   ├── extra-page.md           → sidebar entry "Extra Page"
│   └── css/
│       └── custom.css          → added to customCss
├── public/
│   └── logo.png                → copied to public/
```

Files are overlaid on top of the Starlight scaffold — user customizations win.

## Verification Checklist

- [ ] `npm run build:astroSite:examples` completes without errors
- [ ] Static site output in `build/site/` with `index.html`
- [ ] Sidebar navigation lists all TMs
- [ ] Each TM page renders with correct styling (`.proposal`, `.tooltip`, tables)
- [ ] SVG diagrams (attack trees, security objectives) load via relative paths
- [ ] Search (Pagefind) indexes all TM content
- [ ] Dark mode toggle works; TM-specific CSS is readable
- [ ] `--templateSiteFolderSRC` overlay adds extra pages and CSS
