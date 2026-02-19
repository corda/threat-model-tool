# Threat Model Tool (TypeScript)

This is the TypeScript port of the original Python-based Threat Modeling Tool. It is designed to be more maintainable, type-safe, and easier to integrate into modern CI/CD pipelines.

## Status

The core functionality has been ported, including:
- YAML parsing with recursive model loading.
- CVSS score calculations.
- Markdown report generation (Full and Summary).
- PlantUML diagram generation.
- Asset and Key classification.

## Prerequisites

- **Node.js**: v20 or newer.
- **Java/PlantUML**: (Optional) For diagram rendering.
- **Graphviz**: (Optional) Dependency for PlantUML.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. (Optional) Run initialization in the root folder to set up both Python and Node environments:
   ```bash
   make init
   ```

## Quick start: create a new threat model project (easy path)

If you just want to start quickly, follow these 3 steps.

### 1) Create your YAML files

Use the directory naming convention `<modelName>/<modelName>.yaml` (this is required for directory/site generation).

```text
threatModels/
  MySystem/
    MySystem.yaml
```

You can copy one of these as a starting point:
- `tests/exampleThreatModels/Example1/Example1.yaml`
- `tests/exampleThreatModels/FullFeature/FullFeature.yaml`

After copying, update the YAML `ID` to match your file/folder name (for example `MySystem`) to avoid filename/ID mismatch warnings.

### 2) Add simple scripts to `package.json`

Use scripts like these (adjust paths as needed for your repo layout):

```json
{
  "scripts": {
    "tm:generate": "npx tsx src/scripts/build-threat-model.ts threatModels/MySystem/MySystem.yaml build/reports/MySystem --template=full",
    "tm:generate:all": "npx tsx src/scripts/build-threat-model-directory.ts --TMDirectory threatModels --outputDir build/reports",
    "tm:site:mkdocs": "npx tsx src/scripts/build-mkdocs-site.ts --TMDirectory threatModels --MKDocsDir build/mkdocs --MKDocsSiteDir build/site-mkdocs --outputDir build/mkdocs/docs",
    "tm:site:mkdocs:pdf": "npx tsx src/scripts/build-mkdocs-site.ts --TMDirectory threatModels --MKDocsDir build/mkdocs --MKDocsSiteDir build/site-mkdocs --outputDir build/mkdocs/docs --generatePDF --pdfHeaderNote \"Private and confidential\"",
    "tm:site:serve": "mkdocs serve --config-file build/mkdocs/mkdocs.yml --dev-addr 127.0.0.1:4324"
  }
}
```

### 3) Run generation

```bash
npm run tm:generate
npm run tm:generate:all
npm run tm:site:mkdocs
# optional: site + per-model PDFs (homepage includes PDF links when present)
npm run tm:site:mkdocs:pdf
```

Optional local preview:

```bash
npm run tm:site:serve
```

## Publish MkDocs site with GitHub Actions (GitHub Pages)

Create `.github/workflows/publish-mkdocs.yml`:

```yaml
name: Publish MkDocs Site

on:
  workflow_dispatch:
  push:
    branches: [main]
    paths:
      - 'threatModels/**/*.yaml'
      - 'threat-model-tool-js/**'
      - '.github/workflows/publish-mkdocs.yml'

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm
          cache-dependency-path: threat-model-tool-js/package-lock.json

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Node dependencies
        run: npm ci
        working-directory: threat-model-tool-js

      - name: Install MkDocs
        run: pip install mkdocs mkdocs-material

      - name: Install PDF dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y pandoc

      - name: Build MkDocs site + PDFs from threat models
        run: >
          npm run build:mkdocsSite:withPDF --
          --TMDirectory ../threatModels
          --MKDocsDir ./build/mkdocs
          --MKDocsSiteDir ./build/site-mkdocs
          --outputDir ./build/mkdocs/docs
        working-directory: threat-model-tool-js

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: build/site-mkdocs

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

### Dependency notes for CI (PlantUML + PDF)

- **PlantUML diagrams**: generation first tries local `plantuml`; if unavailable, the script falls back to Docker image `plantuml/plantuml:sha-d2b2bcf`.
- **PDF generation (current TS pipeline)**: `--generatePDF` uses Dockerized Chrome/Puppeteer (recommended in CI) so no manual Chrome install is needed.
- **Runner requirement**: Docker is required for both PlantUML fallback and PDF generation.

## Development and Testing

### TypeScript Execution

This project uses **`tsx`** (TypeScript Execute) to run `.ts` files directly with ESM support.
`ts-node` does not work with `"type": "module"` and `"module": "NodeNext"` out of the box.

### Build
Compile the TypeScript code:
```bash
npm run build      # Emit JS to dist/
npm run compile    # Type-check only (tsc --noEmit)
```

### Run Tests

The test suite uses Node.js built-in test runner (`node:test`) executed via `tsx`:

```bash
npm test           # Run all tests (17 tests across 4 suites)
npm run test:unit  # Same — runs tests/ThreatModel.test.ts
```

Test suites cover:
- **Threat Model Parsing** — parses all example YAML files, validates IDs, threats, and threat types
- **Markdown Rendering** — full report and summary rendering
- **PlantUML Rendering** — threat diagrams, security objective diagrams, attack trees
- **TypeScript Models** — ThreatModel construction, CVSS scoring, REFID resolution

Test fixtures live in the parent project at `../tests/exampleThreatModels/`.

### Available npm scripts

| Script | Description |
|--------|-------------|
| `test` / `test:unit` | Run the full test suite |
| `build` | Compile TypeScript to `dist/` |
| `compile` | Type-check without emitting |
| `build:example` | Build the FullFeature example TM to `./build/examples/FullFeature` |
| `generate:example` | Build a named example: `npm run generate:example --example=Example1` |
| `generate:examples` | Build all examples via shell loop |
| `build:directory` | Build a full directory of TMs (see below) |
| `build:directory:examples` | Build all example TMs via `buildFullDirectory` |
| `build:astroSite` | Build an Astro Starlight docs site (see below) |
| `build:astroSite:examples` | Build a site from example TMs to `./build/site` |
| `build:docusaurusSite` | Build a Docusaurus docs site (see below) |
| `build:docusaurusSite:examples` | Build a Docusaurus site from example TMs to `./build/site-docusaurus` |
| `serve:docusaurusSite` | Serve the generated Docusaurus site locally (port 4322) |
| `build:hugoSite` | Build a Hugo docs site (see below) |
| `build:hugoSite:examples` | Build a Hugo site from example TMs to `./build/site-hugo` |
| `serve:hugoSite` | Serve the generated Hugo site locally (port 4323) |
| `build:mkdocsSite` | Build a MkDocs site (see below) |
| `build:mkdocsSite:withPDF` | Build a MkDocs site and generate PDFs |
| `build:mkdocsSite:examples` | Build a MkDocs site from example TMs to `./build/site-mkdocs` |
| `serve:mkdocsSite` | Serve the generated MkDocs site locally (port 4324) |
| `start` | Run the compiled output |

### Heading numbering defaults

- **Single TM / HTML / PDF builds**: heading numbering is **ON** by default.
- **Astro / Docusaurus / Hugo site pipelines**: heading numbering is **ON** by default.
- **MkDocs site pipeline**: heading numbering is **OFF** by default (enable with `--headerNumbering`).

Numbering supports configurable top-level normalization to avoid prefixes like `0.1`.
Example (top level = `##`):

```markdown
## Executive Summary   -> 1
### Threats Summary    -> 1.1
## Scope               -> 2
```

## Running the Tool

### Build a single threat model

```bash
npx tsx src/scripts/build-threat-model.ts <path-to-yaml> [output-dir] [options]
```

#### Options:
- `--template=<name>`: Specify the report template (default: `full`).
    - `TM_templateFull` / `full`: The standard comprehensive report with TOC and summaries.
    - `TM_templateMKDOCS` / `MKdocs`: Optimized for MkDocs/Starlight (no internal TOC, includes RFI section and testing guide).
    - `TM_templateNoTocNoSummary`: A compact view without TOC or executive summaries.
- `--visibility=<full|public>`: Filter content (default: `full`).
- `--fileName=<name>`: Override output filename (default: TM ID).
- `--no-headerNumbering`: Disable automatic heading numbering (default: ON).
- `--headerNumbering`: Explicitly enable heading numbering.
- `--generatePDF`: Generate a PDF (requires PDF tooling configured in your environment/CI).
- `--pdfHeaderNote="text"`: Custom header for PDF pages.
- `--assetFolder <path>`: Additional asset folder(s) to copy into the output root. Repeat the option or use comma-separated values.

Example:
```bash
npx tsx src/scripts/build-threat-model.ts ../tests/exampleThreatModels/FullFeature/FullFeature.yaml ./build --template=TM_templateMKDOCS

# Add one or more extra asset folders
npx tsx src/scripts/build-threat-model.ts ../tests/exampleThreatModels/FullFeature/FullFeature.yaml ./build \
  --assetFolder ./my-assets \
  --assetFolder ./brand-assets,./shared-assets
```

Or via the convenience script:
```bash
npm run build:example
```

### Build a directory of threat models

Use `build-threat-model-directory.ts` to scan a folder for independent TMs (each following the `<name>/<name>.yaml` convention) and build them all. Each TM is written to its own sub-folder under `--outputDir`.

```bash
npx tsx src/scripts/build-threat-model-directory.ts [options]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--TMDirectory <path>` | `.` | Directory containing TM sub-folders |
| `--outputDir <path>` | `./build` | Root output directory; each TM lands in `<outputDir>/<TM_name>/` |
| `--template <name>` | `full` | Report template name |
| `--visibility full\|public` | `full` | `public` strips non-public content from the output |
| `--no-headerNumbering` | *(numbering on)* | Disable automatic heading numbers |
| `--fileName <name>` | *(TM ID)* | Override the output base filename (`.md` / `.html`) |
| `--generatePDF` | *(off)* | Generate a PDF after HTML generation |
| `--pdfHeaderNote <text>` | `Private and confidential` | Text shown in the PDF page header |
| `--pdfArtifactLink <url>` | *(none)* | Reserved for future artifact linking |
| `--assetFolder <path>` | `src/assets_MD_HTML` | Extra asset folder(s) copied into each TM output (repeat option or comma-separate) |
| `--help` | | Print this help and exit |

**Examples:**

```bash
# Build all TMs in ./threatModels into ./build (one sub-folder per TM)
npx tsx src/scripts/build-threat-model-directory.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build

# Public-only output, no heading numbers
npx tsx src/scripts/build-threat-model-directory.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build-public \
  --visibility  public \
  --no-headerNumbering

# Generate PDFs (requires Docker)
npx tsx src/scripts/build-threat-model-directory.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build \
  --generatePDF \
  --pdfHeaderNote "Confidential — Internal Use Only"

# Copy additional assets into every generated TM output
npx tsx src/scripts/build-threat-model-directory.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build \
  --assetFolder ./my-assets \
  --assetFolder ./brand-assets,./shared-assets

# Or via the npm shortcut (builds example TMs):
npm run build:directory:examples
```

#### Asset sources and override order

For single-model and directory builds, output assets come from these sources:

1. **Generated artifacts** from the model pipeline (`.md`, `.html`, `.puml`, `.svg`, optional `.pdf`).
2. **YAML-relative asset folders** copied by `ReportGenerator` (each model's `assetDir()`, including descendants).
3. **Default tool assets** from `src/assets_MD_HTML` (copied by `buildSingleTM` when `--assetFolder` is not provided).
4. **Renderer/site-specific assets** for site pipelines (for example MkDocs template bootstrap/overlays).

When file paths collide, the last copied source wins. For custom assets this means:
- if you pass `--assetFolder`, those folders are copied in the order provided;
- if you do **not** pass `--assetFolder`, only the default `src/assets_MD_HTML` folder is applied at this stage.

#### PDF generation

When `--generatePDF` is set the tool:
1. Generates an HTML report.
2. Runs `ghcr.io/puppeteer/puppeteer:latest` in Docker, pointing headless Chromium at the generated HTML.
3. Writes `<TM_ID>.pdf` next to the HTML file.

Requires Docker to be available on the `PATH`.

#### TM discovery convention

A sub-folder is included only when the directory name exactly matches the YAML filename inside it:
```
threatModels/
  MyThreatModel/
    MyThreatModel.yaml   ← included
  helpers/
    utils.yaml           ← skipped (name mismatch)
```

### Build a MkDocs docs site (legacy-compatible)

Generate a static documentation site using Python MkDocs, while keeping the build orchestration in TypeScript.
This path mirrors the legacy Python setup (same ReadTheDocs theme, same `mkdocs.css` / `threatmodel.css`, same `tm.js`, and the same `mkdocs.yml` structure).

```bash
npx tsx src/scripts/build-mkdocs-site.ts [options]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--TMDirectory <path>` | `.` | Directory containing TM sub-folders |
| `--outputDir <path>` | `<MKDocsDir>/docs` | MkDocs docs source directory |
| `--MKDocsDir <path>` | `./build/mkdocs` | MkDocs working directory (`mkdocs.yml`) |
| `--MKDocsSiteDir <path>` | `./build/site-mkdocs` | Final generated MkDocs static site |
| `--template <name>` | `MKdocs` | Report template used for TM markdown generation |
| `--visibility full\|public` | `full` | `public` strips non-public content |
| `--siteName <name>` | `Threat Models` | Site name written into `mkdocs.yml` |
| `--templateSiteFolderSRC <path>` | *(none)* | Extra overlay source folder (docs/css/assets) |
| `--templateSiteFolderDST <path>` | `<MKDocsDir>` | Overlay destination folder |
| `--headerNumbering` | *(off)* | Enable automatic heading numbers for generated TM markdown |
| `--no-headerNumbering` | *(off)* | Force-disable automatic heading numbers |
| `--generatePDF` | *(off)* | Also generate PDFs for each TM |
| `--pdfHeaderNote <text>` | *(none)* | Custom header for PDF pages |

**Examples:**

```bash
# Build MkDocs site from example TMs (uses legacy site template overlay)
npm run build:mkdocsSite:examples

# Build from a custom TM directory
npx tsx src/scripts/build-mkdocs-site.ts \
  --TMDirectory ./threatModels \
  --MKDocsDir   ./build/mkdocs \
  --MKDocsSiteDir ./build/site-mkdocs
```

This script copies baseline MkDocs assets from `src/assets/MKDOCS_init`, then applies any user-provided template overlay from `--templateSiteFolderSRC`.

### Build an Astro Starlight docs site

Generate a searchable, static documentation site from a directory of threat models using [Astro Starlight](https://starlight.astro.build/). This is the TypeScript equivalent of the Python MkDocs pipeline.

The command discovers all TMs, builds reports using the `MKdocs` template (no inline TOC — Starlight generates it), renders PlantUML diagrams, and produces a fully self-contained static site with:

- **Left sidebar** — page navigation (one entry per TM + any extra pages from a template folder)
- **Right sidebar** — "On this page" heading TOC (h2/h3) auto-generated by Starlight
- **Full-text search** — powered by [Pagefind](https://pagefind.app/)
- **Dark mode** — built-in toggle

```bash
npx tsx src/scripts/build-astro-site.ts [options]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--TMDirectory <path>` | `.` | Directory containing TM sub-folders |
| `--outputDir <path>` | `./build/site` | Where the final static site is written |
| `--template <name>` | `MKdocs` | Report template (`MKdocs` recommended for Starlight) |
| `--visibility full\|public` | `full` | `public` strips non-public content |
| `--siteName <name>` | `Threat Models` | Site title shown in the header |
| `--base <path>` | `/` | Base URL path (for hosting under a sub-path) |
| `--templateSiteFolderSRC <path>` | *(none)* | Overlay folder for extra pages, CSS, and public assets |
| `--no-headerNumbering` | *(numbering on)* | Disable automatic heading numbers |
| `--generatePDF` | *(off)* | Also generate PDFs for each TM |
| `--pdfHeaderNote <text>` | *(none)* | Custom header for PDF pages |

**Examples:**

```bash
# Build site from example TMs
npm run build:astroSite:examples

# Custom directory with site name
npx tsx src/scripts/build-astro-site.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build/site \
  --siteName    "My Project Security"

# With a template folder overlay (extra sidebar pages, custom CSS)
npx tsx src/scripts/build-astro-site.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build/site \
  --templateSiteFolderSRC ./myTemplate
```

#### Template site folder overlay

The `--templateSiteFolderSRC` option lets you inject additional content into the generated site. The folder structure mirrors the Astro site layout:

```
myTemplate/
  docs/              → Extra markdown pages added to the sidebar
    about.md         → Becomes /about/ with auto-injected frontmatter
  public/            → Static assets copied to the site root
    logo.png
```

Markdown files placed in `docs/` are automatically given Starlight frontmatter and appear in the sidebar navigation alongside the TM pages.

#### Astro site scaffold

The Astro project lives in `astro-site/` and is managed automatically by the build script. It includes:
- Ported CSS from the Python tool (`threatmodel.css`) with dark mode support
- Vanilla JS copy-link-to-heading functionality (`tm.js`)
- Starlight content collections with `docsLoader()` (Astro 5 API)

### Build a Docusaurus docs site

Generate a static documentation site from a directory of threat models using [Docusaurus](https://docusaurus.io/).
This pipeline mirrors the Astro flow: discover all TMs, build reports using `MKdocs` template, stage docs/assets, then run `docusaurus build`.

```bash
npx tsx src/scripts/build-docusaurus-site.ts [options]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--TMDirectory <path>` | `.` | Directory containing TM sub-folders |
| `--outputDir <path>` | `./build/site-docusaurus` | Where the final static site is written |
| `--template <name>` | `MKdocs` | Report template (`MKdocs` recommended) |
| `--visibility full\|public` | `full` | `public` strips non-public content |
| `--siteName <name>` | `Threat Models` | Site title shown in navbar |
| `--base <path>` | `/` | Base URL path (for hosting under a sub-path) |
| `--templateSiteFolderSRC <path>` | *(none)* | Overlay folder for extra pages, CSS, and static assets |
| `--no-headerNumbering` | *(numbering on)* | Disable automatic heading numbers |
| `--generatePDF` | *(off)* | Also generate PDFs for each TM |
| `--pdfHeaderNote <text>` | *(none)* | Custom header for PDF pages |

**Examples:**

```bash
# Build Docusaurus site from example TMs
npm run build:docusaurusSite:examples

# Build from a custom TM directory
npx tsx src/scripts/build-docusaurus-site.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build/site-docusaurus \
  --siteName    "My Project Security"

# Serve site after build
npm run serve:docusaurusSite
```

The Docusaurus project scaffold lives in `docusaurus-site/` and is managed by `build-docusaurus-site.ts`.

### Build a Hugo docs site

Generate a static documentation site from a directory of threat models using [Hugo](https://gohugo.io/).
This pipeline discovers all TMs, builds reports with the `MKdocs` template, stages docs/assets into `hugo-site/`, and runs a Hugo build.

Navigation behavior is opinionated by design:

- **All page links are in the left sidebar**
- **No right-side "On this page" column is rendered**

```bash
npx tsx src/scripts/build-hugo-site.ts [options]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--TMDirectory <path>` | `.` | Directory containing TM sub-folders |
| `--outputDir <path>` | `./build/site-hugo` | Where the final static site is written |
| `--template <name>` | `MKdocs` | Report template (`MKdocs` recommended) |
| `--visibility full\|public` | `full` | `public` strips non-public content |
| `--siteName <name>` | `Threat Models` | Site title |
| `--baseURL <url>` | `/` | Hugo base URL |
| `--templateSiteFolderSRC <path>` | *(none)* | Overlay folder for extra pages, CSS, and static assets |
| `--no-headerNumbering` | *(numbering on)* | Disable automatic heading numbers |
| `--generatePDF` | *(off)* | Also generate PDFs for each TM |
| `--pdfHeaderNote <text>` | *(none)* | Custom header for PDF pages |

**Examples:**

```bash
# Build Hugo site from example TMs
npm run build:hugoSite:examples

# Build from a custom TM directory
npx tsx src/scripts/build-hugo-site.ts \
  --TMDirectory ./threatModels \
  --outputDir   ./build/site-hugo \
  --siteName    "My Project Security"

# Serve site after build
npm run serve:hugoSite
```

The Hugo project scaffold lives in `hugo-site/` and is managed by `build-hugo-site.ts`.

## Project Structure

- `src/models/`: Core data models (Threat, Asset, Countermeasure, etc.).
- `src/renderers/`: Logic for converting models into Markdown, PlantUML, or Table of Contents.
- `src/utils/`: Shared utilities like `CVSSHelper` and `HeadingNumberer`.
- `src/scripts/`: CLI entry points (`build-threat-model.ts`, `build-astro-site.ts`, `build-docusaurus-site.ts`, `build-hugo-site.ts`, `build-mkdocs-site.ts`).
- `astro-site/`: Starlight project scaffold (managed by `build-astro-site.ts`).
- `docusaurus-site/`: Docusaurus project scaffold (managed by `build-docusaurus-site.ts`).
- `hugo-site/`: Hugo project scaffold (managed by `build-hugo-site.ts`).
- `tests/`: Test suites using `node:test` + `node:assert`.

## Troubleshooting

### `ERR_UNKNOWN_FILE_EXTENSION ".ts"` when using `ts-node`

This project is configured as ESM (`"type": "module"` in package.json) with `"module": "NodeNext"` in tsconfig.json. The `ts-node` package does not support this combination reliably. Use `tsx` instead:

```bash
# Instead of:  npx ts-node src/scripts/build-threat-model.ts ...
# Use:         npx tsx src/scripts/build-threat-model.ts ...
```

## Next Steps / Future Work

- Complete parity with Python's ISO27001 mapping.
- Expand end-to-end integration tests.
- Integrate with `markdown-it` for richer HTML output.

- other thank mkdocs site (astro hugo docusaurus are POCs and need css / theme refactoring)
