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
| `build:example` | Build the FullFeature example TM to `../build/examples/FullFeature` |
| `generate:example` | Build a named example: `npm run generate:example --example=Example1` |
| `generate:examples` | Build all examples via shell loop |
| `build:directory` | Build a full directory of TMs (see below) |
| `build:directory:examples` | Build all example TMs via `buildFullDirectory` |
| `build:astroSite` | Build an Astro Starlight docs site (see below) |
| `build:astroSite:examples` | Build a site from example TMs to `../build/site` |
| `start` | Run the compiled output |

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
- `--generatePDF`: Generate a PDF via Puppeteer (requires Docker).
- `--pdfHeaderNote="text"`: Custom header for PDF pages.

Example:
```bash
npx tsx src/scripts/build-threat-model.ts ../tests/exampleThreatModels/FullFeature/FullFeature.yaml ./output --template=TM_templateMKDOCS
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
| `--generatePDF` | *(off)* | Generate a PDF via Docker + Puppeteer after HTML generation |
| `--pdfHeaderNote <text>` | `Private and confidential` | Text shown in the PDF page header |
| `--pdfArtifactLink <url>` | *(none)* | Reserved for future artifact linking |
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

# Or via the npm shortcut (builds example TMs):
npm run build:directory:examples
```

#### PDF generation

When `--generatePDF` is set the tool:
1. Copies `pdfScript.js` into `<tmOutputDir>/scripts/`
2. Runs `ghcr.io/puppeteer/puppeteer:latest` in Docker, pointing headless Chromium at the generated HTML
3. Writes `<TM_ID>.pdf` next to the HTML file

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

## Project Structure

- `src/models/`: Core data models (Threat, Asset, Countermeasure, etc.).
- `src/renderers/`: Logic for converting models into Markdown, PlantUML, or Table of Contents.
- `src/utils/`: Shared utilities like `CVSSHelper` and `HeadingNumberer`.
- `src/scripts/`: CLI entry points (`build-threat-model.ts`, `build-astro-site.ts`).
- `astro-site/`: Starlight project scaffold (managed by `build-astro-site.ts`).
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
