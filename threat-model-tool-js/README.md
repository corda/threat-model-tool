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

| Script | Command | Description |
|--------|---------|-------------|
| `test` | `tsx --test tests/ThreatModel.test.ts` | Run the full test suite |
| `test:unit` | `tsx --test tests/ThreatModel.test.ts` | Run unit tests |
| `build` | `tsc` | Compile TypeScript to `dist/` |
| `compile` | `tsc --noEmit` | Type-check without emitting |
| `build:example` | `tsx src/scripts/build-threat-model.ts ...` | Build the FullFeature example to `./test-output` |
| `start` | `node dist/index.js` | Run the compiled output |

## Running the Tool

To generate a threat model report from a YAML file:

```bash
npx tsx src/scripts/build-threat-model.ts <path-to-yaml> [output-directory]
```

Example:
```bash
npx tsx src/scripts/build-threat-model.ts ../tests/exampleThreatModels/FullFeature/FullFeature.yaml ./test-output
```

Or via the convenience script:
```bash
npm run build:example
```

## Project Structure

- `src/models/`: Core data models (Threat, Asset, Countermeasure, etc.).
- `src/renderers/`: Logic for converting models into Markdown, PlantUML, or Table of Contents.
- `src/utils/`: Shared utilities like `CVSSHelper` and `HeadingNumberer`.
- `src/scripts/`: CLI entry points (`build-threat-model.ts`).
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
- Implement specialized HTML/VitePress site generation.
- Expand end-to-end integration tests.
- Integrate with `markdown-it` for richer HTML output.
