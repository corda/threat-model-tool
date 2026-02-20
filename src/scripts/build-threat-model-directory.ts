#!/usr/bin/env node
/**
 * build-threat-model-directory.ts
 *
 * Scans a directory for independent threat models (each following the
 * <name>/<name>.yaml convention) and builds them all, writing each into
 * its own sub-folder under outputDir.
 *
 * CLI usage:
 *   tsx src/scripts/build-threat-model-directory.ts \
 *     --TMDirectory ./threatModels \
 *     --outputDir   ./build       \
 *     [--template full]           \
 *     [--visibility full|public]  \
 *     [--no-headerNumbering]      \
 *     [--fileName <name>]         \
 *     [--generatePDF]             \
 *     [--pdfHeaderNote "Private and confidential"] \
 *     [--pdfArtifactLink <url>]
 *
 * Note: default outputs are under ./build/* to avoid polluting source folders.
 */

import path from 'path';
import fs from 'fs';
import { buildSingleTM, type BuildTMOptions } from './build-threat-model.js';
import { parseFlag, parseOption, parseMultiOption } from './cli-options.js';

// ---------------------------------------------------------------------------
// Core library function (importable by external consumers)
// ---------------------------------------------------------------------------

export interface DirectoryBuildOptions extends BuildTMOptions {
    /** Sub-folder naming: 'per-tm' (default) creates outputDir/<tmName>/,
     *  'flat' puts everything straight into outputDir */
    outputLayout?: 'per-tm' | 'flat';
}

export function buildFullDirectory(
    tmDirectory: string,
    outputDir: string = './build',
    options: DirectoryBuildOptions = {}
): void {
    const { outputLayout = 'per-tm', ...tmOptions } = options;

    const absDir = path.resolve(tmDirectory);
    if (!fs.existsSync(absDir)) {
        console.error(`TMDirectory not found: ${absDir}`);
        process.exit(1);
    }

    // Discover TMs: directories whose name matches a YAML file inside them.
    // e.g.  threatModels/ExampleTM/ExampleTM.yaml  →  valid entry
    const entries = fs.readdirSync(absDir, { withFileTypes: true });
    const tmList: Array<{ name: string; yamlPath: string }> = [];

    for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const yamlPath = path.join(absDir, entry.name, `${entry.name}.yaml`);
        if (fs.existsSync(yamlPath)) {
            tmList.push({ name: entry.name, yamlPath });
        } else {
            console.info(`Skipping ${entry.name}: no matching ${entry.name}.yaml found`);
        }
    }

    // Sort alphabetically (mirrors Python's `sorted()`)
    tmList.sort((a, b) => a.name.localeCompare(b.name));

    if (tmList.length === 0) {
        console.warn(`No threat models found in: ${absDir}`);
        return;
    }

    console.log(`Found ${tmList.length} threat model(s) in ${absDir}`);

    let succeeded = 0;
    let failed = 0;

    for (const tm of tmList) {
        const tmOutputDir = outputLayout === 'per-tm'
            ? path.join(path.resolve(outputDir), tm.name)
            : path.resolve(outputDir);

        console.log(`\n${'='.repeat(60)}`);
        console.log(`Building: ${tm.name}`);
        console.log(`  YAML  : ${tm.yamlPath}`);
        console.log(`  Output: ${tmOutputDir}`);
        console.log('='.repeat(60));

        try {
            buildSingleTM(tm.yamlPath, tmOutputDir, tmOptions);
            succeeded++;
        } catch (err) {
            console.error(`ERROR building ${tm.name}: ${err}`);
            failed++;
        }
    }

    console.log(`\n${'='.repeat(60)}`);
    console.log(`Directory build complete: ${succeeded} succeeded, ${failed} failed`);
    console.log('='.repeat(60));
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage: build-threat-model-directory.ts [options]

Defaults: generated outputs are written under ./build/* unless overridden.

Options:
  --TMDirectory <path>       Directory containing TM sub-folders (default: .)
    --outputDir   <path>       Root output directory (default: ./build)
  --template    <name>       Report template (default: full)
  --visibility  full|public  Content visibility (default: full)
  --no-headerNumbering       Disable auto heading numbers (default: ON)
  --fileName    <name>       Override output base filename
  --generatePDF              Generate PDF via Docker+Puppeteer
  --pdfHeaderNote <text>     Text shown in PDF page headers
  --pdfArtifactLink <url>    Reserved for future artifact linking
    --assetFolder <path>       Asset folder(s) copied into each output (repeat or comma-separate)
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory') ?? '.';
const outputDir   = parseOption(cliArgs, 'outputDir')   ?? './build';
const template    = parseOption(cliArgs, 'template')    ?? 'full';
const visibilityArg = parseOption(cliArgs, 'visibility');
const visibility: 'full' | 'public' =
    visibilityArg === 'public' ? 'public' : 'full';
const headerNumbering = !parseFlag(cliArgs, 'no-headerNumbering');
const fileName        = parseOption(cliArgs, 'fileName');
const generatePDF     = parseFlag(cliArgs, 'generatePDF');
const pdfHeaderNote   = parseOption(cliArgs, 'pdfHeaderNote') ?? 'Private and confidential';
const pdfArtifactLink = parseOption(cliArgs, 'pdfArtifactLink');
const assetFolders    = parseMultiOption(cliArgs, 'assetFolder');

buildFullDirectory(tmDirectory, outputDir, {
    template,
    visibility,
    headerNumbering,
    fileName,
    generatePDF,
    pdfHeaderNote,
    pdfArtifactLink,
    assetFolders: assetFolders.length > 0 ? assetFolders : undefined,
});
