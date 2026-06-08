#!/usr/bin/env node
import path from 'node:path';
import {
    create_indexHAR_file,
    create_starter_HAR_config_file,
} from '../../utils/HAR_2_TM_tool.js';
import { parseFlag, parseMultiOption, parseOption } from '../cli-options.js';

function defaultHarOutputDir(): string {
    return path.resolve(process.cwd(), 'build', 'har');
}

function defaultIndexOutputPath(harPath: string): string {
    return path.join(defaultHarOutputDir(), `${path.parse(path.resolve(harPath)).name}.indexHAR.yaml`);
}

function defaultConfigOutputPath(harPath: string): string {
    return path.join(defaultHarOutputDir(), `${path.parse(path.resolve(harPath)).name}.config.yaml`);
}

function printHelp(): void {
    console.log(`
Usage:
    threat-model-har-config --har <input.har> [--index <input.indexHAR.yaml>] [--out <config.yaml>] [--index-out <output.indexHAR.yaml>]

Options:
  --har <path>         Path to HAR file (required)
    --index <path>       Optional existing .indexHAR.yaml file to use as input
  --out <path>         Output YAML config path (default: build/har/<name>.config.yaml)
  --index-out <path>   Write a fresh .indexHAR file before generating config (default: build/har/<name>.indexHAR.yaml)
    --first-party <pat>  First-party host pattern. Repeat or comma-separate, e.g. --first-party '*.example.com,*.example.it'
        --collapse-third-party  Optional coarse mode: preserve first-party hosts and collapse everything else into a single 3rd Party participant (default keeps third parties separate)
  --help, -h           Show this help
`);
}

const args = process.argv.slice(2);

if (parseFlag(args, 'help') || parseFlag(args, 'h')) {
    printHelp();
    process.exit(0);
}

const harPath = parseOption(args, 'har');
if (!harPath) {
    console.error('Missing required option: --har <input.har>');
    printHelp();
    process.exit(1);
}

const providedIndexPath = parseOption(args, 'index');
const indexOutPath = parseOption(args, 'index-out');
const firstPartyPatterns = parseMultiOption(args, 'first-party');
const collapseThirdParty = parseFlag(args, 'collapse-third-party');
const defaultOutPath = defaultConfigOutputPath(harPath);
const outPath = parseOption(args, 'out') || defaultOutPath;

try {
    let effectiveIndexPath = providedIndexPath;

    if (!effectiveIndexPath || indexOutPath) {
        effectiveIndexPath = create_indexHAR_file(harPath, indexOutPath || defaultIndexOutputPath(harPath));
        console.log(`Generated HAR index: ${effectiveIndexPath}`);
    }

    const configPath = create_starter_HAR_config_file(harPath, outPath, effectiveIndexPath, {
        outputHarPath: path.resolve(harPath),
        firstPartyPatterns,
        collapseThirdParty,
    });

    console.log(`Generated starter HAR config: ${configPath}`);
} catch (error) {
    console.error(`init-har-config failed: ${(error as Error).message}`);
    process.exit(1);
}