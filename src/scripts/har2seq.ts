#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {
    buildSequenceFromHarFile,
    create_indexHAR_file,
    type Har2SeqOptions,
    type SequenceFormat,
} from '../utils/HAR_2_TM_tool.js';
import { parseFlag, parseOption } from './cli-options.js';

interface PlantUmlVariant {
    suffix: string;
    options: Har2SeqOptions;
}

function defaultHarOutputDir(): string {
        return path.resolve(process.cwd(), 'build', 'har');
}

function defaultSequenceOutputPath(harPath: string, format: SequenceFormat): string {
        const ext = format === 'mermaid' ? 'mmd' : 'puml';
        return path.join(defaultHarOutputDir(), `${path.parse(path.resolve(harPath)).name}.${ext}`);
}

function defaultPlantUmlVariantOutputPath(harPath: string, suffix: string): string {
    return path.join(defaultHarOutputDir(), `${path.parse(path.resolve(harPath)).name}.${suffix}.puml`);
}

function defaultPlantUmlVariants(baseOptions: Har2SeqOptions): PlantUmlVariant[] {
    const includeSourceHostInLabel = baseOptions.includeSourceHostInLabel ?? true;
    const genericCallDescription = baseOptions.genericCallDescription ?? 'Browser interactions';

    return [
        {
            suffix: 'sequence',
            options: {
                ...baseOptions,
                view: 'sequence',
                includeSourceHostInLabel,
                singleCallPerSourceHost: false,
                singleCallPerParticipant: false,
            },
        },
        {
            suffix: 'sourceHostSummary',
            options: {
                ...baseOptions,
                view: 'sequence',
                includeSourceHostInLabel,
                singleCallPerSourceHost: true,
                singleCallPerParticipant: false,
            },
        },
        {
            suffix: 'HighLevelDFD',
            options: {
                ...baseOptions,
                view: 'HighLevelDFD',
                genericCallDescription,
                singleCallPerSourceHost: false,
                singleCallPerParticipant: true,
            },
        },
    ];
}

function defaultIndexOutputPath(harPath: string): string {
        return path.join(defaultHarOutputDir(), `${path.parse(path.resolve(harPath)).name}.indexHAR.yaml`);
}

function printHelp(): void {
    console.log(`
Usage:
    threat-model-har2seq --har <input.har> [--config <config.yaml>] [--out <diagram.puml>] [--format plantuml|mermaid] [--browser <name>] [--view sequence|HighLevelDFD] [--single-call-per-participant] [--single-call-per-source-host] [--include-source-host-in-label] [--generic-call-description <label>] [--no-activate] [--index-out <file.indexHAR.yaml>] [--only-index]

Options:
  --har <path>         Path to HAR file (required)
    --config <path>      Optional YAML/JSON config (participants, excludePaths, messagePrefixes, trustBoundaries)
        --out <path>         Optional single output file path. If omitted for PlantUML, a default bundle is written to build/har/<name>.sequence.puml, .sourceHostSummary.puml, and .HighLevelDFD.puml
    --format <value>     Output format: plantuml or mermaid (default: plantuml)
    --mermaid            Shortcut for --format mermaid
    --plantuml           Shortcut for --format plantuml
  --browser <name>     Browser participant name (default: Browser)
    --view <value>       PlantUML view mode: sequence or HighLevelDFD
    --single-call-per-participant  Emit one call per visible participant
    --single-call-per-source-host  Emit one call per source host while still respecting collapsed participants
    --include-source-host-in-label Keep the original source host inside collapsed request labels
    --generic-call-description <label>  Generic label to use for HighLevelDFD calls (default: Browser interactions)
  --no-activate        Do not emit activate/deactivate lines
        --index-out <path>   Write HAR line-reference index file. Defaults to build/har/<name>.indexHAR.yaml when needed
    --only-index         Generate only the index file (skip sequence output)
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

const configPath = parseOption(args, 'config');
const outPath = parseOption(args, 'out');
const indexOutPath = parseOption(args, 'index-out');
const onlyIndex = parseFlag(args, 'only-index');
const browserParticipant = parseOption(args, 'browser') || 'Browser';
const includeActivation = !parseFlag(args, 'no-activate');
const formatOption = parseOption(args, 'format');
const viewOption = parseOption(args, 'view');
const genericCallDescription = parseOption(args, 'generic-call-description');

let view: Har2SeqOptions['view'];
if (viewOption === 'sequence' || viewOption === 'HighLevelDFD') {
    view = viewOption;
} else if (viewOption) {
    console.error(`Invalid --view value: ${viewOption}. Use sequence or HighLevelDFD.`);
    process.exit(1);
}

let format: SequenceFormat = 'plantuml';
if (parseFlag(args, 'mermaid')) {
    format = 'mermaid';
} else if (parseFlag(args, 'plantuml')) {
    format = 'plantuml';
} else if (formatOption === 'mermaid' || formatOption === 'plantuml') {
    format = formatOption;
} else if (formatOption) {
    console.error(`Invalid --format value: ${formatOption}. Use plantuml or mermaid.`);
    process.exit(1);
}

const cliOptions: Har2SeqOptions = {
    browserParticipant,
    includeActivation,
    format,
    view,
    genericCallDescription: genericCallDescription || undefined,
    includeSourceHostInLabel: parseFlag(args, 'include-source-host-in-label') || undefined,
    singleCallPerSourceHost: parseFlag(args, 'single-call-per-source-host') || undefined,
    singleCallPerParticipant: parseFlag(args, 'single-call-per-participant') || undefined,
};

try {
    if (!onlyIndex) {
        if (format === 'plantuml' && !outPath) {
            const variants = defaultPlantUmlVariants(cliOptions);

            for (const variant of variants) {
                const outputFile = defaultPlantUmlVariantOutputPath(harPath, variant.suffix);
                const sequenceDiagram = buildSequenceFromHarFile(harPath, configPath, {
                    ...variant.options,
                    format: 'plantuml',
                });

                fs.mkdirSync(path.dirname(outputFile), { recursive: true });
                fs.writeFileSync(outputFile, sequenceDiagram, 'utf8');
                console.log(`Generated PlantUML view (${variant.suffix}): ${outputFile}`);
            }
        } else {
            const sequenceDiagram = buildSequenceFromHarFile(harPath, configPath, cliOptions);

            const outputFile = path.resolve(outPath || defaultSequenceOutputPath(harPath, format));
            fs.mkdirSync(path.dirname(outputFile), { recursive: true });
            fs.writeFileSync(outputFile, sequenceDiagram, 'utf8');
            console.log(`Generated sequence diagram: ${outputFile}`);
        }
    }

    if (indexOutPath || onlyIndex) {
        const indexPath = create_indexHAR_file(harPath, indexOutPath || defaultIndexOutputPath(harPath));
        console.log(`Generated HAR index: ${indexPath}`);
    }
} catch (error) {
    console.error(`har2seq failed: ${(error as Error).message}`);
    process.exit(1);
}
