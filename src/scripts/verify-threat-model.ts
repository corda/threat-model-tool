#!/usr/bin/env node
/**
 * CLI command to parse and verify threat model YAML files.
 * Instantiates the full ThreatModel object tree, validating structure and references.
 *
 * Usage:
 *   tsx src/scripts/verify-threat-model.ts <yamlFile>
 *   tsx src/scripts/verify-threat-model.ts --TMDirectory <path>
 */
import path from 'path';
import fs from 'fs';
import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';
import Countermeasure from '../models/Countermeasure.js';
import { parseOption, parseFlag } from './cli-options.js';

export function verifyThreatModel(yamlFile: string): ThreatModel {
    const fullPath = path.resolve(yamlFile);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`File not found: ${fullPath}`);
    }

    const tmo = new ThreatModel(fullPath);

    const allThreats = tmo.getAllDown(Threat);
    const allCountermeasures = tmo.getAllDown(Countermeasure);
    const childModels = tmo.getDescendantsTM();

    console.log(`Threat model verified successfully: ${tmo.id}`);
    console.log(`  Title: ${tmo.title}`);
    console.log(`  Schema version: ${tmo.schemaVersion}`);
    console.log(`  Security objectives: ${tmo.securityObjectives.length}`);
    console.log(`  Assets: ${tmo.assets.length}`);
    console.log(`  Attackers: ${tmo.attackers.length}`);
    console.log(`  Assumptions: ${tmo.assumptions.length}`);
    console.log(`  Threats: ${allThreats.length}`);
    console.log(`  Countermeasures: ${allCountermeasures.length}`);
    if (childModels.length > 0) {
        console.log(`  Child threat models: ${childModels.length}`);
    }

    return tmo;
}

/**
 * Discover and verify all threat models in a directory.
 * Uses the same <name>/<name>.yaml convention as the build-directory script.
 */
export function verifyDirectory(tmDirectory: string): { succeeded: number; failed: number } {
    const absDir = path.resolve(tmDirectory);
    if (!fs.existsSync(absDir)) {
        throw new Error(`TMDirectory not found: ${absDir}`);
    }

    const entries = fs.readdirSync(absDir, { withFileTypes: true });
    const tmList: Array<{ name: string; yamlPath: string }> = [];

    for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const yamlPath = path.join(absDir, entry.name, `${entry.name}.yaml`);
        if (fs.existsSync(yamlPath)) {
            tmList.push({ name: entry.name, yamlPath });
        }
    }

    tmList.sort((a, b) => a.name.localeCompare(b.name));

    if (tmList.length === 0) {
        console.warn(`No threat models found in: ${absDir}`);
        return { succeeded: 0, failed: 0 };
    }

    console.log(`Found ${tmList.length} threat model(s) in ${absDir}\n`);

    let succeeded = 0;
    let failed = 0;

    for (const tm of tmList) {
        try {
            verifyThreatModel(tm.yamlPath);
            succeeded++;
        } catch (err) {
            console.error(`FAILED: ${tm.name} — ${(err as Error).message}`);
            failed++;
        }
        console.log('');
    }

    console.log(`${'='.repeat(60)}`);
    console.log(`Verification complete: ${succeeded} succeeded, ${failed} failed`);
    console.log('='.repeat(60));

    return { succeeded, failed };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage:
  verify-threat-model <yamlFile>
  verify-threat-model --TMDirectory <path>

Options:
  --TMDirectory <path>   Directory containing TM sub-folders (<name>/<name>.yaml)
  --help, -h             Show this help
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory');

try {
    if (tmDirectory) {
        const { failed } = verifyDirectory(tmDirectory);
        if (failed > 0) process.exit(1);
    } else if (cliArgs.length >= 1 && !cliArgs[0].startsWith('--')) {
        verifyThreatModel(cliArgs[0]);
    } else {
        console.error('Usage: verify-threat-model <yamlFile> | --TMDirectory <path>');
        process.exit(1);
    }
} catch (error) {
    console.error(`Verification failed: ${(error as Error).message}`);
    process.exit(1);
}
