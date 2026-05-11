#!/usr/bin/env node
/**
 * CLI command to scaffold a new threat model with a minimal working skeleton.
 *
 * Usage:
 *   tsx src/scripts/init-threat-model.ts --name <ID> [--title <string>] [--outputDir <path>] [--author <string>]
 */
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { parseOption, parseFlag } from './cli-options.js';

export interface InitOptions {
    name: string;
    title?: string;
    outputDir?: string;
    author?: string;
}

export function initThreatModel(options: InitOptions): string {
    const { name } = options;

    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(name)) {
        throw new Error(
            `Invalid --name "${name}". Must start with a letter and contain only letters, digits, "_" or "-".`,
        );
    }

    const title = options.title ?? name;
    const author = options.author ?? 'TODO';
    const outputDir = path.resolve(options.outputDir ?? process.cwd());
    const tmDir = path.join(outputDir, name);
    const yamlPath = path.join(tmDir, `${name}.yaml`);

    if (fs.existsSync(tmDir)) {
        throw new Error(`Folder already exists: ${tmDir}`);
    }

    fs.mkdirSync(tmDir, { recursive: true });
    fs.writeFileSync(yamlPath, buildSkeleton({ id: name, title, author }), 'utf8');

    return yamlPath;
}

function buildSkeleton({ id, title, author }: { id: string; title: string; author: string }): string {
    return `ID: ${id}
schemaVersion: 2
title: ${title}
version: 0.1
authors: |
  ${author}
scope:
  description: |
    TODO: Describe the system, its boundaries, and what is in/out of scope for this threat model.
  securityObjectives:
    - ID: SYSTEM_CONFIDENTIALITY
      title: System Confidentiality
      description: |
        Prevent unauthorized disclosure of data.
      group: Data Security

    - ID: SYSTEM_INTEGRITY
      title: System Integrity
      description: |
        Prevent unauthorized modification of data or behavior.
      group: System Integrity

  assets:
    - ID: EXAMPLE_ASSET
      type: data
      title: Example Asset
      description: |
        TODO: Describe an asset (data, component, credential, etc.) that needs protection.
      inScope: true

  attackers:
    - ID: EXTERNAL_ATTACKER
      description: |
        Unauthenticated external user with network access.
      inScope: true

analysis: |
  TODO: Summarize the analysis approach, key findings, and residual risk.

threats:
  - ID: EXAMPLE_THREAT
    title: Example Threat
    attack: |
      TODO: Describe how an attacker could realize this threat.
    threatType: Information Disclosure
    impactDesc: |
      TODO: Describe the impact if the threat is realized.
    impactedSecObj:
      - REFID: SYSTEM_CONFIDENTIALITY
    attackers:
      - REFID: EXTERNAL_ATTACKER
    CVSS:
      vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    fullyMitigated: false
    countermeasures:
      - ID: EXAMPLE_COUNTERMEASURE
        title: Example Countermeasure
        description: |
          TODO: Describe the control that mitigates the threat.
        inPlace: false
        public: true
`;
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

function runCli(): void {
    const cliArgs = process.argv.slice(2);

    if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
        console.log(`
Usage:
  init-threat-model --name <ID> [--title <string>] [--outputDir <path>] [--author <string>]

Options:
  --name <ID>            Threat model ID and folder name (required)
  --title <string>       Human-readable title (defaults to --name)
  --outputDir <path>     Parent directory to create the TM folder in (defaults to cwd)
  --author <string>      Author name (defaults to "TODO")
  --help, -h             Show this help
`);
        process.exit(0);
    }

    const name = parseOption(cliArgs, 'name');
    if (!name) {
        console.error('Error: --name is required. Use --help for usage.');
        process.exit(1);
    }

    try {
        const yamlPath = initThreatModel({
            name,
            title: parseOption(cliArgs, 'title'),
            outputDir: parseOption(cliArgs, 'outputDir'),
            author: parseOption(cliArgs, 'author'),
        });
        console.log(`Threat model skeleton created: ${yamlPath}`);
        console.log(`Next steps:`);
        console.log(`  1. Edit the YAML to describe your system, assets, threats, and countermeasures.`);
        console.log(`  2. Run: npm run verify -- ${yamlPath}`);
    } catch (error) {
        console.error(`Init failed: ${(error as Error).message}`);
        process.exit(1);
    }
}

// Only run CLI when this file is executed directly (not when imported).
// Compare via realpath so npm-link / symlinked installs still match.
function isMainModule(): boolean {
    const argv1 = process.argv[1];
    if (!argv1) return false;
    try {
        const argvReal = fs.realpathSync(argv1);
        const moduleReal = fs.realpathSync(fileURLToPath(import.meta.url));
        return argvReal === moduleReal;
    } catch {
        return false;
    }
}

if (isMainModule()) {
    runCli();
}
