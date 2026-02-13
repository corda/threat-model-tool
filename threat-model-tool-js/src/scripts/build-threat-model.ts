#!/usr/bin/env node
import ThreatModel from '../models/ThreatModel.js';
import { ReportGenerator } from '../ReportGenerator.js';
import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const args = process.argv.slice(2);
const yamlFile = args[0];
const outputDir = args[1] || './output';

if (!yamlFile) {
    console.error('Usage: build-threat-model.ts <yaml-file> [output-dir]');
    process.exit(1);
}

// Load and generate
const fullPath = path.resolve(yamlFile);
if (!fs.existsSync(fullPath)) {
    console.error(`File not found: ${fullPath}`);
    process.exit(1);
}

const tmo = new ThreatModel(fullPath);
ReportGenerator.generate(tmo, 'full', path.resolve(outputDir));

// Run PlantUML via Docker
const imgDir = path.join(path.resolve(outputDir), 'img');
console.log('Generating PlantUML diagrams...');

try {
    // Check if there are any .puml files
    const pumlFiles = fs.readdirSync(imgDir).filter(f => f.endsWith('.puml'));
    if (pumlFiles.length > 0) {
        // Try local plantuml if available, otherwise suggest docker
        try {
            execSync(`plantuml -svg "${imgDir}/*.puml"`, { stdio: 'inherit' });
        } catch (e) {
            console.log('Local plantuml failed, trying docker...');
            execSync(`docker run --rm -v "${imgDir}:/data" plantuml/plantuml:sha-d2b2bcf *.puml -svg`, {
                stdio: 'inherit'
            });
        }
    }
} catch (error) {
    console.warn('PlantUML generation failed (Docker or local plantuml required)');
}

console.log('Done!');
