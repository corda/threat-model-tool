#!/usr/bin/env node

import ThreatModel from './dist/models/ThreatModel.js';
import { MarkdownRenderer } from './dist/renderers/MarkdownRenderer.js';
import { PlantUMLRenderer } from './dist/renderers/PlantUMLRenderer.js';
import fs from 'fs';
import path from 'path';

const outputDir = './output';

// Create output directory if it doesn't exist
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
}

console.log('=== Threat Model Tool Demo ===\n');

// Load example threat model
const examplePath = '/workspaces/threat-model-tool/tests/exampleThreatModels/Example2/Example2.yaml';

if (!fs.existsSync(examplePath)) {
    console.error('Example file not found at:', examplePath);
    process.exit(1);
}

console.log('Loading threat model from:', examplePath);
const tm = new ThreatModel(examplePath);

console.log('\n--- Threat Model Summary ---');
console.log('ID:', tm._id);
console.log('Schema Version:', tm.schemaVersion);
console.log('Total Threats:', tm.threats.length);
console.log('Total Assets:', tm.assets.length);
console.log('Total Security Objectives:', tm.securityObjectives.length);

console.log('\n--- Threats ---');
tm.threats.forEach(threat => {
    console.log(`\n${threat.id}: ${threat.title}`);
    console.log(`  Type: ${threat.threatType}`);
    console.log(`  CVSS Score: ${threat.getSmartScoreVal().toFixed(1)} (${threat.getSmartScoreDesc()})`);
    console.log(`  Fully Mitigated: ${threat.fullyMitigated ? 'Yes' : 'No'}`);
    console.log(`  Countermeasures: ${threat.countermeasures.length}`);
});

// Generate Markdown report
console.log('\n--- Generating Markdown Report ---');
const mdRenderer = new MarkdownRenderer(tm);
const markdown = mdRenderer.renderFullReport();
const mdPath = path.join(outputDir, 'threat-model-report.md');
fs.writeFileSync(mdPath, markdown, 'utf8');
console.log('Markdown report saved to:', mdPath);

// Generate summary
const summary = mdRenderer.renderSummary();
const summaryPath = path.join(outputDir, 'threat-model-summary.md');
fs.writeFileSync(summaryPath, summary, 'utf8');
console.log('Summary saved to:', summaryPath);

// Generate PlantUML diagrams
console.log('\n--- Generating PlantUML Diagrams ---');
const pumlRenderer = new PlantUMLRenderer(tm);

const threatDiagram = pumlRenderer.renderThreatDiagram();
const threatDiagramPath = path.join(outputDir, 'threat-diagram.puml');
fs.writeFileSync(threatDiagramPath, threatDiagram, 'utf8');
console.log('Threat diagram saved to:', threatDiagramPath);

const secObjDiagram = pumlRenderer.renderSecurityObjectivesDiagram();
const secObjDiagramPath = path.join(outputDir, 'security-objectives-diagram.puml');
fs.writeFileSync(secObjDiagramPath, secObjDiagram, 'utf8');
console.log('Security objectives diagram saved to:', secObjDiagramPath);

// Generate attack trees for each threat
tm.threats.forEach((threat, index) => {
    const attackTree = pumlRenderer.renderAttackTree(threat);
    const attackTreePath = path.join(outputDir, `attack-tree-${threat.id}.puml`);
    fs.writeFileSync(attackTreePath, attackTree, 'utf8');
});
console.log(`Attack trees saved for ${tm.threats.length} threats`);

console.log('\n=== Demo Complete ===');
console.log(`\nAll outputs saved to: ${outputDir}/`);
console.log('\nTo view PlantUML diagrams, use:');
console.log('  - PlantUML online editor: https://www.plantuml.com/plantuml/');
console.log('  - Local PlantUML: java -jar plantuml.jar output/*.puml');
