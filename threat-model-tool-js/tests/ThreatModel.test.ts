import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';
import { MarkdownRenderer } from '../src/renderers/MarkdownRenderer.js';
import { PlantUMLRenderer } from '../src/renderers/PlantUMLRenderer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const examplesDir = path.join(__dirname, 'exampleThreatModels');

function getYamlFiles(dir: string, fileList: string[] = []): string[] {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
        const filePath = path.join(dir, file);
        if (fs.statSync(filePath).isDirectory()) {
            getYamlFiles(filePath, fileList);
        } else if (file.endsWith('.yaml')) {
            fileList.push(filePath);
        }
    });
    return fileList;
}

test('Threat Model Parsing', async (t) => {
    if (!fs.existsSync(examplesDir)) {
        console.warn('Example threat models directory not found at ' + examplesDir);
        return;
    }

    const files = getYamlFiles(examplesDir);
    console.log(`Found ${files.length} example files`);

    for (const filePath of files) {
        const fileName = path.basename(filePath);
        await t.test(`should parse ${fileName}`, () => {
            const tm = new ThreatModel(filePath);
            
            assert.ok(tm._id, `ID missing for ${fileName}`);
            assert.ok(tm.threats.length >= 0);
            
            tm.threats.forEach(threat => {
                assert.ok(threat.id, `Threat missing ID in ${fileName}`);
                assert.ok(threat.attack !== undefined, `Threat missing attack in ${threat.id}`);
                assert.ok(threat.threatType, `Threat missing threatType in ${threat.id}`);
            });
        });
    }
});

test('Markdown Rendering', async (t) => {
    if (!fs.existsSync(examplesDir)) {
        console.warn('Example threat models directory not found');
        return;
    }

    await t.test('should render full report', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        const renderer = new MarkdownRenderer(tm);
        const markdown = renderer.renderFullReport();
        
        assert.ok(markdown.length > 0, 'Markdown should not be empty');
        assert.ok(markdown.includes('# '), 'Markdown should have title');
        assert.ok(markdown.includes('## Threats'), 'Markdown should have threats section');
    });

    await t.test('should render summary', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        const renderer = new MarkdownRenderer(tm);
        const summary = renderer.renderSummary();
        
        assert.ok(summary.includes('Summary'), 'Summary should have title');
        assert.ok(summary.includes('Total Threats'), 'Summary should have threat count');
    });
});

test('PlantUML Rendering', async (t) => {
    if (!fs.existsSync(examplesDir)) {
        console.warn('Example threat models directory not found');
        return;
    }

    await t.test('should render threat diagram', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        const renderer = new PlantUMLRenderer(tm);
        const puml = renderer.renderThreatDiagram();
        
        assert.ok(puml.startsWith('@startuml'), 'PlantUML should start with @startuml');
        assert.ok(puml.endsWith('@enduml\n'), 'PlantUML should end with @enduml');
        assert.ok(puml.includes('rectangle'), 'PlantUML should have rectangles');
    });

    await t.test('should render security objectives diagram', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        const renderer = new PlantUMLRenderer(tm);
        const puml = renderer.renderSecurityObjectivesDiagram();
        
        assert.ok(puml.startsWith('@startuml'), 'PlantUML should start with @startuml');
        assert.ok(puml.endsWith('@enduml\n'), 'PlantUML should end with @enduml');
    });

    await t.test('should render attack tree for threat', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        const renderer = new PlantUMLRenderer(tm);
        
        if (tm.threats.length > 0) {
            const puml = renderer.renderAttackTree(tm.threats[0]);
            
            assert.ok(puml.startsWith('@startuml'), 'PlantUML should start with @startuml');
            assert.ok(puml.endsWith('@enduml\n'), 'PlantUML should end with @enduml');
            assert.ok(puml.includes('Attack Tree'), 'PlantUML should mention attack tree');
        }
    });
});

test('TypeScript Models', async (t) => {
    await t.test('should create ThreatModel from YAML', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        
        assert.ok(tm._id === 'Example2', 'ThreatModel should have correct ID');
        assert.ok(tm.schemaVersion === 2, 'ThreatModel should have schema version');
        assert.ok(tm.threats.length > 0, 'ThreatModel should have threats');
    });

    await t.test('should have CVSS scoring', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        
        if (tm.threats.length > 0) {
            const threat = tm.threats[0];
            assert.ok(threat.cvssObject, 'Threat should have CVSS object');
            
            const scoreDesc = threat.getSmartScoreDesc();
            // Format is now "9.8 (Critical)" matching Python output
            const validDescPattern = /^\d+\.?\d*\s*\(\w+\)$|^TODO$|^None$/;
            assert.ok(validDescPattern.test(scoreDesc) || 
                      ['None', 'Low', 'Medium', 'High', 'Critical'].some(s => scoreDesc.includes(s)), 
                     `CVSS score description should be valid, got: ${scoreDesc}`);
            
            const scoreVal = threat.getSmartScoreVal();
            assert.ok(scoreVal >= 0 && scoreVal <= 10, 'CVSS score should be between 0 and 10');
        }
    });

    await t.test('should resolve REFIDs', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'Example2/Example2.yaml'));
        
        if (tm.threats.length > 0 && tm.threats[0].impactedSecObjs.length > 0) {
            const refid = tm.threats[0].impactedSecObjs[0];
            const resolved = refid.resolve();
            
            assert.ok(resolved !== null, 'REFID should resolve to an object');
        }
    });
});
