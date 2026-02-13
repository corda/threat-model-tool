import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import ThreatModel from '../src/models/ThreatModel.js';

function getYamlFiles(dir, fileList = []) {
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

function printProperties(obj, depth = 0, seen = new WeakSet()) {
    if (obj === null || typeof obj !== 'object') return;
    if (seen.has(obj)) return;
    seen.add(obj);

    const indent = "  ".repeat(depth);
    for (const [key, value] of Object.entries(obj)) {
        if (key === 'parent' || key === 'threatModel' || key === 'originDict' || key === 'children' || key === 'threat') continue;
        if (Array.isArray(value)) {
            console.log(`${indent}${key}: [`);
            value.forEach(item => {
                if (typeof item === 'object' && item !== null) {
                    printProperties(item, depth + 1, seen);
                } else {
                    console.log(`${indent}  ${item}`);
                }
            });
            console.log(`${indent}]`);
        } else if (typeof value === 'object' && value !== null) {
            console.log(`${indent}${key}:`);
            printProperties(value, depth + 1, seen);
        } else {
            console.log(`${indent}${key}: ${value}`);
        }
    }
}

test('Threat Model Parsing', async (t) => {
    const examplesDir = '/workspaces/threat-model-tool/tests/exampleThreatModels';
    
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
            
            console.log(`\n--- Properties for ${fileName} ---`);
            printProperties(tm);

            console.log(`\n--- JSON representation for ${fileName} ---`);
            const jsonReplacer = (key, value) => {
                if (key === 'parent' || key === 'threatModel' || key === 'originDict' || key === 'children' || key === 'threat' || key === 'cvssObject') {
                    return undefined;
                }
                return value;
            };
            console.log(JSON.stringify(tm, jsonReplacer, 2));

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
