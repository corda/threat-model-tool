import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { initThreatModel } from '../src/scripts/init-threat-model.js';
import ThreatModel from '../src/models/ThreatModel.js';
import Threat from '../src/models/Threat.js';
import Countermeasure from '../src/models/Countermeasure.js';

function makeTempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'tm-init-test-'));
}

test('init-threat-model', async (t) => {
    await t.test('creates folder + yaml at <outputDir>/<name>/<name>.yaml', () => {
        const dir = makeTempDir();
        try {
            const yamlPath = initThreatModel({ name: 'MyService', outputDir: dir });
            assert.strictEqual(yamlPath, path.join(dir, 'MyService', 'MyService.yaml'));
            assert.ok(fs.existsSync(yamlPath), 'YAML should exist');
            assert.ok(fs.statSync(path.join(dir, 'MyService')).isDirectory(), 'TM folder should be a directory');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await t.test('generated skeleton parses as a valid ThreatModel', () => {
        const dir = makeTempDir();
        try {
            const yamlPath = initThreatModel({
                name: 'MyService',
                title: 'My Service Threat Model',
                author: 'Tester',
                outputDir: dir,
            });
            const tm = new ThreatModel(yamlPath);
            assert.strictEqual(tm.id, 'MyService');
            assert.strictEqual(tm.title, 'My Service Threat Model');
            assert.strictEqual(tm.schemaVersion, 2);
            assert.ok(tm.securityObjectives.length >= 1, 'should have security objectives');
            assert.ok(tm.attackers.length >= 1, 'should have attackers');
            assert.ok(tm.getAllDown(Threat).length >= 1, 'should have at least one threat');
            assert.ok(tm.getAllDown(Countermeasure).length >= 1, 'should have at least one countermeasure');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await t.test('defaults title to name and author to TODO', () => {
        const dir = makeTempDir();
        try {
            const yamlPath = initThreatModel({ name: 'Defaulted', outputDir: dir });
            const content = fs.readFileSync(yamlPath, 'utf8');
            assert.match(content, /^title: Defaulted$/m);
            assert.match(content, /^ {2}TODO$/m);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await t.test('rejects invalid names', () => {
        const dir = makeTempDir();
        try {
            assert.throws(() => initThreatModel({ name: '1bad', outputDir: dir }), /Invalid --name/);
            assert.throws(() => initThreatModel({ name: 'has space', outputDir: dir }), /Invalid --name/);
            assert.throws(() => initThreatModel({ name: 'has/slash', outputDir: dir }), /Invalid --name/);
            assert.throws(() => initThreatModel({ name: '', outputDir: dir }), /Invalid --name/);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await t.test('refuses to overwrite an existing folder', () => {
        const dir = makeTempDir();
        try {
            initThreatModel({ name: 'Dup', outputDir: dir });
            assert.throws(
                () => initThreatModel({ name: 'Dup', outputDir: dir }),
                /already exists/,
            );
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    await t.test('auto-creates a missing outputDir', () => {
        const missing = path.join(os.tmpdir(), 'tm-init-auto-' + Date.now());
        try {
            const yamlPath = initThreatModel({ name: 'AutoMk', outputDir: missing });
            assert.ok(fs.existsSync(yamlPath), 'YAML should exist');
            assert.ok(fs.statSync(missing).isDirectory(), 'outputDir should have been created');
        } finally {
            fs.rmSync(missing, { recursive: true, force: true });
        }
    });
});
