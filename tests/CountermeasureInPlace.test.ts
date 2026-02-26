import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const examplesDir = path.join(__dirname, 'exampleThreatModels');

test('Countermeasure inPlace property', async (t) => {
    await t.test('should correctly parse inPlace: true from YAML', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        // THREAT_SQL_INJECTION has CM_PREPARED_STATEMENTS with inPlace: true
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        assert.ok(threat, 'THREAT_SQL_INJECTION should exist');

        const cm = threat!.countermeasures[0] as any;
        assert.strictEqual(cm._id, 'CM_PREPARED_STATEMENTS');
        assert.strictEqual(cm.inPlace, true, 'inPlace should be true');
        assert.strictEqual(typeof cm.inPlace, 'boolean', 'inPlace should be a boolean');
    });

    await t.test('should correctly parse inPlace: false from YAML', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        // THREAT_DATA_LEAK has CM_LOG_MASKING with inPlace: false
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_DATA_LEAK');
        assert.ok(threat, 'THREAT_DATA_LEAK should exist');

        const cm = threat!.countermeasures[0] as any;
        assert.strictEqual(cm._id, 'CM_LOG_MASKING');
        assert.strictEqual(cm.inPlace, false, 'inPlace should be false');
        assert.strictEqual(typeof cm.inPlace, 'boolean', 'inPlace should be a boolean');
    });

    await t.test('statusColors() should return green for inPlace: true', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        const cm = threat!.countermeasures[0] as any;

        assert.strictEqual(cm.inPlace, true);
        const colors = cm.statusColors();
        assert.strictEqual(colors.fill, '#D5E8D4', 'inPlace=true fill should be green');
        assert.strictEqual(colors.border, '#82B366', 'inPlace=true border should be green');
    });

    await t.test('statusColors() should return yellow for inPlace: false', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_DATA_LEAK');
        const cm = threat!.countermeasures[0] as any;

        assert.strictEqual(cm.inPlace, false);
        const colors = cm.statusColors();
        assert.strictEqual(colors.fill, '#FFF2CC', 'inPlace=false fill should be yellow');
        assert.strictEqual(colors.border, '#D6B656', 'inPlace=false border should be yellow');
    });

    await t.test('RAGStyle() should reflect inPlace value', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        const mitigatedThreat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        const cmInPlace = mitigatedThreat!.countermeasures[0] as any;
        assert.strictEqual(cmInPlace.RAGStyle(), 'countermeasureIP');

        const unmitigatedThreat = tm.threats.find(t => (t as any)._id === 'THREAT_DATA_LEAK');
        const cmNotInPlace = unmitigatedThreat!.countermeasures[0] as any;
        assert.strictEqual(cmNotInPlace.RAGStyle(), 'countermeasureNIP');
    });

    await t.test('public property should be correctly parsed', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        const cm = threat!.countermeasures[0] as any;

        assert.strictEqual(cm.public, true, 'public property should be true');
        assert.strictEqual(typeof cm.public, 'boolean', 'public should be a boolean');
    });

    await t.test('operational and operator should be correctly parsed', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        // THREAT_KEY_COMPROMISE has CM_KEY_ROTATION: operational: true, operator: Security Operations Team
        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_KEY_COMPROMISE');
        assert.ok(threat, 'THREAT_KEY_COMPROMISE should exist');

        const cm = threat!.countermeasures[0] as any;
        assert.strictEqual(cm._id, 'CM_KEY_ROTATION');
        assert.strictEqual(cm.operational, true, 'operational should be true');
        assert.strictEqual(cm.operator, 'Security Operations Team');
    });
});
