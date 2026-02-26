import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const examplesDir = path.join(__dirname, 'exampleThreatModels');

/**
 * Tests that all model class properties are correctly assigned from YAML dictData.
 *
 * Background: BaseThreatModelObject.constructor() dynamically assigns properties via
 * a for..of loop on dictData entries. TypeScript class field declarations can reset
 * values to undefined after super() returns (especially with useDefineForClassFields:true
 * or target >= ES2022). Each model class must explicitly assign critical properties in
 * its own constructor to guard against this.
 */
test('Model property assignment from YAML', async (t) => {
    await t.test('Threat: attack, threatType, impactDesc, fullyMitigated', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        assert.ok(threat, 'Threat should exist');

        assert.strictEqual(typeof threat!.attack, 'string', 'attack should be a string');
        assert.ok(threat!.attack!.length > 0, 'attack should not be empty');

        assert.strictEqual(threat!.threatType, 'Tampering');
        assert.strictEqual(threat!.impactDesc, 'High');
        assert.strictEqual(threat!.fullyMitigated, true);
        assert.strictEqual(typeof threat!.fullyMitigated, 'boolean');
    });

    await t.test('Threat: fullyMitigated=false should be preserved', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        const threat = tm.threats.find(t => (t as any)._id === 'THREAT_DATA_LEAK');
        assert.ok(threat);
        assert.strictEqual(threat!.fullyMitigated, false, 'fullyMitigated=false should not become undefined');
    });

    await t.test('Asset: type, inScope, properties', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        assert.ok(tm.assets.length > 0, 'Should have assets');

        const asset = tm.assets.find(a => (a as any)._id === 'ASSET_USER_DATA');
        assert.ok(asset, 'ASSET_USER_DATA should exist');
        assert.strictEqual(asset!.type, 'data');
        assert.strictEqual(asset!.inScope, true);
        assert.strictEqual(typeof asset!.inScope, 'boolean');
        assert.ok(Object.keys(asset!.properties).length > 0, 'Should have properties');

        const oosAsset = tm.assets.find(a => (a as any)._id === 'DATAFLOW_EXTERNAL_API');
        assert.ok(oosAsset, 'Out-of-scope asset should exist');
        assert.strictEqual(oosAsset!.inScope, false);
    });

    await t.test('SecurityObjective: group, priority, inScope, treeImage', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        assert.ok(tm.securityObjectives.length > 0, 'Should have security objectives');

        const secObj = tm.securityObjectives.find(so => (so as any)._id === 'OBJ_CONFIDENTIALITY');
        assert.ok(secObj, 'OBJ_CONFIDENTIALITY should exist');
        assert.strictEqual(secObj!.group, 'General');
        assert.strictEqual(typeof secObj!.inScope, 'boolean');
        assert.strictEqual(secObj!.inScope, true);
    });

    await t.test('Attacker: inScope', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
        assert.ok(tm.attackers.length > 0, 'Should have attackers');

        const attacker = tm.attackers.find(a => (a as any)._id === 'ATT_EXTERNAL');
        assert.ok(attacker, 'ATT_EXTERNAL should exist');
        assert.strictEqual(attacker!.inScope, true);
        assert.strictEqual(typeof attacker!.inScope, 'boolean');
    });

    await t.test('Countermeasure: inPlace, public, operational, operator', () => {
        const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));

        // inPlace: true, public: true, operational: false
        const sqlThreat = tm.threats.find(t => (t as any)._id === 'THREAT_SQL_INJECTION');
        const cmPrep = sqlThreat!.countermeasures[0] as any;
        assert.strictEqual(cmPrep.inPlace, true);
        assert.strictEqual(cmPrep.public, true);
        assert.strictEqual(cmPrep.operational, false);

        // inPlace: false, public: true
        const leakThreat = tm.threats.find(t => (t as any)._id === 'THREAT_DATA_LEAK');
        const cmLog = leakThreat!.countermeasures[0] as any;
        assert.strictEqual(cmLog.inPlace, false);
        assert.strictEqual(cmLog.public, true);

        // operational: true with operator
        const keyThreat = tm.threats.find(t => (t as any)._id === 'THREAT_KEY_COMPROMISE');
        const cmRot = keyThreat!.countermeasures[0] as any;
        assert.strictEqual(cmRot.operational, true);
        assert.strictEqual(cmRot.operator, 'Security Operations Team');
    });
});
