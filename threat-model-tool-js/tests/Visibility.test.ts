import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';
import Threat from '../src/models/Threat.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, 'fixtures', 'visibility-test.yaml');

test('Visibility Filtering', async (t) => {
    
    await t.test('should hide private objects when publicFlag is true', () => {
        const tm = new ThreatModel(fixturePath, null, true); // publicFlag = true

        // Check threats
        assert.strictEqual(tm.threats.length, 1, 'Should only have 1 public threat');
        assert.strictEqual(tm.threats[0].id, 'PUBLIC_THREAT');
        
        // Check ticketLink (should be stripped for public mode)
        assert.strictEqual(tm.threats[0].ticketLink, undefined, 'ticketLink should be hidden in public mode');

        // Check countermeasures in public threat
        const publicThreat = tm.threats[0];
        assert.strictEqual(publicThreat.countermeasures.length, 1, 'Should only have 1 public countermeasure');
        assert.strictEqual((publicThreat.countermeasures[0] as any).id, 'PUBLIC_CM');

        // Check assets
        assert.strictEqual(tm.assets.length, 1, 'Should only have 1 public asset');
        assert.strictEqual(tm.assets[0].id, 'PUBLIC_ASSET');

        // Check security objectives
        assert.strictEqual(tm.securityObjectives.length, 1, 'Should only have 1 public security objective');
        assert.strictEqual(tm.securityObjectives[0].id, 'PUBLIC_OBJ');

        // Check attackers
        assert.strictEqual(tm.attackers.length, 1, 'Should only have 1 public attacker');
        assert.strictEqual(tm.attackers[0].id, 'PUBLIC_ATTACKER');

        // Check assumptions
        assert.strictEqual(tm.assumptions.length, 1, 'Should only have 1 public assumption');
        assert.strictEqual(tm.assumptions[0].id, 'PUBLIC_ASSUMPTION');
    });

    await t.test('should show all objects when publicFlag is false', () => {
        const tm = new ThreatModel(fixturePath, null, false); // publicFlag = false (Internal)

        // Check threats
        assert.strictEqual(tm.threats.length, 2, 'Should have both threats');
        
        const privateThreat = tm.threats.find(t => t.id === 'PRIVATE_THREAT');
        assert.ok(privateThreat, 'PRIVATE_THREAT should exist');
        assert.strictEqual(privateThreat?.ticketLink, 'http://jira/PRIVATE-1', 'ticketLink should be visible in internal mode');
        assert.strictEqual(privateThreat?.countermeasures.length, 1, 'Private threat should have 1 countermeasure');

        // Check countermeasures
        const publicThreat = tm.threats.find(t => t.id === 'PUBLIC_THREAT')!;
        assert.strictEqual(publicThreat.countermeasures.length, 2, 'Should have both countermeasures');
        assert.strictEqual((publicThreat.countermeasures[0] as any).id, 'PUBLIC_CM');
        assert.strictEqual((publicThreat.countermeasures[1] as any).id, 'PRIVATE_CM_OF_PUBLIC_THREAT');

        // Check assets
        assert.strictEqual(tm.assets.length, 2, 'Should have both assets');

        // Check security objectives
        assert.strictEqual(tm.securityObjectives.length, 2, 'Should have both security objectives');

        // Check attackers
        assert.strictEqual(tm.attackers.length, 2, 'Should have both attackers');

        // Check assumptions
        assert.strictEqual(tm.assumptions.length, 2, 'Should have both assumptions');
    });
});
