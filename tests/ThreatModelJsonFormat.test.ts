import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, 'fixtures', 'json-format.json');

// parser.ts already advertises JSON support (`Unsupported file format. Please
// provide a YAML or JSON file.`), but the ThreatModel constructor previously
// only matched .yaml / .yml when deciding whether to read the file. A .json
// input therefore produced a silent empty model: the early return at the
// `if (!tmDict.ID)` guard ran without warning.
test('ThreatModel loads .json files with the same shape as .yaml', () => {
    const tm = new ThreatModel(fixturePath);

    assert.equal(tm._id, 'json-format', 'ID must be parsed from the JSON document');
    assert.equal(tm.schemaVersion, 2, 'schemaVersion must come through');
    assert.equal(tm.threats.length, 1, 'threats must be populated');

    const [threat] = tm.threats;
    assert.equal(threat.id, 'JSON_THREAT');
    assert.equal(threat.threatType, 'Information Disclosure');
    assert.ok(threat.cvssObject, 'CVSS object must be constructed from the JSON dict');
    assert.equal(threat.countermeasures.length, 1, 'countermeasure must be parsed');
});
