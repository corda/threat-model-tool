import assert from 'node:assert';
import test from 'node:test';

import { normalizeCsvRow } from '../../src/jira/syncCsv.js';
import { planCsvSyncUpdates } from '../../src/jira/syncPlanner.js';

test('planCsvSyncUpdates plans updates and skips invalid rows', () => {
    const rows = [
        normalizeCsvRow({
            'Create Ticket': 'Yes',
            'Threat ID': 'GENERIC_THREAT_ALPHA',
            Summary: 'Remediation for: Generic threat alpha',
            Description: 'Description\n\nAlpha details',
        }),
        normalizeCsvRow({
            'Create Ticket': 'No',
            'Threat ID': 'GENERIC_THREAT_BETA',
            Summary: 'Remediation for: Generic threat beta',
            Description: 'Beta details',
        }),
        normalizeCsvRow({
            'Create Ticket': 'Yes',
            'Threat ID': 'GENERIC_THREAT_GAMMA',
            Summary: '',
            Description: 'Gamma details',
        }),
    ];

    const result = planCsvSyncUpdates(rows, {
        GENERIC_THREAT_ALPHA: 'SEC-200',
        GENERIC_THREAT_GAMMA: 'SEC-201',
    });

    assert.equal(result.updates.length, 1);
    assert.equal(result.updates[0].issueKey, 'SEC-200');
    assert.equal(result.updates[0].descriptionMarkdown, 'Alpha details');

    assert.equal(result.skipped.length, 2);
    assert.equal(result.skipped[0].reason, 'create-ticket-filtered');
    assert.equal(result.skipped[1].reason, 'missing-summary');
});

test('planCsvSyncUpdates applies manual mapping', () => {
    const rows = [
        normalizeCsvRow({
            'Create Ticket': 'Yes',
            'Threat ID': 'GENERIC_THREAT_DELTA',
            Summary: 'Remediation for: Generic threat delta',
            Description: 'Delta details',
        }),
    ];

    const result = planCsvSyncUpdates(rows, {}, { manualMap: { GENERIC_THREAT_DELTA: 'SEC-300' } });

    assert.equal(result.updates.length, 1);
    assert.equal(result.updates[0].issueKey, 'SEC-300');
    assert.equal(result.skipped.length, 0);
});
