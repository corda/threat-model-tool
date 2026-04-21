import assert from 'node:assert';
import test from 'node:test';

import { mergeThreatTicketMaps, parseThreatTicketMapFromYaml } from '../../src/jira/syncMapping.js';

test('parseThreatTicketMapFromYaml extracts threat ID to issue key map', () => {
    const yamlText = `
threats:
  - ID: GENERIC_THREAT_ALPHA
    title: Generic Threat Alpha
    ticketLink: SEC-100
  - ID: GENERIC_THREAT_BETA
    title: Generic Threat Beta
    ticketLink: https://example.invalid/browse/SEC-101
`;

    const map = parseThreatTicketMapFromYaml(yamlText);

    assert.deepEqual(map, {
        GENERIC_THREAT_ALPHA: 'SEC-100',
        GENERIC_THREAT_BETA: 'SEC-101',
    });
});

test('mergeThreatTicketMaps applies last write wins', () => {
    const map = mergeThreatTicketMaps(
        { A: 'SEC-1', B: 'SEC-2' },
        { B: 'SEC-20', C: 'SEC-3' },
    );

    assert.deepEqual(map, { A: 'SEC-1', B: 'SEC-20', C: 'SEC-3' });
});
