import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    buildSequenceFromHarFile,
    buildMermaidFromHarFile,
    buildPlantUmlFromHarFile,
    create_indexHAR_file,
    read_har_entry,
    indexHarEntryByteRanges,
    load_indexHAR_file,
    generateMermaidFromHar,
    generate_indexHAR,
    generatePlantUmlFromHar,
    type HarFile,
} from '../src/utils/HAR_2_TM_tool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const harFixture = path.join(__dirname, 'fixtures', 'har2seq-sample.har.json');
const configFixture = path.join(__dirname, 'fixtures', 'har2seq-config.yaml');
const boundariesFixture = path.join(__dirname, 'fixtures', 'har2seq-boundaries.yaml');
const collapseFixture = path.join(__dirname, 'fixtures', 'har2seq-collapse-properties.yaml');

test('buildSequenceFromHarFile defaults to PlantUML output', () => {
    const output = buildSequenceFromHarFile(harFixture);

    assert.ok(output.startsWith('@startuml'));
    assert.ok(output.includes('box "External Boundary" #EAEAEA'));
    assert.ok(output.includes('BROWSER -> S1: GET /v1/health'));
    assert.ok(!output.includes('--> BROWSER'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(output.includes('@enduml'));
});

test('buildPlantUmlFromHarFile creates trust-boundary boxes from config', () => {
    const output = buildPlantUmlFromHarFile(harFixture, boundariesFixture);

    assert.ok(output.includes('box "First Party Boundary" #D7F3E3'));
    assert.ok(output.includes('box "Third Party Boundary" #F5F5F5'));
    assert.ok(output.includes('participant "api.example.com" as S1'));
    assert.ok(output.includes('participant "cdn.example.com" as S2'));
});

test('buildMermaidFromHarFile creates a diagram from HAR file', () => {
    const output = buildMermaidFromHarFile(harFixture);

    assert.ok(output.startsWith('sequenceDiagram'));
    assert.ok(output.includes('participant "api.example.com" as S1'));
    assert.ok(output.includes('Browser->>S1: GET /v1/health'));
    assert.ok(output.includes('S1-->>Browser: 200'));
});

test('buildMermaidFromHarFile applies participants, excludePaths and messagePrefixes', () => {
    const output = buildMermaidFromHarFile(harFixture, configFixture);

    assert.ok(output.includes('participant "api.example.com" as S1'));
    assert.ok(!output.includes('/v1/health'));
    assert.ok(output.includes('Browser->>S1: AUTH: POST /v1/login'));
    assert.ok(!output.includes('cdn.example.com'));
});

test('generateMermaidFromHar supports disabling activation lines', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://service.example.com/items' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
            ],
        },
    };

    const output = generateMermaidFromHar(har, {}, { includeActivation: false, browserParticipant: 'Client' });

    assert.ok(output.includes('participant Client'));
    assert.ok(output.includes('Client->>S1: GET /items'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
});

test('generatePlantUmlFromHar supports disabling activation lines', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://service.example.com/items' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har, {}, { includeActivation: false, browserParticipant: 'Client' });

    assert.ok(output.includes('actor "Client" as BROWSER'));
    assert.ok(output.includes('BROWSER -> S1: GET /items'));
    assert.ok(!output.includes('S1 --> BROWSER'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
});

test('generatePlantUmlFromHar truncates very long request URLs sensibly', () => {
    const longQuery = 'token='.concat('a'.repeat(160));
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: {
                        method: 'GET',
                        url: `https://service.example.com/api/v1/very/long/resource/path/that/should/stay/readable?${longQuery}`,
                    },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har);

    assert.ok(output.includes('BROWSER -> S1: GET /api/v1/very/long/resource/path/that/should/stay/readable?...'));
    assert.ok(!output.includes(longQuery));
});

test('generatePlantUmlFromHar includes source host in labels for collapsed participants', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://vendor-a.example.net/sdk.js?cache=123' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
                {
                    request: { method: 'POST', url: 'https://vendor-b.example.net/collect' },
                    response: { status: 204 },
                    startedDateTime: '2026-05-11T00:00:01.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har, {
        collapseParticipants: [
            {
                name: '3rd Party',
                participants: ['*'],
            },
        ],
    }, {
        includeSourceHostInLabel: true,
    });

    assert.ok(output.includes('participant "3rd Party" as S1'));
    assert.ok(output.includes('BROWSER -> S1: GET vendor-a.example.net /sdk.js?cache=123'));
    assert.ok(output.includes('BROWSER -> S1: POST vendor-b.example.net /collect'));
    assert.ok(!output.includes('S1 --> BROWSER'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
});

test('generatePlantUmlFromHar can emit one call per source host while keeping a collapsed participant', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://vendor-a.example.net/sdk.js?cache=123' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
                {
                    request: { method: 'POST', url: 'https://vendor-a.example.net/collect' },
                    response: { status: 204 },
                    startedDateTime: '2026-05-11T00:00:01.000Z',
                },
                {
                    request: { method: 'GET', url: 'https://vendor-b.example.net/widget.js' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:02.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har, {
        collapseParticipants: [
            {
                name: '3rd Party',
                participants: ['*'],
            },
        ],
    }, {
        includeSourceHostInLabel: true,
        singleCallPerSourceHost: true,
    });

    assert.ok(output.includes('participant "3rd Party" as S1'));
    assert.ok(output.includes('BROWSER -> S1: GET vendor-a.example.net /sdk.js?cache=123'));
    assert.ok(output.includes('BROWSER -> S1: GET vendor-b.example.net /widget.js'));
    assert.ok(!output.includes('BROWSER -> S1: POST vendor-a.example.net /collect'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
});

test('generate_indexHAR returns byte offsets for each request', () => {
    const indexData = generate_indexHAR(harFixture);

    assert.equal(indexData.schemaVersion, 'indexHAR.v2');
    assert.equal(indexData.totalRequests, 3);
    assert.equal(indexData.entries.length, 3);
    assert.equal(typeof indexData.harBytes, 'number');
    assert.equal(typeof indexData.harSha256, 'string');
    assert.ok(indexData.entries[0].entryOffset >= 0);
    assert.ok(indexData.entries[0].entryLength > 0);

    // The byte range points at the entry's full JSON in the source HAR.
    const buffer = fs.readFileSync(harFixture);
    const e0 = indexData.entries[0];
    const slice = buffer.toString('utf8', e0.entryOffset, e0.entryOffset + e0.entryLength);
    const parsedSlice = JSON.parse(slice) as { request: { url: string } };
    assert.equal(parsedSlice.request.url, e0.url);
});

test('read_har_entry seeks a single full entry by offset/length', () => {
    const indexData = generate_indexHAR(harFixture);
    const e1 = indexData.entries[1];
    const entry = read_har_entry(harFixture, e1.entryOffset, e1.entryLength);
    assert.equal(entry.request.url, e1.url);
    assert.equal(Number(entry.response.status), e1.status);
});

test('indexHarEntryByteRanges aligns ranges with chronological requestId order', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-offsets-'));
    const harPath = path.join(outDir, 'unordered.har');

    // Entries intentionally out of chronological order to prove requestId is by timestamp
    // while byte ranges still resolve to the correct entry.
    const har = {
        log: {
            entries: [
                {
                    startedDateTime: '2026-05-10T10:00:02.000Z',
                    request: { method: 'GET', url: 'https://example.com/third', headers: [{ name: 'x-order', value: '3' }] },
                    response: { status: 200, content: { mimeType: 'text/plain', text: 'ok' } },
                },
                {
                    startedDateTime: '2026-05-10T10:00:00.000Z',
                    request: { method: 'GET', url: 'https://example.com/first', headers: [{ name: 'x-order', value: '1' }] },
                    response: { status: 200, content: { mimeType: 'text/plain', text: 'ok' } },
                },
                {
                    startedDateTime: '2026-05-10T10:00:01.000Z',
                    request: { method: 'GET', url: 'https://example.com/second', headers: [{ name: 'x-order', value: '2' }] },
                    response: { status: 200, content: { mimeType: 'text/plain', text: 'ok' } },
                },
            ],
        },
    };

    try {
        fs.writeFileSync(harPath, JSON.stringify(har), 'utf8');

        // Raw scanner returns ranges in file order (not chronological).
        const buffer = fs.readFileSync(harPath);
        const ranges = indexHarEntryByteRanges(buffer);
        assert.equal(ranges.length, 3);
        const fileOrderUrls = ranges.map(r => (JSON.parse(buffer.toString('utf8', r.offset, r.offset + r.length)) as { request: { url: string } }).request.url);
        assert.deepEqual(fileOrderUrls, [
            'https://example.com/third',
            'https://example.com/first',
            'https://example.com/second',
        ]);

        // The index re-sorts to chronological order and each offset still resolves correctly.
        const indexData = generate_indexHAR(harPath);
        assert.deepEqual(indexData.entries.map(e => e.requestId), [1, 2, 3]);
        assert.deepEqual(indexData.entries.map(e => e.url), [
            'https://example.com/first',
            'https://example.com/second',
            'https://example.com/third',
        ]);
        for (const entry of indexData.entries) {
            const resolved = read_har_entry(harPath, entry.entryOffset, entry.entryLength);
            assert.equal(resolved.request.url, entry.url);
        }
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('create_indexHAR_file writes .indexHAR output file', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-index-'));
    const outFile = path.join(outDir, 'sample.indexHAR.yaml');

    try {
        const writtenPath = create_indexHAR_file(harFixture, outFile);
        assert.equal(writtenPath, outFile);
        assert.ok(fs.existsSync(outFile));

        // On disk the format is columnar v2: a `columns` header + one inline array row per entry,
        // with no repeated key names and no per-row requestId.
        const rawText = fs.readFileSync(outFile, 'utf8');
        assert.match(rawText, /schemaVersion: indexHAR\.v2/);
        assert.match(rawText, /columns:/);
        assert.match(rawText, /- \[GET, /);
        assert.doesNotMatch(rawText, /requestId:/);
        assert.doesNotMatch(rawText, /entryOffset:/);

        const parsed = load_indexHAR_file(outFile) as { totalRequests: number; harSha256?: string; harFile: string; entries: Array<{ requestId: number; url: string; entryOffset: number; entryLength: number }> };
        assert.equal(parsed.totalRequests, 3);
        assert.equal(parsed.harFile, 'har2seq-sample.har.json');
        assert.equal(parsed.entries[0].requestId, 1);
        assert.equal(parsed.entries[0].url, 'https://api.example.com/v1/health');
        assert.ok(parsed.entries[0].entryLength > 0);
        assert.equal(typeof parsed.harSha256, 'string');

        // Offsets in the written index resolve to the full entry directly from the HAR.
        const e0 = parsed.entries[0];
        const resolved = read_har_entry(harFixture, e0.entryOffset, e0.entryLength);
        assert.equal(resolved.request.url, 'https://api.example.com/v1/health');
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('collapseParticipants + singleCallPerParticipant builds compact dataflow output', () => {
    const output = buildPlantUmlFromHarFile(harFixture, collapseFixture, {
        singleCallPerParticipant: true,
    });

    assert.ok(output.includes('participant "Example Edge/CDN" as S1'));
    assert.ok(output.includes('<b>authentication:</b> none'));
    assert.ok(output.includes('<b>authorization:</b> public'));
    assert.ok(output.includes('<b>dataSensitivity:</b> low'));

    const calls = output.match(/^BROWSER -> S1:/gm) ?? [];
    assert.equal(calls.length, 1);
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
});

test('generatePlantUmlFromHar supports HighLevelDFD bucket view with generic labels and host notes', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://vendor-a.example.net/sdk.js' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
                {
                    request: { method: 'POST', url: 'https://vendor-b.example.net/collect' },
                    response: { status: 204 },
                    startedDateTime: '2026-05-11T00:00:01.000Z',
                },
                {
                    request: { method: 'GET', url: 'https://vendor-c.example.net/pixel' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:02.000Z',
                },
                {
                    request: { method: 'GET', url: 'https://vendor-d.example.net/beacon' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:03.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har, {
        collapseParticipants: [
            {
                name: '3rd Party',
                participants: ['*'],
            },
        ],
        participantProperties: [
            {
                participants: ['3rd Party'],
                properties: {
                    owner: 'third-party',
                },
            },
        ],
    }, {
        view: 'HighLevelDFD',
        genericCallDescription: 'Generic browser interaction',
        singleCallPerParticipant: true,
    });

    assert.ok(output.includes('participant "3rd Party" as S1'));
    assert.ok(output.includes('note over S1 #E0E0E0'));
    assert.ok(output.includes('  <b>3rd Party hosts:</b> vendor-a.example.net, vendor-b.example.net,'));
    assert.ok(output.includes('  vendor-c.example.net, vendor-d.example.net'));
    assert.ok(output.includes('BROWSER -> S1: Generic browser interaction'));
    assert.ok(!output.includes('BROWSER -> S1: GET'));
    assert.ok(!output.includes('S1 --> BROWSER'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
    assert.ok(!output.includes('owner: third-party'));
});

test('generatePlantUmlFromHar uses per-bucket default labels in HighLevelDFD', () => {
    const har: HarFile = {
        log: {
            entries: [
                {
                    request: { method: 'GET', url: 'https://vendor-a.example.net/sdk.js' },
                    response: { status: 200 },
                    startedDateTime: '2026-05-11T00:00:00.000Z',
                },
            ],
        },
    };

    const output = generatePlantUmlFromHar(har, {
        collapseParticipants: [
            {
                name: 'Telemetry',
                participants: ['*'],
            },
        ],
    }, {
        view: 'HighLevelDFD',
        singleCallPerParticipant: true,
    });

    assert.ok(output.includes('BROWSER -> S1: Call to telemetry'));
    assert.ok(!output.includes('BROWSER -> S1: Browser interactions'));
});
