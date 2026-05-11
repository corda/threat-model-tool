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

test('generate_indexHAR returns line references for each request', () => {
    const indexData = generate_indexHAR(harFixture);

    assert.equal(indexData.schemaVersion, 'indexHAR.v1');
    assert.equal(indexData.totalRequests, 3);
    assert.equal(indexData.entries.length, 3);
    assert.ok(indexData.entries[0].lineRefs.methodLine);
    assert.ok(indexData.entries[0].lineRefs.urlLine);
    assert.ok(indexData.entries[0].lineRefs.statusLine);
});

test('create_indexHAR_file writes .indexHAR output file', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-index-'));
    const outFile = path.join(outDir, 'sample.indexHAR.yaml');

    try {
        const writtenPath = create_indexHAR_file(harFixture, outFile);
        assert.equal(writtenPath, outFile);
        assert.ok(fs.existsSync(outFile));

        const parsed = load_indexHAR_file(outFile) as { totalRequests: number; entries: Array<{ url: string; lineRefs: { urlLine?: number } }> };
        assert.equal(parsed.totalRequests, 3);
        assert.equal(parsed.entries[0].url, 'https://api.example.com/v1/health');
        assert.ok(parsed.entries[0].lineRefs.urlLine);
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('collapseParticipants + singleCallPerParticipant builds compact dataflow output', () => {
    const output = buildPlantUmlFromHarFile(harFixture, collapseFixture, {
        singleCallPerParticipant: true,
    });

    assert.ok(output.includes('participant "Example Edge/CDN" as S1'));
    assert.ok(output.includes('authentication: none'));
    assert.ok(output.includes('authorization: public'));
    assert.ok(output.includes('dataSensitivity: low'));

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
    assert.ok(output.includes('note right of S1 #E0E0E0'));
    assert.ok(output.includes('  3rd Party hosts: vendor-a.example.net, vendor-b.example.net'));
    assert.ok(output.includes('BROWSER -> S1: Generic browser interaction'));
    assert.ok(!output.includes('BROWSER -> S1: GET'));
    assert.ok(!output.includes('S1 --> BROWSER'));
    assert.ok(!output.includes('activate S1'));
    assert.ok(!output.includes('deactivate S1'));
    assert.ok(!output.includes('owner: third-party'));
});
