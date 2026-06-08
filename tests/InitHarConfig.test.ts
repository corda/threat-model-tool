import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    create_starter_HAR_config_file,
    generate_starter_HAR_config_yaml,
} from '../src/utils/HAR_2_TM_tool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const harFixture = path.join(__dirname, 'fixtures', 'har2seq-sample.har.json');

test('generate_starter_HAR_config_yaml emits starter YAML with workflow comments', () => {
    const yamlText = generate_starter_HAR_config_yaml(harFixture);

    assert.ok(yamlText.includes('# HAR_2_TM_tool starter config'));
    assert.ok(yamlText.includes('browserParticipant: Browser'));
    assert.ok(yamlText.includes('participants:'));
    assert.ok(!yamlText.includes('rendering:'));
});

test('create_starter_HAR_config_file writes starter YAML to disk', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-config-'));
    const outFile = path.join(outDir, 'starter.config.yaml');

    try {
        const written = create_starter_HAR_config_file(harFixture, outFile);
        assert.equal(written, outFile);
        assert.ok(fs.existsSync(outFile));

        const yamlText = fs.readFileSync(outFile, 'utf8');
        assert.ok(yamlText.includes('messagePrefixes:'));
        assert.ok(yamlText.includes('trustBoundaries:'));
        assert.ok(yamlText.includes('participants:'));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('generate_starter_HAR_config_yaml keeps third-party participants separate by default', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-config-default-split-'));
    const harFile = path.join(outDir, 'default-split.har.json');

    try {
        fs.writeFileSync(harFile, JSON.stringify({
            log: {
                entries: [
                    {
                        startedDateTime: '2026-05-10T10:00:00.000Z',
                        request: {
                            method: 'GET',
                            url: 'https://app.example.com/home',
                        },
                        response: { status: 200 },
                    },
                    {
                        startedDateTime: '2026-05-10T10:00:01.000Z',
                        request: {
                            method: 'GET',
                            url: 'https://js.stripe.com/v3',
                        },
                        response: { status: 200 },
                    },
                ],
            },
        }, null, 2), 'utf8');

        const yamlText = generate_starter_HAR_config_yaml(harFile, undefined, {
            firstPartyPatterns: ['*.example.com'],
        });

        assert.ok(!yamlText.includes('ID: THIRD_PARTY\n    title: 3rd Party'));
        assert.ok(!yamlText.includes('collapseTo: THIRD_PARTY'));
        assert.ok(yamlText.includes('ID: STRIPE_COM'));
        assert.ok(yamlText.includes('trustBoundary: THIRD_PARTY'));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('generate_starter_HAR_config_yaml supports collapsing all third parties behind a catch-all participant', () => {
    const yamlText = generate_starter_HAR_config_yaml(harFixture, undefined, {
        firstPartyPatterns: ['*.example.com', '*.example.it'],
        collapseThirdParty: true,
    });

    assert.ok(yamlText.includes('ID: THIRD_PARTY'));
    assert.ok(yamlText.includes('title: 3rd Party'));
    assert.ok(yamlText.includes('trustBoundary: THIRD_PARTY'));
    assert.ok(yamlText.includes('participants:'));
    assert.ok(yamlText.includes('domains: []'));
    assert.ok(!yamlText.includes('rendering:'));
    assert.ok(!yamlText.includes('Google Edge/CDN'));
});

test('generate_starter_HAR_config_yaml keeps known third-party buckets visible when collapsing the rest', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-config-buckets-'));
    const harFile = path.join(outDir, 'bucketed.har.json');

    try {
        fs.writeFileSync(harFile, JSON.stringify({
            log: {
                entries: [
                    {
                        startedDateTime: '2026-05-10T10:00:00.000Z',
                        request: {
                            method: 'GET',
                            url: 'https://app.example.com/home',
                        },
                        response: { status: 200 },
                    },
                    {
                        startedDateTime: '2026-05-10T10:00:01.000Z',
                        request: {
                            method: 'GET',
                            url: 'https://www.googletagmanager.com/gtm.js?id=GTM-TEST',
                        },
                        response: { status: 200 },
                    },
                    {
                        startedDateTime: '2026-05-10T10:00:02.000Z',
                        request: {
                            method: 'GET',
                            url: 'https://unknown-vendor.example.net/script.js',
                        },
                        response: { status: 200 },
                    },
                ],
            },
        }, null, 2), 'utf8');

        const yamlText = generate_starter_HAR_config_yaml(harFile, undefined, {
            firstPartyPatterns: ['*.example.com'],
            collapseThirdParty: true,
        });

        assert.ok(yamlText.includes('ID: GOOGLE_EDGE_CDN'));
        assert.ok(yamlText.includes('title: Google Edge/CDN'));
        assert.ok(!yamlText.includes('ID: GOOGLE_EDGE_CDN\n    title: Google Edge/CDN\n    domains:\n      - www.googletagmanager.com\n    trustBoundary: THIRD_PARTY\n    collapseTo: THIRD_PARTY'));
        assert.ok(yamlText.includes('ID: EXAMPLE_NET'));
        assert.ok(yamlText.includes('collapseTo: THIRD_PARTY'));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});
