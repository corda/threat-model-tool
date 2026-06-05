import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const harFixture = path.join(__dirname, 'fixtures', 'har2seq-sample.har.json');
const configFixture = path.join(__dirname, 'fixtures', 'har2seq-collapse-properties.yaml');
const tsxCli = path.join(repoRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const har2seqScript = path.join(repoRoot, 'src', 'scripts', 'har-workflow', 'har2seq.ts');

function runHar2Seq(args: string[], cwd: string): string {
    return execFileSync(process.execPath, [tsxCli, har2seqScript, ...args], {
        cwd,
        encoding: 'utf8',
    });
}

test('har2seq CLI supports explicit HighLevelDFD flags', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-cli-view-'));
    const outFile = path.join(outDir, 'view.puml');

    try {
        runHar2Seq([
            '--har', harFixture,
            '--config', configFixture,
            '--out', outFile,
            '--view', 'HighLevelDFD',
            '--single-call-per-participant',
            '--generic-call-description', 'Browser flows',
        ], repoRoot);

        const output = fs.readFileSync(outFile, 'utf8');
        assert.ok(output.includes('note over S1 #E0E0E0'));
        assert.ok(output.includes('<b>Example Edge/CDN hosts:</b>'));
        assert.ok(output.includes('BROWSER -> S1: Browser flows'));
        assert.ok(!output.includes('S1 --> BROWSER'));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('har2seq CLI emits the default PlantUML bundle when --out is omitted', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-cli-bundle-'));
    const harCopy = path.join(outDir, 'sample.har.json');
    fs.copyFileSync(harFixture, harCopy);

    try {
        runHar2Seq([
            '--har', harCopy,
            '--config', configFixture,
        ], outDir);

        assert.ok(fs.existsSync(path.join(outDir, 'build', 'har', 'sample.har.sequence.puml')));
        assert.ok(fs.existsSync(path.join(outDir, 'build', 'har', 'sample.har.sourceHostSummary.puml')));
        assert.ok(fs.existsSync(path.join(outDir, 'build', 'har', 'sample.har.HighLevelDFD.puml')));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});

test('har2seq CLI uses per-bucket default labels for HighLevelDFD when no override is passed', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'har-cli-default-highlevel-'));
    const outFile = path.join(outDir, 'view.puml');

    try {
        runHar2Seq([
            '--har', harFixture,
            '--config', configFixture,
            '--out', outFile,
            '--view', 'HighLevelDFD',
            '--single-call-per-participant',
        ], repoRoot);

        const output = fs.readFileSync(outFile, 'utf8');
        assert.ok(output.includes('BROWSER -> S1: Call to example edge/cdn'));
        assert.ok(!output.includes('BROWSER -> S1: Browser interactions'));
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});