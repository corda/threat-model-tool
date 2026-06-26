import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';
import { MarkdownRenderer } from '../src/renderers/MarkdownRenderer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const examplesDir = path.join(__dirname, 'exampleThreatModels');

test('MarkdownRenderer.renderSummary groups threats by severity bucket', async (t) => {
    const tm = new ThreatModel(path.join(examplesDir, 'FullFeature/FullFeature.yaml'));
    const summary = new MarkdownRenderer(tm).renderSummary();

    await t.test('does not bucket by numeric score', () => {
        // Pre-fix output looked like "- 7.5 (High): 1\n- 9.8 (Critical): 1\n- 5.4 (Medium): 1...".
        // The grouping key now should be the severity bucket only.
        const numericBucket = summary.match(/^- \d/m);
        assert.strictEqual(
            numericBucket,
            null,
            `Severity breakdown lines should not start with a numeric score, got line: ${numericBucket}`
        );
    });

    await t.test('uses severity-only bucket names', () => {
        const allowed = ['Critical', 'High', 'Medium', 'Low', 'None', 'TODO CVSS'];
        const breakdownLines = summary
            .split('\n')
            .filter(line => line.startsWith('- ') && line.includes(':'));
        // After the "Severity Breakdown" heading, every bullet's key must be one of the allowed bucket names.
        const heading = summary.indexOf('**Threat Severity Breakdown:**');
        assert.ok(heading >= 0, 'Severity Breakdown heading should be present');
        const tail = summary.slice(heading);
        for (const line of tail.split('\n').filter(l => l.startsWith('- '))) {
            const key = line.slice(2, line.indexOf(':')).trim();
            assert.ok(
                allowed.includes(key),
                `Bucket name "${key}" should be one of ${allowed.join(', ')} (line: ${line})`
            );
        }
        assert.ok(breakdownLines.length > 0, 'Should emit at least one breakdown line');
    });

    await t.test('a single bucket aggregates all threats sharing that severity', () => {
        // Count "High" threats in the underlying model and compare to the summary line.
        const expectedHigh = tm.threats.filter(t => t.getSmartScoreSeverity() === 'High').length;
        if (expectedHigh === 0) return;
        const match = summary.match(/- High:\s+(\d+)/);
        assert.ok(match, 'Should emit a "High:" bucket line when High-severity threats exist');
        assert.strictEqual(
            Number(match![1]),
            expectedHigh,
            `Summary should report ${expectedHigh} High-severity threats`
        );
    });
});
