import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { buildPuppeteerDockerArgs } from '../src/renderers/PDFRenderer.js';

// PDFRenderer.renderToPDF used to compose a single shell-string command and
// hand it to execSync with only the `"` character escaped on headerNote.
// `$(...)`, backticks, `;`, `&&`, and similar metacharacters in the
// headerNote (or in the resolved mount paths) would still be interpreted by
// the host shell.
//
// The renderer now builds an explicit argv list and runs it via execFileSync,
// which spawns docker directly with no shell in between. This test pins that
// behaviour by asserting that:
//   - the substituted values arrive as their own argv entries (no joining), and
//   - the headerNote is passed through verbatim regardless of what
//     metacharacters it contains.
test('buildPuppeteerDockerArgs keeps headerNote and resolved paths as standalone argv entries', () => {
    const headerNote = 'Private $(rm -rf ~) `id` & echo PWNED; "Confidential"';
    const tempScriptsDir = '/tmp/scripts dir';
    const outputDir = '/tmp/out dir';

    const args = buildPuppeteerDockerArgs({
        tempScriptsDir,
        outputDir,
        containerUser: '/home/pptruser',
        image: 'ghcr.io/puppeteer/puppeteer:latest',
        htmlFileName: 'report.html',
        fileName: 'report.pdf',
        headerNote,
    });

    // headerNote is the trailing argv entry and must arrive byte-for-byte.
    assert.equal(
        args[args.length - 1],
        headerNote,
        'headerNote must round-trip through the argv list without escaping or splitting',
    );

    // The two -v mount specs must each be a single argv entry, not multiple.
    const tempIdx = args.indexOf(`${path.resolve(tempScriptsDir)}:/home/pptruser/scripts`);
    const outIdx = args.indexOf(`${path.resolve(outputDir)}:/home/pptruser/output`);
    assert.ok(tempIdx > 0, 'tempScriptsDir mount must appear as a single argv entry');
    assert.ok(outIdx > 0, 'outputDir mount must appear as a single argv entry');
    assert.equal(args[tempIdx - 1], '-v', '-v flag must precede the temp mount entry');
    assert.equal(args[outIdx - 1], '-v', '-v flag must precede the output mount entry');

    // No argv entry concatenates the host path with a shell metachar tail —
    // a smoke test that the old `\` / `"` escaping is gone.
    for (const a of args) {
        assert.ok(typeof a === 'string', 'every argv entry must be a string');
        assert.ok(
            !a.includes('\\"'),
            `argv entry should not contain shell-escaped quotes (got: ${a})`,
        );
    }
});
